//! Load generator rig (DW-024); public for reuse and testing.
//!
//! A dependency-free (wrk/k6-less) HTTP/1.1 load generator used by
//! scripts/bench-macro.sh and .github/workflows/bench.yml to measure the
//! gateway's end-to-end throughput and latency. One worker task per
//! connection; each worker owns a persistent hyper connection
//! (hyper client::conn::http1, no pool) and issues back-to-back requests,
//! recording per-request latency into a hand-rolled histogram (a sorted
//! Vec of nanosecond samples; percentiles at these sample counts are a
//! cheap sort away — no hdrhistogram dependency).
//!
//! The `dwara-loadgen` binary is a thin wrapper: it parses [`Args`] and
//! calls [`run`]; everything else here is the reusable rig.
//!
//! Usage:
//!
//! ```text
//! dwara-loadgen --url http://127.0.0.1:18080/ \
//!     --connections 100 --duration 10 --rate 0
//! ```
//!
//! - `--rate 0` (default) is unbounded: each connection goes as fast as
//!   it can. A positive rate is a global target, dispensed as tokens by
//!   a pacing task and shared fairly-but-not-exactly across workers.
//! - `--echo PORT` (optional) ALSO starts a minimal HTTP/1.1 echo server
//!   on that port inside this same process, so the rig needs no external
//!   upstream: point the gateway at 127.0.0.1:PORT and run the load
//!   against the gateway in one command.
//!
//! Output (STDOUT): a human-readable block plus a machine-parseable
//! `RESULT:` line — `RESULT rps=<f64> errors=<u64> p50_ns=.. p90_ns=..
//! p99_ns=.. p999_ns=.. err_p99_ns=..`. Success percentiles cover only
//! successful requests on warm connections (one unrecorded warmup request
//! per worker); failed and timed-out requests land in err_p99. Exit code
//! 1 if any request failed (the CI macro job asserts errors=0 via this).
//!
//! 100k-connection runs: this rig imposes no connection cap, but the
//! OS does — on Linux raise file descriptors first
//! (`ulimit -n 1048576`); the macOS dev default is far lower, so local
//! smoke runs should stay at 10k connections or fewer (see
//! scripts/bench-macro.sh).

use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

/// Command-line shape (unit-tested in `tests/loadgen_unit.rs`; keep
/// `parse_from`-able).
#[derive(Debug, Parser)]
#[command(
    name = "dwara-loadgen",
    version,
    about = "dwara macro load generator (DW-024)"
)]
pub struct Args {
    /// Target URL to hammer.
    #[arg(long, default_value = "http://127.0.0.1:18080/")]
    pub url: String,
    /// Number of concurrent connections (worker tasks).
    #[arg(long, default_value = "10")]
    pub connections: usize,
    /// Test duration in seconds.
    #[arg(long, default_value = "10")]
    pub duration: u64,
    /// Target requests per second across ALL connections; 0 = unbounded.
    #[arg(long, default_value = "0")]
    pub rate: u64,
    /// Also serve a minimal HTTP/1.1 echo server on this port (in-process
    /// upstream for the bench rig), in addition to generating load.
    #[arg(long)]
    pub echo: Option<u16>,
    /// Serve ONLY the echo server on --echo's port and do no load
    /// generation (the standalone upstream for scripts/bench-macro.sh).
    #[arg(long, default_value = "false", requires = "echo")]
    pub echo_only: bool,
    /// Size of the echo response body in bytes (with --echo).
    #[arg(long, default_value = "128")]
    pub echo_body: usize,
    /// Per-request timeout in milliseconds; a request that exceeds it is
    /// counted as an error (its latency lands in the err_* buckets).
    #[arg(long, default_value = "10000")]
    pub timeout_ms: u64,
}

/// Latency samples in nanoseconds; percentile computed by sorting at
/// report time. Correctness is unit-tested in `tests/loadgen_unit.rs`.
///
/// Memory is bounded for long runs: once the sample vector reaches
/// [`SAMPLE_CAP`], it is halved (every 2nd sample kept) and the recording
/// stride doubles, so the vector stays O(SAMPLE_CAP) regardless of run
/// length. Subsampling is uniform in arrival order, so nearest-rank
/// percentiles over the retained set estimate the true percentiles; at
/// multi-million sample counts the discretization error is far below
/// run-to-run noise.
#[derive(Debug)]
pub struct Histogram {
    /// Retained (subsampled) latency samples in ns.
    pub samples: Vec<u64>,
    /// Recording stride: only every stride-th arriving sample is kept
    /// (1 until the first halving, then doubling per halving).
    pub stride: u64,
    /// Total samples ever recorded, retained or dropped.
    pub seen: u64,
}

impl Default for Histogram {
    fn default() -> Self {
        Histogram {
            samples: Vec::new(),
            stride: 1,
            seen: 0,
        }
    }
}

/// Retained-sample ceiling (about 32 MB of u64 samples).
pub const SAMPLE_CAP: usize = 4_000_000;

impl Histogram {
    /// Record one latency sample (ns); halves the retained vector and
    /// doubles the stride once [`SAMPLE_CAP`] is reached.
    pub fn record(&mut self, ns: u64) {
        self.seen += 1;
        if !self.seen.is_multiple_of(self.stride) {
            return;
        }
        self.samples.push(ns);
        if self.samples.len() >= SAMPLE_CAP {
            let mut kept: Vec<u64> = Vec::with_capacity(self.samples.len() / 2);
            kept.extend(self.samples.iter().step_by(2).copied());
            self.samples = kept;
            self.stride *= 2;
        }
    }

    /// Nearest-rank percentile: the smallest sample at or above the given
    /// fraction (p50 of [1..100] = 50th smallest). `p` is 0.0-1.0.
    pub fn percentile(&mut self, p: f64) -> u64 {
        if self.samples.is_empty() {
            return 0;
        }
        self.samples.sort_unstable();
        let p = p.clamp(0.0, 1.0);
        let rank = ((self.samples.len() as f64) * p).ceil() as usize;
        // ceil of len*1.0 == len; ceil of len*0.0 == 0 -> clamp to 1..=len.
        self.samples[rank.clamp(1, self.samples.len()) - 1]
    }
}

/// Per-run request/error counters shared by all workers.
#[derive(Debug, Default)]
pub struct Totals {
    /// Requests completed in the measurement window (warmup excluded).
    pub requests: u64,
    /// Requests that failed or timed out.
    pub errors: u64,
}

/// Pacing slice: the dispenser wakes and tops up every 50 ms, and a
/// starved worker sleeps to the NEXT slice boundary. One constant (and
/// the single epoch in [`Pacer`]) is what keeps the two sides of pacing
/// on the same grid.
pub const PACE_SLICE: Duration = Duration::from_millis(50);

/// Shared pacing state: the permit balance plus the single time base
/// both sides of pacing use (#127).
///
/// The dispenser task's interval is anchored to `epoch`, and every
/// starved worker sleeps to the next `epoch + k*PACE_SLICE` boundary.
/// Before this was shared, the starve-sleep re-anchored to its own
/// `now + 50ms` on every wake, drifting against the dispenser's grid —
/// a worker could land just before a dispensation and pay a second
/// slice of wait for the same token.
pub struct Pacer {
    /// Permit balance. Workers CAS-decrement; the pacing task tops up
    /// with [`pace_top_up`]. In unbounded mode (`--rate 0`) it is
    /// pre-filled with a huge balance so workers never wait.
    pub permits: std::sync::atomic::AtomicU64,
    /// Pacing epoch; `None` in unbounded mode (workers never starve).
    pub epoch: Option<Instant>,
}

impl Pacer {
    /// Unbounded-mode pacer: a huge pre-filled balance, no epoch.
    pub fn unbounded() -> Self {
        Pacer {
            permits: std::sync::atomic::AtomicU64::new(u64::MAX / 2),
            epoch: None,
        }
    }
}

/// One dispenser tick's top-up decision (#127): how many permits to add,
/// given the cumulative total the rate schedule owes (`owed`), the
/// cumulative total already dispensed (`paid`), and the current
/// unconsumed `balance`. The top-up target is
/// `min(owed, consumed + per_slice)` with `consumed = paid - balance`:
///
/// - the owed-total keeps the exact requested schedule (rates below one
///   token per slice remain expressible), and
/// - the balance may never exceed one slice above what workers have
///   actually CONSUMED, so a worker that stops consuming and later
///   resumes cannot discharge the accumulated backlog as one burst — a
///   burst would contaminate paced latency percentiles.
///
/// Concurrency: `balance` is read once per tick; a worker consuming
/// concurrently only lowers the real balance, so the computed target is
/// an upper bound with at most the intended one slice of slack —
/// over-dispensing past the cap is impossible.
///
/// Pure arithmetic; unit-tested in `tests/loadgen_unit.rs`.
pub fn pace_top_up(owed: u64, paid: u64, balance: u64, per_slice: u64) -> u64 {
    let consumed = paid.saturating_sub(balance);
    owed.min(consumed.saturating_add(per_slice))
        .saturating_sub(paid)
}

/// Wait from `now` until the next pacing-slice boundary STRICTLY after
/// `now`, where boundaries are `epoch + k * PACE_SLICE` (k = 1, 2, ...).
/// Pure arithmetic over `Instant`s; unit-tested in
/// `tests/loadgen_unit.rs`. `now` before `epoch` (never in practice)
/// reads as phase 0 and waits one full slice.
pub fn until_next_tick(now: Instant, epoch: Instant) -> Duration {
    let slice = PACE_SLICE.as_millis() as u64;
    let phase = now.saturating_duration_since(epoch).as_millis() as u64 % slice;
    Duration::from_millis(if phase == 0 { slice } else { slice - phase })
}

/// Per-run state shared by all workers: request/error counters plus the
/// success and error latency histograms (error latencies kept separate so
/// failures never contaminate the success percentiles).
pub struct SharedState {
    /// Request/error counters.
    pub totals: Arc<std::sync::Mutex<Totals>>,
    /// Success-path latency samples.
    pub histogram: Arc<std::sync::Mutex<Histogram>>,
    /// Failed/timeout latency samples.
    pub err_histogram: Arc<std::sync::Mutex<Histogram>>,
}

/// Run the whole rig per `args`: optionally the in-process echo upstream,
/// the pacing dispenser (positive `--rate`), one [`worker`] per
/// connection, then the report. Returns the process exit code (1 if any
/// request failed, 2 on invalid arguments).
pub async fn run(args: Args) -> i32 {
    if args.connections == 0 {
        eprintln!("--connections must be >= 1");
        return 2;
    }
    if let Some(port) = args.echo {
        if args.echo_only {
            echo_server(port, args.echo_body).await;
            return 0;
        }
        tokio::spawn(echo_server(port, args.echo_body));
        // Give the echo listener a moment to bind before the gateway (or
        // the load) needs it.
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let start = Instant::now();
    let deadline = start + Duration::from_secs(args.duration);
    let totals = Arc::new(std::sync::Mutex::new(Totals::default()));
    let histogram = Arc::new(std::sync::Mutex::new(Histogram::default()));
    // Error-path latencies (failed/timeout requests) are recorded in a
    // separate histogram so they never contaminate the success percentiles;
    // they are reported as err_p99 on the RESULT line.
    let err_histogram = Arc::new(std::sync::Mutex::new(Histogram::default()));
    // Unbounded mode pre-fills a huge permit balance so workers never wait;
    // paced mode starts at 0, is dispensed by the pacing task below, and
    // its epoch anchors BOTH the dispenser tick and the workers'
    // starve-sleeps (see Pacer).
    let pacer = Arc::new(if args.rate > 0 {
        Pacer {
            permits: std::sync::atomic::AtomicU64::new(0),
            epoch: Some(Instant::now()),
        }
    } else {
        Pacer::unbounded()
    });

    if let Some(epoch) = pacer.epoch {
        // Pacing: dispense `rate` tokens per second in PACE_SLICE slices.
        // Each tick tops the cumulative dispensed total up to
        // `min(rate * elapsed + one slice, consumed + one slice)` via
        // [pace_top_up]: the owed-total keeps the exact requested schedule
        // (even below 20 rps, where per-slice dispensing cannot), while the
        // consumed-relative cap bounds catch-up — unused tokens never
        // accumulate behind an idle worker, so resumed workers cannot
        // discharge a backlog as one burst (#127).
        let pacer = pacer.clone();
        let per_slice = ((args.rate as f64 / 20.0).ceil() as u64).max(1);
        let rate = args.rate;
        tokio::spawn(async move {
            // interval_at anchors the grid to the shared epoch so the
            // first tick fires immediately and later ticks land exactly on
            // the boundaries starved workers sleep to.
            let mut tick =
                tokio::time::interval_at(tokio::time::Instant::from_std(epoch), PACE_SLICE);
            // Cumulative tokens ever dispensed.
            let mut paid: u64 = 0;
            loop {
                tick.tick().await;
                let owed = (rate as f64 * epoch.elapsed().as_secs_f64()) as u64 + per_slice;
                let balance = pacer.permits.load(std::sync::atomic::Ordering::Relaxed);
                let add = pace_top_up(owed, paid, balance, per_slice);
                if add > 0 {
                    pacer
                        .permits
                        .fetch_add(add, std::sync::atomic::Ordering::Relaxed);
                    paid += add;
                }
            }
        });
    }

    let url: hyper::Uri = match args.url.parse() {
        Ok(u) => u,
        Err(e) => {
            eprintln!("invalid --url: {e}");
            return 2;
        }
    };
    let authority = url
        .authority()
        .map(|a| a.as_str().to_string())
        .unwrap_or_else(|| "127.0.0.1".into());
    let path = url
        .path_and_query()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "/".into());

    let timeout = Duration::from_millis(args.timeout_ms);
    // Shared per-run state handed to every worker as one Arc (keeps the
    // worker signature small and clippy-happy).
    let shared = Arc::new(SharedState {
        totals,
        histogram,
        err_histogram,
    });
    let mut workers = Vec::with_capacity(args.connections);
    for _ in 0..args.connections {
        workers.push(tokio::spawn(worker(
            url.scheme_str().unwrap_or("http").to_string(),
            authority.clone(),
            path.clone(),
            deadline,
            timeout,
            pacer.clone(),
            shared.clone(),
        )));
    }
    for w in workers {
        let _ = w.await;
    }

    let code = {
        let totals = shared.totals.lock().unwrap();
        let mut histogram = shared.histogram.lock().unwrap();
        let mut err_histogram = shared.err_histogram.lock().unwrap();
        report(
            &args,
            start.elapsed(),
            &totals,
            &mut histogram,
            &mut err_histogram,
        )
    };
    code
}

/// One load-generation connection: owns a persistent hyper connection,
/// acquires pacing permits from `pacer`, and records each request's
/// outcome into `shared` until `deadline`. The first (warmup) request per
/// connection is unrecorded, so percentiles measure pure RTT on warm
/// connections.
pub async fn worker(
    scheme: String,
    authority: String,
    path: String,
    deadline: Instant,
    timeout: Duration,
    pacer: Arc<Pacer>,
    shared: Arc<SharedState>,
) {
    let mut conn: Option<(
        hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
        tokio::task::JoinHandle<()>,
    )> = None;
    // Warmup: one unrecorded request per worker before the measurement
    // loop, so TCP connect + HTTP handshake latency never contaminates a
    // worker's first sample. RESULT percentiles therefore mean pure
    // request RTT on warm connections. A warmup failure is not fatal —
    // the measurement loop re-handshakes on demand.
    let _ = tokio::time::timeout(timeout, do_request(&mut conn, &scheme, &authority, &path)).await;
    while Instant::now() < deadline {
        // Acquire one rate permit (unbounded mode: the balance is huge, so
        // this is a single uncontended atomic).
        loop {
            let b = pacer.permits.load(std::sync::atomic::Ordering::Relaxed);
            if b > 0
                && pacer
                    .permits
                    .compare_exchange(
                        b,
                        b - 1,
                        std::sync::atomic::Ordering::Relaxed,
                        std::sync::atomic::Ordering::Relaxed,
                    )
                    .is_ok()
            {
                break;
            }
            if Instant::now() >= deadline {
                return;
            }
            // Starved of permits: sleep to the NEXT dispenser boundary on
            // the pacer's shared epoch grid rather than busy-yielding — a
            // yield_now spin burns a full core per waiting worker and
            // contaminates the paced latencies of everyone else. Sleeping
            // to an unaligned now+50ms (the old behavior) drifts against
            // the dispenser: it can wake just before a dispensation and
            // pay a second slice of wait for the same token (#127). The
            // `None` arm is unreachable in unbounded mode (the balance is
            // pre-filled huge); the full-slice fallback just stays honest.
            let wait = pacer
                .epoch
                .map(|epoch| until_next_tick(Instant::now(), epoch))
                .unwrap_or(PACE_SLICE);
            tokio::time::sleep(wait).await;
        }

        let start = Instant::now();
        let outcome =
            tokio::time::timeout(timeout, do_request(&mut conn, &scheme, &authority, &path)).await;
        let elapsed = start.elapsed();
        let mut totals = shared.totals.lock().unwrap();
        totals.requests += 1;
        match outcome {
            Ok(Ok(())) => shared
                .histogram
                .lock()
                .unwrap()
                .record(elapsed.as_nanos() as u64),
            Ok(Err(e)) => {
                totals.errors += 1;
                shared
                    .err_histogram
                    .lock()
                    .unwrap()
                    .record(elapsed.as_nanos() as u64);
                // A failed connection is dead; force re-handshake.
                if let Some((_, driver)) = conn.take() {
                    driver.abort();
                }
                if totals.errors <= 5 {
                    eprintln!("request error: {e}");
                }
            }
            Err(_) => {
                totals.errors += 1;
                shared
                    .err_histogram
                    .lock()
                    .unwrap()
                    .record(elapsed.as_nanos() as u64);
                // A timed-out request leaves the connection in an
                // indeterminate state; drop it and re-handshake.
                if let Some((_, driver)) = conn.take() {
                    driver.abort();
                }
                if totals.errors <= 5 {
                    eprintln!("request error: timeout after {}ms", timeout.as_millis());
                }
            }
        }
    }
    if let Some((_, driver)) = conn.take() {
        driver.abort();
    }
}

/// One request over the owned connection, re-handshaking when the
/// connection is absent or the request fails at the transport level.
async fn do_request(
    conn: &mut Option<(
        hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
        tokio::task::JoinHandle<()>,
    )>,
    scheme: &str,
    authority: &str,
    path: &str,
) -> Result<(), String> {
    if conn.is_none() {
        let stream = if scheme == "https" {
            return Err("TLS load generation is not wired in the v1 rig (use http targets)".into());
        } else {
            TcpStream::connect(authority)
                .await
                .map_err(|e| format!("connect: {e}"))?
        };
        let (tx, rx) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| format!("handshake: {e}"))?;
        let driver = tokio::spawn(async move {
            let _ = rx.await;
        });
        *conn = Some((tx, driver));
    }
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(path)
        .header(hyper::header::HOST, authority)
        .body(Empty::<Bytes>::new())
        .map_err(|e| format!("build: {e}"))?;
    let res = conn
        .as_mut()
        .expect("connection present")
        .0
        .send_request(req)
        .await
        .map_err(|e| format!("send: {e}"))?;
    let status = res.status();
    let body = res
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("body: {e}"))?;
    if !status.is_success() {
        return Err(format!("status {status}"));
    }
    let _ = body;
    Ok(())
}

/// Minimal HTTP/1.1 echo server on 127.0.0.1:`port`, serving
/// `body_len`-byte bodies forever (the in-process upstream for the rig).
pub async fn echo_server(port: u16, body_len: usize) {
    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("echo server bind failed on port {port}: {e}");
            return;
        }
    };
    let body = vec![b'x'; body_len];
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(a) => a,
            Err(_) => continue,
        };
        let body = body.clone();
        tokio::spawn(async move {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    hyper::service::service_fn(move |_| {
                        let body = body.clone();
                        async move {
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(
                                http_body_util::Full::new(hyper::body::Bytes::from(body)),
                            ))
                        }
                    }),
                )
                .await;
        });
    }
}

/// Print the human block + RESULT line; returns the exit code (1 iff any
/// request failed).
fn report(
    args: &Args,
    ran_for: Duration,
    totals: &Totals,
    histogram: &mut Histogram,
    err_histogram: &mut Histogram,
) -> i32 {
    let ran_for = ran_for.max(Duration::from_secs(1)).as_secs_f64();
    let rps = totals.requests as f64 / ran_for;
    let p50 = histogram.percentile(0.50);
    let p90 = histogram.percentile(0.90);
    let p99 = histogram.percentile(0.99);
    let p999 = histogram.percentile(0.999);
    let err_p99 = err_histogram.percentile(0.99);
    println!(
        "connections={} duration={}s rate={}",
        args.connections, args.duration, args.rate
    );
    println!(
        "requests={} errors={} rps={:.0}",
        totals.requests, totals.errors, rps
    );
    println!(
        "p50={}us p90={}us p99={}us p999={}us",
        p50 / 1_000,
        p90 / 1_000,
        p99 / 1_000,
        p999 / 1_000
    );
    if totals.errors > 0 {
        println!("err_p99={}us (failed/timeout requests)", err_p99 / 1_000);
    }
    println!(
        "RESULT: rps={rps:.2} errors={} p50_ns={p50} p90_ns={p90} p99_ns={p99} p999_ns={p999} err_p99_ns={err_p99}",
        totals.errors
    );
    if totals.errors > 0 {
        1
    } else {
        0
    }
}
