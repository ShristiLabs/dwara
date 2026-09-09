//! Load generator rig (DW-024, PERF-06); public for reuse and testing.
//!
//! A dependency-free (wrk/k6-less) load generator used by
//! scripts/bench-macro.sh, scripts/bench-regression.sh, and
//! .github/workflows/bench*.yml to measure the gateway's end-to-end
//! throughput and latency across HTTP/1, HTTP/2, and (feature-gated)
//! HTTP/3, plus pool-reuse and streaming macro workloads.
//!
//! ## Protocols
//!
//! - `h1` (default): one worker task per connection; each worker owns a
//!   persistent hyper HTTP/1.1 connection (`client::conn::http1`, no
//!   pool) and issues back-to-back requests.
//! - `h2`: each worker owns a persistent HTTP/2 connection
//!   (`client::conn::http2`, h2c prior-knowledge over cleartext) and
//!   issues back-to-back requests multiplexed on it.
//! - `h3`: feature-gated behind the `h3` cargo feature (QUIC + h3). Each
//!   worker owns one QUIC connection and opens one bidirectional stream
//!   per request. h3 has NO in-process echo upstream (`--echo` is
//!   rejected with `--protocol h3`): point it at a real h3 listener
//!   (the gateway with a `protocol: h3` listener). `--insecure` skips
//!   certificate verification for loopback benchmark targets only.
//!
//! ## Workloads
//!
//! - `throughput` (default): owned persistent connection, back-to-back
//!   requests against a fixed-body echo. Measures raw max throughput.
//! - `pool-reuse`: a shared pooled client (hyper-util legacy for h1/h2;
//!   one shared QUIC connection for h3) issues requests across all
//!   workers, exercising connection/stream reuse on the client side and
//!   the gateway's upstream pool on the server side.
//! - `streaming`: owned persistent connection against a streaming echo
//!   that emits `--stream-chunks` chunks of `--stream-chunk-bytes` bytes
//!   each (with `--stream-chunk-delay-ms` between chunks); the client
//!   drains the full streaming body. Measures streaming throughput.
//!
//! ## Output
//!
//! STDOUT: a human-readable block plus a machine-parseable `RESULT:`
//! line (`RESULT rps=<f64> errors=<u64> p50_ns=.. p90_ns=.. p99_ns=..
//! p999_ns=.. err_p99_ns=..`). With `--json`, an additional `JSON:`
//! line carries the same metrics plus the protocol/workload labels for
//! the regression gate (`scripts/bench-regression.py`). Success
//! percentiles cover only successful requests on warm connections (one
//! unrecorded warmup request per worker); failed and timed-out requests
//! land in err_p99. Exit code 1 if any request failed (the CI macro job
//! asserts errors=0 via this).
//!
//! 100k-connection runs: this rig imposes no connection cap, but the
//! OS does - on Linux raise file descriptors first
//! (`ulimit -n 1048576`); the macOS dev default is far lower, so local
//! smoke runs should stay at 10k connections or fewer (see
//! scripts/bench-macro.sh).

use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

/// Wire protocol to drive the target with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Protocol {
    /// HTTP/1.1 over a persistent owned connection.
    H1,
    /// HTTP/2 (h2c prior-knowledge over cleartext) over a persistent
    /// owned connection.
    H2,
    /// HTTP/3 (QUIC + h3). Feature-gated behind the `h3` cargo feature.
    /// No in-process echo upstream; point at a real h3 listener.
    H3,
}

impl Protocol {
    /// Lowercase label used in JSON output and the regression gate key.
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::H1 => "h1",
            Protocol::H2 => "h2",
            Protocol::H3 => "h3",
        }
    }
}

/// Macro workload shape (PERF-06).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Workload {
    /// Owned persistent connection, back-to-back requests, fixed-body
    /// echo. Raw max throughput.
    Throughput,
    /// Shared pooled client across all workers; exercises connection /
    /// stream reuse on the client side and the gateway's upstream pool.
    PoolReuse,
    /// Owned persistent connection against a streaming echo; the client
    /// drains the full chunked body. Streaming throughput.
    Streaming,
}

impl Workload {
    /// Lowercase label used in JSON output and the regression gate key.
    pub fn as_str(self) -> &'static str {
        match self {
            Workload::Throughput => "throughput",
            Workload::PoolReuse => "pool-reuse",
            Workload::Streaming => "streaming",
        }
    }
}

/// Command-line shape (unit-tested in `tests/loadgen_unit.rs`; keep
/// `parse_from`-able).
#[derive(Debug, Parser)]
#[command(
    name = "dwara-loadgen",
    version,
    about = "dwara macro load generator (DW-024, PERF-06)"
)]
pub struct Args {
    /// Target URL to hammer.
    #[arg(long, default_value = "http://127.0.0.1:18080/")]
    pub url: String,
    /// Wire protocol to drive: h1, h2, or h3 (h3 requires the h3 feature).
    #[arg(long, value_enum, default_value_t = Protocol::H1)]
    pub protocol: Protocol,
    /// Macro workload: throughput, pool-reuse, or streaming.
    #[arg(long, value_enum, default_value_t = Workload::Throughput)]
    pub workload: Workload,
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
    /// upstream for the bench rig), in addition to generating load. Not
    /// supported with `--protocol h3` (h3 has no in-process echo).
    #[arg(long)]
    pub echo: Option<u16>,
    /// Serve ONLY the echo server on --echo's port and do no load
    /// generation (the standalone upstream for scripts/bench-macro.sh).
    #[arg(long, default_value = "false", requires = "echo")]
    pub echo_only: bool,
    /// Size of the echo response body in bytes (with --echo, throughput
    /// and pool-reuse workloads).
    #[arg(long, default_value = "128")]
    pub echo_body: usize,
    /// Number of chunks the streaming echo emits per response (with
    /// `--workload streaming` and `--echo`).
    #[arg(long, default_value_t = 8)]
    pub stream_chunks: usize,
    /// Bytes per streaming chunk (with `--workload streaming` and `--echo`).
    #[arg(long, default_value_t = 1024)]
    pub stream_chunk_bytes: usize,
    /// Delay between streaming chunks in milliseconds (with
    /// `--workload streaming` and `--echo`); 0 emits as fast as possible.
    #[arg(long, default_value_t = 0)]
    pub stream_chunk_delay_ms: u64,
    /// Per-request timeout in milliseconds; a request that exceeds it is
    /// counted as an error (its latency lands in the err_* buckets).
    #[arg(long, default_value = "10000")]
    pub timeout_ms: u64,
    /// Emit a machine-parseable `JSON:` line in addition to the
    /// human/RESULT block (consumed by scripts/bench-regression.py).
    #[arg(long, default_value_t = false)]
    pub json: bool,
    /// (h3 only) Skip server certificate verification. UNSAFE: for
    /// loopback benchmark targets only - never use against a production
    /// endpoint or any host whose cert you do not control.
    #[arg(long, default_value_t = false)]
    pub insecure: bool,
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
/// `now + 50ms` on every wake, drifting against the dispenser's grid -
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
///   resumes cannot discharge the accumulated backlog as one burst - a
///   burst would contaminate paced latency percentiles.
///
/// Concurrency: `balance` is read once per tick; a worker consuming
/// concurrently only lowers the real balance, so the computed target is
/// an upper bound with at most the intended one slice of slack -
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
/// the pacing dispenser (positive `--rate`), one worker per connection
/// (or per pooled-client slot), then the report. Returns the process
/// exit code (1 if any request failed, 2 on invalid arguments).
pub async fn run(args: Args) -> i32 {
    if args.connections == 0 {
        eprintln!("--connections must be >= 1");
        return 2;
    }
    if args.protocol == Protocol::H3 && args.echo.is_some() {
        eprintln!("--echo is not supported with --protocol h3 (no in-process h3 echo; point at a real h3 listener)");
        return 2;
    }

    if let Some(port) = args.echo {
        if args.echo_only {
            if args.workload == Workload::Streaming {
                echo_server_streaming(
                    port,
                    args.stream_chunks,
                    args.stream_chunk_bytes,
                    args.stream_chunk_delay_ms,
                )
                .await;
            } else {
                echo_server(port, args.echo_body).await;
            }
            return 0;
        }
        if args.workload == Workload::Streaming {
            tokio::spawn(echo_server_streaming(
                port,
                args.stream_chunks,
                args.stream_chunk_bytes,
                args.stream_chunk_delay_ms,
            ));
        } else {
            tokio::spawn(echo_server(port, args.echo_body));
        }
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
        // consumed-relative cap bounds catch-up - unused tokens never
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
    // --insecure disables certificate verification and is only safe for
    // loopback benchmark targets. Reject it for non-loopback hosts to
    // prevent accidental use against remote/production endpoints.
    if args.insecure {
        let host = authority
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(&authority);
        let is_loopback = matches!(host, "127.0.0.1" | "::1" | "localhost" | "[::1]");
        if !is_loopback {
            eprintln!(
                "--insecure is only permitted for loopback targets (127.0.0.1, ::1, localhost); \
                 got '{host}'"
            );
            return 2;
        }
    }
    let path = url
        .path_and_query()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "/".into());
    let scheme = url.scheme_str().unwrap_or("http").to_string();

    let timeout = Duration::from_millis(args.timeout_ms);
    // Shared per-run state handed to every worker as one Arc (keeps the
    // worker signature small and clippy-happy).
    let shared = Arc::new(SharedState {
        totals,
        histogram,
        err_histogram,
    });

    let code = spawn_workers(
        &args,
        scheme,
        authority,
        path,
        deadline,
        timeout,
        pacer,
        Arc::clone(&shared),
    )
    .await;

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
    .max(code)
}

/// Dispatch workers per protocol + workload, await them all, and return
/// a nonzero exit code if any worker observed a failure (1) or the
/// dispatch itself was misconfigured (2).
#[allow(clippy::too_many_arguments)]
async fn spawn_workers(
    args: &Args,
    scheme: String,
    authority: String,
    path: String,
    deadline: Instant,
    timeout: Duration,
    pacer: Arc<Pacer>,
    shared: Arc<SharedState>,
) -> i32 {
    let protocol = args.protocol;
    let workload = args.workload;
    match (protocol, workload) {
        (Protocol::H1, Workload::Throughput) | (Protocol::H1, Workload::Streaming) => {
            let mut workers = Vec::with_capacity(args.connections);
            for _ in 0..args.connections {
                workers.push(tokio::spawn(worker(
                    scheme.clone(),
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
            0
        }
        (Protocol::H2, Workload::Throughput) | (Protocol::H2, Workload::Streaming) => {
            let mut workers = Vec::with_capacity(args.connections);
            for _ in 0..args.connections {
                workers.push(tokio::spawn(worker_h2(
                    scheme.clone(),
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
            0
        }
        (Protocol::H3, Workload::Throughput) | (Protocol::H3, Workload::Streaming) => {
            let target = H3Target {
                authority: authority.clone(),
                path: path.clone(),
                insecure: args.insecure,
            };
            let mut workers = Vec::with_capacity(args.connections);
            for _ in 0..args.connections {
                workers.push(tokio::spawn(worker_h3(
                    target.clone(),
                    deadline,
                    timeout,
                    pacer.clone(),
                    shared.clone(),
                )));
            }
            for w in workers {
                let _ = w.await;
            }
            0
        }
        (Protocol::H1, Workload::PoolReuse) => {
            let client = match build_pooled_h1_client() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("pooled h1 client build failed: {e}");
                    return 2;
                }
            };
            let mut workers = Vec::with_capacity(args.connections);
            for _ in 0..args.connections {
                workers.push(tokio::spawn(worker_pooled_h1(
                    client.clone(),
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
            0
        }
        (Protocol::H2, Workload::PoolReuse) => {
            // One shared h2 connection; all workers get their own clone
            // of the `SendRequest` (Clone — clones share the connection
            // but issue concurrent streams without mutex serialization).
            match shared_h2_connection(&authority).await {
                Ok(send_request) => {
                    let mut workers = Vec::with_capacity(args.connections);
                    for _ in 0..args.connections {
                        workers.push(tokio::spawn(worker_pooled_h2(
                            send_request.clone(),
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
                    0
                }
                Err(e) => {
                    eprintln!("h2 pool connection failed: {e}");
                    2
                }
            }
        }
        (Protocol::H3, Workload::PoolReuse) => {
            let target = H3Target {
                authority: authority.clone(),
                path: path.clone(),
                insecure: args.insecure,
            };
            match shared_h3_connection(&target).await {
                Ok((_endpoint, send_request, _driver)) => {
                    // Keep `_endpoint` and `_driver` alive for the
                    // duration of the run — dropping the endpoint closes
                    // the UDP socket and kills the QUIC connection.
                    // Each worker gets its own clone of `SendRequest`
                    // (Clone — clones share the connection but issue
                    // concurrent streams without mutex serialization).
                    let mut workers = Vec::with_capacity(args.connections);
                    for _ in 0..args.connections {
                        workers.push(tokio::spawn(worker_pooled_h3(
                            send_request.clone(),
                            target.clone(),
                            deadline,
                            timeout,
                            pacer.clone(),
                            shared.clone(),
                        )));
                    }
                    for w in workers {
                        let _ = w.await;
                    }
                    0
                }
                Err(e) => {
                    eprintln!("h3 pool connection failed: {e}");
                    2
                }
            }
        }
    }
}

/// Acquire one pacing permit (unbounded mode: a single uncontended
/// atomic; paced mode: CAS-decrement, starve-sleeping to the next
/// dispenser boundary on the pacer's shared epoch grid). Returns when a
/// permit is held or `deadline` has passed.
async fn acquire_permit(pacer: &Arc<Pacer>, deadline: Instant) {
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
            return;
        }
        if Instant::now() >= deadline {
            return;
        }
        // Starved of permits: sleep to the NEXT dispenser boundary on the
        // pacer's shared epoch grid rather than busy-yielding - a yield_now
        // spin burns a full core per waiting worker and contaminates the
        // paced latencies of everyone else. The `None` arm is unreachable
        // in unbounded mode (the balance is pre-filled huge); the
        // full-slice fallback just stays honest.
        let wait = pacer
            .epoch
            .map(|epoch| until_next_tick(Instant::now(), epoch))
            .unwrap_or(PACE_SLICE);
        tokio::time::sleep(wait).await;
    }
}

/// Record one request outcome into the shared totals + histograms. The
/// outer `Err` is a timeout (the `Elapsed` from `tokio::time::timeout`,
/// normalized to `()` by the callers via `map_err`); the inner `Err` is
/// a transport/status failure. Failed/timeout messages are printed
/// rate-limited (first five).
fn record_outcome(
    shared: &Arc<SharedState>,
    elapsed: Duration,
    outcome: Result<Result<(), String>, ()>,
    timeout: Duration,
) {
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
            if totals.errors <= 5 {
                eprintln!("request error: {e}");
            }
        }
        Err(()) => {
            totals.errors += 1;
            shared
                .err_histogram
                .lock()
                .unwrap()
                .record(elapsed.as_nanos() as u64);
            if totals.errors <= 5 {
                eprintln!("request error: timeout after {}ms", timeout.as_millis());
            }
        }
    }
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
    // request RTT on warm connections. A warmup failure is not fatal -
    // the measurement loop re-handshakes on demand.
    let _ = tokio::time::timeout(
        timeout,
        do_request_h1(&mut conn, &scheme, &authority, &path),
    )
    .await;
    while Instant::now() < deadline {
        acquire_permit(&pacer, deadline).await;
        if Instant::now() >= deadline {
            break;
        }
        let start = Instant::now();
        let outcome = tokio::time::timeout(
            timeout,
            do_request_h1(&mut conn, &scheme, &authority, &path),
        )
        .await;
        let elapsed = start.elapsed();
        // A failed/timed-out h1 connection is dead; force re-handshake.
        if !matches!(outcome, Ok(Ok(()))) {
            if let Some((_, driver)) = conn.take() {
                driver.abort();
            }
        }
        record_outcome(&shared, elapsed, outcome.map_err(|_| ()), timeout);
    }
    if let Some((_, driver)) = conn.take() {
        driver.abort();
    }
}

/// h2 owned-connection worker: one persistent h2c connection, back-to-back
/// requests multiplexed on it.
pub async fn worker_h2(
    scheme: String,
    authority: String,
    path: String,
    deadline: Instant,
    timeout: Duration,
    pacer: Arc<Pacer>,
    shared: Arc<SharedState>,
) {
    let _ = scheme; // h2c is cleartext; scheme is always http for the rig.
    let mut conn: Option<(
        hyper::client::conn::http2::SendRequest<Empty<Bytes>>,
        tokio::task::JoinHandle<()>,
    )> = None;
    let _ = tokio::time::timeout(timeout, do_request_h2(&mut conn, &authority, &path)).await;
    while Instant::now() < deadline {
        acquire_permit(&pacer, deadline).await;
        if Instant::now() >= deadline {
            break;
        }
        let start = Instant::now();
        let outcome =
            tokio::time::timeout(timeout, do_request_h2(&mut conn, &authority, &path)).await;
        let elapsed = start.elapsed();
        if !matches!(outcome, Ok(Ok(()))) {
            if let Some((_, driver)) = conn.take() {
                driver.abort();
            }
        }
        record_outcome(&shared, elapsed, outcome.map_err(|_| ()), timeout);
    }
    if let Some((_, driver)) = conn.take() {
        driver.abort();
    }
}

/// h1 pool-reuse worker: issues requests through a shared hyper-util
/// legacy client (which pools connections). No owned connection state.
pub async fn worker_pooled_h1(
    client: hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Empty<Bytes>,
    >,
    authority: String,
    path: String,
    deadline: Instant,
    timeout: Duration,
    pacer: Arc<Pacer>,
    shared: Arc<SharedState>,
) {
    let uri: hyper::Uri = format!("http://{authority}{path}")
        .parse()
        .expect("valid h1 pooled uri");
    // Warmup (unrecorded).
    let _ = tokio::time::timeout(timeout, do_request_pooled_h1(&client, &uri)).await;
    while Instant::now() < deadline {
        acquire_permit(&pacer, deadline).await;
        if Instant::now() >= deadline {
            break;
        }
        let start = Instant::now();
        let outcome = tokio::time::timeout(timeout, do_request_pooled_h1(&client, &uri)).await;
        let elapsed = start.elapsed();
        record_outcome(&shared, elapsed, outcome.map_err(|_| ()), timeout);
    }
}

/// h2 pool-reuse worker: each worker holds its own clone of the h2
/// `SendRequest` (it is `Clone` — clones share the same underlying
/// connection but can issue concurrent streams without mutex
/// serialization). This exercises real h2 stream multiplexing: many
/// workers, many concurrent streams, one connection.
pub async fn worker_pooled_h2(
    mut send_request: hyper::client::conn::http2::SendRequest<Empty<Bytes>>,
    authority: String,
    path: String,
    deadline: Instant,
    timeout: Duration,
    pacer: Arc<Pacer>,
    shared: Arc<SharedState>,
) {
    // Warmup (unrecorded).
    let _ = tokio::time::timeout(
        timeout,
        do_request_pooled_h2(&mut send_request, &authority, &path),
    )
    .await;
    while Instant::now() < deadline {
        acquire_permit(&pacer, deadline).await;
        if Instant::now() >= deadline {
            break;
        }
        let start = Instant::now();
        let outcome = tokio::time::timeout(
            timeout,
            do_request_pooled_h2(&mut send_request, &authority, &path),
        )
        .await;
        let elapsed = start.elapsed();
        record_outcome(&shared, elapsed, outcome.map_err(|_| ()), timeout);
    }
}

/// Build a shared hyper-util legacy client for h1 pool-reuse. The pool
/// reuses idle connections across requests; the timer is installed so
/// idle-timeout eviction can fire.
fn build_pooled_h1_client() -> Result<
    hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Empty<Bytes>,
    >,
    String,
> {
    let connector = hyper_util::client::legacy::connect::HttpConnector::new();
    let mut builder =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new());
    builder.pool_timer(hyper_util::rt::TokioTimer::new());
    builder.timer(hyper_util::rt::TokioTimer::new());
    Ok(builder.build(connector))
}

/// Establish one shared h2 (h2c prior-knowledge) connection to `authority`
/// for the pool-reuse workload. Returns the `SendRequest` (cloneable —
/// each worker gets its own clone sharing the same connection).
async fn shared_h2_connection(
    authority: &str,
) -> Result<hyper::client::conn::http2::SendRequest<Empty<Bytes>>, String> {
    let stream = TcpStream::connect(authority)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let (tx, rx) = hyper::client::conn::http2::handshake::<_, _, Empty<Bytes>>(
        hyper_util::rt::TokioExecutor::new(),
        TokioIo::new(stream),
    )
    .await
    .map_err(|e| format!("h2 handshake: {e}"))?;
    tokio::spawn(async move {
        let _ = rx.await;
    });
    Ok(tx)
}

/// One h1 request over the owned connection, re-handshaking when the
/// connection is absent or the request fails at the transport level.
async fn do_request_h1(
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
    res.into_body()
        .collect()
        .await
        .map_err(|e| format!("body: {e}"))?;
    if !status.is_success() {
        return Err(format!("status {status}"));
    }
    Ok(())
}

/// One h2 request over the owned connection, re-handshaking when absent.
async fn do_request_h2(
    conn: &mut Option<(
        hyper::client::conn::http2::SendRequest<Empty<Bytes>>,
        tokio::task::JoinHandle<()>,
    )>,
    authority: &str,
    path: &str,
) -> Result<(), String> {
    if conn.is_none() {
        let stream = TcpStream::connect(authority)
            .await
            .map_err(|e| format!("connect: {e}"))?;
        let (tx, rx) = hyper::client::conn::http2::handshake::<_, _, Empty<Bytes>>(
            hyper_util::rt::TokioExecutor::new(),
            TokioIo::new(stream),
        )
        .await
        .map_err(|e| format!("h2 handshake: {e}"))?;
        let driver = tokio::spawn(async move {
            let _ = rx.await;
        });
        *conn = Some((tx, driver));
    }
    let tx = &mut conn.as_mut().expect("connection present").0;
    tx.ready().await.map_err(|e| format!("h2 ready: {e}"))?;
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(path)
        .header(hyper::header::HOST, authority)
        .body(Empty::<Bytes>::new())
        .map_err(|e| format!("build: {e}"))?;
    let res = tx
        .send_request(req)
        .await
        .map_err(|e| format!("send: {e}"))?;
    let status = res.status();
    res.into_body()
        .collect()
        .await
        .map_err(|e| format!("body: {e}"))?;
    if !status.is_success() {
        return Err(format!("status {status}"));
    }
    Ok(())
}

/// One h1 request through the shared pooled client.
async fn do_request_pooled_h1(
    client: &hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Empty<Bytes>,
    >,
    uri: &hyper::Uri,
) -> Result<(), String> {
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(uri.clone())
        .body(Empty::<Bytes>::new())
        .map_err(|e| format!("build: {e}"))?;
    let res = client
        .request(req)
        .await
        .map_err(|e| format!("send: {e}"))?;
    let status = res.status();
    res.into_body()
        .collect()
        .await
        .map_err(|e| format!("body: {e}"))?;
    if !status.is_success() {
        return Err(format!("status {status}"));
    }
    Ok(())
}

/// One h2 request through a cloned `SendRequest` (no mutex — each
/// worker has its own clone sharing the same connection).
async fn do_request_pooled_h2(
    send_request: &mut hyper::client::conn::http2::SendRequest<Empty<Bytes>>,
    authority: &str,
    path: &str,
) -> Result<(), String> {
    send_request
        .ready()
        .await
        .map_err(|e| format!("h2 ready: {e}"))?;
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(path)
        .header(hyper::header::HOST, authority)
        .body(Empty::<Bytes>::new())
        .map_err(|e| format!("build: {e}"))?;
    let res = send_request
        .send_request(req)
        .await
        .map_err(|e| format!("send: {e}"))?;
    let status = res.status();
    res.into_body()
        .collect()
        .await
        .map_err(|e| format!("body: {e}"))?;
    if !status.is_success() {
        return Err(format!("status {status}"));
    }
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
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                                hyper::body::Bytes::from(body),
                            )))
                        }
                    }),
                )
                .await;
        });
    }
}

/// Streaming HTTP/1.1 echo server on 127.0.0.1:`port`: each response is
/// a chunked body of `chunks` frames of `chunk_bytes` bytes, with
/// `chunk_delay_ms` between frames. Used by the `streaming` workload.
pub async fn echo_server_streaming(port: u16, chunks: usize, chunk_bytes: usize, delay_ms: u64) {
    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("streaming echo server bind failed on port {port}: {e}");
            return;
        }
    };
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(a) => a,
            Err(_) => continue,
        };
        tokio::spawn(async move {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    hyper::service::service_fn(move |_| {
                        let chunks = chunks;
                        let chunk_bytes = chunk_bytes;
                        let delay = Duration::from_millis(delay_ms);
                        async move {
                            // A self-contained streaming body: emits
                            // `chunks` data frames of `chunk_bytes` bytes,
                            // sleeping `delay` between frames. The body is
                            // chunked (no Content-Length) so the client
                            // drains it frame-by-frame. No channel/producer
                            // task is needed - the pacing lives in the
                            // Body's poll_frame state machine.
                            let body = StreamingBody::new(chunks, chunk_bytes, delay);
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(body))
                        }
                    }),
                )
                .await;
        });
    }
}

/// A self-paced streaming response body: emits `chunks` data frames of
/// `chunk_bytes` bytes each, sleeping `delay` between frames (after the
/// first). Implements `hyper::body::Body` directly so the streaming echo
/// needs no extra feature on `http-body-util` (the `channel` feature is
/// off in the workspace). `Unpin` (all fields are `Unpin`), so `Pin<&mut
/// Self>` dereferences freely.
struct StreamingBody {
    /// Frames still to emit.
    remaining: usize,
    /// Pre-allocated reusable chunk (cloned per frame — `Bytes::clone`
    /// is a cheap Arc refcount bump, no heap allocation).
    chunk: Bytes,
    /// Inter-frame delay.
    delay: Duration,
    /// A pending sleep before the next frame, if any.
    sleep: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
}

impl StreamingBody {
    fn new(chunks: usize, chunk_bytes: usize, delay: Duration) -> Self {
        StreamingBody {
            remaining: chunks,
            chunk: Bytes::from(vec![b'x'; chunk_bytes]),
            delay,
            sleep: None,
        }
    }
}

impl hyper::body::Body for StreamingBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, std::convert::Infallible>>> {
        use std::future::Future;
        // If a sleep is pending, wait for it to fire before emitting the
        // next frame.
        if let Some(sleep) = self.sleep.as_mut() {
            if sleep.as_mut().poll(cx).is_pending() {
                return std::task::Poll::Pending;
            }
            self.sleep = None;
        }
        if self.remaining == 0 {
            return std::task::Poll::Ready(None);
        }
        let chunk = self.chunk.clone();
        self.remaining -= 1;
        // Schedule the delay before the NEXT frame (no delay after the
        // last frame, and none when the delay is zero).
        if self.remaining > 0 && !self.delay.is_zero() {
            self.sleep = Some(Box::pin(tokio::time::sleep(self.delay)));
        }
        std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(chunk))))
    }
}

// ----- HTTP/3 (QUIC) load generation, feature-gated behind `h3`. -----

mod h3 {
    use super::{acquire_permit, record_outcome, Pacer, SharedState};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use bytes::{Buf, Bytes};
    use quinn::crypto::rustls::QuicClientConfig;
    use quinn::{ClientConfig, Endpoint};
    use rustls::pki_types::ServerName;

    /// A resolved h3 target: authority (host:port), path, and the
    /// insecure-verifier flag.
    #[derive(Clone)]
    pub struct H3Target {
        pub authority: String,
        pub path: String,
        pub insecure: bool,
    }

    /// A permissive certificate verifier that accepts ANY server
    /// certificate. UNSAFE: for loopback benchmark targets only - never
    /// use against a production endpoint or any host whose cert you do
    /// not control. Selected by `--insecure`.
    #[derive(Debug)]
    struct PermissiveVerifier;

    impl rustls::client::danger::ServerCertVerifier for PermissiveVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::ED448,
            ]
        }
    }

    /// Build a rustls client config for h3 (ALPN "h3"). With
    /// `insecure`, uses the permissive verifier; otherwise the Mozilla
    /// webpki root set.
    fn h3_client_config(insecure: bool) -> Result<rustls::ClientConfig, String> {
        let mut cfg = if insecure {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PermissiveVerifier))
                .with_no_client_auth()
        } else {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        };
        cfg.alpn_protocols = vec![b"h3".to_vec()];
        Ok(cfg)
    }

    /// Build a quinn client endpoint with the h3 client config.
    fn client_endpoint(insecure: bool) -> Result<Endpoint, String> {
        let tls = h3_client_config(insecure)?;
        let quic = QuicClientConfig::try_from(Arc::new(tls))
            .map_err(|e| format!("quic client config: {e}"))?;
        let mut client_config = ClientConfig::new(Arc::new(quic));
        let _ = &mut client_config;
        let mut endpoint = Endpoint::client(
            "0.0.0.0:0"
                .parse()
                .map_err(|e| format!("client bind: {e}"))?,
        )
        .map_err(|e| format!("client endpoint: {e}"))?;
        endpoint.set_default_client_config(client_config);
        Ok(endpoint)
    }

    /// Split `host:port` into (host, port, server_name).
    fn split_authority(authority: &str) -> Result<(String, u16, String), String> {
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or_else(|| format!("authority '{authority}' missing :port"))?;
        let port: u16 = port
            .parse()
            .map_err(|e| format!("authority port '{port}': {e}"))?;
        Ok((host.to_string(), port, host.to_string()))
    }

    /// Resolve `host:port` to a SocketAddr via async DNS (handles both
    /// IP literals and hostnames).
    async fn resolve_authority(authority: &str) -> Result<std::net::SocketAddr, String> {
        let (host, port, _server_name) = split_authority(authority)?;
        // Fast path: it is already an IP literal.
        if let Ok(addr) = format!("{host}:{port}").parse::<std::net::SocketAddr>() {
            return Ok(addr);
        }
        // Hostname: async DNS lookup, first answer. Pass an owned
        // `(String, u16)` so the lookup future does not borrow `host`
        // (kept for the error message).
        let mut iter = tokio::net::lookup_host((host.clone(), port))
            .await
            .map_err(|e| format!("resolve {host}:{port}: {e}"))?;
        iter.next()
            .ok_or_else(|| format!("resolve {host}:{port}: no addresses"))
    }

    /// Dial one QUIC connection and wrap it in h3, returning the
    /// cloneable request sender and the driver join handle.
    async fn dial(
        endpoint: &Endpoint,
        target: &H3Target,
    ) -> Result<
        (
            h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
            tokio::task::JoinHandle<()>,
        ),
        String,
    > {
        let (_host, _port, server_name) = split_authority(&target.authority)?;
        let addr = resolve_authority(&target.authority).await?;
        let conn = endpoint
            .connect(addr, &server_name)
            .map_err(|e| format!("quic connect: {e}"))?
            .await
            .map_err(|e| format!("quic handshake: {e}"))?;
        let (mut h3_conn, send_request) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .map_err(|e| format!("h3 client: {e}"))?;
        let driver = tokio::spawn(async move {
            let _ = h3_conn.wait_idle().await;
        });
        Ok((send_request, driver))
    }

    /// One h3 request over a `SendRequest` (one stream per call).
    async fn do_request_h3(
        send_request: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
        authority: &str,
        path: &str,
    ) -> Result<(), String> {
        let req = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(path)
            .header(hyper::header::HOST, authority)
            .body(())
            .map_err(|e| format!("build: {e}"))?;
        let mut stream = send_request
            .send_request(req)
            .await
            .map_err(|e| format!("h3 send_request: {e}"))?;
        stream
            .finish()
            .await
            .map_err(|e| format!("h3 finish: {e}"))?;
        let resp = stream
            .recv_response()
            .await
            .map_err(|e| format!("h3 recv_response: {e}"))?;
        let status = resp.status();
        while let Some(mut chunk) = stream
            .recv_data()
            .await
            .map_err(|e| format!("h3 recv_data: {e}"))?
        {
            let bytes = chunk.copy_to_bytes(chunk.remaining());
            let _ = bytes;
        }
        let _ = stream.recv_trailers().await;
        if !status.is_success() {
            return Err(format!("status {status}"));
        }
        Ok(())
    }

    /// One h3 request over an owned connection, dialing first if the
    /// connection is absent. Mirrors the h1/h2 owned-request helpers.
    async fn do_request_h3_owned(
        endpoint: &Endpoint,
        conn: &mut Option<(
            h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
            tokio::task::JoinHandle<()>,
        )>,
        target: &H3Target,
    ) -> Result<(), String> {
        if conn.is_none() {
            let (sr, driver) = dial(endpoint, target).await?;
            *conn = Some((sr, driver));
        }
        let sr = &mut conn.as_mut().expect("h3 conn present").0;
        do_request_h3(sr, &target.authority, &target.path).await
    }

    /// h3 owned-connection worker: one QUIC connection, back-to-back
    /// streams.
    pub async fn worker_h3(
        target: H3Target,
        deadline: Instant,
        timeout: Duration,
        pacer: Arc<Pacer>,
        shared: Arc<SharedState>,
    ) {
        let endpoint = match client_endpoint(target.insecure) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("h3 endpoint build failed: {e}");
                return;
            }
        };
        let mut conn: Option<(
            h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
            tokio::task::JoinHandle<()>,
        )> = None;
        // Warmup (unrecorded).
        let _ =
            tokio::time::timeout(timeout, do_request_h3_owned(&endpoint, &mut conn, &target)).await;
        while Instant::now() < deadline {
            acquire_permit(&pacer, deadline).await;
            if Instant::now() >= deadline {
                break;
            }
            let start = Instant::now();
            let outcome =
                tokio::time::timeout(timeout, do_request_h3_owned(&endpoint, &mut conn, &target))
                    .await;
            let elapsed = start.elapsed();
            if !matches!(outcome, Ok(Ok(()))) {
                if let Some((_, driver)) = conn.take() {
                    driver.abort();
                }
            }
            record_outcome(&shared, elapsed, outcome.map_err(|_| ()), timeout);
        }
        if let Some((_, driver)) = conn.take() {
            driver.abort();
        }
    }

    /// Establish one shared h3 connection for the pool-reuse workload.
    /// Returns the `Endpoint` (must be kept alive for the duration of
    /// the run — dropping it closes the UDP socket and kills the QUIC
    /// connection), the cloneable `SendRequest`, and the driver
    /// `JoinHandle` (also must be kept alive).
    pub async fn shared_h3_connection(
        target: &H3Target,
    ) -> Result<
        (
            Endpoint,
            h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
            tokio::task::JoinHandle<()>,
        ),
        String,
    > {
        let endpoint = client_endpoint(target.insecure)?;
        let (sr, driver) = dial(&endpoint, target).await?;
        Ok((endpoint, sr, driver))
    }

    /// h3 pool-reuse worker: each worker holds its own clone of the h3
    /// `SendRequest` (Clone — clones share the same QUIC connection but
    /// can issue concurrent streams without mutex serialization). This
    /// exercises real h3 stream multiplexing: many workers, many
    /// concurrent streams, one QUIC connection.
    pub async fn worker_pooled_h3(
        mut send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
        target: H3Target,
        deadline: Instant,
        timeout: Duration,
        pacer: Arc<Pacer>,
        shared: Arc<SharedState>,
    ) {
        // Warmup (unrecorded).
        let _ = tokio::time::timeout(timeout, async {
            do_request_h3(&mut send_request, &target.authority, &target.path).await
        })
        .await;
        while Instant::now() < deadline {
            acquire_permit(&pacer, deadline).await;
            if Instant::now() >= deadline {
                break;
            }
            let start = Instant::now();
            let outcome = tokio::time::timeout(timeout, async {
                do_request_h3(&mut send_request, &target.authority, &target.path).await
            })
            .await;
            let elapsed = start.elapsed();
            record_outcome(&shared, elapsed, outcome.map_err(|_| ()), timeout);
        }
    }
}

pub use h3::{shared_h3_connection, worker_h3, worker_pooled_h3, H3Target};

/// Print the human block + RESULT line (+ optional JSON line); returns
/// the exit code (1 iff any request failed).
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
        "protocol={} workload={} connections={} duration={}s rate={}",
        args.protocol.as_str(),
        args.workload.as_str(),
        args.connections,
        args.duration,
        args.rate
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
    if args.json {
        // The JSON line carries the protocol/workload labels so the
        // regression gate can key each workload independently. serde_json
        // is already a workspace dependency of dwara-cli (the `schema`
        // subcommand); no new external crate enters the tree.
        let json = serde_json::json!({
            "protocol": args.protocol.as_str(),
            "workload": args.workload.as_str(),
            "connections": args.connections,
            "duration_s": args.duration,
            "rate": args.rate,
            "requests": totals.requests,
            "errors": totals.errors,
            "rps": rps,
            "p50_ns": p50,
            "p90_ns": p90,
            "p99_ns": p99,
            "p999_ns": p999,
            "err_p99_ns": err_p99,
        });
        println!("JSON: {json}");
    }
    if totals.errors > 0 {
        1
    } else {
        0
    }
}
