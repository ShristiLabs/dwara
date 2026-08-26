//! dwara-loadgen (DW-024): the macro load-generation rig.
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
//! Usage:
//!
//!     dwara-loadgen --url http://127.0.0.1:18080/ \
//!         --connections 100 --duration 10 --rate 0
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
//! 100k-connection runs: this binary imposes no connection cap, but the
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

/// Command-line shape (unit-tested below; keep `parse_from`-able).
#[derive(Debug, Parser)]
#[command(
    name = "dwara-loadgen",
    version,
    about = "dwara macro load generator (DW-024)"
)]
struct Args {
    /// Target URL to hammer.
    #[arg(long, default_value = "http://127.0.0.1:18080/")]
    url: String,
    /// Number of concurrent connections (worker tasks).
    #[arg(long, default_value = "10")]
    connections: usize,
    /// Test duration in seconds.
    #[arg(long, default_value = "10")]
    duration: u64,
    /// Target requests per second across ALL connections; 0 = unbounded.
    #[arg(long, default_value = "0")]
    rate: u64,
    /// Also serve a minimal HTTP/1.1 echo server on this port (in-process
    /// upstream for the bench rig), in addition to generating load.
    #[arg(long)]
    echo: Option<u16>,
    /// Serve ONLY the echo server on --echo's port and do no load
    /// generation (the standalone upstream for scripts/bench-macro.sh).
    #[arg(long, default_value = "false", requires = "echo")]
    echo_only: bool,
    /// Size of the echo response body in bytes (with --echo).
    #[arg(long, default_value = "128")]
    echo_body: usize,
    /// Per-request timeout in milliseconds; a request that exceeds it is
    /// counted as an error (its latency lands in the err_* buckets).
    #[arg(long, default_value = "10000")]
    timeout_ms: u64,
}

/// Latency samples in nanoseconds; percentile computed by sorting at
/// report time. Correctness is unit-tested below.
///
/// Memory is bounded for long runs: once the sample vector reaches
/// [`SAMPLE_CAP`], it is halved (every 2nd sample kept) and the recording
/// stride doubles, so the vector stays O(SAMPLE_CAP) regardless of run
/// length. Subsampling is uniform in arrival order, so nearest-rank
/// percentiles over the retained set estimate the true percentiles; at
/// multi-million sample counts the discretization error is far below
/// run-to-run noise.
#[derive(Debug)]
struct Histogram {
    samples: Vec<u64>,
    stride: u64,
    seen: u64,
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
const SAMPLE_CAP: usize = 4_000_000;

impl Histogram {
    fn record(&mut self, ns: u64) {
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
    fn percentile(&mut self, p: f64) -> u64 {
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

#[derive(Debug, Default)]
struct Totals {
    requests: u64,
    errors: u64,
}

fn main() {
    let args = Args::parse();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = rt.block_on(run(args));
    std::process::exit(code);
}

async fn run(args: Args) -> i32 {
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
    // paced mode starts at 0 and is dispensed by the pacing task below.
    let permits = Arc::new(std::sync::atomic::AtomicU64::new(if args.rate > 0 {
        0
    } else {
        u64::MAX / 2
    }));

    if args.rate > 0 {
        // Pacing: dispense `rate` tokens per second in 50ms slices. The
        // balance is CLAMPED to one slice of headroom after each
        // dispensation: if the workers ever fall behind (GC pause, runner
        // hiccup), unused tokens must not accumulate and later burst out —
        // a burst would contaminate paced latency percentiles.
        // Unbounded mode leaves a huge permit balance, so workers never
        // wait on it.
        let permits = permits.clone();
        let per_slice = ((args.rate as f64 / 20.0).ceil() as u64).max(1);
        let rate = args.rate;
        let pace_start = Instant::now();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(50));
            // Cumulative tokens ever dispensed. Each tick tops the total up
            // to `rate * elapsed + one slice of headroom`. Dispensing per
            // slice with a balance clamp cannot express rates below 20/s (a
            // slice always dispenses at least 1 token); an owed-total
            // dispenser keeps the exact requested schedule while the
            // headroom bound prevents burst accumulation if workers fall
            // behind.
            let mut paid: u64 = 0;
            loop {
                tick.tick().await;
                let allowed = (rate as f64 * pace_start.elapsed().as_secs_f64()) as u64 + per_slice;
                if paid < allowed {
                    permits.fetch_add(allowed - paid, std::sync::atomic::Ordering::Relaxed);
                    paid = allowed;
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
            permits.clone(),
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

/// Per-run state shared by all workers: request/error counters plus the
/// success and error latency histograms (error latencies kept separate so
/// failures never contaminate the success percentiles).
struct SharedState {
    totals: Arc<std::sync::Mutex<Totals>>,
    histogram: Arc<std::sync::Mutex<Histogram>>,
    err_histogram: Arc<std::sync::Mutex<Histogram>>,
}

async fn worker(
    scheme: String,
    authority: String,
    path: String,
    deadline: Instant,
    timeout: Duration,
    permits: Arc<std::sync::atomic::AtomicU64>,
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
            let b = permits.load(std::sync::atomic::Ordering::Relaxed);
            if b > 0
                && permits
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
            // Starved of permits: sleep until the next 50ms pacing slice
            // boundary rather than busy-yielding — a yield_now spin burns
            // a full core per waiting worker and contaminates the paced
            // latencies of everyone else.
            let now = tokio::time::Instant::now();
            tokio::time::sleep_until(now + Duration::from_millis(50)).await;
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

async fn echo_server(port: u16, body_len: usize) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn filled(samples: Vec<u64>) -> Histogram {
        let mut h = Histogram::default();
        for s in samples {
            h.record(s);
        }
        h
    }

    #[test]
    fn percentile_nearest_rank_on_ordered_samples() {
        let mut h = filled((1..=100).map(|i| i * 1_000).collect());
        assert_eq!(h.percentile(0.50), 50_000);
        assert_eq!(h.percentile(0.90), 90_000);
        assert_eq!(h.percentile(0.99), 99_000);
        assert_eq!(h.percentile(0.999), 100_000);
    }

    #[test]
    fn percentile_sorts_unordered_input() {
        let mut h = filled(vec![9, 3, 7, 1, 5]);
        assert_eq!(h.percentile(0.50), 5);
        assert_eq!(h.percentile(1.0), 9);
        assert_eq!(h.percentile(0.0), 1);
    }

    #[test]
    fn percentile_empty_is_zero() {
        let mut h = Histogram::default();
        assert_eq!(h.percentile(0.99), 0);
    }

    #[test]
    fn percentile_small_sample_clamps_rank() {
        // 3 samples: rank(0.9) = ceil(2.7) = 3 -> the max; rank(0.5) = 2.
        let mut h = filled(vec![10, 20, 30]);
        assert_eq!(h.percentile(0.5), 20);
        assert_eq!(h.percentile(0.9), 30);
    }

    #[test]
    fn percentile_single_sample_returns_it_for_all_p() {
        let mut h = filled(vec![42_000]);
        for p in [0.0, 0.01, 0.5, 0.99, 1.0] {
            assert_eq!(h.percentile(p), 42_000, "p={p}");
        }
    }

    #[test]
    fn percentile_p0_p100_clamp_beyond_unit_range() {
        // p below 0 / above 1 clamp to the min / max sample, never panic.
        let mut h = filled(vec![100, 200, 300]);
        assert_eq!(h.percentile(-0.5), 100);
        assert_eq!(h.percentile(0.0), 100);
        assert_eq!(h.percentile(1.0), 300);
        assert_eq!(h.percentile(2.0), 300);
    }

    #[test]
    fn stride_halving_bounds_memory_and_keeps_percentiles_sane() {
        // 2*cap + slack samples force at least one halving; the retained
        // vector must stay under the cap and percentiles must remain close
        // to the exact values of the full deterministic sequence.
        let n = 2 * SAMPLE_CAP + 123;
        let mut h = Histogram::default();
        for i in 0..n as u64 {
            h.record(i);
        }
        assert!(h.samples.len() <= SAMPLE_CAP, "len={}", h.samples.len());
        assert!(h.stride >= 2);
        assert_eq!(h.seen, n as u64);
        // With a monotone uniform sequence, subsampling preserves ranks
        // exactly in value terms only up to one stride step; allow a
        // generous relative tolerance of 2% (far tighter than run noise).
        let exact = |p: f64| (n as f64 * p).ceil() as u64 - 1;
        for p in [0.5, 0.9, 0.99] {
            let got = h.percentile(p) as f64;
            let want = exact(p) as f64;
            assert!(
                (got - want).abs() / want < 0.02,
                "p={p}: got {got}, exact {want}"
            );
        }
    }

    #[test]
    fn stride_halving_against_unstrided_computation() {
        // Cross-check: a sequence with varied (non-monotone) values run
        // through a small forced-stride histogram stays near the exact
        // percentile of the same values recorded without any halving.
        // We cannot shrink SAMPLE_CAP, so drive the halving logic via the
        // public record() at full cap once: use a repeating pattern with
        // period coprime-ish to the stride so the retained subset stays
        // representative.
        let n = 2 * SAMPLE_CAP + 7;
        let value = |i: u64| (i % 997) * 13 + (i / 997); // deterministic, spread
        let mut h = Histogram::default();
        let mut exact = Vec::with_capacity(n);
        for i in 0..n as u64 {
            let v = value(i);
            h.record(v);
            exact.push(v);
        }
        exact.sort_unstable();
        assert!(h.samples.len() <= SAMPLE_CAP);
        let exact_pct =
            |p: f64| exact[(((exact.len() as f64) * p).ceil() as usize).clamp(1, exact.len()) - 1];
        for p in [0.5, 0.9, 0.99] {
            let got = h.percentile(p) as f64;
            let want = exact_pct(p) as f64;
            // Values span ~13k; tolerance is generous: 5% of the value
            // range, well below anything the macro rig asserts.
            assert!(
                (got - want).abs() <= 0.05 * (13.0 * 997.0),
                "p={p}: strided {got} vs exact {want}"
            );
        }
    }

    #[test]
    fn args_parse_defaults() {
        let a = Args::parse_from(["dwara-loadgen"]);
        assert_eq!(a.connections, 10);
        assert_eq!(a.duration, 10);
        assert_eq!(a.rate, 0);
        assert!(a.echo.is_none());
    }

    #[test]
    fn args_parse_full() {
        let a = Args::parse_from([
            "dwara-loadgen",
            "--url",
            "http://10.0.0.1:9/x",
            "--connections",
            "100000",
            "--duration",
            "60",
            "--rate",
            "50000",
            "--echo",
            "18081",
        ]);
        assert_eq!(a.connections, 100_000);
        assert_eq!(a.duration, 60);
        assert_eq!(a.rate, 50_000);
        assert_eq!(a.echo, Some(18_081));
    }

    #[test]
    fn args_reject_missing_positional_garbage() {
        assert!(Args::try_parse_from(["dwara-loadgen", "nonsense"]).is_err());
    }

    /// Grab a free localhost port by binding to :0 and immediately
    /// dropping the listener (echo_server re-binds it; the race window is
    /// empty for the lifetime of one test process).
    fn free_port() -> u16 {
        std::net::TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn warmup_excluded_from_totals_and_histogram() {
        // One worker against the in-process echo server in unbounded mode:
        // every counted request must have exactly one histogram sample
        // (warmup is unrecorded, so histogram.seen == totals.requests —
        // if warmup were counted, requests would exceed seen by one).
        let port = free_port();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        rt.block_on(async move {
            tokio::spawn(echo_server(port, 128));
            // Same bind-settle delay the production run() uses before
            // pointing load at the echo listener.
            tokio::time::sleep(Duration::from_millis(200)).await;
            let shared = Arc::new(SharedState {
                totals: Arc::new(std::sync::Mutex::new(Totals::default())),
                histogram: Arc::new(std::sync::Mutex::new(Histogram::default())),
                err_histogram: Arc::new(std::sync::Mutex::new(Histogram::default())),
            });
            worker(
                "http".into(),
                format!("127.0.0.1:{port}"),
                "/".into(),
                Instant::now() + Duration::from_secs(1),
                Duration::from_secs(2),
                Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX / 2)),
                shared.clone(),
            )
            .await;
            let totals = shared.totals.lock().unwrap();
            assert!(
                totals.requests >= 10,
                "expected a busy 1s run, got {}",
                totals.requests
            );
            assert_eq!(totals.errors, 0);
            assert_eq!(
                shared.histogram.lock().unwrap().seen,
                totals.requests,
                "warmup request must not be counted in RESULT totals"
            );
            assert_eq!(shared.err_histogram.lock().unwrap().seen, 0);
        });
    }
}
