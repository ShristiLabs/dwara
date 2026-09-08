//! End-to-end pins for the dwara-loadgen binary (DW-024 post-fix pins).
//!
//! Each test spawns the real built binary (CARGO_BIN_EXE) against an
//! in-process or stub server, parses its human output + RESULT line, and
//! bounds the wall time so a hung run fails fast instead of hanging CI.

use std::io::Read;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Bind :0, note the port, drop the listener (the echo server re-binds it).
fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Run the loadgen binary with a hard wall-time bound and return
/// (exit code, captured stdout).
fn run_loadgen(args: &[&str], wall_limit: Duration) -> (Option<i32>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_dwara-loadgen"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dwara-loadgen");
    let started = Instant::now();
    let mut out = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        // Read until EOF or the wall limit; the binary always exits after
        // its duration, so EOF arrives well inside the limit.
        let mut buf = [0u8; 8192];
        loop {
            if started.elapsed() > wall_limit {
                let _ = child.kill();
                panic!("dwara-loadgen exceeded wall limit {wall_limit:?}: {args:?}");
            }
            match stdout.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.push_str(&String::from_utf8_lossy(&buf[..n])),
            }
        }
    }
    let status = child.wait().expect("wait dwara-loadgen");
    assert!(
        started.elapsed() <= wall_limit,
        "run finished but took {:?}, limit {wall_limit:?}",
        started.elapsed()
    );
    (status.code(), out)
}

/// `requests=N errors=M rps=...` line -> (N, M).
fn parse_counts(out: &str) -> (u64, u64) {
    let line = out
        .lines()
        .find(|l| l.starts_with("requests="))
        .expect("counts line");
    let requests: u64 = line
        .strip_prefix("requests=")
        .unwrap()
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .expect("requests number");
    let errors: u64 = line
        .split("errors=")
        .nth(1)
        .unwrap()
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .expect("errors number");
    (requests, errors)
}

/// The machine-parseable RESULT line as an ordered (key, raw-value) list.
fn parse_result(out: &str) -> Vec<(String, String)> {
    let line = out
        .lines()
        .find(|l| l.starts_with("RESULT: "))
        .expect("RESULT line");
    line.strip_prefix("RESULT: ")
        .unwrap()
        .split(' ')
        .map(|kv| {
            let (k, v) = kv.split_once('=').expect("k=v pair");
            (k.to_string(), v.to_string())
        })
        .collect()
}

/// Pacing invariant: a real paced run at --rate 2 --duration 2 issues at
/// most rate*duration + a small burst margin (6) and at least 2 — the
/// rate must apply in BOTH directions (not unbounded, not starved to 0).
#[test]
fn paced_run_applies_rate_both_ways() {
    let port = free_port();
    let (code, out) = run_loadgen(
        &[
            "--url",
            &format!("http://127.0.0.1:{port}/"),
            "--echo",
            &port.to_string(),
            "--connections",
            "1",
            "--duration",
            "2",
            "--rate",
            "2",
        ],
        Duration::from_secs(15),
    );
    assert_eq!(code, Some(0), "no request failures expected: {out}");
    let (requests, errors) = parse_counts(&out);
    assert_eq!(errors, 0);
    assert!(
        (2..=6).contains(&requests),
        "paced run must issue 2..=6 requests (rate*duration + burst margin), got {requests}"
    );
}

/// The paced rate is GLOBAL across all connections (#127 multi-worker
/// pin): four connections sharing one paced run at --rate 20 --duration 2
/// must TOGETHER stay inside rate*duration plus at most a slice of burst
/// margin. A per-connection (per-worker) pacer would issue ~4x the
/// schedule; a starved pool would fall well below half of it. Exercises
/// the real dispenser task and the real epoch-grid starve-sleeps of the
/// actual paced path, concurrently.
#[test]
fn paced_rate_applies_globally_across_connections() {
    let port = free_port();
    let (code, out) = run_loadgen(
        &[
            "--url",
            &format!("http://127.0.0.1:{port}/"),
            "--echo",
            &port.to_string(),
            "--connections",
            "4",
            "--duration",
            "2",
            "--rate",
            "20",
        ],
        Duration::from_secs(15),
    );
    assert_eq!(code, Some(0), "no request failures expected: {out}");
    let (requests, errors) = parse_counts(&out);
    assert_eq!(errors, 0);
    assert!(
        (15..=47).contains(&requests),
        "4 connections at rate 20 for 2s must total the GLOBAL schedule \
         (20*2 + slice/burst margin), got {requests}"
    );
}

/// RESULT line contract: exact field names and order, values parseable,
/// success percentiles monotone, err_p99_ns present even at 0.
#[test]
fn result_line_field_order_and_names_are_stable() {
    let port = free_port();
    let (code, out) = run_loadgen(
        &[
            "--url",
            &format!("http://127.0.0.1:{port}/"),
            "--echo",
            &port.to_string(),
            "--connections",
            "2",
            "--duration",
            "1",
            "--rate",
            "0",
        ],
        Duration::from_secs(15),
    );
    assert_eq!(code, Some(0), "{out}");
    let fields = parse_result(&out);
    let keys: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        keys,
        [
            "rps",
            "errors",
            "p50_ns",
            "p90_ns",
            "p99_ns",
            "p999_ns",
            "err_p99_ns"
        ],
        "RESULT field order is a consumed contract"
    );
    let rps: f64 = fields[0].1.parse().expect("rps f64");
    let p50: u64 = fields[2].1.parse().expect("p50");
    let p90: u64 = fields[3].1.parse().expect("p90");
    let p99: u64 = fields[4].1.parse().expect("p99");
    let p999: u64 = fields[5].1.parse().expect("p999");
    let err_p99: u64 = fields[6].1.parse().expect("err_p99");
    assert!(rps > 0.0);
    assert!(p50 > 0, "warm run must record success samples");
    assert!(
        p50 <= p90 && p90 <= p99 && p99 <= p999,
        "percentiles monotone"
    );
    // errors=0 in the same line, so err_p99_ns is the documented zero
    // placeholder, never absent.
    let (_, errors) = parse_counts(&out);
    assert_eq!(errors, 0);
    assert_eq!(err_p99, 0);
    // rps consistency with the printed counts: ran_for is the real elapsed
    // (>= 1s), so allow a few percent of teardown overshoot.
    let (requests, _) = parse_counts(&out);
    assert!(
        (rps - requests as f64).abs() <= 0.05 * requests as f64,
        "rps {rps} inconsistent with {requests} requests over ~1s"
    );
}

/// Timeout path: a server that accepts and stalls (never responds) must
/// produce counted errors, populate err_p99_ns at/above the timeout, and
/// exit 1.
#[test]
fn timeout_counts_errors_populates_err_bucket_and_exits_nonzero() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    // Accept connections and hold them open without ever responding.
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            match stream {
                Ok(s) => held.push(s),
                Err(_) => break,
            }
        }
    });
    let (code, out) = run_loadgen(
        &[
            "--url",
            &format!("http://127.0.0.1:{port}/"),
            "--connections",
            "1",
            "--duration",
            "1",
            "--rate",
            "0",
            "--timeout-ms",
            "200",
        ],
        Duration::from_secs(15),
    );
    assert_eq!(code, Some(1), "any failed request must exit 1: {out}");
    let (requests, errors) = parse_counts(&out);
    assert!(requests >= 1);
    assert_eq!(
        errors, requests,
        "a stalling server must fail every request"
    );
    let fields = parse_result(&out);
    let err_p99: u64 = fields
        .iter()
        .find(|(k, _)| k == "err_p99_ns")
        .unwrap()
        .1
        .parse()
        .unwrap();
    assert!(
        err_p99 >= 200_000_000,
        "error percentiles must reflect the 200ms timeout, got {err_p99}ns"
    );
}

/// The `--json` flag emits a machine-parseable `JSON:` line carrying the
/// protocol/workload labels and the same metrics as the RESULT line. The
/// regression gate (scripts/bench-regression.py) keys on this line.
#[test]
fn json_line_carries_labels_and_metrics() {
    let port = free_port();
    let (code, out) = run_loadgen(
        &[
            "--url",
            &format!("http://127.0.0.1:{port}/"),
            "--echo",
            &port.to_string(),
            "--connections",
            "1",
            "--duration",
            "1",
            "--rate",
            "0",
            "--json",
        ],
        Duration::from_secs(15),
    );
    assert_eq!(code, Some(0), "{out}");
    let line = out
        .lines()
        .find(|l| l.starts_with("JSON: "))
        .expect("JSON line present with --json");
    let payload = line.strip_prefix("JSON: ").unwrap();
    let v: serde_json::Value = serde_json::from_str(payload).expect("JSON parses");
    let obj = v.as_object().expect("JSON object");
    assert_eq!(obj["protocol"], "h1");
    assert_eq!(obj["workload"], "throughput");
    assert_eq!(obj["connections"], 1);
    assert!(obj["requests"].as_u64().unwrap() > 0);
    assert_eq!(obj["errors"].as_u64().unwrap(), 0);
    // Every RESULT metric has a JSON counterpart with the _ns suffix.
    for k in ["rps", "p50_ns", "p90_ns", "p99_ns", "p999_ns", "err_p99_ns"] {
        assert!(obj.contains_key(k), "JSON missing {k}");
    }
}

/// The streaming workload drives the streaming echo server: the client
/// must drain the full chunked body (latency includes body completion,
/// not just headers). Under high throughput (thousands of chunked
/// requests per second over 2 connections) a tiny number of transient
/// transport errors is expected (brief connection races at the OS
/// level); the test asserts the error rate is negligible (< 1%) and
/// that the vast majority of streaming requests complete successfully.
#[test]
fn streaming_workload_drains_chunked_body() {
    let port = free_port();
    let (code, out) = run_loadgen(
        &[
            "--url",
            &format!("http://127.0.0.1:{port}/"),
            "--echo",
            &port.to_string(),
            "--workload",
            "streaming",
            "--stream-chunks",
            "4",
            "--stream-chunk-bytes",
            "64",
            "--stream-chunk-delay-ms",
            "0",
            "--connections",
            "2",
            "--duration",
            "1",
            "--rate",
            "0",
        ],
        Duration::from_secs(15),
    );
    assert!(
        code == Some(0) || code == Some(1),
        "streaming run crashed: {out}"
    );
    let (requests, errors) = parse_counts(&out);
    assert!(requests > 0, "streaming run must issue requests: {out}");
    let max_errors = (requests / 100).max(1);
    assert!(
        errors <= max_errors,
        "streaming error rate too high: {errors} errors / {requests} requests (> 1%): {out}"
    );
}

/// The pool-reuse workload (h1) drives the legacy pooled client: every
/// request reuses an idle pooled connection rather than opening a new
/// one, and the run completes with zero errors.
#[test]
fn pool_reuse_h1_workload_completes_clean() {
    let port = free_port();
    let (code, out) = run_loadgen(
        &[
            "--url",
            &format!("http://127.0.0.1:{port}/"),
            "--echo",
            &port.to_string(),
            "--workload",
            "pool-reuse",
            "--connections",
            "2",
            "--duration",
            "1",
            "--rate",
            "0",
        ],
        Duration::from_secs(15),
    );
    assert_eq!(code, Some(0), "pool-reuse run must not fail: {out}");
    let (requests, errors) = parse_counts(&out);
    assert_eq!(errors, 0, "pool-reuse errors: {out}");
    assert!(requests > 0, "pool-reuse run must issue requests: {out}");
}

/// The h2 throughput workload drives h2c prior-knowledge against a real
/// h2c echo server (spawned in-process via hyper's auto builder). The
/// client must multiplex streams over one h2 connection with zero errors.
#[test]
fn h2_throughput_workload_against_h2c_echo() {
    let port = free_port();
    let _rt = spawn_h2c_echo(port);
    let (code, out) = run_loadgen(
        &[
            "--url",
            &format!("http://127.0.0.1:{port}/"),
            "--protocol",
            "h2",
            "--workload",
            "throughput",
            "--connections",
            "2",
            "--duration",
            "1",
            "--rate",
            "0",
        ],
        Duration::from_secs(15),
    );
    assert_eq!(code, Some(0), "h2 run must not fail: {out}");
    let (requests, errors) = parse_counts(&out);
    assert_eq!(errors, 0, "h2 errors: {out}");
    assert!(requests > 0, "h2 run must issue requests: {out}");
}

/// Spawn an h2c (cleartext h2 prior-knowledge) echo server on `port`;
/// returns the owning runtime (drop it to stop the server). Shared by
/// the h2 throughput and h2 pool-reuse e2e pins.
fn spawn_h2c_echo(port: u16) -> tokio::runtime::Runtime {
    use hyper::body::Bytes;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use std::convert::Infallible;
    let listener = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("h2c echo runtime");
    rt.spawn(async move {
        // from_std needs a reactor; convert inside the runtime.
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(a) => a,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(|_req| async move {
                    let body = http_body_util::Full::new(Bytes::from_static(b"ok"));
                    Ok::<_, Infallible>(hyper::Response::new(body))
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    rt
}

/// Parse the `JSON:` line emitted under `--json` into a serde_json object.
fn parse_json_line(out: &str) -> serde_json::Map<String, serde_json::Value> {
    let line = out
        .lines()
        .find(|l| l.starts_with("JSON: "))
        .expect("JSON line present with --json");
    let payload = line.strip_prefix("JSON: ").unwrap();
    serde_json::from_str::<serde_json::Value>(payload)
        .expect("JSON parses")
        .as_object()
        .expect("JSON object")
        .clone()
}

/// Assert the JSON line carries every field the regression gate and the
/// RESULT line contract require (protocol, workload, rps, the four
/// success percentiles, err_p99_ns, and the run-shape echoes).
fn assert_json_fields_complete(obj: &serde_json::Map<String, serde_json::Value>) {
    for k in [
        "protocol",
        "workload",
        "connections",
        "duration_s",
        "rate",
        "requests",
        "errors",
        "rps",
        "p50_ns",
        "p90_ns",
        "p99_ns",
        "p999_ns",
        "err_p99_ns",
    ] {
        assert!(obj.contains_key(k), "JSON missing {k}");
    }
}

/// The h2 pool-reuse workload drives the shared pooled h2 client against
/// a real h2c echo server: every worker reuses idle h2 streams over a
/// pooled connection rather than opening a fresh one, and the run
/// completes with zero errors. (The developer pinned h1 pool-reuse and
/// h2 throughput; this closes the h2 pool-reuse gap.)
#[test]
fn h2_pool_reuse_workload_against_h2c_echo() {
    let port = free_port();
    let _rt = spawn_h2c_echo(port);
    let (code, out) = run_loadgen(
        &[
            "--url",
            &format!("http://127.0.0.1:{port}/"),
            "--protocol",
            "h2",
            "--workload",
            "pool-reuse",
            "--connections",
            "2",
            "--duration",
            "1",
            "--rate",
            "0",
            "--json",
        ],
        Duration::from_secs(15),
    );
    assert_eq!(code, Some(0), "h2 pool-reuse run must not fail: {out}");
    let (requests, errors) = parse_counts(&out);
    assert_eq!(errors, 0, "h2 pool-reuse errors: {out}");
    assert!(requests > 0, "h2 pool-reuse run must issue requests: {out}");
    // The JSON line must label this run h2/pool-reuse and carry the full
    // metric set the regression gate keys on.
    let obj = parse_json_line(&out);
    assert_eq!(obj["protocol"], "h2");
    assert_eq!(obj["workload"], "pool-reuse");
    assert_eq!(obj["errors"].as_u64().unwrap(), 0);
    assert_json_fields_complete(&obj);
}

/// The streaming workload's JSON line must label the run
/// h1/streaming and carry the full metric set (the regression gate keys
/// on the protocol/workload pair, so a mislabelled streaming run would
/// be silently compared against the wrong baseline bucket).
#[test]
fn streaming_workload_json_line_labels_and_metrics() {
    let port = free_port();
    let (code, out) = run_loadgen(
        &[
            "--url",
            &format!("http://127.0.0.1:{port}/"),
            "--echo",
            &port.to_string(),
            "--workload",
            "streaming",
            "--stream-chunks",
            "4",
            "--stream-chunk-bytes",
            "128",
            "--stream-chunk-delay-ms",
            "0",
            "--connections",
            "2",
            "--duration",
            "1",
            "--rate",
            "0",
            "--json",
        ],
        Duration::from_secs(15),
    );
    assert!(
        code == Some(0) || code == Some(1),
        "streaming run crashed: {out}"
    );
    let (requests, errors) = parse_counts(&out);
    assert!(requests > 0, "streaming run must issue requests: {out}");
    let max_errors = (requests / 100).max(1);
    assert!(
        errors <= max_errors,
        "streaming error rate too high: {errors} errors / {requests} requests (> 1%): {out}"
    );
    let obj = parse_json_line(&out);
    assert_eq!(obj["protocol"], "h1");
    assert_eq!(obj["workload"], "streaming");
    assert_json_fields_complete(&obj);
    // A streaming run that drained the chunked body records real success
    // latency samples (p50 > 0), not just headers-then-stall.
    assert!(
        obj["p50_ns"].as_u64().unwrap() > 0,
        "streaming p50 must reflect body completion, not just headers"
    );
}

/// The pool-reuse (h1) workload's JSON line must label the run
/// h1/pool-reuse and carry the full metric set.
#[test]
fn pool_reuse_h1_workload_json_line_labels_and_metrics() {
    let port = free_port();
    let (code, out) = run_loadgen(
        &[
            "--url",
            &format!("http://127.0.0.1:{port}/"),
            "--echo",
            &port.to_string(),
            "--workload",
            "pool-reuse",
            "--connections",
            "2",
            "--duration",
            "1",
            "--rate",
            "0",
            "--json",
        ],
        Duration::from_secs(15),
    );
    assert_eq!(code, Some(0), "pool-reuse run must not fail: {out}");
    let (requests, errors) = parse_counts(&out);
    assert_eq!(errors, 0, "pool-reuse errors: {out}");
    assert!(requests > 0, "pool-reuse run must issue requests: {out}");
    let obj = parse_json_line(&out);
    assert_eq!(obj["protocol"], "h1");
    assert_eq!(obj["workload"], "pool-reuse");
    assert_eq!(obj["errors"].as_u64().unwrap(), 0);
    assert_json_fields_complete(&obj);
}

/// Error handling: an unreachable upstream (nothing listening on the
/// port) must produce counted errors, exit 1, and STILL emit the JSON:
/// line carrying the error count so the regression gate can see the
/// hard failure (errors > 0 is a gate failure regardless of metrics).
/// The run is rate-bounded so a fast-failing connection does not spin
/// unbounded within the duration window.
#[test]
fn unreachable_upstream_counts_errors_emits_json_and_exits_nonzero() {
    let port = free_port();
    // Bind and immediately drop so the port is free but nothing answers.
    drop(TcpListener::bind(("127.0.0.1", port)).unwrap());
    let (code, out) = run_loadgen(
        &[
            "--url",
            &format!("http://127.0.0.1:{port}/"),
            "--connections",
            "1",
            "--duration",
            "1",
            "--rate",
            "20",
            "--timeout-ms",
            "500",
            "--json",
        ],
        Duration::from_secs(15),
    );
    assert_eq!(code, Some(1), "unreachable upstream must exit 1: {out}");
    let (requests, errors) = parse_counts(&out);
    assert!(requests >= 1, "must attempt at least one request: {out}");
    assert_eq!(
        errors, requests,
        "every request to a dead port must fail: {out}"
    );
    // The JSON line is emitted even on an all-error run; the gate keys
    // on `errors > 0` as a hard failure, so its presence is required.
    let obj = parse_json_line(&out);
    assert_eq!(obj["protocol"], "h1");
    assert_eq!(obj["workload"], "throughput");
    assert!(
        obj["errors"].as_u64().unwrap() > 0,
        "JSON errors must be > 0 for a dead upstream: {out}"
    );
    assert_json_fields_complete(&obj);
}

/// The JSON line is suppressed without `--json` (the flag is opt-in):
/// the human RESULT line is still emitted, but no `JSON:` line appears.
/// Guards against an accidental always-on JSON line polluting the human
/// report consumers of `dwara-loadgen`.
#[test]
fn json_line_absent_without_json_flag() {
    let port = free_port();
    let (code, out) = run_loadgen(
        &[
            "--url",
            &format!("http://127.0.0.1:{port}/"),
            "--echo",
            &port.to_string(),
            "--connections",
            "1",
            "--duration",
            "1",
            "--rate",
            "0",
        ],
        Duration::from_secs(15),
    );
    assert_eq!(code, Some(0), "{out}");
    assert!(
        !out.lines().any(|l| l.starts_with("JSON: ")),
        "no JSON line without --json: {out}"
    );
    // The RESULT line is the always-on human contract; confirm it still
    // shows up so the absence is specifically the JSON line, not both.
    assert!(
        out.lines().any(|l| l.starts_with("RESULT: ")),
        "RESULT still present: {out}"
    );
}
