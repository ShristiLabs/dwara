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
