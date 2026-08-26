//! Unit tests for the load-generator rig (DW-024), relocated from the
//! `dwara-loadgen` bin into an integration test against the public lib
//! API: histogram subsampling math, CLI shape, and the warmup-exclusion
//! invariant. (The end-to-end pins live in `loadgen_e2e.rs`.)

use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use dwara_cli::loadgen::*;

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
