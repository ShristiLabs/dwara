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

// Pacing dispenser catch-up cap (#127): the top-up target is
// min(owed schedule, consumed + one slice), so an idle worker accrues no
// dischargeable backlog, while steady-state dispensing (consumption on
// schedule) is unchanged.

#[test]
fn pace_top_up_caps_backlog_not_schedule() {
    let s = 25;
    // Idle worker (all dispensed permits still on the balance): the
    // schedule's owed total explodes but NOTHING further is dispensed —
    // backlog accrual is impossible.
    assert_eq!(pace_top_up(1_000_000, 25, 25, s), 0);
    assert_eq!(pace_top_up(u64::MAX, 25, 25, s), 0);
    // Resume with everything consumed: at most ONE slice this tick,
    // however far behind the schedule is — that is the bounded catch-up.
    assert_eq!(pace_top_up(1_000_000, 25, 0, s), s);
    // Steady state (consumption exactly on schedule): one slice per
    // tick, same as an uncapped owed-total dispenser — pacing unchanged.
    assert_eq!(pace_top_up(1_025, 1_000, 0, s), s);
    // Sub-slice rates stay expressible: the owed total, not the slice,
    // decides when the first token appears (rate < 20/s case).
    assert_eq!(pace_top_up(3, 0, 0, 1), 1);
    // Schedule momentarily behind what was paid (clock rounding): the
    // saturating subtraction yields a no-op tick, never a rollback.
    assert_eq!(pace_top_up(10, 12, 2, s), 0);
}

#[test]
fn paced_dispenser_bounds_catch_up_after_idle() {
    // Deterministic tick-loop simulation of the dispenser against a
    // greedy worker that consumes every available permit on each tick,
    // idles for 40 consecutive ticks mid-run (2s at 50ms slices), then
    // resumes. Under the old owed-only top-up the balance would grow to
    // rate*2s = 1000 permits during the idle window and discharge as one
    // burst on resume; the capped top-up must bound every single-tick
    // burst to at most the accumulated slice plus the resume tick's
    // slice, and steady-state throughput must be unaffected outside the
    // idle window.
    let per_slice = 25u64; // rate 500/s -> 25 tokens per 50ms slice
    let rate = 500u64;
    let mut paid = 0u64;
    let mut permits = 0u64; // balance, single-threaded so exact
    let mut consumed = 0u64;
    let mut max_burst = 0u64;
    for tick in 0..100u64 {
        let owed = rate * tick / 20 + per_slice; // schedule at t = tick*50ms
        let add = pace_top_up(owed, paid, permits, per_slice);
        permits += add;
        paid += add;
        let idle = (20..60).contains(&tick);
        if !idle {
            let burst = permits;
            permits = 0;
            consumed += burst;
            max_burst = max_burst.max(burst);
        }
    }
    assert!(
        max_burst <= 2 * per_slice,
        "post-idle burst must be bounded by ~one slice, got {max_burst}"
    );
    // 60 active ticks at one slice each (the idle window forfeits its
    // credit by design — that forfeit IS the burst bound); allow one
    // slice of scheduling slack so this pins behavior, not arithmetic.
    assert!(
        (59..=61).contains(&(consumed / per_slice)),
        "steady-state pacing outside the idle window must be unchanged, consumed {consumed}"
    );
}

// Starve-sleep epoch alignment (#127): starved workers sleep to the NEXT
// boundary of the dispenser's epoch grid (epoch + k*PACE_SLICE), never to
// an independent now+50ms that can drift a full slice against it.

#[test]
fn until_next_tick_lands_on_the_epoch_grid() {
    let epoch = Instant::now();
    let at = |ms: u64| epoch + Duration::from_millis(ms);
    // Exactly on a boundary waits a FULL slice (strictly-after): a worker
    // waking on boundary k must not spin against the dispenser's own
    // dispensation on that same boundary.
    for boundary in [0, 50, 1_000] {
        assert_eq!(until_next_tick(at(boundary), epoch), PACE_SLICE);
    }
    // Off-boundary waits close exactly the phase gap to the next
    // boundary...
    assert_eq!(until_next_tick(at(49), epoch), Duration::from_millis(1));
    assert_eq!(until_next_tick(at(51), epoch), Duration::from_millis(49));
    assert_eq!(until_next_tick(at(1_234), epoch), Duration::from_millis(16));
    // ...and nothing more: every wake time is epoch + k*50ms, in (0, 50ms].
    for off in 1..50u64 {
        let now = at(off);
        let wait = until_next_tick(now, epoch);
        assert!(wait > Duration::ZERO && wait <= PACE_SLICE, "off={off}");
        assert_eq!(
            (now + wait).duration_since(epoch).as_millis() % 50,
            0,
            "wake must sit on the epoch grid, off={off}"
        );
    }
}

#[test]
fn pace_top_up_extreme_inputs_saturate_never_wrap_or_panic() {
    // per_slice = 0 (unreachable in wiring, where per_slice >= 1):
    // the dispenser simply stalls — no permits appear from nothing.
    assert_eq!(pace_top_up(1_000, 0, 0, 0), 0);
    // u64::MAX in every position: saturating add/sub keep the result
    // well-defined (no wrap-around to a huge bogus top-up, no panic).
    assert_eq!(pace_top_up(u64::MAX, u64::MAX, 0, u64::MAX), 0);
    assert_eq!(pace_top_up(u64::MAX, 0, 0, u64::MAX), u64::MAX);
    // consumed + per_slice would overflow: consumed = u64::MAX - 5,
    // per_slice = 25 -> target saturates at u64::MAX, not wrapping to 19.
    assert_eq!(
        pace_top_up(u64::MAX, u64::MAX - 5, 0, 25),
        5,
        "saturating add must cap the target at u64::MAX, add back-figures to the schedule"
    );
    // balance > paid (impossible: balance only ever holds previously
    // dispensed permits) reads as consumed = 0 via saturating sub, so
    // the tick tops paid up to one slice above that zero — defined,
    // no wrap, no panic.
    assert_eq!(pace_top_up(50, 10, 40, 25), 15);
}

#[test]
fn pace_top_up_fast_consumer_cannot_pre_pay_the_schedule() {
    let s = 25;
    // A consumer that has already outrun the schedule (paid=100, all
    // consumed, owed only 60): min() picks the OWED total — the target
    // never exceeds what the schedule has earned, so no pre-pay.
    assert_eq!(pace_top_up(60, 100, 0, s), 0);
    // consumed beyond owed but paid still behind: tops up to owed
    // exactly (target = min(owed, consumed + s) = owed).
    assert_eq!(pace_top_up(110, 100, 0, s), 10);
    // Pre-pay bound from the other side: even an infinite cap target
    // (consumed + slice) cannot push paid past owed.
    assert_eq!(pace_top_up(120, 100, 0, s), 20);
    assert_eq!(pace_top_up(1_000_000, 100, 0, s), 25);
}

// Multi-worker semantics (#127): the Pacer is ONE shared pool — the cap
// is computed from the GLOBAL consumed total, not per worker. This
// simulation pins the two cross-worker properties of the capped
// dispenser: a hungry worker is never throttled below the schedule by
// slower peers (the cap rides on consumed, which the hungry worker
// itself raises), and a worker that slows down holds at most one slice
// of buffer — its unused credit never accrues into a dischargeable
// backlog. (Which worker wins a permit within a slice is the shared
// pool's pre-existing CAS race, unchanged by the cap.)

#[test]
fn paced_dispenser_global_cap_across_mixed_speed_workers() {
    let per_slice = 25u64; // rate 500/s -> 25 tokens per 50ms slice
    let rate = 500u64;
    let mut paid = 0u64;
    let mut permits = 0u64; // global balance; single-threaded so exact
    let mut consumed = 0u64; // global consumed total
    let mut hungry_total = 0u64; // worker A: drains everything, ticks 0..50
    let mut slow_total = 0u64; // worker A after tick 50: takes 1/tick
    for tick in 0..100u64 {
        let owed = rate * tick / 20 + per_slice;
        let add = pace_top_up(owed, paid, permits, per_slice);
        // Cap invariant, every tick, GLOBALLY: the pool never holds
        // more than one slice above total consumption.
        assert!(
            permits + add <= consumed + per_slice,
            "tick {tick}: global balance {} exceeds consumed + one slice",
            permits + add
        );
        // Phase behavior asserts use `paid` BEFORE this tick's add is
        // folded in, so the schedule gap is directly comparable.
        if tick < 50 {
            // Phase 1 — hungry worker: dispensing runs at full schedule
            // rate (the cap is not binding while consumption keeps up).
            assert_eq!(
                add,
                (owed - paid).min(per_slice),
                "tick {tick}: hungry worker must never be throttled below schedule"
            );
        } else if tick == 50 {
            // Phase transition: the phase-1 drain left the pool empty,
            // so this one refill of a full slice is legitimate (still
            // inside the cap); from the NEXT tick the cap must bind.
            assert!(
                add <= per_slice,
                "tick {tick}: transition refill beyond a slice"
            );
        } else {
            // Phase 2 — same worker now takes 1 per tick (e.g. its RTT
            // rose): the cap binds, add tracks consumption growth (1),
            // and the buffered balance stays pinned at ~one slice.
            assert_eq!(add, 1, "tick {tick}: slow consumer must not accrue credit");
            assert!(
                permits + add <= per_slice + 1,
                "tick {tick}: buffer {} beyond one slice",
                permits + add
            );
        }
        permits += add;
        paid += add;
        // Consumption for this tick (single worker model: hungry drain,
        // then 1/tick).
        if tick < 50 {
            hungry_total += permits;
            consumed += permits;
            permits = 0;
        } else {
            permits -= 1;
            consumed += 1;
            slow_total += 1;
        }
    }
    // 50 hungry ticks at full rate: within one slice of the 50-tick
    // schedule total (rate*50/20 = 1250).
    assert!(
        hungry_total >= 50 * per_slice - per_slice,
        "hungry phase must receive the full schedule, got {hungry_total}"
    );
    assert_eq!(slow_total, 50);
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
            Arc::new(Pacer::unbounded()),
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
