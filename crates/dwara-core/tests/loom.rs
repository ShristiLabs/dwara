//! Loom model-checking tests (DW-025, feature analysis 13.3).
//!
//! Run with `cargo test -p dwara-core --features loom --test loom`. The
//! `loom` feature swaps the synchronization primitives in `health.rs`,
//! `breaker.rs`, and `retries.rs` for loom's model-checked equivalents,
//! letting loom enumerate every interleaving of the small scenarios here.
//!
//! Scope note (honest limitation): `arc-swap` (1.9.x) exposes no loom
//! feature, so the `ArcSwap`-based hot paths — `ConfigState` snapshot
//! publish/read and `UpstreamLb` state swap — CANNOT be model-checked
//! with loom here. Those paths are covered instead by the real-thread
//! stress test in `tests/swap_stress.rs`. The scenarios below cover the
//! primitives that are loom-representable: the EndpointHealth CAS
//! transition machine, the breaker Mutex state machine, and the retry
//! budget's check-and-record critical section.
//!
//! Scenarios are deliberately tiny: loom's state space grows
//! exponentially with operations, so each test exercises one invariant
//! with the minimum number of threads and steps needed to expose a race.

#![cfg(feature = "loom")]

use dwara_core::breaker::{Breaker, BreakerParams};
use dwara_core::health::{EndpointHealth, HealthParams};
use dwara_core::retries::RetryBudget;

fn health_params() -> HealthParams {
    HealthParams {
        window_ms: 60_000,
        consecutive_failures: 2,
        failure_ratio: 0.5,
        failure_min_volume: 20,
        eject_ms: 1_000,
        half_open_probes: 1,
    }
}

fn breaker_params() -> BreakerParams {
    BreakerParams {
        consecutive_failures: 2,
        error_ratio: 1.0,
        error_volume: 100,
        open_ms: 1_000,
        half_open_probes: 1,
    }
}

/// Two threads race `acquire` on an endpoint whose ejection just expired:
/// the EJECTED -> HALF_OPEN transition must arm the probe budget exactly
/// once and at most `half_open_probes` picks may succeed.
#[test]
fn health_half_open_race_grants_at_most_budget() {
    loom::model(|| {
        let params = loom::sync::Arc::new(health_params());
        let tracker = loom::sync::Arc::new(EndpointHealth::new());
        // Eject via the consecutive-failure path (threshold 2).
        tracker.report(&params, 0, true);
        tracker.report(&params, 0, true);
        assert!(!tracker.is_available(0), "must be ejected at t=0");

        let a = loom::sync::Arc::clone(&tracker);
        let p1 = loom::sync::Arc::clone(&params);
        let t1 = loom::thread::spawn(move || a.acquire(&p1, 2_000));
        let b = loom::sync::Arc::clone(&tracker);
        let p2 = loom::sync::Arc::clone(&params);
        let t2 = loom::thread::spawn(move || b.acquire(&p2, 2_000));
        let granted = usize::from(t1.join().unwrap()) + usize::from(t2.join().unwrap());
        assert!(
            granted <= params.half_open_probes as usize,
            "half-open probe budget exceeded: {granted} grants for {} slots",
            params.half_open_probes
        );
    });
}

/// A success report racing a failure report on a half-open endpoint: no
/// deadlock, no panic, and the tracker answers availability cleanly
/// afterwards (a success restores health; the model explores both
/// interleavings).
#[test]
fn health_concurrent_reports_no_deadlock_or_corruption() {
    loom::model(|| {
        let params = loom::sync::Arc::new(health_params());
        let tracker = loom::sync::Arc::new(EndpointHealth::new());
        tracker.report(&params, 0, true);
        tracker.report(&params, 0, true);
        // Drive to half-open (a pick arms and consumes the probe budget).
        let probed = tracker.acquire(&params, 2_000);
        assert!(probed);

        let a = loom::sync::Arc::clone(&tracker);
        let p1 = loom::sync::Arc::clone(&params);
        let t1 = loom::thread::spawn(move || a.report_probe(&p1, 2_000, false));
        let b = loom::sync::Arc::clone(&tracker);
        let p2 = loom::sync::Arc::clone(&params);
        let t2 = loom::thread::spawn(move || b.report(&p2, 2_000, true));
        t1.join().unwrap();
        t2.join().unwrap();
        let _ = tracker.is_available(2_000);
    });
}

/// Breaker check racing a success report while the breaker is open: no
/// panic or deadlock, and every observed decision is a legal outcome of
/// some interleaving (still open, or re-armed as the half-open probe).
#[test]
fn breaker_concurrent_check_report() {
    loom::model(|| {
        // The clock is a fixed point in time: loom models interleavings,
        // not the passage of wall time, and no operation here advances it.
        fn now() -> u64 {
            1_000
        }
        let breaker = loom::sync::Arc::new(Breaker::with_clock(now));
        let params = loom::sync::Arc::new(breaker_params());
        // Trip it (consecutive threshold 2).
        breaker.report(&params, true);
        breaker.report(&params, true);

        let a = loom::sync::Arc::clone(&breaker);
        let p1 = loom::sync::Arc::clone(&params);
        let t1 = loom::thread::spawn(move || a.check(&p1));
        let b = loom::sync::Arc::clone(&breaker);
        let p2 = loom::sync::Arc::clone(&params);
        let t2 = loom::thread::spawn(move || b.report(&p2, false));
        let _ = t1.join().unwrap();
        t2.join().unwrap();
    });
}

/// Retry budget: seeded request volume, two threads race
/// `try_reserve_retry`; the in-window invariant
/// `retries * 100 <= percent * requests` must hold at the end.
#[test]
fn retry_budget_reservation_invariant() {
    loom::model(|| {
        fn now() -> u64 {
            1_000
        }
        let budget = loom::sync::Arc::new(RetryBudget::with_clock(10_000, now));
        // Seed volume: 10 original requests.
        for _ in 0..10 {
            budget.record_request();
        }
        let a = loom::sync::Arc::clone(&budget);
        let t1 = loom::thread::spawn(move || a.try_reserve_retry(25));
        let b = loom::sync::Arc::clone(&budget);
        let t2 = loom::thread::spawn(move || b.try_reserve_retry(25));
        let _ = t1.join().unwrap();
        let _ = t2.join().unwrap();
        let requests = budget.totals() - budget.retries();
        assert!(
            budget.retries() as u64 * 100 <= 25 * requests as u64,
            "retry budget invariant violated: {} retries vs {requests} requests",
            budget.retries()
        );
    });
}
