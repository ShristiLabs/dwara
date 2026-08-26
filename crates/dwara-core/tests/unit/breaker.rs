//! Unit tests for `resilience::breaker` (relocated from src).

use std::sync::atomic::{AtomicU64, Ordering};

use dwara_core::resilience::breaker::*;

fn params() -> BreakerParams {
    BreakerParams {
        consecutive_failures: 5,
        error_ratio: 0.5,
        error_volume: 20,
        open_ms: 30_000,
        half_open_probes: 1,
    }
}

#[test]
fn opens_on_consecutive_failures_and_fails_fast() {
    static NOW: AtomicU64 = AtomicU64::new(1_000);
    let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
    let p = params();
    for _ in 0..4 {
        assert_eq!(b.check(&p), BreakerDecision::Allow);
        b.report(&p, true);
        assert!(matches!(b.state(), BreakerState::Closed { .. }));
    }
    // 5th consecutive failure trips it.
    b.report(&p, true);
    assert!(matches!(b.state(), BreakerState::Open { .. }));
    let BreakerDecision::Reject { retry_after_ms } = b.check(&p) else {
        panic!("open breaker must reject");
    };
    assert_eq!(retry_after_ms, 30_000);
}

#[test]
fn success_resets_the_streak() {
    static NOW: AtomicU64 = AtomicU64::new(1_000);
    let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
    let p = params();
    for _ in 0..4 {
        b.report(&p, true);
    }
    b.report(&p, false);
    assert!(matches!(b.state(), BreakerState::Closed { consecutive: 0 }));
    // Four more failures after the reset do not trip (streak restarted).
    for _ in 0..4 {
        b.report(&p, true);
    }
    assert!(matches!(b.state(), BreakerState::Closed { .. }));
}

#[test]
fn opens_on_ratio_with_volume() {
    static NOW: AtomicU64 = AtomicU64::new(1_000);
    let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
    let p = params();
    // 9 failures + 10 successes = 19 observations at ~47% < 50%: not
    // tripped, and below volume anyway.
    for i in 0..19 {
        b.report(&p, i % 2 == 0);
    }
    assert!(matches!(b.state(), BreakerState::Closed { .. }));
    // 20th observation is a failure: 10/20 = 50% with volume 20.
    b.report(&p, true);
    assert!(matches!(b.state(), BreakerState::Open { .. }));
}

#[test]
fn ratio_needs_volume_even_when_high() {
    static NOW: AtomicU64 = AtomicU64::new(1_000);
    let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
    let p = params();
    // Streak below 5 cannot trip via ratio either (4 < 5): with volume
    // 20, 4/4 = 100% ratio still does not trip.
    for _ in 0..4 {
        b.report(&p, true);
    }
    assert!(matches!(b.state(), BreakerState::Closed { .. }));
}

#[test]
fn half_open_probe_closes_on_success() {
    static NOW: AtomicU64 = AtomicU64::new(1_000);
    let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
    let p = params();
    for _ in 0..5 {
        b.report(&p, true);
    }
    assert!(matches!(b.state(), BreakerState::Open { .. }));
    // Before the cool-off: rejected with the remaining time.
    let BreakerDecision::Reject { retry_after_ms } = b.check(&p) else {
        panic!("must reject while open");
    };
    assert_eq!(retry_after_ms, 30_000);
    // Advance past open_ms: the same check admits a probe.
    NOW.store(31_001, Ordering::Relaxed);
    assert_eq!(b.check(&p), BreakerDecision::Allow);
    assert!(matches!(
        b.state(),
        BreakerState::HalfOpen { probes_left: 0 }
    ));
    // Probe succeeds: closed, counters reset.
    b.report(&p, false);
    assert!(matches!(b.state(), BreakerState::Closed { consecutive: 0 }));
    assert_eq!(b.totals(), 0, "window cleared on close");
}

#[test]
fn half_open_probe_failure_reopens() {
    static NOW: AtomicU64 = AtomicU64::new(1_000);
    let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
    let p = params();
    for _ in 0..5 {
        b.report(&p, true);
    }
    NOW.store(31_000, Ordering::Relaxed);
    assert_eq!(b.check(&p), BreakerDecision::Allow);
    b.report(&p, true);
    assert!(matches!(b.state(), BreakerState::Open { until_ms: 61_000 }));
}

#[test]
fn half_open_second_probe_rejected_until_resolved() {
    static NOW: AtomicU64 = AtomicU64::new(1_000);
    let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
    let p = params();
    for _ in 0..5 {
        b.report(&p, true);
    }
    NOW.store(31_000, Ordering::Relaxed);
    assert_eq!(b.check(&p), BreakerDecision::Allow);
    // All probes (default 1) in flight: the next request is rejected.
    let BreakerDecision::Reject { retry_after_ms } = b.check(&p) else {
        panic!("must reject while probing");
    };
    assert_eq!(retry_after_ms, HALF_OPEN_RETRY_AFTER_MS);
}

#[test]
fn multiple_half_open_probes_admitted() {
    static NOW: AtomicU64 = AtomicU64::new(1_000);
    let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
    let p = BreakerParams {
        half_open_probes: 3,
        ..params()
    };
    for _ in 0..5 {
        b.report(&p, true);
    }
    NOW.store(31_000, Ordering::Relaxed);
    assert_eq!(b.check(&p), BreakerDecision::Allow);
    assert_eq!(b.check(&p), BreakerDecision::Allow);
    assert_eq!(b.check(&p), BreakerDecision::Allow);
    assert!(matches!(b.check(&p), BreakerDecision::Reject { .. }));
}

#[test]
fn in_flight_reports_do_not_change_open_state() {
    static NOW: AtomicU64 = AtomicU64::new(1_000);
    let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
    let p = params();
    for _ in 0..5 {
        b.report(&p, true);
    }
    // A request admitted before the trip now succeeds: Open holds (the
    // probe protocol, not stale successes, closes the breaker).
    b.report(&p, false);
    assert!(matches!(b.state(), BreakerState::Open { .. }));
}

#[test]
fn window_expires_old_observations() {
    static NOW: AtomicU64 = AtomicU64::new(1_000);
    let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
    let p = params();
    // 5 failures trip via the streak; use success mix to keep Closed
    // and then age the window out entirely.
    let p2 = BreakerParams {
        consecutive_failures: 100,
        ..p
    };
    for i in 0..20 {
        b.report(&p2, i % 2 == 0);
    }
    assert!(matches!(b.state(), BreakerState::Closed { .. }));
    assert_eq!(b.totals(), 20);
    NOW.store(1_000 + BREAKER_WINDOW_MS + 1, Ordering::Relaxed);
    assert_eq!(b.totals(), 0);
    // 20 more failures at the new time re-trip on ratio (streak is
    // also 100-bound; ratio 20/20 trips).
    for _ in 0..20 {
        b.report(&p2, true);
    }
    assert!(matches!(b.state(), BreakerState::Open { .. }));
}

#[test]
fn ratio_below_volume_never_trips_even_at_full_failure_ratio() {
    // 19/19 = 100% failures is the worst possible ratio, but volume 19
    // is one short of `error_volume` 20: the ratio gate stays closed.
    // Pins that volume gates the ratio regardless of how bad it is
    // (the streak is suppressed at consecutive_failures 100).
    static NOW: AtomicU64 = AtomicU64::new(1_000);
    let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
    let p = BreakerParams {
        consecutive_failures: 100,
        ..params()
    };
    for _ in 0..19 {
        b.report(&p, true);
    }
    assert!(
        matches!(b.state(), BreakerState::Closed { consecutive: 19 }),
        "volume-1 must not trip even at a 100% ratio"
    );
    // The 20th failure lands exactly at volume with 20/20 >= 0.5.
    b.report(&p, true);
    assert!(matches!(b.state(), BreakerState::Open { .. }));
}

#[test]
fn aged_out_failures_no_longer_count_toward_volume() {
    // 19 failures age out of the 60 s window; 19 FRESH failures then
    // hold a 100% ratio but only volume 19: not tripped. The window
    // (not lifetime history) is the denominator; the 20th fresh
    // failure completes the fresh volume and trips.
    static NOW: AtomicU64 = AtomicU64::new(1_000);
    let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
    let p = BreakerParams {
        consecutive_failures: 100,
        ..params()
    };
    for _ in 0..19 {
        b.report(&p, true);
    }
    NOW.store(1_000 + BREAKER_WINDOW_MS + 1, Ordering::Relaxed);
    for _ in 0..19 {
        b.report(&p, true);
    }
    assert!(
        matches!(b.state(), BreakerState::Closed { .. }),
        "stale failures must not count toward volume"
    );
    b.report(&p, true);
    assert!(matches!(b.state(), BreakerState::Open { .. }));
}
