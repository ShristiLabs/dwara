//! Unit tests for `resilience::adaptive` (DW-089) -- the EWMA math and
//! factor-adjustment logic. The controller is constructed with a
//! controllable nanosecond clock (the same pattern as `Breaker::with_clock`)
//! so the tests advance time deterministically without real sleeps.

use std::cell::Cell;
use std::time::Duration;

use dwara_core::config::{
    AdaptiveRateLimit, Gateway, OriginSignal, Policy, RateLimitRule, RateLimitSelector,
    RateRequestsPer,
};
use dwara_core::resilience::adaptive::AdaptiveController;

// Thread-local test clock: each test runs in its own thread, so
// thread-locals isolate the clock without a shared static that would
// race under parallel test execution.
thread_local! {
    static CLOCK: Cell<u64> = const { Cell::new(1_000_000_000_000) };
}

fn clock_ns() -> u64 {
    CLOCK.with(|c| c.get())
}

/// Advance the test clock by `ms` milliseconds.
fn tick(ms: u64) {
    CLOCK.with(|c| c.set(c.get() + ms * 1_000_000));
}

fn reset_clock() {
    CLOCK.with(|c| c.set(1_000_000_000_000));
}

fn adaptive_cfg() -> AdaptiveRateLimit {
    AdaptiveRateLimit {
        enabled: true,
        ewma_window_secs: 60,
        min_factor: 0.1,
        max_factor: 2.0,
        error_threshold: 0.05,
        latency_threshold_ms: 500,
        origin_signals: vec![OriginSignal::RetryAfter],
    }
}

fn gateway_with_adaptive(cfg: AdaptiveRateLimit) -> Gateway {
    let mut g = dwara_core::config::parse_gateway("").expect("empty gateway parses");
    g.policies = vec![Policy {
        name: "adaptive".into(),
        rate_limit: None,
        rate_limits: vec![RateLimitRule {
            name: None,
            selector: vec![RateLimitSelector::Route],
            requests_per: RateRequestsPer {
                per_second: Some(10),
                minute: None,
                hour: None,
            },
            burst: None,
        }],
        timeouts: None,
        dry_run: false,
        token_budget: None,
        anomaly: None,
        adaptive: Some(cfg),
    }];
    g
}

fn compile(cfg: AdaptiveRateLimit) -> AdaptiveController {
    reset_clock();
    AdaptiveController::compile_with_clock(&gateway_with_adaptive(cfg), None, clock_ns)
}

#[test]
fn no_adaptive_no_change() {
    // A gateway with no adaptive config compiles an empty controller;
    // factor_for returns 1.0 for every policy.
    let g = dwara_core::config::parse_gateway("").expect("empty gateway parses");
    let ctrl = AdaptiveController::compile(&g, None);
    assert!(ctrl.is_empty());
    assert_eq!(ctrl.factor_for("anything"), 1.0);
}

#[test]
fn factor_starts_at_one() {
    let ctrl = compile(adaptive_cfg());
    assert_eq!(ctrl.factor_for("adaptive"), 1.0);
}

#[test]
fn factor_decreases_under_5xx() {
    let ctrl = compile(adaptive_cfg());
    // Feed a stream of 5xx outcomes with realistic spacing (1s apart,
    // within a 60s EWMA window). The error EWMA rises above the 0.05
    // threshold and the factor tightens below 1.0.
    for _ in 0..10 {
        ctrl.record_outcome("adaptive", 500, Duration::from_millis(10), None);
        tick(1000);
    }
    let factor = ctrl.factor_for("adaptive");
    assert!(
        factor < 1.0,
        "factor must tighten under sustained 5xx; got {factor}"
    );
    assert!(
        factor >= 0.1,
        "factor must never go below min_factor; got {factor}"
    );
}

#[test]
fn factor_increases_when_healthy() {
    let ctrl = compile(adaptive_cfg());
    // First tighten with 5xx outcomes.
    for _ in 0..10 {
        ctrl.record_outcome("adaptive", 500, Duration::from_millis(10), None);
        tick(1000);
    }
    let tightened = ctrl.factor_for("adaptive");
    assert!(
        tightened < 1.0,
        "factor must tighten first; got {tightened}"
    );
    // Now feed healthy outcomes with realistic spacing; the factor must
    // relax (rise). Note: the error EWMA takes ~60 more updates to decay
    // below the 0.05 threshold (during which the factor keeps tightening
    // to min), then ~200+ relaxing updates to recover past the tightened
    // value (relaxing at 1% per update is deliberately slower than the
    // 5% tightening). 600 healthy outcomes gives ample margin.
    for _ in 0..600 {
        ctrl.record_outcome("adaptive", 200, Duration::from_millis(10), None);
        tick(1000);
    }
    let relaxed = ctrl.factor_for("adaptive");
    assert!(
        relaxed > tightened,
        "factor must relax when healthy; tightened={tightened} relaxed={relaxed}"
    );
}

#[test]
fn factor_bounded_min() {
    let cfg = AdaptiveRateLimit {
        min_factor: 0.5,
        ..adaptive_cfg()
    };
    let ctrl = compile(cfg);
    for _ in 0..200 {
        ctrl.record_outcome("adaptive", 500, Duration::from_millis(10), None);
        tick(1000);
    }
    let factor = ctrl.factor_for("adaptive");
    assert!(
        factor >= 0.5,
        "factor must never go below min_factor=0.5; got {factor}"
    );
}

#[test]
fn factor_bounded_max() {
    let cfg = AdaptiveRateLimit {
        max_factor: 1.5,
        ..adaptive_cfg()
    };
    let ctrl = compile(cfg);
    for _ in 0..500 {
        ctrl.record_outcome("adaptive", 200, Duration::from_millis(10), None);
        tick(1000);
    }
    let factor = ctrl.factor_for("adaptive");
    assert!(
        factor <= 1.5,
        "factor must never exceed max_factor=1.5; got {factor}"
    );
}

#[test]
fn factor_never_zero() {
    let ctrl = compile(adaptive_cfg());
    for _ in 0..1000 {
        ctrl.record_outcome("adaptive", 500, Duration::from_millis(10), None);
        tick(1000);
    }
    let factor = ctrl.factor_for("adaptive");
    assert!(factor > 0.0, "factor must never be 0; got {factor}");
}

#[test]
fn retry_after_causes_immediate_backoff() {
    let ctrl = compile(adaptive_cfg());
    // A Retry-After signal drops the factor to min immediately.
    ctrl.record_outcome(
        "adaptive",
        429,
        Duration::from_millis(10),
        Some(Duration::from_secs(30)),
    );
    let factor = ctrl.factor_for("adaptive");
    assert_eq!(
        factor, 0.1,
        "Retry-After must drop the factor to min_factor immediately"
    );
}

#[test]
fn retry_after_expires() {
    let ctrl = compile(adaptive_cfg());
    // Set a 30s Retry-After backoff window.
    ctrl.record_outcome(
        "adaptive",
        429,
        Duration::from_millis(10),
        Some(Duration::from_secs(30)),
    );
    assert_eq!(ctrl.factor_for("adaptive"), 0.1);
    // Advance the clock past the backoff window.
    tick(31_000);
    // Feed healthy outcomes to relax it back up.
    for _ in 0..200 {
        ctrl.record_outcome("adaptive", 200, Duration::from_millis(10), None);
        tick(1000);
    }
    let factor = ctrl.factor_for("adaptive");
    assert!(
        factor > 0.1,
        "factor must recover after the Retry-After window elapses; got {factor}"
    );
}

#[test]
fn retry_after_honored_within_window() {
    let ctrl = compile(adaptive_cfg());
    // Set a 30s Retry-After backoff window.
    ctrl.record_outcome(
        "adaptive",
        429,
        Duration::from_millis(10),
        Some(Duration::from_secs(30)),
    );
    // Within the window, even healthy outcomes keep the factor at min.
    tick(10_000);
    ctrl.record_outcome("adaptive", 200, Duration::from_millis(10), None);
    assert_eq!(
        ctrl.factor_for("adaptive"),
        0.1,
        "factor must stay at min within the Retry-After window"
    );
}

#[test]
fn ewma_error_tracking() {
    // A single 5xx among many 2xx should produce a small error EWMA
    // that does NOT trip the threshold (0.05). Sustained 5xx should.
    let ctrl = compile(adaptive_cfg());
    // One 5xx then many 2xx: the EWMA decays, factor should relax.
    ctrl.record_outcome("adaptive", 500, Duration::from_millis(10), None);
    for _ in 0..100 {
        tick(1000);
        ctrl.record_outcome("adaptive", 200, Duration::from_millis(10), None);
    }
    let factor = ctrl.factor_for("adaptive");
    // After 100 healthy outcomes the factor should be relaxing (>= 1.0
    // or close to it -- a single early 5xx is well-decayed).
    assert!(
        factor >= 0.99,
        "a single decayed 5xx should not keep the factor tightened; got {factor}"
    );
}

#[test]
fn ewma_latency_tracking() {
    // High latency (above the 500ms threshold) should tighten. With a
    // 60s EWMA window and 1s spacing, the latency EWMA needs ~100
    // updates to cross the 500ms threshold.
    let ctrl = compile(adaptive_cfg());
    for _ in 0..100 {
        ctrl.record_outcome("adaptive", 200, Duration::from_millis(800), None);
        tick(1000);
    }
    let factor = ctrl.factor_for("adaptive");
    assert!(
        factor < 1.0,
        "high latency must tighten the factor; got {factor}"
    );
}

#[test]
fn unknown_policy_returns_one() {
    let ctrl = compile(adaptive_cfg());
    assert_eq!(
        ctrl.factor_for("nonexistent"),
        1.0,
        "unknown policy returns 1.0 (no adaptive tuning)"
    );
}

#[test]
fn record_outcome_unknown_policy_is_noop() {
    let ctrl = compile(adaptive_cfg());
    // Recording for an unknown policy must not panic.
    ctrl.record_outcome("nonexistent", 500, Duration::from_millis(10), None);
    assert_eq!(ctrl.factor_for("adaptive"), 1.0);
}

#[test]
fn factor_converges_to_min_under_sustained_errors() {
    // With enough sustained 5xx the factor converges to min_factor.
    let ctrl = compile(adaptive_cfg());
    for _ in 0..200 {
        ctrl.record_outcome("adaptive", 500, Duration::from_millis(10), None);
        tick(1000);
    }
    let factor = ctrl.factor_for("adaptive");
    assert!(
        (factor - 0.1).abs() < 0.01,
        "factor must converge to min_factor=0.1 under sustained 5xx; got {factor}"
    );
}

#[test]
fn factor_converges_to_max_when_healthy() {
    // With enough sustained healthy outcomes the factor converges to
    // max_factor.
    let ctrl = compile(adaptive_cfg());
    for _ in 0..500 {
        ctrl.record_outcome("adaptive", 200, Duration::from_millis(10), None);
        tick(1000);
    }
    let factor = ctrl.factor_for("adaptive");
    assert!(
        (factor - 2.0).abs() < 0.01,
        "factor must converge to max_factor=2.0 when healthy; got {factor}"
    );
}
