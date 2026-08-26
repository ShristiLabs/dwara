//! Unit tests for `resilience::health` (relocated from src).

use dwara_core::resilience::health::*;

fn params() -> HealthParams {
    HealthParams {
        window_ms: 60_000,
        consecutive_failures: 3,
        failure_ratio: 0.5,
        failure_min_volume: 4,
        eject_ms: 1_000,
        half_open_probes: 1,
    }
}

#[test]
fn consecutive_failures_eject_and_block_picks() {
    let p = params();
    let t = EndpointHealth::new();
    let now = 10_000;
    for i in 1..=2 {
        t.report(&p, now, true);
        assert!(
            t.is_available(now),
            "two failures stay healthy (threshold 3), iter {i}"
        );
    }
    t.report(&p, now, true);
    assert!(!t.is_available(now), "third consecutive failure ejects");
    assert!(!t.acquire(&p, now), "ejected endpoint is not pickable");
    assert_eq!(t.ejections(), 1);
}

#[test]
fn success_resets_the_consecutive_streak() {
    // Ratio path disabled (huge volume gate): isolates the streak.
    let mut p = params();
    p.failure_min_volume = 100;
    let t = EndpointHealth::new();
    t.report(&p, 1_000, true);
    t.report(&p, 1_001, true);
    t.report(&p, 1_002, false); // a success breaks the streak
    t.report(&p, 1_003, true);
    assert!(t.is_available(1_003), "1-of-4 streak is below threshold");
}

#[test]
fn ratio_requires_volume_before_ejection() {
    // Consecutive threshold disabled (100): only the ratio path fires.
    let mut p = params();
    p.consecutive_failures = 100;
    p.failure_min_volume = 4;
    p.failure_ratio = 0.5;
    let t = EndpointHealth::new();
    let now = 5_000;
    // 3 failures: ratio (1.0) met, volume (3) NOT met -> no ejection.
    for _ in 0..3 {
        t.report(&p, now, true);
    }
    assert!(t.is_available(now), "volume below threshold: no ejection");
    // One more failure: volume 4, failures 4 (ratio 1.0 >= 0.5) -> out.
    t.report(&p, now, true);
    assert!(!t.is_available(now), "ratio with volume met ejects");
}

#[test]
fn mixed_window_ratio_ejects_at_threshold() {
    let mut p = params();
    p.consecutive_failures = 100;
    p.failure_min_volume = 4;
    p.failure_ratio = 0.5;
    let t = EndpointHealth::new();
    let now = 5_000;
    // 2 failures + 1 success: volume 3 < 4 -> healthy regardless.
    t.report(&p, now, true);
    t.report(&p, now, true);
    t.report(&p, now, false);
    assert!(t.is_available(now));
    // Another failure: volume 4, failures 3, ratio 0.75 >= 0.5 -> out.
    t.report(&p, now, true);
    assert!(!t.is_available(now));
}

#[test]
fn old_failures_expire_from_the_window() {
    let mut p = params();
    p.consecutive_failures = 100;
    p.failure_min_volume = 3;
    p.failure_ratio = 0.5;
    p.window_ms = 1_000;
    let t = EndpointHealth::new();
    // Two failures inside the window would eject on the next failure.
    t.report(&p, 10_000, true);
    t.report(&p, 10_100, true);
    // Both older than the window by the next report: volume resets to
    // the fresh observation only, so no ratio ejection.
    t.report(&p, 11_200, false);
    assert!(t.is_available(11_200), "expired failures leave the window");
    // Fresh failure: volume 2, failures 1, below the (3, 0.5) gates.
    t.report(&p, 11_200, true);
    assert!(t.is_available(11_200));
}

#[test]
fn half_open_probe_success_restores_health() {
    let p = params();
    let t = EndpointHealth::new();
    let t0 = 100_000;
    for _ in 0..3 {
        t.report(&p, t0, true);
    }
    assert!(!t.acquire(&p, t0 + 500), "inside eject_ms: no pickup");
    // Ejection expired: the pick arms half-open and consumes the one
    // probe; a second pick is refused until the probe resolves.
    assert!(t.acquire(&p, t0 + p.eject_ms + 1), "probe granted");
    assert!(
        !t.acquire(&p, t0 + p.eject_ms + 2),
        "single probe budget exhausted"
    );
    // Successful probe: healthy again with a clean history.
    t.report(&p, t0 + p.eject_ms + 3, false);
    assert!(t.acquire(&p, t0 + p.eject_ms + 4), "back in rotation");
}

#[test]
fn half_open_probe_failure_re_ejects_for_another_window() {
    let p = params();
    let t = EndpointHealth::new();
    let t0 = 100_000;
    for _ in 0..3 {
        t.report(&p, t0, true);
    }
    let probe_at = t0 + p.eject_ms + 1;
    assert!(t.acquire(&p, probe_at));
    t.report(&p, probe_at, true);
    assert_eq!(t.ejections(), 2, "failed probe re-ejects");
    assert!(!t.is_available(probe_at + p.eject_ms - 1), "still out");
    // Full second window expires: a new probe attempt is granted.
    assert!(t.acquire(&p, probe_at + p.eject_ms + 1));
}

#[test]
fn multiple_half_open_probes_are_granted_then_gated() {
    let mut p = params();
    p.half_open_probes = 2;
    let t = EndpointHealth::new();
    let t0 = 100_000;
    for _ in 0..3 {
        t.report(&p, t0, true);
    }
    let at = t0 + p.eject_ms + 1;
    assert!(t.acquire(&p, at), "probe 1");
    assert!(t.acquire(&p, at), "probe 2");
    assert!(!t.acquire(&p, at), "budget of 2 exhausted");
}

#[test]
fn fail_open_success_on_ejected_endpoint_recovers_it() {
    // Only reachable via the balancer's all-ejected fail-open path.
    let p = params();
    let t = EndpointHealth::new();
    let t0 = 100_000;
    for _ in 0..3 {
        t.report(&p, t0, true);
    }
    assert!(!t.is_available(t0 + 10));
    t.report(&p, t0 + 20, false);
    assert!(t.is_available(t0 + 20), "observed success restores health");
}
