//! Unit tests for `dataplane::active` (relocated from src).

use std::time::Duration;

use dwara_core::config::ProbeKind;
use dwara_core::dataplane::active::*;
use dwara_core::resilience::health::HealthParams;

#[test]
fn full_jitter_stays_in_bounds() {
    for bound in [1u64, 100, 500] {
        for _ in 0..200 {
            let v = next_below(bound);
            assert!(v < bound, "{v} not below {bound}");
        }
    }
    assert_eq!(next_below(0), 0);
}

#[test]
fn report_params_swap_thresholds_and_disable_ratio() {
    let active = ActiveParams {
        kind: ProbeKind::Http,
        path: "/x".into(),
        interval: Duration::from_millis(10),
        timeout: Duration::from_millis(5),
        success_threshold: 2,
        failure_threshold: 4,
        jitter: Duration::ZERO,
    };
    let passive = HealthParams {
        window_ms: 1_000,
        consecutive_failures: 9,
        failure_ratio: 0.5,
        failure_min_volume: 5,
        eject_ms: 2_000,
        half_open_probes: 1,
    };
    let p = report_params(&active, &passive);
    assert_eq!(p.consecutive_failures, 4);
    assert_eq!(p.failure_min_volume, u32::MAX);
    assert_eq!(p.eject_ms, 2_000);
    assert_eq!(p.window_ms, 1_000);
}
