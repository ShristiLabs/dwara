//! Auto-canary analysis tests (DW-091): the controller's
/// metrics-driven promotion/rollback of canary split weights.
///
/// These tests exercise the pure controller logic (record_outcome ->
/// evaluate -> action) and the transient weight-swap methods on
/// DataPlane. The background runner's polling loop is not tested
/// here (it is a thin wrapper around the controller); the controller
/// itself is the unit of correctness.
mod support;

use dwara_core::dataplane::canary::{CanaryAction, CanaryController, CanaryKind};
use support::{dataplane_from, state_from};

/// Gateway YAML: a service split with canary_analysis, two upstreams
/// (stable + canary), and a single route.
fn split_yaml(
    stable_weight: u32,
    canary_weight: u32,
    analysis_yaml: &str,
    stable_port: u16,
    canary_port: u16,
) -> String {
    format!(
        "routes:\n\
         - name: all\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         services:\n\
         - name: svc\n\
         \x20 split:\n\
         \x20   targets:\n\
         \x20   - upstream: stable\n\
         \x20     weight: {stable_weight}\n\
         \x20   - upstream: canary\n\
         \x20     weight: {canary_weight}\n\
         \x20   canary_analysis:\n{analysis_yaml}\n\
         upstreams:\n\
         - name: stable\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {stable_port}\n\
         - name: canary\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {canary_port}\n"
    )
}

#[test]
fn empty_controller_is_a_no_op() {
    let yaml = "routes:\n- name: r\n  service: s\n  match:\n    path:\n      type: prefix\n      value: /api\n  action:\n    type: proxy\nservices:\n- name: s\n  upstream: u\nupstreams:\n- name: u\n  endpoints:\n  - address: 127.0.0.1\n    port: 9999\n";
    let state = state_from(yaml);
    let gateway = state.snapshot().gateway().clone();
    let controller = CanaryController::compile(&gateway, None);
    assert!(controller.is_empty());
    // record_outcome and evaluate are no-ops.
    controller.record_outcome("s", true, 500, 100.0);
    assert!(controller.evaluate().is_empty());
}

#[test]
fn controller_compiles_from_service_split_with_canary_analysis() {
    let yaml = split_yaml(
        90,
        10,
        "      enabled: true\n\
         \x20     window_seconds: 60\n\
         \x20     step: 5\n\
         \x20     min_requests: 10\n\
         \x20     cooldown_seconds: 30\n\
         \x20     promote:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.01\n\
         \x20     rollback:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.05",
        9999,
        9998,
    );
    let state = state_from(&yaml);
    let gateway = state.snapshot().gateway().clone();
    let controller = CanaryController::compile(&gateway, None);
    assert!(!controller.is_empty());
    assert_eq!(controller.current_canary_weight("svc"), Some(10));
    assert_eq!(controller.total_weight("svc"), Some(100));
}

#[test]
fn controller_skips_disabled_canary_analysis() {
    let yaml = split_yaml(
        90,
        10,
        "      enabled: false\n\
         \x20     window_seconds: 60\n\
         \x20     step: 5\n\
         \x20     min_requests: 10\n\
         \x20     cooldown_seconds: 30\n\
         \x20     promote:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.01\n\
         \x20     rollback:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.05",
        9999,
        9998,
    );
    let state = state_from(&yaml);
    let gateway = state.snapshot().gateway().clone();
    let controller = CanaryController::compile(&gateway, None);
    assert!(controller.is_empty());
}

#[test]
fn controller_skips_non_2_target_splits() {
    // A 3-target split with canary_analysis is rejected by validation
    // (canary_analysis requires exactly 2 targets). The controller
    // never sees it. This test verifies the validation catches it.
    let yaml = "routes:\n\
         - name: all\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         services:\n\
         - name: svc\n\
         \x20 split:\n\
         \x20   targets:\n\
         \x20   - upstream: a\n\
         \x20     weight: 50\n\
         \x20   - upstream: b\n\
         \x20     weight: 30\n\
         \x20   - upstream: c\n\
         \x20     weight: 20\n\
         \x20   canary_analysis:\n\
         \x20     enabled: true\n\
         \x20     window_seconds: 60\n\
         \x20     step: 5\n\
         \x20     min_requests: 10\n\
         \x20     cooldown_seconds: 30\n\
         \x20     promote:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.01\n\
         \x20     rollback:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.05\n\
         upstreams:\n\
         - name: a\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 9999\n\
         - name: b\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 9998\n\
         - name: c\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 9997\n";
    let gateway = dwara_core::config::parse_gateway(yaml).unwrap();
    let issues = dwara_core::snapshot::validate(&gateway);
    let text = issues
        .iter()
        .map(|i| i.message.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        text.contains("canary_analysis requires exactly 2 targets"),
        "expected canary_analysis validation error, got: {text}"
    );
}

#[test]
fn rollback_on_high_canary_error_rate() {
    let yaml = split_yaml(
        90,
        10,
        "      enabled: true\n\
         \x20     window_seconds: 60\n\
         \x20     step: 5\n\
         \x20     min_requests: 10\n\
         \x20     cooldown_seconds: 1\n\
         \x20     promote:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.01\n\
         \x20     rollback:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.05",
        9999,
        9998,
    );
    let state = state_from(&yaml);
    let gateway = state.snapshot().gateway().clone();
    let controller = CanaryController::compile(&gateway, None);
    // Record 10 baseline requests (all 200) and 16 canary requests
    // with 1 error (1/16 = 6.25% error rate, above the 5% rollback
    // threshold but below 10% = 2x threshold, so NOT severe
    // regression).
    for _ in 0..10 {
        controller.record_outcome("svc", false, 200, 50.0);
    }
    controller.record_outcome("svc", true, 500, 50.0);
    for _ in 0..15 {
        controller.record_outcome("svc", true, 200, 50.0);
    }
    let actions = controller.evaluate();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].group, "svc");
    assert_eq!(actions[0].kind, CanaryKind::Service);
    assert_eq!(actions[0].new_canary_weight, 5); // 10 - 5 = 5
    assert_eq!(actions[0].reason, "rollback");
}

#[test]
fn severe_regression_rolls_back_to_zero() {
    let yaml = split_yaml(
        90,
        10,
        "      enabled: true\n\
         \x20     window_seconds: 60\n\
         \x20     step: 5\n\
         \x20     min_requests: 10\n\
         \x20     cooldown_seconds: 1\n\
         \x20     promote:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.01\n\
         \x20     rollback:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.05",
        9999,
        9998,
    );
    let state = state_from(&yaml);
    let gateway = state.snapshot().gateway().clone();
    let controller = CanaryController::compile(&gateway, None);
    // 20 canary requests, all 500 -> 100% error rate, > 2x the 5%
    // rollback threshold (10%) -> severe regression -> immediate 0.
    for _ in 0..10 {
        controller.record_outcome("svc", false, 200, 50.0);
        controller.record_outcome("svc", true, 500, 50.0);
    }
    let actions = controller.evaluate();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].new_canary_weight, 0);
    assert_eq!(actions[0].reason, "severe_regression");
}

#[test]
fn promote_on_low_canary_error_rate() {
    let yaml = split_yaml(
        90,
        10,
        "      enabled: true\n\
         \x20     window_seconds: 60\n\
         \x20     step: 5\n\
         \x20     min_requests: 10\n\
         \x20     cooldown_seconds: 1\n\
         \x20     promote:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.01\n\
         \x20     rollback:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.05",
        9999,
        9998,
    );
    let state = state_from(&yaml);
    let gateway = state.snapshot().gateway().clone();
    let controller = CanaryController::compile(&gateway, None);
    // 10 baseline + 10 canary, all 200 -> 0% error rate, below the
    // 1% promote threshold -> promote.
    for _ in 0..10 {
        controller.record_outcome("svc", false, 200, 50.0);
        controller.record_outcome("svc", true, 200, 50.0);
    }
    let actions = controller.evaluate();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].new_canary_weight, 15); // 10 + 5 = 15
    assert_eq!(actions[0].reason, "promote");
}

#[test]
fn no_action_below_min_requests() {
    let yaml = split_yaml(
        90,
        10,
        "      enabled: true\n\
         \x20     window_seconds: 60\n\
         \x20     step: 5\n\
         \x20     min_requests: 100\n\
         \x20     cooldown_seconds: 1\n\
         \x20     promote:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.01\n\
         \x20     rollback:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.05",
        9999,
        9998,
    );
    let state = state_from(&yaml);
    let gateway = state.snapshot().gateway().clone();
    let controller = CanaryController::compile(&gateway, None);
    // Only 5 requests total — below min_requests=100.
    for _ in 0..5 {
        controller.record_outcome("svc", false, 200, 50.0);
    }
    let actions = controller.evaluate();
    assert!(actions.is_empty());
}

#[test]
fn no_action_in_neutral_zone() {
    let yaml = split_yaml(
        90,
        10,
        "      enabled: true\n\
         \x20     window_seconds: 60\n\
         \x20     step: 5\n\
         \x20     min_requests: 10\n\
         \x20     cooldown_seconds: 1\n\
         \x20     promote:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.01\n\
         \x20     rollback:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.05",
        9999,
        9998,
    );
    let state = state_from(&yaml);
    let gateway = state.snapshot().gateway().clone();
    let controller = CanaryController::compile(&gateway, None);
    // 10 baseline + 25 canary, canary has 1 error (1/25 = 4% error
    // rate) — between the promote threshold (1%) and the rollback
    // threshold (5%). No action.
    for _ in 0..10 {
        controller.record_outcome("svc", false, 200, 50.0);
    }
    controller.record_outcome("svc", true, 500, 50.0);
    for _ in 0..24 {
        controller.record_outcome("svc", true, 200, 50.0);
    }
    let actions = controller.evaluate();
    assert!(actions.is_empty());
}

#[test]
fn cooldown_suppresses_rapid_adjustments() {
    let yaml = split_yaml(
        90,
        10,
        "      enabled: true\n\
         \x20     window_seconds: 60\n\
         \x20     step: 5\n\
         \x20     min_requests: 10\n\
         \x20     cooldown_seconds: 3600\n\
         \x20     promote:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.01\n\
         \x20     rollback:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.05",
        9999,
        9998,
    );
    let state = state_from(&yaml);
    let gateway = state.snapshot().gateway().clone();
    let controller = CanaryController::compile(&gateway, None);
    // Record enough to trigger a promote.
    for _ in 0..10 {
        controller.record_outcome("svc", false, 200, 50.0);
        controller.record_outcome("svc", true, 200, 50.0);
    }
    let actions = controller.evaluate();
    assert_eq!(actions.len(), 1);
    // Apply the action (sets last_adjustment to now).
    controller.note_applied(&actions[0]);
    // Immediately evaluate again — cooldown (3600s) suppresses.
    let actions2 = controller.evaluate();
    assert!(actions2.is_empty());
}

#[test]
fn note_applied_updates_current_weight() {
    let yaml = split_yaml(
        90,
        10,
        "      enabled: true\n\
         \x20     window_seconds: 60\n\
         \x20     step: 5\n\
         \x20     min_requests: 10\n\
         \x20     cooldown_seconds: 1\n\
         \x20     promote:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.01\n\
         \x20     rollback:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.05",
        9999,
        9998,
    );
    let state = state_from(&yaml);
    let gateway = state.snapshot().gateway().clone();
    let controller = CanaryController::compile(&gateway, None);
    assert_eq!(controller.current_canary_weight("svc"), Some(10));
    let action = CanaryAction {
        group: "svc".to_string(),
        kind: CanaryKind::Service,
        new_canary_weight: 20,
        reason: "promote".to_string(),
        metric_value: 0.0,
        threshold: 0.01,
    };
    controller.note_applied(&action);
    assert_eq!(controller.current_canary_weight("svc"), Some(20));
}

#[test]
fn apply_service_split_weights_swaps_the_generation() {
    let yaml = split_yaml(
        90,
        10,
        "      enabled: true\n\
         \x20     window_seconds: 60\n\
         \x20     step: 5\n\
         \x20     min_requests: 10\n\
         \x20     cooldown_seconds: 30\n\
         \x20     promote:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.01\n\
         \x20     rollback:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.05",
        9999,
        9998,
    );
    let dp = dataplane_from(&yaml);
    // The initial canary weight is 10 (out of 100 total).
    let registry = dp.registry();
    let split = registry.split_for("svc").expect("split exists");
    assert_eq!(split.total_weight(), 100);
    // Apply a new canary weight of 30 (baseline becomes 70).
    assert!(dp.apply_service_split_weights("svc", 30));
    // The new generation's split should have the new weights.
    let registry2 = dp.registry();
    let split2 = registry2.split_for("svc").expect("split exists");
    assert_eq!(split2.total_weight(), 100); // total stays constant
    let weights = split2.weights();
    assert_eq!(weights, vec![70, 30]); // baseline=70, canary=30
}

#[test]
fn apply_service_split_weights_returns_false_for_unknown_service() {
    let yaml = split_yaml(
        90,
        10,
        "      enabled: true\n\
         \x20     window_seconds: 60\n\
         \x20     step: 5\n\
         \x20     min_requests: 10\n\
         \x20     cooldown_seconds: 30\n\
         \x20     promote:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.01\n\
         \x20     rollback:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.05",
        9999,
        9998,
    );
    let dp = dataplane_from(&yaml);
    assert!(!dp.apply_service_split_weights("nonexistent", 30));
}

#[test]
fn apply_service_split_weights_clamps_to_total() {
    let yaml = split_yaml(
        90,
        10,
        "      enabled: true\n\
         \x20     window_seconds: 60\n\
         \x20     step: 5\n\
         \x20     min_requests: 10\n\
         \x20     cooldown_seconds: 30\n\
         \x20     promote:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.01\n\
         \x20     rollback:\n\
         \x20       metric: error_rate\n\
         \x20       threshold: 0.05",
        9999,
        9998,
    );
    let dp = dataplane_from(&yaml);
    // Request canary weight 200 — should clamp to total (100).
    assert!(dp.apply_service_split_weights("svc", 200));
    let registry = dp.registry();
    let split = registry.split_for("svc").expect("split exists");
    let weights = split.weights();
    assert_eq!(weights, vec![0, 100]); // baseline=0, canary=100
}

#[test]
fn validation_rejects_canary_analysis_on_non_2_target_split() {
    let issues = dwara_core::snapshot::validate(
        &dwara_core::config::parse_gateway(
            "services:\n\
             - name: svc\n\
             \x20 split:\n\
             \x20   targets:\n\
             \x20   - upstream: a\n\
             \x20     weight: 50\n\
             \x20   - upstream: b\n\
             \x20     weight: 30\n\
             \x20   - upstream: c\n\
             \x20     weight: 20\n\
             \x20   canary_analysis:\n\
             \x20     enabled: true\n\
             \x20     window_seconds: 60\n\
             \x20     step: 5\n\
             \x20     min_requests: 10\n\
             \x20     cooldown_seconds: 30\n\
             \x20     promote:\n\
             \x20       metric: error_rate\n\
             \x20       threshold: 0.01\n\
             \x20     rollback:\n\
             \x20       metric: error_rate\n\
             \x20       threshold: 0.05\n\
             upstreams:\n\
             - name: a\n\
             \x20 endpoints:\n\
             \x20   - address: 127.0.0.1\n\
             \x20     port: 9999\n\
             - name: b\n\
             \x20 endpoints:\n\
             \x20   - address: 127.0.0.1\n\
             \x20     port: 9998\n\
             - name: c\n\
             \x20 endpoints:\n\
             \x20   - address: 127.0.0.1\n\
             \x20     port: 9997\n",
        )
        .unwrap(),
    );
    let text = issues
        .iter()
        .map(|i| i.message.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        text.contains("canary_analysis requires exactly 2 targets"),
        "expected canary_analysis validation error, got: {text}"
    );
}

#[test]
fn validation_rejects_zero_step() {
    let issues = dwara_core::snapshot::validate(
        &dwara_core::config::parse_gateway(
            split_yaml(
                90,
                10,
                "      enabled: true\n\
                 \x20     window_seconds: 60\n\
                 \x20     step: 0\n\
                 \x20     min_requests: 10\n\
                 \x20     cooldown_seconds: 30\n\
                 \x20     promote:\n\
                 \x20       metric: error_rate\n\
                 \x20       threshold: 0.01\n\
                 \x20     rollback:\n\
                 \x20       metric: error_rate\n\
                 \x20       threshold: 0.05",
                9999,
                9998,
            )
            .as_str(),
        )
        .unwrap(),
    );
    let text = issues
        .iter()
        .map(|i| i.message.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        text.contains("step must be >= 1"),
        "expected step validation error, got: {text}"
    );
}

#[test]
fn validation_rejects_invalid_error_rate_threshold() {
    let issues = dwara_core::snapshot::validate(
        &dwara_core::config::parse_gateway(
            split_yaml(
                90,
                10,
                "      enabled: true\n\
                 \x20     window_seconds: 60\n\
                 \x20     step: 5\n\
                 \x20     min_requests: 10\n\
                 \x20     cooldown_seconds: 30\n\
                 \x20     promote:\n\
                 \x20       metric: error_rate\n\
                 \x20       threshold: 1.5\n\
                 \x20     rollback:\n\
                 \x20       metric: error_rate\n\
                 \x20       threshold: 0.05",
                9999,
                9998,
            )
            .as_str(),
        )
        .unwrap(),
    );
    let text = issues
        .iter()
        .map(|i| i.message.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        text.contains("error_rate threshold must be in [0.0, 1.0]"),
        "expected threshold validation error, got: {text}"
    );
}

#[test]
fn latency_metric_uses_percentile() {
    let yaml = split_yaml(
        90,
        10,
        "      enabled: true\n\
         \x20     window_seconds: 60\n\
         \x20     step: 5\n\
         \x20     min_requests: 10\n\
         \x20     cooldown_seconds: 1\n\
         \x20     promote:\n\
         \x20       metric: latency_p99\n\
         \x20       threshold: 200\n\
         \x20     rollback:\n\
         \x20       metric: latency_p99\n\
         \x20       threshold: 500",
        9999,
        9998,
    );
    let state = state_from(&yaml);
    let gateway = state.snapshot().gateway().clone();
    let controller = CanaryController::compile(&gateway, None);
    // Baseline: 10 requests at 50ms each.
    // Canary: 10 requests at 600ms each — p99 is 600ms, above the
    // 500ms rollback threshold.
    for _ in 0..10 {
        controller.record_outcome("svc", false, 200, 50.0);
        controller.record_outcome("svc", true, 200, 600.0);
    }
    let actions = controller.evaluate();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].reason, "rollback");
    assert_eq!(actions[0].new_canary_weight, 5); // 10 - 5 = 5
}
