//! Unit tests for `synthetic` (relocated from src).

use dwara_core::synthetic::{failure_result, success_result, ProbeOutcome, ProbeRunner, ProbeSpec};
use std::time::Duration;

fn make_spec(route: &str, threshold: u32) -> ProbeSpec {
    ProbeSpec {
        route_name: route.to_string(),
        url: Some(format!("http://localhost:8080/{route}")),
        method: "GET".to_string(),
        interval: Duration::from_secs(10),
        timeout: Duration::from_secs(5),
        expected_status: 200,
        headers: vec![],
        body: None,
        failure_threshold: threshold,
        body_contains: None,
        body_jsonpath: None,
        journey: None,
        probe_from: None,
    }
}

#[test]
fn runner_starts_with_no_alerts() {
    let runner = ProbeRunner::new(vec![make_spec("api", 1)]);
    assert_eq!(runner.probe_count(), 1);
    assert!(!runner.is_alerting("api"));
    assert_eq!(runner.consecutive_failures("api"), 0);
}

#[test]
fn success_does_not_alert() {
    let mut runner = ProbeRunner::new(vec![make_spec("api", 1)]);
    let result = success_result("api", 1000, 50, 200);
    let outcome = runner.process_result(&result);
    assert_eq!(outcome, ProbeOutcome::Success);
    assert!(!runner.is_alerting("api"));
}

#[test]
fn failure_with_threshold_1_alerts_immediately() {
    let mut runner = ProbeRunner::new(vec![make_spec("api", 1)]);
    let result = failure_result("api", 1000, 5000, 0, "connection refused");
    let outcome = runner.process_result(&result);
    assert_eq!(outcome, ProbeOutcome::AlertFired);
    assert!(runner.is_alerting("api"));
    assert_eq!(runner.consecutive_failures("api"), 1);
}

#[test]
fn failure_with_threshold_3_alerts_after_third() {
    let mut runner = ProbeRunner::new(vec![make_spec("api", 3)]);

    // First failure -- no alert.
    let r1 = failure_result("api", 1000, 5000, 0, "timeout");
    assert_eq!(runner.process_result(&r1), ProbeOutcome::Failure(1));
    assert!(!runner.is_alerting("api"));

    // Second failure -- no alert.
    let r2 = failure_result("api", 2000, 5000, 0, "timeout");
    assert_eq!(runner.process_result(&r2), ProbeOutcome::Failure(2));
    assert!(!runner.is_alerting("api"));

    // Third failure -- alert.
    let r3 = failure_result("api", 3000, 5000, 0, "timeout");
    assert_eq!(runner.process_result(&r3), ProbeOutcome::AlertFired);
    assert!(runner.is_alerting("api"));

    // Fourth failure -- no new alert (edge-triggered).
    let r4 = failure_result("api", 4000, 5000, 0, "timeout");
    assert_eq!(runner.process_result(&r4), ProbeOutcome::Failure(4));
    assert!(runner.is_alerting("api"));
}

#[test]
fn recovery_after_alert() {
    let mut runner = ProbeRunner::new(vec![make_spec("api", 1)]);

    // Fail to trigger alert.
    let r1 = failure_result("api", 1000, 5000, 0, "timeout");
    assert_eq!(runner.process_result(&r1), ProbeOutcome::AlertFired);
    assert!(runner.is_alerting("api"));

    // Success -- recovery.
    let r2 = success_result("api", 2000, 50, 200);
    assert_eq!(runner.process_result(&r2), ProbeOutcome::Recovered);
    assert!(!runner.is_alerting("api"));
    assert_eq!(runner.consecutive_failures("api"), 0);
}

#[test]
fn success_without_prior_alert_is_not_recovery() {
    let mut runner = ProbeRunner::new(vec![make_spec("api", 1)]);
    let result = success_result("api", 1000, 50, 200);
    let outcome = runner.process_result(&result);
    assert_eq!(outcome, ProbeOutcome::Success);
}

#[test]
fn multiple_probes_independent() {
    let mut runner = ProbeRunner::new(vec![make_spec("api1", 1), make_spec("api2", 2)]);

    // api1 fails -- alerts.
    let r1 = failure_result("api1", 1000, 5000, 0, "timeout");
    assert_eq!(runner.process_result(&r1), ProbeOutcome::AlertFired);
    assert!(runner.is_alerting("api1"));
    assert!(!runner.is_alerting("api2"));

    // api2 fails once -- no alert (threshold 2).
    let r2 = failure_result("api2", 2000, 5000, 0, "timeout");
    assert_eq!(runner.process_result(&r2), ProbeOutcome::Failure(1));
    assert!(!runner.is_alerting("api2"));

    // api2 fails again -- alerts.
    let r3 = failure_result("api2", 3000, 5000, 0, "timeout");
    assert_eq!(runner.process_result(&r3), ProbeOutcome::AlertFired);
    assert!(runner.is_alerting("api2"));
}

#[test]
fn unknown_route_failure_creates_state() {
    let mut runner = ProbeRunner::new(vec![]);
    let result = failure_result("unknown", 1000, 5000, 0, "timeout");
    // No spec -- threshold defaults to 1.
    let outcome = runner.process_result(&result);
    assert_eq!(outcome, ProbeOutcome::AlertFired);
}

#[test]
fn spec_lookup() {
    let runner = ProbeRunner::new(vec![make_spec("api", 1)]);
    assert!(runner.spec("api").is_some());
    assert!(runner.spec("unknown").is_none());
}

#[test]
fn specs_iter() {
    let runner = ProbeRunner::new(vec![make_spec("api1", 1), make_spec("api2", 2)]);
    let names: Vec<_> = runner.specs().map(|s| s.route_name.clone()).collect();
    assert!(names.contains(&"api1".to_string()));
    assert!(names.contains(&"api2".to_string()));
}

#[test]
fn probe_result_constructors() {
    let success = success_result("api", 1000, 50, 200);
    assert!(success.success);
    assert_eq!(success.status, 200);
    assert!(success.error.is_none());

    let failure = failure_result("api", 1000, 5000, 0, "timeout");
    assert!(!failure.success);
    assert_eq!(failure.status, 0);
    assert!(failure.error.is_some());
}

// --- Body assertions (DP-10, #238) ---------------------------------------

#[test]
fn body_contains_passes_when_substring_present() {
    use dwara_core::synthetic::check_body_assertions;
    let spec = make_spec("api", 1);
    let spec = ProbeSpec {
        body_contains: Some("ok".to_string()),
        ..spec
    };
    assert!(check_body_assertions(&spec, "{\"status\":\"ok\"}").is_ok());
}

#[test]
fn body_contains_fails_when_substring_absent() {
    use dwara_core::synthetic::check_body_assertions;
    let spec = make_spec("api", 1);
    let spec = ProbeSpec {
        body_contains: Some("missing".to_string()),
        ..spec
    };
    assert!(check_body_assertions(&spec, "{\"status\":\"ok\"}").is_err());
}

#[test]
fn body_jsonpath_passes_when_path_resolves() {
    use dwara_core::synthetic::check_body_assertions;
    let spec = make_spec("api", 1);
    let spec = ProbeSpec {
        body_jsonpath: Some("$.status".to_string()),
        ..spec
    };
    assert!(check_body_assertions(&spec, "{\"status\":\"ok\"}").is_ok());
}

#[test]
fn body_jsonpath_fails_when_path_missing() {
    use dwara_core::synthetic::check_body_assertions;
    let spec = make_spec("api", 1);
    let spec = ProbeSpec {
        body_jsonpath: Some("$.missing".to_string()),
        ..spec
    };
    assert!(check_body_assertions(&spec, "{\"status\":\"ok\"}").is_err());
}

#[test]
fn body_jsonpath_handles_nested_paths() {
    use dwara_core::synthetic::check_body_assertions;
    let spec = make_spec("api", 1);
    let spec = ProbeSpec {
        body_jsonpath: Some("$.data.id".to_string()),
        ..spec
    };
    let body = "{\"data\":{\"id\":42,\"name\":\"test\"}}";
    assert!(check_body_assertions(&spec, body).is_ok());

    let spec2 = ProbeSpec {
        body_jsonpath: Some("$.data.missing".to_string()),
        ..spec
    };
    assert!(check_body_assertions(&spec2, body).is_err());
}

#[test]
fn body_jsonpath_handles_array_index() {
    use dwara_core::synthetic::check_body_assertions;
    let spec = make_spec("api", 1);
    let spec = ProbeSpec {
        body_jsonpath: Some("$.items[0].id".to_string()),
        ..spec
    };
    let body = "{\"items\":[{\"id\":1},{\"id\":2}]}";
    assert!(check_body_assertions(&spec, body).is_ok());
}

#[test]
fn body_jsonpath_fails_on_invalid_json() {
    use dwara_core::synthetic::check_body_assertions;
    let spec = make_spec("api", 1);
    let spec = ProbeSpec {
        body_jsonpath: Some("$.status".to_string()),
        ..spec
    };
    assert!(check_body_assertions(&spec, "not json").is_err());
}

// --- Executor (DP-10, #238) ---------------------------------------------

#[tokio::test]
async fn run_probe_fails_without_url() {
    use dwara_core::synthetic::run_probe;
    let spec = ProbeSpec {
        url: None,
        ..make_spec("api", 1)
    };
    let result = run_probe(&spec).await;
    assert!(!result.success);
    assert!(result.error.as_deref().unwrap().contains("no url"));
}

#[tokio::test]
async fn run_probe_fails_on_connection_error() {
    use dwara_core::synthetic::run_probe;
    let spec = ProbeSpec {
        url: Some("http://127.0.0.1:1".to_string()),
        timeout: std::time::Duration::from_millis(100),
        ..make_spec("api", 1)
    };
    let result = run_probe(&spec).await;
    assert!(!result.success);
    assert!(result.error.is_some());
}
