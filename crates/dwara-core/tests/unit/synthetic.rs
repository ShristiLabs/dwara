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
