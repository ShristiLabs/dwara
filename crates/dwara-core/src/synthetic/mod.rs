//! Synthetic monitoring (DW-071).
//!
//! Built-in probes per route that measure latency and uptime, feeding
//! results into analytics and webhooks. This is the proactive/synthetic
//! side of SLO tracking -- it pairs with DW-052 (SLO & error-budget
//! export, M2), which derives SLO/burn-rate metrics from real traffic.
//! Synthetic monitoring lets an SLO be tracked even on routes with
//! little real traffic.
//!
//! ## Design (section 6-Traffic Intelligence)
//!
//! "The gateway measures the SLOs it exports." Each route can have a
//! synthetic probe configured: a periodic HTTP request to the route's
//! URL (or a custom URL) that records latency, status code, and
//! success/failure. The results feed into the analytics store (as
//! access records tagged as synthetic) and the event bus (for webhook
//! delivery on probe failures).
//!
//! ## Probe lifecycle
//!
//! 1. At config publish time, the probe configuration is compiled
//!    into a [`ProbeSpec`] per route.
//! 2. A background task ([`ProbeRunner`]) runs each probe on its
//!    configured interval.
//! 3. Each probe result ([`ProbeResult`]) is:
//!    - Recorded in the analytics store (as a synthetic access record).
//!    - Emitted as an event if the probe failed (for webhook delivery).
//!    - Used to update the route's SLO metrics.
//!
//! ## Alerting
//!
//! When a probe fails, an event is emitted on the event bus. If a
//! webhook is configured for the `probe_failed` event kind, the
//! webhook deliverer sends a notification. The alert fires on the
//! first failure (edge-triggered); subsequent consecutive failures
//! do not re-fire until the probe recovers.

use std::collections::HashMap;
use std::time::Duration;

/// A synthetic probe specification for a route.
///
/// Created at config publish time from the route's `probe` config
/// field. Immutable after creation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeSpec {
    /// The route name this probe is attached to.
    pub route_name: String,
    /// The URL to probe. If None, the probe uses the route's own URL
    /// (constructed from the listener + route match).
    pub url: Option<String>,
    /// The HTTP method to use (default: GET).
    pub method: String,
    /// The probe interval (how often to run the probe).
    pub interval: Duration,
    /// The probe timeout (how long to wait for a response).
    pub timeout: Duration,
    /// The expected status code. If the response status does not
    /// match, the probe is considered failed.
    pub expected_status: u16,
    /// Optional headers to send with the probe request.
    pub headers: Vec<(String, String)>,
    /// Optional request body to send with the probe.
    pub body: Option<String>,
    /// The number of consecutive failures before alerting (default: 1).
    pub failure_threshold: u32,
}

/// The result of a single probe run.
#[derive(Clone, Debug)]
pub struct ProbeResult {
    /// The route name this probe is for.
    pub route_name: String,
    /// The time the probe was initiated (Unix epoch milliseconds).
    pub started_at_ms: u64,
    /// The round-trip latency in milliseconds.
    pub latency_ms: u64,
    /// The HTTP status code received (0 if the request failed before
    /// getting a response).
    pub status: u16,
    /// Whether the probe was successful (status matched expected, and
    /// the request completed within the timeout).
    pub success: bool,
    /// An error message if the probe failed (None on success).
    pub error: Option<String>,
}

/// The current state of a probe (for edge-triggered alerting).
#[derive(Clone, Debug, Default)]
struct ProbeState {
    /// The number of consecutive failures since the last success.
    consecutive_failures: u32,
    /// Whether the probe is currently in a failed state (has crossed
    /// the failure threshold). Used for edge-triggered alerting.
    is_alerting: bool,
}

/// A probe runner: holds probe specs and their current states, and
/// runs probes on their configured intervals.
///
/// The runner is not a background thread -- it is a coordinator that
/// the caller (the gateway's background task pool) calls into. The
/// caller is responsible for scheduling probe runs (e.g. via
/// `tokio::spawn` with a sleep loop per probe).
pub struct ProbeRunner {
    specs: HashMap<String, ProbeSpec>,
    states: HashMap<String, ProbeState>,
}

/// The outcome of processing a probe result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The probe succeeded.
    Success,
    /// The probe failed but has not crossed the failure threshold.
    Failure(u32),
    /// The probe failed and crossed the failure threshold -- an alert
    /// should be fired (edge-triggered).
    AlertFired,
    /// The probe recovered from a previous alert.
    Recovered,
}

impl ProbeRunner {
    /// Create a new probe runner from a list of probe specs.
    pub fn new(specs: Vec<ProbeSpec>) -> Self {
        let states = specs
            .iter()
            .map(|s| (s.route_name.clone(), ProbeState::default()))
            .collect();
        let specs = specs
            .into_iter()
            .map(|s| (s.route_name.clone(), s))
            .collect();
        Self { specs, states }
    }

    /// Get the probe spec for a route.
    pub fn spec(&self, route_name: &str) -> Option<&ProbeSpec> {
        self.specs.get(route_name)
    }

    /// Get all probe specs.
    pub fn specs(&self) -> impl Iterator<Item = &ProbeSpec> {
        self.specs.values()
    }

    /// Process a probe result and return the outcome.
    ///
    /// This updates the probe's internal state and determines whether
    /// an alert should be fired (edge-triggered) or the probe has
    /// recovered.
    pub fn process_result(&mut self, result: &ProbeResult) -> ProbeOutcome {
        let state = self.states.entry(result.route_name.clone()).or_default();

        if result.success {
            let was_alerting = state.is_alerting;
            state.consecutive_failures = 0;
            state.is_alerting = false;
            if was_alerting {
                ProbeOutcome::Recovered
            } else {
                ProbeOutcome::Success
            }
        } else {
            state.consecutive_failures += 1;
            let spec = self.specs.get(&result.route_name);
            let threshold = spec.map(|s| s.failure_threshold).unwrap_or(1).max(1);

            if state.consecutive_failures >= threshold && !state.is_alerting {
                state.is_alerting = true;
                ProbeOutcome::AlertFired
            } else {
                ProbeOutcome::Failure(state.consecutive_failures)
            }
        }
    }

    /// Whether a probe is currently in an alerting state.
    pub fn is_alerting(&self, route_name: &str) -> bool {
        self.states
            .get(route_name)
            .map(|s| s.is_alerting)
            .unwrap_or(false)
    }

    /// The number of consecutive failures for a probe.
    pub fn consecutive_failures(&self, route_name: &str) -> u32 {
        self.states
            .get(route_name)
            .map(|s| s.consecutive_failures)
            .unwrap_or(0)
    }

    /// The number of probes.
    pub fn probe_count(&self) -> usize {
        self.specs.len()
    }
}

/// Create a probe result from a successful HTTP response.
pub fn success_result(
    route_name: &str,
    started_at_ms: u64,
    latency_ms: u64,
    status: u16,
) -> ProbeResult {
    ProbeResult {
        route_name: route_name.to_string(),
        started_at_ms,
        latency_ms,
        status,
        success: true,
        error: None,
    }
}

/// Create a probe result from a failed HTTP response (or error).
pub fn failure_result(
    route_name: &str,
    started_at_ms: u64,
    latency_ms: u64,
    status: u16,
    error: &str,
) -> ProbeResult {
    ProbeResult {
        route_name: route_name.to_string(),
        started_at_ms,
        latency_ms,
        status,
        success: false,
        error: Some(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
