//! Synthetic monitoring (DW-071, DP-10 / #238).
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
//! 2. A background task ([`ProbeScheduler`]) runs each probe on its
//!    configured interval via the async HTTP executor ([`run_probe`]).
//! 3. Each probe result ([`ProbeResult`]) is:
//!    - Fed into [`ProbeRunner::process_result`] for state tracking.
//!    - Emitted as an event on state transitions (alert/recovery).
//!    - Recorded in the analytics store (as a synthetic access record).
//!
//! ## Alerting
//!
//! When a probe fails, an event is emitted on the event bus. If a
//! webhook is configured for the `probe_failed` event kind, the
//! webhook deliverer sends a notification. The alert fires on the
//! first failure that crosses the threshold (edge-triggered);
//! subsequent consecutive failures do not re-fire until the probe
//! recovers.
//!
//! ## Body assertions (DP-10, #238)
//!
//! Probes can assert on the response body:
//! - `body_contains`: the body must contain a substring.
//! - `body_jsonpath`: a JSONPath expression that must resolve to a
//!   non-null value (simple dot-notation, e.g. `$.status`).
//!
//! ## Multi-step journeys (DP-10, #238)
//!
//! A probe can be a multi-step journey: a sequence of requests where
//! each step can extract values (e.g. a session token) and pass them
//! to subsequent steps via header templates. The journey fails if any
//! step fails.
//!
//! ## Probe-from header (DP-10, #238)
//!
//! A probe can set the `X-Dwara-Probe-From` header to identify the
//! region/agent executing the probe, enabling multi-region synthetic
//! monitoring where agents in different geographies probe the same
//! route and report their origin.

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
    /// DP-10 (#238): optional body-contains assertion. The probe
    /// fails if the response body does not contain this substring.
    pub body_contains: Option<String>,
    /// DP-10 (#238): optional JSONPath assertion (simple dot-notation
    /// like `$.status` or `$.data.id`). The probe fails if the path
    /// does not resolve to a non-null value in the JSON body.
    pub body_jsonpath: Option<String>,
    /// DP-10 (#238): optional multi-step journey. When set, the probe
    /// executes each step sequentially; the journey fails if any step
    /// fails. Step-extracted values (via `extract` JSONPath) are
    /// substituted into subsequent step headers via `{{var}}` templates.
    pub journey: Option<Vec<ProbeStep>>,
    /// DP-10 (#238): optional probe-from identifier. When set, the
    /// `X-Dwara-Probe-From` header is added to each probe request so
    /// the target can identify the probing agent/region.
    pub probe_from: Option<String>,
}

/// One step in a multi-step probe journey (DP-10, #238).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeStep {
    /// The URL to probe for this step.
    pub url: String,
    /// The HTTP method (default: GET).
    pub method: String,
    /// Optional headers. Values may contain `{{var}}` templates that
    /// are substituted from values extracted by prior steps.
    pub headers: Vec<(String, String)>,
    /// Optional request body.
    pub body: Option<String>,
    /// The expected status code.
    pub expected_status: u16,
    /// Optional JSONPath extraction. The extracted value is stored
    /// under the `extract_name` key for use in subsequent steps.
    pub extract_name: Option<String>,
    /// The JSONPath expression to extract (e.g. `$.token`).
    pub extract_jsonpath: Option<String>,
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
/// processes results to drive edge-triggered alerting.
///
/// The runner is not a background thread -- it is a coordinator that
/// the caller (the [`ProbeScheduler`]) calls into. The scheduler is
/// responsible for spawning async tasks and feeding results.
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

// --- Body assertions (DP-10, #238) ----------------------------------------

/// Check a response body against the probe's body assertions.
/// Returns `Ok(())` if all assertions pass, or `Err(message)` on
/// the first failure.
pub fn check_body_assertions(spec: &ProbeSpec, body: &str) -> Result<(), String> {
    if let Some(substr) = &spec.body_contains {
        if !body.contains(substr) {
            return Err(format!(
                "body does not contain expected substring {:?}",
                substr
            ));
        }
    }
    if let Some(path) = &spec.body_jsonpath {
        if !jsonpath_exists(body, path) {
            return Err(format!(
                "jsonpath {:?} did not resolve to a non-null value",
                path
            ));
        }
    }
    Ok(())
}

/// Simple JSONPath existence check (dot-notation: `$.foo.bar`).
/// Returns true if the path resolves to a non-null value in the JSON
/// body. This is a minimal implementation for probe assertions; it
/// handles the common cases (`$.field`, `$.a.b.c`, `$.arr[0]`) without
/// a full JSONPath engine dependency.
fn jsonpath_exists(body: &str, path: &str) -> bool {
    let trimmed = path.strip_prefix("$.").unwrap_or(path);
    let value = match serde_json::from_str::<serde_json::Value>(body) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut current = &value;
    for segment in trimmed.split('.') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        // Handle array index: arr[0]
        if let Some(idx_end) = segment.find('[') {
            let key = &segment[..idx_end];
            let idx_str = &segment[idx_end + 1..].trim_end_matches(']');
            if !key.is_empty() {
                current = current.get(key).unwrap_or(&serde_json::Value::Null);
            }
            if let Ok(idx) = idx_str.parse::<usize>() {
                current = current.get(idx).unwrap_or(&serde_json::Value::Null);
            } else {
                return false;
            }
        } else {
            current = current.get(segment).unwrap_or(&serde_json::Value::Null);
        }
        if current.is_null() {
            return false;
        }
    }
    !current.is_null()
}

// --- Async HTTP executor (DP-10, #238) ------------------------------------

/// Execute a single probe spec as an HTTP request and return the
/// result. This is the core executor: it sends the request, measures
/// latency, checks the status code, and runs body assertions.
///
/// For multi-step journeys, use [`run_journey`] instead.
pub async fn run_probe(spec: &ProbeSpec) -> ProbeResult {
    let started = std::time::Instant::now();
    let started_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let url = match spec.url.as_deref() {
        Some(u) => u.to_string(),
        None => {
            return failure_result(
                &spec.route_name,
                started_at_ms,
                started.elapsed().as_millis() as u64,
                0,
                "probe has no url",
            );
        }
    };

    // Multi-step journey: delegate to the journey executor.
    if let Some(steps) = &spec.journey {
        return run_journey(spec, steps, &url, started, started_at_ms).await;
    }

    let result = execute_http(
        &url,
        &spec.method,
        &spec.headers,
        spec.body.as_deref(),
        spec.timeout,
        spec.probe_from.as_deref(),
    )
    .await;

    match result {
        Ok((status, body)) => {
            let latency_ms = started.elapsed().as_millis() as u64;
            if status != spec.expected_status {
                return failure_result(
                    &spec.route_name,
                    started_at_ms,
                    latency_ms,
                    status,
                    &format!("expected status {} got {}", spec.expected_status, status),
                );
            }
            if let Err(msg) = check_body_assertions(spec, &body) {
                return failure_result(&spec.route_name, started_at_ms, latency_ms, status, &msg);
            }
            success_result(&spec.route_name, started_at_ms, latency_ms, status)
        }
        Err(err) => failure_result(
            &spec.route_name,
            started_at_ms,
            started.elapsed().as_millis() as u64,
            0,
            &err,
        ),
    }
}

/// Execute a multi-step journey (DP-10, #238). Each step is executed
/// sequentially; extracted values are substituted into subsequent
/// step headers via `{{var}}` templates.
async fn run_journey(
    spec: &ProbeSpec,
    steps: &[ProbeStep],
    _base_url: &str,
    started: std::time::Instant,
    started_at_ms: u64,
) -> ProbeResult {
    let mut extracted: HashMap<String, String> = HashMap::new();

    for step in steps {
        let method = if step.method.is_empty() {
            "GET"
        } else {
            step.method.as_str()
        };
        // Substitute {{var}} templates in headers.
        let headers: Vec<(String, String)> = step
            .headers
            .iter()
            .map(|(k, v)| {
                let mut substituted = v.clone();
                for (ek, ev) in &extracted {
                    substituted = substituted.replace(&format!("{{{{{}}}}}", ek), ev);
                }
                (k.clone(), substituted)
            })
            .collect();

        let result = execute_http(
            &step.url,
            method,
            &headers,
            step.body.as_deref(),
            spec.timeout,
            spec.probe_from.as_deref(),
        )
        .await;

        match result {
            Ok((status, body)) => {
                if status != step.expected_status {
                    return failure_result(
                        &spec.route_name,
                        started_at_ms,
                        started.elapsed().as_millis() as u64,
                        status,
                        &format!(
                            "journey step {:?}: expected status {} got {}",
                            step.url, step.expected_status, status
                        ),
                    );
                }
                // Extract values for subsequent steps.
                if let (Some(name), Some(path)) = (&step.extract_name, &step.extract_jsonpath) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body) {
                        if let Some(extracted_val) = jsonpath_get(&val, path) {
                            extracted.insert(name.clone(), extracted_val);
                        }
                    }
                }
            }
            Err(err) => {
                return failure_result(
                    &spec.route_name,
                    started_at_ms,
                    started.elapsed().as_millis() as u64,
                    0,
                    &format!("journey step {:?}: {}", step.url, err),
                );
            }
        }
    }

    success_result(
        &spec.route_name,
        started_at_ms,
        started.elapsed().as_millis() as u64,
        200,
    )
}

/// Extract a string value from a JSON value using a simple dot-notation
/// path (e.g. `$.token`, `$.data.id`).
fn jsonpath_get(value: &serde_json::Value, path: &str) -> Option<String> {
    let trimmed = path.strip_prefix("$.").unwrap_or(path);
    let mut current = value;
    for segment in trimmed.split('.') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        if let Some(idx_end) = segment.find('[') {
            let key = &segment[..idx_end];
            let idx_str = &segment[idx_end + 1..].trim_end_matches(']');
            if !key.is_empty() {
                current = current.get(key)?;
            }
            if let Ok(idx) = idx_str.parse::<usize>() {
                current = current.get(idx)?;
            } else {
                return None;
            }
        } else {
            current = current.get(segment)?;
        }
    }
    match current {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => current.as_str().map(|s| s.to_string()),
    }
}

/// Low-level HTTP execution: send a request, return (status, body) or
/// an error string. Uses a simple TCP+HTTP/1.1 client to avoid pulling
/// a heavy HTTP client dependency into the synthetic module (the
/// dataplane's upstream client is upstream-pool-specific and not
/// suitable for arbitrary probe URLs).
async fn execute_http(
    url: &str,
    method: &str,
    headers: &[(String, String)],
    body: Option<&str>,
    timeout: Duration,
    probe_from: Option<&str>,
) -> Result<(u16, String), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    // Parse the URL: scheme://host:port/path
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("invalid url {:?}: no scheme", url))?;
    let is_tls = scheme == "https";
    let (authority, path) = rest
        .split_once('/')
        .map(|(a, p)| (a, format!("/{}", p)))
        .unwrap_or((rest, "/".to_string()));
    let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
        (
            h.to_string(),
            p.parse::<u16>().map_err(|e| format!("invalid port: {e}"))?,
        )
    } else {
        (authority.to_string(), if is_tls { 443 } else { 80 })
    };

    let connect_addr = format!("{}:{}", host, port);
    let stream = tokio::time::timeout(timeout, TcpStream::connect(&connect_addr))
        .await
        .map_err(|_| format!("connect timeout to {}", connect_addr))?
        .map_err(|e| format!("connect failed: {e}"))?;

    // For TLS, we'd need a TLS client; synthetic probes to https URLs
    // are supported but require the rustls connector. For now, only
    // plaintext HTTP is supported (http:// URLs). TLS support can be
    // added by wiring in the existing rustls client setup.
    if is_tls {
        return Err(
            "https probe URLs are not yet supported; use http:// for synthetic probes".to_string(),
        );
    }

    let mut stream = stream;
    let _ = stream.set_nodelay(true);

    // Build the HTTP/1.1 request.
    let mut req = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", method, path, host);
    for (k, v) in headers {
        req.push_str(&format!("{}: {}\r\n", k, v));
    }
    if let Some(pf) = probe_from {
        req.push_str(&format!("X-Dwara-Probe-From: {}\r\n", pf));
    }
    if let Some(body) = body {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
        req.push_str("\r\n");
        req.push_str(body);
    } else {
        req.push_str("Connection: close\r\n\r\n");
    }

    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("write failed: {e}"))?;

    // Read the full response.
    let mut response = Vec::new();
    tokio::time::timeout(timeout, stream.read_to_end(&mut response))
        .await
        .map_err(|_| "response timeout".to_string())?
        .map_err(|e| format!("read failed: {e}"))?;

    let response_str = String::from_utf8_lossy(&response);
    // Parse status line: HTTP/1.1 200 OK
    let status: u16 = response_str
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Split headers and body.
    let body = response_str
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();

    Ok((status, body))
}

// --- Probe scheduler (DP-10, #238) ----------------------------------------

/// A probe scheduler: spawns a background task per probe that runs
/// the probe on its configured interval and feeds results into a
/// [`ProbeRunner`]. State transitions (alert/recovery) are emitted
/// as events.
///
/// The scheduler owns the [`ProbeRunner`] behind a `Mutex` so the
/// background tasks can feed results concurrently. The caller
/// typically holds a handle to the scheduler for graceful shutdown.
pub struct ProbeScheduler {
    runner: std::sync::Arc<tokio::sync::Mutex<ProbeRunner>>,
    emitter: Option<crate::events::Emitter>,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl ProbeScheduler {
    /// Create a new scheduler from probe specs. The scheduler does
    /// not start until [`ProbeScheduler::start`] is called.
    pub fn new(specs: Vec<ProbeSpec>, emitter: Option<crate::events::Emitter>) -> Self {
        ProbeScheduler {
            runner: std::sync::Arc::new(tokio::sync::Mutex::new(ProbeRunner::new(specs))),
            emitter,
            handles: Vec::new(),
        }
    }

    /// Start the scheduler: spawns one background task per probe.
    /// Each task runs the probe on its interval, feeds the result
    /// into the runner, and emits events on state transitions.
    pub fn start(&mut self) {
        let runner = std::sync::Arc::clone(&self.runner);
        let emitter = self.emitter.clone();
        let specs: Vec<ProbeSpec> = runner
            .try_lock()
            .expect("runner not locked at start")
            .specs()
            .cloned()
            .collect();
        for spec in specs {
            let runner = std::sync::Arc::clone(&runner);
            let emitter = emitter.clone();
            let handle = tokio::spawn(async move {
                let mut interval = tokio::time::interval(spec.interval);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    interval.tick().await;
                    let result = run_probe(&spec).await;
                    let outcome = {
                        let mut guard = runner.lock().await;
                        guard.process_result(&result)
                    };
                    // Emit events on state transitions.
                    if let Some(ref emitter) = emitter {
                        match outcome {
                            ProbeOutcome::AlertFired => {
                                emitter.emit(
                                    crate::events::EventKind::ProbeFailed,
                                    crate::events::EventPayload::probe(
                                        &spec.route_name,
                                        result.status,
                                        result.latency_ms,
                                        result.error.as_deref(),
                                    ),
                                );
                            }
                            ProbeOutcome::Recovered => {
                                emitter.emit(
                                    crate::events::EventKind::ProbeRecovered,
                                    crate::events::EventPayload::probe(
                                        &spec.route_name,
                                        result.status,
                                        result.latency_ms,
                                        None,
                                    ),
                                );
                            }
                            _ => {}
                        }
                    }
                }
            });
            self.handles.push(handle);
        }
    }

    /// Abort all background probe tasks.
    pub fn shutdown(&mut self) {
        for handle in self.handles.drain(..) {
            handle.abort();
        }
    }

    /// Get a snapshot of the probe runner (e.g. for admin API queries).
    pub fn runner(&self) -> std::sync::Arc<tokio::sync::Mutex<ProbeRunner>> {
        std::sync::Arc::clone(&self.runner)
    }
}

impl Drop for ProbeScheduler {
    fn drop(&mut self) {
        self.shutdown();
    }
}
