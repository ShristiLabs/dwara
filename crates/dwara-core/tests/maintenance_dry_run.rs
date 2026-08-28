//! Maintenance mode and policy dry-run integration tests (DW-041,
//! feature analysis sections 5-Traffic and 9.3).
//!
//! Drives `proxy::handle` directly against small in-process backends and
//! pins both halves of the feature:
//!
//! - MAINTENANCE: a route with a `maintenance` block answers 503 +
//!   `Retry-After` + the `maintenance` JSON envelope BEFORE its route
//!   limits, its CORS preflight short-circuit (preflights stay 204), and
//!   its action (redirect/respond never run, the upstream is never
//!   contacted); other routes and the reserved paths are spared; the
//!   state hot-toggles through the ordinary reload pipeline
//!   (compile_and_publish + refresh).
//! - DRY RUN: every policy phase that can reject — route limits (413/
//!   431), authz (401/403), rate limiting (429, routed and unrouted),
//!   load shedding (503) — evaluates and REPORTS (the
//!   `dwara_policy_dry_run_total{phase,route}` metric plus one
//!   `dwara::policy` warn event) while letting the request PROCEED; the
//!   same configs with the flag off enforce exactly as before; mixed
//!   live/dry attachments on one route keep the LIVE deny authoritative
//!   (dry run never makes enforcement more permissive).

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use dwara_core::config::parse_gateway;
use dwara_core::observability::ListenerLabel;
use dwara_core::proxy::DataPlane;
use dwara_core::snapshot::ConfigState;
use hmac::{Hmac, Mac};
use http_body_util::{BodyExt, Full};
use hyper::header::HeaderMap;
use hyper::Request;
use hyper::StatusCode;
use sha2::{Digest, Sha256};
use tracing_subscriber::layer::SubscriberExt as _;

mod support;

// --- fixtures ---------------------------------------------------------------

fn peer() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

/// Publish `yaml` and build a dataplane over the state (the caller keeps
/// the state for hot-toggle republishes).
fn publish(yaml: &str) -> (Arc<ConfigState>, Arc<DataPlane>) {
    let gateway = parse_gateway(yaml).expect("test config parses");
    let state = Arc::new(ConfigState::new());
    state
        .compile_and_publish(&gateway)
        .expect("test config publishes");
    let dp = DataPlane::new(Arc::clone(&state));
    (state, dp)
}

fn dp_from(yaml: &str) -> Arc<DataPlane> {
    publish(yaml).1
}

/// Republish `yaml` against the running state and refresh the dataplane
/// — the exact mechanism the binary's reload path drives.
fn republish(state: &ConfigState, dp: &DataPlane, yaml: &str) {
    let gateway = parse_gateway(yaml).expect("test config parses");
    state
        .compile_and_publish(&gateway)
        .expect("test config publishes");
    dp.refresh();
}

fn req(path: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .uri(path)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

fn req_with(path: &str, headers: &[(&str, &str)]) -> Request<Full<Bytes>> {
    let mut builder = Request::builder().uri(path);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Full::new(Bytes::new())).unwrap()
}

async fn envelope(
    dp: &DataPlane,
    request: Request<Full<Bytes>>,
) -> (StatusCode, serde_json::Value, HeaderMap) {
    let resp = dwara_core::proxy::handle(dp, peer(), request).await;
    let (parts, body) = resp.into_parts();
    let text =
        String::from_utf8(body.collect().await.expect("body").to_bytes().to_vec()).expect("utf8");
    let json = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    (parts.status, json, parts.headers)
}

/// `envelope` for responses whose body need not be JSON (e.g. a
/// compressed control response).
async fn status_and_headers(
    dp: &DataPlane,
    request: Request<Full<Bytes>>,
) -> (StatusCode, HeaderMap) {
    let resp = dwara_core::proxy::handle(dp, peer(), request).await;
    let status = resp.status();
    let headers = resp.headers().clone();
    let _ = resp.into_body().collect().await;
    (status, headers)
}

fn error_code(json: &serde_json::Value) -> &str {
    json["error"]["code"].as_str().unwrap_or("")
}

fn error_message(json: &serde_json::Value) -> &str {
    json["error"]["message"].as_str().unwrap_or("")
}

/// Read one `dwara_policy_dry_run_total{phase,route}` series from the
/// rendered /metrics text (0 when the series does not exist yet).
fn dry_run_total(dp: &DataPlane, phase: &str, route: &str) -> u64 {
    let text = dp.observability().render();
    let want = format!("dwara_policy_dry_run_total{{phase=\"{phase}\",route=\"{route}\"}}");
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(&want) {
            return rest.trim().parse().unwrap_or(0);
        }
    }
    0
}

// Suite-local variant of the capturing subscriber (the observability
// suite's fixture is local to that suite by repo convention). Tests run
// on the current-thread runtime, so set_default captures every event the
// request opens on this thread.
#[derive(Default)]
struct FieldVisitor {
    fields: Vec<(String, String)>,
}

impl tracing::field::Visit for FieldVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.fields
            .push((field.name().to_string(), format!("{value:?}")));
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }
}

type CapturedEvent = (String, Vec<(String, String)>);

#[derive(Clone, Default)]
struct Capture {
    events: Arc<Mutex<Vec<CapturedEvent>>>,
}

impl<S> tracing_subscriber::Layer<S> for Capture
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        self.events
            .lock()
            .unwrap()
            .push((event.metadata().target().to_string(), visitor.fields));
    }
}

fn capture() -> (Capture, tracing::subscriber::DefaultGuard) {
    let cap = Capture::default();
    let guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(cap.clone()));
    (cap, guard)
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> &'a str {
    &fields
        .iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("field {name} missing in {fields:?}"))
        .1
}

/// The `dwara::policy` dry-run events captured so far.
fn policy_events(cap: &Capture) -> Vec<Vec<(String, String)>> {
    cap.events
        .lock()
        .unwrap()
        .iter()
        .filter(|(t, _)| t == "dwara::policy")
        .cloned()
        .map(|(_, f)| f)
        .collect()
}

// --- maintenance: config shapes ----------------------------------------------

fn maintenance_yaml(port: u16, maintenance: &str) -> String {
    format!(
        "routes:\n\
         - name: main\n\
         \x20 service: svc\n\
         {maintenance}\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action: {{ type: proxy }}\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port}\n"
    )
}

// --- maintenance ----------------------------------------------------------

#[tokio::test]
async fn maintenance_503_retry_after_envelope_without_upstream_contact() {
    let (port, hits) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::from_static(b"hello"))),
        Duration::from_millis(0),
    )
    .await;
    let dp = dp_from(&maintenance_yaml(port, "  maintenance: {}\n"));

    let (status, json, headers) = envelope(&dp, req("/api/things")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(&json), "maintenance");
    assert_eq!(error_message(&json), "route under maintenance");
    assert!(json["error"]["request_id"].as_str().is_some());
    assert_eq!(
        headers.get(hyper::header::RETRY_AFTER).unwrap(),
        "60",
        "absent retry_after_secs falls back to the 60s default"
    );
    assert!(
        headers.get(hyper::header::WWW_AUTHENTICATE).is_none(),
        "maintenance is not an authentication failure"
    );
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the upstream must never be contacted during maintenance"
    );

    // A request ID offered by the client is echoed (same envelope rule
    // as every gateway-generated response).
    let (status, json, headers) = envelope(
        &dp,
        req_with("/api/other", &[("x-request-id", "maint-req-1")]),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json["error"]["request_id"].as_str(), Some("maint-req-1"));
    assert_eq!(headers.get("x-request-id").unwrap(), "maint-req-1");
}

#[tokio::test]
async fn maintenance_custom_retry_after_and_message() {
    let (port, _) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::new())),
        Duration::from_millis(0),
    )
    .await;
    let dp = dp_from(&maintenance_yaml(
        port,
        "  maintenance:\n    retry_after_secs: 30\n    message: back soon\n",
    ));

    let (status, json, headers) = envelope(&dp, req("/api/x")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(headers.get(hyper::header::RETRY_AFTER).unwrap(), "30");
    assert_eq!(error_code(&json), "maintenance");
    assert_eq!(error_message(&json), "back soon");
}

#[tokio::test]
async fn maintenance_precedes_redirect_and_respond_actions() {
    let (port, _) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::new())),
        Duration::from_millis(0),
    )
    .await;
    let yaml = format!(
        "routes:\n\
         - name: red\n\
         \x20 service: svc\n\
         \x20 maintenance: {{}}\n\
         \x20 match:\n\
         \x20   path: {{ type: exact, value: /go }}\n\
         \x20 action:\n\
         \x20   type: redirect\n\
         \x20   status: 302\n\
         - name: fixed\n\
         \x20 service: svc\n\
         \x20 maintenance: {{}}\n\
         \x20 match:\n\
         \x20   path: {{ type: exact, value: /fixed }}\n\
         \x20 action:\n\
         \x20   type: respond\n\
         \x20   status: 200\n\
         \x20   body: hi\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port}\n"
    );
    let dp = dp_from(&yaml);

    let (status, json, headers) = envelope(&dp, req("/go")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "redirect muted");
    assert_eq!(error_code(&json), "maintenance");
    assert!(headers.get(hyper::header::LOCATION).is_none());

    let (status, json, _) = envelope(&dp, req("/fixed")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "respond muted");
    assert_eq!(error_code(&json), "maintenance");
}

#[tokio::test]
async fn maintenance_cors_preflight_204_actual_503_readable_by_browser() {
    let (port, hits) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::new())),
        Duration::from_millis(0),
    )
    .await;
    let yaml = format!(
        "routes:\n\
         - name: corsy\n\
         \x20 service: svc\n\
         \x20 maintenance: {{}}\n\
         \x20 cors:\n\
         \x20   allowed_origins: [\"https://example.com\"]\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20   methods: [GET, OPTIONS]\n\
         \x20 action: {{ type: proxy }}\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port}\n"
    );
    let dp = dp_from(&yaml);

    // Preflight: still answered 204 by the gateway (the Fetch handshake
    // is about cross-origin POLICY, not backend availability — failing
    // it would surface as an opaque CORS error and hide the 503).
    let preflight = Request::builder()
        .method(hyper::Method::OPTIONS)
        .uri("/api/x")
        .header("origin", "https://example.com")
        .header("access-control-request-method", "GET")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status, _, headers) = envelope(&dp, preflight).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "preflights stay 204");
    assert_eq!(
        headers.get("access-control-allow-origin").unwrap(),
        "https://example.com"
    );

    // Actual request: 503 with the CORS actual-response headers, so a
    // browser client can READ the maintenance envelope cross-origin.
    let (status, json, headers) = envelope(
        &dp,
        req_with("/api/x", &[("origin", "https://example.com")]),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(&json), "maintenance");
    assert_eq!(
        headers.get("access-control-allow-origin").unwrap(),
        "https://example.com",
        "the maintenance 503 carries the CORS actual headers"
    );
    let vary = headers
        .get(hyper::header::VARY)
        .map(|v| v.to_str().unwrap());
    assert!(vary.is_some_and(|v| v.contains("Origin")));
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn maintenance_precedes_route_limits() {
    let (port, _) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::new())),
        Duration::from_millis(0),
    )
    .await;
    let yaml = format!(
        "routes:\n\
         - name: main\n\
         \x20 service: svc\n\
         \x20 maintenance: {{}}\n\
         \x20 limits:\n\
         \x20   max_header_bytes: 10\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action: {{ type: proxy }}\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port}\n"
    );
    let dp = dp_from(&yaml);

    // The request's headers far exceed max_header_bytes: 10, but
    // maintenance answers first — the operator's statement is about the
    // ROUTE, not the request's shape.
    let (status, json, _) =
        envelope(&dp, req_with("/api/x", &[("x-big", "0123456789abcdef")])).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(&json), "maintenance");
}

#[tokio::test]
async fn maintenance_hot_toggles_through_the_reload_pipeline() {
    let (port, _) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::from_static(b"hello"))),
        Duration::from_millis(0),
    )
    .await;
    let plain = maintenance_yaml(port, "");
    let maintaining = maintenance_yaml(port, "  maintenance: {}\n");
    let (state, dp) = publish(&plain);

    let (status, _, _) = envelope(&dp, req("/api/x")).await;
    assert_eq!(status, StatusCode::OK, "no maintenance block: serves");

    republish(&state, &dp, &maintaining);
    let (status, json, headers) = envelope(&dp, req("/api/x")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(&json), "maintenance");
    assert_eq!(headers.get(hyper::header::RETRY_AFTER).unwrap(), "60");

    republish(&state, &dp, &plain);
    let (status, _, _) = envelope(&dp, req("/api/x")).await;
    assert_eq!(status, StatusCode::OK, "maintenance lifted: serves again");
}

#[tokio::test]
async fn maintenance_spares_other_routes_and_reserved_paths() {
    let (port, _) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::from_static(b"hello"))),
        Duration::from_millis(0),
    )
    .await;
    let yaml = format!(
        "routes:\n\
         - name: down\n\
         \x20 service: svc\n\
         \x20 maintenance: {{}}\n\
         \x20 match:\n\
         \x20   path: {{ type: prefix, value: /down }}\n\
         \x20 action: {{ type: proxy }}\n\
         - name: up-route\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path: {{ type: prefix, value: /up }}\n\
         \x20 action: {{ type: proxy }}\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port}\n"
    );
    let dp = dp_from(&yaml);

    let (status, json, _) = envelope(&dp, req("/down/x")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(&json), "maintenance");

    let (status, _, _) = envelope(&dp, req("/up/x")).await;
    assert_eq!(status, StatusCode::OK, "sibling route unaffected");

    let (status, json, _) = envelope(&dp, req("/healthz")).await;
    assert_eq!(status, StatusCode::OK, "reserved paths answer first");
    assert_eq!(error_code(&json), "ok");

    let (status, json, _) = envelope(&dp, req("/nowhere")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unrouted stays 404");
    assert_eq!(error_code(&json), "no_route");
}

// --- dry run: shared config shapes -----------------------------------------

fn consumer_yaml(port: u16, route_extra: &str, tail_extra: &str) -> String {
    format!(
        "routes:\n\
         - name: main\n\
         \x20 service: svc\n\
         {route_extra}\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action: {{ type: proxy }}\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port}\n\
         consumers:\n\
         - name: alpha\n\
         \x20 credentials:\n\
         \x20   - type: api_key\n\
         \x20     key: test-key-123\n\
         {tail_extra}"
    )
}

// --- dry run: route limits -------------------------------------------------

#[tokio::test]
#[serial_test::serial]
async fn route_limits_dry_run_allows_with_metric_and_log() {
    let (port, hits) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::from_static(b"hello"))),
        Duration::from_millis(0),
    )
    .await;
    let yaml = format!(
        "routes:\n\
         - name: main\n\
         \x20 service: svc\n\
         \x20 limits:\n\
         \x20   max_header_count: 2\n\
         \x20   dry_run: true\n\
         \x20 match:\n\
         \x20   path: {{ type: prefix, value: /api }}\n\
         \x20 action: {{ type: proxy }}\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port}\n"
    );
    let dp = dp_from(&yaml);
    let (cap, _guard) = capture();

    // 4 headers against a cap of 2: would be 431, is allowed.
    let (status, _, _) = envelope(
        &dp,
        req_with("/api/x", &[("a", "1"), ("b", "2"), ("c", "3"), ("d", "4")]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "dry-run violation is not enforced");
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);

    assert_eq!(dry_run_total(&dp, "route_limits", "main"), 1);
    let events = policy_events(&cap);
    assert_eq!(events.len(), 1, "one dwara::policy event: {events:?}");
    assert_eq!(field(&events[0], "phase"), "route_limits");
    assert_eq!(field(&events[0], "would_be_status"), "431");
    assert_eq!(field(&events[0], "route"), "main");
    assert!(field(&events[0], "detail").contains("header fields"));
}

#[tokio::test]
async fn route_limits_enforced_when_flag_off() {
    let (port, _) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::new())),
        Duration::from_millis(0),
    )
    .await;
    let yaml = format!(
        "routes:\n\
         - name: main\n\
         \x20 service: svc\n\
         \x20 limits:\n\
         \x20   max_header_count: 2\n\
         \x20 match:\n\
         \x20   path: {{ type: prefix, value: /api }}\n\
         \x20 action: {{ type: proxy }}\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port}\n"
    );
    let dp = dp_from(&yaml);

    let (status, json, _) = envelope(
        &dp,
        req_with("/api/x", &[("a", "1"), ("b", "2"), ("c", "3")]),
    )
    .await;
    assert_eq!(status, StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
    assert_eq!(error_code(&json), "request_headers_too_large");
    assert_eq!(dry_run_total(&dp, "route_limits", "main"), 0);
}

// --- dry run: authz --------------------------------------------------------

#[tokio::test]
#[serial_test::serial]
async fn authz_dry_run_allows_would_be_denied_consumer() {
    let (port, _) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::from_static(b"hello"))),
        Duration::from_millis(0),
    )
    .await;
    let yaml = consumer_yaml(
        port,
        "  authorization:\n    denied_consumers: [alpha]\n    dry_run: true\n",
        "",
    );
    let dp = dp_from(&yaml);
    let (cap, _guard) = capture();

    let (status, _, _) = envelope(&dp, req_with("/api/x", &[("x-api-key", "test-key-123")])).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a dry-run authz deny proceeds to the upstream"
    );

    assert_eq!(dry_run_total(&dp, "authz", "main"), 1);
    let events = policy_events(&cap);
    assert_eq!(events.len(), 1, "one dwara::policy event: {events:?}");
    assert_eq!(field(&events[0], "phase"), "authz");
    assert_eq!(field(&events[0], "would_be_status"), "403");
    assert_eq!(field(&events[0], "route"), "main");
    assert_eq!(field(&events[0], "consumer"), "alpha");
    assert!(field(&events[0], "detail").contains("route level"));
}

#[tokio::test]
async fn authz_enforced_when_flag_off() {
    let (port, _) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::new())),
        Duration::from_millis(0),
    )
    .await;
    let yaml = consumer_yaml(
        port,
        "  authorization:\n    denied_consumers: [alpha]\n",
        "",
    );
    let dp = dp_from(&yaml);

    let (status, json, _) =
        envelope(&dp, req_with("/api/x", &[("x-api-key", "test-key-123")])).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error_code(&json), "forbidden");
    assert_eq!(dry_run_total(&dp, "authz", "main"), 0);
}

/// The dry-run invariant: monitor mode never makes enforcement MORE
/// permissive. A route-level dry deny is observed, but the walk
/// continues and the service-level LIVE deny still rejects.
#[tokio::test]
#[serial_test::serial]
async fn authz_live_deny_enforced_despite_more_specific_dry_deny() {
    let (port, _) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::new())),
        Duration::from_millis(0),
    )
    .await;
    let yaml = format!(
        "routes:\n\
         - name: main\n\
         \x20 service: svc\n\
         \x20 authorization:\n\
         \x20   denied_consumers: [alpha]\n\
         \x20   dry_run: true\n\
         \x20 match:\n\
         \x20   path: {{ type: prefix, value: /api }}\n\
         \x20 action: {{ type: proxy }}\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         \x20 authorization:\n\
         \x20   denied_consumers: [alpha]\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port}\n\
         consumers:\n\
         - name: alpha\n\
         \x20 credentials:\n\
         \x20   - type: api_key\n\
         \x20     key: test-key-123\n"
    );
    let dp = dp_from(&yaml);
    let (cap, _guard) = capture();

    let (status, json, _) =
        envelope(&dp, req_with("/api/x", &[("x-api-key", "test-key-123")])).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "the live service deny wins");
    assert_eq!(error_code(&json), "forbidden");
    assert_eq!(
        dry_run_total(&dp, "authz", "main"),
        1,
        "the route-level dry deny is still OBSERVED while the live deny enforces"
    );
    let events = policy_events(&cap);
    assert_eq!(events.len(), 1);
    assert!(field(&events[0], "detail").contains("route level"));
}

// --- dry run: rate limiting ------------------------------------------------

fn rate_limit_yaml(port: u16, policies: &str, route_policies: &str, tail: &str) -> String {
    format!(
        "{policies}\
         routes:\n\
         - name: main\n\
         \x20 service: svc\n\
         {route_policies}\
         \x20 match:\n\
         \x20   path: {{ type: prefix, value: /api }}\n\
         \x20 action: {{ type: proxy }}\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port}\n{tail}"
    )
}

const TIGHT_RULE: &str = "    rate_limits:\n      - selector: [route]\n        \
                          requests_per: { s: 1 }\n        burst: 1\n";

#[tokio::test]
#[serial_test::serial]
async fn rate_limit_dry_run_allows_without_headers_with_metric_and_log() {
    let (port, hits) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::from_static(b"hello"))),
        Duration::from_millis(0),
    )
    .await;
    let yaml = rate_limit_yaml(
        port,
        &format!("policies:\n  - name: tight\n    dry_run: true\n{TIGHT_RULE}"),
        "  policies: [tight]\n",
        "",
    );
    let dp = dp_from(&yaml);
    let (cap, _guard) = capture();

    let (status, _, headers) = envelope(&dp, req("/api/x")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers.get("x-ratelimit-limit").is_none(),
        "a dry bundle contributes no rate headers, allowed or denied"
    );

    // The bucket still advances: the second request inside the window
    // WOULD be denied — reported, not enforced.
    let (status, _, headers) = envelope(&dp, req("/api/x")).await;
    assert_eq!(status, StatusCode::OK, "dry-run denial is not enforced");
    assert!(
        headers.get("x-ratelimit-limit").is_none(),
        "no rate headers from a dry bundle on the would-deny either"
    );
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 2);

    assert_eq!(dry_run_total(&dp, "rate_limit", "main"), 1);
    let events = policy_events(&cap);
    assert_eq!(events.len(), 1, "one dwara::policy event: {events:?}");
    assert_eq!(field(&events[0], "phase"), "rate_limit");
    assert_eq!(field(&events[0], "would_be_status"), "429");
    assert_eq!(field(&events[0], "route"), "main");
}

#[tokio::test]
async fn rate_limit_enforced_when_flag_off() {
    let (port, _) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::new())),
        Duration::from_millis(0),
    )
    .await;
    let yaml = rate_limit_yaml(
        port,
        &format!("policies:\n  - name: tight\n{TIGHT_RULE}"),
        "  policies: [tight]\n",
        "",
    );
    let dp = dp_from(&yaml);

    let (status, _, _) = envelope(&dp, req("/api/x")).await;
    assert_eq!(status, StatusCode::OK);
    let (status, json, headers) = envelope(&dp, req("/api/x")).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(error_code(&json), "rate_limit_exceeded");
    assert!(headers.get("x-ratelimit-limit").is_some());
    assert_eq!(dry_run_total(&dp, "rate_limit", "main"), 0);
}

/// Mixed dry/live attachments on one route: the LIVE bundle's denial is
/// a real 429 with real headers; the dry bundle's would-deny is still
/// reported. Dry run never mutes a live rejection.
#[tokio::test]
#[serial_test::serial]
async fn rate_limit_live_and_dry_bundles_on_one_route() {
    let (port, _) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::new())),
        Duration::from_millis(0),
    )
    .await;
    let yaml = rate_limit_yaml(
        port,
        &format!(
            "policies:\n  - name: dry-tight\n    dry_run: true\n{TIGHT_RULE}\
             \x20 - name: live-tight\n{TIGHT_RULE}"
        ),
        "  policies: [dry-tight, live-tight]\n",
        "",
    );
    let dp = dp_from(&yaml);
    let (cap, _guard) = capture();

    let (status, _, headers) = envelope(&dp, req("/api/x")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get("x-ratelimit-limit").unwrap(),
        "1",
        "the live bundle's headers bind the allowed response"
    );

    let (status, json, headers) = envelope(&dp, req("/api/x")).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "live bundle enforces"
    );
    assert_eq!(error_code(&json), "rate_limit_exceeded");
    assert_eq!(
        headers.get("x-ratelimit-limit").unwrap(),
        "1",
        "the 429 headers come from the live denying rule"
    );
    assert_eq!(
        dry_run_total(&dp, "rate_limit", "main"),
        1,
        "the dry bundle's would-deny is observed on the same request"
    );
    assert_eq!(policy_events(&cap).len(), 1);
}

#[tokio::test]
#[serial_test::serial]
async fn unrouted_global_dry_run_reports_on_404() {
    let (port, _) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::new())),
        Duration::from_millis(0),
    )
    .await;
    let yaml = rate_limit_yaml(
        port,
        "policies:\n  - name: g\n    dry_run: true\n    rate_limits:\n      \
         - selector: [ip]\n        requests_per: { s: 1 }\n        burst: 1\n",
        "",
        "global_policies: [g]\n",
    );
    let dp = dp_from(&yaml);
    let (cap, _guard) = capture();

    let (status, json, _) = envelope(&dp, req("/unknown")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(error_code(&json), "no_route");

    let (status, json, _) = envelope(&dp, req("/unknown")).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a dry global policy does not 429 unrouted traffic"
    );
    assert_eq!(error_code(&json), "no_route");
    assert_eq!(
        dry_run_total(&dp, "rate_limit", "unrouted"),
        1,
        "the unrouted pass reports under the 'unrouted' route label"
    );
    let events = policy_events(&cap);
    assert_eq!(events.len(), 1);
    assert_eq!(field(&events[0], "route"), "unrouted");
}

// --- dry run: load shedding -----------------------------------------------

fn cap_yaml(port: u16, gateway_extra: &str) -> String {
    format!(
        "{gateway_extra}\
         routes:\n\
         - name: main\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path: {{ type: prefix, value: /api }}\n\
         \x20 action: {{ type: proxy }}\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port}\n"
    )
}

async fn two_concurrent(dp: Arc<DataPlane>) -> (StatusCode, StatusCode) {
    let a = async {
        let resp = dwara_core::proxy::handle(&dp, peer(), req("/api/a")).await;
        let status = resp.status();
        let _ = resp.into_body().collect().await;
        status
    };
    let b = async {
        let resp = dwara_core::proxy::handle(&dp, peer(), req("/api/b")).await;
        let status = resp.status();
        let _ = resp.into_body().collect().await;
        status
    };
    tokio::join!(a, b)
}

#[tokio::test]
#[serial_test::serial]
async fn load_shed_dry_run_admits_over_cap_with_metric_and_log() {
    let (port, hits) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::from_static(b"hello"))),
        // Long enough that the second request always arrives while the
        // first still holds the single permit; short enough to keep the
        // test brisk (generous margin either way).
        Duration::from_millis(300),
    )
    .await;
    let dp = dp_from(&cap_yaml(
        port,
        "max_concurrent_requests: 1\nload_shed_dry_run: true\n",
    ));
    let (cap, _guard) = capture();

    let (first, second) = two_concurrent(Arc::clone(&dp)).await;
    assert_eq!(first, StatusCode::OK);
    assert_eq!(
        second,
        StatusCode::OK,
        "the would-shed request is admitted over the cap in monitor mode"
    );
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 2);

    assert_eq!(dry_run_total(&dp, "load_shed", "main"), 1);
    assert_eq!(dp.priority_counters().admitted_at(5), 2);
    assert_eq!(dp.priority_counters().shed_at(5), 0, "nothing was shed");
    let events = policy_events(&cap);
    assert_eq!(events.len(), 1, "one dwara::policy event: {events:?}");
    assert_eq!(field(&events[0], "phase"), "load_shed");
    assert_eq!(field(&events[0], "would_be_status"), "503");
    assert!(field(&events[0], "detail").contains("priority 5"));
}

#[tokio::test]
async fn load_shed_enforced_when_flag_off() {
    let (port, _) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::from_static(b"hello"))),
        Duration::from_millis(300),
    )
    .await;
    let dp = dp_from(&cap_yaml(port, "max_concurrent_requests: 1\n"));

    let (first, second) = two_concurrent(Arc::clone(&dp)).await;
    assert_eq!(first, StatusCode::OK);
    assert_eq!(second, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(dp.priority_counters().shed_at(5), 1);
    assert_eq!(dry_run_total(&dp, "load_shed", "main"), 0);
}

// --- validation ------------------------------------------------------------

#[test]
fn maintenance_validation_rejects_zero_retry_and_empty_message() {
    let base = maintenance_yaml(9, "  maintenance:\n    retry_after_secs: 0\n");
    let issues = dwara_core::snapshot::validate(&parse_gateway(&base).expect("parses"));
    assert!(
        issues
            .iter()
            .any(|i| i.field == "maintenance.retry_after_secs"),
        "{issues:?}"
    );

    let base = maintenance_yaml(9, "  maintenance:\n    message: \"  \"\n");
    let issues = dwara_core::snapshot::validate(&parse_gateway(&base).expect("parses"));
    assert!(
        issues.iter().any(|i| i.field == "maintenance.message"),
        "{issues:?}"
    );

    // The minimal block is valid.
    let base = maintenance_yaml(9, "  maintenance: {}\n");
    let issues = dwara_core::snapshot::validate(&parse_gateway(&base).expect("parses"));
    assert!(
        issues.is_empty(),
        "empty maintenance block is the minimal valid spelling: {issues:?}"
    );
}

#[test]
fn load_shed_dry_run_requires_a_cap() {
    let port = 9;
    let yaml = cap_yaml(port, "load_shed_dry_run: true\n");
    let issues = dwara_core::snapshot::validate(&parse_gateway(&yaml).expect("parses"));
    assert!(
        issues
            .iter()
            .any(|i| i.field == "load_shed_dry_run" && i.entity == "gateway"),
        "{issues:?}"
    );

    let yaml = cap_yaml(
        port,
        "max_concurrent_requests: 4\nload_shed_dry_run: true\n",
    );
    let issues = dwara_core::snapshot::validate(&parse_gateway(&yaml).expect("parses"));
    assert!(
        issues.is_empty(),
        "with a cap the flag is valid: {issues:?}"
    );
}

// --- maintenance interplay: the decoration tail -----------------------------

/// The 503 short-circuit returns BEFORE the response decoration tail:
/// no Deprecation/Sunset/Link stamps (those describe the route's
/// lifecycle, not an availability state) and no compression — not even
/// the `Vary: Accept-Encoding` a compression-configured route otherwise
/// always carries.
#[tokio::test]
async fn maintenance_503_skips_deprecation_stamps_and_compression() {
    let (port, _) = support::spawn_backend(
        |_n, _m, _p, _b| {
            hyper::Response::builder()
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(b"{\"ok\":true}")))
                .unwrap()
        },
        Duration::from_millis(0),
    )
    .await;
    let deprecation = "  deprecation:\n\
                     \x20   since: Mon, 01 Jan 2024 00:00:00 GMT\n\
                     \x20   sunset: Tue, 01 Jan 2030 00:00:00 GMT\n";
    let compression = "  compression:\n    min_size: 0\n";
    let yaml = format!(
        "routes:\n\
         - name: down\n\
         \x20 service: svc\n\
         \x20 maintenance: {{}}\n\
         {deprecation}\
         {compression}\
         \x20 match:\n\
         \x20   path: {{ type: prefix, value: /down }}\n\
         \x20 action: {{ type: proxy }}\n\
         - name: live\n\
         \x20 service: svc\n\
         {deprecation}\
         {compression}\
         \x20 match:\n\
         \x20   path: {{ type: prefix, value: /live }}\n\
         \x20 action: {{ type: proxy }}\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port}\n"
    );
    let dp = dp_from(&yaml);

    // Control: on the sibling route WITHOUT maintenance the same blocks
    // are active — the 200 is stamped and compressed.
    let (status, headers) =
        status_and_headers(&dp, req_with("/live/x", &[("accept-encoding", "gzip")])).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers.get("deprecation").is_some(),
        "control: the deprecation block is active on the sibling route"
    );
    assert!(
        headers.get("sunset").is_some(),
        "control: the sunset stamp is active on the sibling route"
    );
    assert_eq!(
        headers.get(hyper::header::CONTENT_ENCODING).unwrap(),
        "gzip",
        "control: the compression policy is active on the sibling route"
    );

    let (status, json, headers) =
        envelope(&dp, req_with("/down/x", &[("accept-encoding", "gzip")])).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(&json), "maintenance");
    assert_eq!(
        headers.get(hyper::header::CONTENT_ENCODING),
        None,
        "the maintenance 503 is never compressed"
    );
    let vary = headers
        .get(hyper::header::VARY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        !vary.to_ascii_lowercase().contains("accept-encoding"),
        "the short-circuit bypasses even the Vary-only branch: {vary:?}"
    );
    for absent in ["deprecation", "sunset", "link"] {
        assert!(
            headers.get(absent).is_none(),
            "the maintenance 503 carries no {absent} header"
        );
    }
    assert_eq!(
        headers.get(hyper::header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
}

// --- maintenance interplay: rate limiting -----------------------------------

/// Two routes share one service-level `[ip]`-keyed tight policy. The
/// maintenance 503s never reach the rate phase, so they consume NONE of
/// the shared budget (the first live request is still allowed) — and
/// once the budget IS exhausted, a maintenance request still answers
/// 503, not 429: maintenance is the earlier, coarser statement.
#[tokio::test]
async fn maintenance_503_wins_over_rate_limit_and_consumes_no_rate_budget() {
    let (port, hits) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::from_static(b"hello"))),
        Duration::from_millis(0),
    )
    .await;
    let yaml = format!(
        "policies:\n\
         \x20 - name: tight\n\
         \x20   rate_limits:\n\
         \x20     - selector: [ip]\n\
         \x20       requests_per: {{ minute: 1 }}\n\
         \x20       burst: 1\n\
         routes:\n\
         - name: down\n\
         \x20 service: svc\n\
         \x20 maintenance: {{}}\n\
         \x20 match:\n\
         \x20   path: {{ type: prefix, value: /down }}\n\
         \x20 action: {{ type: proxy }}\n\
         - name: up-route\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path: {{ type: prefix, value: /up }}\n\
         \x20 action: {{ type: proxy }}\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         \x20 policies: [tight]\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port}\n"
    );
    let dp = dp_from(&yaml);

    // Three maintenance 503s: none may touch the shared minute bucket.
    for _ in 0..3 {
        let (status, json, _) = envelope(&dp, req("/down/x")).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error_code(&json), "maintenance");
    }
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);

    let (status, _, _) = envelope(&dp, req("/up/x")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the maintenance requests consumed none of the shared [ip] budget"
    );

    let (status, json, _) = envelope(&dp, req("/up/x")).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "control: the shared policy is live and counts real requests"
    );
    assert_eq!(error_code(&json), "rate_limit_exceeded");

    let (status, json, _) = envelope(&dp, req("/down/x")).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "with the budget exhausted, maintenance still answers 503, not 429"
    );
    assert_eq!(error_code(&json), "maintenance");
}

// --- maintenance interplay: authentication ----------------------------------

const HMAC_SECRET: &str = "test-hmac-secret-0123456789abcdef0123456789abcdef";
const HMAC_KEY_ID: &str = "signer-key-1";

/// The independent conformance signer of the DW-036 grammar (the same
/// re-derivation as the hmac_signing suite; kept local so this suite
/// stays self-contained).
fn hmac_sign(target: &str, nonce: &str, timestamp: u64) -> Vec<(String, String)> {
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q.to_string()),
        None => (target, String::new()),
    };
    let digest = {
        let mut hasher = Sha256::new();
        hasher.update(b"");
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let timestamp = timestamp.to_string();
    let canonical = [
        "dwara-hmac-v1",
        HMAC_KEY_ID,
        "GET",
        path,
        &query,
        &timestamp,
        nonce,
        &digest,
    ]
    .join("\n");
    let mut mac = Hmac::<Sha256>::new_from_slice(HMAC_SECRET.as_bytes()).unwrap();
    mac.update(canonical.as_bytes());
    let signature: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    vec![
        ("x-dwara-key-id".to_string(), HMAC_KEY_ID.to_string()),
        ("x-dwara-timestamp".to_string(), timestamp),
        ("x-dwara-nonce".to_string(), nonce.to_string()),
        ("x-dwara-body-sha256".to_string(), digest),
        ("x-dwara-signature".to_string(), signature),
    ]
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn hmac_route_yaml(port: u16, maintenance: &str) -> String {
    format!(
        "hmac_auth:\n\
         \x20 max_clock_skew_secs: 300\n\
         routes:\n\
         - name: main\n\
         \x20 service: svc\n\
         {maintenance}\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action: {{ type: proxy }}\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port}\n\
         consumers:\n\
         - name: signer\n\
         \x20 credentials:\n\
         \x20   - type: hmac\n\
         \x20     key_id: {HMAC_KEY_ID}\n\
         \x20     secret: {HMAC_SECRET}\n"
    )
}

/// Authentication never runs for a maintenance 503, so an HMAC-signed
/// request's replay nonce is NOT burned: the very same signed request
/// succeeds once maintenance is lifted (a burned nonce would 401 as a
/// replay). The third send — after the successful one — proves the
/// nonce cache IS active on this dataplane, i.e. the test can detect a
/// burn.
#[tokio::test]
async fn maintenance_503_precedes_authn_so_an_hmac_nonce_is_not_burned() {
    let (port, hits) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::from_static(b"hello"))),
        Duration::from_millis(0),
    )
    .await;
    let signed = hmac_sign("/api/x", "maintenance-nonce-0001", now_secs());
    let headers: Vec<(&str, &str)> = signed
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let (state, dp) = publish(&hmac_route_yaml(port, "  maintenance: {}\n"));

    let (status, json, _) = envelope(&dp, req_with("/api/x", &headers)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(&json), "maintenance");

    // Lift maintenance; replay the SAME signed request. The nonce cache
    // survives generations, so this only succeeds if the 503 above left
    // the nonce unburned.
    republish(&state, &dp, &hmac_route_yaml(port, ""));
    let (status, _, _) = envelope(&dp, req_with("/api/x", &headers)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the maintenance 503 must not burn the HMAC nonce"
    );
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Detector control: the successful pass DID burn the nonce, so a
    // third identical send is a replay 401.
    let (status, json, _) = envelope(&dp, req_with("/api/x", &headers)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(&json), "unauthorized");
}

// --- dry run: multi-phase reports on one request -----------------------------

/// One request can trip THREE dry phases at once (route limits, authz,
/// rate limit): each reports independently — its own metric series and
/// its own `dwara::policy` event — in the documented request-path
/// order, and the request still reaches the upstream.
#[tokio::test]
#[serial_test::serial]
async fn multiple_dry_phases_report_independently_on_one_request() {
    let (port, hits) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::from_static(b"hello"))),
        Duration::from_millis(0),
    )
    .await;
    let yaml = format!(
        "policies:\n\
         \x20 - name: dry-tight\n\
         \x20   dry_run: true\n\
         \x20   rate_limits:\n\
         \x20     - selector: [route]\n\
         \x20       requests_per: {{ s: 1 }}\n\
         \x20       burst: 1\n\
         routes:\n\
         - name: main\n\
         \x20 service: svc\n\
         \x20 limits:\n\
         \x20   max_header_count: 2\n\
         \x20   dry_run: true\n\
         \x20 authorization:\n\
         \x20   denied_consumers: [alpha]\n\
         \x20   dry_run: true\n\
         \x20 policies: [dry-tight]\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action: {{ type: proxy }}\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port}\n\
         consumers:\n\
         - name: alpha\n\
         \x20 credentials:\n\
         \x20   - type: api_key\n\
         \x20     key: test-key-123\n"
    );
    let dp = dp_from(&yaml);
    let (cap, _guard) = capture();

    // Request 1: header-count violation (3 > 2) and the authz deny both
    // report; the dry rate bundle's fresh bucket still allows.
    let (status, _, headers) = envelope(
        &dp,
        req_with(
            "/api/x",
            &[("x-api-key", "test-key-123"), ("a", "1"), ("b", "2")],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "no dry phase enforces");
    assert!(
        headers.get(hyper::header::RETRY_AFTER).is_none(),
        "a dry rate bundle contributes no Retry-After on an allowed response"
    );
    let events = policy_events(&cap);
    let phases: Vec<&str> = events.iter().map(|f| field(f, "phase")).collect();
    assert_eq!(phases, vec!["route_limits", "authz"], "{events:?}");

    // Request 2: all three phases would reject — three independent
    // reports in request-path order, still one 200.
    let (status, _, _) = envelope(
        &dp,
        req_with(
            "/api/x",
            &[("x-api-key", "test-key-123"), ("a", "1"), ("b", "2")],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let events = policy_events(&cap);
    let phases: Vec<&str> = events.iter().map(|f| field(f, "phase")).collect();
    assert_eq!(
        phases,
        vec![
            "route_limits",
            "authz",
            "route_limits",
            "authz",
            "rate_limit"
        ],
        "every would-rejecting phase reports, in request-path order: {events:?}"
    );
    assert_eq!(dry_run_total(&dp, "route_limits", "main"), 2);
    assert_eq!(dry_run_total(&dp, "authz", "main"), 2);
    assert_eq!(dry_run_total(&dp, "rate_limit", "main"), 1);
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 2);
}

// --- dry run: listener attachment on unrouted traffic ------------------------

/// The pre-404 pass reports a LISTENER-attached dry policy exactly like
/// a global one (route label "unrouted") — the label plumbing through
/// `ListenerLabel` is part of the same evaluate call, pinned here.
#[tokio::test]
#[serial_test::serial]
async fn listener_attached_dry_policy_reports_on_unrouted_404() {
    let (port, _) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::new())),
        Duration::from_millis(0),
    )
    .await;
    let yaml = format!(
        "policies:\n\
         \x20 - name: edge-dry\n\
         \x20   dry_run: true\n\
         \x20   rate_limits:\n\
         \x20     - selector: [ip]\n\
         \x20       requests_per: {{ s: 1 }}\n\
         \x20       burst: 1\n\
         listeners:\n\
         \x20 - name: edge\n\
         \x20   address: 127.0.0.1\n\
         \x20   port: 18099\n\
         \x20   policies: [edge-dry]\n\
         routes:\n\
         - name: main\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path: {{ type: prefix, value: /api }}\n\
         \x20 action: {{ type: proxy }}\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port}\n"
    );
    let dp = dp_from(&yaml);
    let (cap, _guard) = capture();
    let unrouted = |path: &str| {
        Request::builder()
            .uri(path)
            .extension(ListenerLabel(Arc::from("edge")))
            .body(Full::new(Bytes::new()))
            .unwrap()
    };

    let (status, json, _) = envelope(&dp, unrouted("/unknown")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(error_code(&json), "no_route");

    let (status, _, _) = envelope(&dp, unrouted("/unknown")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        dry_run_total(&dp, "rate_limit", "unrouted"),
        1,
        "the listener-attached dry policy reports under 'unrouted'"
    );
    let events = policy_events(&cap);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(field(&events[0], "route"), "unrouted");
    assert_eq!(field(&events[0], "phase"), "rate_limit");
}

// --- dry run: load-shed accounting ------------------------------------------

/// Over-cap dry admission holds NO permit, so it cannot leak one: after
/// the two concurrent requests complete, the released permit admits a
/// sequential request WITHOUT a second would-shed report (a leaked slot
/// would saturate the cap again and increment the metric).
#[tokio::test]
#[serial_test::serial]
async fn load_shed_dry_run_over_cap_admission_leaks_no_slot() {
    let (port, hits) = support::spawn_backend(
        |_n, _m, _p, _b| hyper::Response::new(Full::new(Bytes::from_static(b"hello"))),
        Duration::from_millis(300),
    )
    .await;
    let dp = dp_from(&cap_yaml(
        port,
        "max_concurrent_requests: 1\nload_shed_dry_run: true\n",
    ));
    let (cap, _guard) = capture();

    let (first, second) = two_concurrent(Arc::clone(&dp)).await;
    assert_eq!(first, StatusCode::OK);
    assert_eq!(second, StatusCode::OK);
    assert_eq!(dry_run_total(&dp, "load_shed", "main"), 1);

    // The single permit was released by the first request: the third,
    // sequential request acquires it and must not look like a would-shed.
    let (status, _, _) = envelope(&dp, req("/api/c")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        dry_run_total(&dp, "load_shed", "main"),
        1,
        "over-cap dry admission leaked a concurrency slot"
    );
    assert_eq!(policy_events(&cap).len(), 1);
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 3);
}
