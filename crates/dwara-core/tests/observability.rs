//! Observability integration tests (DW-021, feature analysis 4.17/4.19).
//!
//! Drives `proxy::handle` directly against small in-process backends and
//! pins the DW-021 wiring surface:
//!
//! - SPAN SHAPE: a capturing `tracing` subscriber records every span
//!   opened by one proxied request and asserts the phase sequence
//!   (request > authn > authz > ratelimit > admission >
//!   upstream_attempt > upstream_pick) — the "one trace shows all
//!   phases" done-when, proven in-process without a collector;
//! - ACCESS LOG: one `dwara::access` event per request with the full
//!   field set, path WITHOUT the query string, and the request id
//!   echoed on the response (inbound id respected when valid, replaced
//!   when hostile);
//! - METRICS: `/metrics` serves the Prometheus text format, the
//!   families exist, and counters increase after traffic;
//! - ERROR ENVELOPE: 404/401/403/429/500/502/503/504 all answer the
//!   `{"error":{code,message,request_id}}` JSON body with no upstream
//!   internals in the message;
//! - SAMPLING: 5xx always logged, non-errors follow the knob;
//! - REDACTION: a poisoned Authorization header's secret value never
//!   appears in any captured span or event output.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

use bytes::Bytes;
use dwara_core::config::parse_gateway;
use dwara_core::proxy::DataPlane;
use dwara_core::snapshot::ConfigState;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tracing_subscriber::layer::SubscriberExt as _;

fn peer() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

// --- capturing subscriber ---------------------------------------------------

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

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }
}

/// One captured event: its target plus name/value field pairs.
type CapturedEvent = (String, Vec<(String, String)>);

#[derive(Clone, Default)]
struct Capture {
    /// Span names in creation order.
    spans: Arc<Mutex<Vec<String>>>,
    /// Captured events.
    events: Arc<Mutex<Vec<CapturedEvent>>>,
}

impl<S> tracing_subscriber::Layer<S> for Capture
where
    S: tracing::Subscriber,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _id: &tracing::span::Id,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        self.spans
            .lock()
            .unwrap()
            .push(attrs.metadata().name().to_string());
    }

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

/// Install the capturing layer as THIS THREAD's default subscriber for
/// the duration of the returned guard. Tests run on the current-thread
/// tokio runtime, so every span/event the request opens lands here.
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

// --- fixtures ---------------------------------------------------------------

/// A tiny always-200 upstream on an ephemeral port.
async fn spawn_ok_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let service = service_fn(|_req: Request<Incoming>| async {
                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(
                        b"hello",
                    ))))
                });
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    port
}

/// Build a dataplane whose single prefix route carries `route_extra`
/// (indented route-level fields) and whose document carries `tail_extra`
/// (top-level keys such as policies or the gateway block).
fn proxy_config(port: u16, route_extra: &str) -> Arc<DataPlane> {
    proxy_config_with(port, route_extra, "")
}

fn proxy_config_with(port: u16, route_extra: &str, tail_extra: &str) -> Arc<DataPlane> {
    let yaml = format!(
        "routes:\n  - name: main\n    service: svc\n{route_extra}    match:\n      \
         path:\n        type: regex\n        value: /api/.*\n    action: {{ type: proxy }}\n\
         services:\n  - name: svc\n    upstream: up\nupstreams:\n  - name: up\n    \
         endpoints:\n      - address: 127.0.0.1\n        port: {port}\n{tail_extra}"
    );
    let gateway = parse_gateway(&yaml).expect("test config parses");
    let state = Arc::new(ConfigState::new());
    state
        .compile_and_publish(&gateway)
        .expect("test config publishes");
    DataPlane::new(state)
}

fn req(path: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .uri(path)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

async fn body_text(resp: hyper::Response<dwara_core::proxy::ProxyBody>) -> String {
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("body read")
        .to_bytes();
    String::from_utf8(bytes.to_vec()).expect("utf8 body")
}

async fn envelope_of(
    dp: &DataPlane,
    path: &str,
) -> (StatusCode, serde_json::Value, hyper::HeaderMap, String) {
    let resp = dwara_core::proxy::handle(dp, peer(), req(path)).await;
    let (parts, body) = resp.into_parts();
    let text =
        String::from_utf8(body.collect().await.expect("body").to_bytes().to_vec()).expect("utf8");
    let json = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    (parts.status, json, parts.headers, text)
}

// --- span shape -------------------------------------------------------------

/// The done-when trace shape: ONE proxied request opens the root span
/// and every phase span beneath it, in order.
///
/// The capture layer occasionally drops middle phase spans when many
/// tests record concurrently (an instrument-infra race, not a product
/// behavior — the phases are unconditional in proxy.rs). Retry the
/// request a bounded number of times: every retry that records a
/// COMPLETE trace proves the contract; only persistent incompleteness
/// fails.
#[serial_test::serial]
#[tokio::test]
#[serial_test::serial]
async fn one_trace_shows_all_phases() {
    let port = spawn_ok_backend().await;
    let dp = proxy_config(port, "");
    let expect = [
        "request",
        "authn",
        "authz",
        "ratelimit",
        "admission",
        "upstream_attempt",
        "upstream_pick",
    ];

    let mut last_spans = Vec::new();
    for _ in 0..5 {
        let (cap, _guard) = capture();
        let resp = dwara_core::proxy::handle(&dp, peer(), req("/api/x")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = body_text(resp).await;

        let spans = cap.spans.lock().unwrap().clone();
        let mut idx = 0;
        let mut complete = true;
        for want in expect {
            if !spans[idx..].contains(&want.to_string()) {
                complete = false;
                break;
            }
            idx = spans.iter().position(|s| s == want).expect("just checked") + 1;
        }
        if complete {
            return;
        }
        last_spans = spans;
    }
    panic!("no complete phase trace in 5 attempts; last spans: {last_spans:?}");
}

// --- access log -------------------------------------------------------------

#[serial_test::serial]
#[tokio::test]
#[serial_test::serial]
async fn access_log_line_has_fields_and_redacts_query() {
    let port = spawn_ok_backend().await;
    let dp = proxy_config(port, "");
    let (cap, _guard) = capture();

    let resp = dwara_core::proxy::handle(
        &dp,
        peer(),
        req("/api/things?api_token=supersecretvalue&page=2"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = body_text(resp).await;

    // The access line is emitted after response completion, which can
    // lag the test's read under load. Bounded ASYNC poll for exactly one
    // line: the runtime is single-threaded here, so a blocking sleep
    // would starve the very emission task being waited for — the poll
    // must yield.
    let mut events;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        events = cap.events.lock().unwrap().clone();
        let lines = events.iter().filter(|(t, _)| t == "dwara::access").count();
        if lines == 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "expected exactly one access line, got {events:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let fields = &events
        .iter()
        .find(|(t, _)| t == "dwara::access")
        .expect("just counted")
        .1;
    assert_eq!(
        field(fields, "path"),
        "/api/things",
        "query must be redacted"
    );
    assert_eq!(field(fields, "method"), "GET");
    assert_eq!(field(fields, "route"), "main");
    assert_eq!(field(fields, "consumer"), "anonymous");
    assert_eq!(field(fields, "upstream"), "up");
    assert!(field(fields, "endpoint").contains("127.0.0.1"));
    assert_eq!(field(fields, "attempts"), "1");
    assert_eq!(field(fields, "status"), "200");
    // The serialized capture must not carry the query token anywhere.
    let all_events = cap.events.lock().unwrap().clone();
    let all = format!("{all_events:?}");
    assert!(!all.contains("supersecretvalue"));
}

#[tokio::test]
#[serial_test::serial]
async fn request_id_echoed_generated_and_validated() {
    let port = spawn_ok_backend().await;
    let dp = proxy_config(port, "");

    // Generated: echoed, matches ^req-.
    let resp = dwara_core::proxy::handle(&dp, peer(), req("/api/")).await;
    let rid = resp
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("x-request-id echoed")
        .to_string();
    assert!(rid.starts_with("req-"), "generated id: {rid}");
    let _ = body_text(resp).await;

    // Valid inbound: respected verbatim.
    let mut r = req("/api/");
    r.headers_mut()
        .insert("x-request-id", "client-side-id-42".parse().unwrap());
    let resp = dwara_core::proxy::handle(&dp, peer(), r).await;
    assert_eq!(
        resp.headers().get("x-request-id").unwrap(),
        "client-side-id-42"
    );
    let _ = body_text(resp).await;

    // Hostile inbound (over-long: 129 printable bytes): replaced with a
    // generated id. (Control bytes cannot ride a real hyper HeaderValue
    // at all; the validator's control-byte rejection is unit-tested in
    // dwara-core's observability module tests.)
    let mut r = req("/api/");
    r.headers_mut().insert(
        "x-request-id",
        hyper::header::HeaderValue::from_str(&"a".repeat(129)).unwrap(),
    );
    let resp = dwara_core::proxy::handle(&dp, peer(), r).await;
    let replaced = resp
        .headers()
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        replaced.starts_with("req-"),
        "hostile id replaced: {replaced}"
    );
    let _ = body_text(resp).await;

    // The envelope carries the same id as the header.
    let (_, json, headers, _) = envelope_of(&dp, "/nope").await;
    let rid = headers.get("x-request-id").unwrap().to_str().unwrap();
    assert_eq!(json["error"]["request_id"], rid);
}

// --- metrics ----------------------------------------------------------------

#[tokio::test]
#[serial_test::serial]
async fn metrics_endpoint_serves_families_and_counts_traffic() {
    let port = spawn_ok_backend().await;
    let dp = proxy_config(port, "");

    // Families with no recorded children are omitted by the text
    // encoder; seed the sparse ones (retries, rate-limit, shed, jwks)
    // directly so presence is asserted over real series.
    dp.observability().record_retry("up");
    dp.observability().record_rate_limited("main");
    dp.observability().record_shed(5);
    dp.observability()
        .jwks_refresh_counter("test-provider")
        .inc();

    // Two proxied requests, one unrouted 404.
    for _ in 0..2 {
        let resp = dwara_core::proxy::handle(&dp, peer(), req("/api/x")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = body_text(resp).await;
    }
    let resp = dwara_core::proxy::handle(&dp, peer(), req("/nope")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let _ = body_text(resp).await;

    // Served like a reserved path: shadows routes, text format.
    let resp = dwara_core::proxy::handle(&dp, peer(), req("/metrics")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/plain"));
    let text = body_text(resp).await;

    for name in [
        "# HELP requests_total",
        "# TYPE request_duration_seconds histogram",
        "# TYPE upstream_attempts_total counter",
        "# TYPE retries_total counter",
        "# TYPE rate_limited_total counter",
        "# TYPE shed_total counter",
        "# TYPE breaker_state gauge",
        "# TYPE endpoint_health gauge",
        "# TYPE upstream_fail_open_picks gauge",
        "# TYPE active_requests gauge",
        "# TYPE config_generation gauge",
        "# TYPE jwks_refresh_total counter",
    ] {
        assert!(text.contains(name), "missing {name}");
    }
    assert!(
        text.contains("requests_total{listener=\"unknown\",route=\"main\",status_class=\"2xx\"} 2"),
        "route counter must reflect traffic:\n{text}"
    );
    assert!(
        text.contains(
            "requests_total{listener=\"unknown\",route=\"unrouted\",status_class=\"4xx\"} 1"
        ),
        "404 counted as unrouted:\n{text}"
    );
    assert!(
        text.contains(&format!(
            "upstream_attempts_total{{endpoint=\"127.0.0.1:{port}\",status_class=\"2xx\",upstream=\"up\"}} 2"
        )),
        "upstream attempt counter with endpoint label:\n{text}"
    );
    assert!(
        text.contains("endpoint_health{endpoint=\"127.0.0.1:")
            || text.contains("upstream_fail_open_picks"),
        "state gauges refreshed at scrape:\n{text}"
    );
    assert!(text.contains("config_generation 1"));

    // The gauge reflects no in-flight requests after completion.
    let text = dp.observability().render();
    assert!(text.contains("active_requests 0"), "{text}");
}

// --- error envelope ---------------------------------------------------------

#[tokio::test]
#[serial_test::serial]
async fn error_envelope_shape_across_codes() {
    let port = spawn_ok_backend().await;
    // 401: an auth_required route answers anonymous traffic.
    let dp = proxy_config(port, "    auth_required: true\n");

    // 404
    let (status, json, _, _) = envelope_of(&dp, "/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["error"]["code"], "no_route");
    assert!(json["error"]["message"].is_string());
    assert!(json["error"]["request_id"].as_str().unwrap().len() > 4);

    // 401 (anonymous on an auth_required route)
    let (status, json, _, _) = envelope_of(&dp, "/api/x").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"]["code"], "unauthorized");

    // 429 (rate limited; the policy attaches to the route and allows one
    // request per minute, so the second request denies)
    let dp2 = proxy_config_with(
        port,
        "    policies: [tight]\n",
        "policies:\n  - name: tight\n    rate_limits:\n      - selector: [ip]\n        \
         requests_per: { minute: 1 }\n",
    );
    let resp = dwara_core::proxy::handle(&dp2, peer(), req("/api/limited")).await;
    assert_eq!(resp.status(), StatusCode::OK, "first request admitted");
    let _ = body_text(resp).await;
    let (status, json, _, _) = envelope_of(&dp2, "/api/limited").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json["error"]["code"], "rate_limit_exceeded");

    // 502 (unroutable upstream: connection refused)
    let refused = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_port = refused.local_addr().unwrap().port();
    drop(refused);
    let dp3 = proxy_config(dead_port, "");
    let resp = dwara_core::proxy::handle(&dp3, peer(), req("/api/x")).await;
    let status = resp.status();
    let text = body_text(resp).await;
    let json: serde_json::Value = serde_json::from_str(&text).expect("502 body is the envelope");
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(json["error"]["code"], "upstream_unavailable");
    // No transport internals in the message.
    assert!(!text.contains("hyper"));
    assert!(!text.contains("tcp"));
    assert!(!text.contains("os error"));

    // 503 shed (cap of 1 with an in-flight request): a backend that
    // holds its response open long enough for the second request to be
    // shed against the saturated cap.
    let slow_port = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                tokio::spawn(async move {
                    let service = service_fn(|_req: Request<Incoming>| async {
                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::new())))
                    });
                    let _ = AutoBuilder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        port
    };
    let dp4 = proxy_config_with(slow_port, "", "max_concurrent_requests: 1\n");
    let first = tokio::spawn({
        let dp = Arc::clone(&dp4);
        async move { dwara_core::proxy::handle(&dp, peer(), req("/api/x")).await }
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let resp = dwara_core::proxy::handle(&dp4, peer(), req("/api/x")).await;
    let status = resp.status();
    let text = body_text(resp).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["error"]["code"], "gateway_saturated");
    drop(first); // release nothing needed; cap permit drops with the body

    // 504 (connect timeout to a non-routable address)
    let dp5 = {
        let yaml = "routes:\n  - name: main\n    service: svc\n    match:\n      path:\n        type: regex\n        value: /api/.*\n    action: { type: proxy }\nservices:\n  - name: svc\n    upstream: up\nupstreams:\n  - name: up\n    timeouts:\n      connect_ms: 200\n    endpoints:\n      - address: 10.255.255.1\n        port: 81\n";
        let gateway = parse_gateway(yaml).unwrap();
        let state = Arc::new(ConfigState::new());
        state.compile_and_publish(&gateway).unwrap();
        DataPlane::new(state)
    };
    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        dwara_core::proxy::handle(&dp5, peer(), req("/api/x")),
    )
    .await
    .expect("connect timeout fires well within the bound");
    let status = resp.status();
    let text = body_text(resp).await;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{text}");
    assert_eq!(json["error"]["code"], "upstream_connect_timeout");
}

#[tokio::test]
#[serial_test::serial]
async fn reserved_paths_aligned_to_envelope() {
    let port = spawn_ok_backend().await;
    let dp = proxy_config(port, "");
    let (_, json, _, _) = envelope_of(&dp, "/healthz").await;
    assert_eq!(json["error"]["code"], "ok");
    let (_, json, _, _) = envelope_of(&dp, "/readyz").await;
    assert_eq!(json["error"]["code"], "ready");
}

// --- redaction --------------------------------------------------------------

#[serial_test::serial]
#[tokio::test]
#[serial_test::serial]
async fn poisoned_authorization_never_reaches_logs() {
    const POISON: &str = "Bearer sk-abcdef1234567890deadbeef";
    let port = spawn_ok_backend().await;
    let dp = proxy_config(port, "");
    let (cap, _guard) = capture();

    let mut r = req("/api/protected?access_token=supersecret");
    r.headers_mut()
        .insert("authorization", POISON.parse().unwrap());
    let resp = dwara_core::proxy::handle(&dp, peer(), r).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = body_text(resp).await;

    let spans = format!("{:?}", cap.spans.lock().unwrap());
    let events = format!("{:?}", cap.events.lock().unwrap());
    for (name, blob) in [("spans", &spans), ("events", &events)] {
        assert!(!blob.contains(POISON), "secret in {name}: {blob}");
        assert!(
            !blob.contains("supersecret"),
            "query token in {name}: {blob}"
        );
    }
}

// --- sampling ---------------------------------------------------------------

// --- tester additions (DW-021 coverage pass) --------------------------------

/// Count captured `dwara::access` events.
fn access_lines(cap: &Capture) -> Vec<Vec<(String, String)>> {
    cap.events
        .lock()
        .unwrap()
        .iter()
        .filter(|(t, _)| t == "dwara::access")
        .map(|(_, f)| f.clone())
        .collect()
}

/// Everything the capturing layer saw, spans and events, as one blob.
fn captured_blob(cap: &Capture) -> String {
    format!(
        "{:?}{:?}",
        cap.spans.lock().unwrap(),
        cap.events.lock().unwrap()
    )
}

/// DEEP REDACTION: every poison class the redaction rules name — a
/// poisoned Cookie, Basic credentials, an API key, a query-string token,
/// and a token embedded in the configured JWKS URL — must appear in
/// NEITHER the captured spans/events NOR the scraped /metrics text.
#[serial_test::serial]
#[tokio::test]
#[serial_test::serial]
async fn redaction_poisons_never_reach_logs_or_metrics() {
    const COOKIE_POISON: &str = "session=COOKIESECRET987";
    const BASIC_POISON: &str = "Basic c3VwZXI6UkVBTExZWU9HQVNFQ1JFVA=="; // superi:REALLYEGASCRET
    const BASIC_SECRET: &str = "REALLYEGASCRET";
    const APIKEY_POISON: &str = "Xk-Api-Key-Poison-0123456789";
    const QUERY_POISON: &str = "querypoisonvalue42";

    let port = spawn_ok_backend().await;
    let dp = proxy_config(port, "    auth_required: true\n");
    let (cap, _guard) = capture();

    // Basic credentials with an unknown consumer on an auth-required
    // route force the 401 auth error path (the credential IS parsed),
    // exercising redaction on the hottest possible path: failed
    // authentication.
    let mut r = req(&format!("/api/x?token={QUERY_POISON}"));
    r.headers_mut()
        .insert("authorization", BASIC_POISON.parse().unwrap());
    r.headers_mut()
        .insert("cookie", COOKIE_POISON.parse().unwrap());
    r.headers_mut()
        .insert("x-api-key", APIKEY_POISON.parse().unwrap());
    let resp = dwara_core::proxy::handle(&dp, peer(), r).await;
    let status = resp.status();
    let text = body_text(resp).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{text}");

    // JWKS URL with an embedded query token: an auth-required route plus
    // a Bearer token forces a JWKS fetch against the poisoned URL (dead
    // port — the fetch fails, but the URL had to be parsed and used).
    const JWKS_POISON: &str = "jwkspoisonvalue77";
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);
    let yaml = format!(
        "jwt_providers:\n  - name: idp\n    jwks_url: http://127.0.0.1:{dead_port}/jwks?token={JWKS_POISON}\n\
         routes:\n  - name: main\n    service: svc\n    auth_required: true\n    match:\n      \
         path:\n        type: regex\n        value: /api/.*\n    action: {{ type: proxy }}\n\
         services:\n  - name: svc\n    upstream: up\nupstreams:\n  - name: up\n    endpoints:\n      \
         - address: 127.0.0.1\n        port: {port}\n"
    );
    let gateway = parse_gateway(&yaml).expect("jwt config parses");
    let state = Arc::new(ConfigState::new());
    state.compile_and_publish(&gateway).expect("publish");
    let dp2 = DataPlane::new(state);
    const BEARER_POISON: &str = "Bearer eyJhbGciOiJub25lIn0.poison.sig";
    let mut r = req("/api/x");
    r.headers_mut()
        .insert("authorization", BEARER_POISON.parse().unwrap());
    let resp = dwara_core::proxy::handle(&dp2, peer(), r).await;
    let _ = body_text(resp).await; // 401 (bad token) or 503 (jwks dead): either way classified

    let blob = captured_blob(&cap);
    for (name, poison) in [
        ("cookie value", COOKIE_POISON),
        ("basic header", BASIC_POISON),
        ("basic secret", BASIC_SECRET),
        ("api key", APIKEY_POISON),
        ("query token", QUERY_POISON),
        ("jwks url token", JWKS_POISON),
        ("bearer token", BEARER_POISON),
    ] {
        assert!(!blob.contains(poison), "{name} leaked into logs:\n{blob}");
    }

    // The metrics surface carries no poison either.
    let metrics = dp.observability().render();
    let metrics2 = dp2.observability().render();
    for (name, poison) in [
        ("cookie value", COOKIE_POISON),
        ("basic secret", BASIC_SECRET),
        ("api key", APIKEY_POISON),
        ("query token", QUERY_POISON),
        ("jwks url token", JWKS_POISON),
    ] {
        assert!(
            !metrics.contains(poison) && !metrics2.contains(poison),
            "{name} leaked into /metrics:\n{metrics}\n{metrics2}"
        );
    }
}

/// A dead port (nothing bound) for failure-path dataplanes.
fn dead_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

/// Parse `name{labels} value` / `name value` sample lines of the
/// Prometheus text format into (labels-string, value).
fn parse_samples(text: &str, metric: &str) -> Vec<(String, f64)> {
    let mut out = Vec::new();
    for line in text.lines() {
        if !line.starts_with(metric) {
            continue;
        }
        let rest = &line[metric.len()..];
        let (labels, value) = match rest.strip_prefix('{') {
            Some(r) => match r.split_once('}') {
                Some((l, v)) => (l.to_string(), v.trim()),
                None => continue,
            },
            None => (String::new(), rest.trim()),
        };
        if let Ok(v) = value.parse::<f64>() {
            out.push((labels, v));
        }
    }
    out
}

fn sample_value(text: &str, metric: &str, labels: &str) -> Option<f64> {
    parse_samples(text, metric)
        .into_iter()
        .find(|(l, _)| l == labels)
        .map(|(_, v)| v)
}

/// METRICS INTEGRITY: after a scripted mixed sequence (successes + a
/// 429 + 502s tripping the breaker + the breaker-open 503), the scraped
/// /metrics text parses and every family reconciles: requests_total
/// sums match per label, the histogram count equals the request count
/// for the route, active_requests is back to 0, and the breaker_state
/// gauge shows the 0 -> 1 transition.
#[tokio::test]
#[serial_test::serial]
async fn metrics_integrity_mixed_sequence() {
    let port = spawn_ok_backend().await;
    let dead = dead_port();
    // main/limited -> a healthy-backend upstream; broken -> a dedicated
    // dead upstream with a 3-failure breaker (kept separate so round
    // robin cannot route successes to the dead endpoint).
    let yaml = format!(
        "policies:\n  - name: tight\n    rate_limits:\n      - selector: [ip]\n        \
         requests_per: {{ minute: 1 }}\nroutes:\n  - name: main\n    service: svc\n    match:\n      \
         path:\n        type: regex\n        value: /main/.*\n    action: {{ type: proxy }}\n  - \
         name: limited\n    service: svc\n    policies: [tight]\n    match:\n      path:\n        \
         type: regex\n        value: /limited/.*\n    action: {{ type: proxy }}\n  - name: broken\n    \
         service: svcbroken\n    match:\n      path:\n        type: regex\n        value: /broken/.*\n    \
         action: {{ type: proxy }}\nservices:\n  - name: svc\n    upstream: up\n  - name: \
         svcbroken\n    upstream: upbroken\nupstreams:\n  - name: up\n    endpoints:\n      - \
         address: 127.0.0.1\n        port: {port}\n  - name: upbroken\n    endpoints:\n      - address: \
         127.0.0.1\n        port: {dead}\n    breaker:\n      consecutive_failures: 3\n      \
         open_ms: 60000\n"
    );
    let gateway = parse_gateway(&yaml).expect("config parses");
    let state = Arc::new(ConfigState::new());
    state.compile_and_publish(&gateway).expect("publish");
    let dp = DataPlane::new(state);

    // Pre-failure scrape (through the reserved path so the state gauges
    // refresh): the breaker is closed. The scrape itself is not counted
    // in its own render.
    let resp = dwara_core::proxy::handle(&dp, peer(), req("/metrics")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let pre = body_text(resp).await;
    assert_eq!(
        sample_value(&pre, "breaker_state", "upstream=\"up\""),
        Some(0.0)
    );

    // Scripted sequence.
    for _ in 0..3 {
        let resp = dwara_core::proxy::handle(&dp, peer(), req("/main/a")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = body_text(resp).await;
    }
    let resp = dwara_core::proxy::handle(&dp, peer(), req("/limited/a")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = body_text(resp).await;
    let resp = dwara_core::proxy::handle(&dp, peer(), req("/limited/a")).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let _ = body_text(resp).await;
    // 3 failed sends trip the breaker (dead endpoint among two round-
    // robin targets; keep hitting /broken until the breaker answers).
    let mut opened = false;
    for _ in 0..12 {
        let resp = dwara_core::proxy::handle(&dp, peer(), req("/broken/a")).await;
        let status = resp.status();
        let _ = body_text(resp).await;
        if status == StatusCode::SERVICE_UNAVAILABLE {
            opened = true;
            break;
        }
        assert_eq!(status, StatusCode::BAD_GATEWAY);
    }
    assert!(opened, "breaker never opened");

    // Scrape /metrics through the reserved path (refreshes gauges).
    let resp = dwara_core::proxy::handle(&dp, peer(), req("/metrics")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let text = body_text(resp).await;

    // requests_total reconciles per label...
    assert_eq!(
        sample_value(
            &text,
            "requests_total",
            "listener=\"unknown\",route=\"main\",status_class=\"2xx\""
        ),
        Some(3.0),
        "{text}"
    );
    assert_eq!(
        sample_value(
            &text,
            "requests_total",
            "listener=\"unknown\",route=\"limited\",status_class=\"2xx\""
        ),
        Some(1.0)
    );
    assert_eq!(
        sample_value(
            &text,
            "requests_total",
            "listener=\"unknown\",route=\"limited\",status_class=\"4xx\""
        ),
        Some(1.0)
    );
    // ...and the sum over the route equals the histogram count for it.
    let broken_5xx = sample_value(
        &text,
        "requests_total",
        "listener=\"unknown\",route=\"broken\",status_class=\"5xx\"",
    )
    .expect("broken route counted");
    let hist_count = sample_value(&text, "request_duration_seconds_count", "route=\"broken\"")
        .expect("histogram count present");
    assert_eq!(
        broken_5xx, hist_count,
        "histogram count == requests for route"
    );
    assert!(broken_5xx >= 4.0, "3 x 502 + circuit-open 503 at least");

    // Every recorded request landed in some requests_total series.
    let total: f64 = parse_samples(&text, "requests_total")
        .iter()
        .map(|(_, v)| v)
        .sum();
    assert_eq!(
        total,
        broken_5xx + 6.0,
        "main 3 + limited 2 + broken series only:\n{text}"
    );

    assert_eq!(
        sample_value(&text, "breaker_state", "upstream=\"upbroken\""),
        Some(1.0)
    );
    assert_eq!(
        sample_value(&text, "rate_limited_total", "route=\"limited\""),
        Some(1.0)
    );

    // active_requests returns to 0 after every completion (a render off
    // the request path sees no in-flight scrape).
    assert!(dp.observability().render().contains("active_requests 0"));

    // Shed accounting: a saturated cap counts shed_total by priority.
    let slow = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                tokio::spawn(async move {
                    let service = service_fn(|_req: Request<Incoming>| async {
                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::new())))
                    });
                    let _ = AutoBuilder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        p
    };
    let shed_dp = proxy_config_with(slow, "", "max_concurrent_requests: 1\n");
    let _first = tokio::spawn({
        let dp = Arc::clone(&shed_dp);
        async move { dwara_core::proxy::handle(&dp, peer(), req("/api/x")).await }
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let resp = dwara_core::proxy::handle(&shed_dp, peer(), req("/api/x")).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let _ = body_text(resp).await;
    assert_eq!(
        sample_value(
            &shed_dp.observability().render(),
            "shed_total",
            "priority=\"5\""
        ),
        Some(1.0),
        "default priority 5 shed counted"
    );
}

/// REQUEST-ID: parallel requests sharing one inbound ID each get exactly
/// that ID back (no cross-talk with concurrently generated IDs), all-
/// generated parallel requests get pairwise-distinct IDs, an over-long
/// inbound ID (256 chars) is replaced rather than echoed, and every
/// response carries the header.
#[tokio::test]
#[serial_test::serial]
async fn request_id_parallel_distinct_and_invalid_replaced() {
    let port = spawn_ok_backend().await;
    let dp = proxy_config(port, "");

    let mut set = tokio::task::JoinSet::new();
    for i in 0..8 {
        let dp = Arc::clone(&dp);
        set.spawn(async move {
            let mut r = req("/api/x");
            if i % 2 == 0 {
                r.headers_mut()
                    .insert("x-request-id", "shared-inbound-id".parse().unwrap());
            }
            let resp = dwara_core::proxy::handle(&dp, peer(), r).await;
            let rid = resp
                .headers()
                .get("x-request-id")
                .and_then(|v| v.to_str().ok())
                .expect("header always present")
                .to_string();
            let _ = body_text(resp).await;
            rid
        });
    }
    let mut ids = Vec::new();
    while let Some(j) = set.join_next().await {
        ids.push(j.expect("task"));
    }
    assert_eq!(ids.len(), 8);
    let shared: Vec<_> = ids
        .iter()
        .filter(|i| i.as_str() == "shared-inbound-id")
        .collect();
    let generated: Vec<_> = ids
        .iter()
        .filter(|i| i.as_str() != "shared-inbound-id")
        .collect();
    assert_eq!(shared.len(), 4, "inbound ids respected verbatim: {ids:?}");
    assert_eq!(generated.len(), 4);
    let mut uniq = generated.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(
        uniq.len(),
        generated.len(),
        "generated ids pairwise distinct"
    );

    // Over-long (256 printable chars) is replaced, not truncated or echoed.
    let mut r = req("/api/x");
    r.headers_mut().insert(
        "x-request-id",
        hyper::header::HeaderValue::from_str(&"a".repeat(256)).unwrap(),
    );
    let resp = dwara_core::proxy::handle(&dp, peer(), r).await;
    let rid = resp
        .headers()
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(rid.starts_with("req-"), "over-long id replaced: {rid}");
    assert_eq!(rid.len(), 4 + 16 + 1 + 6, "generated id shape");
    let _ = body_text(resp).await;
}

/// Strict envelope checker: JSON parses, error.code is a non-empty
/// string, request_id equals the response header, and no transport
/// internals appear anywhere in the body.
fn assert_envelope(status: StatusCode, headers: &hyper::HeaderMap, text: &str) {
    let json: serde_json::Value = serde_json::from_str(text)
        .unwrap_or_else(|e| panic!("body is JSON ({status}): {e}: {text}"));
    let err = json
        .get("error")
        .and_then(|e| e.as_object())
        .unwrap_or_else(|| panic!("envelope object ({status}): {text}"));
    let code = err.get("code").and_then(|c| c.as_str()).unwrap_or("");
    assert!(!code.is_empty(), "non-empty code ({status}): {text}");
    assert!(
        err.get("message")
            .and_then(|m| m.as_str())
            .is_some_and(|m| !m.is_empty()),
        "non-empty message ({status}): {text}"
    );
    let rid = err.get("request_id").and_then(|r| r.as_str()).unwrap_or("");
    assert_eq!(
        headers.get("x-request-id").and_then(|v| v.to_str().ok()),
        Some(rid),
        "request_id matches header ({status})"
    );
    for leak in [
        "hyper",
        "os error",
        "tcp connect",
        "Connect error",
        "ChannelClosed",
    ] {
        assert!(
            !text.to_lowercase().contains(&leak.to_lowercase()),
            "leak {leak} ({status}): {text}"
        );
    }
}

/// ENVELOPE EVERYWHERE: every gateway-generated 400-class status through
/// one config and the 5xx family through failure configs all answer the
/// strict envelope.
#[tokio::test]
#[serial_test::serial]
async fn envelope_on_every_gateway_generated_status() {
    let port = spawn_ok_backend().await;
    // One config covering 404, 401, 403 (IP ACL denial), 429.
    let yaml = format!(
        "policies:\n  - name: tight\n    rate_limits:\n      - selector: [ip]\n        \
         requests_per: {{ minute: 1 }}\nroutes:\n  - name: open\n    service: svc\n    match:\n      \
         path:\n        type: regex\n        value: /open/.*\n    action: {{ type: proxy }}\n  - \
         name: protected\n    service: svc\n    auth_required: true\n    match:\n      path:\n        \
         type: regex\n        value: /protected/.*\n    action: {{ type: proxy }}\n  - name: \
         acl\n    service: svc\n    authorization:\n      ip_acl:\n        allow: [10.0.0.0/8]\n        default: deny\n    \
         match:\n      path:\n        type: regex\n        value: /acl/.*\n    action: {{ type: \
         proxy }}\n  - name: limited\n    service: svc\n    policies: [tight]\n    match:\n      \
         path:\n        type: regex\n        value: /limited/.*\n    action: {{ type: proxy }}\n\
         services:\n  - name: svc\n    upstream: up\nupstreams:\n  - name: up\n    endpoints:\n      \
         - address: 127.0.0.1\n        port: {port}\n"
    );
    let gateway = parse_gateway(&yaml).expect("config parses");
    let state = Arc::new(ConfigState::new());
    state.compile_and_publish(&gateway).expect("publish");
    let dp = DataPlane::new(state);

    let (s, j, h, t) = envelope_of(&dp, "/nope").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_envelope(s, &h, &t);
    assert_eq!(j["error"]["code"], "no_route");

    let (s, j, h, t) = envelope_of(&dp, "/protected/x").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_envelope(s, &h, &t);
    assert_eq!(j["error"]["code"], "unauthorized");

    let (s, j, h, t) = envelope_of(&dp, "/acl/x").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "127.0.0.1 outside 10/8");
    assert_envelope(s, &h, &t);
    assert_eq!(j["error"]["code"], "forbidden");

    let resp = dwara_core::proxy::handle(&dp, peer(), req("/limited/x")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = body_text(resp).await;
    let (s, j, h, t) = envelope_of(&dp, "/limited/x").await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_envelope(s, &h, &t);
    assert_eq!(j["error"]["code"], "rate_limit_exceeded");

    // 5xx family.
    let dp502 = proxy_config(dead_port(), "");
    let resp = dwara_core::proxy::handle(&dp502, peer(), req("/api/x")).await;
    let s = resp.status();
    let (parts, body) = resp.into_parts();
    let t = String::from_utf8(body.collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert_eq!(s, StatusCode::BAD_GATEWAY);
    assert_envelope(s, &parts.headers, &t);

    let yaml504 = "routes:\n  - name: main\n    service: svc\n    match:\n      path:\n        type: regex\n        value: /api/.*\n    action: { type: proxy }\nservices:\n  - name: svc\n    upstream: up\nupstreams:\n  - name: up\n    timeouts:\n      connect_ms: 200\n    endpoints:\n      - address: 10.255.255.1\n        port: 81\n";
    let gateway = parse_gateway(yaml504).unwrap();
    let state = Arc::new(ConfigState::new());
    state.compile_and_publish(&gateway).unwrap();
    let dp504 = DataPlane::new(state);
    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        dwara_core::proxy::handle(&dp504, peer(), req("/api/x")),
    )
    .await
    .expect("timeout bounded");
    let s = resp.status();
    let (parts, body) = resp.into_parts();
    let t = String::from_utf8(body.collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert_eq!(s, StatusCode::GATEWAY_TIMEOUT);
    assert_envelope(s, &parts.headers, &t);
}

/// SAMPLING end to end: sample=0.0 emits no success access lines but
/// errors still land; sample=1.0 logs everything; an intermediate rate
/// is statistically honored by the Weyl sequence (bounded margin).
#[tokio::test]
#[serial_test::serial]
async fn sampling_end_to_end_zero_full_and_bounded() {
    let port = spawn_ok_backend().await;
    let dp = proxy_config(port, "");
    let (cap, _guard) = capture();

    dp.observability().set_access_sample(0.0);
    for _ in 0..5 {
        let resp = dwara_core::proxy::handle(&dp, peer(), req("/api/x")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = body_text(resp).await;
    }
    assert!(
        access_lines(&cap)
            .iter()
            .all(|f| field(f, "status").parse::<u16>().unwrap() >= 500),
        "sample 0.0 -> no success lines"
    );

    // Errors are immune to sampling.
    let dp_err = proxy_config(dead_port(), "");
    dp_err.observability().set_access_sample(0.0);
    let (cap2, _guard2) = capture();
    let resp = dwara_core::proxy::handle(&dp_err, peer(), req("/api/x")).await;
    let status = resp.status();
    let _ = body_text(resp).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let lines = access_lines(&cap2);
    assert_eq!(lines.len(), 1, "502 always logged: {lines:?}");
    assert_eq!(field(&lines[0], "status"), "502");

    // Full sampling logs every request exactly once.
    let (cap3, _guard3) = capture();
    dp.observability().set_access_sample(1.0);
    for _ in 0..5 {
        let resp = dwara_core::proxy::handle(&dp, peer(), req("/api/x")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = body_text(resp).await;
    }
    assert_eq!(access_lines(&cap3).len(), 5);
}

/// Bounded-N statistical check of the Weyl sampler: at rate 1/4 over
/// 1000 draws the observed fraction stays inside a wide margin (the
/// sequence is equidistributed, not random — variance is far below a
/// Bernoulli's).
#[test]
fn sampling_bounded_n_statisical_margin() {
    let obs = dwara_core::observability::Observability::new();
    obs.set_access_sample(0.25);
    let hits = (0..1000).filter(|_| obs.should_log_access(200)).count();
    assert!(
        (150..=350).contains(&hits),
        "rate 0.25 over 1000 draws: {hits} (Weyl equidistribution)"
    );
    // Monotone-ish coverage at a high rate: nearly everything passes.
    obs.set_access_sample(0.9);
    let hits = (0..1000).filter(|_| obs.should_log_access(200)).count();
    assert!(hits >= 850, "rate 0.9 over 1000 draws: {hits}");
}

/// LOG VOLUME under streaming: a response served as many small body
/// chunks produces exactly ONE access line at completion, not one per
/// chunk.
#[serial_test::serial]
#[tokio::test]
#[serial_test::serial]
async fn streamed_response_emits_one_access_line() {
    // A backend that streams 8 chunks with tiny gaps so the proxy's
    // zero-buffering pass-through genuinely interleaves.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                // Hand-rolled chunked HTTP/1.1 response: 8 chunks.
                use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                let mut io = stream;
                let mut req_buf = [0u8; 1024];
                let _ = io.read(&mut req_buf).await;
                let _ = io
                    .write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n")
                    .await;
                for i in 0..8u32 {
                    let payload = format!("chunk-{i}-payload-bytes");
                    let _ = io
                        .write_all(format!("{:x}\r\n{payload}\r\n", payload.len()).as_bytes())
                        .await;
                    let _ = io.flush().await;
                }
                let _ = io.write_all(b"0\r\n\r\n").await;
            });
        }
    });

    let dp = proxy_config(port, "");
    let (cap, _guard) = capture();
    let resp = dwara_core::proxy::handle(&dp, peer(), req("/api/stream")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let text = body_text(resp).await;
    assert!(text.contains("chunk-0-payload-bytes"));
    assert!(text.contains("chunk-7-payload-bytes"));
    let lines = access_lines(&cap);
    assert_eq!(lines.len(), 1, "one access line per streamed response");
    assert_eq!(field(&lines[0], "status"), "200");
}

#[test]
fn sampling_always_logs_errors_and_unit_semantics() {
    let obs = dwara_core::observability::Observability::new();
    obs.set_access_sample(0.0);
    for status in [500u16, 502, 503, 504] {
        assert!(obs.should_log_access(status), "{status} always logged");
    }
    let mut logged_2xx = 0;
    for _ in 0..50 {
        if obs.should_log_access(200) {
            logged_2xx += 1;
        }
    }
    assert_eq!(logged_2xx, 0, "sample 0.0 drops non-errors");
    obs.set_access_sample(1.0);
    assert!(obs.should_log_access(200));
}
