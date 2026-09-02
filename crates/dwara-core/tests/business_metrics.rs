//! Business metrics dimensions tests (DW-093): custom KPI dimensions
//! (consumer tier, feature flag, business key) from headers, JWT
//! claims, and request body JSON pointers, plus correlation-ID
//! journey/funnel analytics — through the real gateway with the
//! embedded analytics store.
//!
//! The dimension-capture and correlation-ID tests drive the real
//! dataplane (the same path dwara-bin serves) and assert against the
//! RAW table after a clean writer shutdown. The validation tests drive
//! the snapshot validator directly (no dataplane needed). The query
//! tests drive the query functions directly against a store with
//! hand-seeded rollup rows.

mod support;

use std::sync::Arc;

use bytes::Bytes;
use dwara_core::analytics::{query, EmbeddedAnalytics, DEFAULT_RETENTION_MS};
use dwara_core::config::parse_gateway;
use dwara_core::proxy::DataPlane;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use support::{body_of, gateway_yaml, h1_client, spawn_backend, spawn_gateway, uri};
use tokio::net::TcpListener;
use tokio::sync::watch;

// --- helpers ---------------------------------------------------------------

fn ok() -> hyper::Response<Full<Bytes>> {
    hyper::Response::builder()
        .status(200)
        .body(Full::new(Bytes::from("ok")))
        .unwrap()
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Open an analytics store in a temp dir, attach it to the dataplane,
/// and spawn the background writers. Returns the store handle (for
/// direct SQLite queries) and a shutdown guard.
struct AnalyticsHandle {
    store: Arc<EmbeddedAnalytics>,
    _dir: tempfile::TempDir,
    _shutdown_tx: watch::Sender<()>,
}

fn attach_analytics(dp: &Arc<DataPlane>) -> AnalyticsHandle {
    let dir = tempfile::tempdir().unwrap();
    let store = EmbeddedAnalytics::open(
        &dir.path().join("a.db").display().to_string(),
        DEFAULT_RETENTION_MS,
        100,
        0,
    )
    .unwrap();
    dp.set_analytics(Arc::clone(&store));
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let _workers = store.spawn_workers(shutdown_rx);
    AnalyticsHandle {
        store,
        _dir: dir,
        _shutdown_tx: shutdown_tx,
    }
}

/// Wait for raw rows to flush (bounded poll on the raw table count).
/// MUST be async and use `tokio::time::sleep` — the writer task runs on
/// the same single-threaded tokio runtime, so `std::thread::sleep`
/// would block it and the rows would never flush.
async fn wait_for_raw(store: &Arc<EmbeddedAnalytics>, expected: i64) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let count: i64 = store
            .query(|c| c.query_row("SELECT COUNT(*) FROM raw", [], |r| r.get(0)))
            .unwrap_or(0);
        if count >= expected {
            return;
        }
        if std::time::Instant::now() > deadline {
            panic!("timed out waiting for {expected} raw rows (got {count})");
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

// --- header dimension ------------------------------------------------------

#[tokio::test]
async fn header_dimension_captured() {
    let (backend_port, _hits) = spawn_backend(
        |_n, _method, _path, _body| ok(),
        std::time::Duration::from_millis(0),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("a.db").to_str().unwrap().to_string();
    let gateway_extra = format!(
        "analytics:\n\
         \x20 path: {db_path}\n\
         \x20 dimensions:\n\
         \x20   - name: plan\n\
         \x20     header: x-plan\n"
    );
    let yaml = gateway_yaml(&gateway_extra, backend_port, None, "");
    let dp = support::dataplane_from(&yaml);
    let ah = attach_analytics(&dp);
    let port = spawn_gateway(dp).await;
    let client = h1_client();

    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(uri(port, "/api/one"))
        .header("x-plan", "pro")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert!(resp.status().is_success());
    let _ = body_of(resp).await;

    wait_for_raw(&ah.store, 1).await;
    let dims: String = ah
        .store
        .query(|c| {
            c.query_row("SELECT dims FROM raw ORDER BY id DESC LIMIT 1", [], |r| {
                r.get(0)
            })
        })
        .unwrap();
    assert_eq!(dims, r#"{"plan":"pro"}"#, "header dimension captured");
}

// --- correlation ID --------------------------------------------------------

#[tokio::test]
async fn correlation_id_stored() {
    let (backend_port, _hits) = spawn_backend(
        |_n, _method, _path, _body| ok(),
        std::time::Duration::from_millis(0),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("a.db").to_str().unwrap().to_string();
    let gateway_extra = format!("analytics:\n  path: {db_path}\n");
    let yaml = gateway_yaml(&gateway_extra, backend_port, None, "");
    let dp = support::dataplane_from(&yaml);
    let ah = attach_analytics(&dp);
    let port = spawn_gateway(dp).await;
    let client = h1_client();

    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(uri(port, "/api/one"))
        .header("x-correlation-id", "journey-abc-123")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert!(resp.status().is_success());
    let _ = body_of(resp).await;

    wait_for_raw(&ah.store, 1).await;
    let (cid, rid): (String, String) = ah
        .store
        .query(|c| {
            c.query_row(
                "SELECT correlation_id, request_id FROM raw ORDER BY id DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
        })
        .unwrap();
    assert_eq!(cid, "journey-abc-123", "correlation_id stored from header");
    assert!(!rid.is_empty(), "request_id also stored");
}

#[tokio::test]
async fn correlation_id_falls_back_to_request_id() {
    let (backend_port, _hits) = spawn_backend(
        |_n, _method, _path, _body| ok(),
        std::time::Duration::from_millis(0),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("a.db").to_str().unwrap().to_string();
    let gateway_extra = format!("analytics:\n  path: {db_path}\n");
    let yaml = gateway_yaml(&gateway_extra, backend_port, None, "");
    let dp = support::dataplane_from(&yaml);
    let ah = attach_analytics(&dp);
    let port = spawn_gateway(dp).await;
    let client = h1_client();

    // No X-Correlation-Id header: correlation_id should equal request_id.
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(uri(port, "/api/one"))
        .header("x-request-id", "req-fallback-001")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert!(resp.status().is_success());
    let _ = body_of(resp).await;

    wait_for_raw(&ah.store, 1).await;
    let (cid, rid): (String, String) = ah
        .store
        .query(|c| {
            c.query_row(
                "SELECT correlation_id, request_id FROM raw ORDER BY id DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
        })
        .unwrap();
    assert_eq!(
        cid, "req-fallback-001",
        "correlation_id falls back to request_id"
    );
    assert_eq!(rid, "req-fallback-001");
}

#[tokio::test]
async fn correlation_id_echoed_on_response() {
    let (backend_port, _hits) = spawn_backend(
        |_n, _method, _path, _body| ok(),
        std::time::Duration::from_millis(0),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("a.db").to_str().unwrap().to_string();
    let gateway_extra = format!("analytics:\n  path: {db_path}\n");
    let yaml = gateway_yaml(&gateway_extra, backend_port, None, "");
    let dp = support::dataplane_from(&yaml);
    let _ah = attach_analytics(&dp);
    let port = spawn_gateway(dp).await;
    let client = h1_client();

    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(uri(port, "/api/one"))
        .header("x-correlation-id", "echo-test-456")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert!(resp.status().is_success());
    assert_eq!(
        resp.headers()
            .get("x-correlation-id")
            .and_then(|v| v.to_str().ok()),
        Some("echo-test-456"),
        "X-Correlation-Id echoed on response"
    );
    let _ = body_of(resp).await;
}

// --- journey query ---------------------------------------------------------

#[tokio::test]
async fn journey_query_returns_correlated_requests() {
    let (backend_port, _hits) = spawn_backend(
        |_n, _method, _path, _body| ok(),
        std::time::Duration::from_millis(0),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("a.db").to_str().unwrap().to_string();
    let gateway_extra = format!("analytics:\n  path: {db_path}\n");
    let yaml = gateway_yaml(&gateway_extra, backend_port, None, "");
    let dp = support::dataplane_from(&yaml);
    let ah = attach_analytics(&dp);
    let port = spawn_gateway(dp).await;
    let client = h1_client();

    // Two requests with the SAME correlation id, one without.
    for path in ["/api/a", "/api/b"] {
        let req = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(uri(port, path))
            .header("x-correlation-id", "journey-xyz")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        assert!(resp.status().is_success());
        let _ = body_of(resp).await;
    }
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(uri(port, "/api/c"))
        .header("x-correlation-id", "other-journey")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert!(resp.status().is_success());
    let _ = body_of(resp).await;

    wait_for_raw(&ah.store, 3).await;
    let rows = ah
        .store
        .query(|c| query::journey_query(c, "journey-xyz", None, None))
        .unwrap();
    assert_eq!(rows.len(), 2, "journey query returns 2 correlated requests");
    assert_eq!(rows[0].correlation_id, "journey-xyz");
    assert_eq!(rows[1].correlation_id, "journey-xyz");
    // Ordered by time ascending.
    assert!(rows[0].ts_ms <= rows[1].ts_ms);
}

// --- dimension query (rollup) ----------------------------------------------

#[tokio::test]
async fn dimension_query_returns_rollup() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("a.db").to_str().unwrap().to_string();
    let store = EmbeddedAnalytics::open(&db_path, DEFAULT_RETENTION_MS, 50, 0).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let _workers = store.spawn_workers(shutdown_rx);

    // Seed a rollup_dim row directly (the rollup cascade is pinned in
    // unit tests; here we only test the query layer).
    let now = now_ms();
    let minute = (now / 60_000) * 60_000;
    store
        .query(|c| {
            c.execute(
                "INSERT OR REPLACE INTO rollup_dim \
                 (gran, window_start, dim, value, requests, errors, \
                 duration_sum_ms, b0, b1, b2, b3, b4, b5, b6, b7, b8, \
                 b9, b10, b11, b12) \
                 VALUES (0, ?1, 'plan', 'pro', 5, 1, 100.0, \
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)",
                [minute],
            )
        })
        .unwrap();

    let q = query::DimensionQuery {
        from_ms: now - 120_000,
        to_ms: now + 60_000,
        gran: 0,
        dim: "plan".to_string(),
        value: None,
        limit: None,
    };
    q.validate().unwrap();
    let rows = store.query(|c| query::dimension_query(c, &q)).unwrap();
    assert_eq!(rows.len(), 1, "dimension query returns the seeded row");
    assert_eq!(rows[0].dim, "plan");
    assert_eq!(rows[0].value, "pro");
    assert_eq!(rows[0].requests, 5);
    assert_eq!(rows[0].error_count, 1);
    assert!((rows[0].avg_duration_ms - 20.0).abs() < 0.01);

    drop(shutdown_tx);
}

// --- body-path dimension (with retries to force buffering) -----------------

#[tokio::test]
async fn body_path_dimension_captured() {
    let (backend_port, _hits) = spawn_backend(
        |_n, _method, _path, _body| ok(),
        std::time::Duration::from_millis(0),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("a.db").to_str().unwrap().to_string();
    // Enable retries so the body is buffered (the body_path dimension
    // only works when the body is buffered).
    let gateway_extra = format!(
        "analytics:\n\
         \x20 path: {db_path}\n\
         \x20 dimensions:\n\
         \x20   - name: feature\n\
         \x20     source: body_path\n\
         \x20     body_path: /feature\n"
    );
    let upstream_extra =
        "  retries:\n    attempts: 1\n    retry_post: true\n    buffer_max_bytes: 1048576\n";
    let yaml = gateway_yaml(&gateway_extra, backend_port, None, upstream_extra);
    let dp = support::dataplane_from(&yaml);
    let ah = attach_analytics(&dp);
    let port = spawn_gateway(dp).await;
    let client = h1_client();

    let body = serde_json::json!({"feature": "beta-flag", "data": 42}).to_string();
    let req = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(uri(port, "/api/one"))
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert!(resp.status().is_success());
    let _ = body_of(resp).await;

    wait_for_raw(&ah.store, 1).await;
    let dims: String = ah
        .store
        .query(|c| {
            c.query_row("SELECT dims FROM raw ORDER BY id DESC LIMIT 1", [], |r| {
                r.get(0)
            })
        })
        .unwrap();
    assert_eq!(
        dims, r#"{"feature":"beta-flag"}"#,
        "body_path dimension captured from buffered JSON body"
    );
}

// --- JWT claim dimension ---------------------------------------------------

/// Spawn a JWKS server (the authn.rs pattern, trimmed).
async fn spawn_jwks(keys: Arc<std::sync::Mutex<Vec<serde_json::Value>>>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let keys = Arc::clone(&keys);
            let io = hyper_util::rt::TokioIo::new(stream);
            tokio::spawn(async move {
                let service = service_fn(move |_req: Request<Incoming>| {
                    let keys = Arc::clone(&keys);
                    async move {
                        let keys = keys.lock().unwrap().clone();
                        let body = serde_json::json!({"keys": keys}).to_string();
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(200)
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(io, service)
                .await;
            });
        }
    });
    addr
}

/// Extract the P-256 public point (x, y) from an rcgen SPKI DER.
fn p256_xy(spki_der: &[u8]) -> (String, String) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use base64::Engine as _;
    let body = &spki_der[spki_der.len() - 65..];
    assert_eq!(body[0], 0x04, "uncompressed EC point");
    (B64URL.encode(&body[1..33]), B64URL.encode(&body[33..65]))
}

#[tokio::test]
async fn claim_dimension_captured() {
    let key = rcgen::KeyPair::generate().unwrap();
    let (x, y) = p256_xy(&key.public_key_der());
    let kid = "key-1".to_string();
    let jwk = serde_json::json!({
        "kty": "EC", "crv": "P-256", "x": x, "y": y,
        "kid": kid, "alg": "ES256", "use": "sig",
    });
    let jwks = Arc::new(std::sync::Mutex::new(vec![jwk]));
    let jwks_addr = spawn_jwks(Arc::clone(&jwks)).await;
    let (backend_port, _hits) = spawn_backend(
        |_n, _method, _path, _body| ok(),
        std::time::Duration::from_millis(0),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("a.db").to_str().unwrap().to_string();
    let yaml = format!(
        "analytics:\n\
         \x20 path: {db_path}\n\
         \x20 dimensions:\n\
         \x20   - name: tier\n\
         \x20     source: claim\n\
         \x20     claim: tier\n\
         routes:\n\
         - name: all\n\
         \x20 service: svc\n\
         \x20 auth_required: true\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {backend_port}\n\
         jwt_providers:\n\
         - name: idp\n\
         \x20 jwks_url: http://127.0.0.1:{jwks_port}/jwks\n\
         consumers:\n\
         - name: acme\n\
         \x20 credentials:\n\
         \x20   - type: jwt\n\
         \x20     issuer: https://idp.example\n\
         \x20     audiences: [dwara-api]\n",
        jwks_port = jwks_addr.port()
    );
    let dp = support::dataplane_from(&yaml);
    let ah = attach_analytics(&dp);
    let port = spawn_gateway(dp).await;
    let client = h1_client();

    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let claims = serde_json::json!({
        "iss": "https://idp.example",
        "aud": "dwara-api",
        "sub": "user-1",
        "exp": exp,
        "tier": "enterprise",
    });
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(kid.clone());
    let enc = EncodingKey::from_ec_der(&key.serialize_der());
    let token = jsonwebtoken::encode(&header, &claims, &enc).unwrap();

    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(uri(port, "/api/one"))
        .header("authorization", format!("Bearer {token}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert!(resp.status().is_success(), "JWT auth succeeded");
    let _ = body_of(resp).await;

    wait_for_raw(&ah.store, 1).await;
    let dims: String = ah
        .store
        .query(|c| {
            c.query_row("SELECT dims FROM raw ORDER BY id DESC LIMIT 1", [], |r| {
                r.get(0)
            })
        })
        .unwrap();
    assert_eq!(
        dims, r#"{"tier":"enterprise"}"#,
        "claim dimension captured from verified JWT"
    );
}

// --- validation tests ------------------------------------------------------

fn parse_ok(yaml: &str) -> dwara_core::config::Gateway {
    parse_gateway(yaml).expect("test config parses")
}

fn validation_base() -> &'static str {
    "listeners: []\nroutes:\n  - name: r\n    service: s\n    match:\n      path: { type: regex, value: /.* }\n    action: { type: respond, status: 200 }\nservices:\n  - name: s\n    upstream: u\nupstreams:\n  - name: u\n    endpoints:\n      - address: 127.0.0.1\n        port: 1\n"
}

#[test]
fn validation_rejects_missing_header_for_header_source() {
    let gw = parse_ok(&format!(
        "{base}analytics:\n  path: /tmp/a.db\n  dimensions:\n    - name: plan\n      source: header\n",
        base = validation_base()
    ));
    let issues = dwara_core::snapshot::validate(&gw);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "analytics.dimensions[0].header"
                && i.message.contains("requires the 'header' field")),
        "missing header for header source: {issues:?}"
    );
}

#[test]
fn validation_rejects_missing_claim_for_claim_source() {
    let gw = parse_ok(&format!(
        "{base}analytics:\n  path: /tmp/a.db\n  dimensions:\n    - name: tier\n      source: claim\n",
        base = validation_base()
    ));
    let issues = dwara_core::snapshot::validate(&gw);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "analytics.dimensions[0].claim"
                && i.message.contains("requires the 'claim' field")),
        "missing claim for claim source: {issues:?}"
    );
}

#[test]
fn validation_rejects_missing_body_path_for_body_path_source() {
    let gw = parse_ok(&format!(
        "{base}analytics:\n  path: /tmp/a.db\n  dimensions:\n    - name: feature\n      source: body_path\n",
        base = validation_base()
    ));
    let issues = dwara_core::snapshot::validate(&gw);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "analytics.dimensions[0].body_path"
                && i.message.contains("requires the 'body_path' field")),
        "missing body_path for body_path source: {issues:?}"
    );
}

#[test]
fn validation_rejects_invalid_json_pointer() {
    let gw = parse_ok(&format!(
        "{base}analytics:\n  path: /tmp/a.db\n  dimensions:\n    - name: feature\n      source: body_path\n      body_path: not-a-pointer\n",
        base = validation_base()
    ));
    let issues = dwara_core::snapshot::validate(&gw);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "analytics.dimensions[0].body_path"
                && i.message.contains("valid RFC 6901 JSON pointer")),
        "invalid JSON pointer: {issues:?}"
    );
}

#[test]
fn validation_accepts_backward_compatible_header_only_dimension() {
    // The original DW-043 shape: header without source. Must still
    // validate clean (source defaults to header).
    let gw = parse_ok(&format!(
        "{base}analytics:\n  path: /tmp/a.db\n  dimensions:\n    - name: plan\n      header: x-plan\n",
        base = validation_base()
    ));
    let issues = dwara_core::snapshot::validate(&gw);
    assert!(
        !issues
            .iter()
            .any(|i| i.field.contains("analytics.dimensions")),
        "backward-compatible header-only dimension: {issues:?}"
    );
}

#[test]
fn validation_accepts_all_three_sources() {
    let gw = parse_ok(&format!(
        "{base}analytics:\n  path: /tmp/a.db\n  dimensions:\n    - name: plan\n      header: x-plan\n    - name: tier\n      source: claim\n      claim: tier\n    - name: feature\n      source: body_path\n      body_path: /feature\n",
        base = validation_base()
    ));
    let issues = dwara_core::snapshot::validate(&gw);
    assert!(
        !issues
            .iter()
            .any(|i| i.field.contains("analytics.dimensions")),
        "all three sources valid: {issues:?}"
    );
}
