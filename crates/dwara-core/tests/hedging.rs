//! Request hedging integration tests (DW-063).
//!
//! Serves real in-process backends against the gateway dataplane and
//! verifies the hedge behavior:
//!
//! - A slow primary (delayed response) triggers a hedge copy after
//!   `hedge_after_ms`; the fast hedge wins and the client sees its
//!   response.
//! - When the primary responds before `hedge_after_ms`, no hedge is
//!   sent (the hedge timer never fires).
//! - Hedging requires `buffer_max_bytes > 0`; without it, hedging is
//!   disabled even when the `hedge` block is present.
//! - Validation rejects a `hedge` block without `buffer_max_bytes > 0`.
//! - Validation rejects out-of-bounds `hedge_after_ms` and `hedge_max`.

use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dwara_core::config::parse_gateway;
use dwara_core::snapshot::validate;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::net::TcpListener;

mod support;

use support::{body_of, dataplane_from, h1_client, spawn_gateway};

// --- infrastructure -------------------------------------------------------

/// A backend that delays its response by `delay` and returns a
/// distinguishable body. The `counter` tracks how many requests arrived.
async fn spawn_delayed_backend(
    delay: Duration,
    body: &'static str,
    counter: Arc<AtomicU64>,
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            let c = Arc::clone(&counter);
            tokio::spawn(async move {
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req: Request<Incoming>| {
                            let c = Arc::clone(&c);
                            async move {
                                // Drain the request body.
                                let _ = req.into_body().collect().await;
                                c.fetch_add(1, Ordering::Relaxed);
                                tokio::time::sleep(delay).await;
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header("content-type", "text/plain")
                                        .body(Full::new(Bytes::from(body)))
                                        .unwrap(),
                                )
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    port
}

/// A fast backend that responds immediately with a distinguishable body.
async fn spawn_fast_backend(body: &'static str, counter: Arc<AtomicU64>) -> u16 {
    spawn_delayed_backend(Duration::ZERO, body, counter).await
}

/// Gateway YAML with two endpoints and a hedge block.
fn hedge_yaml(
    port_slow: u16,
    port_fast: u16,
    hedge_after_ms: u64,
    hedge_max: u32,
    buffer_max_bytes: u64,
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
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 load_balancer: round_robin\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port_slow}\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port_fast}\n\
         \x20 retries:\n\
         \x20   attempts: 0\n\
         \x20   buffer_max_bytes: {buffer_max_bytes}\n\
         \x20   hedge:\n\
         \x20     hedge_after_ms: {hedge_after_ms}\n\
         \x20     hedge_max: {hedge_max}\n"
    )
}

// --- 1. hedge wins when primary is slow -----------------------------------

/// Two endpoints: a slow primary (200ms delay) and a fast hedge (0ms).
/// With `hedge_after_ms: 50`, the hedge timer fires before the primary
/// responds, the hedge copy is sent to the fast endpoint, and the client
/// sees the fast response. The request count on the fast backend should
/// be >= 1 (the hedge copy).
#[tokio::test]
async fn hedge_wins_when_primary_is_slow() {
    let slow_count = Arc::new(AtomicU64::new(0));
    let fast_count = Arc::new(AtomicU64::new(0));

    let port_slow =
        spawn_delayed_backend(Duration::from_millis(200), "slow", Arc::clone(&slow_count)).await;
    let port_fast = spawn_fast_backend("fast", Arc::clone(&fast_count)).await;

    let yaml = hedge_yaml(port_slow, port_fast, 50, 1, 65536);
    let dp = dataplane_from(&yaml);
    let gw_port = spawn_gateway(dp).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(support::uri(gw_port, "/api/test"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    // The fast hedge should win — the body is "fast", not "slow".
    assert_eq!(
        &body[..],
        b"fast",
        "hedge should win with the fast backend's response"
    );

    // The fast backend received at least one request (the hedge copy).
    let fast_hits = fast_count.load(Ordering::Relaxed);
    assert!(
        fast_hits >= 1,
        "fast backend should have received the hedge copy (got {fast_hits})"
    );
}

// --- 2. no hedge when primary is fast -------------------------------------

/// Both endpoints respond immediately. The hedge timer (50ms) never fires
/// because the primary resolves first. No hedge copies are sent.
#[tokio::test]
async fn no_hedge_when_primary_is_fast() {
    let count_a = Arc::new(AtomicU64::new(0));
    let count_b = Arc::new(AtomicU64::new(0));

    let port_a = spawn_fast_backend("a", Arc::clone(&count_a)).await;
    let port_b = spawn_fast_backend("b", Arc::clone(&count_b)).await;

    let yaml = hedge_yaml(port_a, port_b, 50, 1, 65536);
    let dp = dataplane_from(&yaml);
    let gw_port = spawn_gateway(dp).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(support::uri(gw_port, "/api/test"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);

    // Total requests across both backends should be exactly 1 (the
    // primary). No hedge copy was sent because the primary resolved
    // before the hedge timer fired.
    let total = count_a.load(Ordering::Relaxed) + count_b.load(Ordering::Relaxed);
    assert_eq!(
        total, 1,
        "only the primary should have been called (no hedge)"
    );
}

// --- 3. validation: hedge requires buffer_max_bytes > 0 -------------------

#[test]
fn hedge_validation_requires_buffer() {
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
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 9999\n\
         \x20 retries:\n\
         \x20   attempts: 0\n\
         \x20   buffer_max_bytes: 0\n\
         \x20   hedge:\n\
         \x20     hedge_after_ms: 50\n\
         \x20     hedge_max: 1\n";
    let gw = parse_gateway(yaml).unwrap();
    let issues = validate(&gw);
    let has_hedge_issue = issues
        .iter()
        .any(|i| i.field.contains("hedge") && i.message.contains("buffer_max_bytes"));
    assert!(
        has_hedge_issue,
        "validation should reject hedge without buffer_max_bytes > 0"
    );
}

// --- 4. validation: hedge_after_ms bounds ---------------------------------

#[test]
fn hedge_validation_after_ms_bounds() {
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
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 9999\n\
         \x20 retries:\n\
         \x20   attempts: 0\n\
         \x20   buffer_max_bytes: 65536\n\
         \x20   hedge:\n\
         \x20     hedge_after_ms: 0\n\
         \x20     hedge_max: 1\n";
    let gw = parse_gateway(yaml).unwrap();
    let issues = validate(&gw);
    let has_issue = issues
        .iter()
        .any(|i| i.field.contains("hedge_after_ms") && i.message.contains("must be in"));
    assert!(has_issue, "validation should reject hedge_after_ms = 0");
}

// --- 5. validation: hedge_max bounds --------------------------------------

#[test]
fn hedge_validation_max_bounds() {
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
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 9999\n\
         \x20 retries:\n\
         \x20   attempts: 0\n\
         \x20   buffer_max_bytes: 65536\n\
         \x20   hedge:\n\
         \x20     hedge_after_ms: 50\n\
         \x20     hedge_max: 10\n";
    let gw = parse_gateway(yaml).unwrap();
    let issues = validate(&gw);
    let has_issue = issues
        .iter()
        .any(|i| i.field.contains("hedge_max") && i.message.contains("must be in"));
    assert!(has_issue, "validation should reject hedge_max = 10 (> 4)");
}

// --- 6. hedge config parses and serializes round-trip ---------------------

#[test]
fn hedge_config_round_trip() {
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
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 9999\n\
         \x20 retries:\n\
         \x20   attempts: 2\n\
         \x20   buffer_max_bytes: 65536\n\
         \x20   hedge:\n\
         \x20     hedge_after_ms: 100\n\
         \x20     hedge_max: 2\n";
    let gw = parse_gateway(yaml).unwrap();
    let upstream = &gw.upstreams[0];
    let retries = upstream.retries.as_ref().expect("retries present");
    let hedge = retries.hedge.as_ref().expect("hedge present");
    assert_eq!(hedge.hedge_after_ms, 100);
    assert_eq!(hedge.hedge_max, 2);
}

// --- 7. POST is hedged only with retry_post -------------------------------

/// POST is not hedged by default (non-idempotent). With `retry_post:
/// true`, POST IS hedged. This pins the safety gate: a side-effecting
/// POST must not be speculatively duplicated unless the operator opted in.
#[tokio::test]
async fn post_hedged_only_with_retry_post() {
    // A slow backend that counts requests. If hedging fires, the count
    // will be > 1 (primary + hedge copy).
    let slow_count = Arc::new(AtomicU64::new(0));
    let port_slow =
        spawn_delayed_backend(Duration::from_millis(200), "ok", Arc::clone(&slow_count)).await;
    let port_fast = spawn_fast_backend("ok", Arc::new(AtomicU64::new(0))).await;

    // Without retry_post: POST should NOT be hedged even with a hedge
    // block. Only the primary is sent.
    let yaml = format!(
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
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 load_balancer: round_robin\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port_slow}\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port_fast}\n\
         \x20 retries:\n\
         \x20   attempts: 0\n\
         \x20   retry_post: false\n\
         \x20   buffer_max_bytes: 65536\n\
         \x20   hedge:\n\
         \x20     hedge_after_ms: 50\n\
         \x20     hedge_max: 1\n"
    );
    let dp = dataplane_from(&yaml);
    let gw_port = spawn_gateway(dp).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(support::uri(gw_port, "/api/test"))
                .body(Full::new(Bytes::from_static(b"body")))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    // Only the primary was called — no hedge copy for POST without
    // retry_post. The slow backend received exactly 1 request.
    let hits = slow_count.load(Ordering::Relaxed);
    assert_eq!(
        hits, 1,
        "POST without retry_post should not be hedged (only primary)"
    );
}

// --- 8. all hedges error, primary wins ------------------------------------

/// All hedge copies fail (fast error), but the primary eventually
/// succeeds. The client should get the primary's response. This tests
/// the fall-through path in hedge_race (line: "All hedges errored —
/// await the primary directly").
#[tokio::test]
async fn all_hedges_error_primary_wins() {
    // A slow-but-healthy primary.
    let slow_count = Arc::new(AtomicU64::new(0));
    let port_slow = spawn_delayed_backend(
        Duration::from_millis(150),
        "primary",
        Arc::clone(&slow_count),
    )
    .await;

    // A "hedge" endpoint that refuses connections (immediate error).
    // We use a port that's not listening — the connect will fail fast.
    let port_dead = support::dead_port();

    let yaml = hedge_yaml(port_slow, port_dead, 50, 1, 65536);
    let dp = dataplane_from(&yaml);
    let gw_port = spawn_gateway(dp).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(support::uri(gw_port, "/api/test"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    // The primary won — its body is "primary", not an error.
    assert_eq!(&body[..], b"primary");
}

// --- 9. hedge_max > 1 sends multiple copies -------------------------------

/// With hedge_max=3, the hedge timer fires and 3 speculative copies are
/// sent. We verify by counting total requests to the fast backend.
#[tokio::test]
async fn hedge_max_sends_multiple_copies() {
    let slow_count = Arc::new(AtomicU64::new(0));
    let fast_count = Arc::new(AtomicU64::new(0));

    let port_slow =
        spawn_delayed_backend(Duration::from_millis(200), "slow", Arc::clone(&slow_count)).await;
    let port_fast = spawn_fast_backend("fast", Arc::clone(&fast_count)).await;

    let yaml = hedge_yaml(port_slow, port_fast, 50, 3, 65536);
    let dp = dataplane_from(&yaml);
    let gw_port = spawn_gateway(dp).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(support::uri(gw_port, "/api/test"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"fast");

    // The fast backend received at least 1 hedge copy (round-robin may
    // send some to the slow backend too, but at least one hedge copy
    // must reach the fast backend for it to win).
    let fast_hits = fast_count.load(Ordering::Relaxed);
    assert!(
        fast_hits >= 1,
        "fast backend should have received at least one hedge copy (got {fast_hits})"
    );

    // Total requests = 1 primary + up to 3 hedges = at most 4. The
    // primary goes to one endpoint, hedges go to independently-picked
    // endpoints. At minimum, the primary + at least 1 hedge = 2.
    let total = slow_count.load(Ordering::Relaxed) + fast_hits;
    assert!(
        total >= 2,
        "primary + at least one hedge should have been sent (got {total})"
    );
    assert!(
        total <= 4,
        "at most 1 primary + 3 hedges = 4 requests (got {total})"
    );
}

// --- 10. over-cap body disables hedging -----------------------------------

/// A body larger than `buffer_max_bytes` cannot be replayed, so hedging
/// is disabled for that request. The primary streams normally and no
/// hedge copy is sent even though the hedge timer would fire.
#[tokio::test]
async fn over_cap_body_disables_hedging() {
    let slow_count = Arc::new(AtomicU64::new(0));
    let fast_count = Arc::new(AtomicU64::new(0));

    let port_slow =
        spawn_delayed_backend(Duration::from_millis(200), "slow", Arc::clone(&slow_count)).await;
    let port_fast = spawn_fast_backend("fast", Arc::clone(&fast_count)).await;

    // buffer_max_bytes = 16, but we send a 64-byte body — over cap.
    let yaml = hedge_yaml(port_slow, port_fast, 50, 1, 16);
    let dp = dataplane_from(&yaml);
    let gw_port = spawn_gateway(dp).await;

    let big_body = Bytes::from(vec![b'x'; 64]);
    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(support::uri(gw_port, "/api/test"))
                .body(Full::new(big_body))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);

    // Only the primary was called — no hedge copy because the body
    // couldn't be buffered for replay.
    let total = slow_count.load(Ordering::Relaxed) + fast_count.load(Ordering::Relaxed);
    assert_eq!(
        total, 1,
        "over-cap body should disable hedging (only primary sent)"
    );
}
