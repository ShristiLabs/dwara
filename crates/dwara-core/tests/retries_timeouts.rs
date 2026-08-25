//! Timeouts and retries integration tests (DW-014, feature analysis 4.11).
//!
//! Serves real in-process backends against the gateway dataplane (and, for
//! the raw transport timeout knobs, the upstream handle directly) and pins
//! the done-when surface:
//!
//! - `timeouts.read_ms` bounds each attempt (stalling before headers);
//! - `timeouts.write_ms` bounds response-body stalls (inactivity);
//! - POST is never retried by default, only with `retries.retry_post`;
//! - buffered bodies replay byte-exact; over-cap bodies stream, no retry;
//! - the retry budget is never exceeded under forced-failure load;
//! - a mid-body abort reports a passive-health failure (ejection);
//! - retry-off configs behave exactly as before (single attempt).

use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dwara_core::config::parse_gateway;
use dwara_core::proxy::{self, DataPlane};
use dwara_core::snapshot::{validate, ConfigState};
use dwara_core::upstream::{UpstreamBodyError, UpstreamError, UpstreamRegistry};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// --- infrastructure -----------------------------------------------------

fn state_from(yaml: &str) -> Arc<ConfigState> {
    let gateway = parse_gateway(yaml).expect("test config parses");
    let state = Arc::new(ConfigState::new());
    state
        .compile_and_publish(&gateway)
        .expect("test config publishes");
    state
}

fn dataplane_from(yaml: &str) -> Arc<DataPlane> {
    DataPlane::new(state_from(yaml))
}

async fn spawn_gateway(dp: Arc<DataPlane>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            let dp = Arc::clone(&dp);
            tokio::spawn(async move {
                let _ =
                    AutoBuilder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(
                            TokioIo::new(stream),
                            service_fn(move |req| {
                                let dp = Arc::clone(&dp);
                                let peer_ip = peer.ip();
                                async move {
                                    Ok::<_, Infallible>(proxy::handle(&dp, peer_ip, req).await)
                                }
                            }),
                        )
                        .await;
            });
        }
    });
    port
}

/// Backend counting every request; the handler sees the FULL request body.
/// `first` receives (method, path, body) per request and builds a response.
async fn spawn_backend<F>(first: F) -> (u16, Arc<AtomicU64>)
where
    F: Fn(u32, Method, String, Bytes) -> Response<Full<Bytes>> + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&count);
    let handler = Arc::new(first);
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            let counter = Arc::clone(&counter);
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req: Request<Incoming>| {
                            let counter = Arc::clone(&counter);
                            let handler = Arc::clone(&handler);
                            async move {
                                let (parts, body) = req.into_parts();
                                let bytes = body.collect().await.unwrap().to_bytes();
                                let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                                Ok::<_, Infallible>(handler(
                                    n as u32,
                                    parts.method,
                                    parts.uri.path().to_string(),
                                    bytes,
                                ))
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    (port, count)
}

fn h1_client() -> Client<HttpConnector, Full<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

fn uri(port: u16, path: &str) -> hyper::Uri {
    format!("http://127.0.0.1:{port}{path}").parse().unwrap()
}

/// Gateway YAML with one route to one upstream plus per-test extras spliced
/// into the upstream block.
fn gateway_yaml(backend_port: u16, upstream_extra: &str) -> String {
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
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {backend_port}\n{upstream_extra}"
    )
}

fn retries_yaml(attempts: u32, retry_post: bool, budget_percent: u32) -> String {
    format!(
        "  retries:\n\
         \x20   attempts: {attempts}\n\
         \x20   retry_post: {retry_post}\n\
         \x20   backoff_base_ms: 1\n\
         \x20   backoff_cap_ms: 2\n\
         \x20   budget_percent: {budget_percent}\n\
         \x20   buffer_max_bytes: 65536\n"
    )
}

async fn body_of<B>(resp: Response<B>) -> (StatusCode, Bytes)
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: std::fmt::Debug + Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (parts.status, bytes)
}

// --- 1. read timeout (per-attempt, before headers) ------------------------

/// Accept connections, consume the request, never answer: headers stall.
async fn serve_silent(listener: TcpListener) {
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(_) => continue,
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            // Drain the request (so the client finishes writing), then
            // hold the connection open without ever responding.
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 {
                    return;
                }
            }
        });
    }
}

#[tokio::test]
async fn read_timeout_fires_when_headers_stall() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(serve_silent(listener));

    let yaml = gateway_yaml(port, "  timeouts:\n    read_ms: 150\n");
    let state = state_from(&yaml);
    let registry = UpstreamRegistry::from_snapshot(&state.snapshot());
    let handle = registry.get("up").unwrap();
    assert_eq!(handle.read_timeout(), Some(Duration::from_millis(150)));

    let started = std::time::Instant::now();
    let err = handle
        .send(
            Request::builder()
                .uri("/x")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .expect_err("headers stall must trip read_ms");
    match err {
        UpstreamError::ReadTimeout { after } => {
            assert_eq!(after, Duration::from_millis(150))
        }
        other => panic!("expected ReadTimeout, got {other:?}"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "timed out within the bound, took {:?}",
        started.elapsed()
    );
}

/// Accept, drain the request, answer with headers + a PARTIAL body, then
/// hold the connection: the body stalls mid-stream.
async fn serve_partial_body(listener: TcpListener) {
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(_) => continue,
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            // Drain request head + body.
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        let s = String::from_utf8_lossy(&buf[..n]).to_string();
                        if s.contains("hello-body") {
                            break;
                        }
                    }
                }
            }
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\npartial")
                .await;
            // Hold forever: the remaining ~93 bytes never arrive.
            std::future::pending::<()>().await;
        });
    }
}

#[tokio::test]
async fn write_timeout_fires_when_body_stalls() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(serve_partial_body(listener));

    let yaml = gateway_yaml(port, "  timeouts:\n    write_ms: 150\n");
    let state = state_from(&yaml);
    let registry = UpstreamRegistry::from_snapshot(&state.snapshot());
    let handle = registry.get("up").unwrap();
    assert_eq!(handle.write_timeout(), Some(Duration::from_millis(150)));

    let req = Request::builder()
        .method(Method::POST)
        .uri("/x")
        .body(Full::new(Bytes::from("hello-body")))
        .unwrap();
    let resp = handle.send(req).await.expect("headers arrive");
    assert_eq!(resp.status(), StatusCode::OK);
    // First frame arrives; the stall then exceeds write_ms and the body
    // errors (inactivity timeout, not a total-streaming budget).
    let mut body = resp.into_body();
    let first = tokio::time::timeout(Duration::from_secs(2), body.frame()).await;
    assert!(first.is_ok(), "first frame arrives");
    let started = std::time::Instant::now();
    let second = tokio::time::timeout(Duration::from_secs(3), body.frame()).await;
    match second {
        Ok(Some(Err(e))) => {
            assert!(
                matches!(e, UpstreamBodyError::WriteTimeout { .. }),
                "expected WriteTimeout, got {e:?}"
            );
        }
        other => panic!("expected WriteTimeout error, got {other:?}"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "idle timeout fired within the bound"
    );
}

// --- 2. idempotency (done-when: POST not retried by default) --------------

#[tokio::test]
async fn post_is_not_retried_by_default() {
    let (port, hits) = spawn_backend(|n, _m, _p, _b| {
        // Fail the FIRST request only: a retry would see 200.
        if n == 1 {
            Response::builder()
                .status(503)
                .body(Full::new(Bytes::new()))
                .unwrap()
        } else {
            Response::new(Full::new(Bytes::from("ok")))
        }
    })
    .await;
    let dp = dataplane_from(&gateway_yaml(port, &retries_yaml(3, false, 100)));
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(gp, "/api/submit"))
                .body(Full::new(Bytes::from("payload-123")))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _body) = body_of(resp).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "fails through");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "POST never retried");
}

#[tokio::test]
async fn post_is_retried_when_opted_in_and_replays_body_exactly() {
    let (port, hits) = spawn_backend(|n, _m, _p, body| {
        if n == 1 {
            assert_eq!(&body[..], b"payload-123");
            Response::builder()
                .status(503)
                .body(Full::new(Bytes::new()))
                .unwrap()
        } else {
            // Byte-exact replay, proven by echoing the second attempt's body.
            Response::new(Full::new(body))
        }
    })
    .await;
    let dp = dataplane_from(&gateway_yaml(port, &retries_yaml(3, true, 100)));
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(gp, "/api/submit"))
                .body(Full::new(Bytes::from("payload-123")))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"payload-123", "replayed byte-exact");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn get_with_body_is_retried_on_503() {
    let (port, hits) = spawn_backend(|n, _m, _p, _body| {
        if n == 1 {
            Response::builder()
                .status(503)
                .body(Full::new(Bytes::new()))
                .unwrap()
        } else {
            Response::new(Full::new(Bytes::from("recovered")))
        }
    })
    .await;
    // GET is idempotent-eligible by method, and the buffered body replays.
    let dp = dataplane_from(&gateway_yaml(port, &retries_yaml(2, false, 100)));
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(uri(gp, "/api/search"))
                .body(Full::new(Bytes::from("q=1")))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"recovered");
    assert_eq!(hits.load(Ordering::SeqCst), 2, "one retry after the 503");
}

#[tokio::test]
async fn no_retry_config_is_single_attempt() {
    // Golden sanity for the default path: retries off -> the 503 is final
    // and the backend sees exactly one request (behavior unchanged).
    let (port, hits) = spawn_backend(|_n, _m, _p, _b| {
        Response::builder()
            .status(503)
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;
    let dp = dataplane_from(&gateway_yaml(port, ""));
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(uri(gp, "/api/x"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(&body[..], b"");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

// --- 3. retry budget (done-when: never exceeded under failures) -----------

#[tokio::test]
async fn retry_budget_is_never_exceeded_under_forced_failures() {
    const REQUESTS: u64 = 30;
    const PERCENT: u64 = 10;
    let (port, hits) = spawn_backend(|_n, _m, _p, _b| {
        Response::builder()
            .status(503)
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;
    // attempts 10, budget 10%: every attempt would be "allowed" by the
    // attempt cap; only the budget should bound the blast radius.
    let dp = dataplane_from(&gateway_yaml(
        port,
        &retries_yaml(10, false, PERCENT as u32),
    ));
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let client = h1_client();
    for _ in 0..REQUESTS {
        let resp = client
            .request(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri(gp, "/api/x"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
    let attempts = hits.load(Ordering::SeqCst);
    let retries = attempts - REQUESTS;
    assert!(
        retries * 100 <= PERCENT * REQUESTS,
        "budget exceeded: {retries} retries for {REQUESTS} requests \
         ({attempts} backend attempts)"
    );
    assert!(retries >= 1, "budget allows some retries: got {retries}");
}

// --- 4. body buffering cap -------------------------------------------------

#[tokio::test]
async fn over_cap_body_streams_without_retry() {
    let (port, hits) = spawn_backend(|_n, _m, _p, body| {
        // Prove the FULL body arrived even on the single (503) attempt.
        if body.len() == 100 {
            Response::builder()
                .status(503)
                .body(Full::new(Bytes::new()))
                .unwrap()
        } else {
            Response::builder()
                .status(500)
                .body(Full::new(Bytes::new()))
                .unwrap()
        }
    })
    .await;
    // Buffer cap 4 bytes: the 100-byte body is over cap -> streams, no retry.
    let extra = "  retries:\n    attempts: 5\n    retry_post: true\n    backoff_base_ms: 1\n    backoff_cap_ms: 2\n    budget_percent: 100\n    buffer_max_bytes: 4\n";
    let dp = dataplane_from(&gateway_yaml(port, extra));
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(gp, "/api/big"))
                .body(Full::new(Bytes::from(vec![b'x'; 100])))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _body) = body_of(resp).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "fails through");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "over-cap body never retried"
    );
}

// --- 5. mid-body abort reports a health failure (DW-012 gap) ---------------

/// Accept, drain the request, answer headers + partial body, then CLOSE.
async fn serve_truncating(listener: TcpListener) {
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(_) => continue,
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            // Wait for the request head to arrive (the GET has no body).
            if matches!(stream.read(&mut buf).await, Ok(0) | Err(_)) {
                return;
            }
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\nshort")
                .await;
            drop(stream); // truncate: the body dies mid-stream
        });
    }
}

#[tokio::test]
async fn mid_body_abort_reports_health_failure_and_ejects() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(serve_truncating(listener));

    let extra = "  health:\n    consecutive_failures: 1\n    eject_ms: 60000\n";
    let dp = dataplane_from(&gateway_yaml(port, extra));
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(uri(gp, "/api/stream"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "headers resolve fine");
    // Drain the body: the truncation surfaces as an error or abrupt end.
    let _ = tokio::time::timeout(Duration::from_secs(3), resp.into_body().collect()).await;

    // The abort was reported as a failure; with consecutive_failures: 1 the
    // endpoint must now be ejected.
    let handle = dp.registry().get("up").unwrap();
    let (_, _, tracker) = handle.lb().health_targets()[0].clone();
    let tracker = tracker.expect("health tracker present");
    assert_eq!(
        tracker.ejections(),
        1,
        "mid-body abort ejected the endpoint"
    );
}

// --- 6. transport retries (connect failures) --------------------------------

#[tokio::test]
async fn transport_error_is_retried_to_a_new_endpoint() {
    // Endpoint A is a dead port (connection refused); endpoint B works.
    // With retries on, the refused connect is retried and succeeds on B.
    let (good_port, hits) =
        spawn_backend(|_n, _m, _p, _b| Response::new(Full::new(Bytes::from("from-b")))).await;
    let dead_port = {
        // Bind then drop: the port is (almost certainly) closed.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };
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
         \x20     port: {dead_port}\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {good_port}\n{}",
        retries_yaml(2, false, 100)
    );
    let dp = dataplane_from(&yaml);
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(uri(gp, "/api/x"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"from-b");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "landed on the live endpoint"
    );
}

// --- 7. schema + validation --------------------------------------------------

#[test]
fn schema_parses_retries_with_defaults() {
    let yaml = gateway_yaml(9, "  retries:\n    attempts: 2\n");
    let gw = parse_gateway(&yaml).unwrap();
    let r = gw.upstreams[0].retries.as_ref().unwrap();
    assert_eq!(r.attempts, 2);
    assert!(!r.retry_post);
    assert_eq!(r.backoff_base_ms, 25);
    assert_eq!(r.backoff_cap_ms, 250);
    assert_eq!(r.retry_statuses, vec![502, 503, 504]);
    assert!(r.retry_transport);
    assert_eq!(r.budget_percent, 10);
    assert_eq!(r.buffer_max_bytes, 0);
}

#[test]
fn schema_rejects_unknown_retry_fields() {
    let yaml = gateway_yaml(9, "  retries:\n    attempts: 1\n    bogus: true\n");
    assert!(parse_gateway(&yaml).is_err());
}

fn validated(upstream_extra: &str) -> Vec<String> {
    let gw = parse_gateway(&gateway_yaml(9, upstream_extra)).unwrap();
    validate(&gw)
        .into_iter()
        .map(|i| i.field)
        .collect::<Vec<_>>()
}

#[test]
fn validation_rejects_out_of_bounds_retry_knobs() {
    assert_eq!(
        validated("  retries:\n    attempts: 11\n"),
        vec!["retries.attempts"]
    );
    assert_eq!(
        validated("  retries:\n    attempts: 1\n    backoff_base_ms: 0\n"),
        vec!["retries.backoff_base_ms"]
    );
    assert_eq!(
        validated("  retries:\n    attempts: 1\n    backoff_cap_ms: 10\n"),
        vec!["retries.backoff_cap_ms"]
    );
    for bad in [0u32, 101] {
        assert_eq!(
            validated(&format!(
                "  retries:\n    attempts: 1\n    budget_percent: {bad}\n"
            )),
            vec!["retries.budget_percent"]
        );
    }
    assert_eq!(
        validated("  retries:\n    attempts: 1\n    retry_statuses: [302]\n"),
        vec!["retries.retry_statuses[0]"]
    );
    // The full valid block passes clean.
    assert!(validated(&retries_yaml(3, true, 50)).is_empty());
}

// --- 8. budget invariant at spec scale (100 requests, 20%) -------------------

/// Deterministic serial driving: 100 requests, attempts 3, budget 20% ->
/// total retry attempts observed by the backend NEVER exceed 20. The budget
/// charges each retry BEFORE it runs, so the margin-free bound holds exactly
/// for serial traffic (no jitter race: the reservation is granted only while
/// `(retries + 1) * 100 <= 20 * requests` already holds in the window).
#[tokio::test]
async fn budget_caps_100_request_storm_at_20_percent() {
    const REQUESTS: u64 = 100;
    let (port, hits) = spawn_backend(|_n, _m, _p, _b| {
        Response::builder()
            .status(503)
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;
    let dp = dataplane_from(&gateway_yaml(
        port,
        &retries_yaml(3, false, 20), // attempts 3, budget 20%
    ));
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let client = h1_client();
    for _ in 0..REQUESTS {
        let resp = client
            .request(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri(gp, "/api/x"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
    let attempts = hits.load(Ordering::SeqCst);
    let retries = attempts - REQUESTS;
    assert!(
        retries <= 20,
        "budget exceeded: {retries} retries over {REQUESTS} requests \
         ({attempts} backend attempts)"
    );
    assert!(retries >= 1, "budget grants some retries: got {retries}");
}

// --- 9. idempotency: the actual safe-method set ------------------------------

/// PUT is retry-eligible by method (no opt-in needed); DELETE is NOT in
/// the safe set (GET/HEAD/OPTIONS/TRACE/PUT eligible, POST only with
/// `retry_post`, DELETE never) and fails through on the first 503.
#[tokio::test]
async fn put_is_auto_retried_on_503() {
    let (port, hits) = spawn_backend(|n, _m, _p, _b| {
        if n == 1 {
            Response::builder()
                .status(503)
                .body(Full::new(Bytes::new()))
                .unwrap()
        } else {
            Response::new(Full::new(Bytes::from("put-ok")))
        }
    })
    .await;
    let dp = dataplane_from(&gateway_yaml(port, &retries_yaml(2, false, 100)));
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::PUT)
                .uri(uri(gp, "/api/thing"))
                .body(Full::new(Bytes::from("v2")))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"put-ok");
    assert_eq!(hits.load(Ordering::SeqCst), 2, "PUT retried once");
}

#[tokio::test]
async fn delete_is_never_retried_on_503() {
    let (port, hits) = spawn_backend(|_n, _m, _p, _b| {
        Response::builder()
            .status(503)
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;
    let dp = dataplane_from(&gateway_yaml(port, &retries_yaml(3, false, 100)));
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::DELETE)
                .uri(uri(gp, "/api/thing"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _body) = body_of(resp).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(hits.load(Ordering::SeqCst), 1, "DELETE not in safe set");
}

// --- 9b. post-fix pins: retry_post governs POST only -------------------------

/// `retry_post: true` must NOT unlock DELETE: exactly one backend hit on a
/// 503 (the opt-in is exclusive to POST; DELETE is never retried).
#[tokio::test]
async fn delete_is_not_retried_even_with_retry_post_true() {
    let (port, hits) = spawn_backend(|_n, _m, _p, _b| {
        Response::builder()
            .status(503)
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;
    let dp = dataplane_from(&gateway_yaml(port, &retries_yaml(3, true, 100)));
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::DELETE)
                .uri(uri(gp, "/api/thing"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _body) = body_of(resp).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "retry_post must not unlock DELETE"
    );
}

/// `retry_post: true` must NOT unlock PATCH either: exactly one hit on 503.
#[tokio::test]
async fn patch_is_not_retried_even_with_retry_post_true() {
    let (port, hits) = spawn_backend(|_n, _m, _p, _b| {
        Response::builder()
            .status(503)
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;
    let dp = dataplane_from(&gateway_yaml(port, &retries_yaml(3, true, 100)));
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::PATCH)
                .uri(uri(gp, "/api/thing"))
                .body(Full::new(Bytes::from("v2")))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _body) = body_of(resp).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "retry_post must not unlock PATCH"
    );
}

/// Control: with `retry_post: true` POST retries still work — a transient
/// 503 is retried exactly `attempts + 1` total backend hits (attempts 1 ->
/// 2 hits).
#[tokio::test]
async fn post_with_retry_post_true_still_retries_attempts_plus_one() {
    let (port, hits) = spawn_backend(|n, _m, _p, _b| {
        if n == 1 {
            Response::builder()
                .status(503)
                .body(Full::new(Bytes::new()))
                .unwrap()
        } else {
            Response::new(Full::new(Bytes::from("ok")))
        }
    })
    .await;
    let dp = dataplane_from(&gateway_yaml(port, &retries_yaml(1, true, 100)));
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(gp, "/api/submit"))
                .body(Full::new(Bytes::from("payload")))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _body) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "attempts(1) + 1 backend hits"
    );
}

/// Starvation fix: the budget denominator records ALL proxied requests —
/// POST-heavy traffic (retry_post=false, every POST failing 503, no retries
/// possible) still builds headroom. After 30 such POSTs the window holds 31
/// recorded requests once the GET arrives: at 10% that is ~3 retries of
/// headroom, so an eligible GET 503 IS retried. Under the old
/// eligibility-only denominator the window would have held only the GET (1
/// recorded request => no headroom => no retry).
#[tokio::test]
async fn post_traffic_builds_budget_headroom_for_later_get_retry() {
    let (port, hits) = spawn_backend(|_n, m, _p, _b| {
        // Everything 503: the POSTs can never recover, the GET retries stay
        // observable as extra backend hits.
        assert!(
            m == Method::POST || m == Method::GET,
            "unexpected method {m}"
        );
        Response::builder()
            .status(503)
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;
    // attempts 3 but budget 10% over 31 recorded requests -> <= 3 retries.
    let dp = dataplane_from(&gateway_yaml(port, &retries_yaml(3, false, 10)));
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let client = h1_client();
    for _ in 0..30 {
        let resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(uri(gp, "/api/submit"))
                    .body(Full::new(Bytes::from("p")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let _ = body_of(resp).await;
    }
    assert_eq!(hits.load(Ordering::SeqCst), 30, "POSTs never retried");

    let resp = client
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(uri(gp, "/api/x"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let _ = body_of(resp).await;
    let total = hits.load(Ordering::SeqCst);
    assert!(
        total >= 31,
        "GET was not retried (starvation): {total} hits"
    );
    // And the budget still bounded it: 10% of 31 -> at most 3 retries.
    assert!(
        total <= 34,
        "budget exceeded for the GET: {total} hits (30 POSTs + retries)"
    );
}

// --- 10. backoff shape: measured inter-attempt gaps ---------------------------

/// Backend recording the wall-clock arrival instant of every hit, for
/// measuring the real gap between the first attempt and its retry.
async fn spawn_timing_backend(status: u16) -> (u16, Arc<Mutex<Vec<Instant>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let ts: Arc<Mutex<Vec<Instant>>> = Arc::new(Mutex::new(Vec::new()));
    let shared = Arc::clone(&ts);
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            let shared = Arc::clone(&shared);
            tokio::spawn(async move {
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req: Request<Incoming>| {
                            let shared = Arc::clone(&shared);
                            async move {
                                let _ = req.into_body().collect().await;
                                shared.lock().unwrap().push(Instant::now());
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(status)
                                        .body(Full::new(Bytes::new()))
                                        .unwrap(),
                                )
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    (port, ts)
}

/// Two attempts with base 50 / cap 200: the measured inter-attempt gap is
/// a full-jitter draw in [0, 50] (nominal retry-1 backoff), so every gap
/// must be >= 0 and < cap (200 ms). Statistical over N samples; the bound
/// is generous on the upper side (scheduling slack) but strictly under cap.
#[tokio::test]
async fn backoff_inter_attempt_gap_stays_under_cap() {
    const SAMPLES: usize = 15;
    let (port, ts) = spawn_timing_backend(503).await;
    // attempts 1 (one retry), base 50, cap 200, budget 100, buffered bodies.
    let extra = "  retries:\n    attempts: 1\n    retry_post: false\n    backoff_base_ms: 50\n    backoff_cap_ms: 200\n    budget_percent: 100\n    buffer_max_bytes: 65536\n";
    let dp = dataplane_from(&gateway_yaml(port, extra));
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let client = h1_client();
    for _ in 0..SAMPLES {
        let resp = client
            .request(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri(gp, "/api/x"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let _ = body_of(resp).await;
    }
    let hits = ts.lock().unwrap().clone();
    assert_eq!(hits.len(), SAMPLES * 2, "exactly one retry per request");
    for pair in hits.chunks(2) {
        let gap = pair[1].duration_since(pair[0]);
        assert!(
            gap < Duration::from_millis(200),
            "inter-attempt gap {gap:?} reached the 200ms cap"
        );
    }
}

// --- 11. body replay at realistic sizes --------------------------------------

/// Buffered 10 KB POST under a 1 MB cap: the retry replays the body
/// BYTE-IDENTICALLY (the echo of the second attempt equals the original).
#[tokio::test]
async fn ten_kb_post_body_replays_byte_identical_within_cap() {
    let original = (0..10_240u32).map(|i| (i % 251) as u8).collect::<Vec<u8>>();
    let (port, hits) = spawn_backend(move |n, _m, _p, body| {
        if n == 1 {
            Response::builder()
                .status(503)
                .body(Full::new(Bytes::new()))
                .unwrap()
        } else {
            Response::new(Full::new(body))
        }
    })
    .await;
    let extra = "  retries:\n    attempts: 2\n    retry_post: true\n    backoff_base_ms: 1\n    backoff_cap_ms: 2\n    budget_percent: 100\n    buffer_max_bytes: 1048576\n";
    let dp = dataplane_from(&gateway_yaml(port, extra));
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(gp, "/api/upload"))
                .body(Full::new(Bytes::from(original.clone())))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.len(), 10_240);
    assert_eq!(&body[..], &original[..], "second attempt byte-identical");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

/// Over-cap (cap 4 KB, body 10 KB, retry_post on): exactly ONE backend hit,
/// the full body still streams to the upstream (single-attempt path), and
/// the client receives the complete streamed response.
#[tokio::test]
async fn over_cap_ten_kb_body_streams_fully_single_hit() {
    let original = (0..10_240u32).map(|i| (i % 241) as u8).collect::<Vec<u8>>();
    let (port, hits) = spawn_backend(move |_n, _m, _p, body| {
        // Echo only when the FULL 10 KB arrived; a truncated body would
        // fail the byte-identical assertion below.
        Response::new(Full::new(body))
    })
    .await;
    let extra = "  retries:\n    attempts: 5\n    retry_post: true\n    backoff_base_ms: 1\n    backoff_cap_ms: 2\n    budget_percent: 100\n    buffer_max_bytes: 4096\n";
    let dp = dataplane_from(&gateway_yaml(port, extra));
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(gp, "/api/upload"))
                .body(Full::new(Bytes::from(original.clone())))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.len(), 10_240, "full body streamed upstream");
    assert_eq!(&body[..], &original[..], "echo byte-identical");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "over-cap body never retried"
    );
}

// --- 12. timeout enforcement through the gateway -----------------------------

#[tokio::test]
async fn read_timeout_surfaces_as_504_to_client() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(serve_silent(listener));

    let dp = dataplane_from(&gateway_yaml(port, "  timeouts:\n    read_ms: 200\n"));
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let started = Instant::now();
    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(uri(gp, "/api/x"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = body_of(resp).await;
    // 504 (gateway-timeout classification), NOT the backend's own status.
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    assert!(!body.is_empty());
    assert!(
        started.elapsed() < Duration::from_millis(600),
        "504 within ~2x the 200ms bound, took {:?}",
        started.elapsed()
    );
}

/// `write_ms` unset: a mid-body stall (600 ms frame gap) is TOLERATED and
/// the client still receives the complete body.
async fn serve_slow_body(listener: TcpListener) {
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(_) => continue,
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            if matches!(stream.read(&mut buf).await, Ok(0) | Err(_)) {
                return;
            }
            let head = b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n";
            let _ = stream.write_all(head).await;
            let _ = stream.write_all(&[b'a'; 10]).await;
            tokio::time::sleep(Duration::from_millis(600)).await;
            let _ = stream.write_all(&[b'b'; 90]).await;
        });
    }
}

#[tokio::test]
async fn stalled_body_completes_when_write_timeout_unset() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(serve_slow_body(listener));

    // No timeouts block at all: the 600 ms frame gap is fine.
    let dp = dataplane_from(&gateway_yaml(port, ""));
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(uri(gp, "/api/stream"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let (status, body) = tokio::time::timeout(Duration::from_secs(5), body_of(resp))
        .await
        .expect("stall tolerated, body completes");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.len(), 100, "full body received across the stall");
}

#[tokio::test]
async fn write_timeout_errors_client_and_reports_health_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(serve_partial_body(listener));

    let extra = "  timeouts:\n    write_ms: 150\n  health:\n    consecutive_failures: 1\n    eject_ms: 60000\n";
    let dp = dataplane_from(&gateway_yaml(port, extra));
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(gp, "/api/stream"))
                .body(Full::new(Bytes::from("hello-body")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "headers resolve fine");
    // The frame-gap timeout must ERROR the client body (abrupt
    // truncation), never hang silently.
    let started = Instant::now();
    let collected = tokio::time::timeout(Duration::from_secs(3), resp.into_body().collect())
        .await
        .expect("write_ms fired, no silent hang");
    assert!(
        collected.is_err(),
        "truncated body surfaces as an error, not a clean EOF"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "error within the bound"
    );
    // The stall was reported as a passive-health FAILURE (ejection).
    let handle = dp.registry().get("up").unwrap();
    let (_, _, tracker) = handle.lb().health_targets()[0].clone();
    let tracker = tracker.expect("health tracker present");
    assert_eq!(
        tracker.ejections(),
        1,
        "write-timeout body stall ejected the endpoint"
    );
}

// --- 13. retry + health interplay ---------------------------------------------

/// Endpoint A always 503 (retryable), endpoint B healthy, attempts 2: the
/// first attempt lands on A, the retry re-picks and lands on B, and the
/// client sees 200. Both backends are hit EXACTLY once (smooth WRR with
/// equal weights alternates deterministically starting at endpoint 0).
#[tokio::test]
async fn retry_on_503_fails_over_to_healthy_endpoint() {
    let (a_port, a_hits) = spawn_backend(|_n, _m, _p, _b| {
        Response::builder()
            .status(503)
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;
    let (b_port, b_hits) =
        spawn_backend(|_n, _m, _p, _b| Response::new(Full::new(Bytes::from("from-b")))).await;
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
         \x20     port: {a_port}\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {b_port}\n{}",
        retries_yaml(2, false, 100)
    );
    let dp = dataplane_from(&yaml);
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(uri(gp, "/api/x"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"from-b");
    assert_eq!(a_hits.load(Ordering::SeqCst), 1, "A tried first");
    assert_eq!(b_hits.load(Ordering::SeqCst), 1, "B served the retry");
}

/// A fully-failing upstream drives passive-health EJECTION while the retry
/// budget still caps the retry blast radius.
#[tokio::test]
async fn failing_upstream_ejects_while_budget_caps_retries() {
    const REQUESTS: u64 = 30;
    let (port, hits) = spawn_backend(|_n, _m, _p, _b| {
        Response::builder()
            .status(503)
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;
    let extra = "  retries:\n    attempts: 3\n    retry_post: false\n    backoff_base_ms: 1\n    backoff_cap_ms: 2\n    budget_percent: 20\n    buffer_max_bytes: 65536\n  health:\n    consecutive_failures: 2\n    eject_ms: 60000\n";
    let dp = dataplane_from(&gateway_yaml(port, extra));
    let gp = spawn_gateway(Arc::clone(&dp)).await;

    let client = h1_client();
    for _ in 0..REQUESTS {
        let resp = client
            .request(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri(gp, "/api/x"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
    // Ejection happened (fail-open keeps serving once fully ejected).
    let handle = dp.registry().get("up").unwrap();
    let (_, _, tracker) = handle.lb().health_targets()[0].clone();
    let tracker = tracker.expect("health tracker present");
    assert!(
        tracker.ejections() >= 1,
        "503s drove ejection of the endpoint"
    );
    // And the budget still held: retries <= 20% of the 30 requests.
    let retries = hits.load(Ordering::SeqCst) - REQUESTS;
    assert!(
        retries * 100 <= 20 * REQUESTS,
        "budget exceeded under ejection pressure: {retries} retries"
    );
}
