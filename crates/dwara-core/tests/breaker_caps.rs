//! Circuit breaking and caps integration tests (DW-015, feature analysis
//! 4.11).
//!
//! Serves real in-process backends against the gateway dataplane and pins
//! the done-when surface:
//!
//! - the per-upstream breaker opens on consecutive 5xx and on an
//!   error-ratio with volume, failing fast with 503 + `Retry-After`;
//! - half-open probes close the breaker on success and re-open it on
//!   failure, with real-clock cool-off timing;
//! - `max_pending` rejects excess waiting requests immediately (503
//!   "upstream saturated") instead of queueing them behind the
//!   connection cap;
//! - `gateway.max_concurrent_requests` admits N concurrent requests,
//!   rejects the N+1th instantly, releases slots on completion, and keeps
//!   `/healthz` answering under saturation;
//! - an open breaker consumes no endpoint health (no ejections during a
//!   pure breaker-open period);
//! - breaker-less / cap-less configs behave exactly as before;
//! - validation rejects nonsensical breaker/pending/global-cap values;
//! - admission rejections (Saturated) drive NEITHER the breaker NOR
//!   passive health (self-inflicted-outage regression), while genuine
//!   transport failures (read timeouts, connection refusals) still do.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dwara_core::config::parse_gateway;
use dwara_core::proxy::{self, DataPlane};
use dwara_core::snapshot::{validate, ConfigState};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::net::TcpListener;

/// DW-021: gateway-generated error bodies are the JSON envelope; compare
/// by its stable `code` field.
fn envelope_code(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body).unwrap()["error"]["code"]
        .as_str()
        .unwrap()
        .to_string()
}

// --- infrastructure (mirrors retries_timeouts.rs) ------------------------

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

/// Backend counting every request; `delay` is served per request.
async fn spawn_backend<F>(first: F, delay: Duration) -> (u16, Arc<AtomicU64>)
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
                            let delay = delay;
                            async move {
                                let (parts, body) = req.into_parts();
                                let bytes = body.collect().await.unwrap().to_bytes();
                                let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                                tokio::time::sleep(delay).await;
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

fn gateway_yaml(backend_port: u16, upstream_extra: &str, gateway_extra: &str) -> String {
    two_endpoint_gateway_yaml(backend_port, None, upstream_extra, gateway_extra)
}

/// Like [`gateway_yaml`] but with a SECOND endpoint (Some) or a single
/// one (None).
fn two_endpoint_gateway_yaml(
    backend_port: u16,
    backend_port2: Option<u16>,
    upstream_extra: &str,
    gateway_extra: &str,
) -> String {
    let second = match backend_port2 {
        Some(p) => format!(
            "\x20   - address: 127.0.0.1\n\
             \x20     port: {p}\n"
        ),
        None => String::new(),
    };
    format!(
        "{gateway_extra}routes:\n\
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
         \x20     port: {backend_port}\n{second}{upstream_extra}"
    )
}

fn status_only(status: u16) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .expect("response")
}

async fn body_of<B>(resp: Response<B>) -> (StatusCode, Bytes, hyper::HeaderMap)
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: std::fmt::Debug + Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (parts.status, bytes, parts.headers)
}

// --- 1. consecutive-5xx breaker -------------------------------------------

#[tokio::test]
async fn breaker_opens_on_consecutive_5xx_and_fails_fast() {
    // First 3 requests fail with 500; everything after succeeds.
    let (port, count) = spawn_backend(
        |n, _m, _p, _b| status_only(if n <= 3 { 500 } else { 200 }),
        Duration::ZERO,
    )
    .await;
    let yaml = gateway_yaml(
        port,
        "  breaker:\n    consecutive_failures: 3\n    open_ms: 60000\n",
        "",
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;
    let client = h1_client();

    for _ in 0..3 {
        let (status, _, _) = body_of(client.get(uri(gw, "/api/x")).await.unwrap()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }
    // 4th request: the breaker is open. Fail fast 503, Retry-After = the
    // seconds until half-open (rounded up), no backend attempt.
    let started = Instant::now();
    let (status, body, headers) = body_of(client.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(envelope_code(&body), "upstream_circuit_open");
    let retry_after: u64 = headers
        .get("retry-after")
        .expect("Retry-After present")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        (1..=60).contains(&retry_after),
        "Retry-After {retry_after} should be the seconds until half-open"
    );
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "fail-fast must not wait on the upstream"
    );
    assert_eq!(count.load(Ordering::SeqCst), 3, "no attempt while open");
}

// --- 2. error-ratio breaker ------------------------------------------------

#[tokio::test]
async fn breaker_opens_on_error_ratio_with_volume() {
    // consecutive_failures is set unreachable (100); only the ratio path
    // can trip. Observations: F S F S (2/4 = 50%, volume met but only
    // evaluated on a failure report), then F -> 3/5 = 60% >= 50% trips.
    let (port, count) = spawn_backend(
        |n, _m, _p, _b| status_only(if n % 2 == 1 { 500 } else { 200 }),
        Duration::ZERO,
    )
    .await;
    let yaml = gateway_yaml(
        port,
        "  breaker:\n    consecutive_failures: 100\n    error_ratio: 0.5\n    error_volume: 4\n    open_ms: 60000\n",
        "",
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;
    let client = h1_client();

    // Five real attempts: the backend alternates 500/200, so responses are
    // 500, 200, 500, 200, 500 (the 5th observation is a failure crossing
    // the 0.5 ratio at volume 5).
    for expected in [500, 200, 500, 200, 500] {
        let (status, _, _) = body_of(client.get(uri(gw, "/api/x")).await.unwrap()).await;
        assert_eq!(status.as_u16(), expected);
    }
    let (status, body, _) = body_of(client.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(envelope_code(&body), "upstream_circuit_open");
    assert_eq!(count.load(Ordering::SeqCst), 5);
}

// --- 3/4. half-open --------------------------------------------------------

#[tokio::test]
async fn half_open_probe_success_closes_the_breaker() {
    let (port, _count) = spawn_backend(
        |n, _m, _p, _b| status_only(if n <= 3 { 500 } else { 200 }),
        Duration::ZERO,
    )
    .await;
    let yaml = gateway_yaml(
        port,
        "  breaker:\n    consecutive_failures: 3\n    open_ms: 300\n",
        "",
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;
    let client = h1_client();

    for _ in 0..3 {
        let _ = client.get(uri(gw, "/api/x")).await.unwrap();
    }
    // Still open right now.
    let (status, _, _) = body_of(client.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    // Cool-off elapses: the next request is the half-open probe; the
    // backend now answers 200, so the probe closes the breaker.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let (status, _, _) = body_of(client.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "probe succeeds and closes");
    // Closed: traffic flows (and stays open for successes).
    for _ in 0..2 {
        let (status, _, _) = body_of(client.get(uri(gw, "/api/x")).await.unwrap()).await;
        assert_eq!(status, StatusCode::OK);
    }
}

#[tokio::test]
async fn half_open_probe_failure_reopens() {
    // The backend never succeeds.
    let (port, _count) = spawn_backend(|_n, _m, _p, _b| status_only(500), Duration::ZERO).await;
    let yaml = gateway_yaml(
        port,
        "  breaker:\n    consecutive_failures: 2\n    open_ms: 300\n",
        "",
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;
    let client = h1_client();

    for _ in 0..2 {
        let _ = client.get(uri(gw, "/api/x")).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    // Half-open probe passes THROUGH to the backend and sees its 500 (a
    // real upstream answer, not the gateway's fail-fast 503).
    let (status, _, _) = body_of(client.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    // The failed probe re-opened the breaker: fail fast again.
    let (status, body, _) = body_of(client.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(envelope_code(&body), "upstream_circuit_open");
}

// --- 5. max_pending --------------------------------------------------------

#[tokio::test]
async fn max_pending_rejects_excess_requests_immediately() {
    let (port, _count) = spawn_backend(
        |_n, _m, _p, _b| status_only(200),
        Duration::from_millis(500),
    )
    .await;
    // connection_cap 1: one outbound connection; max_pending 1: exactly one
    // request may WAIT for that slot; the third concurrent request must be
    // rejected immediately instead of queueing.
    let yaml = gateway_yaml(port, "  connection_cap: 1\n  max_pending: 1\n", "");
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;

    let c0 = h1_client();
    let c1 = h1_client();
    let c2 = h1_client();
    let r1 = tokio::spawn(async move { c0.get(uri(gw, "/api/slow")).await.unwrap() });
    let r2 = tokio::spawn(async move { c1.get(uri(gw, "/api/slow")).await.unwrap() });
    // Let the first two occupy the connection and the pending slot.
    tokio::time::sleep(Duration::from_millis(150)).await;
    let started = Instant::now();
    let (status, body, _) = body_of(third_request(&c2, gw).await).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(envelope_code(&body), "upstream_saturated");
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "rejection must be immediate, took {:?}",
        started.elapsed()
    );
    let (s1, _, _) = body_of(r1.await.unwrap()).await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, _, _) = body_of(r2.await.unwrap()).await;
    assert_eq!(s2, StatusCode::OK, "the admitted pending request waits");
}

/// The third concurrent request for the max_pending test.
async fn third_request(
    client: &Client<HttpConnector, Full<Bytes>>,
    gw: u16,
) -> Response<hyper::body::Incoming> {
    client.get(uri(gw, "/api/slow")).await.unwrap()
}

// --- 6. global concurrency cap ---------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn global_cap_admits_two_and_rejects_the_third_instantly() {
    let (port, _count) = spawn_backend(
        |_n, _m, _p, _b| status_only(200),
        Duration::from_millis(400),
    )
    .await;
    let yaml = gateway_yaml(port, "", "max_concurrent_requests: 2\n");
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;

    let clients: Vec<_> = (0..3).map(|_| h1_client()).collect();
    let mut tasks = Vec::new();
    for c in clients {
        tasks.push(tokio::spawn(async move {
            let started = Instant::now();
            let resp = c.get(uri(gw, "/api/slow")).await.unwrap();
            let elapsed = started.elapsed();
            (elapsed, resp)
        }));
    }
    let mut statuses = Vec::new();
    let mut rejected_elapsed = None;
    for t in tasks {
        let (elapsed, resp) = t.await.unwrap();
        let (status, body, _) = body_of(resp).await;
        if status == StatusCode::SERVICE_UNAVAILABLE {
            assert_eq!(envelope_code(&body), "gateway_saturated");
            rejected_elapsed = Some(elapsed);
        }
        statuses.push(status);
    }
    assert_eq!(
        statuses.iter().filter(|s| **s == StatusCode::OK).count(),
        2,
        "exactly the cap-many requests admitted: {statuses:?}"
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::SERVICE_UNAVAILABLE)
            .count(),
        1
    );
    let elapsed = rejected_elapsed.expect("one request rejected");
    assert!(
        elapsed < Duration::from_millis(300),
        "rejection must be immediate, took {elapsed:?}"
    );

    // Slots released on completion: a follow-up request flows again.
    let client = h1_client();
    let (status, _, _) = body_of(client.get(uri(gw, "/api/slow")).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn healthz_answers_under_global_saturation() {
    let (port, _count) = spawn_backend(
        |_n, _m, _p, _b| status_only(200),
        Duration::from_millis(400),
    )
    .await;
    let yaml = gateway_yaml(port, "", "max_concurrent_requests: 1\n");
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;

    let c0 = h1_client();
    let busy = tokio::spawn(async move { c0.get(uri(gw, "/api/slow")).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;
    // The cap is fully occupied; the reserved liveness path still answers.
    let client = h1_client();
    let (status, _, _) = body_of(client.get(uri(gw, "/healthz")).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    let _ = body_of(busy.await.unwrap()).await;
}

// --- 7. breaker vs endpoint ejection ---------------------------------------

#[tokio::test]
async fn breaker_open_period_ejects_no_endpoints() {
    let (port, count) = spawn_backend(|_n, _m, _p, _b| status_only(500), Duration::ZERO).await;
    // Passive health would eject after 4 consecutive failures — one MORE
    // than the breaker (3), so the breaker opens first and short-circuits
    // every later request: health never observes a 4th failure and the
    // endpoint is never ejected. Independent layers.
    let yaml = gateway_yaml(
        port,
        "  breaker:\n    consecutive_failures: 3\n    open_ms: 60000\n  health:\n    consecutive_failures: 4\n    failure_ratio: 0.99\n    failure_min_volume: 1000\n    window_ms: 60000\n    eject_ms: 30000\n    half_open_probes: 1\n",
        "",
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();

    for _ in 0..6 {
        let _ = client.get(uri(gw, "/api/x")).await.unwrap();
    }
    // Three real attempts (500s), then three fail-fasts: no ejection.
    assert_eq!(count.load(Ordering::SeqCst), 3);
    let handle = dp.registry().get("up").expect("handle");
    let (_, _, health) = handle
        .lb()
        .health_targets()
        .into_iter()
        .next()
        .expect("endpoint health tracked");
    let health = health.expect("health configured");
    assert_eq!(health.ejections(), 0, "breaker-open must not eject");
}

// --- 8. no-config behavior identical ---------------------------------------

#[tokio::test]
async fn no_breaker_or_caps_config_behaves_as_before() {
    // A failing backend with NO breaker block: every request is attempted
    // and the upstream 500 passes through every time.
    let (port, count) = spawn_backend(|_n, _m, _p, _b| status_only(500), Duration::ZERO).await;
    let yaml = gateway_yaml(port, "", "");
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;
    let client = h1_client();
    for _ in 0..8 {
        let (status, _, headers) = body_of(client.get(uri(gw, "/api/x")).await.unwrap()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(headers.get("retry-after").is_none());
    }
    assert_eq!(count.load(Ordering::SeqCst), 8, "every request attempted");
}

// --- 9. validation ----------------------------------------------------------

#[test]
fn validate_rejects_nonsensical_breaker_and_cap_values() {
    let bad_breaker = gateway_yaml(
        9001,
        "  breaker:\n    consecutive_failures: 0\n    error_ratio: 1.5\n    error_volume: 0\n    open_ms: 0\n    half_open_probes: 0\n  max_pending: 0\n",
        "max_concurrent_requests: 0\n",
    );
    let gateway = parse_gateway(&bad_breaker).expect("parses");
    let issues = validate(&gateway);
    let fields: Vec<&str> = issues.iter().map(|i| i.field.as_str()).collect();
    for expected in [
        "breaker.consecutive_failures",
        "breaker.error_ratio",
        "breaker.error_volume",
        "breaker.open_ms",
        "breaker.half_open_probes",
        "max_pending",
        "max_concurrent_requests",
    ] {
        assert!(
            fields.contains(&expected),
            "missing issue for {expected}: {fields:?}"
        );
    }

    let ok = gateway_yaml(
        9001,
        "  breaker: {}\n  max_pending: 4\n",
        "max_concurrent_requests: 8\n",
    );
    let gateway = parse_gateway(&ok).expect("parses");
    assert!(
        validate(&gateway).is_empty(),
        "defaulted breaker block must validate: {:?}",
        validate(&gateway)
    );
}

// --- 10. validation: ratio 0 / NaN rejected, 1.0 accepted --------------------

#[test]
fn validate_rejects_zero_and_nan_error_ratio_and_accepts_one() {
    for bad_ratio in ["0", ".nan"] {
        let yaml = gateway_yaml(
            9001,
            &format!("  breaker:\n    error_ratio: {bad_ratio}\n"),
            "",
        );
        let gateway = parse_gateway(&yaml).expect("parses");
        let issues = validate(&gateway);
        assert!(
            issues.iter().any(|i| i.field == "breaker.error_ratio"),
            "error_ratio {bad_ratio} must be rejected: {issues:?}"
        );
    }
    // 1.0 (everything is a failure once volume is met) is in (0, 1].
    let ok = gateway_yaml(9001, "  breaker:\n    error_ratio: 1.0\n", "");
    let gateway = parse_gateway(&ok).expect("parses");
    assert!(
        validate(&gateway).is_empty(),
        "error_ratio 1.0 must validate: {:?}",
        validate(&gateway)
    );
}

// --- 11. half-open under concurrency ----------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn half_open_admits_at_most_half_open_probes_concurrently() {
    // First 2 requests fail (trip on consecutive_failures 2); everything
    // after SUCCEEDS but slowly (400 ms), so the three admitted probes
    // stay in flight while the rest arrive.
    let (port, count) = spawn_backend(
        |n, _m, _p, _b| status_only(if n <= 2 { 500 } else { 200 }),
        Duration::from_millis(400),
    )
    .await;
    let yaml = gateway_yaml(
        port,
        "  breaker:\n    consecutive_failures: 2\n    open_ms: 300\n    half_open_probes: 3\n",
        "",
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;

    for _ in 0..2 {
        let c = h1_client();
        let (status, _, _) = body_of(c.get(uri(gw, "/api/x")).await.unwrap()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }
    // Cool-off elapses; the backend is healthy-but-slow now.
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Six CONCURRENT requests during half-open: at most 3 (the probe
    // count) may reach the backend; the rest fail fast. The probes take
    // 400 ms, so admission for all six is decided long before any probe
    // resolves — deterministic in practice, verified over repeated runs.
    let clients: Vec<_> = (0..6).map(|_| h1_client()).collect();
    let mut tasks = Vec::new();
    for c in clients {
        tasks.push(tokio::spawn(async move {
            let started = Instant::now();
            let resp = c.get(uri(gw, "/api/x")).await.unwrap();
            let elapsed = started.elapsed();
            (elapsed, resp)
        }));
    }
    let mut ok = 0;
    let mut rejected = 0;
    for t in tasks {
        let (elapsed, resp) = t.await.unwrap();
        let (status, body, headers) = body_of(resp).await;
        match status {
            StatusCode::OK => ok += 1,
            StatusCode::SERVICE_UNAVAILABLE => {
                assert_eq!(envelope_code(&body), "upstream_circuit_open");
                // Probing hint while probes are in flight.
                assert_eq!(headers.get("retry-after").unwrap(), "1");
                assert!(
                    elapsed < Duration::from_millis(300),
                    "fail-fast must be immediate, took {elapsed:?}"
                );
                rejected += 1;
            }
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!(ok, 3, "exactly the probe count succeeded");
    assert_eq!(rejected, 3);
    assert_eq!(
        count.load(Ordering::SeqCst),
        5,
        "2 trip attempts + exactly 3 probes reached the backend"
    );
}

// --- 12. breaker + retries interplay ----------------------------------------

#[tokio::test]
async fn open_breaker_makes_no_attempts_and_consumes_no_retry_budget() {
    // Backend always 500; retries allowed on 500 (attempts 1, budget
    // 100%). Request 1: two attempts (both 500) — the SECOND report trips
    // the breaker (consecutive_failures 2), but the response still passes
    // through. Every later request: NO attempts at all and the retry
    // budget is untouched by the open-period requests.
    let (port, count) = spawn_backend(|_n, _m, _p, _b| status_only(500), Duration::ZERO).await;
    let yaml = gateway_yaml(
        port,
        "  retries:\n    attempts: 1\n    retry_statuses: [500]\n    budget_percent: 100\n    backoff_base_ms: 1\n    backoff_cap_ms: 2\n  breaker:\n    consecutive_failures: 2\n    open_ms: 60000\n",
        "",
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    let c1 = h1_client();
    let (status, _, _) = body_of(c1.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(count.load(Ordering::SeqCst), 2, "one retry ran");
    let budget = Arc::clone(dp.registry().get("up").unwrap().retry_budget());
    // totals counts request + retry events: 1 original + 1 retry.
    assert_eq!(budget.totals(), 2);
    assert_eq!(budget.retries(), 1);

    // Open-period requests: fail fast, no backend attempt, and NO retry
    // budget consumption (retry count frozen; denominators still accrue
    // by design — one record per proxied request).
    for _ in 0..3 {
        let c = h1_client();
        let (status, body, _) = body_of(c.get(uri(gw, "/api/x")).await.unwrap()).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(envelope_code(&body), "upstream_circuit_open");
    }
    assert_eq!(count.load(Ordering::SeqCst), 2, "zero attempts while open");
    assert_eq!(budget.totals(), 5, "denominator grows (by design)");
    assert_eq!(
        budget.retries(),
        1,
        "an open breaker must not consume retry budget"
    );
    // A follow-up eligible request still has headroom.
    assert!(
        budget.try_reserve_retry(100),
        "retry budget headroom must be intact"
    );
}

// --- 13. breaker + endpoint ejection independence ----------------------------

#[tokio::test]
async fn breaker_gates_upstream_even_after_endpoints_recover_from_ejection() {
    // Two endpoints, both always failing. Passive health ejects each
    // after 2 of its own failures; the breaker (streak 6) opens after 6
    // total failures — both layers trip. After eject_ms the endpoints
    // are available again (fail-open/half-open), but the breaker — which
    // gates the WHOLE upstream, independent of endpoint state — still
    // rejects: the breaker sits ABOVE ejection in the layering.
    let (p1, c1) = spawn_backend(|_n, _m, _p, _b| status_only(500), Duration::ZERO).await;
    let (p2, c2) = spawn_backend(|_n, _m, _p, _b| status_only(500), Duration::ZERO).await;
    let yaml = two_endpoint_gateway_yaml(
        p1,
        Some(p2),
        "  breaker:\n    consecutive_failures: 6\n    open_ms: 60000\n  health:\n    consecutive_failures: 2\n    failure_ratio: 0.99\n    failure_min_volume: 1000\n    window_ms: 60000\n    eject_ms: 300\n    half_open_probes: 1\n",
        "",
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    // Six failures: round-robin gives each endpoint three; each ejects on
    // its own second failure, the breaker opens on the sixth.
    for _ in 0..6 {
        let c = h1_client();
        let (status, _, _) = body_of(c.get(uri(gw, "/api/x")).await.unwrap()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }
    assert_eq!(
        c1.load(Ordering::SeqCst) + c2.load(Ordering::SeqCst),
        6,
        "all six attempts reached a backend (fail-open picks included)"
    );
    let handle = dp.registry().get("up").unwrap();
    let ejected = handle
        .lb()
        .health_targets()
        .into_iter()
        .filter(|(_, _, h)| h.as_ref().is_some_and(|h| h.ejections() >= 1))
        .count();
    assert_eq!(ejected, 2, "both endpoints eventually ejected");

    // Breaker open: fail fast, no attempt.
    let c = h1_client();
    let (status, body, _) = body_of(c.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(envelope_code(&body), "upstream_circuit_open");
    assert_eq!(c1.load(Ordering::SeqCst) + c2.load(Ordering::SeqCst), 6);

    // eject_ms (300 ms) elapses: endpoints are candidates again, but the
    // breaker — the layer above — still gates the upstream. Layering
    // pinned: endpoint state does not affect breaker state.
    tokio::time::sleep(Duration::from_millis(450)).await;
    let c = h1_client();
    let (status, body, _) = body_of(c.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(envelope_code(&body), "upstream_circuit_open");
    assert_eq!(
        c1.load(Ordering::SeqCst) + c2.load(Ordering::SeqCst),
        6,
        "breaker gates even with recovered endpoints"
    );
}

// --- 14. streaming backend for the global-cap body-completion test ----------

type StreamSender = tokio::sync::mpsc::Sender<Bytes>;

/// A response body that streams nothing until the sender side is dropped
/// (then ends): lets a test hold a response body OPEN and complete it on
/// demand. `Unpin` (mpsc receiver), so the `Body` impl is trivial.
struct HeldBody {
    rx: tokio::sync::mpsc::Receiver<Bytes>,
}

impl hyper::body::Body for HeldBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(b)) => Poll::Ready(Some(Ok(hyper::body::Frame::data(b)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Backend serving 200 responses whose bodies are held OPEN until the
/// test drops the registered sender — completing that stream.
async fn spawn_streaming_backend() -> (
    u16,
    Arc<AtomicU64>,
    Arc<std::sync::Mutex<Vec<StreamSender>>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&count);
    let senders: Arc<std::sync::Mutex<Vec<StreamSender>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let reg = Arc::clone(&senders);
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            let counter = Arc::clone(&counter);
            let reg = Arc::clone(&reg);
            tokio::spawn(async move {
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req: Request<Incoming>| {
                            let counter = Arc::clone(&counter);
                            let reg = Arc::clone(&reg);
                            async move {
                                let _ = req.into_body().collect().await;
                                counter.fetch_add(1, Ordering::SeqCst);
                                let (tx, rx) = tokio::sync::mpsc::channel(1);
                                // Prime the stream so headers + one chunk
                                // flush, then hold it open (tx parked in
                                // the registry keeps rx from ending).
                                tx.send(Bytes::from_static(b"chunk"))
                                    .await
                                    .expect("priming chunk");
                                let body = HeldBody { rx };
                                reg.lock().unwrap().push(tx);
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(200)
                                        .body(body)
                                        .expect("response"),
                                )
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    (port, count, senders)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn global_cap_releases_slot_on_stream_body_completion_not_headers() {
    let (port, count, senders) = spawn_streaming_backend().await;
    let yaml = gateway_yaml(port, "", "max_concurrent_requests: 2\n");
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;

    // Two streaming responses, headers received, bodies HELD OPEN: both
    // global slots stay taken.
    let c1 = h1_client();
    let r1 = c1.get(uri(gw, "/api/s")).await.unwrap();
    let c2 = h1_client();
    let r2 = c2.get(uri(gw, "/api/s")).await.unwrap();
    assert_eq!(r1.status(), StatusCode::OK);
    assert_eq!(r2.status(), StatusCode::OK);
    assert_eq!(count.load(Ordering::SeqCst), 2);

    // Third: instant gateway-saturated 503 (both bodies still streaming).
    let c3 = h1_client();
    let started = Instant::now();
    let (status, body, _) = body_of(c3.get(uri(gw, "/api/s")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(envelope_code(&body), "gateway_saturated");
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "rejection must be immediate, took {:?}",
        started.elapsed()
    );

    // Complete stream 1 (drop its sender) AND drain the client body: only
    // then does the gateway's body — and with it the slot — release.
    {
        let mut reg = senders.lock().unwrap();
        let tx = reg.remove(0);
        drop(tx); // ends the backend response body
    }
    let (s1, _, _) = body_of(r1).await;
    assert_eq!(s1, StatusCode::OK);

    // Fourth: admitted again (headers prove the slot freed).
    let c4 = h1_client();
    let r4 = c4.get(uri(gw, "/api/s")).await.unwrap();
    assert_eq!(r4.status(), StatusCode::OK);

    // Cleanup: complete the remaining held streams.
    senders.lock().unwrap().clear();
    let _ = body_of(r2).await;
    let _ = body_of(r4).await;
}

// --- 15. reload semantics ----------------------------------------------------

#[tokio::test]
async fn breaker_state_survives_config_reload() {
    // Trip the breaker, then publish an UNRELATED config change and
    // refresh: the breaker (carried across reloads keyed by upstream
    // name) is still Open — fail fast, no backend attempt.
    let (port, count) = spawn_backend(
        |n, _m, _p, _b| status_only(if n <= 2 { 500 } else { 200 }),
        Duration::ZERO,
    )
    .await;
    let breaker_yaml = "  breaker:\n    consecutive_failures: 2\n    open_ms: 60000\n";
    let yaml1 = gateway_yaml(port, breaker_yaml, "");
    let state = state_from(&yaml1);
    let dp = DataPlane::new(Arc::clone(&state));
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    // Trip the breaker with two proxied 500s. Under load the second
    // request's breaker check can land after both failure reports (the
    // breaker opens one request early); that is benign for the contract
    // under test (state surviving reload), so an early circuit-open is
    // accepted here.
    for _ in 0..2 {
        let c = h1_client();
        let (status, body, _) = body_of(c.get(uri(gw, "/api/x")).await.unwrap()).await;
        match status {
            StatusCode::INTERNAL_SERVER_ERROR => {}
            StatusCode::SERVICE_UNAVAILABLE => {
                assert_eq!(envelope_code(&body), "upstream_circuit_open");
            }
            other => panic!(
                "unexpected trip-phase status {other}: {:?}",
                envelope_code(&body)
            ),
        }
    }

    // Unrelated change: a trusted-proxies entry. Same breaker config.
    let yaml2 = gateway_yaml(port, breaker_yaml, "trusted_proxies:\n  - 127.0.0.1\n");
    let gateway2 = parse_gateway(&yaml2).expect("reload config parses");
    state.compile_and_publish(&gateway2).expect("publishes");
    dp.refresh();

    let hits_before_reload = count.load(Ordering::SeqCst);
    let c = h1_client();
    let (status, body, _) = body_of(c.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(envelope_code(&body), "upstream_circuit_open");
    assert_eq!(
        count.load(Ordering::SeqCst),
        hits_before_reload,
        "no backend attempt after reload"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn global_cap_reload_admits_new_generation_permits() {
    // cap 2 with two in-flight streaming requests (old semaphore permits,
    // Arc-held by their bodies); reload to cap 3: the NEW generation's
    // semaphore admits three MORE requests before rejecting — permits do
    // not carry across generations, and the old in-flight permits do not
    // count against the new cap.
    let (port, _count, senders) = spawn_streaming_backend().await;
    let state = state_from(&gateway_yaml(port, "", "max_concurrent_requests: 2\n"));
    let dp = DataPlane::new(Arc::clone(&state));
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    // Two admitted (headers resolved, bodies held), holding
    // old-generation permits.
    let c1 = h1_client();
    let r1 = c1.get(uri(gw, "/api/s")).await.unwrap();
    let c2 = h1_client();
    let r2 = c2.get(uri(gw, "/api/s")).await.unwrap();
    assert_eq!(r1.status(), StatusCode::OK);
    assert_eq!(r2.status(), StatusCode::OK);

    // Reload: cap 2 -> 3.
    let gateway2 =
        parse_gateway(&gateway_yaml(port, "", "max_concurrent_requests: 3\n")).expect("parses");
    state.compile_and_publish(&gateway2).expect("publishes");
    dp.refresh();

    // The new generation admits three; the fourth is rejected.
    let mut held = Vec::new();
    for i in 0..3 {
        let c = h1_client();
        let resp = c.get(uri(gw, "/api/s")).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "new-generation request {i} must be admitted"
        );
        held.push(resp);
    }
    let c6 = h1_client();
    let (status, body, _) = body_of(c6.get(uri(gw, "/api/s")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(envelope_code(&body), "gateway_saturated");

    // Cleanup: complete all held streams (releases permits).
    senders.lock().unwrap().clear();
    let _ = body_of(r1).await;
    let _ = body_of(r2).await;
    for resp in held {
        let _ = body_of(resp).await;
    }
}

// --- 16. Saturated rejections vs the breaker (regression) -------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saturated_rejections_do_not_trip_the_breaker() {
    // connection_cap 1 + max_pending 1: one outbound connection, one
    // waiting slot. A slow backend keeps the connection busy; extra
    // concurrent requests are rejected as "upstream saturated". If
    // those admission rejections fed the breaker (consecutive_failures
    // 3), it would open — a self-inflicted outage. It must stay CLOSED:
    // once the slow requests drain, a fresh request still reaches the
    // backend.
    //
    // Seating races: spawned holder tasks can be scheduling-starved and
    // serial probes cannot observe saturation (they queue on the sole
    // connection). The load-tolerant shape: fire CONCURRENT bursts
    // until at least one Saturated is observed (a burst self-sustains a
    // pending waiter), then verify the invariant that matters — the
    // breaker never opened.
    let (port, _count) = spawn_backend(
        |_n, _m, _p, _b| status_only(200),
        Duration::from_millis(2500),
    )
    .await;
    let yaml = gateway_yaml(
        port,
        "  connection_cap: 1\n  max_pending: 1\n  breaker:\n    consecutive_failures: 3\n    open_ms: 60000\n",
        "",
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;

    // Concurrent background load (includes the eventual holders).
    let mut holders = Vec::new();
    for _ in 0..2 {
        let c = h1_client();
        holders.push(tokio::spawn(async move {
            c.get(uri(gw, "/api/slow")).await.unwrap()
        }));
    }

    let mut saw_saturated = false;
    let burst_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    'bursts: for _ in 0..8 {
        let mut burst = Vec::new();
        for _ in 0..6 {
            let c = h1_client();
            burst.push(tokio::spawn(async move {
                c.get(uri(gw, "/api/slow")).await.unwrap()
            }));
        }
        for t in burst {
            let (status, body, headers) = body_of(t.await.unwrap()).await;
            match status {
                StatusCode::OK => {}
                StatusCode::SERVICE_UNAVAILABLE => {
                    if envelope_code(&body) == "upstream_saturated" {
                        saw_saturated = true;
                    } else {
                        panic!("breaker must not trip on Saturated: {body:?}");
                    }
                    assert!(
                        headers.get("retry-after").is_none(),
                        "no breaker-open hint may leak"
                    );
                }
                other => panic!("unexpected burst status {other}"),
            }
        }
        if saw_saturated {
            break 'bursts;
        }
        assert!(
            tokio::time::Instant::now() < burst_deadline,
            "saturation never observed across bursts"
        );
    }
    assert!(saw_saturated, "saturation must occur at least once");

    for t in holders {
        let _ = body_of(t.await.unwrap()).await;
    }

    // Regression pin: despite the Saturated observations, the breaker is
    // still CLOSED — a fresh request eventually reaches the backend. A
    // transient admission 503 while the pool drains is legitimate; a
    // circuit-open 503 (Retry-After hint) at ANY point is an immediate
    // failure.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let c = h1_client();
        let (status, body, headers) = body_of(c.get(uri(gw, "/api/slow")).await.unwrap()).await;
        if status == StatusCode::SERVICE_UNAVAILABLE {
            assert!(
                headers.get("retry-after").is_none()
                    && envelope_code(&body) == "upstream_saturated",
                "breaker must not trip on Saturated: got {status} with Retry-After/breaker-open body"
            );
            assert!(
                tokio::time::Instant::now() < deadline,
                "fresh request still Saturated after 20s; pool never drained"
            );
            tokio::time::sleep(Duration::from_millis(75)).await;
            continue;
        }
        assert_eq!(status, StatusCode::OK, "breaker must not trip on Saturated");
        assert!(
            headers.get("retry-after").is_none(),
            "no breaker-open hint may leak"
        );
        break;
    }
}

// --- 17. Saturated rejections vs endpoint ejection (regression) -------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saturated_rejections_do_not_eject_endpoints() {
    // Same saturation setup, but the second observation wire is under
    // test: passive health (consecutive_failures 3) must never see the
    // Saturated rejections — admission rejections say nothing about the
    // endpoint, so ejections() must stay 0. Load-tolerant shape as in
    // the breaker sibling: concurrent bursts until saturation observed,
    // then the ejection invariant. The backend-count invariant is a
    // DELTA: burst requests that were admitted (200) legitimately hit
    // the backend; Saturated ones must not.
    let (port, count) = spawn_backend(
        |_n, _m, _p, _b| status_only(200),
        Duration::from_millis(2500),
    )
    .await;
    let yaml = gateway_yaml(
        port,
        "  connection_cap: 1\n  max_pending: 1\n  breaker:\n    consecutive_failures: 100\n  health:\n    consecutive_failures: 3\n    failure_ratio: 0.99\n    failure_min_volume: 1000\n    window_ms: 60000\n    eject_ms: 30000\n    half_open_probes: 1\n",
        "",
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    let mut holders = Vec::new();
    for _ in 0..2 {
        let c = h1_client();
        holders.push(tokio::spawn(async move {
            c.get(uri(gw, "/api/slow")).await.unwrap()
        }));
    }

    let mut saw_saturated = false;
    let burst_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    'bursts: for _ in 0..8 {
        let mut burst = Vec::new();
        for _ in 0..6 {
            let c = h1_client();
            burst.push(tokio::spawn(async move {
                c.get(uri(gw, "/api/slow")).await.unwrap()
            }));
        }
        for t in burst {
            let (status, body, _) = body_of(t.await.unwrap()).await;
            match status {
                StatusCode::OK => {}
                StatusCode::SERVICE_UNAVAILABLE => {
                    assert_eq!(envelope_code(&body), "upstream_saturated");
                    saw_saturated = true;
                }
                other => panic!("unexpected burst status {other}"),
            }
        }
        if saw_saturated {
            break 'bursts;
        }
        assert!(
            tokio::time::Instant::now() < burst_deadline,
            "saturation never observed across bursts"
        );
    }
    assert!(saw_saturated, "saturation must occur at least once");

    // Controlled backend-count check: let any straggler admits land,
    // then one final burst — its admitted requests hit the backend,
    // its Saturated ones must not.
    tokio::time::sleep(Duration::from_millis(150)).await;
    for t in holders {
        let _ = body_of(t.await.unwrap()).await;
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
    let hits = count.load(Ordering::SeqCst);
    let mut final_burst = Vec::new();
    for _ in 0..6 {
        let c = h1_client();
        final_burst.push(tokio::spawn(async move {
            c.get(uri(gw, "/api/slow")).await.unwrap()
        }));
    }
    let mut admitted = 0u64;
    for t in final_burst {
        let (status, body, _) = body_of(t.await.unwrap()).await;
        match status {
            StatusCode::OK => admitted += 1,
            StatusCode::SERVICE_UNAVAILABLE => {
                assert_eq!(envelope_code(&body), "upstream_saturated");
            }
            other => panic!("unexpected final-burst status {other}"),
        }
    }
    assert_eq!(
        count.load(Ordering::SeqCst) - hits,
        admitted,
        "Saturated rejections must not reach the backend"
    );

    let handle = dp.registry().get("up").expect("handle");
    let (_, _, health) = handle
        .lb()
        .health_targets()
        .into_iter()
        .next()
        .expect("endpoint health tracked");
    let health = health.expect("health configured");
    assert_eq!(
        health.ejections(),
        0,
        "Saturated rejections must not eject endpoints"
    );
}

// --- 18. read timeouts DO trip the breaker (integration) --------------------

#[tokio::test]
async fn read_timeouts_trip_the_breaker_and_fail_fast() {
    // A backend that accepts requests but stalls 800 ms before headers,
    // with read_ms 200: every attempt is a ReadTimeout — a GENUINE
    // transport failure that must feed the breaker. After two (the
    // threshold), the third request fails fast with Retry-After and the
    // backend sees no third attempt.
    let (port, count) = spawn_backend(
        |_n, _m, _p, _b| status_only(200),
        Duration::from_millis(800),
    )
    .await;
    let yaml = gateway_yaml(
        port,
        "  timeouts:\n    read_ms: 200\n  breaker:\n    consecutive_failures: 2\n    open_ms: 60000\n",
        "",
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;
    let client = h1_client();

    for _ in 0..2 {
        let (status, _, headers) = body_of(client.get(uri(gw, "/api/x")).await.unwrap()).await;
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "read timeout surfaces");
        assert!(headers.get("retry-after").is_none());
    }
    assert_eq!(
        count.load(Ordering::SeqCst),
        2,
        "both attempts reached the backend"
    );

    // Breaker open: fail fast, circuit-open body, Retry-After hint, and
    // zero further backend traffic.
    let started = Instant::now();
    let (status, body, headers) = body_of(client.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(envelope_code(&body), "upstream_circuit_open");
    assert!(
        headers.get("retry-after").is_some(),
        "breaker-open responses carry Retry-After"
    );
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "fail-fast must not wait on the upstream"
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        2,
        "no backend attempt while open"
    );
}

// --- 19. genuine transport failures still trip (doc-contract control) -------

#[tokio::test]
async fn connection_refusals_still_trip_the_breaker() {
    // Control for the counting fix: with Saturated / config-class errors
    // excluded, REAL transport failures must still be counted. A port
    // with no listener refuses every connection; the third refusal opens
    // the breaker and the fourth fails fast.
    //
    // The freed ephemeral port can be reclaimed by a concurrently
    // starting sibling test's listener (bind/drop is a TOCTOU): the
    // connect then SUCCEEDS against a foreign server and the request
    // surfaces as a non-refusal error. Retry the whole scenario on a
    // fresh port when that happens.
    for attempt in 0..3 {
        let ghost = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = ghost.local_addr().unwrap().port();
        drop(ghost);

        let yaml = gateway_yaml(
            port,
            "  breaker:\n    consecutive_failures: 3\n    open_ms: 60000\n",
            "",
        );
        let dp = dataplane_from(&yaml);
        let gw = spawn_gateway(dp).await;
        let client = h1_client();

        let mut refused = true;
        for _ in 0..3 {
            let (status, body, headers) =
                body_of(client.get(uri(gw, "/api/x")).await.unwrap()).await;
            if status != StatusCode::BAD_GATEWAY {
                // Port reclaimed mid-run (or a sibling bound it): the
                // connect hit a foreign server. Any 5xx here means
                // retry on a fresh port; anything else is a real bug.
                assert!(
                    status.is_server_error(),
                    "unexpected status {status} on refusal attempt {attempt}: {:?}",
                    envelope_code(&body)
                );
                refused = false;
                break;
            }
            assert_ne!(envelope_code(&body), "upstream_circuit_open");
            assert!(headers.get("retry-after").is_none());
        }
        if !refused {
            continue;
        }
        let (status, body, _) = body_of(client.get(uri(gw, "/api/x")).await.unwrap()).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(envelope_code(&body), "upstream_circuit_open");
        return;
    }
    panic!("refused-port scenario could not run cleanly across attempts");
}
