//! Mirroring and fault injection integration tests (DW-062).
//!
//! Serves real in-process backends against the gateway dataplane and
//! verifies:
//!
//! - Fault injection abort: a 100% abort returns the configured status
//!   without contacting the upstream.
//! - Fault injection delay: a 100% delay adds measurable latency.
//! - Mirroring: a 100% mirror sends a fire-and-forget copy to the
//!   mirror upstream; the primary response is unaffected.
//! - Validation rejects out-of-bounds percentages, statuses, and
//!   fixed_ms; rejects a mirror upstream that does not exist; rejects
//!   an empty fault_injection block.
//! - Config round-trips through parse + serialize.

use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dwara_core::config::parse_gateway;
use dwara_core::snapshot::validate;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::net::TcpListener;

mod support;

use support::{body_of, dataplane_from, h1_client, spawn_gateway, uri};

// --- infrastructure -------------------------------------------------------

/// A simple echo backend that counts requests and returns "ok".
async fn spawn_echo_backend(counter: Arc<AtomicU64>) -> u16 {
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
                                let _ = req.into_body().collect().await;
                                c.fetch_add(1, Ordering::SeqCst);
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header("content-type", "text/plain")
                                        .body(Full::new(Bytes::from("ok")))
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

/// Gateway YAML with a primary upstream and optional mirror/fault blocks.
fn gateway_yaml(
    primary_port: u16,
    mirror_port: Option<u16>,
    mirror_percentage: Option<u8>,
    abort_percentage: Option<u8>,
    abort_status: Option<u16>,
    delay_percentage: Option<u8>,
    delay_ms: Option<u64>,
) -> String {
    let mut s = String::new();
    s.push_str(
        "routes:
",
    );
    s.push_str(
        "  - name: all
",
    );
    s.push_str(
        "    service: svc
",
    );
    s.push_str(
        "    match:
",
    );
    s.push_str(
        "      path:
",
    );
    s.push_str(
        "        type: prefix
",
    );
    s.push_str(
        "        value: /api
",
    );
    s.push_str(
        "    action:
",
    );
    s.push_str(
        "      type: proxy
",
    );
    if let Some(mp) = mirror_percentage {
        s.push_str(
            "    mirror:
",
        );
        s.push_str(
            "      upstream: mirror
",
        );
        s.push_str(&format!(
            "      percentage: {mp}
"
        ));
    }
    if abort_percentage.is_some() || delay_percentage.is_some() {
        s.push_str(
            "    fault_injection:
",
        );
        if let Some(ap) = abort_percentage {
            let st = abort_status.unwrap_or(503);
            s.push_str(
                "      abort:
",
            );
            s.push_str(&format!(
                "        percentage: {ap}
"
            ));
            s.push_str(&format!(
                "        status: {st}
"
            ));
        }
        if let Some(dp) = delay_percentage {
            let dm = delay_ms.unwrap_or(100);
            s.push_str(
                "      delay:
",
            );
            s.push_str(&format!(
                "        percentage: {dp}
"
            ));
            s.push_str(&format!(
                "        fixed_ms: {dm}
"
            ));
        }
    }
    s.push_str(
        "services:
",
    );
    s.push_str(
        "  - name: svc
",
    );
    s.push_str(
        "    upstream: up
",
    );
    s.push_str(
        "upstreams:
",
    );
    s.push_str(
        "  - name: up
",
    );
    s.push_str(
        "    load_balancer: round_robin
",
    );
    s.push_str(
        "    endpoints:
",
    );
    s.push_str(
        "      - address: 127.0.0.1
",
    );
    s.push_str(&format!(
        "        port: {primary_port}
"
    ));
    if let Some(mp) = mirror_port {
        s.push_str(
            "  - name: mirror
",
        );
        s.push_str(
            "    load_balancer: round_robin
",
        );
        s.push_str(
            "    endpoints:
",
        );
        s.push_str(
            "      - address: 127.0.0.1
",
        );
        s.push_str(&format!(
            "        port: {mp}
"
        ));
    }
    s
}

// --- 1. fault injection abort (100%) --------------------------------------

/// A 100% abort returns the configured status without contacting the
/// upstream. The primary backend counter stays at zero.
#[tokio::test]
async fn fault_injection_abort_100_percent() {
    let primary_count = Arc::new(AtomicU64::new(0));
    let port = spawn_echo_backend(Arc::clone(&primary_count)).await;
    let yaml = gateway_yaml(port, None, None, Some(100), Some(503), None, None);
    let dp = dataplane_from(&yaml);
    let gw_port = spawn_gateway(dp).await;

    let client = h1_client();
    let resp = client.get(uri(gw_port, "/api/test")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let (_, body) = body_of(resp).await;
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("fault_injection_abort"),
        "body should contain fault_injection_abort: {body:?}"
    );
    // The primary backend was never contacted.
    assert_eq!(primary_count.load(Ordering::SeqCst), 0);
}

// --- 2. fault injection abort with custom status --------------------------

/// A 100% abort with a custom status (429) returns that status.
#[tokio::test]
async fn fault_injection_abort_custom_status() {
    let primary_count = Arc::new(AtomicU64::new(0));
    let port = spawn_echo_backend(Arc::clone(&primary_count)).await;
    let yaml = gateway_yaml(port, None, None, Some(100), Some(429), None, None);
    let dp = dataplane_from(&yaml);
    let gw_port = spawn_gateway(dp).await;

    let client = h1_client();
    let resp = client.get(uri(gw_port, "/api/test")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(primary_count.load(Ordering::SeqCst), 0);
}

// --- 3. fault injection delay (100%) --------------------------------------

/// A 100% delay adds measurable latency. The request still succeeds
/// (the delay is before the forward, not an abort).
#[tokio::test]
async fn fault_injection_delay_100_percent() {
    let primary_count = Arc::new(AtomicU64::new(0));
    let port = spawn_echo_backend(Arc::clone(&primary_count)).await;
    let yaml = gateway_yaml(port, None, None, None, None, Some(100), Some(200));
    let dp = dataplane_from(&yaml);
    let gw_port = spawn_gateway(dp).await;

    let client = h1_client();
    let start = Instant::now();
    let resp = client.get(uri(gw_port, "/api/test")).await.unwrap();
    let elapsed = start.elapsed();
    assert_eq!(resp.status(), StatusCode::OK);
    // The 200ms delay should be visible. Use a generous lower bound
    // to avoid flakiness under load.
    assert!(elapsed >= Duration::from_millis(150));
    // The primary was eventually contacted (delay is not an abort).
    assert_eq!(primary_count.load(Ordering::SeqCst), 1);
}

// --- 4. mirroring sends shadow traffic (100%) -----------------------------

/// A 100% mirror sends a fire-and-forget copy to the mirror upstream.
/// The primary response is unaffected, and the mirror backend receives
/// at least one request.
#[tokio::test]
async fn mirror_sends_shadow_traffic_100_percent() {
    let primary_count = Arc::new(AtomicU64::new(0));
    let mirror_count = Arc::new(AtomicU64::new(0));
    let primary_port = spawn_echo_backend(Arc::clone(&primary_count)).await;
    let mirror_port = spawn_echo_backend(Arc::clone(&mirror_count)).await;
    let yaml = gateway_yaml(
        primary_port,
        Some(mirror_port),
        Some(100),
        None,
        None,
        None,
        None,
    );
    let dp = dataplane_from(&yaml);
    let gw_port = spawn_gateway(dp).await;

    let client = h1_client();
    let resp = client.get(uri(gw_port, "/api/test")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let (status, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"ok");
    // The primary was contacted.
    assert_eq!(primary_count.load(Ordering::SeqCst), 1);
    // The mirror was contacted (fire-and-forget; poll briefly).
    let mut mirror_hits = 0;
    for _ in 0..20 {
        mirror_hits = mirror_count.load(Ordering::SeqCst);
        if mirror_hits >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        mirror_hits >= 1,
        "mirror backend should receive at least 1 request"
    );
}

// --- 5. mirroring does not affect primary latency -------------------------

/// The mirror is fire-and-forget; the primary response time should not
/// be measurably impacted by the mirror (the mirror task is detached).
#[tokio::test]
async fn mirror_does_not_affect_primary_latency() {
    let primary_count = Arc::new(AtomicU64::new(0));
    let mirror_count = Arc::new(AtomicU64::new(0));
    let primary_port = spawn_echo_backend(Arc::clone(&primary_count)).await;
    // The mirror backend has a 500ms delay — if the mirror were not
    // fire-and-forget, the primary response would be delayed by 500ms.
    let mirror_port =
        spawn_delayed_echo_backend(Arc::clone(&mirror_count), Duration::from_millis(500)).await;
    let yaml = gateway_yaml(
        primary_port,
        Some(mirror_port),
        Some(100),
        None,
        None,
        None,
        None,
    );
    let dp = dataplane_from(&yaml);
    let gw_port = spawn_gateway(dp).await;

    let client = h1_client();
    let start = Instant::now();
    let resp = client.get(uri(gw_port, "/api/test")).await.unwrap();
    let elapsed = start.elapsed();
    assert_eq!(resp.status(), StatusCode::OK);
    // The primary should respond quickly (well under 500ms) despite
    // the mirror's 500ms delay. Use a generous bound.
    assert!(
        elapsed < Duration::from_millis(400),
        "primary response should not wait for the mirror: {elapsed:?}"
    );
}

/// A backend that delays its response by `delay` and counts requests.
async fn spawn_delayed_echo_backend(counter: Arc<AtomicU64>, delay: Duration) -> u16 {
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
                                let _ = req.into_body().collect().await;
                                c.fetch_add(1, Ordering::SeqCst);
                                tokio::time::sleep(delay).await;
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header("content-type", "text/plain")
                                        .body(Full::new(Bytes::from("ok")))
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

// --- 6. fault injection + mirror together ---------------------------------

/// When both fault injection (delay) and mirror are configured, the
/// delay runs before the mirror spawn, and both fire. The primary is
/// delayed and the mirror receives the shadow copy.
#[tokio::test]
async fn fault_injection_delay_and_mirror_together() {
    let primary_count = Arc::new(AtomicU64::new(0));
    let mirror_count = Arc::new(AtomicU64::new(0));
    let primary_port = spawn_echo_backend(Arc::clone(&primary_count)).await;
    let mirror_port = spawn_echo_backend(Arc::clone(&mirror_count)).await;
    let yaml = gateway_yaml(
        primary_port,
        Some(mirror_port),
        Some(100),
        None,
        None,
        Some(100),
        Some(100),
    );
    let dp = dataplane_from(&yaml);
    let gw_port = spawn_gateway(dp).await;

    let client = h1_client();
    let start = Instant::now();
    let resp = client.get(uri(gw_port, "/api/test")).await.unwrap();
    let elapsed = start.elapsed();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(elapsed >= Duration::from_millis(80));
    assert_eq!(primary_count.load(Ordering::SeqCst), 1);
    // Mirror should also have been contacted.
    let mut mirror_hits = 0;
    for _ in 0..20 {
        mirror_hits = mirror_count.load(Ordering::SeqCst);
        if mirror_hits >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(mirror_hits >= 1, "mirror should receive shadow traffic");
}

// --- 7. abort prevents mirroring ------------------------------------------

/// When an abort fires, the request is short-circuited before the
/// mirror spawn. The mirror backend should not receive any traffic.
#[tokio::test]
async fn abort_prevents_mirroring() {
    let primary_count = Arc::new(AtomicU64::new(0));
    let mirror_count = Arc::new(AtomicU64::new(0));
    let primary_port = spawn_echo_backend(Arc::clone(&primary_count)).await;
    let mirror_port = spawn_echo_backend(Arc::clone(&mirror_count)).await;
    let yaml = gateway_yaml(
        primary_port,
        Some(mirror_port),
        Some(100),
        Some(100),
        Some(503),
        None,
        None,
    );
    let dp = dataplane_from(&yaml);
    let gw_port = spawn_gateway(dp).await;

    let client = h1_client();
    let resp = client.get(uri(gw_port, "/api/test")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(primary_count.load(Ordering::SeqCst), 0);
    // Give the mirror task time to potentially fire (it should not).
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(mirror_count.load(Ordering::SeqCst), 0);
}

// --- 8. validation: abort percentage out of bounds ------------------------

#[tokio::test]
async fn validation_abort_percentage_out_of_bounds() {
    let yaml = "routes:\n\
         - name: all\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         \x20 fault_injection:\n\
         \x20   abort:\n\
         \x20     percentage: 150\n\
         \x20     status: 503\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 load_balancer: round_robin\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 1\n";
    let gw = parse_gateway(yaml).unwrap();
    let issues = validate(&gw);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "fault_injection.abort.percentage"),
        "should reject percentage > 100: {issues:?}"
    );
}

// --- 9. validation: abort status out of bounds ----------------------------

#[tokio::test]
async fn validation_abort_status_out_of_bounds() {
    let yaml = "routes:\n\
         - name: all\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         \x20 fault_injection:\n\
         \x20   abort:\n\
         \x20     percentage: 100\n\
         \x20     status: 700\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 load_balancer: round_robin\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 1\n";
    let gw = parse_gateway(yaml).unwrap();
    let issues = validate(&gw);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "fault_injection.abort.status"),
        "should reject status > 599: {issues:?}"
    );
}

// --- 10. validation: delay fixed_ms out of bounds -------------------------

#[tokio::test]
async fn validation_delay_fixed_ms_out_of_bounds() {
    let yaml = "routes:\n\
         - name: all\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         \x20 fault_injection:\n\
         \x20   delay:\n\
         \x20     percentage: 100\n\
         \x20     fixed_ms: 0\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 load_balancer: round_robin\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 1\n";
    let gw = parse_gateway(yaml).unwrap();
    let issues = validate(&gw);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "fault_injection.delay.fixed_ms"),
        "should reject fixed_ms = 0: {issues:?}"
    );
}

// --- 11. validation: mirror upstream not found -----------------------------

#[tokio::test]
async fn validation_mirror_upstream_not_found() {
    let yaml = "routes:\n\
         - name: all\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         \x20 mirror:\n\
         \x20   upstream: nonexistent\n\
         \x20   percentage: 100\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 load_balancer: round_robin\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 1\n";
    let gw = parse_gateway(yaml).unwrap();
    let issues = validate(&gw);
    assert!(
        issues.iter().any(|i| i.field == "mirror.upstream"),
        "should reject mirror upstream not found: {issues:?}"
    );
}

// --- 12. validation: empty fault_injection block --------------------------

#[tokio::test]
async fn validation_empty_fault_injection_block() {
    let yaml = "routes:\n\
         - name: all\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         \x20 fault_injection: {}\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 load_balancer: round_robin\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 1\n";
    let gw = parse_gateway(yaml).unwrap();
    let issues = validate(&gw);
    assert!(
        issues.iter().any(|i| i.field == "fault_injection"),
        "should reject empty fault_injection block: {issues:?}"
    );
}

// --- 13. config round-trip ------------------------------------------------

/// The mirror and fault_injection blocks survive a parse + serialize
/// round-trip.
#[tokio::test]
async fn mirror_fault_config_round_trip() {
    let yaml = "routes:\n\
         - name: all\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         \x20 mirror:\n\
         \x20   upstream: mirror\n\
         \x20   percentage: 50\n\
         \x20 fault_injection:\n\
         \x20   abort:\n\
         \x20     percentage: 10\n\
         \x20     status: 503\n\
         \x20   delay:\n\
         \x20     percentage: 20\n\
         \x20     fixed_ms: 500\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 load_balancer: round_robin\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 1\n\
         - name: mirror\n\
         \x20 load_balancer: round_robin\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 2\n";
    let gw = parse_gateway(yaml).unwrap();
    let issues = validate(&gw);
    assert!(
        issues.is_empty(),
        "valid config should have no issues: {issues:?}"
    );
    let route = &gw.routes[0];
    assert_eq!(route.mirror.as_ref().unwrap().upstream, "mirror");
    assert_eq!(route.mirror.as_ref().unwrap().percentage, 50);
    let fi = route.fault_injection.as_ref().unwrap();
    assert_eq!(fi.abort.as_ref().unwrap().percentage, 10);
    assert_eq!(fi.abort.as_ref().unwrap().status, 503);
    assert_eq!(fi.delay.as_ref().unwrap().percentage, 20);
    assert_eq!(fi.delay.as_ref().unwrap().fixed_ms, 500);
    // Round-trip through serde.
    let serialized = serde_yaml_ng::to_string(&gw).unwrap();
    let reparsed = parse_gateway(&serialized).unwrap();
    assert_eq!(reparsed.routes[0].mirror, gw.routes[0].mirror);
    assert_eq!(
        reparsed.routes[0].fault_injection,
        gw.routes[0].fault_injection
    );
}
