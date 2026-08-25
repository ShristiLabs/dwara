//! Local rate limiting integration tests (DW-017, feature analysis 4.8).
//!
//! Drives `proxy::handle` directly (respond-action routes: no upstream
//! needed) and pins the wiring surface:
//!
//! - route- and service-attached policies apply after route resolution
//!   and before cap admission (a 429 never consumes a cap slot);
//! - a denied request answers 429 with `Retry-After` (ceil, min 1) and
//!   `X-RateLimit-Limit` / `-Remaining` / `-Reset` from the binding
//!   constraint;
//! - admitted requests carry `X-RateLimit-*` with decreasing Remaining
//!   and a sane (epoch) Reset;
//! - selector keying: `[ip]` isolates client IPs, `[ip, route]` isolates
//!   (client, route) pairs;
//! - the legacy `rate_limit` policy field still limits (route-scoped);
//! - requests with no matching policy carry no rate headers.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use bytes::Bytes;
use dwara_core::config::parse_gateway;
use dwara_core::proxy::DataPlane;
use dwara_core::snapshot::ConfigState;
use http_body_util::{BodyExt, Full};
use hyper::header::{HeaderMap, RETRY_AFTER};
use hyper::{Request, StatusCode};

/// DW-021: gateway-generated error bodies are the JSON envelope; compare
/// by its stable `code` field.
fn envelope_code(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body).unwrap()["error"]["code"]
        .as_str()
        .unwrap()
        .to_string()
}

fn dataplane_from(yaml: &str) -> Arc<DataPlane> {
    let gateway = parse_gateway(yaml).expect("test config parses");
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

async fn send(
    dp: &DataPlane,
    peer: IpAddr,
    path: &str,
) -> hyper::Response<dwara_core::proxy::ProxyBody> {
    dwara_core::proxy::handle(dp, peer, req(path)).await
}

async fn status_body(
    resp: hyper::Response<dwara_core::proxy::ProxyBody>,
) -> (StatusCode, HeaderMap, String) {
    let (parts, body) = resp.into_parts();
    let bytes = body
        .collect()
        .await
        .unwrap_or_else(|e| panic!("body read failed: {e}"))
        .to_bytes();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    (parts.status, parts.headers, text)
}

fn ip(a: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, a))
}

fn rate_headers(h: &HeaderMap) -> Option<(u64, u64, u64)> {
    let get = |n: &str| -> Option<u64> {
        h.get(format!("x-ratelimit-{n}"))
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
    };
    Some((get("limit")?, get("remaining")?, get("reset")?))
}

const BASE_YAML: &str = "
policies:
  - name: per-ip
    rate_limits:
      - selector: [ip]
        requests_per: { minute: 3 }
  - name: ip-route
    rate_limits:
      - selector: [ip, route]
        requests_per: { minute: 3 }
  - name: legacy
    rate_limit: { requests: 2, window_seconds: 60 }
routes:
  - name: limited
    service: svc
    match: { path: { type: prefix, value: /limited } }
    action: { type: respond, status: 200, body: ok }
    policies: [per-ip]
  - name: pair-keyed
    service: svc
    match: { path: { type: prefix, value: /pair } }
    action: { type: respond, status: 200, body: ok }
    policies: [ip-route]
  - name: legacy-route
    service: svc
    match: { path: { type: prefix, value: /legacy } }
    action: { type: respond, status: 200, body: ok }
    policies: [legacy]
  - name: free
    service: svc
    match: { path: { type: prefix, value: /free } }
    action: { type: respond, status: 200, body: ok }
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";

#[tokio::test]
async fn burst_admits_then_429_with_retry_after_and_headers() {
    let dp = dataplane_from(BASE_YAML);
    let peer = ip(1);
    for expected_remaining in [2, 1, 0] {
        let (status, headers, body) = status_body(send(&dp, peer, "/limited").await).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "within the burst the request passes"
        );
        assert_eq!(body, "ok");
        let (limit, remaining, _reset) = rate_headers(&headers).expect("rate headers on success");
        assert_eq!(limit, 3);
        assert_eq!(remaining, expected_remaining);
    }
    let (status, headers, body) = status_body(send(&dp, peer, "/limited").await).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(envelope_code(body.as_bytes()), "rate_limit_exceeded");
    let retry: u64 = headers
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .expect("Retry-After on 429");
    assert!(retry >= 1, "Retry-After is at least one second");
    let (limit, remaining, reset) = rate_headers(&headers).expect("rate headers on 429");
    assert_eq!(limit, 3);
    assert_eq!(remaining, 0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(reset >= now, "Reset is a future unix epoch second");
}

#[tokio::test]
async fn selector_ip_isolates_clients() {
    let dp = dataplane_from(BASE_YAML);
    for _ in 0..3 {
        assert_eq!(
            status_body(send(&dp, ip(7), "/limited").await).await.0,
            StatusCode::OK
        );
    }
    assert_eq!(
        status_body(send(&dp, ip(7), "/limited").await).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    // A different peer: independent bucket, unaffected by the first.
    assert_eq!(
        status_body(send(&dp, ip(8), "/limited").await).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn selector_ip_route_isolates_pairs() {
    let dp = dataplane_from(BASE_YAML);
    for _ in 0..3 {
        assert_eq!(
            status_body(send(&dp, ip(9), "/pair").await).await.0,
            StatusCode::OK
        );
    }
    assert_eq!(
        status_body(send(&dp, ip(9), "/pair").await).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Same IP, different ROUTE: the [ip, route] key differs, so the
    // request flows (through a different route of the same config).
    assert_eq!(
        status_body(send(&dp, ip(9), "/limited").await).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn legacy_rate_limit_field_still_limits() {
    let dp = dataplane_from(BASE_YAML);
    assert_eq!(
        status_body(send(&dp, ip(2), "/legacy").await).await.0,
        StatusCode::OK
    );
    assert_eq!(
        status_body(send(&dp, ip(3), "/legacy").await).await.0,
        StatusCode::OK,
        "legacy field keys by route, not client"
    );
    let (status, headers, _) = status_body(send(&dp, ip(4), "/legacy").await).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(rate_headers(&headers).unwrap().0, 2);
}

#[tokio::test]
async fn requests_without_policy_carry_no_rate_headers() {
    let dp = dataplane_from(BASE_YAML);
    for _ in 0..10 {
        let (status, headers, _) = status_body(send(&dp, ip(5), "/free").await).await;
        assert_eq!(status, StatusCode::OK);
        assert!(rate_headers(&headers).is_none(), "no policy, no headers");
        assert!(headers.get(RETRY_AFTER).is_none());
    }
}

#[tokio::test]
async fn four_twenty_nine_never_consumes_a_cap_slot() {
    // The rate check runs BEFORE cap admission: a fully rate-limited
    // caller cannot fill the gateway cap (and the cap cannot mask the
    // 429).
    let yaml = BASE_YAML.to_string() + "\nmax_concurrent_requests: 2";
    let dp = dataplane_from(&yaml);
    for _ in 0..3 {
        assert_eq!(
            status_body(send(&dp, ip(6), "/limited").await).await.0,
            StatusCode::OK
        );
    }
    for _ in 0..10 {
        assert_eq!(
            status_body(send(&dp, ip(6), "/limited").await).await.0,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    // A different caller still gets admitted under the same cap.
    assert_eq!(
        status_body(send(&dp, ip(1), "/limited").await).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn service_attached_policies_apply() {
    let yaml = "
policies:
  - name: svc-policy
    rate_limits:
      - selector: [route]
        requests_per: { minute: 2 }
routes:
  - name: r
    service: svc
    match: { path: { type: prefix, value: /r } }
    action: { type: respond, status: 200, body: ok }
services:
  - name: svc
    upstream: up
    policies: [svc-policy]
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";
    let dp = dataplane_from(yaml);
    for _ in 0..2 {
        assert_eq!(
            status_body(send(&dp, ip(1), "/r").await).await.0,
            StatusCode::OK
        );
    }
    let (status, headers, _) = status_body(send(&dp, ip(1), "/r").await).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(rate_headers(&headers).unwrap().0, 2);
}

#[tokio::test]
async fn multi_rule_denial_reports_max_retry_after_but_first_rule_headers() {
    // Route rule (2/s, sub-second retry horizon) AND a service-attached
    // rule (2/minute, ~30s horizon) BOTH deny the third request: the 429's
    // Retry-After must reflect the LONGER wait (minute-scaled), while
    // X-RateLimit-Limit still shows the FIRST-binding rule (the route
    // rule's 2) — pinning the header/retry split semantics.
    let yaml = "
policies:
  - name: fast-route
    rate_limits:
      - selector: [ip]
        requests_per: { s: 2 }
  - name: slow-service
    rate_limits:
      - selector: [ip]
        requests_per: { minute: 2 }
routes:
  - name: r
    service: svc
    match: { path: { type: prefix, value: /r } }
    action: { type: respond, status: 200, body: ok }
    policies: [fast-route]
services:
  - name: svc
    upstream: up
    policies: [slow-service]
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";
    let dp = dataplane_from(yaml);
    for _ in 0..2 {
        assert_eq!(
            status_body(send(&dp, ip(1), "/r").await).await.0,
            StatusCode::OK
        );
    }
    let (status, headers, _) = status_body(send(&dp, ip(1), "/r").await).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let (limit, remaining, _) = rate_headers(&headers).expect("rate headers on 429");
    assert_eq!(
        limit, 2,
        "headers come from the first-binding (route) rule, not the long one"
    );
    assert_eq!(remaining, 0);
    let retry: u64 = headers
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .expect("Retry-After on 429");
    // The route rule alone would hint ~1s; the minute rule's wait (~30s)
    // must win the MAX. Assert minute-scaled magnitude with headroom for
    // elapsed time: strictly above anything the s-window could report.
    assert!(
        retry >= 15,
        "Retry-After {retry} must be minute-scaled (the MAX across rules), not the route rule's ~1s"
    );
}

#[tokio::test]
async fn stacked_windows_bind_on_the_tighter_one() {
    // s: 50 (burst 50) AND minute: 2 (burst 2): the minute window binds.
    let yaml = "
policies:
  - name: stacked
    rate_limits:
      - selector: [ip]
        requests_per: { s: 50, minute: 2 }
routes:
  - name: r
    service: svc
    match: { path: { type: prefix, value: /r } }
    action: { type: respond, status: 200, body: ok }
    policies: [stacked]
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";
    let dp = dataplane_from(yaml);
    assert_eq!(
        status_body(send(&dp, ip(1), "/r").await).await.0,
        StatusCode::OK
    );
    assert_eq!(
        status_body(send(&dp, ip(1), "/r").await).await.0,
        StatusCode::OK
    );
    let (status, headers, _) = status_body(send(&dp, ip(1), "/r").await).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let (limit, remaining, _) = rate_headers(&headers).unwrap();
    assert_eq!(limit, 2, "the minute window is the binding constraint");
    assert_eq!(remaining, 0);
    // Retry-After reflects the minute window (~30s per token), not the
    // per-second one.
    let retry: u64 = headers
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap();
    assert!(
        retry >= 10,
        "retry hint {retry} must be minute-window-scaled"
    );
}

#[tokio::test]
async fn stacked_hour_window_binds_and_reports_hour_scale_retry() {
    // 100 r/s AND 10 per hour stacked: the hour window binds after the
    // first 10 rapid requests, and the 429 surfaces the HOUR constraint
    // (Limit 10, not 100) with an hour-scaled Retry-After.
    let yaml = "
policies:
  - name: stacked-hour
    rate_limits:
      - selector: [ip]
        requests_per: { s: 100, hour: 10 }
routes:
  - name: r
    service: svc
    match: { path: { type: prefix, value: /r } }
    action: { type: respond, status: 200, body: ok }
    policies: [stacked-hour]
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";
    let dp = dataplane_from(yaml);
    for i in 0..10 {
        assert_eq!(
            status_body(send(&dp, ip(1), "/r").await).await.0,
            StatusCode::OK,
            "hour-burst request {i} must pass"
        );
    }
    let (status, headers, body) = status_body(send(&dp, ip(1), "/r").await).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(!body.is_empty(), "429 carries an explanatory body");
    let (limit, remaining, _) = rate_headers(&headers).expect("rate headers on 429");
    assert_eq!(
        limit, 10,
        "the hour window (10) binds, not the s window (100)"
    );
    assert_eq!(remaining, 0);
    let retry: u64 = headers
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .expect("Retry-After on 429");
    // One hour token per 360s: the retry hint must be hour-scaled.
    assert!(retry >= 60, "retry hint {retry} must be hour-scaled");
}

#[tokio::test]
async fn selector_route_shares_one_bucket_across_ips() {
    // [route] keys by route name ONLY: two different client IPs on the
    // same route share one bucket — exhaustion by the first denies the
    // second (pinned shared semantics, contrast [ip]).
    let yaml = "
policies:
  - name: per-route
    rate_limits:
      - selector: [route]
        requests_per: { minute: 3 }
routes:
  - name: r
    service: svc
    match: { path: { type: prefix, value: /r } }
    action: { type: respond, status: 200, body: ok }
    policies: [per-route]
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";
    let dp = dataplane_from(yaml);
    for _ in 0..3 {
        assert_eq!(
            status_body(send(&dp, ip(1), "/r").await).await.0,
            StatusCode::OK
        );
    }
    let (status, headers, _) = status_body(send(&dp, ip(2), "/r").await).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "a different IP shares the route bucket"
    );
    assert_eq!(rate_headers(&headers).unwrap().0, 3);
}

#[tokio::test]
async fn headers_track_the_budget_across_the_burst() {
    // Across successive allowed requests: Limit constant, Remaining
    // strictly decreasing, Reset a sane epoch (within [now, now+window]);
    // the terminal 429 has a non-empty body and Retry-After.
    let dp = dataplane_from(BASE_YAML);
    let peer = ip(4);
    let mut prev_remaining = u64::MAX;
    for _ in 0..3 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (status, headers, _) = status_body(send(&dp, peer, "/limited").await).await;
        assert_eq!(status, StatusCode::OK);
        let (limit, remaining, reset) = rate_headers(&headers).expect("rate headers");
        assert_eq!(limit, 3, "Limit is the binding window's burst size");
        assert!(
            remaining < prev_remaining,
            "Remaining decreases monotonically"
        );
        prev_remaining = remaining;
        // The window is minute(3): full refill is at most the 60s window
        // (plus rounding slack) from now.
        assert!(
            reset >= now && reset <= now + 61,
            "Reset {reset} not within [now, now+60s]"
        );
    }
    let (status, headers, body) = status_body(send(&dp, peer, "/limited").await).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(!body.is_empty());
    assert!(headers.get(RETRY_AFTER).is_some());
}

#[tokio::test]
async fn reload_with_unchanged_policy_still_resets_buckets() {
    // The engine is rebuilt per generation, so a republish of the SAME
    // config resets every bucket (documented): an exhausted key gets a
    // fresh allowance even though the rules are identical.
    let state = Arc::new(ConfigState::new());
    state
        .compile_and_publish(&parse_gateway(BASE_YAML).unwrap())
        .unwrap();
    let dp = DataPlane::new(Arc::clone(&state));
    let peer = ip(2);
    for _ in 0..3 {
        assert_eq!(
            status_body(send(&dp, peer, "/limited").await).await.0,
            StatusCode::OK
        );
    }
    assert_eq!(
        status_body(send(&dp, peer, "/limited").await).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    state
        .compile_and_publish(&parse_gateway(BASE_YAML).unwrap())
        .unwrap();
    dp.refresh();
    let (status, headers, _) = status_body(send(&dp, peer, "/limited").await).await;
    assert_eq!(status, StatusCode::OK, "reload resets the bucket");
    let (_, remaining, _) = rate_headers(&headers).expect("fresh budget reports headers");
    assert_eq!(remaining, 2, "fresh burst 3 minus the one admission");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limited_request_429s_even_when_the_cap_is_saturated() {
    // Order pin: with the gateway cap fully held by one in-flight slow
    // proxied request, an over-limit request still gets 429 — the rate
    // check runs BEFORE cap admission, so the cap can never mask a 429
    // (and a 429 never waits on or consumes a permit).
    use std::convert::Infallible;
    use std::time::Duration;

    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as AutoBuilder;

    // Backend answering 200 after 400ms (holds the proxied request).
    let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bport = backend.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match backend.accept().await {
                Ok(c) => c,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(
                        TokioIo::new(stream),
                        service_fn(|_: hyper::Request<hyper::body::Incoming>| async {
                            tokio::time::sleep(Duration::from_millis(400)).await;
                            Ok::<_, Infallible>(hyper::Response::new(Full::new(Bytes::new())))
                        }),
                    )
                    .await;
            });
        }
    });

    let yaml = format!(
        "
max_concurrent_requests: 1
policies:
  - name: per-ip
    rate_limits:
      - selector: [ip]
        requests_per: {{ minute: 3 }}
routes:
  - name: limited
    service: svc
    match: {{ path: {{ type: prefix, value: /limited }} }}
    action: {{ type: respond, status: 200, body: ok }}
    policies: [per-ip]
  - name: slow
    service: svc
    match: {{ path: {{ type: prefix, value: /slow }} }}
    action: {{ type: proxy }}
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{{ address: 127.0.0.1, port: {bport} }}]
"
    );
    let dp = dataplane_from(&yaml);
    // Exhaust the rate limit for ip(1) on /limited (cap is free between
    // the immediate responds).
    for _ in 0..3 {
        assert_eq!(
            status_body(send(&dp, ip(1), "/limited").await).await.0,
            StatusCode::OK
        );
    }
    // Saturate the cap (1) with one in-flight slow proxied request from a
    // different peer, wait until it is parked on the backend...
    let dp2 = Arc::clone(&dp);
    let slow = tokio::spawn(async move {
        let resp = dwara_core::proxy::handle(&dp2, ip(9), req("/slow")).await;
        let (parts, body) = resp.into_parts();
        let _ = body.collect().await.unwrap().to_bytes();
        parts.status
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    // ...then the over-limit request must still answer 429 (were the cap
    // checked first it would shed with 503 instead).
    let (status, headers, _) = status_body(send(&dp, ip(1), "/limited").await).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(headers.get(RETRY_AFTER).is_some());
    assert_eq!(slow.await.unwrap(), StatusCode::OK);
}

#[test]
fn malformed_rate_limit_rules_are_rejected_at_schema_and_validation() {
    use dwara_core::snapshot::validate;

    const BASE: &str = "
policies:
  - name: p
    rate_limits:
      - selector: {SELECTOR}
        requests_per: {RATE}{BURST}
routes:
  - name: r
    service: svc
    match: { path: { type: prefix, value: /r } }
    action: { type: respond, status: 200 }
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";

    let yaml = |sel: &str, rate: &str, burst: &str| {
        BASE.replace("{SELECTOR}", sel)
            .replace("{RATE}", rate)
            .replace("{BURST}", burst)
    };

    // Unknown selector token: rejected at the SCHEMA (deserialization).
    assert!(
        parse_gateway(&yaml("[bogus]", "{minute: 3}", "")).is_err(),
        "unknown selector token must fail schema deserialization"
    );

    // Empty selector list parses but is rejected by validation.
    let gw = parse_gateway(&yaml("[]", "{minute: 3}", "")).unwrap();
    assert!(
        validate(&gw)
            .iter()
            .any(|i| i.field == "rate_limits[0].selector"),
        "empty selector rejected: {:?}",
        validate(&gw)
    );

    // A zero window rate parses but is rejected by validation (0 would
    // block every request).
    let gw = parse_gateway(&yaml("[ip]", "{s: 0, minute: 3}", "")).unwrap();
    assert!(validate(&gw)
        .iter()
        .any(|i| i.field == "rate_limits[0].requests_per.s"));

    // Burst 0 parses but is rejected by validation.
    let gw = parse_gateway(&yaml("[ip]", "{minute: 3}", "\n        burst: 0")).unwrap();
    assert!(validate(&gw)
        .iter()
        .any(|i| i.field == "rate_limits[0].burst"));

    // The legacy `rate_limit` field still validates: requests 0 is
    // rejected as before.
    let yaml = "
policies:
  - name: legacy
    rate_limit: { requests: 0, window_seconds: 60 }
";
    let gw = parse_gateway(yaml).unwrap();
    assert!(
        validate(&gw)
            .iter()
            .any(|i| i.field == "rate_limit.requests"),
        "legacy rate_limit requests 0 still rejected"
    );
}

#[tokio::test]
async fn reload_rebuilds_the_engine_from_the_new_generation() {
    let state = Arc::new(ConfigState::new());
    state
        .compile_and_publish(&parse_gateway(BASE_YAML).unwrap())
        .unwrap();
    let dp = DataPlane::new(Arc::clone(&state));
    let peer = ip(1);
    for _ in 0..3 {
        assert_eq!(
            status_body(send(&dp, peer, "/limited").await).await.0,
            StatusCode::OK
        );
    }
    assert_eq!(
        status_body(send(&dp, peer, "/limited").await).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Republish a config without the rate policy and refresh: the new
    // generation's engine has no rules, and buckets reset (documented).
    let mut next = parse_gateway(BASE_YAML).unwrap();
    next.routes[0].policies.clear();
    state.compile_and_publish(&next).unwrap();
    dp.refresh();
    let (status, headers, _) = status_body(send(&dp, peer, "/limited").await).await;
    assert_eq!(status, StatusCode::OK);
    assert!(rate_headers(&headers).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_rate_headers_replace_upstream_sent_ones() {
    // The upstream answers with its OWN X-RateLimit-Limit: 999; the
    // gateway's policy also applies, so the client must see the GATEWAY's
    // value (3) — exactly one header, the upstream's 999 gone (the
    // gateway is the source of truth for rate accounting).
    use std::convert::Infallible;

    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as AutoBuilder;

    let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bport = backend.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match backend.accept().await {
                Ok(c) => c,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(
                        TokioIo::new(stream),
                        service_fn(|_: hyper::Request<hyper::body::Incoming>| async {
                            Ok::<_, Infallible>(
                                hyper::Response::builder()
                                    .header("x-ratelimit-limit", "999")
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            )
                        }),
                    )
                    .await;
            });
        }
    });

    let yaml = format!(
        "
policies:
  - name: per-ip
    rate_limits:
      - selector: [ip]
        requests_per: {{ minute: 3 }}
routes:
  - name: p
    service: svc
    match: {{ path: {{ type: prefix, value: /p }} }}
    action: {{ type: proxy }}
    policies: [per-ip]
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{{ address: 127.0.0.1, port: {bport} }}]
"
    );
    let dp = dataplane_from(&yaml);
    let (status, headers, _) = status_body(send(&dp, ip(1), "/p").await).await;
    assert_eq!(status, StatusCode::OK);
    let values: Vec<&str> = headers
        .get_all("x-ratelimit-limit")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert_eq!(
        values,
        vec!["3"],
        "the gateway's value replaces the upstream's 999 (single header)"
    );
}
