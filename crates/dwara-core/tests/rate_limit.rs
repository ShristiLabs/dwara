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
//! - requests with no matching policy carry no rate headers;
//! - every attachment level applies (#123): a policy attached at the
//!   consumer, route, service, listener, or gateway (global) level
//!   demonstrably limits, with the frozen resolution order
//!   consumer > route > service > listener > global binding the 429
//!   headers when several levels deny at once (all levels AND together;
//!   a policy attached at SEVERAL levels is evaluated once — its
//!   budget spent once per request, the most specific position the one
//!   that binds);
//! - UNROUTED traffic (no route) is limited by the listener and global
//!   links before its 404 is answered (the closed DW-017 gap), while
//!   the reserved paths stay exempt.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use bytes::Bytes;
use dwara_core::config::parse_gateway;
use dwara_core::observability::ListenerLabel;
use dwara_core::proxy::DataPlane;
use dwara_core::snapshot::ConfigState;
use http_body_util::{BodyExt, Full};
use hyper::header::{HeaderMap, RETRY_AFTER};
use hyper::{Request, StatusCode};

mod support;

use support::{dataplane_from, envelope_code};

fn req(path: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .uri(path)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// A request carrying the listener label the real listener frontend
/// (dwara-bin listeners.rs) inserts — how a test names the accepting
/// listener for listener-level policy resolution (#123).
fn req_labeled(listener: &str, path: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .uri(path)
        .extension(ListenerLabel(std::sync::Arc::from(listener)))
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

// ---- #123: every attachment level applies; unrouted traffic is limited ----

async fn send_request(
    dp: &DataPlane,
    peer: IpAddr,
    request: Request<Full<Bytes>>,
) -> hyper::Response<dwara_core::proxy::ProxyBody> {
    dwara_core::proxy::handle(dp, peer, request).await
}

#[tokio::test]
async fn global_policy_limits_routed_traffic_without_lower_attachments() {
    // `gateway.global_policies` is the least specific link: it applies to
    // a route that attaches nothing itself.
    let yaml = "
policies:
  - name: global-per-ip
    rate_limits:
      - selector: [ip]
        requests_per: { minute: 3 }
global_policies: [global-per-ip]
routes:
  - name: r
    service: svc
    match: { path: { type: prefix, value: /r } }
    action: { type: respond, status: 200, body: ok }
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";
    let dp = dataplane_from(yaml);
    for expected_remaining in [2, 1, 0] {
        let (status, headers, _) = status_body(send(&dp, ip(1), "/r").await).await;
        assert_eq!(status, StatusCode::OK);
        let (limit, remaining, _) = rate_headers(&headers).expect("global policy reports headers");
        assert_eq!(limit, 3);
        assert_eq!(remaining, expected_remaining);
    }
    let (status, headers, _) = status_body(send(&dp, ip(1), "/r").await).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(rate_headers(&headers).unwrap().0, 3);
}

#[tokio::test]
async fn global_policy_limits_unrouted_traffic_before_the_404() {
    // The closed DW-017 gap: requests to a path no route matches are
    // rate-limited by the global link BEFORE the 404 is answered. A
    // denied unrouted request is a 429 (Retry-After + rate headers +
    // the error envelope), an admitted one is the plain 404.
    let yaml = "
policies:
  - name: global-per-ip
    rate_limits:
      - selector: [ip]
        requests_per: { minute: 2 }
global_policies: [global-per-ip]
routes:
  - name: r
    service: svc
    match: { path: { type: prefix, value: /r } }
    action: { type: respond, status: 200, body: ok }
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";
    let dp = dataplane_from(yaml);
    for _ in 0..2 {
        let (status, _, _) = status_body(send(&dp, ip(2), "/no-such-path").await).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    let (status, headers, body) = status_body(send(&dp, ip(2), "/no-such-path").await).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the unrouted 404 flood is throttled by the global policy"
    );
    assert_eq!(envelope_code(body.as_bytes()), "rate_limit_exceeded");
    assert!(headers.get(RETRY_AFTER).is_some());
    assert_eq!(rate_headers(&headers).unwrap().0, 2);
    // A different peer has an independent bucket (selector [ip]).
    let (status, _, _) = status_body(send(&dp, ip(3), "/no-such-path").await).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn reserved_paths_stay_exempt_from_global_policies() {
    let yaml = "
policies:
  - name: global-per-ip
    rate_limits:
      - selector: [ip]
        requests_per: { s: 1 }
global_policies: [global-per-ip]
routes:
  - name: r
    service: svc
    match: { path: { type: prefix, value: /r } }
    action: { type: respond, status: 200, body: ok }
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";
    let dp = dataplane_from(yaml);
    // Far beyond the s:1 budget, all reserved paths still answer.
    for _ in 0..6 {
        assert_eq!(
            status_body(send(&dp, ip(4), "/healthz").await).await.0,
            StatusCode::OK
        );
        assert_eq!(
            status_body(send(&dp, ip(4), "/readyz").await).await.0,
            StatusCode::OK
        );
        assert_eq!(
            status_body(send(&dp, ip(4), "/metrics").await).await.0,
            StatusCode::OK
        );
    }
    // While ordinary unrouted traffic on the same peer is throttled:
    // the s:1 burst admits the first request, the second 429s.
    assert_eq!(
        status_body(send(&dp, ip(4), "/nothing").await).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status_body(send(&dp, ip(4), "/nothing").await).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn listener_policy_applies_to_the_labeled_listener_only() {
    // `listeners[].policies` resolves by the listener label the real
    // frontend inserts: requests on "edge" are limited, requests with
    // no (or a non-matching) label attach nothing.
    let yaml = "
policies:
  - name: edge-per-ip
    rate_limits:
      - selector: [ip]
        requests_per: { minute: 3 }
listeners:
  - name: edge
    address: 127.0.0.1
    port: 18080
    policies: [edge-per-ip]
routes:
  - name: r
    service: svc
    match: { path: { type: prefix, value: /r } }
    action: { type: respond, status: 200, body: ok }
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";
    let dp = dataplane_from(yaml);
    for _ in 0..3 {
        let (status, headers, _) =
            status_body(send_request(&dp, ip(5), req_labeled("edge", "/r")).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(rate_headers(&headers).unwrap().0, 3);
    }
    let (status, headers, _) =
        status_body(send_request(&dp, ip(5), req_labeled("edge", "/r")).await).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(rate_headers(&headers).unwrap().0, 3);
    // No label (handle driven directly): the listener link is
    // transparent, so the same peer is unbounded and headerless.
    for _ in 0..5 {
        let (status, headers, _) = status_body(send(&dp, ip(5), "/r").await).await;
        assert_eq!(status, StatusCode::OK);
        assert!(rate_headers(&headers).is_none());
    }
    // A label naming no configured listener attaches nothing either.
    let (status, headers, _) =
        status_body(send_request(&dp, ip(5), req_labeled("ghost", "/r")).await).await;
    assert_eq!(status, StatusCode::OK);
    assert!(rate_headers(&headers).is_none());
}

#[tokio::test]
async fn listener_policy_limits_unrouted_traffic() {
    let yaml = "
policies:
  - name: edge-per-ip
    rate_limits:
      - selector: [ip]
        requests_per: { minute: 2 }
listeners:
  - name: edge
    address: 127.0.0.1
    port: 18081
    policies: [edge-per-ip]
routes:
  - name: r
    service: svc
    match: { path: { type: prefix, value: /r } }
    action: { type: respond, status: 200, body: ok }
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";
    let dp = dataplane_from(yaml);
    for _ in 0..2 {
        let (status, _, _) =
            status_body(send_request(&dp, ip(6), req_labeled("edge", "/nothing")).await).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    let (status, _, _) =
        status_body(send_request(&dp, ip(6), req_labeled("edge", "/nothing")).await).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "unrouted traffic on the labeled listener is throttled"
    );
    // The same path without the label: no listener link, plain 404.
    let (status, _, _) = status_body(send(&dp, ip(6), "/nothing").await).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn consumer_policy_applies_and_binds_headers_over_route_policy() {
    // Precedence for the 429 HEADERS: all levels AND together, but the
    // FIRST denying rule in resolution order (consumer > route >
    // service > listener > global) binds Limit/Remaining. The consumer
    // rule (s:2) denies before the route rule (minute:5) is consulted
    // for headers, so Limit reports 2, not 5.
    let yaml = "
policies:
  - name: fast-consumer
    rate_limits:
      - selector: [credential]
        requests_per: { s: 2 }
  - name: slow-route
    rate_limits:
      - selector: [credential]
        requests_per: { minute: 5 }
consumers:
  - name: acme
    credentials:
      - type: api_key
        key: acme-key
    policies: [fast-consumer]
routes:
  - name: r
    service: svc
    match: { path: { type: prefix, value: /r } }
    action: { type: respond, status: 200, body: ok }
    policies: [slow-route]
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";
    let dp = dataplane_from(yaml);
    // The consumer link only exists once authn identifies the consumer:
    // every request presents acme's API key.
    async fn as_acme(dp: &DataPlane) -> hyper::Response<dwara_core::proxy::ProxyBody> {
        let req = Request::builder()
            .uri("/r")
            .header("x-api-key", "acme-key")
            .body(Full::new(Bytes::new()))
            .unwrap();
        dwara_core::proxy::handle(dp, ip(7), req).await
    }
    for _ in 0..2 {
        let (status, headers, _) = status_body(as_acme(&dp).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(rate_headers(&headers).unwrap().0, 2);
    }
    let (status, headers, _) = status_body(as_acme(&dp).await).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        rate_headers(&headers).unwrap().0,
        2,
        "the consumer-level rule binds the 429 headers over the route rule (5)"
    );
}

#[tokio::test]
async fn route_policy_binds_headers_over_global_policy() {
    // The same header precedence one link down: route (s:2) binds over
    // the global rule (minute:5) when both apply.
    let yaml = "
policies:
  - name: fast-route
    rate_limits:
      - selector: [ip]
        requests_per: { s: 2 }
  - name: slow-global
    rate_limits:
      - selector: [ip]
        requests_per: { minute: 5 }
global_policies: [slow-global]
routes:
  - name: r
    service: svc
    match: { path: { type: prefix, value: /r } }
    action: { type: respond, status: 200, body: ok }
    policies: [fast-route]
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";
    let dp = dataplane_from(yaml);
    for _ in 0..2 {
        let (status, headers, _) = status_body(send(&dp, ip(8), "/r").await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(rate_headers(&headers).unwrap().0, 2);
    }
    let (status, headers, _) = status_body(send(&dp, ip(8), "/r").await).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        rate_headers(&headers).unwrap().0,
        2,
        "the route-level rule binds the 429 headers over the global rule (5)"
    );
}

/// Config for the precedence-pair test: a `fast` policy (minute: 2) at
/// `fast_level` and a `slow` policy (minute: 5) at `slow_level`, one of
/// each of "consumer", "route", "service", "listener", "global". Every
/// other level attaches nothing. A consumer with credentials exists so
/// the consumer link CAN attach (its resolution requires authn), and
/// every request of the pair tests presents the key plus the "edge"
/// listener label, so all five links are live in every case.
fn precedence_pair_yaml(fast_level: &str, slow_level: &str) -> String {
    let attach = |level: &str| -> String {
        let mut names: Vec<&str> = Vec::new();
        if level == fast_level {
            names.push("fast");
        }
        if level == slow_level {
            names.push("slow");
        }
        if names.is_empty() {
            "[]".to_string()
        } else {
            format!("[{}]", names.join(", "))
        }
    };
    format!(
        "policies:
  - name: fast
    rate_limits:
      - selector: [ip]
        requests_per: {{ minute: 2 }}
  - name: slow
    rate_limits:
      - selector: [ip]
        requests_per: {{ minute: 5 }}
consumers:
  - name: acme
    credentials:
      - type: api_key
        key: acme-key
    policies: {consumer}
listeners:
  - name: edge
    address: 127.0.0.1
    port: 18082
    policies: {listener}
global_policies: {global}
routes:
  - name: r
    service: svc
    match: {{ path: {{ type: prefix, value: /r }} }}
    action: {{ type: respond, status: 200, body: ok }}
    policies: {route}
services:
  - name: svc
    upstream: up
    policies: {service}
upstreams:
  - name: up
    endpoints: [{{ address: 127.0.0.1, port: 1 }}]
",
        consumer = attach("consumer"),
        route = attach("route"),
        service = attach("service"),
        listener = attach("listener"),
        global = attach("global"),
    )
}

#[tokio::test]
async fn resolution_order_binds_429_headers_when_two_levels_deny_at_once() {
    // The strong form of the header-precedence pin: at the SIXTH request
    // of one peer BOTH rules deny simultaneously (fast exhausted since
    // request 3; slow — minute: 5 — spent its budget on the admissions
    // of requests 1-5), so X-RateLimit-Limit can only come from the
    // rule the engine consults FIRST. Every adjacent pair of the frozen
    // chain plus the consumer-vs-service skip pair reports the MORE
    // specific level's limit (2), not the less specific one's (5).
    // Minute windows throughout: no refill can race the test.
    let cases: &[(&str, &str)] = &[
        ("consumer", "route"),
        ("consumer", "service"),
        ("route", "service"),
        ("service", "listener"),
        ("listener", "global"),
    ];
    for (fast_level, slow_level) in cases {
        let dp = dataplane_from(&precedence_pair_yaml(fast_level, slow_level));
        let peer = ip(9);
        for i in 0..6u32 {
            let req = Request::builder()
                .uri("/r")
                .header("x-api-key", "acme-key")
                .extension(ListenerLabel(std::sync::Arc::from("edge")))
                .body(Full::new(Bytes::new()))
                .unwrap();
            let (status, headers, _) =
                status_body(dwara_core::proxy::handle(&dp, peer, req).await).await;
            let expected = if i < 2 {
                StatusCode::OK
            } else {
                StatusCode::TOO_MANY_REQUESTS
            };
            assert_eq!(
                status,
                expected,
                "case {fast_level}>{slow_level}, request {}: fast is minute:2",
                i + 1
            );
            if i == 5 {
                assert_eq!(
                    rate_headers(&headers).unwrap().0,
                    2,
                    "case {fast_level}>{slow_level}: both rules deny at once, so the \
                     more specific level ({fast_level}, limit 2) must bind the 429 \
                     headers over {slow_level} (limit 5)"
                );
            }
        }
    }
}

#[tokio::test]
async fn same_policy_at_two_levels_consumes_its_budget_once() {
    // The dedup pin: ONE policy attached at BOTH the listener and the
    // global link is ONE evaluation per request, not one per link. The
    // pre-dedup engine resolved the shared name at every attaching
    // level, so a minute:3 policy throttled at request 2 (each
    // admission spent the budget twice). Now the full burst of 3 is
    // admitted with Remaining stepping 2 -> 1 -> 0 — under double
    // consumption request 1 would already report 1 — and only the
    // FOURTH request 429s. With a single shared rule the header VALUES
    // are level-independent by construction, so WHICH occurrence binds
    // the headers is only observable with distinct policies (pinned by
    // the precedence matrix above); what this test pins is the single
    // consumption, on the routed path (all five links resolve, the
    // chain holds the name twice) and on the unrouted one (listener +
    // global only, the pre-404 limiter).
    let yaml = "
policies:
  - name: shared
    rate_limits:
      - selector: [ip]
        requests_per: { minute: 3 }
listeners:
  - name: edge
    address: 127.0.0.1
    port: 18086
    policies: [shared]
global_policies: [shared]
routes:
  - name: r
    service: svc
    match: { path: { type: prefix, value: /r } }
    action: { type: respond, status: 200, body: ok }
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";
    let dp = dataplane_from(yaml);
    // Routed traffic on the labeled listener: consumer/route/service
    // attach nothing, so the chain is [listener: shared, global:
    // shared] and the name appears twice.
    for expected_remaining in [2, 1, 0] {
        let (status, headers, _) =
            status_body(send_request(&dp, ip(18), req_labeled("edge", "/r")).await).await;
        assert_eq!(status, StatusCode::OK);
        let (limit, remaining, _) = rate_headers(&headers).expect("rate headers on success");
        assert_eq!(limit, 3);
        assert_eq!(
            remaining, expected_remaining,
            "the shared policy spends its budget once per request"
        );
    }
    let (status, headers, _) =
        status_body(send_request(&dp, ip(18), req_labeled("edge", "/r")).await).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "minute:3 denies the FOURTH request, not the second"
    );
    let (limit, remaining, _) = rate_headers(&headers).expect("rate headers on 429");
    assert_eq!(limit, 3);
    assert_eq!(remaining, 0);
    assert!(headers.get(RETRY_AFTER).is_some());
    // Unrouted traffic (fresh peer: independent [ip] budget): only the
    // listener and global links resolve — both attach the same policy —
    // and the pre-404 limiter spends the budget once (the bug 429'd
    // the SECOND unrouted request).
    for _ in 0..3 {
        let (status, headers, _) =
            status_body(send_request(&dp, ip(19), req_labeled("edge", "/nothing")).await).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(rate_headers(&headers).unwrap().0, 3);
    }
    let (status, _, _) =
        status_body(send_request(&dp, ip(19), req_labeled("edge", "/nothing")).await).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn listener_binds_429_headers_over_global_on_unrouted_traffic() {
    // The unrouted counterpart of the header-precedence pin: listener
    // (minute: 2) AND global (minute: 5) policies both apply to unrouted
    // traffic on the labeled listener; at the sixth unrouted request both
    // deny at once and the LISTENER rule — earlier in the frozen chain —
    // must bind the 429 headers (Limit 2, not 5). The unrouted 429 also
    // carries the JSON error envelope, exactly like a routed one.
    let yaml = "
policies:
  - name: fast-edge
    rate_limits:
      - selector: [ip]
        requests_per: { minute: 2 }
  - name: slow-global
    rate_limits:
      - selector: [ip]
        requests_per: { minute: 5 }
listeners:
  - name: edge
    address: 127.0.0.1
    port: 18083
    policies: [fast-edge]
global_policies: [slow-global]
routes:
  - name: r
    service: svc
    match: { path: { type: prefix, value: /r } }
    action: { type: respond, status: 200, body: ok }
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";
    let dp = dataplane_from(yaml);
    for i in 0..6u32 {
        let (status, headers, body) =
            status_body(send_request(&dp, ip(11), req_labeled("edge", "/nothing")).await).await;
        let expected = if i < 2 {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::TOO_MANY_REQUESTS
        };
        assert_eq!(status, expected, "unrouted request {}", i + 1);
        if i == 5 {
            assert_eq!(
                rate_headers(&headers).unwrap().0,
                2,
                "both links deny at once; the listener rule binds the unrouted 429 \
                 headers over the global rule (5)"
            );
            assert_eq!(envelope_code(body.as_bytes()), "rate_limit_exceeded");
            assert!(headers.get(RETRY_AFTER).is_some());
        }
    }
    // A different peer has independent [ip] budgets at BOTH links: its
    // first unrouted request is a plain admitted 404, not a 429.
    let (status, headers, _) =
        status_body(send_request(&dp, ip(15), req_labeled("edge", "/nothing")).await).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        rate_headers(&headers).unwrap().0,
        2,
        "the admitted unrouted 404 still reports the applied policy's headers"
    );
}

#[tokio::test]
async fn reserved_paths_stay_exempt_on_a_listener_with_policies() {
    // Listener-level mirror of the global exemption test: the reserved
    // paths never reach the limiter even on a listener carrying
    // policies — far beyond the minute:2 budget they all answer 200
    // WITHOUT rate headers, while ordinary unrouted traffic on the same
    // peer and listener is throttled.
    let yaml = "
policies:
  - name: edge-per-ip
    rate_limits:
      - selector: [ip]
        requests_per: { minute: 2 }
listeners:
  - name: edge
    address: 127.0.0.1
    port: 18084
    policies: [edge-per-ip]
routes:
  - name: r
    service: svc
    match: { path: { type: prefix, value: /r } }
    action: { type: respond, status: 200, body: ok }
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";
    let dp = dataplane_from(yaml);
    for _ in 0..3 {
        for path in ["/healthz", "/readyz", "/metrics"] {
            let (status, headers, _) =
                status_body(send_request(&dp, ip(16), req_labeled("edge", path)).await).await;
            assert_eq!(status, StatusCode::OK, "{path} stays exempt");
            assert!(
                rate_headers(&headers).is_none(),
                "{path} never reaches the limiter, so it carries no rate headers"
            );
        }
    }
    let (status, _, _) =
        status_body(send_request(&dp, ip(16), req_labeled("edge", "/nothing")).await).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) =
        status_body(send_request(&dp, ip(16), req_labeled("edge", "/nothing")).await).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) =
        status_body(send_request(&dp, ip(16), req_labeled("edge", "/nothing")).await).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "ordinary unrouted traffic on the same peer exhausts the minute:2 budget"
    );
}

#[tokio::test]
async fn unrouted_route_selector_keys_one_shared_bucket_across_peers() {
    // Which key does an unrouted request get? The [ip] selector keys per
    // peer (pinned above); the [route] selector keys the EMPTY route
    // component on unrouted traffic (documented), i.e. ONE bucket shared
    // by every unrouted request of the policy: peer A's single admitted
    // unrouted request spends the minute:1 budget and a DIFFERENT peer's
    // unrouted request 429s — the shared-bucket shape an operator must
    // know about before attaching a [route]-keyed policy globally.
    let yaml = "
policies:
  - name: per-route
    rate_limits:
      - selector: [route]
        requests_per: { minute: 1 }
global_policies: [per-route]
routes:
  - name: r
    service: svc
    match: { path: { type: prefix, value: /r } }
    action: { type: respond, status: 200, body: ok }
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";
    let dp = dataplane_from(yaml);
    let (status, headers, _) = status_body(send(&dp, ip(13), "/a-not-found").await).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        rate_headers(&headers).is_some(),
        "the applied policy reports its headers on the admitted 404"
    );
    let (status, _, _) = status_body(send(&dp, ip(14), "/b-not-found").await).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "a different peer shares the same unrouted bucket: the [route] key has no \
         per-peer component before routing (the empty-string route)"
    );
}

#[tokio::test]
async fn reload_attaches_global_and_listener_policies_without_restart() {
    // Hot reload of the NEW attachment fields: a policy that exists but
    // is attached nowhere limits nothing; one compile_and_publish plus
    // the dataplane refresh (what the reload watcher and the admin API
    // both drive) attaches it at the global AND listener levels and both
    // links go live on the next request — routed traffic gains the
    // global link, unrouted traffic gains both.
    let v1 = "
policies:
  - name: per-ip-2
    rate_limits:
      - selector: [ip]
        requests_per: { minute: 2 }
listeners:
  - name: edge
    address: 127.0.0.1
    port: 18085
routes:
  - name: r
    service: svc
    match: { path: { type: prefix, value: /r } }
    action: { type: respond, status: 200, body: ok }
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";
    let state = Arc::new(ConfigState::new());
    state
        .compile_and_publish(&parse_gateway(v1).unwrap())
        .unwrap();
    let dp = DataPlane::new(Arc::clone(&state));
    for _ in 0..5 {
        let (status, headers, _) = status_body(send(&dp, ip(12), "/r").await).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            rate_headers(&headers).is_none(),
            "attached nowhere: no limit"
        );
        let (status, headers, _) =
            status_body(send_request(&dp, ip(12), req_labeled("edge", "/nothing")).await).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(rate_headers(&headers).is_none());
    }
    // The reload: same entities, DISTINCT policies now attached at the
    // two new levels — one per link keeps each link's attachment
    // independently observable across the reload (the same policy at
    // both levels would now correctly evaluate once per request; see
    // `same_policy_at_two_levels_consumes_its_budget_once`). The engine
    // is rebuilt per generation (buckets reset).
    let v2 = "
policies:
  - name: global-per-ip
    rate_limits:
      - selector: [ip]
        requests_per: { minute: 2 }
  - name: edge-per-ip
    rate_limits:
      - selector: [ip]
        requests_per: { minute: 2 }
global_policies: [global-per-ip]
listeners:
  - name: edge
    address: 127.0.0.1
    port: 18085
    policies: [edge-per-ip]
routes:
  - name: r
    service: svc
    match: { path: { type: prefix, value: /r } }
    action: { type: respond, status: 200, body: ok }
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";
    state
        .compile_and_publish(&parse_gateway(v2).unwrap())
        .unwrap();
    dp.refresh();
    // Routed traffic: the global link now limits (minute: 2).
    for _ in 0..2 {
        let (status, headers, _) = status_body(send(&dp, ip(12), "/r").await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(rate_headers(&headers).unwrap().0, 2);
    }
    let (status, headers, _) = status_body(send(&dp, ip(12), "/r").await).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(rate_headers(&headers).unwrap().0, 2);
    // Unrouted traffic on the labeled listener: the listener link now
    // limits BEFORE the 404 (fresh peer: independent [ip] budget).
    for _ in 0..2 {
        let (status, _, _) =
            status_body(send_request(&dp, ip(17), req_labeled("edge", "/nothing")).await).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    let (status, _, _) =
        status_body(send_request(&dp, ip(17), req_labeled("edge", "/nothing")).await).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}
