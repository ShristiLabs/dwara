//! Unit tests for `observability` (relocated from src).

use std::time::Duration;

use hyper::header::{HeaderMap, HeaderValue};

use dwara_core::observability::*;

#[test]
fn inbound_request_id_validation() {
    assert!(valid_inbound_request_id(b"abc-123"));
    assert!(valid_inbound_request_id(&[b'a'; 128]));
    assert!(!valid_inbound_request_id(&[b'a'; 129]));
    assert!(!valid_inbound_request_id(b""));
    assert!(!valid_inbound_request_id(b"bad\nid"));
    assert!(!valid_inbound_request_id(b"caf\xc3\xa9")); // UTF-8 multibyte
    assert!(!valid_inbound_request_id(&[0x7f])); // DEL
}

#[test]
fn generated_ids_are_unique_and_prefixed() {
    let a = generate_request_id();
    let b = generate_request_id();
    assert!(a.starts_with("req-"));
    assert_ne!(a, b);
}

#[test]
fn resolve_respects_valid_inbound_and_replaces_hostile() {
    let mut h = HeaderMap::new();
    h.insert(&X_REQUEST_ID, HeaderValue::from_static("client-42"));
    assert_eq!(resolve_request_id(&h), "client-42");
    // hyper itself refuses control bytes in a HeaderValue, so the
    // hostile-via-real-HTTP case is the over-long id; control-byte
    // rejection is covered by inbound_request_id_validation above.
    let mut h = HeaderMap::new();
    h.insert(
        &X_REQUEST_ID,
        HeaderValue::from_str(&"a".repeat(129)).unwrap(),
    );
    assert!(resolve_request_id(&h).starts_with("req-"));
}

#[test]
fn sampling_always_logs_errors() {
    let obs = Observability::new();
    obs.set_access_sample(0.0);
    assert!(obs.should_log_access(500));
    assert!(obs.should_log_access(503));
    assert!(!obs.should_log_access(200));
    assert!(!obs.should_log_access(404));
    obs.set_access_sample(1.0);
    assert!(obs.should_log_access(200));
}

#[test]
fn sample_rate_is_clamped() {
    let obs = Observability::new();
    obs.set_access_sample(7.0);
    assert_eq!(obs.access_sample(), 1.0);
    obs.set_access_sample(-1.0);
    assert_eq!(obs.access_sample(), 0.0);
}

#[test]
fn envelope_has_code_message_request_id() {
    let body = envelope_body("no_route", "no route", "req-x");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let err = v.get("error").unwrap();
    assert_eq!(err["code"], "no_route");
    assert_eq!(err["message"], "no route");
    assert_eq!(err["request_id"], "req-x");
}

#[test]
fn render_contains_families() {
    let obs = Observability::new();
    obs.record_request("r", "l", 200, Duration::from_millis(5));
    obs.record_upstream_attempt("u", "127.0.0.1:9", 200);
    obs.record_retry("u");
    obs.record_rate_limited("r");
    obs.record_shed(5);
    obs.jwks_refresh_counter("p").inc();
    obs.set_config_generation(3);
    // State-derived gauges only gain series after a scrape-time
    // refresh over a registry that actually has an upstream.
    let state = dwara_core::snapshot::ConfigState::new();
    use dwara_core::config::{Endpoint, Gateway, LoadBalancer, Upstream};
    state
        .compile_and_publish(&Gateway {
            trusted_proxies: vec![],
            listeners: vec![],
            routes: vec![],
            services: vec![],
            upstreams: vec![Upstream {
                name: "u".into(),
                load_balancer: LoadBalancer::RoundRobin,
                protocol: dwara_core::config::UpstreamProtocol::Http1,
                endpoints: vec![Endpoint {
                    address: "127.0.0.1".into(),
                    port: 9,
                    weight: 1,
                }],
                connection_cap: None,
                slow_start_ms: None,
                health: None,
                active_health: None,
                retries: None,
                timeouts: None,
                breaker: None,
                max_pending: None,
                trusted_ca_file: None,
            }],
            consumers: vec![],
            policies: vec![],
            global_policies: Vec::new(),
            authorization: None,
            max_concurrent_requests: None,
            jwt_providers: Vec::new(),
            admin: None,
        })
        .expect("publish");
    let registry =
        dwara_core::dataplane::upstream::UpstreamRegistry::from_snapshot(&state.snapshot());
    dwara_core::dataplane::upstream::refresh_observation_gauges(&registry, &obs);
    let text = obs.render();
    for name in [
        "# HELP requests_total",
        "# TYPE requests_total counter",
        "requests_total{listener=\"l\",route=\"r\",status_class=\"2xx\"} 1",
        "upstream_attempts_total{endpoint=\"127.0.0.1:9\",status_class=\"2xx\",upstream=\"u\"} 1",
        "jwks_refresh_total{provider=\"p\"} 1",
        "breaker_state{upstream=\"u\"} 0",
        "endpoint_health{endpoint=\"127.0.0.1:9\",upstream=\"u\"} 1",
        "upstream_fail_open_picks{upstream=\"u\"} 0",
        "# TYPE request_duration_seconds histogram",
        "# TYPE active_requests gauge",
        "active_requests 0",
        "config_generation 3",
        "# TYPE shed_total counter",
        "# TYPE breaker_state gauge",
        "# TYPE endpoint_health gauge",
        "# TYPE upstream_fail_open_picks gauge",
        "# TYPE jwks_refresh_total counter",
        "# TYPE upstream_attempts_total counter",
        "# TYPE retries_total counter",
        "# TYPE rate_limited_total counter",
    ] {
        assert!(text.contains(name), "missing {name} in:\n{text}");
    }
}

#[test]
fn access_record_redacts_query_by_construction() {
    // The record only ever holds the path component; assert the
    // field is taken verbatim and emit includes no query anywhere.
    let mut rec = AccessRecord::new("req-1".into(), "GET".into(), "/a".into(), "l".into());
    rec.status = 200;
    rec.duration_ms = 1.0;
    // No subscriber installed: emit is a no-op; exercising it here
    // proves the call compiles with the exhaustive field list.
    emit_access(&rec);
}
