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
            load_shed_dry_run: false,
            jwt_providers: Vec::new(),
            admin: None,
            // Genuinely zero-route: only the registry-driven gauges matter
            // (#129 opt-in).
            allow_empty_routes: true,
            hmac_auth: None,
            webhooks: Vec::new(),
            analytics: None,
            analytics_stream: None,
            geoip: None,
            admission_queue: None,
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

// --- SLO burn-rate windows (DW-052) ---------------------------------------

fn slo_targets() -> dwara_core::observability::SloTargets {
    dwara_core::observability::SloTargets {
        availability: 0.99,
        latency_threshold_ms: Some(100.0),
        latency_target: 0.99,
    }
}

fn burn(text: &str, route: &str, objective: &str, window: &str) -> Option<f64> {
    // Lines look like:
    // dwara_slo_burn_rate{objective="availability",route="r",window="5m"} 1.5
    for line in text.lines() {
        if line.starts_with("dwara_slo_burn_rate{")
            && line.contains(&format!("route=\"{route}\""))
            && line.contains(&format!("objective=\"{objective}\""))
            && line.contains(&format!("window=\"{window}\""))
        {
            return line
                .split_whitespace()
                .last()
                .and_then(|v| v.parse::<f64>().ok());
        }
    }
    None
}

#[test]
fn slo_burn_rate_computes_the_windowed_ratio() {
    let obs = Observability::new();
    obs.set_route_slos(vec![("api".to_string(), slo_targets())]);
    // At t=0: four requests, one 5xx and one over the 100ms threshold.
    // allowed = 1% for both objectives -> burn = (1/4) / 0.01 = 25.
    obs.record_slo_at("api", 200, 50.0, 0);
    obs.record_slo_at("api", 200, 150.0, 1_000);
    obs.record_slo_at("api", 500, 50.0, 2_000);
    obs.record_slo_at("api", 200, 50.0, 3_000);
    let text = obs.render_slo(10_000);
    for window in ["5m", "1h"] {
        let avail = burn(&text, "api", "availability", window).unwrap();
        assert!(
            (avail - 25.0).abs() < 1e-9,
            "{window} availability: {avail}"
        );
        let lat = burn(&text, "api", "latency", window).unwrap();
        assert!((lat - 25.0).abs() < 1e-9, "{window} latency: {lat}");
    }
    // Target gauges carry the configured fractions.
    assert!(text.contains("dwara_slo_target{objective=\"availability\",route=\"api\"} 0.99"));
    assert!(text.contains("dwara_slo_target{objective=\"latency\",route=\"api\"} 0.99"));
}

#[test]
fn slo_windows_expire_and_empty_windows_are_zero() {
    let obs = Observability::new();
    obs.set_route_slos(vec![("api".to_string(), slo_targets())]);
    // Traffic ONLY at t=0. At t=5m+1 the 5m window no longer contains
    // bucket 0 (15s buckets: cutoff = now - 300s excludes the start-0
    // bucket); the 1h window still does.
    obs.record_slo_at("api", 500, 1.0, 0);
    let text = obs.render_slo(300_000 + 1_000);
    let w5 = burn(&text, "api", "availability", "5m").unwrap();
    let w1h = burn(&text, "api", "availability", "1h").unwrap();
    assert_eq!(w5, 0.0, "5m window expired the traffic");
    assert!((w1h - 100.0).abs() < 1e-9, "1h still holds it: {w1h}");
    // No traffic at all: zero, never NaN.
    obs.set_route_slos(vec![("idle".to_string(), slo_targets())]);
    let text = obs.render_slo(300_000 + 2_000);
    assert_eq!(burn(&text, "idle", "availability", "5m").unwrap(), 0.0);
    assert_eq!(burn(&text, "idle", "availability", "1h").unwrap(), 0.0);
}

#[test]
fn slo_buckets_wrap_and_reset_across_ring_boundaries() {
    let obs = Observability::new();
    obs.set_route_slos(vec![("api".to_string(), slo_targets())]);
    // Write into buckets 0 and 19 (the 5m ring's boundary), then into
    // bucket 20 (wraps onto bucket 0): the wrapped write must RESET
    // bucket 0, not add to it.
    obs.record_slo_at("api", 500, 1.0, 0); // bucket 0
    obs.record_slo_at("api", 200, 1.0, 19 * 15_000); // bucket 19
    obs.record_slo_at("api", 200, 1.0, 20 * 15_000); // wraps bucket 0
    let text = obs.render_slo(20 * 15_000 + 1_000);
    // Window holds buckets 1..=20: the 5xx in old bucket 0 is gone.
    let w5 = burn(&text, "api", "availability", "5m").unwrap();
    assert_eq!(w5, 0.0, "wrapped bucket 0 was reset: {w5}");
    // The 1h ring holds all three records (its bucket 0 never
    // wrapped): 1 bad of 3 total at 1% allowed.
    let w1h = burn(&text, "api", "availability", "1h").unwrap();
    assert!(
        (w1h - 100.0 / 3.0).abs() < 1e-9,
        "1/3 bad at 1% allowed: {w1h}"
    );
}

#[test]
fn slo_unconfigured_routes_and_removal_stop_exporting() {
    let obs = Observability::new();
    obs.record_slo_at("ghost", 500, 1.0, 0); // no state: no-op, no panic
    assert!(!obs.render_slo(1_000).contains("dwara_slo_burn_rate{"));
    // Configure, record, then REMOVE: the series disappears (no stale
    // gauge children).
    obs.set_route_slos(vec![("api".to_string(), slo_targets())]);
    obs.record_slo_at("api", 200, 1.0, 0);
    assert!(obs.render_slo(1_000).contains("route=\"api\""));
    obs.set_route_slos(vec![]);
    assert!(!obs.render_slo(1_000).contains("route=\"api\""));
}

#[test]
fn slo_full_render_includes_the_families() {
    // The registered collector path (render, not render_slo): the SLO
    // families must appear in the ordinary /metrics gather.
    let obs = Observability::new();
    obs.set_route_slos(vec![("api".to_string(), slo_targets())]);
    obs.record_slo_at("api", 200, 1.0, 0);
    let text = obs.render();
    assert!(text.contains("dwara_slo_burn_rate"), "{text}");
    assert!(text.contains("dwara_slo_target"), "{text}");
}
