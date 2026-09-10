//! Integration tests for the `dwara explain` CLI library half (USA-09, #231).

use dwara_cli::explain::{run_explain, ExplainRequest};

const BASE_CONFIG: &str = "\
listeners: []
routes:
  - name: api
    service: svc
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy }
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 8080
";

#[test]
fn explain_matched_route() {
    let request = ExplainRequest::get("/api/foo");
    let report = run_explain(BASE_CONFIG, &request).expect("explain runs");
    assert!(report.text.contains("Matched route: api"));
    assert!(report.text.contains("Action: proxy"));
    assert!(report.text.contains("Upstream: pool"));
}

#[test]
fn explain_no_route_matched() {
    let request = ExplainRequest::get("/nonexistent");
    let report = run_explain(BASE_CONFIG, &request).expect("explain runs");
    assert!(report.text.contains("No route matched"));
}

#[test]
fn explain_shows_authorization_allow() {
    let request = ExplainRequest::get("/api/foo");
    let report = run_explain(BASE_CONFIG, &request).expect("explain runs");
    assert!(report.text.contains("Authorization"));
    assert!(report.text.contains("ALLOW"));
}

#[test]
fn explain_shows_authorization_deny() {
    let config = "\
listeners: []
routes:
  - name: api
    service: svc
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy }
    authorization:
      ip_acl:
        default: deny
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 8080
";
    let request = ExplainRequest::get("/api/foo");
    let report = run_explain(config, &request).expect("explain runs");
    assert!(report.text.contains("DENY"));
}

#[test]
fn explain_shows_caching_when_configured() {
    let config = "\
listeners: []
routes:
  - name: api
    service: svc
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy }
    cache:
      ttl_secs: 60
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 8080
";
    let request = ExplainRequest::get("/api/foo");
    let report = run_explain(config, &request).expect("explain runs");
    assert!(report.text.contains("Caching: enabled"));
    assert!(report.text.contains("TTL: 60s"));
}

#[test]
fn explain_shows_no_caching_when_not_configured() {
    let request = ExplainRequest::get("/api/foo");
    let report = run_explain(BASE_CONFIG, &request).expect("explain runs");
    assert!(report.text.contains("Caching: not configured"));
}

#[test]
fn explain_with_consumer_identity() {
    let config = "\
listeners: []
routes:
  - name: api
    service: svc
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy }
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 8080
consumers:
  - name: alice
";
    let request = ExplainRequest {
        auth_identity: Some("alice".to_string()),
        ..ExplainRequest::get("/api/foo")
    };
    let report = run_explain(config, &request).expect("explain runs");
    assert!(report.text.contains("Consumer: alice"));
}

#[test]
fn explain_with_headers() {
    let request = ExplainRequest {
        headers: vec![("X-Plan".to_string(), "pro".to_string())],
        ..ExplainRequest::get("/api/foo")
    };
    let report = run_explain(BASE_CONFIG, &request).expect("explain runs");
    assert!(report.text.contains("X-Plan: pro"));
}
