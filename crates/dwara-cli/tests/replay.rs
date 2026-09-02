//! Integration tests for the `dwara replay` CLI library half (DW-102).
//!
//! These tests exercise [`dwara_cli::replay::run_replay`] and
//! [`dwara_cli::replay::replay_against`] through the public lib API,
//! verifying the end-to-end recording-parse -> compile -> decide -> diff
//! flow and the exit-code contract (0 = no diffs, 1 = diffs found,
//! error = operator error).

use dwara_cli::replay::{run_replay, ReplayReport};

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

fn recording_with(config: &str, requests: &str) -> String {
    format!(
        "{{\"baseline_config\":{},\"requests\":{requests}}}",
        serde_json::to_string(config).unwrap()
    )
}

#[test]
fn no_diffs_when_candidate_matches_baseline() {
    let recording = recording_with(
        BASE_CONFIG,
        "[{\"method\":\"GET\",\"path\":\"/api/foo\",\"timestamp_ms\":1700000000000}]",
    );
    let report = run_replay(&recording, BASE_CONFIG).expect("replay runs");
    assert_eq!(report.diff_count, 0);
    assert!(report.render().contains("no decision differences"));
}

#[test]
fn detects_authz_diff() {
    let new_config = "\
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
    let recording = recording_with(
        BASE_CONFIG,
        "[{\"method\":\"GET\",\"path\":\"/api/foo\",\"timestamp_ms\":1700000000000}]",
    );
    let report = run_replay(&recording, new_config).expect("replay runs");
    assert_eq!(report.diff_count, 1);
    assert!(report.render().contains("authz"));
}

#[test]
fn detects_route_rename_diff() {
    let new_config = "\
listeners: []
routes:
  - name: api-v2
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
    let recording = recording_with(
        BASE_CONFIG,
        "[{\"method\":\"GET\",\"path\":\"/api/foo\",\"timestamp_ms\":1700000000000}]",
    );
    let report = run_replay(&recording, new_config).expect("replay runs");
    assert_eq!(report.diff_count, 1);
    assert!(report.render().contains("route"));
}

#[test]
fn detects_upstream_change_diff() {
    let new_config = "\
listeners: []
routes:
  - name: api
    service: svc
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy }
services:
  - name: svc
    upstream: pool2
upstreams:
  - name: pool2
    endpoints:
      - address: 10.0.0.1
        port: 9090
";
    let recording = recording_with(
        BASE_CONFIG,
        "[{\"method\":\"GET\",\"path\":\"/api/foo\",\"timestamp_ms\":1700000000000}]",
    );
    let report = run_replay(&recording, new_config).expect("replay runs");
    assert_eq!(report.diff_count, 1);
    assert!(report.render().contains("upstream"));
}

#[test]
fn invalid_recording_returns_error() {
    let result = run_replay("not json", BASE_CONFIG);
    assert!(result.is_err());
}

#[test]
fn invalid_candidate_config_returns_error() {
    let recording = recording_with(BASE_CONFIG, "[]");
    let result = run_replay(&recording, "not: valid: yaml: :::");
    assert!(result.is_err());
}

#[test]
fn empty_recording_reports_no_requests() {
    let recording = recording_with(BASE_CONFIG, "[]");
    let report = run_replay(&recording, BASE_CONFIG).expect("replay runs");
    assert_eq!(report.diff_count, 0);
    assert!(report.render().contains("no requests in recording"));
}

#[test]
fn multiple_requests_partial_diffs() {
    // Two requests: one hits /api (matches both configs), one hits /other
    // (matches neither). Only the /api request can diff when the candidate
    // adds an authz rule.
    let new_config = "\
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
    let recording = recording_with(
        BASE_CONFIG,
        "[\
            {\"method\":\"GET\",\"path\":\"/api/foo\",\"timestamp_ms\":1700000000000},\
            {\"method\":\"GET\",\"path\":\"/other\",\"timestamp_ms\":1700000000001}\
        ]",
    );
    let report = run_replay(&recording, new_config).expect("replay runs");
    // Only the /api request diffs (authz changed); /other is a miss in
    // both configs (no diff).
    assert_eq!(report.diff_count, 1);
}

#[test]
fn replay_report_render_empty_diffs() {
    let report = ReplayReport {
        diffs: vec![],
        diff_count: 0,
    };
    assert_eq!(report.render(), "no requests in recording\n");
}
