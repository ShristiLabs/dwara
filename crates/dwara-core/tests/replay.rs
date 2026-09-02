//! Integration tests for replay time-travel debugging (DW-102).
//!
//! These tests exercise the pure decision replayer
//! ([`dwara_core::dataplane::replay::decide`]) and the diff logic
//! ([`DecisionDiff`]) through the public API. They verify:
//!
//! - Route matching (match, miss, path-param routes).
//! - Authorization verdicts (allow by default, deny via IP ACL).
//! - Rate-limit simulation (admitted within budget, denied over budget,
//!   dry-run never enforces).
//! - Transform summary (counts of header/query/body ops).
//! - Upstream pick (deterministic first endpoint, path rewrite label).
//! - Diff detection across two config generations (route change, authz
//!   change, rate-limit change, transform change, upstream change).
//! - The simulated counter window-reset and key-independence behavior.
//!
//! The CLI library half (`dwara_cli::replay::run_replay`) is tested in
//! `crates/dwara-cli/tests/replay.rs` (the dependency direction is
//! cli -> core, so core cannot import cli).

use dwara_core::config::parse_gateway;
use dwara_core::dataplane::replay::{decide, DecisionDiff, ReplayRequest, SimulatedCounter};
use dwara_core::snapshot::{compile, Snapshot};

// --- helpers ------------------------------------------------------------

/// Compile a YAML config string into a generation-0 snapshot.
fn snap(yaml: &str) -> Snapshot {
    let gateway = parse_gateway(yaml).expect("config parses");
    let compiled = compile(&gateway).expect("config compiles");
    Snapshot::from_compiled(compiled)
}

/// A minimal request for `path` with no auth identity.
fn req(path: &str) -> ReplayRequest {
    ReplayRequest {
        method: "GET".to_string(),
        path: path.to_string(),
        headers: Vec::new(),
        auth_identity: None,
        timestamp_ms: 1_700_000_000_000,
    }
}

/// A minimal config with one proxy route to a single upstream endpoint.
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

// --- route matching -----------------------------------------------------

#[test]
fn route_match_reports_route_name() {
    let snap = snap(BASE_CONFIG);
    let mut counter = SimulatedCounter::new();
    let d = decide(&snap, &req("/api/foo"), &mut counter);
    assert_eq!(d.matched_route.as_deref(), Some("api"));
}

#[test]
fn route_miss_reports_no_match() {
    let snap = snap(BASE_CONFIG);
    let mut counter = SimulatedCounter::new();
    let d = decide(&snap, &req("/other"), &mut counter);
    assert!(d.matched_route.is_none());
    assert!(d.authz_result.is_none());
    assert!(d.rate_limit_result.is_none());
    assert!(d.transform_result.is_none());
    assert!(d.upstream_pick.is_none());
}

#[test]
fn exact_route_matches_only_exact_path() {
    let yaml = "\
listeners: []
routes:
  - name: exact
    service: svc
    match:
      path: { type: exact, value: /api/users }
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
    let snap = snap(yaml);
    let mut counter = SimulatedCounter::new();
    let d = decide(&snap, &req("/api/users"), &mut counter);
    assert_eq!(d.matched_route.as_deref(), Some("exact"));
    let d = decide(&snap, &req("/api/users/42"), &mut counter);
    assert!(d.matched_route.is_none());
}

// --- authorization ------------------------------------------------------

#[test]
fn authz_allow_when_no_rules() {
    let snap = snap(BASE_CONFIG);
    let mut counter = SimulatedCounter::new();
    let d = decide(&snap, &req("/api/foo"), &mut counter);
    assert_eq!(
        d.authz_result,
        Some(dwara_core::security::authz::Decision::Allow)
    );
}

#[test]
fn authz_deny_via_route_ip_acl() {
    let yaml = "\
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
    let snap = snap(yaml);
    let mut counter = SimulatedCounter::new();
    let d = decide(&snap, &req("/api/foo"), &mut counter);
    // Replay uses 127.0.0.1 as the peer IP; default deny blocks it.
    assert!(matches!(
        d.authz_result,
        Some(dwara_core::security::authz::Decision::Deny { .. })
    ));
}

#[test]
fn authz_allow_when_ip_acl_permits_loopback() {
    let yaml = "\
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
        allow: [127.0.0.1]
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 8080
";
    let snap = snap(yaml);
    let mut counter = SimulatedCounter::new();
    let d = decide(&snap, &req("/api/foo"), &mut counter);
    assert_eq!(
        d.authz_result,
        Some(dwara_core::security::authz::Decision::Allow)
    );
}

// --- rate-limit simulation ----------------------------------------------

#[test]
fn rate_limit_none_when_no_policies() {
    let snap = snap(BASE_CONFIG);
    let mut counter = SimulatedCounter::new();
    let d = decide(&snap, &req("/api/foo"), &mut counter);
    assert!(d.rate_limit_result.is_none());
}

#[test]
fn rate_limit_admitted_within_budget() {
    let yaml = "\
listeners: []
routes:
  - name: api
    service: svc
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy }
    policies: [rl]
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 8080
policies:
  - name: rl
    rate_limit:
      requests: 10
      window_seconds: 60
";
    let snap = snap(yaml);
    let mut counter = SimulatedCounter::new();
    let d = decide(&snap, &req("/api/foo"), &mut counter);
    assert_eq!(d.rate_limit_result, Some(true));
}

#[test]
fn rate_limit_denied_over_budget() {
    let yaml = "\
listeners: []
routes:
  - name: api
    service: svc
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy }
    policies: [rl]
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 8080
policies:
  - name: rl
    rate_limit:
      requests: 1
      window_seconds: 60
";
    let snap = snap(yaml);
    let mut counter = SimulatedCounter::new();
    // First request admitted.
    let d1 = decide(&snap, &req("/api/foo"), &mut counter);
    assert_eq!(d1.rate_limit_result, Some(true));
    // Second request in the same window is over budget.
    let d2 = decide(&snap, &req("/api/foo"), &mut counter);
    assert_eq!(d2.rate_limit_result, Some(false));
}

#[test]
fn rate_limit_dry_run_always_admitted() {
    let yaml = "\
listeners: []
routes:
  - name: api
    service: svc
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy }
    policies: [rl]
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 8080
policies:
  - name: rl
    dry_run: true
    rate_limit:
      requests: 1
      window_seconds: 60
";
    let snap = snap(yaml);
    let mut counter = SimulatedCounter::new();
    // Even after many requests, dry-run never enforces.
    for _ in 0..5 {
        let d = decide(&snap, &req("/api/foo"), &mut counter);
        assert_eq!(d.rate_limit_result, Some(true));
    }
}

// --- transforms ---------------------------------------------------------

#[test]
fn transform_summary_none_when_no_transforms() {
    let snap = snap(BASE_CONFIG);
    let mut counter = SimulatedCounter::new();
    let d = decide(&snap, &req("/api/foo"), &mut counter);
    assert!(d.transform_result.is_none());
}

#[test]
fn transform_summary_counts_header_ops() {
    let yaml = "\
listeners: []
routes:
  - name: api
    service: svc
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy }
    transforms:
      request:
        headers:
          set:
            x-replay: \"1\"
          add:
            x-trace: abc
          remove: [x-debug]
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 8080
";
    let snap = snap(yaml);
    let mut counter = SimulatedCounter::new();
    let d = decide(&snap, &req("/api/foo"), &mut counter);
    let t = d.transform_result.expect("transform summary present");
    assert_eq!(t.request_header_ops, 3); // 1 set + 1 add + 1 remove
    assert_eq!(t.request_query_ops, 0);
    assert!(!t.request_body_transform);
    assert_eq!(t.response_header_ops, 0);
    assert!(!t.response_body_transform);
}

// --- upstream pick ------------------------------------------------------

#[test]
fn upstream_pick_reports_first_endpoint() {
    let snap = snap(BASE_CONFIG);
    let mut counter = SimulatedCounter::new();
    let d = decide(&snap, &req("/api/foo"), &mut counter);
    let pick = d.upstream_pick.expect("upstream pick present");
    assert_eq!(pick.upstream, "pool");
    assert_eq!(pick.endpoint, "127.0.0.1:8080");
    assert_eq!(pick.path_rewrite, "none");
}

#[test]
fn upstream_pick_with_strip_prefix() {
    let yaml = "\
listeners: []
routes:
  - name: api
    service: svc
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy, rewrite: { type: strip_prefix } }
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 8080
";
    let snap = snap(yaml);
    let mut counter = SimulatedCounter::new();
    let d = decide(&snap, &req("/api/foo"), &mut counter);
    let pick = d.upstream_pick.expect("upstream pick present");
    assert_eq!(pick.path_rewrite, "strip_prefix");
}

#[test]
fn upstream_pick_none_for_respond_action() {
    let yaml = "\
listeners: []
routes:
  - name: api
    service: svc
    match:
      path: { type: prefix, value: /api }
    action: { type: respond, status: 200 }
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 8080
";
    let snap = snap(yaml);
    let mut counter = SimulatedCounter::new();
    let d = decide(&snap, &req("/api/foo"), &mut counter);
    assert!(d.upstream_pick.is_none());
}

// --- diff logic ---------------------------------------------------------

#[test]
fn diff_no_change_when_identical() {
    let snap = snap(BASE_CONFIG);
    let mut c1 = SimulatedCounter::new();
    let mut c2 = SimulatedCounter::new();
    let old = decide(&snap, &req("/api/foo"), &mut c1);
    let new = decide(&snap, &req("/api/foo"), &mut c2);
    let diff = DecisionDiff::compare("/api/foo", &old, &new);
    assert!(!diff.any());
    assert!(diff.summary().is_empty());
}

#[test]
fn diff_detects_route_change() {
    let old_yaml = "\
listeners: []
routes:
  - name: old-route
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
    let new_yaml = "\
listeners: []
routes:
  - name: new-route
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
    let old_snap = snap(old_yaml);
    let new_snap = snap(new_yaml);
    let mut c1 = SimulatedCounter::new();
    let mut c2 = SimulatedCounter::new();
    let old = decide(&old_snap, &req("/api/foo"), &mut c1);
    let new = decide(&new_snap, &req("/api/foo"), &mut c2);
    let diff = DecisionDiff::compare("/api/foo", &old, &new);
    assert!(diff.route_changed);
    assert!(diff.any());
    assert!(diff.summary().contains("route"));
}

#[test]
fn diff_detects_authz_change() {
    let old_yaml = BASE_CONFIG;
    let new_yaml = "\
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
    let old_snap = snap(old_yaml);
    let new_snap = snap(new_yaml);
    let mut c1 = SimulatedCounter::new();
    let mut c2 = SimulatedCounter::new();
    let old = decide(&old_snap, &req("/api/foo"), &mut c1);
    let new = decide(&new_snap, &req("/api/foo"), &mut c2);
    let diff = DecisionDiff::compare("/api/foo", &old, &new);
    assert!(diff.authz_changed);
    assert!(diff.any());
    assert!(diff.summary().contains("authz"));
}

#[test]
fn diff_detects_rate_limit_change() {
    let old_yaml = BASE_CONFIG;
    let new_yaml = "\
listeners: []
routes:
  - name: api
    service: svc
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy }
    policies: [rl]
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 8080
policies:
  - name: rl
    rate_limit:
      requests: 10
      window_seconds: 60
";
    let old_snap = snap(old_yaml);
    let new_snap = snap(new_yaml);
    let mut c1 = SimulatedCounter::new();
    let mut c2 = SimulatedCounter::new();
    let old = decide(&old_snap, &req("/api/foo"), &mut c1);
    let new = decide(&new_snap, &req("/api/foo"), &mut c2);
    let diff = DecisionDiff::compare("/api/foo", &old, &new);
    assert!(diff.rate_limit_changed);
    assert!(diff.any());
    assert!(diff.summary().contains("rate_limit"));
}

#[test]
fn diff_detects_upstream_change() {
    let old_yaml = BASE_CONFIG;
    let new_yaml = "\
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
    let old_snap = snap(old_yaml);
    let new_snap = snap(new_yaml);
    let mut c1 = SimulatedCounter::new();
    let mut c2 = SimulatedCounter::new();
    let old = decide(&old_snap, &req("/api/foo"), &mut c1);
    let new = decide(&new_snap, &req("/api/foo"), &mut c2);
    let diff = DecisionDiff::compare("/api/foo", &old, &new);
    assert!(diff.upstream_changed);
    assert!(diff.any());
    assert!(diff.summary().contains("upstream"));
}

#[test]
fn diff_detects_transform_change() {
    let old_yaml = BASE_CONFIG;
    let new_yaml = "\
listeners: []
routes:
  - name: api
    service: svc
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy }
    transforms:
      request:
        headers:
          set:
            x-replay: \"1\"
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 8080
";
    let old_snap = snap(old_yaml);
    let new_snap = snap(new_yaml);
    let mut c1 = SimulatedCounter::new();
    let mut c2 = SimulatedCounter::new();
    let old = decide(&old_snap, &req("/api/foo"), &mut c1);
    let new = decide(&new_snap, &req("/api/foo"), &mut c2);
    let diff = DecisionDiff::compare("/api/foo", &old, &new);
    assert!(diff.transform_changed);
    assert!(diff.any());
    assert!(diff.summary().contains("transforms"));
}

// --- simulated counter --------------------------------------------------

#[test]
fn simulated_counter_resets_after_window() {
    let mut c = SimulatedCounter::new();
    // Budget: 1 request per 1 second.
    assert!(c.check("k", 1, 1, 1000));
    assert!(!c.check("k", 1, 1, 1500)); // same window, over budget.
                                        // Window resets at 2000 (1000 + 1000).
    assert!(c.check("k", 1, 1, 2000));
}

#[test]
fn simulated_counter_keys_are_independent() {
    let mut c = SimulatedCounter::new();
    assert!(c.check("a", 1, 60, 1000));
    assert!(c.check("b", 1, 60, 1000)); // different key, own budget.
    assert!(!c.check("a", 1, 60, 1000)); // key "a" exhausted.
}
