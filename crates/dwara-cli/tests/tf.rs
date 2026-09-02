//! Terraform state tool integration tests (DW-065).
//!
//! Exercises the `dwara_cli::tf` module: the pure functions that
//! convert a Gateway to tfstate JSON and HCL, compute plan diffs, and
//! derive apply YAML. The round-trip (export -> modify -> plan -> apply
//! -> export) is tested at the pure-function level against parsed
//! Gateway values, which is deterministic and does not require spawning
//! the full gateway binary (the dwara binary lives in dwara-bin, not
//! dwara-cli; the admin HTTP round-trip is covered by the dwara-bin
//! admin_reload_coherence suite).
//!
//! The CLI binary's `tf` subcommand is exercised via `CARGO_BIN_EXE`
//! for argument parsing and help output.

use std::process::Command;

use dwara_cli::tf::{
    format_diff, gateway_to_hcl, gateway_to_state, plan_diff, state_from_json, state_to_gateway,
    state_to_json, state_to_yaml, DiffEntry,
};
use dwara_core::config::{
    parse_gateway, Endpoint, Gateway, LoadBalancer, PathMatch, PathMatchKind, Route, RouteAction,
    RouteMatch, Service, Upstream, UpstreamProtocol,
};

/// A minimal valid gateway config with one listener, route, service,
/// and upstream — the fixture for the round-trip tests.
fn sample_config_yaml() -> String {
    r#"
listeners:
  - name: main
    address: 127.0.0.1
    port: 8080
routes:
  - name: api
    service: api-service
    match:
      path:
        type: prefix
        value: /api
    action:
      type: proxy
services:
  - name: api-service
    upstream: api-upstream
upstreams:
  - name: api-upstream
    endpoints:
      - address: 127.0.0.1
        port: 9000
"#
    .to_string()
}

/// A second config with an added route and a changed upstream port —
/// the "desired" state for plan-diff assertions.
fn modified_config_yaml() -> String {
    r#"
listeners:
  - name: main
    address: 127.0.0.1
    port: 8080
routes:
  - name: api
    service: api-service
    match:
      path:
        type: prefix
        value: /api
    action:
      type: proxy
  - name: web
    service: web-service
    match:
      path:
        type: prefix
        value: /web
    action:
      type: proxy
services:
  - name: api-service
    upstream: api-upstream
  - name: web-service
    upstream: web-upstream
upstreams:
  - name: api-upstream
    endpoints:
      - address: 127.0.0.1
        port: 9999
  - name: web-upstream
    endpoints:
      - address: 127.0.0.1
        port: 9001
"#
    .to_string()
}

fn empty_gateway() -> Gateway {
    Gateway {
        listeners: Vec::new(),
        routes: Vec::new(),
        services: Vec::new(),
        upstreams: Vec::new(),
        consumers: Vec::new(),
        policies: Vec::new(),
        global_policies: Vec::new(),
        authorization: None,
        trusted_proxies: Vec::new(),
        max_concurrent_requests: None,
        load_shed_dry_run: false,
        jwt_providers: Vec::new(),
        admin: None,
        allow_empty_routes: true,
        hmac_auth: None,
        webhooks: Vec::new(),
        analytics: None,
        analytics_stream: None,
        geoip: None,
        admission_queue: None,
        mtls_consumer_mapping: None,
        mtls_forward_headers: None,
        license: None,
        oidc_providers: Vec::new(),
        redis_rate_limiter: None,
        config_convergence: None,
        plugins: Vec::new(),
        ai: None,
        fleet: None,
    }
}

#[test]
fn export_produces_valid_tfstate() {
    let gateway = parse_gateway(&sample_config_yaml()).unwrap();
    let state = gateway_to_state(&gateway);
    let json = state_to_json(&state).unwrap();

    // The tfstate JSON must parse back.
    let parsed = state_from_json(&json).unwrap();
    assert_eq!(parsed.version, 4);
    assert_eq!(parsed.terraform_version, "1.5.0");

    // One resource per entity kind present.
    let types: Vec<&str> = parsed.resources.iter().map(|r| r.r#type.as_str()).collect();
    assert!(types.contains(&"dwara_listener"));
    assert!(types.contains(&"dwara_route"));
    assert!(types.contains(&"dwara_service"));
    assert!(types.contains(&"dwara_upstream"));
}

#[test]
fn export_produces_hcl_with_resource_blocks() {
    let gateway = parse_gateway(&sample_config_yaml()).unwrap();
    let hcl = gateway_to_hcl(&gateway);
    assert!(hcl.contains("resource \"dwara_listener\" \"main\""));
    assert!(hcl.contains("resource \"dwara_route\" \"api\""));
    assert!(hcl.contains("resource \"dwara_service\" \"api-service\""));
    assert!(hcl.contains("resource \"dwara_upstream\" \"api-upstream\""));
}

#[test]
fn state_round_trips_through_gateway() {
    let gateway = parse_gateway(&sample_config_yaml()).unwrap();
    let state = gateway_to_state(&gateway);
    let json = state_to_json(&state).unwrap();
    let parsed = state_from_json(&json).unwrap();
    let gateway2 = state_to_gateway(&parsed).unwrap();

    assert_eq!(gateway2.listeners.len(), 1);
    assert_eq!(gateway2.listeners[0].name, "main");
    assert_eq!(gateway2.listeners[0].port, 8080);
    assert_eq!(gateway2.routes.len(), 1);
    assert_eq!(gateway2.routes[0].name, "api");
    assert_eq!(gateway2.routes[0].service, "api-service");
    assert_eq!(gateway2.routes[0].r#match.path.kind, PathMatchKind::Prefix);
    assert_eq!(gateway2.routes[0].r#match.path.value, "/api");
    assert_eq!(gateway2.services.len(), 1);
    assert_eq!(gateway2.upstreams.len(), 1);
    assert_eq!(gateway2.upstreams[0].endpoints[0].port, 9000);
}

#[test]
fn plan_diff_detects_added_route() {
    let actual = parse_gateway(&sample_config_yaml()).unwrap();
    let desired = parse_gateway(&modified_config_yaml()).unwrap();
    let desired_state = gateway_to_state(&desired);

    let entries = plan_diff(&desired_state, &actual);
    // The "web" route is in desired but not actual -> added.
    assert!(entries.iter().any(|e| matches!(
        e,
        DiffEntry::Added {
            r#type,
            name,
        } if r#type == "dwara_route" && name == "web"
    )));
    // The "web-service" is in desired but not actual -> added.
    assert!(entries.iter().any(|e| matches!(
        e,
        DiffEntry::Added {
            r#type,
            name,
        } if r#type == "dwara_service" && name == "web-service"
    )));
    // The "web-upstream" is in desired but not actual -> added.
    assert!(entries.iter().any(|e| matches!(
        e,
        DiffEntry::Added {
            r#type,
            name,
        } if r#type == "dwara_upstream" && name == "web-upstream"
    )));
}

#[test]
fn plan_diff_detects_changed_upstream() {
    let actual = parse_gateway(&sample_config_yaml()).unwrap();
    let desired = parse_gateway(&modified_config_yaml()).unwrap();
    let desired_state = gateway_to_state(&desired);

    let entries = plan_diff(&desired_state, &actual);
    // The api-upstream port changed from 9000 to 9999 -> changed.
    assert!(entries.iter().any(|e| matches!(
        e,
        DiffEntry::Changed {
            r#type,
            name,
            ..
        } if r#type == "dwara_upstream" && name == "api-upstream"
    )));
}

#[test]
fn plan_diff_clean_when_identical() {
    let gateway = parse_gateway(&sample_config_yaml()).unwrap();
    let state = gateway_to_state(&gateway);
    let entries = plan_diff(&state, &gateway);
    assert!(entries.is_empty());
}

#[test]
fn plan_diff_detects_removed_entity() {
    let actual = parse_gateway(&modified_config_yaml()).unwrap();
    let desired = parse_gateway(&sample_config_yaml()).unwrap();
    let desired_state = gateway_to_state(&desired);

    let entries = plan_diff(&desired_state, &actual);
    // The "web" route is in actual but not desired -> removed.
    assert!(entries.iter().any(|e| matches!(
        e,
        DiffEntry::Removed {
            r#type,
            name,
        } if r#type == "dwara_route" && name == "web"
    )));
}

#[test]
fn format_diff_reports_changes() {
    let actual = parse_gateway(&sample_config_yaml()).unwrap();
    let desired = parse_gateway(&modified_config_yaml()).unwrap();
    let desired_state = gateway_to_state(&desired);
    let entries = plan_diff(&desired_state, &actual);
    let (text, has_diff) = format_diff(&entries);
    assert!(has_diff);
    assert!(text.contains("Plan:"));
}

#[test]
fn format_diff_no_changes_message() {
    let (text, has_diff) = format_diff(&[]);
    assert!(!has_diff);
    assert!(text.contains("No changes"));
}

#[test]
fn state_to_yaml_produces_valid_config() {
    let gateway = parse_gateway(&sample_config_yaml()).unwrap();
    let state = gateway_to_state(&gateway);
    let yaml = state_to_yaml(&state).unwrap();
    let gateway2 = parse_gateway(&yaml).unwrap();
    assert_eq!(gateway2.routes.len(), 1);
    assert_eq!(gateway2.upstreams.len(), 1);
    assert_eq!(gateway2.upstreams[0].endpoints[0].port, 9000);
}

#[test]
fn export_apply_export_round_trip() {
    // The done-when: export -> (modify state) -> plan (asserts diff) ->
    // apply (derive YAML from modified state) -> export again (asserts
    // the state matches the applied config).
    //
    // Step 1: export the initial config as tfstate.
    let initial = parse_gateway(&sample_config_yaml()).unwrap();
    let state = gateway_to_state(&initial);
    let state_json = state_to_json(&state).unwrap();

    // Step 2: modify the state to reflect the desired config (the
    // modified_config has an added route and a changed port).
    let desired = parse_gateway(&modified_config_yaml()).unwrap();
    let desired_state = gateway_to_state(&desired);

    // Step 3: plan — compare desired state against the initial config
    // (the "actual"). A diff must be present.
    let entries = plan_diff(&desired_state, &initial);
    assert!(
        !entries.is_empty(),
        "plan must show a diff after modification"
    );

    // Step 4: apply — derive the desired YAML from the modified state
    // and push it (here we simulate the push by parsing the YAML back).
    let desired_yaml = state_to_yaml(&desired_state).unwrap();
    let applied = parse_gateway(&desired_yaml).unwrap();

    // Step 5: export again — the new state must match the desired state.
    let applied_state = gateway_to_state(&applied);
    let applied_json = state_to_json(&applied_state).unwrap();
    let desired_json = state_to_json(&desired_state).unwrap();
    assert_eq!(
        applied_json, desired_json,
        "export after apply must match the desired state"
    );

    // The original state JSON is still valid (no mutation).
    let _ = state_from_json(&state_json).unwrap();
}

#[test]
fn empty_gateway_round_trips() {
    let gw = empty_gateway();
    let state = gateway_to_state(&gw);
    assert!(state.resources.is_empty());
    let json = state_to_json(&state).unwrap();
    let parsed = state_from_json(&json).unwrap();
    let gw2 = state_to_gateway(&parsed).unwrap();
    assert!(gw2.routes.is_empty());
    assert!(gw2.allow_empty_routes);
}

#[test]
fn tfstate_with_consumer_round_trips() {
    let mut gw = parse_gateway(&sample_config_yaml()).unwrap();
    gw.consumers.push(dwara_core::config::Consumer {
        name: "test-consumer".to_string(),
        credentials: Vec::new(),
        policies: Vec::new(),
        consumer_type: dwara_core::config::ConsumerType::User,
        tool_allowlist: vec![],
        token_budget: None,
        priority: None,
        groups: Vec::new(),
        authorization: None,
        quotas: None,
        ai_logging: None,
    });
    let state = gateway_to_state(&gw);
    let json = state_to_json(&state).unwrap();
    let parsed = state_from_json(&json).unwrap();
    let gw2 = state_to_gateway(&parsed).unwrap();
    assert_eq!(gw2.consumers.len(), 1);
    assert_eq!(gw2.consumers[0].name, "test-consumer");
}

#[test]
fn hcl_escapes_special_characters() {
    let mut gw = empty_gateway();
    gw.routes.push(Route {
        name: "test".to_string(),
        service: "svc".to_string(),
        r#match: RouteMatch {
            path: PathMatch {
                kind: PathMatchKind::Prefix,
                value: "/path with \"quotes\"".to_string(),
            },
            host: None,
            methods: Vec::new(),
            headers: std::collections::BTreeMap::new(),
            query: Vec::new(),
            cookies: Vec::new(),
            accept: None,
        },
        action: RouteAction::Proxy { rewrite: None },
        policies: Vec::new(),
        priority: None,
        auth_required: false,
        cors: None,
        compression: None,
        limits: None,
        authorization: None,
        deprecation: None,
        maintenance: None,
        transforms: None,
        security_headers: None,
        masking: None,
        cache: None,
        methods: Vec::new(),
        slo: None,
        websocket: None,
        waf: None,
        request_validation: None,
        openapi: None,
        mirror: None,
        fault_injection: None,
        plugins: Vec::new(),
    });
    gw.services.push(Service {
        name: "svc".to_string(),
        upstream: Some("up".to_string()),
        split: None,
        sticky: None,
        base_path: None,
        version: None,
        policies: Vec::new(),
        authorization: None,
    });
    gw.upstreams.push(Upstream {
        name: "up".to_string(),
        load_balancer: LoadBalancer::RoundRobin,
        protocol: UpstreamProtocol::Http1,
        trusted_ca_file: None,
        endpoints: vec![Endpoint {
            address: "127.0.0.1".to_string(),
            port: 9000,
            weight: 1,
            region: None,
            zone: None,
        }],
        connection_cap: None,
        slow_start_ms: None,
        health: None,
        active_health: None,
        retries: None,
        breaker: None,
        max_pending: None,
        timeouts: None,
        oauth2_client_credentials: None,
        dns_discovery: None,
        peak_ewma: None,
        locality: None,
    });
    gw.allow_empty_routes = false;
    let hcl = gateway_to_hcl(&gw);
    assert!(hcl.contains("\\\"quotes\\\""));
}

#[test]
fn tf_cli_help_lists_subcommands() {
    // The CLI binary must accept `tf --help` and list the subcommands.
    let output = Command::new(env!("CARGO_BIN_EXE_dwara-cli"))
        .args(["tf", "--help"])
        .output()
        .expect("spawns dwara-cli");
    assert!(output.status.success(), "tf --help must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("export"), "help must list export");
    assert!(stdout.contains("plan"), "help must list plan");
    assert!(stdout.contains("apply"), "help must list apply");
}

#[test]
fn tf_cli_export_help_shows_flags() {
    let output = Command::new(env!("CARGO_BIN_EXE_dwara-cli"))
        .args(["tf", "export", "--help"])
        .output()
        .expect("spawns dwara-cli");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--admin"));
    assert!(stdout.contains("--out-state"));
    assert!(stdout.contains("--out-hcl"));
}

#[test]
fn tf_cli_plan_help_shows_flags() {
    let output = Command::new(env!("CARGO_BIN_EXE_dwara-cli"))
        .args(["tf", "plan", "--help"])
        .output()
        .expect("spawns dwara-cli");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--admin"));
    assert!(stdout.contains("--state"));
}

#[test]
fn tf_cli_apply_help_shows_flags() {
    let output = Command::new(env!("CARGO_BIN_EXE_dwara-cli"))
        .args(["tf", "apply", "--help"])
        .output()
        .expect("spawns dwara-cli");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--admin"));
    assert!(stdout.contains("--state"));
    assert!(stdout.contains("--config"));
}
