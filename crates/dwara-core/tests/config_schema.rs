//! Integration tests for the config schema v1 (fixtures under tests/fixtures).

use dwara_core::config::{gateway_to_yaml, json_schema, parse_gateway};

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    ))
    .expect("fixture file")
}

#[test]
fn valid_minimal_parses() {
    let gateway = parse_gateway(&fixture("valid_minimal.yaml")).expect("minimal config is valid");
    assert_eq!(gateway.listeners.len(), 1);
    assert_eq!(gateway.listeners[0].port, 8080);
    assert_eq!(gateway.routes[0].service, "echo");
    assert_eq!(gateway.upstreams[0].endpoints[0].port, 9000);
}

#[test]
fn valid_full_parses() {
    let gateway = parse_gateway(&fixture("valid_full.yaml")).expect("full config is valid");
    assert_eq!(gateway.listeners.len(), 2);
    assert_eq!(gateway.routes.len(), 3);
    assert_eq!(gateway.consumers[0].credentials.len(), 2);
    assert_eq!(gateway.policies.len(), 3);
    assert_eq!(
        gateway.routes[1].action,
        dwara_core::config::RouteAction::Redirect {
            scheme: Some("https".to_string()),
            host: Some("api.example.com".to_string()),
            path: Some("/v1/users".to_string()),
            status: 301,
        }
    );
}

#[test]
fn round_trip_is_stable() {
    for name in ["valid_minimal.yaml", "valid_full.yaml"] {
        let original = fixture(name);
        let gateway = parse_gateway(&original).expect("valid config");
        let yaml_once = gateway_to_yaml(&gateway).expect("serialize");
        // Guaranteed round-trip: normalized text parses back and re-serializes
        // to identical normalized text.
        let reparsed = parse_gateway(&yaml_once).expect("normalized output reparses");
        let yaml_twice = gateway_to_yaml(&reparsed).expect("re-serialize");
        assert_eq!(yaml_once, yaml_twice, "round trip not stable for {name}");
        // Required fields survive the round trip.
        assert_eq!(
            gateway, reparsed,
            "typed value changed across round trip for {name}"
        );
    }
}

#[test]
fn unknown_field_is_rejected_with_path() {
    let err = parse_gateway(&fixture("invalid_unknown_field.yaml"))
        .expect_err("unknown field must be rejected");
    assert!(
        err.path.starts_with("listeners[0]"),
        "unexpected path: {}",
        err.path
    );
    assert!(
        err.message.contains("protocool"),
        "error should name the unknown field: {}",
        err.message
    );
}

#[test]
fn dw027_edge_blocks_reject_unknown_fields_and_round_trip() {
    // Strict unknown-field rejection on the new DW-027 route blocks.
    let err = parse_gateway(
        r#"
routes:
  - name: r
    service: s
    match: { path: { type: prefix, value: /x } }
    action: { type: respond, status: 200 }
    cors:
      allowed_origins: ["*"]
      preflight_depth: 2
services:
  - name: s
    upstream: u
upstreams:
  - name: u
    endpoints: [{ address: 127.0.0.1, port: 1 }]
"#,
    )
    .expect_err("unknown cors field must be rejected");
    assert!(
        err.path.contains("cors"),
        "path names the cors block: {err}"
    );
    assert!(
        err.message.contains("preflight_depth"),
        "error names the field: {err}"
    );

    // A fully-populated edge route survives the YAML round trip with
    // defaults omitted.
    let text = r#"
routes:
  - name: r
    service: s
    match: { path: { type: prefix, value: /x } }
    action: { type: respond, status: 200 }
    cors:
      allowed_origins: ["https://app.example.com"]
      allow_credentials: true
      max_age_secs: 300
    compression:
      algorithms: [gzip, brotli, zstd]
      level: 6
      min_size: 64
      content_types: ["text/"]
      excluded_content_types: ["text/event-stream"]
    limits:
      max_body_bytes: 4096
      max_header_count: 32
      max_header_bytes: 8192
services:
  - name: s
    upstream: u
upstreams:
  - name: u
    endpoints: [{ address: 127.0.0.1, port: 1 }]
"#;
    let gateway = parse_gateway(text).expect("edge route parses");
    let yaml_once = gateway_to_yaml(&gateway).expect("serialize");
    let reparsed = parse_gateway(&yaml_once).expect("re-parse");
    let yaml_twice = gateway_to_yaml(&reparsed).expect("re-serialize");
    assert_eq!(yaml_once, yaml_twice, "round trip not stable");
    assert_eq!(gateway, reparsed, "typed value changed across round trip");
    let route = &reparsed.routes[0];
    assert_eq!(
        route.cors.as_ref().unwrap().allowed_methods,
        vec!["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
        "default method set applies"
    );
    assert_eq!(
        route.compression.as_ref().unwrap().min_size,
        64,
        "explicit min_size preserved"
    );
    assert_eq!(
        route.limits.as_ref().unwrap().max_body_bytes,
        Some(4096),
        "limits preserved"
    );
    // Defaults omitted from the normalized form.
    assert!(
        !yaml_once.contains("max_age_secs: 600"),
        "unrelated defaults stay omitted"
    );
}

#[test]
fn wrong_type_is_rejected_with_path() {
    let err = parse_gateway(&fixture("invalid_wrong_type.yaml"))
        .expect_err("wrong type must be rejected");
    assert_eq!(
        err.path, "listeners[0].port",
        "unexpected path: {}",
        err.path
    );
}

#[test]
fn missing_required_is_rejected_with_path() {
    let err = parse_gateway(&fixture("invalid_missing_required.yaml"))
        .expect_err("missing required field must be rejected");
    assert!(
        err.path.starts_with("upstreams[0].endpoints[0]"),
        "unexpected path: {}",
        err.path
    );
    assert!(
        err.message.contains("port"),
        "error should name the missing field: {}",
        err.message
    );
}

#[test]
fn empty_document_is_valid() {
    let gateway = parse_gateway("").expect("empty document is a valid empty gateway");
    assert_eq!(
        gateway,
        dwara_core::config::Gateway {
            trusted_proxies: vec![],
            listeners: vec![],
            routes: vec![],
            services: vec![],
            upstreams: vec![],
            consumers: vec![],
            policies: vec![],
            global_policies: Vec::new(),
            authorization: None,
            max_concurrent_requests: None,
            load_shed_dry_run: false,
            jwt_providers: Vec::new(),
            admin: None,
            allow_empty_routes: false,
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
        }
    );
}

#[test]
fn json_schema_export_covers_root_type() {
    let schema = json_schema();
    let text = serde_json::to_string(&schema).expect("schema serializes");
    // Root type must reference all top-level collections.
    for key in [
        "listeners",
        "routes",
        "services",
        "upstreams",
        "consumers",
        "policies",
    ] {
        assert!(text.contains(key), "schema missing property {key}");
    }
}

#[test]
fn config_error_display_includes_path() {
    let err = parse_gateway(&fixture("invalid_wrong_type.yaml")).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("listeners[0].port"), "display: {msg}");
}

#[test]
fn transforms_and_security_headers_reject_unknown_fields() {
    // deny_unknown_fields holds for the new DW-028 route blocks exactly
    // like every other block; the error path names the block and field.
    let err = parse_gateway(
        r#"
routes:
  - name: r
    service: s
    match: { path: { type: prefix, value: /x } }
    action: { type: proxy }
    transforms:
      request:
        headers:
          set: { x-a: "1" }
          overwrite: true
services:
  - name: s
    upstream: u
upstreams:
  - name: u
    endpoints: [{ address: 127.0.0.1, port: 1 }]
"#,
    )
    .expect_err("unknown transforms field must be rejected");
    assert!(
        err.path.contains("transforms") && err.message.contains("overwrite"),
        "path names the transforms block: {err}"
    );

    let err = parse_gateway(
        r#"
routes:
  - name: r
    service: s
    match: { path: { type: prefix, value: /x } }
    action: { type: proxy }
    security_headers:
      nosniff: true
      referrer_policy: no-referrer
services:
  - name: s
    upstream: u
upstreams:
  - name: u
    endpoints: [{ address: 127.0.0.1, port: 1 }]
"#,
    )
    .expect_err("unknown security_headers field must be rejected");
    assert!(
        err.path.contains("security_headers") && err.message.contains("referrer_policy"),
        "path names the security_headers block: {err}"
    );
}

#[test]
fn transforms_block_parses_end_to_end() {
    // The full DW-028 surface in one route: both halves, every op kind,
    // and the security-header block alongside.
    let gateway = parse_gateway(
        r#"
routes:
  - name: r
    service: s
    match: { path: { type: prefix, value: /x } }
    action: { type: proxy }
    transforms:
      request:
        headers:
          set: { x-gateway: dwara }
          add: { x-tags: edge }
          remove: [x-client-secret]
          rename: { x-legacy-id: x-request-ref }
        query:
          set: { region: us-east }
          add: { source: gw }
          remove: [debug]
          rename: { uid: user_id }
        body:
          json:
            max_bytes: 65536
            ops:
              - { op: set, path: /meta/via, value: dwara }
              - { op: remove, path: /internal/secret }
      response:
        headers:
          remove: [server]
        body:
          json:
            max_bytes: 262144
            ops:
              - { op: remove, path: /debug/internal }
    security_headers:
      hsts_max_age_secs: 31536000
      hsts_include_subdomains: true
      hsts_preload: true
      nosniff: true
      content_security_policy: "default-src 'self'"
      frame_options: deny
services:
  - name: s
    upstream: u
upstreams:
  - name: u
    endpoints: [{ address: 127.0.0.1, port: 1 }]
"#,
    );
    let gateway = gateway.expect("the full DW-028 surface parses");
    let route = &gateway.routes[0];
    let t = route.transforms.as_ref().unwrap();
    let req = t.request.as_ref().unwrap();
    let h = req.headers.as_ref().unwrap();
    assert_eq!(h.set.get("x-gateway").unwrap(), "dwara");
    assert_eq!(h.rename.get("x-legacy-id").unwrap(), "x-request-ref");
    assert_eq!(req.query.as_ref().unwrap().remove, vec!["debug"]);
    let body = &req.body.as_ref().unwrap().json;
    assert_eq!(body.max_bytes, 65536);
    assert_eq!(body.ops.len(), 2);
    let sh = route.security_headers.as_ref().unwrap();
    assert_eq!(sh.hsts_max_age_secs, Some(31_536_000));
    assert!(sh.hsts_include_subdomains && sh.hsts_preload && sh.nosniff);
    assert_eq!(
        sh.frame_options,
        Some(dwara_core::config::transforms::FrameOptions::Deny)
    );
    let resp = t.response.as_ref().unwrap();
    assert_eq!(resp.headers.as_ref().unwrap().remove, vec!["server"]);
    assert_eq!(resp.body.as_ref().unwrap().json.max_bytes, 262_144);
}
