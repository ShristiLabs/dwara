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
            jwt_providers: Vec::new(),
            admin: None,
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
