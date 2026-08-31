//! Unit tests for the Kong import module (`dwara_cli::import_kong`).
//!
//! These tests exercise the public `import_kong` function: parsing
//! Kong declarative configs, generating Dwara config YAML, and
//! verifying route generation, service/upstream mapping, and warning
//! emission for unsupported constructs (plugins, credentials).

use dwara_cli::import_kong::import_kong;

#[test]
fn parse_simple_service_and_route() {
    let conf = r#"
services:
  - name: api
    url: http://127.0.0.1:9000
routes:
  - name: r
    service:
      name: api
    paths:
      - /api
"#;
    let result = import_kong(conf, false).unwrap();
    assert!(result.yaml.contains("api"));
    assert!(result.yaml.contains("9000"));
    assert!(result.yaml.contains("/api"));
}

#[test]
fn parse_upstream_with_targets() {
    let conf = r#"
upstreams:
  - name: backend
    targets:
      - target: 127.0.0.1:9000
        weight: 50
      - target: 127.0.0.1:9001
        weight: 50
"#;
    let result = import_kong(conf, false).unwrap();
    assert!(result.yaml.contains("backend"));
    assert!(result.yaml.contains("9000"));
    assert!(result.yaml.contains("9001"));
}

#[test]
fn plugin_generates_warning() {
    let conf = r#"
services:
  - name: api
    url: http://127.0.0.1:9000
routes:
  - name: r
    service:
      name: api
    paths:
      - /api
plugins:
  - name: key-auth
"#;
    let result = import_kong(conf, false).unwrap();
    assert!(result.yaml.contains("key-auth"));
    assert!(result.yaml.contains("plugin"));
}

#[test]
fn consumer_credentials_generate_warnings() {
    let conf = r#"
consumers:
  - username: bob
    keyauth_credentials:
      - key: abc
    jwt_credentials:
      - key: def
"#;
    let result = import_kong(conf, false).unwrap();
    assert!(result.yaml.contains("key-auth"));
    assert!(result.yaml.contains("JWT"));
}

#[test]
fn empty_config_produces_empty_gateway() {
    let result = import_kong("", false).unwrap();
    assert_eq!(result.route_count, 0);
}

#[test]
fn json_format_parses() {
    let conf = r#"{"services":[{"name":"s","url":"http://127.0.0.1:9000"}]}"#;
    let result = import_kong(conf, true).unwrap();
    assert!(result.yaml.contains("s"));
}

#[test]
fn route_without_service_ref_uses_first_service() {
    let conf = r#"
services:
  - name: first
    url: http://127.0.0.1:9000
  - name: second
    url: http://127.0.0.1:9001
routes:
  - name: r
    paths:
      - /api
"#;
    let result = import_kong(conf, false).unwrap();
    assert!(result.yaml.contains("first"));
}

#[test]
fn route_references_unknown_service_creates_stub() {
    let conf = r#"
routes:
  - name: r
    service:
      name: missing
    paths:
      - /api
"#;
    let result = import_kong(conf, false).unwrap();
    assert!(result.yaml.contains("missing"));
    assert!(result.yaml.contains("not found"));
}

#[test]
fn regex_path_converted() {
    let conf = r#"
services:
  - name: s
    url: http://127.0.0.1:9000
routes:
  - name: r
    service:
      name: s
    paths:
      - ~/api/v[0-9]+/
"#;
    let result = import_kong(conf, false).unwrap();
    assert!(result.yaml.contains("regex"));
}

#[test]
fn host_port_service_format() {
    let conf = r#"
services:
  - name: s
    host: 192.168.1.1
    port: 8080
"#;
    let result = import_kong(conf, false).unwrap();
    assert!(result.yaml.contains("192.168.1.1"));
    assert!(result.yaml.contains("8080"));
}
