//! Kong import integration tests (DW-065).
//!
//! Exercises the `dwara_cli::import_kong` module: parsing Kong
//! declarative configs (decK YAML and JSON), generating Dwara config
//! YAML, and verifying the generated config round-trips through
//! `parse_gateway` + validation.

use dwara_cli::import_kong::import_kong;
use dwara_core::config::{parse_gateway, PathMatchKind};

const SIMPLE_KONG_YAML: &str = r#"
services:
  - name: api-service
    url: http://127.0.0.1:9000
routes:
  - name: api-route
    service:
      name: api-service
    paths:
      - /api
    methods:
      - GET
      - POST
    hosts:
      - api.example.com
"#;

const UPSTREAM_KONG_YAML: &str = r#"
upstreams:
  - name: backend
    targets:
      - target: 127.0.0.1:9000
        weight: 100
      - target: 127.0.0.1:9001
        weight: 100
services:
  - name: api-service
    url: http://127.0.0.1:9000
routes:
  - name: api-route
    service:
      name: api-service
    paths:
      - /api
"#;

const KONG_WITH_PLUGINS: &str = r#"
services:
  - name: api-service
    url: http://127.0.0.1:9000
routes:
  - name: api-route
    service:
      name: api-service
    paths:
      - /api
plugins:
  - name: key-auth
  - name: rate-limiting
  - name: cors
consumers:
  - username: alice
    keyauth_credentials:
      - key: secret-key
    acl_groups:
      - group1
"#;

const KONG_JSON: &str = r#"{
  "services": [
    {"name": "api-service", "url": "http://127.0.0.1:9000"}
  ],
  "routes": [
    {"name": "api-route", "service": {"name": "api-service"}, "paths": ["/api"]}
  ]
}"#;

#[test]
fn simple_kong_yaml_import_generates_valid_config() {
    let result = import_kong(SIMPLE_KONG_YAML, false).unwrap();
    assert_eq!(result.route_count, 1);

    let gateway = parse_gateway(&result.yaml).unwrap();
    assert_eq!(gateway.routes.len(), 1);
    assert_eq!(gateway.routes[0].name, "api-route");
    assert_eq!(gateway.routes[0].service, "api-service");
    assert_eq!(gateway.routes[0].r#match.path.kind, PathMatchKind::Prefix);
    assert_eq!(gateway.routes[0].r#match.path.value, "/api");
    assert_eq!(gateway.routes[0].r#match.methods, vec!["GET", "POST"]);
    assert_eq!(
        gateway.routes[0].r#match.host.as_deref(),
        Some("api.example.com")
    );
}

#[test]
fn upstream_kong_yaml_import_generates_valid_config() {
    let result = import_kong(UPSTREAM_KONG_YAML, false).unwrap();
    assert_eq!(result.route_count, 1);

    let gateway = parse_gateway(&result.yaml).unwrap();
    assert_eq!(gateway.upstreams.len(), 2);
    let backend = gateway
        .upstreams
        .iter()
        .find(|u| u.name == "backend")
        .expect("backend upstream");
    assert_eq!(backend.endpoints.len(), 2);
    assert_eq!(backend.endpoints[0].port, 9000);
    assert_eq!(backend.endpoints[1].port, 9001);
}

#[test]
fn kong_with_plugins_warns() {
    let result = import_kong(KONG_WITH_PLUGINS, false).unwrap();
    assert!(result.yaml.contains("key-auth"));
    assert!(result.yaml.contains("rate-limiting"));
    assert!(result.yaml.contains("cors"));
    assert!(result.yaml.contains("not migrated"));

    let gateway = parse_gateway(&result.yaml).unwrap();
    assert_eq!(gateway.consumers.len(), 1);
    assert_eq!(gateway.consumers[0].name, "alice");
}

#[test]
fn kong_json_import_generates_valid_config() {
    let result = import_kong(KONG_JSON, true).unwrap();
    assert_eq!(result.route_count, 1);

    let gateway = parse_gateway(&result.yaml).unwrap();
    assert_eq!(gateway.routes.len(), 1);
    assert_eq!(gateway.routes[0].name, "api-route");
}

#[test]
fn empty_kong_config_produces_empty_gateway() {
    let result = import_kong("", false).unwrap();
    assert_eq!(result.route_count, 0);

    let gateway = parse_gateway(&result.yaml).unwrap();
    assert_eq!(gateway.routes.len(), 0);
}

#[test]
fn kong_regex_path_import() {
    let conf = r#"
services:
  - name: svc
    url: http://127.0.0.1:9000
routes:
  - name: regex-route
    service:
      name: svc
    paths:
      - ~/v[0-9]+/
"#;
    let result = import_kong(conf, false).unwrap();
    let gateway = parse_gateway(&result.yaml).unwrap();
    assert_eq!(gateway.routes[0].r#match.path.kind, PathMatchKind::Regex);
    assert!(gateway.routes[0].r#match.path.value.starts_with('/'));
}

#[test]
fn kong_service_with_host_port() {
    let conf = r#"
services:
  - name: svc
    host: 10.0.0.1
    port: 8080
routes:
  - name: r
    service:
      name: svc
    paths:
      - /
"#;
    let result = import_kong(conf, false).unwrap();
    let gateway = parse_gateway(&result.yaml).unwrap();
    let up = gateway
        .upstreams
        .iter()
        .find(|u| u.name == "svc-upstream")
        .expect("upstream");
    assert_eq!(up.endpoints[0].address, "10.0.0.1");
    assert_eq!(up.endpoints[0].port, 8080);
}

#[test]
fn kong_multiple_paths_creates_multiple_routes() {
    let conf = r#"
services:
  - name: svc
    url: http://127.0.0.1:9000
routes:
  - name: multi
    service:
      name: svc
    paths:
      - /api
      - /web
"#;
    let result = import_kong(conf, false).unwrap();
    assert_eq!(result.route_count, 2);
}

#[test]
fn kong_strip_path_warning() {
    let conf = r#"
services:
  - name: svc
    url: http://127.0.0.1:9000
routes:
  - name: r
    service:
      name: svc
    paths:
      - /api
    strip_path: true
"#;
    let result = import_kong(conf, false).unwrap();
    assert!(result.yaml.contains("strip_path"));
}
