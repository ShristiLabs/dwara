//! Envoy import integration tests (DW-065).
//!
//! Exercises the `dwara_cli::import_envoy` module: parsing Envoy
//! static configs (YAML), generating Dwara config YAML, and verifying
//! the generated config round-trips through `parse_gateway` +
//! validation.

use dwara_cli::import_envoy::import_envoy;
use dwara_core::config::{parse_gateway, PathMatchKind};

const SIMPLE_ENVOY: &str = r#"
static_resources:
  listeners:
    - name: main
      address:
        socket_address:
          address: 127.0.0.1
          port_value: 8080
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                route_config:
                  virtual_hosts:
                    - name: backend
                      domains:
                        - "*"
                      routes:
                        - match:
                            prefix: /api
                          route:
                            cluster: backend_cluster
                http_filters:
                  - name: envoy.filters.http.router
  clusters:
    - name: backend_cluster
      load_assignment:
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: 127.0.0.1
                      port_value: 9000
"#;

const ENVOY_WITH_FILTERS: &str = r#"
static_resources:
  listeners:
    - name: main
      address:
        socket_address:
          address: 127.0.0.1
          port_value: 8080
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                route_config:
                  virtual_hosts:
                    - name: backend
                      domains:
                        - api.example.com
                      routes:
                        - match:
                            prefix: /api
                          route:
                            cluster: backend_cluster
                http_filters:
                  - name: envoy.filters.http.router
                  - name: envoy.filters.http.ext_authz
                  - name: envoy.filters.http.ratelimit
  clusters:
    - name: backend_cluster
      load_assignment:
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: 127.0.0.1
                      port_value: 9000
"#;

const ENVOY_MULTIPLE_ENDPOINTS: &str = r#"
static_resources:
  clusters:
    - name: multi
      load_assignment:
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: 127.0.0.1
                      port_value: 9000
              - endpoint:
                  address:
                    socket_address:
                      address: 127.0.0.1
                      port_value: 9001
"#;

#[test]
fn simple_envoy_import_generates_valid_config() {
    let result = import_envoy(SIMPLE_ENVOY).unwrap();
    assert_eq!(result.route_count, 1);

    let gateway = parse_gateway(&result.yaml).unwrap();
    assert_eq!(gateway.listeners.len(), 1);
    assert_eq!(gateway.listeners[0].name, "main");
    assert_eq!(gateway.listeners[0].port, 8080);
    assert_eq!(gateway.routes.len(), 1);
    assert_eq!(gateway.routes[0].r#match.path.kind, PathMatchKind::Prefix);
    assert_eq!(gateway.routes[0].r#match.path.value, "/api");
    assert_eq!(gateway.routes[0].service, "backend_cluster");
    assert_eq!(gateway.upstreams.len(), 1);
    assert_eq!(gateway.upstreams[0].name, "backend_cluster");
    assert_eq!(gateway.upstreams[0].endpoints[0].port, 9000);
}

#[test]
fn envoy_with_filters_warns() {
    let result = import_envoy(ENVOY_WITH_FILTERS).unwrap();
    assert!(result.yaml.contains("ext_authz"));
    assert!(result.yaml.contains("ratelimit"));
    assert!(result.yaml.contains("filter"));

    let gateway = parse_gateway(&result.yaml).unwrap();
    assert_eq!(
        gateway.routes[0].r#match.host.as_deref(),
        Some("api.example.com")
    );
}

#[test]
fn envoy_multiple_endpoints() {
    let result = import_envoy(ENVOY_MULTIPLE_ENDPOINTS).unwrap();
    let gateway = parse_gateway(&result.yaml).unwrap();
    let up = gateway
        .upstreams
        .iter()
        .find(|u| u.name == "multi")
        .expect("multi upstream");
    assert_eq!(up.endpoints.len(), 2);
    assert_eq!(up.endpoints[0].port, 9000);
    assert_eq!(up.endpoints[1].port, 9001);
}

#[test]
fn empty_envoy_config_produces_empty_gateway() {
    let result = import_envoy("").unwrap();
    assert_eq!(result.route_count, 0);

    let gateway = parse_gateway(&result.yaml).unwrap();
    assert_eq!(gateway.routes.len(), 0);
}

#[test]
fn envoy_exact_path_match() {
    let conf = r#"
static_resources:
  listeners:
    - name: main
      address:
        socket_address:
          address: 127.0.0.1
          port_value: 8080
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                route_config:
                  virtual_hosts:
                    - name: vh
                      domains:
                        - "*"
                      routes:
                        - match:
                            path: /health
                          route:
                            cluster: c
                http_filters:
                  - name: envoy.filters.http.router
  clusters:
    - name: c
      load_assignment:
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: 127.0.0.1
                      port_value: 9000
"#;
    let result = import_envoy(conf).unwrap();
    let gateway = parse_gateway(&result.yaml).unwrap();
    assert_eq!(gateway.routes[0].r#match.path.kind, PathMatchKind::Exact);
    assert_eq!(gateway.routes[0].r#match.path.value, "/health");
}

#[test]
fn envoy_dns_cluster_warns() {
    let conf = r#"
static_resources:
  clusters:
    - name: dns-cluster
      type: STRICT_DNS
      load_assignment:
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: 127.0.0.1
                      port_value: 9000
"#;
    let result = import_envoy(conf).unwrap();
    assert!(result.yaml.contains("DNS"));
}

#[test]
fn envoy_network_filter_warns() {
    let conf = r#"
static_resources:
  listeners:
    - name: main
      address:
        socket_address:
          address: 127.0.0.1
          port_value: 8080
      filter_chains:
        - filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config: {}
"#;
    let result = import_envoy(conf).unwrap();
    assert!(result.yaml.contains("tcp_proxy"));
}
