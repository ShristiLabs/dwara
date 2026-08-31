//! Unit tests for the Envoy import module (`dwara_cli::import_envoy`).
//!
//! These tests exercise the public `import_envoy` function: parsing
//! Envoy static configs, generating Dwara config YAML, and verifying
//! listener/cluster/route generation and warning emission for
//! unsupported filters.

use dwara_cli::import_envoy::import_envoy;

#[test]
fn parse_listener_and_cluster() {
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
                            prefix: /api
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
    assert!(result.yaml.contains("main"));
    assert!(result.yaml.contains("8080"));
    assert!(result.yaml.contains("9000"));
    assert!(result.yaml.contains("/api"));
}

#[test]
fn http_filter_generates_warning() {
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
                            prefix: /
                          route:
                            cluster: c
                http_filters:
                  - name: envoy.filters.http.router
                  - name: envoy.filters.http.compressor
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
    assert!(result.yaml.contains("compressor"));
}

#[test]
fn empty_config_produces_empty_gateway() {
    let result = import_envoy("").unwrap();
    assert_eq!(result.route_count, 0);
}

#[test]
fn multiple_routes_from_virtual_host() {
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
                            prefix: /api
                          route:
                            cluster: c
                        - match:
                            prefix: /web
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
    assert_eq!(result.route_count, 2);
}

#[test]
fn cluster_without_endpoints_warns() {
    let conf = r#"
static_resources:
  clusters:
    - name: empty-cluster
      load_assignment: {}
"#;
    let result = import_envoy(conf).unwrap();
    assert!(result.yaml.contains("no resolvable endpoints"));
}

#[test]
fn route_without_cluster_uses_first_cluster() {
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
                            prefix: /
                          route: {}
                http_filters:
                  - name: envoy.filters.http.router
  clusters:
    - name: default
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
    assert!(result.yaml.contains("default"));
}
