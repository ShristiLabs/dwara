//! NGINX import integration tests (DW-065).
//!
//! Exercises the `dwara_cli::import_nginx` module: parsing NGINX
//! configs, generating Dwara config YAML, and verifying the generated
//! config round-trips through `parse_gateway` + validation.

use dwara_cli::import_nginx::import_nginx;
use dwara_core::config::{parse_gateway, PathMatchKind};

const SIMPLE_NGINX: &str = r#"
http {
    server {
        listen 8080;
        server_name api.example.com;
        location /api {
            proxy_pass http://127.0.0.1:9000;
        }
    }
}
"#;

const UPSTREAM_NGINX: &str = r#"
http {
    upstream backend {
        server 127.0.0.1:9000;
        server 127.0.0.1:9001;
    }
    server {
        listen 8080;
        location /api {
            proxy_pass http://backend;
        }
    }
}
"#;

const MIXED_NGINX: &str = r#"
http {
    upstream backend {
        server 127.0.0.1:9000;
        server 127.0.0.1:9001;
    }
    server {
        listen 80;
        server_name example.com;
        location = /health {
            proxy_pass http://127.0.0.1:9000;
        }
        location /api {
            proxy_pass http://backend;
        }
        location ~ ^/v[0-9]+/ {
            proxy_pass http://127.0.0.1:9002;
        }
        location /old {
            rewrite ^/old/(.*)$ /new/$1 permanent;
            proxy_pass http://127.0.0.1:9000;
        }
        location /static {
            root /var/www;
        }
    }
}
"#;

#[test]
fn simple_nginx_import_generates_valid_config() {
    let result = import_nginx(SIMPLE_NGINX).unwrap();
    assert_eq!(result.route_count, 1);

    // The generated YAML must round-trip through parse_gateway.
    let gateway = parse_gateway(&result.yaml).unwrap();
    assert_eq!(gateway.routes.len(), 1);
    assert_eq!(gateway.routes[0].r#match.path.kind, PathMatchKind::Prefix);
    assert_eq!(gateway.routes[0].r#match.path.value, "/api");
}

#[test]
fn upstream_nginx_import_generates_valid_config() {
    let result = import_nginx(UPSTREAM_NGINX).unwrap();
    assert_eq!(result.route_count, 1);

    let gateway = parse_gateway(&result.yaml).unwrap();
    assert_eq!(gateway.routes.len(), 1);
    assert_eq!(gateway.upstreams.len(), 1);
    assert_eq!(gateway.upstreams[0].endpoints.len(), 2);
    assert_eq!(gateway.upstreams[0].endpoints[0].port, 9000);
    assert_eq!(gateway.upstreams[0].endpoints[1].port, 9001);
}

#[test]
fn mixed_nginx_import_generates_valid_config() {
    let result = import_nginx(MIXED_NGINX).unwrap();
    assert_eq!(result.route_count, 4);

    // The generated YAML must round-trip through parse_gateway.
    let gateway = parse_gateway(&result.yaml).unwrap();
    assert_eq!(gateway.routes.len(), 4);

    // Verify route match types.
    let exact = gateway
        .routes
        .iter()
        .find(|r| r.r#match.path.kind == PathMatchKind::Exact)
        .expect("exact match route");
    assert_eq!(exact.r#match.path.value, "/health");

    let regex = gateway
        .routes
        .iter()
        .find(|r| r.r#match.path.kind == PathMatchKind::Regex)
        .expect("regex match route");
    assert!(regex.r#match.path.value.starts_with('/'));

    // Verify warnings are present.
    assert!(result.yaml.contains("rewrite"));
    assert!(result.yaml.contains("no proxy_pass"));
}

#[test]
fn empty_nginx_config_produces_empty_gateway() {
    let result = import_nginx("").unwrap();
    assert_eq!(result.route_count, 0);

    let gateway = parse_gateway(&result.yaml).unwrap();
    assert_eq!(gateway.routes.len(), 0);
}

#[test]
fn nginx_import_with_unsupported_directives_warns() {
    let conf = r#"
server {
    listen 80;
    location /api {
        proxy_pass http://127.0.0.1:9000;
        limit_req zone=api burst=10;
        auth_basic "restricted";
    }
}
"#;
    let result = import_nginx(conf).unwrap();
    assert!(result.yaml.contains("limit_req"));
    assert!(result.yaml.contains("auth_basic"));
}
