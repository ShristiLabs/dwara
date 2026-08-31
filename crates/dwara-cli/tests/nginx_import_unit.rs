//! Unit tests for the NGINX import module (`dwara_cli::import_nginx`).
//!
//! These tests exercise the public `import_nginx` function: parsing
//! NGINX config files, generating Dwara config YAML, and verifying
//! route generation, match-type conversion, and warning emission for
//! unsupported directives.

use dwara_cli::import_nginx::import_nginx;

#[test]
fn parse_simple_server_with_location() {
    let conf = r#"
http {
    server {
        listen 8080;
        server_name example.com;
        location /api {
            proxy_pass http://127.0.0.1:9000;
        }
    }
}
"#;
    let result = import_nginx(conf).unwrap();
    assert!(result.yaml.contains("route-0"));
    assert!(result.yaml.contains("9000"));
}

#[test]
fn parse_upstream_block() {
    let conf = r#"
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
    let result = import_nginx(conf).unwrap();
    assert!(result.yaml.contains("backend-upstream"));
    assert!(result.yaml.contains("backend-service"));
    assert!(result.yaml.contains("9000"));
    assert!(result.yaml.contains("9001"));
}

#[test]
fn exact_match_location() {
    let conf = r#"
server {
    listen 80;
    location = /health {
        proxy_pass http://127.0.0.1:9000;
    }
}
"#;
    let result = import_nginx(conf).unwrap();
    assert!(result.yaml.contains("exact"));
    assert!(result.yaml.contains("/health"));
}

#[test]
fn regex_match_location() {
    let conf = r#"
server {
    listen 80;
    location ~ ^/api/v[0-9]+/ {
        proxy_pass http://127.0.0.1:9000;
    }
}
"#;
    let result = import_nginx(conf).unwrap();
    assert!(result.yaml.contains("regex"));
    // The '^' is stripped and '/' is ensured.
    assert!(result.yaml.contains("/api/v[0-9]+/"));
}

#[test]
fn unsupported_directives_generate_warnings() {
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

#[test]
fn location_without_proxy_pass_skipped() {
    let conf = r#"
server {
    listen 80;
    location /static {
        root /var/www;
    }
}
"#;
    let result = import_nginx(conf).unwrap();
    assert_eq!(result.route_count, 0);
    assert!(result.yaml.contains("no proxy_pass"));
}

#[test]
fn multiple_locations() {
    let conf = r#"
server {
    listen 80;
    location /api {
        proxy_pass http://127.0.0.1:9000;
    }
    location /web {
        proxy_pass http://127.0.0.1:9001;
    }
}
"#;
    let result = import_nginx(conf).unwrap();
    assert_eq!(result.route_count, 2);
}

#[test]
fn parse_listen_with_ip() {
    let conf = r#"
server {
    listen 127.0.0.1:8080;
    location /api {
        proxy_pass http://127.0.0.1:9000;
    }
}
"#;
    let result = import_nginx(conf).unwrap();
    assert_eq!(result.route_count, 1);
}

#[test]
fn empty_config_produces_empty_gateway() {
    let conf = "";
    let result = import_nginx(conf).unwrap();
    assert_eq!(result.route_count, 0);
}

#[test]
fn comments_ignored() {
    let conf = r#"
# This is a comment
server {
    listen 80; # inline comment
    location /api {
        proxy_pass http://127.0.0.1:9000;
    }
}
"#;
    let result = import_nginx(conf).unwrap();
    assert_eq!(result.route_count, 1);
}

#[test]
fn rewrite_directive_warning() {
    let conf = r#"
server {
    listen 80;
    location /old {
        rewrite ^/old/(.*)$ /new/$1 permanent;
        proxy_pass http://127.0.0.1:9000;
    }
}
"#;
    let result = import_nginx(conf).unwrap();
    assert!(result.yaml.contains("rewrite"));
}
