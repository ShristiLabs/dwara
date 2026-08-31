//! Unit tests for `k8s_gateway` (relocated from src; the private
//! `route_attaches_to` helper tests are rewritten to use the public
//! `translate` API and assert route presence/absence).

use std::collections::HashMap;

use dwara_core::config::{Endpoint as DwaraEndpoint, PathMatchKind, RouteAction, TlsMode};
use dwara_core::k8s_gateway::{
    endpoint_key, translate, Gateway, GatewayListener, GatewaySpec, HttpBackendRef, HttpPathMatch,
    HttpRoute, HttpRouteMatch, HttpRouteRule, HttpRouteSpec, ListenerTlsConfig, ObjectMeta,
    ParentReference, SecretObjectReference,
};

fn make_gateway(name: &str, listeners: Vec<GatewayListener>) -> Gateway {
    Gateway {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: "Gateway".to_string(),
        metadata: ObjectMeta {
            name: name.to_string(),
            namespace: Some("default".to_string()),
        },
        spec: GatewaySpec {
            gateway_class_name: "dwara".to_string(),
            listeners,
        },
    }
}

fn make_http_listener(port: u16) -> GatewayListener {
    GatewayListener {
        name: "http".to_string(),
        port,
        protocol: "HTTP".to_string(),
        hostname: None,
        tls: None,
    }
}

fn make_https_listener(port: u16, hostname: &str) -> GatewayListener {
    GatewayListener {
        name: "https".to_string(),
        port,
        protocol: "HTTPS".to_string(),
        hostname: Some(hostname.to_string()),
        tls: Some(ListenerTlsConfig {
            mode: "Terminate".to_string(),
            certificate_refs: vec![SecretObjectReference {
                kind: "Secret".to_string(),
                name: "tls-cert".to_string(),
                namespace: None,
            }],
            frontend_validation: None,
        }),
    }
}

fn make_route(name: &str, gateway_name: &str, rules: Vec<HttpRouteRule>) -> HttpRoute {
    HttpRoute {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: "HTTPRoute".to_string(),
        metadata: ObjectMeta {
            name: name.to_string(),
            namespace: Some("default".to_string()),
        },
        spec: HttpRouteSpec {
            parent_refs: vec![ParentReference {
                kind: "Gateway".to_string(),
                name: gateway_name.to_string(),
                namespace: None,
                section_name: None,
            }],
            hostnames: vec![],
            rules,
        },
    }
}

fn make_backend_ref(name: &str, port: u16) -> HttpBackendRef {
    HttpBackendRef {
        kind: "Service".to_string(),
        name: name.to_string(),
        namespace: None,
        port: Some(port),
        weight: 1,
    }
}

fn make_path_match(match_type: &str, value: &str) -> HttpRouteMatch {
    HttpRouteMatch {
        path: Some(HttpPathMatch {
            match_type: match_type.to_string(),
            value: value.to_string(),
        }),
        headers: vec![],
        query_params: vec![],
    }
}

fn make_endpoint(ip: &str, port: u16) -> DwaraEndpoint {
    DwaraEndpoint {
        address: ip.to_string(),
        port,
        weight: 1,
    }
}

#[test]
fn translate_simple_gateway() {
    let gw = make_gateway("my-gateway", vec![make_http_listener(8080)]);
    let result = translate(&gw, &[], &HashMap::new()).unwrap();

    assert_eq!(result.gateway.listeners.len(), 1);
    assert_eq!(result.gateway.listeners[0].name, "http");
    assert_eq!(result.gateway.listeners[0].port, 8080);
    assert_eq!(
        result.gateway.listeners[0].protocol,
        dwara_core::config::ListenerProtocol::Http
    );
    assert!(result.gateway.listeners[0].tls.is_none());
}

#[test]
fn translate_https_gateway_with_tls() {
    let gw = make_gateway("my-gateway", vec![make_https_listener(8443, "example.com")]);
    let result = translate(&gw, &[], &HashMap::new()).unwrap();

    assert_eq!(result.gateway.listeners.len(), 1);
    let tls = result.gateway.listeners[0].tls.as_ref().unwrap();
    assert_eq!(tls.mode, TlsMode::Terminate);
    assert_eq!(tls.certificates.len(), 1);
    assert_eq!(tls.certificates[0].server_names, vec!["example.com"]);
}

#[test]
fn translate_passthrough_tls() {
    let listener = GatewayListener {
        name: "tls".to_string(),
        port: 8443,
        protocol: "TLS".to_string(),
        hostname: None,
        tls: Some(ListenerTlsConfig {
            mode: "Passthrough".to_string(),
            certificate_refs: vec![],
            frontend_validation: None,
        }),
    };
    let gw = make_gateway("my-gateway", vec![listener]);
    let result = translate(&gw, &[], &HashMap::new()).unwrap();

    let tls = result.gateway.listeners[0].tls.as_ref().unwrap();
    assert_eq!(tls.mode, TlsMode::Passthrough);
}

#[test]
fn translate_route_with_prefix_match() {
    let gw = make_gateway("my-gateway", vec![make_http_listener(8080)]);
    let route = make_route(
        "my-route",
        "my-gateway",
        vec![HttpRouteRule {
            matches: vec![make_path_match("PathPrefix", "/api")],
            backend_refs: vec![make_backend_ref("my-service", 8080)],
            filters: vec![],
        }],
    );

    let mut endpoints = HashMap::new();
    endpoints.insert(
        "default/my-service:8080".to_string(),
        vec![make_endpoint("10.0.0.1", 8080)],
    );

    let result = translate(&gw, &[route], &endpoints).unwrap();

    assert_eq!(result.gateway.routes.len(), 1);
    assert_eq!(result.gateway.services.len(), 1);
    assert_eq!(result.gateway.upstreams.len(), 1);
    assert_eq!(result.gateway.upstreams[0].endpoints.len(), 1);
    assert_eq!(
        result.gateway.routes[0].r#match.path.kind,
        PathMatchKind::Prefix
    );
    assert_eq!(result.gateway.routes[0].r#match.path.value, "/api");
}

#[test]
fn translate_route_with_exact_match() {
    let gw = make_gateway("my-gateway", vec![make_http_listener(8080)]);
    let route = make_route(
        "my-route",
        "my-gateway",
        vec![HttpRouteRule {
            matches: vec![make_path_match("Exact", "/health")],
            backend_refs: vec![make_backend_ref("my-service", 8080)],
            filters: vec![],
        }],
    );

    let mut endpoints = HashMap::new();
    endpoints.insert(
        "default/my-service:8080".to_string(),
        vec![make_endpoint("10.0.0.1", 8080)],
    );

    let result = translate(&gw, &[route], &endpoints).unwrap();

    assert_eq!(result.gateway.routes.len(), 1);
    assert_eq!(
        result.gateway.routes[0].r#match.path.kind,
        PathMatchKind::Exact
    );
    assert_eq!(result.gateway.routes[0].r#match.path.value, "/health");
}

#[test]
fn translate_route_with_no_match_matches_all() {
    let gw = make_gateway("my-gateway", vec![make_http_listener(8080)]);
    let route = make_route(
        "my-route",
        "my-gateway",
        vec![HttpRouteRule {
            matches: vec![],
            backend_refs: vec![make_backend_ref("my-service", 8080)],
            filters: vec![],
        }],
    );

    let mut endpoints = HashMap::new();
    endpoints.insert(
        "default/my-service:8080".to_string(),
        vec![make_endpoint("10.0.0.1", 8080)],
    );

    let result = translate(&gw, &[route], &endpoints).unwrap();

    assert_eq!(result.gateway.routes.len(), 1);
    assert_eq!(
        result.gateway.routes[0].r#match.path.kind,
        PathMatchKind::Prefix
    );
    assert_eq!(result.gateway.routes[0].r#match.path.value, "/");
}

#[test]
fn translate_route_with_no_backends_warns() {
    let gw = make_gateway("my-gateway", vec![make_http_listener(8080)]);
    let route = make_route(
        "my-route",
        "my-gateway",
        vec![HttpRouteRule {
            matches: vec![make_path_match("PathPrefix", "/api")],
            backend_refs: vec![],
            filters: vec![],
        }],
    );

    let result = translate(&gw, &[route], &HashMap::new()).unwrap();

    assert!(result.warnings.iter().any(|w| w.contains("no backends")));
}

#[test]
fn translate_route_with_missing_endpoints_warns() {
    let gw = make_gateway("my-gateway", vec![make_http_listener(8080)]);
    let route = make_route(
        "my-route",
        "my-gateway",
        vec![HttpRouteRule {
            matches: vec![make_path_match("PathPrefix", "/api")],
            backend_refs: vec![make_backend_ref("my-service", 8080)],
            filters: vec![],
        }],
    );

    let result = translate(&gw, &[route], &HashMap::new()).unwrap();

    assert!(result.warnings.iter().any(|w| w.contains("no endpoints")));
}

// Rewritten from the private `route_attaches_to` tests: instead of
// calling the private helper, we verify via `translate` that a route
// attaching to the correct gateway is included, and a route attaching
// to a different gateway is skipped.
#[test]
fn route_attaches_to_correct_gateway() {
    let gw = make_gateway("my-gateway", vec![make_http_listener(8080)]);
    let route = make_route(
        "my-route",
        "my-gateway",
        vec![HttpRouteRule {
            matches: vec![],
            backend_refs: vec![make_backend_ref("svc", 80)],
            filters: vec![],
        }],
    );

    let result = translate(&gw, &[route], &HashMap::new()).unwrap();
    // Route attaches to "my-gateway" -> it is included.
    assert_eq!(result.gateway.routes.len(), 1);
}

#[test]
fn route_attaches_to_wrong_gateway_is_skipped() {
    let gw = make_gateway("my-gateway", vec![make_http_listener(8080)]);
    let route = make_route(
        "my-route",
        "other-gateway",
        vec![HttpRouteRule {
            matches: vec![make_path_match("PathPrefix", "/api")],
            backend_refs: vec![make_backend_ref("svc", 80)],
            filters: vec![],
        }],
    );

    let result = translate(&gw, &[route], &HashMap::new()).unwrap();
    // Route does NOT attach to "my-gateway" -> it is skipped.
    assert_eq!(result.gateway.routes.len(), 0);
}

// Rewritten from the private `route_attaches_to` test: a route with
// no parent refs attaches to all gateways. Verify via `translate`.
#[test]
fn route_with_no_parent_refs_attaches_to_all() {
    let gw = make_gateway("my-gateway", vec![make_http_listener(8080)]);
    let route = HttpRoute {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: "HTTPRoute".to_string(),
        metadata: ObjectMeta {
            name: "my-route".to_string(),
            namespace: Some("default".to_string()),
        },
        spec: HttpRouteSpec {
            parent_refs: vec![],
            hostnames: vec![],
            rules: vec![HttpRouteRule {
                matches: vec![make_path_match("PathPrefix", "/api")],
                backend_refs: vec![make_backend_ref("svc", 80)],
                filters: vec![],
            }],
        },
    };

    let result = translate(&gw, &[route], &HashMap::new()).unwrap();
    // No parent refs -> attaches to all gateways -> route is included.
    assert_eq!(result.gateway.routes.len(), 1);
}

#[test]
fn translate_multiple_rules() {
    let gw = make_gateway("my-gateway", vec![make_http_listener(8080)]);
    let route = make_route(
        "my-route",
        "my-gateway",
        vec![
            HttpRouteRule {
                matches: vec![make_path_match("PathPrefix", "/api")],
                backend_refs: vec![make_backend_ref("api-svc", 8080)],
                filters: vec![],
            },
            HttpRouteRule {
                matches: vec![make_path_match("PathPrefix", "/web")],
                backend_refs: vec![make_backend_ref("web-svc", 8080)],
                filters: vec![],
            },
        ],
    );

    let mut endpoints = HashMap::new();
    endpoints.insert(
        "default/api-svc:8080".to_string(),
        vec![make_endpoint("10.0.0.1", 8080)],
    );
    endpoints.insert(
        "default/web-svc:8080".to_string(),
        vec![make_endpoint("10.0.0.2", 8080)],
    );

    let result = translate(&gw, &[route], &endpoints).unwrap();

    assert_eq!(result.gateway.routes.len(), 2);
    assert_eq!(result.gateway.services.len(), 2);
    assert_eq!(result.gateway.upstreams.len(), 2);
}

#[test]
fn translate_multiple_listeners() {
    let gw = make_gateway(
        "my-gateway",
        vec![
            make_http_listener(8080),
            make_https_listener(8443, "api.example.com"),
        ],
    );
    let result = translate(&gw, &[], &HashMap::new()).unwrap();

    assert_eq!(result.gateway.listeners.len(), 2);
    assert!(result.gateway.listeners[0].tls.is_none());
    assert!(result.gateway.listeners[1].tls.is_some());
}

#[test]
fn endpoint_key_format() {
    assert_eq!(
        endpoint_key("default", "my-svc", 8080),
        "default/my-svc:8080"
    );
}

#[test]
fn translate_unknown_tls_mode_defaults_to_terminate() {
    let listener = GatewayListener {
        name: "https".to_string(),
        port: 8443,
        protocol: "HTTPS".to_string(),
        hostname: None,
        tls: Some(ListenerTlsConfig {
            mode: "Unknown".to_string(),
            certificate_refs: vec![],
            frontend_validation: None,
        }),
    };
    let gw = make_gateway("my-gateway", vec![listener]);
    let result = translate(&gw, &[], &HashMap::new()).unwrap();

    assert!(result
        .warnings
        .iter()
        .any(|w| w.contains("unknown TLS mode")));
    let tls = result.gateway.listeners[0].tls.as_ref().unwrap();
    assert_eq!(tls.mode, TlsMode::Terminate);
}

#[test]
fn translate_route_not_attaching_is_skipped() {
    let gw = make_gateway("my-gateway", vec![make_http_listener(8080)]);
    let route = make_route(
        "my-route",
        "other-gateway",
        vec![HttpRouteRule {
            matches: vec![make_path_match("PathPrefix", "/api")],
            backend_refs: vec![make_backend_ref("svc", 80)],
            filters: vec![],
        }],
    );

    let result = translate(&gw, &[route], &HashMap::new()).unwrap();
    assert_eq!(result.gateway.routes.len(), 0);
}

#[test]
fn translate_multiple_endpoints_for_backend() {
    let gw = make_gateway("my-gateway", vec![make_http_listener(8080)]);
    let route = make_route(
        "my-route",
        "my-gateway",
        vec![HttpRouteRule {
            matches: vec![make_path_match("PathPrefix", "/api")],
            backend_refs: vec![make_backend_ref("my-service", 8080)],
            filters: vec![],
        }],
    );

    let mut endpoints = HashMap::new();
    endpoints.insert(
        "default/my-service:8080".to_string(),
        vec![
            make_endpoint("10.0.0.1", 8080),
            make_endpoint("10.0.0.2", 8080),
            make_endpoint("10.0.0.3", 8080),
        ],
    );

    let result = translate(&gw, &[route], &endpoints).unwrap();
    assert_eq!(result.gateway.upstreams[0].endpoints.len(), 3);
}

#[test]
fn translate_route_action_is_proxy() {
    let gw = make_gateway("my-gateway", vec![make_http_listener(8080)]);
    let route = make_route(
        "my-route",
        "my-gateway",
        vec![HttpRouteRule {
            matches: vec![make_path_match("PathPrefix", "/api")],
            backend_refs: vec![make_backend_ref("svc", 80)],
            filters: vec![],
        }],
    );

    let mut endpoints = HashMap::new();
    endpoints.insert(
        "default/svc:80".to_string(),
        vec![make_endpoint("10.0.0.1", 80)],
    );

    let result = translate(&gw, &[route], &endpoints).unwrap();
    assert!(matches!(
        result.gateway.routes[0].action,
        RouteAction::Proxy { .. }
    ));
}

#[test]
fn translate_route_with_no_backends_responds_503() {
    let gw = make_gateway("my-gateway", vec![make_http_listener(8080)]);
    let route = make_route(
        "my-route",
        "my-gateway",
        vec![HttpRouteRule {
            matches: vec![make_path_match("PathPrefix", "/api")],
            backend_refs: vec![],
            filters: vec![],
        }],
    );

    let result = translate(&gw, &[route], &HashMap::new()).unwrap();
    match &result.gateway.routes[0].action {
        RouteAction::Respond { status, .. } => assert_eq!(*status, 503),
        other => panic!("expected Respond, got {other:?}"),
    }
}

#[test]
fn translate_unknown_protocol_defaults_to_http() {
    let listener = GatewayListener {
        name: "weird".to_string(),
        port: 9999,
        protocol: "Unknown".to_string(),
        hostname: None,
        tls: None,
    };
    let gw = make_gateway("my-gateway", vec![listener]);
    let result = translate(&gw, &[], &HashMap::new()).unwrap();

    assert!(result
        .warnings
        .iter()
        .any(|w| w.contains("unknown protocol")));
    assert_eq!(
        result.gateway.listeners[0].protocol,
        dwara_core::config::ListenerProtocol::Http
    );
}
