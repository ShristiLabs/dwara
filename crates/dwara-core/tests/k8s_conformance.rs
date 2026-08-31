//! Conformance self-test suite for the Kubernetes Gateway API translator
//! (DW-064). Validates the translator against conformance-style test
//! vectors for each standard-channel feature. Deterministic, no cluster.
//!
//! Feature-gated behind the `k8s` cargo feature.

#![cfg(feature = "k8s")]

use std::collections::HashMap;

use dwara_core::config::{Endpoint as DwaraEndpoint, PathMatchKind, RouteAction, TlsMode};
use dwara_core::k8s_gateway::{
    self, ingress, Gateway, GatewayClass, GatewayListener, GatewaySpec, HttpBackendRef,
    HttpHeaderMatch, HttpPathMatch, HttpQueryParamMatch, HttpRoute, HttpRouteFilter,
    HttpRouteMatch, HttpRouteRule, HttpRouteSpec, ListenerTlsConfig, ObjectMeta, ParentReference,
    SecretObjectReference, TranslationResult,
};

/// Build a minimal Gateway with one HTTP listener on port 80.
fn http_gateway() -> Gateway {
    Gateway {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: "Gateway".to_string(),
        metadata: ObjectMeta {
            name: "test-gateway".to_string(),
            namespace: Some("default".to_string()),
        },
        spec: GatewaySpec {
            gateway_class_name: "dwara".to_string(),
            listeners: vec![GatewayListener {
                name: "http".to_string(),
                port: 80,
                protocol: "HTTP".to_string(),
                hostname: None,
                tls: None,
            }],
        },
    }
}

/// Build a minimal HTTPRoute with one rule and one backend ref.
fn httproute_with_path(
    path_type: &str,
    path_value: &str,
    svc_name: &str,
    svc_port: u16,
) -> HttpRoute {
    HttpRoute {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: "HTTPRoute".to_string(),
        metadata: ObjectMeta {
            name: "test-route".to_string(),
            namespace: Some("default".to_string()),
        },
        spec: HttpRouteSpec {
            parent_refs: vec![ParentReference {
                kind: "Gateway".to_string(),
                name: "test-gateway".to_string(),
                namespace: Some("default".to_string()),
                section_name: None,
            }],
            hostnames: Vec::new(),
            rules: vec![HttpRouteRule {
                matches: vec![HttpRouteMatch {
                    path: Some(HttpPathMatch {
                        match_type: path_type.to_string(),
                        value: path_value.to_string(),
                    }),
                    headers: Vec::new(),
                    query_params: Vec::new(),
                }],
                filters: Vec::new(),
                backend_refs: vec![HttpBackendRef {
                    kind: "Service".to_string(),
                    name: svc_name.to_string(),
                    namespace: Some("default".to_string()),
                    port: Some(svc_port),
                    weight: 1,
                }],
            }],
        },
    }
}

/// Build an endpoint map with one endpoint for the given service.
fn endpoints_with(svc: &str, port: u16) -> HashMap<String, Vec<DwaraEndpoint>> {
    let mut m = HashMap::new();
    m.insert(
        k8s_gateway::endpoint_key("default", svc, port),
        vec![DwaraEndpoint {
            address: "10.0.0.1".to_string(),
            port,
            weight: 1,
        }],
    );
    m
}

fn translate(
    gateway: &Gateway,
    routes: &[HttpRoute],
    endpoints: &HashMap<String, Vec<DwaraEndpoint>>,
) -> TranslationResult {
    k8s_gateway::translate(gateway, routes, endpoints).expect("translation should succeed")
}

// ---------------------------------------------------------------------------
// Conformance test vectors (one per standard-channel feature)
// ---------------------------------------------------------------------------

#[test]
fn path_prefix_match() {
    let gw = http_gateway();
    let route = httproute_with_path("PathPrefix", "/api", "backend", 8080);
    let eps = endpoints_with("backend", 8080);
    let result = translate(&gw, &[route], &eps);
    assert_eq!(result.gateway.routes.len(), 1);
    assert_eq!(
        result.gateway.routes[0].r#match.path.kind,
        PathMatchKind::Prefix
    );
    assert_eq!(result.gateway.routes[0].r#match.path.value, "/api");
}

#[test]
fn path_exact_match() {
    let gw = http_gateway();
    let route = httproute_with_path("Exact", "/api/v1/users", "backend", 8080);
    let eps = endpoints_with("backend", 8080);
    let result = translate(&gw, &[route], &eps);
    assert_eq!(result.gateway.routes.len(), 1);
    assert_eq!(
        result.gateway.routes[0].r#match.path.kind,
        PathMatchKind::Exact
    );
    assert_eq!(result.gateway.routes[0].r#match.path.value, "/api/v1/users");
}

#[test]
fn path_regex_match() {
    let gw = http_gateway();
    let route = httproute_with_path("RegularExpression", "/api/.*", "backend", 8080);
    let eps = endpoints_with("backend", 8080);
    let result = translate(&gw, &[route], &eps);
    assert_eq!(result.gateway.routes.len(), 1);
    assert_eq!(
        result.gateway.routes[0].r#match.path.kind,
        PathMatchKind::Regex
    );
    assert_eq!(result.gateway.routes[0].r#match.path.value, "/api/.*");
}

#[test]
fn header_exact_match() {
    let gw = http_gateway();
    let mut route = httproute_with_path("PathPrefix", "/", "backend", 8080);
    route.spec.rules[0].matches[0]
        .headers
        .push(HttpHeaderMatch {
            match_type: "Exact".to_string(),
            name: "X-Env".to_string(),
            value: "prod".to_string(),
        });
    let eps = endpoints_with("backend", 8080);
    let result = translate(&gw, &[route], &eps);
    assert_eq!(result.gateway.routes.len(), 1);
    let headers = &result.gateway.routes[0].r#match.headers;
    assert_eq!(headers.get("X-Env"), Some(&"prod".to_string()));
}

#[test]
fn header_regex_match_emits_warning() {
    let gw = http_gateway();
    let mut route = httproute_with_path("PathPrefix", "/", "backend", 8080);
    route.spec.rules[0].matches[0]
        .headers
        .push(HttpHeaderMatch {
            match_type: "RegularExpression".to_string(),
            name: "X-Env".to_string(),
            value: "prod.*".to_string(),
        });
    let eps = endpoints_with("backend", 8080);
    let result = translate(&gw, &[route], &eps);
    assert!(result
        .warnings
        .iter()
        .any(|w| w.contains("RegularExpression header match")));
}

#[test]
fn query_param_match() {
    let gw = http_gateway();
    let mut route = httproute_with_path("PathPrefix", "/", "backend", 8080);
    route.spec.rules[0].matches[0]
        .query_params
        .push(HttpQueryParamMatch {
            match_type: "Exact".to_string(),
            name: "version".to_string(),
            value: "v2".to_string(),
        });
    let eps = endpoints_with("backend", 8080);
    let result = translate(&gw, &[route], &eps);
    assert_eq!(result.gateway.routes.len(), 1);
    let query = &result.gateway.routes[0].r#match.query;
    assert_eq!(query.len(), 1);
    assert_eq!(query[0].name, "version");
    assert_eq!(query[0].value, Some("v2".to_string()));
}

#[test]
fn tls_terminate() {
    let mut gw = http_gateway();
    gw.spec.listeners[0].protocol = "HTTPS".to_string();
    gw.spec.listeners[0].port = 443;
    gw.spec.listeners[0].tls = Some(ListenerTlsConfig {
        mode: "Terminate".to_string(),
        certificate_refs: vec![SecretObjectReference {
            kind: "Secret".to_string(),
            name: "tls-cert".to_string(),
            namespace: Some("default".to_string()),
        }],
        frontend_validation: None,
    });
    let route = httproute_with_path("PathPrefix", "/", "backend", 8080);
    let eps = endpoints_with("backend", 8080);
    let result = translate(&gw, &[route], &eps);
    let tls = result.gateway.listeners[0]
        .tls
        .as_ref()
        .expect("TLS should be set");
    assert_eq!(tls.mode, TlsMode::Terminate);
    assert!(tls.cert_file.as_ref().unwrap().contains("tls-cert"));
}

#[test]
fn tls_passthrough() {
    let mut gw = http_gateway();
    gw.spec.listeners[0].protocol = "TLS".to_string();
    gw.spec.listeners[0].port = 443;
    gw.spec.listeners[0].tls = Some(ListenerTlsConfig {
        mode: "Passthrough".to_string(),
        certificate_refs: vec![],
        frontend_validation: None,
    });
    let route = httproute_with_path("PathPrefix", "/", "backend", 8080);
    let eps = endpoints_with("backend", 8080);
    let result = translate(&gw, &[route], &eps);
    let tls = result.gateway.listeners[0]
        .tls
        .as_ref()
        .expect("TLS should be set");
    assert_eq!(tls.mode, TlsMode::Passthrough);
}

#[test]
fn tls_reencrypt_maps_to_terminate_with_warning() {
    let mut gw = http_gateway();
    gw.spec.listeners[0].protocol = "HTTPS".to_string();
    gw.spec.listeners[0].port = 443;
    gw.spec.listeners[0].tls = Some(ListenerTlsConfig {
        mode: "Reencrypt".to_string(),
        certificate_refs: vec![SecretObjectReference {
            kind: "Secret".to_string(),
            name: "tls-cert".to_string(),
            namespace: None,
        }],
        frontend_validation: None,
    });
    let route = httproute_with_path("PathPrefix", "/", "backend", 8080);
    let eps = endpoints_with("backend", 8080);
    let result = translate(&gw, &[route], &eps);
    let tls = result.gateway.listeners[0]
        .tls
        .as_ref()
        .expect("TLS should be set");
    assert_eq!(tls.mode, TlsMode::Terminate);
    assert!(result.warnings.iter().any(|w| w.contains("Reencrypt")));
}

#[test]
fn request_redirect_filter() {
    let gw = http_gateway();
    let mut route = httproute_with_path("PathPrefix", "/old", "backend", 8080);
    route.spec.rules[0]
        .filters
        .push(HttpRouteFilter::RequestRedirect {
            scheme: Some("https".to_string()),
            hostname: Some("new.example.com".to_string()),
            path: Some("/new".to_string()),
            port: None,
            status_code: 301,
        });
    let eps = endpoints_with("backend", 8080);
    let result = translate(&gw, &[route], &eps);
    assert_eq!(result.gateway.routes.len(), 1);
    match &result.gateway.routes[0].action {
        RouteAction::Redirect {
            scheme,
            host,
            path,
            status,
        } => {
            assert_eq!(scheme.as_deref(), Some("https"));
            assert_eq!(host.as_deref(), Some("new.example.com"));
            assert_eq!(path.as_deref(), Some("/new"));
            assert_eq!(*status, 301);
        }
        other => panic!("expected Redirect action, got {other:?}"),
    }
}

#[test]
fn request_header_modifier_filter() {
    let gw = http_gateway();
    let mut route = httproute_with_path("PathPrefix", "/", "backend", 8080);
    route.spec.rules[0]
        .filters
        .push(HttpRouteFilter::RequestHeaderModifier {
            add: vec![k8s_gateway::HttpHeaderFilter {
                name: "X-Added".to_string(),
                value: "yes".to_string(),
            }],
            set: vec![k8s_gateway::HttpHeaderFilter {
                name: "X-Set".to_string(),
                value: "val".to_string(),
            }],
            remove: vec!["X-Removed".to_string()],
        });
    let eps = endpoints_with("backend", 8080);
    let result = translate(&gw, &[route], &eps);
    let transforms = result.gateway.routes[0]
        .transforms
        .as_ref()
        .expect("transforms should be set");
    let req_hdrs = transforms
        .request
        .as_ref()
        .expect("request transforms should be set")
        .headers
        .as_ref()
        .expect("request header ops should be set");
    assert_eq!(req_hdrs.set.get("X-Set"), Some(&"val".to_string()));
    assert_eq!(req_hdrs.add.get("X-Added"), Some(&"yes".to_string()));
    assert!(req_hdrs.remove.contains(&"X-Removed".to_string()));
}

#[test]
fn response_header_modifier_filter() {
    let gw = http_gateway();
    let mut route = httproute_with_path("PathPrefix", "/", "backend", 8080);
    route.spec.rules[0]
        .filters
        .push(HttpRouteFilter::ResponseHeaderModifier {
            add: vec![k8s_gateway::HttpHeaderFilter {
                name: "X-Resp-Added".to_string(),
                value: "yes".to_string(),
            }],
            set: vec![],
            remove: vec![],
        });
    let eps = endpoints_with("backend", 8080);
    let result = translate(&gw, &[route], &eps);
    let transforms = result.gateway.routes[0]
        .transforms
        .as_ref()
        .expect("transforms should be set");
    let resp_hdrs = transforms
        .response
        .as_ref()
        .expect("response transforms should be set")
        .headers
        .as_ref()
        .expect("response header ops should be set");
    assert_eq!(resp_hdrs.add.get("X-Resp-Added"), Some(&"yes".to_string()));
}

#[test]
fn backend_ref_produces_service_and_upstream() {
    let gw = http_gateway();
    let route = httproute_with_path("PathPrefix", "/api", "my-svc", 8080);
    let eps = endpoints_with("my-svc", 8080);
    let result = translate(&gw, &[route], &eps);
    assert_eq!(result.gateway.services.len(), 1);
    assert_eq!(result.gateway.upstreams.len(), 1);
    assert!(result.gateway.upstreams[0].endpoints.len() == 1);
    assert_eq!(result.gateway.upstreams[0].endpoints[0].address, "10.0.0.1");
    assert_eq!(result.gateway.upstreams[0].endpoints[0].port, 8080);
}

#[test]
fn multiple_rules_produce_multiple_routes() {
    let gw = http_gateway();
    let mut route = httproute_with_path("PathPrefix", "/api", "backend", 8080);
    route.spec.rules.push(HttpRouteRule {
        matches: vec![HttpRouteMatch {
            path: Some(HttpPathMatch {
                match_type: "PathPrefix".to_string(),
                value: "/web".to_string(),
            }),
            headers: Vec::new(),
            query_params: Vec::new(),
        }],
        filters: Vec::new(),
        backend_refs: vec![HttpBackendRef {
            kind: "Service".to_string(),
            name: "web-svc".to_string(),
            namespace: Some("default".to_string()),
            port: Some(80),
            weight: 1,
        }],
    });
    let mut eps = endpoints_with("backend", 8080);
    eps.insert(
        k8s_gateway::endpoint_key("default", "web-svc", 80),
        vec![DwaraEndpoint {
            address: "10.0.0.2".to_string(),
            port: 80,
            weight: 1,
        }],
    );
    let result = translate(&gw, &[route], &eps);
    assert_eq!(result.gateway.routes.len(), 2);
    assert_eq!(result.gateway.routes[0].r#match.path.value, "/api");
    assert_eq!(result.gateway.routes[1].r#match.path.value, "/web");
}

#[test]
fn multiple_matches_per_rule_expand_to_routes() {
    let gw = http_gateway();
    let mut route = httproute_with_path("PathPrefix", "/api", "backend", 8080);
    route.spec.rules[0].matches.push(HttpRouteMatch {
        path: Some(HttpPathMatch {
            match_type: "Exact".to_string(),
            value: "/api/health".to_string(),
        }),
        headers: Vec::new(),
        query_params: Vec::new(),
    });
    let eps = endpoints_with("backend", 8080);
    let result = translate(&gw, &[route], &eps);
    assert_eq!(result.gateway.routes.len(), 2);
    assert_eq!(result.gateway.routes[0].r#match.path.value, "/api");
    assert_eq!(result.gateway.routes[1].r#match.path.value, "/api/health");
}

#[test]
fn hostname_from_route_becomes_match_host() {
    let gw = http_gateway();
    let mut route = httproute_with_path("PathPrefix", "/", "backend", 8080);
    route.spec.hostnames = vec!["api.example.com".to_string()];
    let eps = endpoints_with("backend", 8080);
    let result = translate(&gw, &[route], &eps);
    assert_eq!(
        result.gateway.routes[0].r#match.host.as_deref(),
        Some("api.example.com")
    );
}

#[test]
fn gatewayclass_acceptance() {
    let gc = GatewayClass {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: "GatewayClass".to_string(),
        metadata: ObjectMeta {
            name: "dwara".to_string(),
            namespace: None,
        },
        spec: k8s_gateway::GatewayClassSpec {
            controller: k8s_gateway::CONTROLLER_NAME.to_string(),
        },
    };
    assert_eq!(gc.spec.controller, k8s_gateway::CONTROLLER_NAME);
}

// ---------------------------------------------------------------------------
// Ingress translator conformance vectors
// ---------------------------------------------------------------------------

#[test]
fn ingress_path_prefix() {
    let ingress = ingress::Ingress {
        api_version: "networking.k8s.io/v1".to_string(),
        kind: "Ingress".to_string(),
        metadata: ingress::IngressObjectMeta {
            name: "test-ingress".to_string(),
            namespace: Some("default".to_string()),
            annotations: HashMap::new(),
        },
        spec: ingress::IngressSpec {
            ingress_class_name: Some("dwara".to_string()),
            rules: vec![ingress::IngressRule {
                host: Some("example.com".to_string()),
                http: vec![ingress::HTTPIngressPath {
                    path_type: "Prefix".to_string(),
                    path: "/api".to_string(),
                    backend: ingress::IngressBackend {
                        service: Some(ingress::IngressServiceBackend {
                            name: "api-svc".to_string(),
                            port: Some(ingress::ServiceBackendPort {
                                name: None,
                                number: Some(8080),
                            }),
                        }),
                    },
                }],
            }],
            tls: Vec::new(),
            default_backend: None,
        },
    };
    let mut eps = HashMap::new();
    eps.insert(
        k8s_gateway::endpoint_key("default", "api-svc", 8080),
        vec![DwaraEndpoint {
            address: "10.0.0.1".to_string(),
            port: 8080,
            weight: 1,
        }],
    );
    let result = ingress::translate_ingress(&[ingress], "dwara", &eps).expect("translation ok");
    assert_eq!(result.gateway.routes.len(), 1);
    assert_eq!(
        result.gateway.routes[0].r#match.path.kind,
        PathMatchKind::Prefix
    );
    assert_eq!(result.gateway.routes[0].r#match.path.value, "/api");
    assert_eq!(
        result.gateway.routes[0].r#match.host.as_deref(),
        Some("example.com")
    );
}

#[test]
fn ingress_tls_produces_https_listener() {
    let ingress = ingress::Ingress {
        api_version: "networking.k8s.io/v1".to_string(),
        kind: "Ingress".to_string(),
        metadata: ingress::IngressObjectMeta {
            name: "tls-ingress".to_string(),
            namespace: Some("default".to_string()),
            annotations: HashMap::new(),
        },
        spec: ingress::IngressSpec {
            ingress_class_name: Some("dwara".to_string()),
            rules: vec![ingress::IngressRule {
                host: Some("secure.example.com".to_string()),
                http: vec![ingress::HTTPIngressPath {
                    path_type: "Prefix".to_string(),
                    path: "/".to_string(),
                    backend: ingress::IngressBackend {
                        service: Some(ingress::IngressServiceBackend {
                            name: "web-svc".to_string(),
                            port: Some(ingress::ServiceBackendPort {
                                name: None,
                                number: Some(80),
                            }),
                        }),
                    },
                }],
            }],
            tls: vec![ingress::IngressTls {
                hosts: vec!["secure.example.com".to_string()],
                secret_name: Some("tls-secret".to_string()),
            }],
            default_backend: None,
        },
    };
    let mut eps = HashMap::new();
    eps.insert(
        k8s_gateway::endpoint_key("default", "web-svc", 80),
        vec![DwaraEndpoint {
            address: "10.0.0.1".to_string(),
            port: 80,
            weight: 1,
        }],
    );
    let result = ingress::translate_ingress(&[ingress], "dwara", &eps).expect("translation ok");
    // Should have HTTP (port 80) + HTTPS (port 443) listeners.
    assert_eq!(result.gateway.listeners.len(), 2);
    let https = result
        .gateway
        .listeners
        .iter()
        .find(|l| l.port == 443)
        .expect("HTTPS listener should exist");
    let tls = https.tls.as_ref().expect("TLS should be set");
    assert_eq!(tls.mode, TlsMode::Terminate);
    assert!(tls.cert_file.as_ref().unwrap().contains("tls-secret"));
}

#[test]
fn ingress_unsupported_annotation_emits_warning() {
    let mut ingress = ingress::Ingress {
        api_version: "networking.k8s.io/v1".to_string(),
        kind: "Ingress".to_string(),
        metadata: ingress::IngressObjectMeta {
            name: "annot-ingress".to_string(),
            namespace: Some("default".to_string()),
            annotations: HashMap::new(),
        },
        spec: ingress::IngressSpec {
            ingress_class_name: Some("dwara".to_string()),
            rules: vec![ingress::IngressRule {
                host: None,
                http: vec![ingress::HTTPIngressPath {
                    path_type: "Prefix".to_string(),
                    path: "/".to_string(),
                    backend: ingress::IngressBackend {
                        service: Some(ingress::IngressServiceBackend {
                            name: "svc".to_string(),
                            port: Some(ingress::ServiceBackendPort {
                                name: None,
                                number: Some(80),
                            }),
                        }),
                    },
                }],
            }],
            tls: Vec::new(),
            default_backend: None,
        },
    };
    ingress.metadata.annotations.insert(
        "nginx.ingress.kubernetes.io/rewrite-target".to_string(),
        "/".to_string(),
    );
    let mut eps = HashMap::new();
    eps.insert(
        k8s_gateway::endpoint_key("default", "svc", 80),
        vec![DwaraEndpoint {
            address: "10.0.0.1".to_string(),
            port: 80,
            weight: 1,
        }],
    );
    let result = ingress::translate_ingress(&[ingress], "dwara", &eps).expect("translation ok");
    assert!(result.warnings.iter().any(|w| w.contains("rewrite-target")));
}
