//! Tests for the Kubernetes Gateway API controller Reconciler (DW-064).
//! Exercises the pure reconciliation core (no cluster required).
//!
//! Feature-gated behind the `k8s` cargo feature.

#![cfg(feature = "k8s")]

use std::collections::HashMap;

use dwara_core::config::Endpoint as DwaraEndpoint;
use dwara_core::k8s_gateway::{
    self, controller::Reconciler, ingress, Gateway, GatewayClass, GatewayClassSpec,
    GatewayListener, GatewaySpec, HttpBackendRef, HttpPathMatch, HttpRoute, HttpRouteMatch,
    HttpRouteRule, HttpRouteSpec, ObjectMeta, ParentReference, CONTROLLER_NAME,
};

fn make_gateway_class(name: &str, controller: &str) -> GatewayClass {
    GatewayClass {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: "GatewayClass".to_string(),
        metadata: ObjectMeta {
            name: name.to_string(),
            namespace: None,
        },
        spec: GatewayClassSpec {
            controller: controller.to_string(),
        },
    }
}

fn make_gateway(name: &str, class: &str) -> Gateway {
    Gateway {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: "Gateway".to_string(),
        metadata: ObjectMeta {
            name: name.to_string(),
            namespace: Some("default".to_string()),
        },
        spec: GatewaySpec {
            gateway_class_name: class.to_string(),
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

fn make_httproute(name: &str, gateway: &str, svc: &str, port: u16) -> HttpRoute {
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
                name: gateway.to_string(),
                namespace: Some("default".to_string()),
                section_name: None,
            }],
            hostnames: Vec::new(),
            rules: vec![HttpRouteRule {
                matches: vec![HttpRouteMatch {
                    path: Some(HttpPathMatch {
                        match_type: "PathPrefix".to_string(),
                        value: "/".to_string(),
                    }),
                    headers: Vec::new(),
                    query_params: Vec::new(),
                }],
                filters: Vec::new(),
                backend_refs: vec![HttpBackendRef {
                    kind: "Service".to_string(),
                    name: svc.to_string(),
                    namespace: Some("default".to_string()),
                    port: Some(port),
                    weight: 1,
                }],
            }],
        },
    }
}

fn make_endpoints(svc: &str, port: u16) -> HashMap<String, Vec<DwaraEndpoint>> {
    let mut m = HashMap::new();
    m.insert(
        k8s_gateway::endpoint_key("default", svc, port),
        vec![DwaraEndpoint {
            address: "10.0.0.1".to_string(),
            port,
            weight: 1,
            region: None,
            zone: None,
        }],
    );
    m
}

fn make_ingress(name: &str, svc: &str, port: u16) -> ingress::Ingress {
    ingress::Ingress {
        api_version: "networking.k8s.io/v1".to_string(),
        kind: "Ingress".to_string(),
        metadata: ingress::IngressObjectMeta {
            name: name.to_string(),
            namespace: Some("default".to_string()),
            annotations: HashMap::new(),
        },
        spec: ingress::IngressSpec {
            ingress_class_name: Some("dwara".to_string()),
            rules: vec![ingress::IngressRule {
                host: Some("example.com".to_string()),
                http: vec![ingress::HTTPIngressPath {
                    path_type: "Prefix".to_string(),
                    path: "/".to_string(),
                    backend: ingress::IngressBackend {
                        service: Some(ingress::IngressServiceBackend {
                            name: svc.to_string(),
                            port: Some(ingress::ServiceBackendPort {
                                name: None,
                                number: Some(port),
                            }),
                        }),
                    },
                }],
            }],
            tls: Vec::new(),
            default_backend: None,
        },
    }
}

#[test]
fn reconciler_accepts_matching_gateway_class() {
    let gc = make_gateway_class("dwara", CONTROLLER_NAME);
    let reconciler = Reconciler::with_defaults().with_gateway_classes(vec![gc]);
    let output = reconciler.reconcile().expect("reconcile ok");
    let status = output
        .gateway_class_statuses
        .get("dwara")
        .expect("status should exist");
    let accepted = status
        .conditions
        .iter()
        .find(|c| c.r#type == "Accepted")
        .expect("Accepted condition should exist");
    assert_eq!(accepted.status, "True");
}

#[test]
fn reconciler_rejects_non_matching_gateway_class() {
    let gc = make_gateway_class("other", "some-other-controller");
    let reconciler = Reconciler::with_defaults().with_gateway_classes(vec![gc]);
    let output = reconciler.reconcile().expect("reconcile ok");
    let status = output
        .gateway_class_statuses
        .get("other")
        .expect("status should exist");
    let accepted = status
        .conditions
        .iter()
        .find(|c| c.r#type == "Accepted")
        .expect("Accepted condition should exist");
    assert_eq!(accepted.status, "False");
}

#[test]
fn reconciler_translates_gateway_with_accepted_class() {
    let gc = make_gateway_class("dwara", CONTROLLER_NAME);
    let gw = make_gateway("my-gateway", "dwara");
    let route = make_httproute("my-route", "my-gateway", "my-svc", 8080);
    let eps = make_endpoints("my-svc", 8080);

    let reconciler = Reconciler::with_defaults()
        .with_gateway_classes(vec![gc])
        .with_gateways(vec![gw])
        .with_httproutes(vec![route])
        .with_endpoints(eps);

    let output = reconciler.reconcile().expect("reconcile ok");
    assert_eq!(output.config.gateway.routes.len(), 1);
    assert_eq!(output.config.gateway.services.len(), 1);
    assert_eq!(output.config.gateway.upstreams.len(), 1);

    // Gateway status should be Accepted + Programmed.
    let gw_status = output
        .gateway_statuses
        .get("default/my-gateway")
        .expect("gateway status should exist");
    assert!(gw_status
        .conditions
        .iter()
        .any(|c| c.r#type == "Accepted" && c.status == "True"));
    assert!(gw_status
        .conditions
        .iter()
        .any(|c| c.r#type == "Programmed" && c.status == "True"));
}

#[test]
fn reconciler_rejects_gateway_with_uncontrolled_class() {
    let gc = make_gateway_class("other", "other-controller");
    let gw = make_gateway("my-gateway", "other");
    let route = make_httproute("my-route", "my-gateway", "my-svc", 8080);
    let eps = make_endpoints("my-svc", 8080);

    let reconciler = Reconciler::with_defaults()
        .with_gateway_classes(vec![gc])
        .with_gateways(vec![gw])
        .with_httproutes(vec![route])
        .with_endpoints(eps);

    let output = reconciler.reconcile().expect("reconcile ok");
    assert_eq!(output.config.gateway.routes.len(), 0);
    let gw_status = output
        .gateway_statuses
        .get("default/my-gateway")
        .expect("gateway status should exist");
    let accepted = gw_status
        .conditions
        .iter()
        .find(|c| c.r#type == "Accepted")
        .expect("Accepted condition");
    assert_eq!(accepted.status, "False");
}

#[test]
fn reconciler_httproute_accepted_and_resolved() {
    let gc = make_gateway_class("dwara", CONTROLLER_NAME);
    let gw = make_gateway("my-gateway", "dwara");
    let route = make_httproute("my-route", "my-gateway", "my-svc", 8080);
    let eps = make_endpoints("my-svc", 8080);

    let reconciler = Reconciler::with_defaults()
        .with_gateway_classes(vec![gc])
        .with_gateways(vec![gw])
        .with_httproutes(vec![route])
        .with_endpoints(eps);

    let output = reconciler.reconcile().expect("reconcile ok");
    let route_status = output
        .httproute_statuses
        .get("default/my-route")
        .expect("route status should exist");
    let accepted = route_status
        .conditions
        .iter()
        .find(|c| c.r#type == "Accepted")
        .expect("Accepted condition");
    assert_eq!(accepted.status, "True");
    let resolved = route_status
        .conditions
        .iter()
        .find(|c| c.r#type == "ResolvedRefs")
        .expect("ResolvedRefs condition");
    assert_eq!(resolved.status, "True");
}

#[test]
fn reconciler_httproute_unresolved_refs_when_endpoints_missing() {
    let gc = make_gateway_class("dwara", CONTROLLER_NAME);
    let gw = make_gateway("my-gateway", "dwara");
    let route = make_httproute("my-route", "my-gateway", "missing-svc", 8080);

    let reconciler = Reconciler::with_defaults()
        .with_gateway_classes(vec![gc])
        .with_gateways(vec![gw])
        .with_httproutes(vec![route])
        .with_endpoints(HashMap::new());

    let output = reconciler.reconcile().expect("reconcile ok");
    let route_status = output
        .httproute_statuses
        .get("default/my-route")
        .expect("route status should exist");
    let resolved = route_status
        .conditions
        .iter()
        .find(|c| c.r#type == "ResolvedRefs")
        .expect("ResolvedRefs condition");
    assert_eq!(resolved.status, "False");
}

#[test]
fn reconciler_merges_gateway_api_and_ingress() {
    let gc = make_gateway_class("dwara", CONTROLLER_NAME);
    let gw = make_gateway("gw", "dwara");
    let route = make_httproute("gw-route", "gw", "gw-svc", 8080);
    let mut eps = make_endpoints("gw-svc", 8080);
    eps.insert(
        k8s_gateway::endpoint_key("default", "ingress-svc", 80),
        vec![DwaraEndpoint {
            address: "10.0.0.2".to_string(),
            port: 80,
            weight: 1,
            region: None,
            zone: None,
        }],
    );
    let ing = make_ingress("my-ingress", "ingress-svc", 80);

    let reconciler = Reconciler::with_defaults()
        .with_gateway_classes(vec![gc])
        .with_gateways(vec![gw])
        .with_httproutes(vec![route])
        .with_ingresses(vec![ing])
        .with_endpoints(eps);

    let output = reconciler.reconcile().expect("reconcile ok");
    // 1 Gateway API route + 1 Ingress route.
    assert_eq!(output.config.gateway.routes.len(), 2);
    // 1 Gateway API listener + 1 Ingress HTTP listener.
    assert_eq!(output.config.gateway.listeners.len(), 2);
}

#[test]
fn reconciler_empty_state_produces_empty_config() {
    let reconciler = Reconciler::with_defaults();
    let output = reconciler.reconcile().expect("reconcile ok");
    assert_eq!(output.config.gateway.routes.len(), 0);
    assert_eq!(output.config.gateway.services.len(), 0);
    assert_eq!(output.config.gateway.upstreams.len(), 0);
    // The Ingress translator always creates a default HTTP listener on
    // port 80, even with no Ingresses (it is the catch-all listener).
    assert_eq!(output.config.gateway.listeners.len(), 1);
}
