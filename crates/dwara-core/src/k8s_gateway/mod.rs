//! Kubernetes Gateway API translator (DW-064).
//!
//! Translates Gateway API v1 resources (Gateway, HTTPRoute, GatewayClass)
//! into dwara's config model. This is the core translation layer; the
//! actual K8s controller wiring (watching the API server via informers)
//! is a separate effort that composes on top of this translator.
//!
//! ## Gateway API v1
//!
//! The Gateway API v1 standard channel (v1.5) includes:
//! - `GatewayClass`: the kind of Gateway (dwara is a controller).
//! - `Gateway`: a listener configuration (ports, TLS, hostname).
//! - `HTTPRoute`: HTTP routing rules (matches, filters, backends).
//!
//! ## Translation
//!
//! The translator maps:
//! - `Gateway` -> `Listener` (one per Gateway listener).
//! - `HTTPRoute` -> `Route` (one per HTTPRoute rule).
//! - `HTTPRoute` backendRefs -> `Service` + `Upstream` + `Endpoint`.
//!
//! ## Feature gate
//!
//! The `k8s` cargo feature must be enabled. Without it, the module is
//! not compiled.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::config::{
    Endpoint as DwaraEndpoint, Gateway as DwaraGateway, Listener as DwaraListener,
    ListenerProtocol, ListenerTls, LoadBalancer, PathMatch, PathMatchKind, Route as DwaraRoute,
    RouteAction, RouteMatch, Service as DwaraService, TlsCertificate, TlsMode,
    Upstream as DwaraUpstream, UpstreamProtocol,
};

// ---------------------------------------------------------------------------
// Gateway API v1 resource types (subset for translation)
// ---------------------------------------------------------------------------

/// A GatewayClass resource.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayClass {
    pub api_version: String,
    pub kind: String,
    pub metadata: ObjectMeta,
    pub spec: GatewayClassSpec,
}

/// GatewayClass spec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayClassSpec {
    /// The controller name (e.g. "shristilabs.com/dwara").
    pub controller: String,
}

/// A Gateway resource.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gateway {
    pub api_version: String,
    pub kind: String,
    pub metadata: ObjectMeta,
    pub spec: GatewaySpec,
}

/// Gateway spec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewaySpec {
    /// The GatewayClass name.
    pub gateway_class_name: String,
    /// The listeners on this Gateway.
    pub listeners: Vec<GatewayListener>,
}

/// A Gateway listener.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayListener {
    /// The listener name (unique within the Gateway).
    pub name: String,
    /// The port.
    pub port: u16,
    /// The protocol: "HTTP", "HTTPS", "TLS".
    pub protocol: String,
    /// The hostname (optional; empty = wildcard).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// TLS configuration (for HTTPS/TLS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<ListenerTlsConfig>,
}

/// Listener TLS configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerTlsConfig {
    /// The TLS mode: "Terminate" or "Passthrough".
    pub mode: String,
    /// The certificate references.
    pub certificate_refs: Vec<SecretObjectReference>,
}

/// A reference to a Kubernetes Secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretObjectReference {
    /// The kind (default "Secret").
    #[serde(default = "default_secret_kind")]
    pub kind: String,
    /// The name.
    pub name: String,
    /// The namespace (defaults to the parent's namespace).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

fn default_secret_kind() -> String {
    "Secret".to_string()
}

/// An HTTPRoute resource.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRoute {
    pub api_version: String,
    pub kind: String,
    pub metadata: ObjectMeta,
    pub spec: HttpRouteSpec,
}

/// HTTPRoute spec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRouteSpec {
    /// The parent Gateways this route attaches to.
    pub parent_refs: Vec<ParentReference>,
    /// The hostnames.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,
    /// The routing rules.
    pub rules: Vec<HttpRouteRule>,
}

/// A parent reference (which Gateway this route attaches to).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentReference {
    /// The kind (default "Gateway").
    #[serde(default = "default_gateway_kind")]
    pub kind: String,
    /// The Gateway name.
    pub name: String,
    /// The namespace (defaults to the route's namespace).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// The listener name (optional section name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_name: Option<String>,
}

fn default_gateway_kind() -> String {
    "Gateway".to_string()
}

/// An HTTPRoute rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRouteRule {
    /// The match conditions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matches: Vec<HttpRouteMatch>,
    /// The backend references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backend_refs: Vec<HttpBackendRef>,
}

/// An HTTPRoute match.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRouteMatch {
    /// The path match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<HttpPathMatch>,
    /// The headers to match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<HttpHeaderMatch>,
}

/// An HTTP path match.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpPathMatch {
    /// The match type: "Exact" or "PathPrefix".
    #[serde(rename = "type")]
    pub match_type: String,
    /// The path value.
    pub value: String,
}

/// An HTTP header match.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpHeaderMatch {
    /// The match type: "Exact" or "RegularExpression".
    #[serde(default = "default_header_match_type", rename = "type")]
    pub match_type: String,
    /// The header name.
    pub name: String,
    /// The header value.
    pub value: String,
}

fn default_header_match_type() -> String {
    "Exact".to_string()
}

/// An HTTP backend reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpBackendRef {
    /// The backend kind (default "Service").
    #[serde(default = "default_service_kind")]
    pub kind: String,
    /// The backend name.
    pub name: String,
    /// The namespace (defaults to the route's namespace).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// The port (for Service backends).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// The weight (for weighted load balancing).
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_service_kind() -> String {
    "Service".to_string()
}

fn default_weight() -> u32 {
    1
}

/// Kubernetes object metadata (subset).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectMeta {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

// ---------------------------------------------------------------------------
// Translator
// ---------------------------------------------------------------------------

/// The translation result: a dwara Gateway config.
#[derive(Clone, Debug, PartialEq)]
pub struct TranslationResult {
    pub gateway: DwaraGateway,
    pub warnings: Vec<String>,
}

/// Translate Gateway API resources into a dwara Gateway config.
///
/// `gateway` is the Gateway resource. `routes` are the HTTPRoutes
/// that attach to it. `endpoints` is a map from
/// `<namespace>/<service-name>:<port>` to a list of endpoint addresses
/// (typically from EndpointSlices, resolved by DW-042's discovery or
/// a K8s informer).
pub fn translate(
    gateway: &Gateway,
    routes: &[HttpRoute],
    endpoints: &HashMap<String, Vec<DwaraEndpoint>>,
) -> Result<TranslationResult, String> {
    let mut warnings = Vec::new();

    // Translate listeners.
    let mut listeners = Vec::new();
    for listener in &gateway.spec.listeners {
        let tls = translate_listener_tls(listener, &mut warnings);
        let protocol = match listener.protocol.as_str() {
            "HTTP" => ListenerProtocol::Http,
            "HTTPS" | "TLS" => ListenerProtocol::Https,
            other => {
                warnings.push(format!(
                    "listener {} has unknown protocol '{other}', defaulting to HTTP",
                    listener.name
                ));
                ListenerProtocol::Http
            }
        };
        let dwara_listener = DwaraListener {
            name: listener.name.clone(),
            address: "0.0.0.0".to_string(),
            port: listener.port,
            protocol,
            tls,
            proxy_protocol: false,
            policies: Vec::new(),
            authorization: None,
        };
        listeners.push(dwara_listener);
    }

    // Translate routes.
    let mut dwara_routes = Vec::new();
    let mut services = Vec::new();
    let mut upstreams = Vec::new();

    for route in routes {
        // Check if this route attaches to this Gateway.
        if !route_attaches_to(route, &gateway.metadata.name, &gateway.metadata.namespace) {
            continue;
        }

        for (rule_idx, rule) in route.spec.rules.iter().enumerate() {
            let route_name = format!("{}-rule-{}", route.metadata.name, rule_idx);

            // Translate matches (dwara Route has a single match, not a list).
            let match_ = if rule.matches.is_empty() {
                RouteMatch {
                    path: PathMatch {
                        kind: PathMatchKind::Prefix,
                        value: "/".to_string(),
                    },
                    host: None,
                    methods: Vec::new(),
                    headers: std::collections::BTreeMap::new(),
                    query: Vec::new(),
                    cookies: Vec::new(),
                    accept: None,
                }
            } else {
                translate_match(&rule.matches[0])
            };

            // Translate backend refs.
            let mut service_name = String::new();

            if let Some(first_backend) = rule.backend_refs.first() {
                let ns = first_backend
                    .namespace
                    .as_ref()
                    .or(route.metadata.namespace.as_ref())
                    .cloned()
                    .unwrap_or_else(|| "default".to_string());

                let port = first_backend.port.unwrap_or(80);
                let endpoint_key = format!("{ns}/{}:{port}", first_backend.name);

                let eps = endpoints.get(&endpoint_key).cloned().unwrap_or_else(|| {
                    warnings.push(format!(
                        "no endpoints found for backend {endpoint_key} (route {route_name})"
                    ));
                    Vec::new()
                });

                let upstream_name = format!("{}-{}-{}", route_name, first_backend.name, port);
                service_name = format!("{}-svc-{}-{}", route_name, first_backend.name, port);

                let upstream = DwaraUpstream {
                    name: upstream_name.clone(),
                    load_balancer: LoadBalancer::RoundRobin,
                    protocol: UpstreamProtocol::Http1,
                    trusted_ca_file: None,
                    endpoints: eps,
                    connection_cap: None,
                    slow_start_ms: None,
                    health: None,
                    active_health: None,
                    retries: None,
                    breaker: None,
                    max_pending: None,
                    timeouts: None,
                    oauth2_client_credentials: None,
                    dns_discovery: None,
                };
                upstreams.push(upstream);

                let service = DwaraService {
                    name: service_name.clone(),
                    upstream: Some(upstream_name),
                    split: None,
                    sticky: None,
                    base_path: None,
                    version: None,
                    policies: Vec::new(),
                    authorization: None,
                };
                services.push(service);
            }

            // Create the route action.
            let action = if service_name.is_empty() {
                warnings.push(format!("route {route_name} has no backends"));
                RouteAction::Respond {
                    status: 503,
                    body: None,
                    headers: std::collections::BTreeMap::new(),
                }
            } else {
                RouteAction::Proxy { rewrite: None }
            };

            let dwara_route = DwaraRoute {
                name: route_name,
                service: if service_name.is_empty() {
                    "none".to_string()
                } else {
                    service_name
                },
                r#match: match_,
                action,
                policies: Vec::new(),
                priority: None,
                auth_required: false,
                cors: None,
                compression: None,
                limits: None,
                authorization: None,
                deprecation: None,
                maintenance: None,
                transforms: None,
                security_headers: None,
                masking: None,
                cache: None,
                methods: Vec::new(),
                slo: None,
                websocket: None,
                waf: None,
                request_validation: None,
                openapi: None,
                mirror: None,
                fault_injection: None,
                plugins: Vec::new(),
            };
            dwara_routes.push(dwara_route);
        }
    }

    // Build the gateway.
    let dwara_gateway = DwaraGateway {
        listeners,
        routes: dwara_routes,
        services,
        upstreams,
        consumers: Vec::new(),
        policies: Vec::new(),
        global_policies: Vec::new(),
        authorization: None,
        trusted_proxies: Vec::new(),
        max_concurrent_requests: None,
        load_shed_dry_run: false,
        jwt_providers: Vec::new(),
        admin: None,
        allow_empty_routes: false,
        hmac_auth: None,
        webhooks: Vec::new(),
        analytics: None,
        analytics_stream: None,
        geoip: None,
        admission_queue: None,
        mtls_consumer_mapping: None,
        mtls_forward_headers: None,
        license: None,
        oidc_providers: Vec::new(),
        redis_rate_limiter: None,
        config_convergence: None,
        plugins: Vec::new(),
    };

    Ok(TranslationResult {
        gateway: dwara_gateway,
        warnings,
    })
}

/// Translate a Gateway listener's TLS config.
fn translate_listener_tls(
    listener: &GatewayListener,
    warnings: &mut Vec<String>,
) -> Option<ListenerTls> {
    let tls = listener.tls.as_ref()?;
    let mode = match tls.mode.as_str() {
        "Terminate" => TlsMode::Terminate,
        "Passthrough" => TlsMode::Passthrough,
        other => {
            warnings.push(format!(
                "listener {} has unknown TLS mode '{other}', defaulting to Terminate",
                listener.name
            ));
            TlsMode::Terminate
        }
    };

    let certificates: Vec<TlsCertificate> = tls
        .certificate_refs
        .iter()
        .map(|r| {
            let ns = r.namespace.as_deref().unwrap_or("default");
            TlsCertificate {
                server_names: listener
                    .hostname
                    .as_ref()
                    .map(|h| vec![h.clone()])
                    .unwrap_or_default(),
                cert_file: format!("k8s-secret:{ns}/{}", r.name),
                key_file: format!("k8s-secret:{ns}/{}", r.name),
            }
        })
        .collect();

    Some(ListenerTls {
        mode,
        cert_file: certificates.first().map(|c| c.cert_file.clone()),
        key_file: certificates.first().map(|c| c.key_file.clone()),
        certificates,
        sni_routes: Vec::new(),
        client_ca_file: None,
    })
}

/// Translate an HTTPRoute match to a dwara RouteMatch.
fn translate_match(m: &HttpRouteMatch) -> RouteMatch {
    let path = m
        .path
        .as_ref()
        .map(|p| {
            let kind = match p.match_type.as_str() {
                "Exact" => PathMatchKind::Exact,
                "PathPrefix" | "" => PathMatchKind::Prefix,
                _ => PathMatchKind::Regex,
            };
            PathMatch {
                kind,
                value: p.value.clone(),
            }
        })
        .unwrap_or(PathMatch {
            kind: PathMatchKind::Prefix,
            value: "/".to_string(),
        });

    RouteMatch {
        path,
        host: None,
        methods: Vec::new(),
        headers: std::collections::BTreeMap::new(),
        query: Vec::new(),
        cookies: Vec::new(),
        accept: None,
    }
}

/// Check if an HTTPRoute attaches to a Gateway.
fn route_attaches_to(
    route: &HttpRoute,
    gateway_name: &str,
    gateway_namespace: &Option<String>,
) -> bool {
    if route.spec.parent_refs.is_empty() {
        // No parent refs: attaches to all Gateways in the same namespace.
        return true;
    }

    let gw_ns = gateway_namespace.as_deref().unwrap_or("default");
    route.spec.parent_refs.iter().any(|p| {
        p.name == gateway_name
            && p.kind == "Gateway"
            && p.namespace.as_deref().unwrap_or("default") == gw_ns
    })
}

/// Build the endpoint key for a K8s Service + port.
pub fn endpoint_key(namespace: &str, service: &str, port: u16) -> String {
    format!("{namespace}/{service}:{port}")
}
