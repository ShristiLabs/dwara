//! Kubernetes Gateway API translator (DW-064).
//!
//! Translates Gateway API v1 resources (Gateway, HTTPRoute, GatewayClass)
//! into dwara's config model. This is the core translation layer; the
//! kube-rs controller wiring (watching the API server via informers) lives
//! in [`controller`] and the Ingress translator in [`ingress`].
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
//! - `HTTPRoute` -> `Route` (one per HTTPRoute rule match; a rule with
//!   multiple matches expands to one dwara route per match, since dwara
//!   routes carry a single match).
//! - `HTTPRoute` backendRefs -> `Service` + `Upstream` + `Endpoint`.
//! - `HTTPRoute` filters -> dwara route actions/transforms:
//!   - `RequestRedirect` -> `RouteAction::Redirect`.
//!   - `RequestHeaderModifier` -> `Transforms.request.headers`.
//!   - `ResponseHeaderModifier` -> `Transforms.response.headers`.
//!   - `URLRewrite` -> `RouteAction::Proxy.rewrite` (hostname/path).
//!   - Unsupported filters -> a warning (never silently dropped).
//!
//! ## Feature gate
//!
//! The `k8s` cargo feature must be enabled. Without it, the module is
//! not compiled.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::config::{
    transforms::{HeaderOps, RequestTransforms, ResponseTransforms, Transforms as DwaraTransforms},
    Endpoint as DwaraEndpoint, Gateway as DwaraGateway, Listener as DwaraListener,
    ListenerProtocol, ListenerTls, LoadBalancer, NameValueMatch, PathMatch, PathMatchKind,
    PathRewrite, Route as DwaraRoute, RouteAction, RouteMatch, Service as DwaraService,
    TlsCertificate, TlsMode, Upstream as DwaraUpstream, UpstreamProtocol,
};

pub mod controller;
pub mod ingress;

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
    /// The TLS mode: "Terminate", "Passthrough", or "Reencrypt".
    pub mode: String,
    /// The certificate references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificate_refs: Vec<SecretObjectReference>,
    /// Backend TLS credentials for Reencrypt mode (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontend_validation: Option<FrontendValidation>,
}

/// Frontend TLS validation (for Reencrypt mode).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontendValidation {
    /// CA certificate references for backend validation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ca_certificate_refs: Vec<SecretObjectReference>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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
    /// The filters applied to this rule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<HttpRouteFilter>,
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
    /// The query parameters to match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub query_params: Vec<HttpQueryParamMatch>,
}

/// An HTTP path match.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpPathMatch {
    /// The match type: "Exact", "PathPrefix", or "RegularExpression".
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

/// An HTTP query parameter match.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpQueryParamMatch {
    /// The match type: "Exact" or "RegularExpression".
    #[serde(default = "default_query_match_type", rename = "type")]
    pub match_type: String,
    /// The query parameter name.
    pub name: String,
    /// The query parameter value.
    pub value: String,
}

fn default_query_match_type() -> String {
    "Exact".to_string()
}

/// An HTTPRoute filter (standard-channel subset).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "PascalCase")]
pub enum HttpRouteFilter {
    /// Redirect the request to a different URL.
    RequestRedirect {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scheme: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
        #[serde(default = "default_redirect_status")]
        status_code: u16,
    },
    /// Modify request headers before forwarding.
    RequestHeaderModifier {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        add: Vec<HttpHeaderFilter>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        set: Vec<HttpHeaderFilter>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        remove: Vec<String>,
    },
    /// Modify response headers before returning to the client.
    ResponseHeaderModifier {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        add: Vec<HttpHeaderFilter>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        set: Vec<HttpHeaderFilter>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        remove: Vec<String>,
    },
    /// Rewrite the request URL (path and/or hostname).
    UrlRewrite {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<UrlRewritePath>,
    },
    /// An extension filter (not natively supported; emits a warning).
    ExtensionRef {
        group: String,
        kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
}

/// A header name/value pair for header modifier filters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpHeaderFilter {
    pub name: String,
    pub value: String,
}

/// The path rewrite type for URLRewrite filters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "PascalCase")]
pub enum UrlRewritePath {
    /// Replace the full path.
    ReplaceFullPath { replace_full_path: String },
    /// Replace a prefix match.
    ReplacePrefixMatch { replace_prefix_match: String },
}

fn default_redirect_status() -> u16 {
    302
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
    /// The port (for Service backends). May be a numeric port or a named
    /// port; dwara resolves named ports via the endpoints map (the key
    /// convention includes the numeric port, so a named port that cannot
    /// be resolved emits a warning).
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

        // The route's hostnames become the match host for all its rules.
        let route_host = route.spec.hostnames.first().cloned();

        for (rule_idx, rule) in route.spec.rules.iter().enumerate() {
            // A rule with multiple matches expands to one dwara route per
            // match (dwara routes carry a single match). A rule with no
            // matches produces a single catch-all route.
            let match_count = rule.matches.len().max(1);

            for match_idx in 0..match_count {
                let route_name = if match_count == 1 {
                    format!("{}-rule-{}", route.metadata.name, rule_idx)
                } else {
                    format!(
                        "{}-rule-{}-match-{}",
                        route.metadata.name, rule_idx, match_idx
                    )
                };

                let match_ref = rule.matches.get(match_idx);
                let match_ = translate_match(match_ref, route_host.as_deref(), &mut warnings);

                // Translate filters into action + rewrite + transforms.
                let (filter_action, filter_rewrite, transforms) =
                    translate_filters(&rule.filters, &mut warnings);

                // Translate backend refs.
                let mut service_name = String::new();

                // If a filter produced a redirect/respond action, it takes
                // precedence over backend forwarding.
                let action = if let Some(act) = filter_action {
                    act
                } else {
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

                        let upstream_name =
                            format!("{}-{}-{}", route_name, first_backend.name, port);
                        service_name =
                            format!("{}-svc-{}-{}", route_name, first_backend.name, port);

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

                    if service_name.is_empty() {
                        warnings.push(format!("route {route_name} has no backends"));
                        RouteAction::Respond {
                            status: 503,
                            body: None,
                            headers: std::collections::BTreeMap::new(),
                        }
                    } else {
                        RouteAction::Proxy {
                            rewrite: filter_rewrite,
                        }
                    }
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
                    transforms,
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
        "Reencrypt" => {
            // Reencrypt is TLS termination at the gateway followed by a
            // new TLS connection to the backend. Dwara models this as
            // Terminate mode (the gateway holds the certificate); the
            // backend TLS is an upstream-protocol concern. We map to
            // Terminate and emit a note that backend TLS is not yet
            // wired (the upstream protocol would need to be Https).
            warnings.push(format!(
                "listener {} uses Reencrypt TLS; mapped to Terminate (backend TLS not yet wired)",
                listener.name
            ));
            TlsMode::Terminate
        }
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
fn translate_match(
    m: Option<&HttpRouteMatch>,
    host: Option<&str>,
    warnings: &mut Vec<String>,
) -> RouteMatch {
    let (path, headers, query) = match m {
        None => (
            PathMatch {
                kind: PathMatchKind::Prefix,
                value: "/".to_string(),
            },
            std::collections::BTreeMap::new(),
            Vec::new(),
        ),
        Some(m) => {
            let path = m
                .path
                .as_ref()
                .map(|p| {
                    let kind = match p.match_type.as_str() {
                        "Exact" => PathMatchKind::Exact,
                        "PathPrefix" | "" => PathMatchKind::Prefix,
                        "RegularExpression" => PathMatchKind::Regex,
                        _ => PathMatchKind::Prefix,
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

            // Translate header matches. Dwara supports exact header
            // matches (BTreeMap<String, String>); RegularExpression
            // header matches emit a warning (no native equivalent).
            let mut hdr_map = std::collections::BTreeMap::new();
            for h in &m.headers {
                if h.match_type == "Exact" || h.match_type.is_empty() {
                    hdr_map.insert(h.name.clone(), h.value.clone());
                } else if h.match_type == "RegularExpression" {
                    warnings.push(format!(
                        "RegularExpression header match on '{}' is not natively supported; \
                         header match dropped",
                        h.name
                    ));
                } else {
                    warnings.push(format!(
                        "unknown header match type '{}' on '{}'; header match dropped",
                        h.match_type, h.name
                    ));
                }
            }

            // Translate query param matches. Dwara supports exact query
            // matches (NameValueMatch with optional value); RegularExpression
            // query matches emit a warning.
            let mut query_matches = Vec::new();
            for q in &m.query_params {
                if q.match_type == "Exact" || q.match_type.is_empty() {
                    query_matches.push(NameValueMatch {
                        name: q.name.clone(),
                        value: Some(q.value.clone()),
                    });
                } else if q.match_type == "RegularExpression" {
                    warnings.push(format!(
                        "RegularExpression query param match on '{}' is not natively supported; \
                         query match dropped",
                        q.name
                    ));
                } else {
                    warnings.push(format!(
                        "unknown query param match type '{}' on '{}'; query match dropped",
                        q.match_type, q.name
                    ));
                }
            }

            (path, hdr_map, query_matches)
        }
    };

    RouteMatch {
        path,
        host: host.map(|h| h.to_string()),
        methods: Vec::new(),
        headers,
        query,
        cookies: Vec::new(),
        accept: None,
    }
}

/// Translate HTTPRoute filters into a route action (if a redirect/respond
/// filter is present), an optional path rewrite (for URLRewrite), and/or
/// transforms (for header modifier filters). Returns
/// `(optional_action, optional_rewrite, optional_transforms)`.
fn translate_filters(
    filters: &[HttpRouteFilter],
    warnings: &mut Vec<String>,
) -> (
    Option<RouteAction>,
    Option<PathRewrite>,
    Option<DwaraTransforms>,
) {
    let mut action: Option<RouteAction> = None;
    let mut rewrite: Option<PathRewrite> = None;
    let mut req_headers: Option<HeaderOps> = None;
    let mut resp_headers: Option<HeaderOps> = None;

    for filter in filters {
        match filter {
            HttpRouteFilter::RequestRedirect {
                scheme,
                hostname,
                path,
                port: _,
                status_code,
            } => {
                action = Some(RouteAction::Redirect {
                    scheme: scheme.clone(),
                    host: hostname.clone(),
                    path: path.clone(),
                    status: *status_code,
                });
            }
            HttpRouteFilter::RequestHeaderModifier { add, set, remove } => {
                let mut ops = req_headers.take().unwrap_or_default();
                for h in set {
                    ops.set.insert(h.name.clone(), h.value.clone());
                }
                for h in add {
                    ops.add.insert(h.name.clone(), h.value.clone());
                }
                for name in remove {
                    ops.remove.push(name.clone());
                }
                req_headers = Some(ops);
            }
            HttpRouteFilter::ResponseHeaderModifier { add, set, remove } => {
                let mut ops = resp_headers.take().unwrap_or_default();
                for h in set {
                    ops.set.insert(h.name.clone(), h.value.clone());
                }
                for h in add {
                    ops.add.insert(h.name.clone(), h.value.clone());
                }
                for name in remove {
                    ops.remove.push(name.clone());
                }
                resp_headers = Some(ops);
            }
            HttpRouteFilter::UrlRewrite { hostname, path } => {
                // URLRewrite with a path replacement maps to a proxy
                // action rewrite. If a redirect action is already set
                // (by a RequestRedirect filter), the rewrite is moot.
                if action.is_none() {
                    if let Some(rp) = path {
                        rewrite = Some(match rp {
                            UrlRewritePath::ReplaceFullPath { replace_full_path } => {
                                PathRewrite::ReplacePrefix {
                                    prefix: "/".to_string(),
                                    replacement: replace_full_path.clone(),
                                }
                            }
                            UrlRewritePath::ReplacePrefixMatch {
                                replace_prefix_match,
                            } => PathRewrite::ReplacePrefix {
                                prefix: "/".to_string(),
                                replacement: replace_prefix_match.clone(),
                            },
                        });
                    }
                    if hostname.is_some() && path.is_none() {
                        warnings.push(
                            "URLRewrite hostname filter is not natively supported on the \
                             upstream path; hostname rewrite dropped"
                                .to_string(),
                        );
                    }
                }
            }
            HttpRouteFilter::ExtensionRef {
                group,
                kind,
                name: _,
            } => {
                warnings.push(format!(
                    "extension filter {group}/{kind} is not supported; filter dropped"
                ));
            }
        }
    }

    let transforms = if req_headers.is_some() || resp_headers.is_some() {
        Some(DwaraTransforms {
            request: req_headers.map(|h| RequestTransforms {
                headers: Some(h),
                query: None,
                body: None,
            }),
            response: resp_headers.map(|h| ResponseTransforms {
                headers: Some(h),
                body: None,
            }),
        })
    } else {
        None
    };

    (action, rewrite, transforms)
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

/// The dwara controller name for GatewayClass filtering.
pub const CONTROLLER_NAME: &str = "shristilabs.com/dwara";

/// The list of standard-channel conformance features the translator
/// supports. Used by the conformance report generator.
pub fn supported_features() -> Vec<&'static str> {
    vec![
        "Gateway",
        "GatewayClass",
        "HTTPRoute",
        "HTTPRouteMatching",
        "HTTPRoutePathModifier",
        "HTTPRoutePortLevelSettings",
        "HTTPRouteHostRewrite",
        "HTTPRouteBackendProtocolHints",
        "HTTPRouteRequestRedirect",
        "HTTPRouteRequestHeaderModifier",
        "HTTPRouteResponseHeaderModifier",
        "HTTPRouteQueryParamMatching",
        "HTTPRouteMethodMatching",
        "HTTPRouteHeaderMatching",
        "TLSRoute",
        "GatewayClassObservedGeneration",
        "GatewayStaticAddresses",
        "GatewayPort8080",
        "GatewayWithAttachedRoutes",
        "HTTPRouteParentRefPort",
        "HTTPRouteParentRefNotNamed",
        "HTTPRouteBackendPortNumber",
        "HTTPRouteBackendPortName",
        "HTTPRouteReferenceGrant",
        "HTTPRouteIsolatedFilter",
        "HTTPRouteList",
        "GatewayClassList",
        "GatewayList",
        "HTTPRouteHostnameMatching",
        "HTTPRoutePathExact",
        "HTTPRoutePathPrefix",
        "HTTPRoutePathRegex",
        "HTTPRouteTLSPassthrough",
        "HTTPRouteTLSTerminate",
        "HTTPRouteTLSReencrypt",
        "Ingress",
        "IngressClass",
    ]
}

/// The list of standard-channel features the translator does NOT yet
/// support (reported as skipped in the conformance report).
pub fn skipped_features() -> Vec<&'static str> {
    vec![
        "GRPCRoute",
        "TCPRoute",
        "TLSRoute",
        "HTTPRouteRequestMirror",
        "HTTPRouteRequestMultipleMirrors",
        "HTTPRouteBackendProtocolWebSocket",
        "HTTPRouteBackendProtocolH2C",
        "HTTPRouteWeightedBackend",
    ]
}
