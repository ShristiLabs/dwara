//! Kubernetes Ingress / IngressClass translator (DW-064).
//!
//! A minimal Ingress controller translator that maps the standard
//! Kubernetes `Ingress` and `IngressClass` resources into dwara's config
//! model. This is the prerequisite that lands BEFORE the Gateway API CRD
//! path (per FEATURE_ANALYSIS.md section 5-Platform): Ingress is the
//! ubiquitous K8s routing API, and folding it into this issue's scope lets
//! dwara serve clusters that have not yet adopted Gateway API.
//!
//! ## Translation
//!
//! - `Ingress` rules -> dwara `Route` (one per rule path; pathType
//!   `Prefix` -> `PathMatchKind::Prefix`, `Exact` -> `Exact`,
//!   `ImplementationSpecific` -> `Prefix` with a warning).
//! - `Ingress` backend (rule backend or defaultBackend) -> `Service` +
//!   `Upstream` + `Endpoint`.
//! - `Ingress` TLS -> listener TLS (Terminate mode, cert from the named
//!   Secret).
//! - Unsupported annotations (nginx.ingress.kubernetes.io/*, rewrite-target,
//!   auth, etc.) -> warnings (never silently dropped).
//!
//! ## Feature gate
//!
//! The `k8s` cargo feature must be enabled.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::config::{
    Endpoint as DwaraEndpoint, Gateway as DwaraGateway, Listener as DwaraListener,
    ListenerProtocol, ListenerTls, LoadBalancer, PathMatch, PathMatchKind, Route as DwaraRoute,
    RouteAction, RouteMatch, Service as DwaraService, TlsCertificate, TlsMode,
    Upstream as DwaraUpstream, UpstreamProtocol, ZeroRttPolicy,
};

// ---------------------------------------------------------------------------
// Ingress resource types (subset for translation)
// ---------------------------------------------------------------------------

/// An Ingress resource (subset for translation).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ingress {
    pub api_version: String,
    pub kind: String,
    pub metadata: IngressObjectMeta,
    pub spec: IngressSpec,
}

/// Ingress object metadata (includes annotations for unsupported-construct
/// detection).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressObjectMeta {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
}

/// Ingress spec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressSpec {
    /// The ingress class name (matched against the configured class).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress_class_name: Option<String>,
    /// The routing rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<IngressRule>,
    /// The TLS configurations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tls: Vec<IngressTls>,
    /// The default backend (for traffic that matches no rule).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_backend: Option<IngressBackend>,
}

/// An Ingress routing rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressRule {
    /// The host (optional; empty = wildcard).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The HTTP paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http: Vec<HTTPIngressPath>,
}

/// An HTTP path in an Ingress rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HTTPIngressPath {
    /// The path match type: "Prefix", "Exact", "ImplementationSpecific".
    #[serde(default = "default_path_type", rename = "pathType")]
    pub path_type: String,
    /// The path value.
    #[serde(default = "default_path_value")]
    pub path: String,
    /// The backend for this path.
    pub backend: IngressBackend,
}

fn default_path_type() -> String {
    "ImplementationSpecific".to_string()
}

fn default_path_value() -> String {
    "/".to_string()
}

/// An Ingress backend reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressBackend {
    /// The Service backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<IngressServiceBackend>,
}

/// A Service backend reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressServiceBackend {
    /// The Service name.
    pub name: String,
    /// The port (name or number).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<ServiceBackendPort>,
}

/// A Service backend port (name or number).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceBackendPort {
    /// The named port (mutually exclusive with `number`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The numeric port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<u16>,
}

/// An Ingress TLS configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressTls {
    /// The hostnames this TLS config serves.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    /// The name of the TLS Secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,
}

/// An IngressClass resource (subset for translation).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressClass {
    pub api_version: String,
    pub kind: String,
    pub metadata: IngressClassObjectMeta,
    pub spec: IngressClassSpec,
}

/// IngressClass object metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressClassObjectMeta {
    pub name: String,
}

/// IngressClass spec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressClassSpec {
    /// The controller name.
    pub controller: String,
}

// ---------------------------------------------------------------------------
// Translator
// ---------------------------------------------------------------------------

/// The set of annotations the translator recognizes as unsupported
/// (emits a warning rather than silently dropping). These are the common
/// NGINX/HAProxy/ALB annotation families that have no dwara equivalent.
const UNSUPPORTED_ANNOTATION_PREFIXES: &[&str] = &[
    "nginx.ingress.kubernetes.io/",
    "nginx.org/",
    "haproxy.org/",
    "alb.ingress.kubernetes.io/",
    "kubernetes.io/ingress.allow-http",
    "ingress.kubernetes.io/rewrite-target",
    "nginx.ingress.kubernetes.io/rewrite-target",
    "nginx.ingress.kubernetes.io/ssl-redirect",
    "nginx.ingress.kubernetes.io/auth",
    "nginx.ingress.kubernetes.io/proxy",
    "nginx.ingress.kubernetes.io/configuration",
];

/// Translate Ingress resources into a dwara Gateway config.
///
/// `ingresses` are the Ingress resources. `ingress_class` is the
/// configured class name (only Ingresses with `spec.ingressClassName`
/// matching this, or with no class name when the class is the default,
/// are translated). `endpoints` is a map from
/// `<namespace>/<service-name>:<port>` to endpoint addresses.
pub fn translate_ingress(
    ingresses: &[Ingress],
    ingress_class: &str,
    endpoints: &HashMap<String, Vec<DwaraEndpoint>>,
) -> Result<TranslationResult, String> {
    let mut warnings = Vec::new();
    let mut listeners = Vec::new();
    let mut dwara_routes = Vec::new();
    let mut services = Vec::new();
    let mut upstreams = Vec::new();

    // Collect TLS configs from all ingresses to build listeners.
    let mut tls_configs: Vec<(String, Option<String>)> = Vec::new(); // (host, secret_name)

    for ingress in ingresses {
        // Check annotations for unsupported constructs.
        for key in ingress.metadata.annotations.keys() {
            if UNSUPPORTED_ANNOTATION_PREFIXES
                .iter()
                .any(|p| key.starts_with(p))
            {
                warnings.push(format!(
                    "Ingress {}/{} has unsupported annotation '{}'; ignored",
                    ingress.metadata.namespace.as_deref().unwrap_or("default"),
                    ingress.metadata.name,
                    key
                ));
            }
        }

        // Filter by ingress class.
        if let Some(ref class) = ingress.spec.ingress_class_name {
            if class != ingress_class {
                continue;
            }
        }

        let ns = ingress.metadata.namespace.as_deref().unwrap_or("default");

        // Collect TLS.
        for tls in &ingress.spec.tls {
            if let Some(ref secret) = tls.secret_name {
                if tls.hosts.is_empty() {
                    tls_configs.push((String::new(), Some(secret.clone())));
                } else {
                    for host in &tls.hosts {
                        tls_configs.push((host.clone(), Some(secret.clone())));
                    }
                }
            }
        }

        // Translate rules.
        for (rule_idx, rule) in ingress.spec.rules.iter().enumerate() {
            let host = rule.host.clone();

            for (path_idx, path) in rule.http.iter().enumerate() {
                let route_name = format!(
                    "{}-rule-{}-path-{}",
                    ingress.metadata.name, rule_idx, path_idx
                );

                let path_kind = match path.path_type.as_str() {
                    "Exact" => PathMatchKind::Exact,
                    "Prefix" => PathMatchKind::Prefix,
                    "ImplementationSpecific" => {
                        warnings.push(format!(
                            "Ingress path '{}' uses ImplementationSpecific pathType; \
                             defaulting to Prefix",
                            path.path
                        ));
                        PathMatchKind::Prefix
                    }
                    other => {
                        warnings.push(format!(
                            "Ingress path '{}' has unknown pathType '{}'; defaulting to Prefix",
                            path.path, other
                        ));
                        PathMatchKind::Prefix
                    }
                };

                let match_ = RouteMatch {
                    path: PathMatch {
                        kind: path_kind,
                        value: path.path.clone(),
                    },
                    host: host.clone(),
                    methods: Vec::new(),
                    headers: std::collections::BTreeMap::new(),
                    query: Vec::new(),
                    cookies: Vec::new(),
                    accept: None,
                };

                // Translate backend.
                let backend = path.backend.service.as_ref().or(ingress
                    .spec
                    .default_backend
                    .as_ref()
                    .and_then(|b| b.service.as_ref()));

                let mut service_name = String::new();

                if let Some(svc) = backend {
                    let port = svc.port.as_ref().and_then(|p| p.number).unwrap_or(80);

                    if let Some(port_name) = svc.port.as_ref().and_then(|p| p.name.as_ref()) {
                        warnings.push(format!(
                            "Ingress backend {}/{} uses named port '{}'; numeric port \
                             resolution not available without Service definition, using default 80",
                            ns, svc.name, port_name
                        ));
                    }

                    let endpoint_key = format!("{ns}/{}:{port}", svc.name);
                    let eps = endpoints.get(&endpoint_key).cloned().unwrap_or_else(|| {
                        warnings.push(format!(
                            "no endpoints found for backend {endpoint_key} (route {route_name})"
                        ));
                        Vec::new()
                    });

                    let upstream_name = format!("{}-{}-{}", route_name, svc.name, port);
                    service_name = format!("{}-svc-{}-{}", route_name, svc.name, port);

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
                        locality: None,
                        pq: false,
                        peak_ewma: None,
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

                let action = if service_name.is_empty() {
                    warnings.push(format!("route {route_name} has no backend"));
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
                    graphql: None,
                    grpc_web: None,
                    translation: None,
                };
                dwara_routes.push(dwara_route);
            }
        }
    }

    // Build listeners: HTTP on port 80, HTTPS on port 443 if any TLS
    // configs were found.
    listeners.push(DwaraListener {
        name: "ingress-http".to_string(),
        address: "0.0.0.0".to_string(),
        port: 80,
        protocol: ListenerProtocol::Http,
        tls: None,
        proxy_protocol: false,
        policies: Vec::new(),
        authorization: None,
        alt_svc: None,
        l4: None,
    });

    if !tls_configs.is_empty() {
        let certificates: Vec<TlsCertificate> = tls_configs
            .iter()
            .filter_map(|(host, secret)| {
                secret.as_ref().map(|s| TlsCertificate {
                    server_names: if host.is_empty() {
                        Vec::new()
                    } else {
                        vec![host.clone()]
                    },
                    cert_file: format!("k8s-secret:default/{s}"),
                    key_file: format!("k8s-secret:default/{s}"),
                })
            })
            .collect();

        let tls = ListenerTls {
            mode: TlsMode::Terminate,
            cert_file: certificates.first().map(|c| c.cert_file.clone()),
            key_file: certificates.first().map(|c| c.key_file.clone()),
            certificates,
            sni_routes: Vec::new(),
            client_ca_file: None,
            zero_rtt: ZeroRttPolicy::Reject,
            pq: false,
        };

        listeners.push(DwaraListener {
            name: "ingress-https".to_string(),
            address: "0.0.0.0".to_string(),
            port: 443,
            protocol: ListenerProtocol::Https,
            tls: Some(tls),
            proxy_protocol: false,
            policies: Vec::new(),
            authorization: None,
            alt_svc: None,
            l4: None,
        });
    }

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
        ai: None,
        fleet: None,
        lifecycle: None,
        mesh: None,
    };

    Ok(TranslationResult {
        gateway: dwara_gateway,
        warnings,
    })
}

/// Re-export the translation result type from the parent module for
/// convenience (the Ingress translator produces the same shape).
pub use super::TranslationResult;
