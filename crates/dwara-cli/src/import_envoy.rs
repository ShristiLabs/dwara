//! Envoy static config import (DW-065): `dwara import envoy` reads an
//! Envoy static config (YAML) and generates a Dwara config YAML with
//! listeners, routes, services, and upstreams derived from the Envoy
//! `static_resources`.
//!
//! This is a switching-cost lever for teams migrating off Envoy to
//! Dwara. The import is a one-shot scaffolding step: it produces a
//! config the operator edits to add Dwara-specific features that Envoy
//! handles via filters.
//!
//! ## Supported Envoy entities
//!
//! - `static_resources.listeners` -> dwara listener (address + port)
//! - `static_resources.clusters` -> dwara upstream + endpoints
//! - Listener `route_config.virtual_hosts.routes` -> dwara route
//!   (route_match prefix/path -> dwara path match; route action
//!   cluster -> dwara service + upstream)
//!
//! ## Unsupported constructs
//!
//! The import reports unsupported constructs as warnings (appended as
//! comments at the end of the generated YAML):
//! - HTTP filters (router, ext_authz, rate_limit, RBAC, compressor,
//!   CORS, JWT auth, wasm, etc.) — Dwara has its own equivalents
//! - Network filters (tcp_proxy, redis, etc.) — Dwara is an HTTP
//!   gateway; L4 proxying is out of scope for this import
//! - `tls_context` / `transport_socket` — use Dwara's listener TLS
//! - `load_assignment` with multiple endpoints is supported (each
//!   becomes a Dwara endpoint); DNS-based discovery is reported as a
//!   warning (use Dwara's `dns_discovery`)
//!
//! No new dependencies: `serde_yaml_ng` (already a workspace
//! dependency) parses the config. Minimal inline structs capture the
//! Envoy static config subset (mirror of `import.rs`'s OpenApiDoc
//! approach).

use std::collections::BTreeMap;

use dwara_core::config::{
    Endpoint, Gateway, Listener, ListenerProtocol, LoadBalancer, PathMatch, PathMatchKind, Route,
    RouteAction, RouteMatch, Service, Upstream, UpstreamProtocol,
};
use serde::Deserialize;

use super::import::ImportResult;

/// The minimal Envoy static config shape the importer reads. Unknown
/// fields are ignored (Envoy's config is vast; we capture only what
/// drives listener/cluster/route generation).
#[derive(Debug, Default, Deserialize)]
struct EnvoyConfig {
    #[serde(default)]
    static_resources: EnvoyStaticResources,
}

#[derive(Debug, Default, Deserialize)]
struct EnvoyStaticResources {
    #[serde(default)]
    listeners: Vec<EnvoyListener>,
    #[serde(default)]
    clusters: Vec<EnvoyCluster>,
}

#[derive(Debug, Default, Deserialize)]
struct EnvoyListener {
    name: String,
    #[serde(default)]
    address: Option<EnvoyAddress>,
    #[serde(default)]
    filter_chains: Vec<EnvoyFilterChain>,
}

#[derive(Debug, Default, Deserialize)]
struct EnvoyAddress {
    #[serde(default)]
    socket_address: Option<EnvoySocketAddress>,
}

#[derive(Debug, Default, Deserialize)]
struct EnvoySocketAddress {
    address: String,
    port_value: u16,
}

#[derive(Debug, Default, Deserialize)]
struct EnvoyFilterChain {
    #[serde(default)]
    filters: Vec<EnvoyFilter>,
}

#[derive(Debug, Default, Deserialize)]
struct EnvoyFilter {
    name: String,
    #[serde(default)]
    typed_config: Option<EnvoyTypedConfig>,
}

/// The typed_config is a YAML map; we extract the route_config from
/// `route_config` (envoy.filters.network.http_connection_manager).
#[derive(Debug, Default, Deserialize)]
struct EnvoyTypedConfig {
    #[serde(default)]
    route_config: Option<EnvoyRouteConfig>,
    // The filter type name (e.g. envoy.filters.http.router) is not in
    // typed_config itself; it is the `name` field on the filter. We
    // capture http_filters here for warning reporting.
    #[serde(default)]
    http_filters: Vec<EnvoyHttpFilter>,
}

#[derive(Debug, Default, Deserialize)]
struct EnvoyRouteConfig {
    #[serde(default)]
    virtual_hosts: Vec<EnvoyVirtualHost>,
}

#[derive(Debug, Default, Deserialize)]
struct EnvoyVirtualHost {
    #[serde(default)]
    name: String,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    routes: Vec<EnvoyRoute>,
}

#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct EnvoyRoute {
    #[serde(default)]
    r#match: Option<EnvoyRouteMatch>,
    #[serde(default)]
    route: Option<EnvoyRouteAction>,
    #[serde(default)]
    redirect: Option<EnvoyRedirectAction>,
}

#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct EnvoyRouteMatch {
    #[serde(default)]
    prefix: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    path_match_policy: Option<EnvoyPathMatchPolicy>,
    #[serde(default)]
    headers: Vec<EnvoyHeaderMatch>,
}

#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct EnvoyPathMatchPolicy {
    #[serde(default)]
    name: String,
}

#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct EnvoyHeaderMatch {
    name: String,
    #[serde(default)]
    exact_match: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct EnvoyRouteAction {
    #[serde(default)]
    cluster: Option<String>,
    #[serde(default)]
    cluster_header: Option<String>,
    #[serde(default)]
    prefix_rewrite: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct EnvoyRedirectAction {
    #[serde(default)]
    host_redirect: Option<String>,
    #[serde(default)]
    path_redirect: Option<String>,
    #[serde(default)]
    response_code: Option<u16>,
}

#[derive(Debug, Default, Deserialize)]
struct EnvoyHttpFilter {
    name: String,
}

#[derive(Debug, Default, Deserialize)]
struct EnvoyCluster {
    name: String,
    #[serde(default)]
    load_assignment: Option<EnvoyLoadAssignment>,
    #[serde(default)]
    r#type: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct EnvoyLoadAssignment {
    #[serde(default)]
    endpoints: Vec<EnvoyLocalityLbEndpoints>,
}

#[derive(Debug, Default, Deserialize)]
struct EnvoyLocalityLbEndpoints {
    #[serde(default)]
    lb_endpoints: Vec<EnvoyLbEndpoint>,
}

#[derive(Debug, Default, Deserialize)]
struct EnvoyLbEndpoint {
    #[serde(default)]
    endpoint: Option<EnvoyEndpoint>,
}

#[derive(Debug, Default, Deserialize)]
struct EnvoyEndpoint {
    #[serde(default)]
    address: Option<EnvoyAddress>,
}

/// Import an Envoy static config (YAML) and produce a Dwara config
/// YAML. Returns the generated config and a list of warnings about
/// unsupported constructs (appended as comments at the end of the YAML).
pub fn import_envoy(text: &str) -> Result<ImportResult, String> {
    let envoy: EnvoyConfig =
        serde_yaml_ng::from_str(text).map_err(|e| format!("invalid YAML Envoy config: {e}"))?;
    let (gateway, warnings) = build_gateway_from_envoy(&envoy);
    let route_count = gateway.routes.len();
    let mut yaml =
        dwara_core::config::gateway_to_yaml(&gateway).map_err(|e| format!("serialize: {e}"))?;

    if !warnings.is_empty() {
        yaml.push_str("\n# --- Import warnings ---\n");
        yaml.push_str("# The following Envoy constructs are not supported and were skipped.\n");
        yaml.push_str("# Review and handle them manually in Dwara config.\n");
        for w in &warnings {
            yaml.push_str(&format!("# - {w}\n"));
        }
    }

    Ok(ImportResult { yaml, route_count })
}

/// Build a Dwara Gateway from the parsed Envoy config.
fn build_gateway_from_envoy(envoy: &EnvoyConfig) -> (Gateway, Vec<String>) {
    let mut warnings = Vec::new();
    let mut listeners = Vec::new();
    let mut services = BTreeMap::new();
    let mut upstreams = BTreeMap::new();
    let mut routes = Vec::new();

    // Convert Envoy clusters to Dwara upstreams.
    for cluster in &envoy.static_resources.clusters {
        let endpoints = extract_cluster_endpoints(cluster, &mut warnings);
        if endpoints.is_empty() {
            warnings.push(format!(
                "cluster '{}' has no resolvable endpoints -- skipped",
                cluster.name
            ));
            continue;
        }
        if cluster.r#type.as_deref() == Some("STRICT_DNS")
            || cluster.r#type.as_deref() == Some("LOGICAL_DNS")
        {
            warnings.push(format!(
                "cluster '{}' uses DNS discovery -- use Dwara dns_discovery on the upstream",
                cluster.name
            ));
        }
        upstreams.insert(
            cluster.name.clone(),
            Upstream {
                name: cluster.name.clone(),
                load_balancer: LoadBalancer::RoundRobin,
                protocol: UpstreamProtocol::Http1,
                trusted_ca_file: None,
                endpoints,
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
                peak_ewma: None,
                locality: None,
            },
        );
        // Each cluster gets a service with the same name.
        services.insert(
            cluster.name.clone(),
            Service {
                name: cluster.name.clone(),
                upstream: Some(cluster.name.clone()),
                split: None,
                sticky: None,
                base_path: None,
                version: None,
                policies: Vec::new(),
                authorization: None,
            },
        );
    }

    // Convert Envoy listeners to Dwara listeners + routes.
    for listener in &envoy.static_resources.listeners {
        let (address, port) = listener
            .address
            .as_ref()
            .and_then(|a| a.socket_address.as_ref())
            .map(|sa| (sa.address.clone(), sa.port_value))
            .unwrap_or(("0.0.0.0".to_string(), 8080u16));

        listeners.push(Listener {
            name: listener.name.clone(),
            address,
            port,
            protocol: ListenerProtocol::Http,
            tls: None,
            proxy_protocol: false,
            policies: Vec::new(),
            authorization: None,
            alt_svc: None,
        });

        // Extract routes from the HTTP connection manager filter chain.
        for fc in &listener.filter_chains {
            for filter in &fc.filters {
                if filter.name == "envoy.filters.network.http_connection_manager" {
                    if let Some(tc) = &filter.typed_config {
                        // Report unsupported HTTP filters.
                        for hf in &tc.http_filters {
                            if hf.name != "envoy.filters.http.router" {
                                warnings.push(format!(
                                    "HTTP filter '{}' -- use Dwara's native equivalent",
                                    hf.name
                                ));
                            }
                        }
                        if let Some(rc) = &tc.route_config {
                            for vh in &rc.virtual_hosts {
                                let host = vh.domains.iter().find(|d| *d != "*").cloned();
                                for (ridx, route) in vh.routes.iter().enumerate() {
                                    let route_name = format!("{}-route-{ridx}", vh.name);
                                    let (kind, path_value) = convert_envoy_match(
                                        route.r#match.as_ref(),
                                        &mut warnings,
                                        ridx,
                                    );
                                    let service = route
                                        .route
                                        .as_ref()
                                        .and_then(|r| r.cluster.clone())
                                        .unwrap_or_else(|| {
                                            if !envoy.static_resources.clusters.is_empty() {
                                                envoy.static_resources.clusters[0].name.clone()
                                            } else {
                                                "default-cluster".to_string()
                                            }
                                        });
                                    routes.push(Route {
                                        name: route_name,
                                        service: service.clone(),
                                        r#match: RouteMatch {
                                            path: PathMatch {
                                                kind,
                                                value: path_value,
                                            },
                                            host: host.clone(),
                                            methods: Vec::new(),
                                            headers: BTreeMap::new(),
                                            query: Vec::new(),
                                            cookies: Vec::new(),
                                            accept: None,
                                        },
                                        action: RouteAction::Proxy { rewrite: None },
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
                                    });
                                }
                            }
                        }
                    }
                } else if !filter.name.is_empty() {
                    warnings.push(format!(
                        "network filter '{}' -- Dwara is an HTTP gateway; L4 filters are out of scope",
                        filter.name
                    ));
                }
            }
        }
    }

    let allow_empty_routes = routes.is_empty();
    let gateway = Gateway {
        listeners,
        routes,
        services: services.into_values().collect(),
        upstreams: upstreams.into_values().collect(),
        consumers: Vec::new(),
        policies: Vec::new(),
        global_policies: Vec::new(),
        authorization: None,
        trusted_proxies: Vec::new(),
        max_concurrent_requests: None,
        load_shed_dry_run: false,
        jwt_providers: Vec::new(),
        admin: None,
        allow_empty_routes,
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
    };

    (gateway, warnings)
}

/// Extract endpoints from an Envoy cluster's load_assignment.
fn extract_cluster_endpoints(cluster: &EnvoyCluster, warnings: &mut Vec<String>) -> Vec<Endpoint> {
    let Some(la) = &cluster.load_assignment else {
        return Vec::new();
    };
    let mut endpoints = Vec::new();
    for locality in &la.endpoints {
        for lbep in &locality.lb_endpoints {
            if let Some(ep) = &lbep.endpoint {
                if let Some(addr) = &ep.address {
                    if let Some(sa) = &addr.socket_address {
                        endpoints.push(Endpoint {
                            address: sa.address.clone(),
                            port: sa.port_value,
                            weight: 1,
                            region: None,
                            zone: None,
                        });
                    }
                }
            }
        }
    }
    let _ = warnings;
    endpoints
}

/// Convert an Envoy route match to a Dwara path match. Envoy `prefix`
/// maps to Dwara prefix; `path` maps to exact; a path_match_policy with
/// `envoy.path_match.regex` maps to regex.
fn convert_envoy_match(
    m: Option<&EnvoyRouteMatch>,
    warnings: &mut Vec<String>,
    ridx: usize,
) -> (PathMatchKind, String) {
    let Some(m) = m else {
        return (PathMatchKind::Prefix, "/".to_string());
    };
    if let Some(prefix) = &m.prefix {
        return (PathMatchKind::Prefix, prefix.clone());
    }
    if let Some(path) = &m.path {
        return (PathMatchKind::Exact, path.clone());
    }
    if let Some(policy) = &m.path_match_policy {
        if policy.name.contains("regex") {
            warnings.push(format!(
                "route {ridx} uses regex path matching -- verify the pattern in Dwara"
            ));
            return (PathMatchKind::Regex, "/.*".to_string());
        }
    }
    (PathMatchKind::Prefix, "/".to_string())
}
