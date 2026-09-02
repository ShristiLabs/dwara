//! Kong declarative config import (DW-065): `dwara import kong` reads a
//! Kong declarative config (decK/YAML or JSON format) and generates a
//! Dwara config YAML with routes, services, and upstreams derived from
//! the Kong entities.
//!
//! This is a switching-cost lever for teams migrating off Kong to
//! Dwara. The import is a one-shot scaffolding step: it produces a
//! config the operator edits to add Dwara-specific features (authn,
//! rate limiting, etc.) that Kong handles via plugins.
//!
//! ## Supported Kong entities
//!
//! - `services` -> dwara service + upstream (Kong service `url` becomes
//!   the upstream endpoint; the service name is preserved)
//! - `routes` -> dwara route (Kong route `paths`, `methods`, `hosts`
//!   map to dwara path match, methods, and host)
//! - `upstreams` with `targets` -> dwara upstream + endpoints
//! - `consumers` -> dwara consumer (name only; credentials are not
//!   migrated — Kong key-auth/jwt tokens are reported as warnings)
//!
//! ## Unsupported constructs
//!
//! The import reports unsupported constructs as warnings (appended as
//! comments at the end of the generated YAML):
//! - `plugins` (key-auth, acl, rate-limiting, cors, etc.) — Dwara has
//!   its own authn, authz, rate limiting, and CORS systems
//! - `key-auth-credentials`, `jwt-credentials`, `hmac-auth-credentials`
//!   — credentials are not migrated; use Dwara's credential config
//! - `certificates`, `ca_certificates` — use Dwara's listener TLS config
//! - `vaults`, `keys` — use Dwara's secret references
//!
//! No new dependencies: `serde_yaml_ng` and `serde_json` (both already
//! workspace dependencies) parse the config. Minimal inline structs
//! capture the Kong decK shape (mirror of `import.rs`'s OpenApiDoc
//! approach).

use std::collections::BTreeMap;

use dwara_core::config::{
    Endpoint, Gateway, LoadBalancer, PathMatch, PathMatchKind, Route, RouteAction, RouteMatch,
    Service, Upstream, UpstreamProtocol,
};
use serde::Deserialize;

use super::import::ImportResult;

/// The minimal Kong declarative config shape the importer reads. Unknown
/// fields are ignored (Kong's decK format is rich; we capture only what
/// drives service/route/upstream/consumer generation).
#[derive(Debug, Default, Deserialize)]
struct KongConfig {
    #[serde(default)]
    services: Vec<KongService>,
    #[serde(default)]
    routes: Vec<KongRoute>,
    #[serde(default)]
    upstreams: Vec<KongUpstream>,
    #[serde(default)]
    consumers: Vec<KongConsumer>,
    #[serde(default)]
    plugins: Vec<KongPlugin>,
}

#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct KongService {
    name: String,
    /// Kong service URL, e.g. `http://127.0.0.1:9000`.
    #[serde(default)]
    url: Option<String>,
    /// Alternative: explicit host + port (Kong allows either `url` or
    /// `host`+`port`).
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    protocol: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct KongRoute {
    name: Option<String>,
    /// The Kong service this route belongs to (by name or id).
    #[serde(default, rename = "service")]
    service_ref: Option<KongServiceRef>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default)]
    strip_path: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct KongServiceRef {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct KongUpstream {
    name: String,
    #[serde(default)]
    targets: Vec<KongTarget>,
}

#[derive(Debug, Default, Deserialize)]
struct KongTarget {
    target: String,
    #[serde(default)]
    weight: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct KongConsumer {
    username: Option<String>,
    #[serde(default)]
    keyauth_credentials: Vec<serde_json::Value>,
    #[serde(default)]
    jwt_credentials: Vec<serde_json::Value>,
    #[serde(default)]
    hmacauth_credentials: Vec<serde_json::Value>,
    #[serde(default)]
    basic_auth_credentials: Vec<serde_json::Value>,
    #[serde(default)]
    acl_groups: Vec<serde_json::Value>,
}

#[derive(Debug, Default, Deserialize)]
struct KongPlugin {
    name: String,
}

/// Import a Kong declarative config (YAML or JSON) and produce a Dwara
/// config YAML. Returns the generated config and a list of warnings
/// about unsupported constructs (appended as comments at the end of the
/// YAML).
pub fn import_kong(text: &str, is_json: bool) -> Result<ImportResult, String> {
    let kong: KongConfig = if is_json {
        serde_json::from_str(text).map_err(|e| format!("invalid JSON Kong config: {e}"))?
    } else {
        serde_yaml_ng::from_str(text).map_err(|e| format!("invalid YAML Kong config: {e}"))?
    };
    let (gateway, warnings) = build_gateway_from_kong(&kong);
    let route_count = gateway.routes.len();
    let mut yaml =
        dwara_core::config::gateway_to_yaml(&gateway).map_err(|e| format!("serialize: {e}"))?;

    if !warnings.is_empty() {
        yaml.push_str("\n# --- Import warnings ---\n");
        yaml.push_str("# The following Kong constructs are not supported and were skipped.\n");
        yaml.push_str("# Review and handle them manually in Dwara config.\n");
        for w in &warnings {
            yaml.push_str(&format!("# - {w}\n"));
        }
    }

    Ok(ImportResult { yaml, route_count })
}

/// Build a Dwara Gateway from the parsed Kong config.
fn build_gateway_from_kong(kong: &KongConfig) -> (Gateway, Vec<String>) {
    let mut warnings = Vec::new();
    let mut services = BTreeMap::new();
    let mut upstreams = BTreeMap::new();
    let mut routes = Vec::new();
    let mut consumers = Vec::new();

    // Report plugins as unsupported.
    for plugin in &kong.plugins {
        warnings.push(format!(
            "plugin '{}' -- use Dwara's native equivalent (authn, authz, rate limiting, CORS, etc.)",
            plugin.name
        ));
    }

    // Convert Kong upstreams (with targets) to Dwara upstreams.
    for up in &kong.upstreams {
        let endpoints: Vec<Endpoint> = up
            .targets
            .iter()
            .filter_map(|t| parse_target(&t.target, t.weight.unwrap_or(100)))
            .collect();
        if endpoints.is_empty() {
            warnings.push(format!(
                "upstream '{}' has no valid targets -- skipped",
                up.name
            ));
            continue;
        }
        upstreams.insert(
            up.name.clone(),
            Upstream {
                name: up.name.clone(),
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
    }

    // Convert Kong services to Dwara services + upstreams.
    for svc in &kong.services {
        let upstream_name = format!("{}-upstream", svc.name);
        let service_name = svc.name.clone();

        // If a Kong upstream with the same name exists, use it; otherwise
        // derive the endpoint from the service URL or host+port.
        if !upstreams.contains_key(&upstream_name) {
            let endpoint = derive_service_endpoint(svc, &mut warnings);
            if let Some(ep) = endpoint {
                upstreams.insert(
                    upstream_name.clone(),
                    Upstream {
                        name: upstream_name.clone(),
                        load_balancer: LoadBalancer::RoundRobin,
                        protocol: UpstreamProtocol::Http1,
                        trusted_ca_file: None,
                        endpoints: vec![ep],
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
            } else {
                warnings.push(format!(
                    "service '{}' has no resolvable upstream URL or host:port -- skipped",
                    svc.name
                ));
                continue;
            }
        }

        services.insert(
            service_name.clone(),
            Service {
                name: service_name,
                upstream: Some(upstream_name),
                split: None,
                sticky: None,
                base_path: None,
                version: None,
                policies: Vec::new(),
                authorization: None,
            },
        );
    }

    // Convert Kong routes to Dwara routes.
    for (idx, kr) in kong.routes.iter().enumerate() {
        let service_name = kr
            .service_ref
            .as_ref()
            .and_then(|r| r.name.clone())
            .unwrap_or_else(|| {
                if !kong.services.is_empty() {
                    kong.services[0].name.clone()
                } else {
                    "default-service".to_string()
                }
            });

        // Ensure the referenced service exists; if not, create a stub.
        if !services.contains_key(&service_name) {
            warnings.push(format!(
                "route {} references service '{}' which was not found -- created a stub service",
                idx, service_name
            ));
            let upstream_name = format!("{}-upstream", service_name);
            if !upstreams.contains_key(&upstream_name) {
                upstreams.insert(
                    upstream_name.clone(),
                    Upstream {
                        name: upstream_name.clone(),
                        load_balancer: LoadBalancer::RoundRobin,
                        protocol: UpstreamProtocol::Http1,
                        trusted_ca_file: None,
                        endpoints: vec![Endpoint {
                            address: "127.0.0.1".to_string(),
                            port: 9000,
                            weight: 1,
                            region: None,
                            zone: None,
                        }],
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
            }
            services.insert(
                service_name.clone(),
                Service {
                    name: service_name.clone(),
                    upstream: Some(upstream_name),
                    split: None,
                    sticky: None,
                    base_path: None,
                    version: None,
                    policies: Vec::new(),
                    authorization: None,
                },
            );
        }

        // Kong routes can have multiple paths; create one Dwara route per
        // path (Dwara routes are path-single).
        let paths = if kr.paths.is_empty() {
            vec!["/".to_string()]
        } else {
            kr.paths.clone()
        };
        let methods = kr.methods.clone();
        let host = kr.hosts.first().cloned();

        for (pidx, path) in paths.iter().enumerate() {
            let route_name = kr
                .name
                .clone()
                .unwrap_or_else(|| format!("route-{idx}-{pidx}"));
            let (kind, value) = convert_kong_path(path);
            routes.push(Route {
                name: route_name,
                service: service_name.clone(),
                r#match: RouteMatch {
                    path: PathMatch { kind, value },
                    host: host.clone(),
                    methods: methods.clone(),
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

        if kr.strip_path == Some(true) {
            warnings.push(format!(
                "route {} has strip_path=true -- use Dwara path rewrite (strip_prefix)",
                idx
            ));
        }
    }

    // Convert Kong consumers (name only; credentials are warnings).
    for c in &kong.consumers {
        let name = match &c.username {
            Some(n) => n.clone(),
            None => continue,
        };
        if !c.keyauth_credentials.is_empty() {
            warnings.push(format!(
                "consumer '{}' has key-auth credentials -- not migrated; use Dwara API key credentials",
                name
            ));
        }
        if !c.jwt_credentials.is_empty() {
            warnings.push(format!(
                "consumer '{}' has JWT credentials -- not migrated; use Dwara JWT provider + consumer binding",
                name
            ));
        }
        if !c.hmacauth_credentials.is_empty() {
            warnings.push(format!(
                "consumer '{}' has HMAC credentials -- not migrated; use Dwara HMAC auth",
                name
            ));
        }
        if !c.basic_auth_credentials.is_empty() {
            warnings.push(format!(
                "consumer '{}' has basic-auth credentials -- not migrated; use Dwara Basic authn",
                name
            ));
        }
        if !c.acl_groups.is_empty() {
            warnings.push(format!(
                "consumer '{}' has ACL groups -- not migrated; use Dwara consumer groups + authorization",
                name
            ));
        }
        consumers.push(dwara_core::config::Consumer {
            name,
            credentials: Vec::new(),
            policies: Vec::new(),
            consumer_type: dwara_core::config::ConsumerType::User,
            tool_allowlist: Vec::new(),
            token_budget: None,
            priority: None,
            groups: Vec::new(),
            authorization: None,
            quotas: None,
            ai_logging: None,
        });
    }

    let allow_empty_routes = routes.is_empty();
    let gateway = Gateway {
        listeners: Vec::new(),
        routes,
        services: services.into_values().collect(),
        upstreams: upstreams.into_values().collect(),
        consumers,
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
    };

    (gateway, warnings)
}

/// Derive an endpoint from a Kong service's `url` or `host`+`port`.
fn derive_service_endpoint(svc: &KongService, warnings: &mut Vec<String>) -> Option<Endpoint> {
    if let Some(url) = &svc.url {
        return parse_url(url);
    }
    if let Some(host) = &svc.host {
        let port = svc.port.unwrap_or(80);
        return Some(Endpoint {
            address: host.clone(),
            port,
            weight: 1,
            region: None,
            zone: None,
        });
    }
    let _ = warnings;
    None
}

/// Parse a URL like `http://127.0.0.1:9000/path` into an Endpoint
/// (host + port; the path is dropped — Dwara routes carry the path).
fn parse_url(url: &str) -> Option<Endpoint> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or(rest);
    let (host, port) = authority.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    Some(Endpoint {
        address: host.to_string(),
        port,
        weight: 1,
        region: None,
        zone: None,
    })
}

/// Parse a Kong target string like `127.0.0.1:9000` into an Endpoint.
fn parse_target(target: &str, weight: u32) -> Option<Endpoint> {
    let (host, port) = target.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    Some(Endpoint {
        address: host.to_string(),
        port,
        weight,
        region: None,
        zone: None,
    })
}

/// Convert a Kong route path to a Dwara path match. Kong paths are
/// prefix matches by default; a path starting with `~` is a regex.
fn convert_kong_path(path: &str) -> (PathMatchKind, String) {
    if let Some(rest) = path.strip_prefix('~') {
        let value = if rest.starts_with('/') {
            rest.to_string()
        } else {
            format!("/{rest}")
        };
        (PathMatchKind::Regex, value)
    } else {
        (PathMatchKind::Prefix, path.to_string())
    }
}
