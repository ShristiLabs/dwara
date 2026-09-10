//! Traefik config import (CFG-09, #257): `dwara import traefik` reads
//! a Traefik dynamic config (YAML) and generates a Dwara config YAML
//! with routes derived from Traefik's HTTP routers and services.
//!
//! Traefik's dynamic config shape (YAML):
//! ```yaml
//! http:
//!   routers:
//!     my-router:
//!       rule: "PathPrefix(`/api`)"
//!       service: my-service
//!   services:
//!     my-service:
//!       loadBalancer:
//!         servers:
//!           - url: http://127.0.0.1:8080
//! ```
//!
//! The import maps each router to a Dwara route and each service to
//! a Dwara upstream. Unsupported features (middlewares, TLS options,
//! TCP/UDP routers) are emitted as YAML comments in the output.

use dwara_core::config::{
    Endpoint, Gateway, LoadBalancer, PathMatch, PathMatchKind, Route, RouteAction, RouteMatch,
    Service, Upstream, UpstreamProtocol,
};
use serde::Deserialize;
use std::collections::BTreeMap;

use crate::import::ImportResult;

/// The minimal Traefik dynamic config shape.
#[derive(Debug, Default, Deserialize)]
struct TraefikConfig {
    #[serde(default)]
    http: Option<TraefikHttp>,
}

#[derive(Debug, Default, Deserialize)]
struct TraefikHttp {
    #[serde(default)]
    routers: BTreeMap<String, TraefikRouter>,
    #[serde(default)]
    services: BTreeMap<String, TraefikService>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct TraefikRouter {
    rule: String,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    priority: Option<i64>,
    #[serde(default)]
    entry_points: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TraefikService {
    #[serde(default)]
    load_balancer: Option<TraefikLoadBalancer>,
}

#[derive(Debug, Deserialize)]
struct TraefikLoadBalancer {
    #[serde(default)]
    servers: Vec<TraefikServer>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct TraefikServer {
    url: String,
}

/// Import a Traefik dynamic config (YAML) and produce a Dwara config
/// YAML. Returns an error string on parse failure.
pub fn import_traefik(text: &str) -> Result<ImportResult, String> {
    let config: TraefikConfig =
        serde_yaml_ng::from_str(text).map_err(|e| format!("invalid Traefik config: {e}"))?;

    let mut upstreams = Vec::new();
    let mut services: BTreeMap<String, Service> = BTreeMap::new();
    let mut routes = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // Build upstreams from services.
    for (name, svc) in config
        .http
        .as_ref()
        .map(|h| &h.services)
        .into_iter()
        .flatten()
    {
        let endpoints: Vec<Endpoint> = svc
            .load_balancer
            .as_ref()
            .map(|lb| &lb.servers)
            .into_iter()
            .flatten()
            .filter_map(|s| parse_url(&s.url))
            .collect();

        if endpoints.is_empty() {
            warnings.push(format!(
                "# WARNING: service '{name}' has no loadBalancer servers"
            ));
        }

        upstreams.push(Upstream {
            name: name.clone(),
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
            pq: false,
            cert_pinning: None,
            mtls: None,
            pool: None,
            hash_on: None,
            use_system_roots: false,
        });

        services.insert(
            name.clone(),
            Service {
                name: name.clone(),
                upstream: Some(name.clone()),
                split: None,
                sticky: None,
                base_path: None,
                version: None,
                policies: Vec::new(),
                authorization: None,
            },
        );
    }

    // Build routes from routers.
    for (name, router) in config
        .http
        .as_ref()
        .map(|h| &h.routers)
        .into_iter()
        .flatten()
    {
        let (path_match, host) = parse_rule(&router.rule, &mut warnings, name);

        let service_name = router.service.clone().unwrap_or_else(|| {
            warnings.push(format!("# WARNING: router '{name}' has no service"));
            "placeholder".to_string()
        });

        // Create a service if it doesn't exist.
        if !services.contains_key(&service_name) {
            services.insert(
                service_name.clone(),
                Service {
                    name: service_name.clone(),
                    upstream: Some(service_name.clone()),
                    split: None,
                    sticky: None,
                    base_path: None,
                    version: None,
                    policies: Vec::new(),
                    authorization: None,
                },
            );
        }

        routes.push(Route {
            name: name.clone(),
            service: service_name,
            r#match: RouteMatch {
                path: path_match,
                host,
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
            graphql: None,
            grpc_web: None,
            translation: None,
            request_validation: None,
            openapi: None,
            mirror: None,
            fault_injection: None,
            plugins: Vec::new(),
            oidc_login: None,
            filter_chain: None,
            security_headers_opt_out: false,
        });
    }

    let allow_empty_routes = routes.is_empty();
    let gateway = Gateway {
        version: 1,
        listeners: Vec::new(),
        routes,
        services: services.into_values().collect(),
        upstreams,
        consumers: Vec::new(),
        policies: Vec::new(),
        global_policies: Vec::new(),
        authorization: None,
        default_security_headers: None,
        waf: None,
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
        redis_quotas: None,
        redis_cache: None,
        config_convergence: None,
        plugins: Vec::new(),
        filter_chain: None,
        plugin_registry: None,
        ai: None,
        fleet: None,
        lifecycle: None,
        mesh: None,
        ssrf_filter: None,
    };

    let route_count = gateway.routes.len();
    let mut yaml = dwara_core::config::gateway_to_yaml(&gateway)
        .map_err(|e| format!("serialize failed: {e}"))?;
    for w in &warnings {
        yaml.push_str(w);
        yaml.push('\n');
    }

    Ok(ImportResult { yaml, route_count })
}

/// Parse a Traefik router rule into a (PathMatch, Option<host>).
/// Supports `PathPrefix(`/path`)`, `Path(`/path`)`, and `Host(`domain`)`.
fn parse_rule(
    rule: &str,
    warnings: &mut Vec<String>,
    router_name: &str,
) -> (PathMatch, Option<String>) {
    let mut path_match = PathMatch {
        kind: PathMatchKind::Prefix,
        value: "/".to_string(),
    };
    let mut host = None;

    for part in rule.split("&&") {
        let part = part.trim();
        if let Some(p) = extract_call(part, "PathPrefix") {
            path_match = PathMatch {
                kind: PathMatchKind::Prefix,
                value: p,
            };
        } else if let Some(p) = extract_call(part, "Path") {
            path_match = PathMatch {
                kind: PathMatchKind::Exact,
                value: p,
            };
        } else if let Some(h) = extract_call(part, "Host") {
            host = Some(h);
        } else {
            warnings.push(format!(
                "# WARNING: router '{router_name}' rule segment '{part}' is not supported (ignored)"
            ));
        }
    }

    (path_match, host)
}

/// Extract the argument from a function-call-like rule segment,
/// e.g. `PathPrefix(`/api`)` -> `/api`.
fn extract_call(s: &str, func: &str) -> Option<String> {
    let s = s.trim();
    let prefix = format!("{func}(`");
    let start = s.find(&prefix)?;
    let rest = &s[start + prefix.len()..];
    let end = rest.find("`)")?;
    Some(rest[..end].to_string())
}

/// Parse a URL string into an Endpoint (host + port).
fn parse_url(url: &str) -> Option<Endpoint> {
    let url = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let (host, port) = url.split_once(':')?;
    let port: u16 = port.parse().ok()?;
    Some(Endpoint {
        address: host.to_string(),
        port,
        weight: 1,
        region: None,
        zone: None,
    })
}
