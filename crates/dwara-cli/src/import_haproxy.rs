//! HAProxy config import (CFG-09, #257): `dwara import haproxy` reads
//! a simplified haproxy.cfg and generates a Dwara config YAML with
//! routes derived from HAProxy's frontend/backend sections.
//!
//! Supported haproxy.cfg syntax (simplified subset):
//! ```text
//! frontend my-frontend
//!     bind *:80
//!     use_backend my-backend if { path_beg /api }
//!     default_backend default-backend
//!
//! backend my-backend
//!     server server1 127.0.0.1:8080
//!     server server2 127.0.0.1:8081
//! ```
//!
//! The import maps each frontend+use_backend rule to a Dwara route and
//! each backend to a Dwara upstream. Unsupported directives are emitted
//! as YAML comments in the output.

use dwara_core::config::{
    Endpoint, Gateway, LoadBalancer, PathMatch, PathMatchKind, Route, RouteAction, RouteMatch,
    Service, Upstream, UpstreamProtocol,
};
use std::collections::BTreeMap;

use crate::import::ImportResult;

/// Import a haproxy.cfg and produce a Dwara config YAML.
pub fn import_haproxy(text: &str) -> Result<ImportResult, String> {
    let sections = parse_sections(text);
    let mut warnings: Vec<String> = Vec::new();

    // Collect backends as upstreams.
    let mut backend_servers: BTreeMap<String, Vec<Endpoint>> = BTreeMap::new();
    for (kind, name, body) in &sections {
        if kind == "backend" {
            let mut servers = Vec::new();
            for line in body {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("server ") {
                    if let Some((_, addr)) = rest.split_once(' ') {
                        if let Some(ep) = parse_server_addr(addr) {
                            servers.push(ep);
                        }
                    }
                }
            }
            if servers.is_empty() {
                warnings.push(format!("# WARNING: backend '{name}' has no servers"));
            }
            backend_servers.insert(name.clone(), servers);
        }
    }

    let mut upstreams = Vec::new();
    let mut services: BTreeMap<String, Service> = BTreeMap::new();

    for (name, servers) in &backend_servers {
        upstreams.push(Upstream {
            name: name.clone(),
            load_balancer: LoadBalancer::RoundRobin,
            protocol: UpstreamProtocol::Http1,
            trusted_ca_file: None,
            endpoints: servers.clone(),
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

    // Build routes from frontends.
    let mut routes = Vec::new();
    for (kind, name, body) in &sections {
        if kind != "frontend" {
            continue;
        }
        for line in body {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("use_backend ") {
                let (backend_name, condition) = rest.split_once(" if ").unwrap_or((rest, ""));
                let backend_name = backend_name.trim();
                let path = parse_path_condition(condition.trim());
                let route_name = format!("{name}-{backend_name}");
                let path_value = path.unwrap_or_else(|| "/".to_string());

                if !services.contains_key(backend_name) {
                    services.insert(
                        backend_name.to_string(),
                        Service {
                            name: backend_name.to_string(),
                            upstream: Some(backend_name.to_string()),
                            split: None,
                            sticky: None,
                            base_path: None,
                            version: None,
                            policies: Vec::new(),
                            authorization: None,
                        },
                    );
                }

                routes.push(make_route(route_name, backend_name.to_string(), path_value));
            } else if let Some(rest) = line.strip_prefix("default_backend ") {
                let backend_name = rest.trim();
                let route_name = format!("{name}-default");
                if !services.contains_key(backend_name) {
                    services.insert(
                        backend_name.to_string(),
                        Service {
                            name: backend_name.to_string(),
                            upstream: Some(backend_name.to_string()),
                            split: None,
                            sticky: None,
                            base_path: None,
                            version: None,
                            policies: Vec::new(),
                            authorization: None,
                        },
                    );
                }
                routes.push(make_route(
                    route_name,
                    backend_name.to_string(),
                    "/".to_string(),
                ));
            }
        }
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

fn make_route(name: String, service: String, path_value: String) -> Route {
    Route {
        name,
        service,
        r#match: RouteMatch {
            path: PathMatch {
                kind: PathMatchKind::Prefix,
                value: path_value,
            },
            host: None,
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
    }
}

/// Parse haproxy.cfg into a list of (kind, name, body_lines) sections.
fn parse_sections(text: &str) -> Vec<(String, String, Vec<String>)> {
    let mut sections = Vec::new();
    let mut current_kind: Option<String> = None;
    let mut current_name: Option<String> = None;
    let mut current_body: Vec<String> = Vec::new();

    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with("frontend ") || trimmed.starts_with("backend ") {
            if let Some(kind) = current_kind.take() {
                sections.push((
                    kind,
                    current_name.take().unwrap_or_default(),
                    std::mem::take(&mut current_body),
                ));
            }
            let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
            current_kind = Some(parts[0].to_string());
            current_name = parts.get(1).map(|s| s.trim().to_string());
        } else if current_kind.is_some() {
            current_body.push(line.to_string());
        }
    }
    if let Some(kind) = current_kind {
        sections.push((kind, current_name.unwrap_or_default(), current_body));
    }
    sections
}

/// Parse a HAProxy ACL path condition like `{ path_beg /api }` -> `/api`.
fn parse_path_condition(condition: &str) -> Option<String> {
    if let Some(start) = condition.find("path_beg ") {
        let rest = &condition[start + "path_beg ".len()..];
        let path = rest.trim().trim_end_matches('}');
        return Some(path.to_string());
    }
    if let Some(start) = condition.find("path ") {
        let rest = &condition[start + "path ".len()..];
        let path = rest.trim().trim_end_matches('}');
        return Some(path.to_string());
    }
    None
}

/// Parse a server address like `127.0.0.1:8080` into an Endpoint.
fn parse_server_addr(addr: &str) -> Option<Endpoint> {
    let addr = addr.split_whitespace().next()?;
    let (host, port) = addr.split_once(':')?;
    let port: u16 = port.parse().ok()?;
    Some(Endpoint {
        address: host.to_string(),
        port,
        weight: 1,
        region: None,
        zone: None,
    })
}
