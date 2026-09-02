//! OpenAPI spec import (DW-047): `dwara import openapi` reads an
//! OpenAPI 3.x spec (YAML or JSON) and generates a Dwara config YAML
//! with routes derived from the spec's paths and methods.
//!
//! The import is a one-shot scaffolding step: it produces a config the
//! operator edits to point at their real backend (the placeholder
//! upstream `openapi-backend` at 127.0.0.1:9000). Each path+method
//! becomes a route with `type: exact` matching (OpenAPI paths are
//! exact, with `{param}` segments preserved as Dwara path params), a
//! `proxy` action, and an `openapi` extension field carrying the
//! operationId, summary, and tags for traceability.
//!
//! No new dependencies: `serde_yaml_ng` and `serde_json` (both already
//! workspace dependencies) parse the spec. A minimal OpenAPI 3.x struct
//! captures paths, methods, operationId, parameters, and requestBody
//! schemas — enough to generate routes; the full OpenAPI surface is
//! out of scope (this is scaffolding, not a spec validator).

use std::collections::BTreeMap;

use dwara_core::config::{
    Endpoint, Gateway, OpenApiMeta, PathMatch, PathMatchKind, Route, RouteAction, RouteMatch,
    Service, Upstream,
};
use serde::Deserialize;

/// The minimal OpenAPI 3.x document shape the importer reads. Unknown
/// fields are ignored (the spec is rich; we capture only what drives
/// route generation).
#[derive(Debug, Deserialize)]
struct OpenApiDoc {
    #[serde(default)]
    paths: BTreeMap<String, PathItem>,
    #[serde(default, rename = "x-openapi-version")]
    _version: Option<String>,
}

/// One path's operations (OpenAPI 3.x: `get`, `post`, ...). Unknown
/// fields (servers, parameters shared across operations) are ignored.
#[derive(Debug, Deserialize)]
struct PathItem {
    #[serde(default)]
    get: Option<Operation>,
    #[serde(default)]
    post: Option<Operation>,
    #[serde(default)]
    put: Option<Operation>,
    #[serde(default)]
    delete: Option<Operation>,
    #[serde(default)]
    patch: Option<Operation>,
    #[serde(default)]
    options: Option<Operation>,
    #[serde(default)]
    head: Option<Operation>,
}

/// One OpenAPI operation: operationId, summary, tags.
#[derive(Debug, Deserialize)]
struct Operation {
    #[serde(default, rename = "operationId")]
    operation_id: Option<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

/// The HTTP methods the importer recognizes, in a stable order for
/// deterministic route generation.
/// Function pointer type for extracting an operation from a path item.
type OpGetter = fn(&PathItem) -> Option<&Operation>;

const METHODS: &[(&str, OpGetter)] = &[
    ("GET", |p| p.get.as_ref()),
    ("POST", |p| p.post.as_ref()),
    ("PUT", |p| p.put.as_ref()),
    ("DELETE", |p| p.delete.as_ref()),
    ("PATCH", |p| p.patch.as_ref()),
    ("OPTIONS", |p| p.options.as_ref()),
    ("HEAD", |p| p.head.as_ref()),
];

/// The output of an import: the generated config YAML text, ready to
/// write to disk.
#[derive(Debug)]
pub struct ImportResult {
    pub yaml: String,
    pub route_count: usize,
}

/// Import an OpenAPI spec (YAML or JSON, detected by file extension or
/// content) and produce a Dwara config YAML. Returns an error string
/// on parse failure (the caller prints it and exits 1).
pub fn import_openapi(spec_text: &str, is_json: bool) -> Result<ImportResult, String> {
    let doc: OpenApiDoc = if is_json {
        serde_json::from_str(spec_text).map_err(|e| format!("invalid JSON spec: {e}"))?
    } else {
        serde_yaml_ng::from_str(spec_text).map_err(|e| format!("invalid YAML spec: {e}"))?
    };
    let gateway = build_gateway(&doc);
    let route_count = gateway.routes.len();
    let yaml = dwara_core::config::gateway_to_yaml(&gateway)
        .map_err(|e| format!("failed to serialize generated config: {e}"))?;
    Ok(ImportResult { yaml, route_count })
}

/// Detect whether the spec text is JSON (starts with `{` after
/// trimming leading whitespace/BOM) or YAML.
pub fn is_json_spec(text: &str) -> bool {
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    trimmed.starts_with('{')
}

/// Build a [`Gateway`] from the parsed OpenAPI document: one route per
/// UNIQUE PATH (Dwara's route table is path-only, so multiple methods
/// on the same path share a single route with `match.methods` listing
/// them all), one service, one placeholder upstream. The first
/// operation on each path drives the route name (operationId
/// preferred); subsequent methods on the same path are appended to
/// `match.methods`.
fn build_gateway(doc: &OpenApiDoc) -> Gateway {
    let mut routes = Vec::new();
    let mut used_names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for (path, item) in &doc.paths {
        let mut methods_for_path: Vec<String> = Vec::new();
        let mut first_op: Option<&Operation> = None;
        let mut first_method: Option<&str> = None;
        for (method, getter) in METHODS {
            let Some(op) = getter(item) else { continue };
            methods_for_path.push(method.to_string());
            if first_op.is_none() {
                first_op = Some(op);
                first_method = Some(method);
            }
        }
        if methods_for_path.is_empty() {
            continue;
        }
        let op = first_op.expect("at least one operation");
        let method = first_method.expect("at least one method");
        let name = derive_route_name(op, path, method, &mut used_names);
        let route = Route {
            name,
            service: "openapi-service".to_string(),
            r#match: RouteMatch {
                path: PathMatch {
                    kind: PathMatchKind::Exact,
                    value: path.clone(),
                },
                host: None,
                methods: methods_for_path,
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
            openapi: Some(OpenApiMeta {
                operation_id: op.operation_id.clone(),
                summary: op.summary.clone(),
                tags: op.tags.clone(),
                method: method.to_string(),
                path: path.clone(),
            }),
            mirror: None,
            fault_injection: None,
            plugins: Vec::new(),
        };
        routes.push(route);
    }

    let allow_empty_routes = routes.is_empty();
    Gateway {
        listeners: Vec::new(),
        routes,
        services: vec![Service {
            name: "openapi-service".to_string(),
            upstream: Some("openapi-backend".to_string()),
            split: None,
            sticky: None,
            base_path: None,
            version: None,
            policies: Vec::new(),
            authorization: None,
        }],
        upstreams: vec![Upstream {
            name: "openapi-backend".to_string(),
            load_balancer: dwara_core::config::LoadBalancer::RoundRobin,
            protocol: dwara_core::config::UpstreamProtocol::Http1,
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
        }],
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
    }
}

/// Derive a route name from the operationId (preferred) or a
/// path+method fallback. Ensures uniqueness by appending a counter
/// when the derived name collides.
fn derive_route_name(
    op: &Operation,
    path: &str,
    method: &str,
    used: &mut std::collections::BTreeSet<String>,
) -> String {
    let base = if let Some(id) = &op.operation_id {
        sanitize_name(id)
    } else {
        // Fallback: method + path with separators replaced.
        let path_slug = path
            .trim_start_matches('/')
            .replace('/', "-")
            .replace(['{', '}', '.'], "");
        let path_slug = path_slug.trim_matches('-');
        if path_slug.is_empty() {
            format!("{}-root", method.to_lowercase())
        } else {
            format!("{}-{}", method.to_lowercase(), path_slug)
        }
    };
    // Ensure uniqueness.
    let mut name = base.clone();
    let mut counter = 2;
    while !used.insert(name.clone()) {
        name = format!("{base}-{counter}");
        counter += 1;
    }
    name
}

/// Sanitize an operationId into a valid Dwara route name (lowercase,
/// alphanumerics and hyphens only).
fn sanitize_name(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}
