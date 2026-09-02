//! Terraform-compatible state tool (DW-065): a `dwara tf` CLI subcommand
//! that exports/imports Terraform-compatible JSON state and generates
//! HCL, performing plan/apply round-trips directly over the admin API.
//!
//! ## Why a CLI tool, not a terraform-plugin-rs provider
//!
//! The `terraform-plugin-rs` ecosystem is MPL-2.0, which is not in the
//! project's `deny.toml` allow list, and the compliance control must not
//! be modified. So this module implements a CLI-based Terraform state
//! tool instead: no gRPC plugin, no Terraform binary required, and no
//! new external dependencies (hyper, serde_json, serde_yaml_ng, serde,
//! clap, tokio are all already workspace deps).
//!
//! ## State model
//!
//! The tfstate JSON follows Terraform's state file structure (version,
//! terraform_version, resources[] with each resource having mode
//! "managed", type, name, instances[] with attributes). Dwara config
//! entities map to resources:
//!
//! - `dwara_listener` (one per listener)
//! - `dwara_route` (one per route)
//! - `dwara_service` (one per service)
//! - `dwara_upstream` (one per upstream, with endpoints as an attribute)
//! - `dwara_consumer` (one per consumer)
//!
//! The HCL file generates `resource "dwara_route" "<name>" { ... }`
//! blocks with the entity attributes. The state is structurally
//! Terraform-compatible so a future real provider or `terraform import`
//! could consume it.
//!
//! ## Plan/apply flow
//!
//! - `export`: GET /config from the admin API, parse the YAML via
//!   `dwara_core::config::parse_gateway`, then serialize each entity to
//!   tfstate attributes and HCL blocks.
//! - `plan`: read local tfstate, GET /config from the gateway, compute
//!   the diff (added/removed/changed entities), print it human-readably.
//!   Exit 0 if no diff, 1 if diff.
//! - `apply`: push the desired config to the gateway via PATCH /config
//!   (body = YAML), then refresh state from the response. If `--config`
//!   is given, use that YAML as the desired config; otherwise derive the
//!   desired YAML from the tfstate.

use std::collections::BTreeMap;

use dwara_core::config::{
    Endpoint, Gateway, Listener, ListenerProtocol, LoadBalancer, PathMatch, PathMatchKind, Route,
    RouteAction, RouteMatch, Service, Upstream, UpstreamProtocol,
};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// tfstate JSON model
// ---------------------------------------------------------------------------

/// The Terraform state file root shape. `version` is the state format
/// version (4 is the current Terraform state format version); the
/// `resources` array holds one entry per managed resource instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TfState {
    pub version: u32,
    pub terraform_version: String,
    pub resources: Vec<TfResource>,
}

/// One resource entry in the tfstate: a managed resource of `type` named
/// `name` with one instance carrying its attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TfResource {
    pub mode: String,
    #[serde(rename = "type")]
    pub r#type: String,
    pub name: String,
    pub instances: Vec<TfInstance>,
}

/// One instance of a resource: the `attributes` object holds the
/// entity's serialized fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TfInstance {
    pub attributes: Value,
}

// ---------------------------------------------------------------------------
// Gateway <-> tfstate conversion (pure functions)
// ---------------------------------------------------------------------------

/// Build a [`TfState`] from a parsed [`Gateway`]. Each listener, route,
/// service, upstream, and consumer becomes one managed resource. The
/// attribute set is the serde_json serialization of the entity (stable
/// and faithful enough for export -> apply -> export round-trips).
pub fn gateway_to_state(gateway: &Gateway) -> TfState {
    let mut resources = Vec::new();

    for l in &gateway.listeners {
        resources.push(TfResource {
            mode: "managed".to_string(),
            r#type: "dwara_listener".to_string(),
            name: l.name.clone(),
            instances: vec![TfInstance {
                attributes: serde_json::to_value(listener_attrs(l)).unwrap_or(Value::Null),
            }],
        });
    }
    for r in &gateway.routes {
        resources.push(TfResource {
            mode: "managed".to_string(),
            r#type: "dwara_route".to_string(),
            name: r.name.clone(),
            instances: vec![TfInstance {
                attributes: serde_json::to_value(route_attrs(r)).unwrap_or(Value::Null),
            }],
        });
    }
    for s in &gateway.services {
        resources.push(TfResource {
            mode: "managed".to_string(),
            r#type: "dwara_service".to_string(),
            name: s.name.clone(),
            instances: vec![TfInstance {
                attributes: serde_json::to_value(service_attrs(s)).unwrap_or(Value::Null),
            }],
        });
    }
    for u in &gateway.upstreams {
        resources.push(TfResource {
            mode: "managed".to_string(),
            r#type: "dwara_upstream".to_string(),
            name: u.name.clone(),
            instances: vec![TfInstance {
                attributes: serde_json::to_value(upstream_attrs(u)).unwrap_or(Value::Null),
            }],
        });
    }
    for c in &gateway.consumers {
        resources.push(TfResource {
            mode: "managed".to_string(),
            r#type: "dwara_consumer".to_string(),
            name: c.name.clone(),
            instances: vec![TfInstance {
                attributes: json!({ "name": c.name }),
            }],
        });
    }

    TfState {
        version: 4,
        terraform_version: "1.5.0".to_string(),
        resources,
    }
}

/// Serialize a [`TfState`] to pretty-printed JSON (the on-disk tfstate
/// file format).
pub fn state_to_json(state: &TfState) -> Result<String, String> {
    serde_json::to_string_pretty(state).map_err(|e| format!("serialize state: {e}"))
}

/// Parse a tfstate JSON string back into a [`TfState`].
pub fn state_from_json(text: &str) -> Result<TfState, String> {
    serde_json::from_str(text).map_err(|e| format!("parse state: {e}"))
}

/// Reconstruct a [`Gateway`] from a [`TfState`]. This is the inverse of
/// [`gateway_to_state`]: each resource's attributes are deserialized
/// back into the typed config entity. Fields not captured in the state
/// default to their schema defaults. The `allow_empty_routes` flag is
/// set when the reconstructed route list is empty (so validation passes
/// for a state that legitimately has no routes).
pub fn state_to_gateway(state: &TfState) -> Result<Gateway, String> {
    let mut listeners = Vec::new();
    let mut routes = Vec::new();
    let mut services = Vec::new();
    let mut upstreams = Vec::new();
    let mut consumers = Vec::new();

    for res in &state.resources {
        let attrs = res
            .instances
            .first()
            .map(|i| &i.attributes)
            .unwrap_or(&Value::Null);
        match res.r#type.as_str() {
            "dwara_listener" => {
                listeners.push(parse_listener_attrs(attrs)?);
            }
            "dwara_route" => {
                routes.push(parse_route_attrs(attrs)?);
            }
            "dwara_service" => {
                services.push(parse_service_attrs(attrs)?);
            }
            "dwara_upstream" => {
                upstreams.push(parse_upstream_attrs(attrs)?);
            }
            "dwara_consumer" => {
                let name = attrs
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
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
            _ => {}
        }
    }

    let allow_empty_routes = routes.is_empty();
    Ok(Gateway {
        listeners,
        routes,
        services,
        upstreams,
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
    })
}

// ---------------------------------------------------------------------------
// Attribute serialization (entity -> JSON value)
// ---------------------------------------------------------------------------

/// The subset of listener attributes captured in tfstate. The full
/// Listener struct is rich; the tf tool captures the fields that
/// round-trip through the admin API's normalized YAML (name, address,
/// port, protocol). TLS and policy attachments are documented as
/// follow-up scope (the dev admin round-trip is the primary target).
fn listener_attrs(l: &Listener) -> Value {
    json!({
        "name": l.name,
        "address": l.address,
        "port": l.port,
        "protocol": match l.protocol {
            ListenerProtocol::Http => "http",
            ListenerProtocol::Https => "https",
        },
    })
}

fn parse_listener_attrs(v: &Value) -> Result<Listener, String> {
    let name = v
        .get("name")
        .and_then(Value::as_str)
        .ok_or("listener missing name")?
        .to_string();
    let address = v
        .get("address")
        .and_then(Value::as_str)
        .ok_or("listener missing address")?
        .to_string();
    let port = v
        .get("port")
        .and_then(Value::as_u64)
        .ok_or("listener missing port")? as u16;
    let protocol = match v.get("protocol").and_then(Value::as_str) {
        Some("https") => ListenerProtocol::Https,
        _ => ListenerProtocol::Http,
    };
    Ok(Listener {
        name,
        address,
        port,
        protocol,
        tls: None,
        proxy_protocol: false,
        policies: Vec::new(),
        authorization: None,
    })
}

fn route_attrs(r: &Route) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("name".to_string(), json!(r.name));
    m.insert("service".to_string(), json!(r.service));
    m.insert(
        "path_type".to_string(),
        json!(match r.r#match.path.kind {
            PathMatchKind::Exact => "exact",
            PathMatchKind::Prefix => "prefix",
            PathMatchKind::Regex => "regex",
        }),
    );
    m.insert("path_value".to_string(), json!(r.r#match.path.value));
    if let Some(h) = &r.r#match.host {
        m.insert("host".to_string(), json!(h));
    }
    if !r.r#match.methods.is_empty() {
        m.insert("methods".to_string(), json!(r.r#match.methods));
    }
    let action_type = match &r.action {
        RouteAction::Proxy { .. } => "proxy",
        RouteAction::Redirect { .. } => "redirect",
        RouteAction::Respond { .. } => "respond",
        RouteAction::Mock { .. } => "mock",
        RouteAction::Ai => "ai",
    };
    m.insert("action_type".to_string(), json!(action_type));
    if r.auth_required {
        m.insert("auth_required".to_string(), json!(true));
    }
    if let Some(p) = r.priority {
        m.insert("priority".to_string(), json!(p));
    }
    Value::Object(m)
}

fn parse_route_attrs(v: &Value) -> Result<Route, String> {
    let name = v
        .get("name")
        .and_then(Value::as_str)
        .ok_or("route missing name")?
        .to_string();
    let service = v
        .get("service")
        .and_then(Value::as_str)
        .ok_or("route missing service")?
        .to_string();
    let path_type = v
        .get("path_type")
        .and_then(Value::as_str)
        .unwrap_or("prefix");
    let kind = match path_type {
        "exact" => PathMatchKind::Exact,
        "regex" => PathMatchKind::Regex,
        _ => PathMatchKind::Prefix,
    };
    let path_value = v
        .get("path_value")
        .and_then(Value::as_str)
        .unwrap_or("/")
        .to_string();
    let host = v.get("host").and_then(Value::as_str).map(String::from);
    let methods: Vec<String> = v
        .get("methods")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let auth_required = v
        .get("auth_required")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let priority = v.get("priority").and_then(Value::as_u64).map(|p| p as u8);

    Ok(Route {
        name,
        service,
        r#match: RouteMatch {
            path: PathMatch {
                kind,
                value: path_value,
            },
            host,
            methods,
            headers: BTreeMap::new(),
            query: Vec::new(),
            cookies: Vec::new(),
            accept: None,
        },
        action: RouteAction::Proxy { rewrite: None },
        policies: Vec::new(),
        priority,
        auth_required,
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
    })
}

fn service_attrs(s: &Service) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("name".to_string(), json!(s.name));
    if let Some(u) = &s.upstream {
        m.insert("upstream".to_string(), json!(u));
    }
    if let Some(bp) = &s.base_path {
        m.insert("base_path".to_string(), json!(bp));
    }
    if let Some(ver) = &s.version {
        m.insert("version".to_string(), json!(ver));
    }
    Value::Object(m)
}

fn parse_service_attrs(v: &Value) -> Result<Service, String> {
    let name = v
        .get("name")
        .and_then(Value::as_str)
        .ok_or("service missing name")?
        .to_string();
    let upstream = v.get("upstream").and_then(Value::as_str).map(String::from);
    let base_path = v.get("base_path").and_then(Value::as_str).map(String::from);
    let version = v.get("version").and_then(Value::as_str).map(String::from);
    Ok(Service {
        name,
        upstream,
        split: None,
        sticky: None,
        base_path,
        version,
        policies: Vec::new(),
        authorization: None,
    })
}

fn upstream_attrs(u: &Upstream) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("name".to_string(), json!(u.name));
    m.insert(
        "load_balancer".to_string(),
        json!(match u.load_balancer {
            LoadBalancer::RoundRobin => "round_robin",
            LoadBalancer::LeastRequests => "least_requests",
            LoadBalancer::Random => "random",
            LoadBalancer::IpHash => "ip_hash",
        }),
    );
    m.insert(
        "protocol".to_string(),
        json!(match u.protocol {
            UpstreamProtocol::Http1 => "http1",
            UpstreamProtocol::Http2 => "http2",
            UpstreamProtocol::Https => "https",
        }),
    );
    let endpoints: Vec<Value> = u
        .endpoints
        .iter()
        .map(|e| json!({ "address": e.address, "port": e.port, "weight": e.weight }))
        .collect();
    m.insert("endpoints".to_string(), json!(endpoints));
    Value::Object(m)
}

fn parse_upstream_attrs(v: &Value) -> Result<Upstream, String> {
    let name = v
        .get("name")
        .and_then(Value::as_str)
        .ok_or("upstream missing name")?
        .to_string();
    let load_balancer = match v.get("load_balancer").and_then(Value::as_str) {
        Some("least_requests") => LoadBalancer::LeastRequests,
        Some("random") => LoadBalancer::Random,
        Some("ip_hash") => LoadBalancer::IpHash,
        _ => LoadBalancer::RoundRobin,
    };
    let protocol = match v.get("protocol").and_then(Value::as_str) {
        Some("http2") => UpstreamProtocol::Http2,
        Some("https") => UpstreamProtocol::Https,
        _ => UpstreamProtocol::Http1,
    };
    let endpoints: Vec<Endpoint> = v
        .get("endpoints")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|e| {
                    let address = e.get("address")?.as_str()?.to_string();
                    let port = e.get("port")?.as_u64()? as u16;
                    let weight = e.get("weight").and_then(Value::as_u64).unwrap_or(1) as u32;
                    Some(Endpoint {
                        address,
                        port,
                        weight,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Upstream {
        name,
        load_balancer,
        protocol,
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
    })
}

// ---------------------------------------------------------------------------
// HCL generation
// ---------------------------------------------------------------------------

/// Generate an HCL `.tf` file from a [`Gateway`]: one `resource` block
/// per entity. The block body uses HCL attribute syntax with the same
/// fields captured in the tfstate attributes.
pub fn gateway_to_hcl(gateway: &Gateway) -> String {
    let mut out = String::new();
    out.push_str("# Generated by `dwara tf export`. Do not edit by hand;\n");
    out.push_str("# regenerate with `dwara tf export --out-hcl <path>`.\n\n");

    for l in &gateway.listeners {
        out.push_str(&format!(
            "resource \"dwara_listener\" \"{}\" {{\n  name    = \"{}\"\n  address = \"{}\"\n  port    = {}\n  protocol = \"{}\"\n}}\n\n",
            hcl_name(&l.name),
            l.name,
            l.address,
            l.port,
            match l.protocol {
                ListenerProtocol::Http => "http",
                ListenerProtocol::Https => "https",
            }
        ));
    }
    for r in &gateway.routes {
        out.push_str(&format!(
            "resource \"dwara_route\" \"{}\" {{\n",
            hcl_name(&r.name)
        ));
        out.push_str(&format!("  name    = \"{}\"\n", r.name));
        out.push_str(&format!("  service = \"{}\"\n", r.service));
        out.push_str(&format!(
            "  path_type  = \"{}\"\n",
            match r.r#match.path.kind {
                PathMatchKind::Exact => "exact",
                PathMatchKind::Prefix => "prefix",
                PathMatchKind::Regex => "regex",
            }
        ));
        out.push_str(&format!(
            "  path_value = \"{}\"\n",
            hcl_string(&r.r#match.path.value)
        ));
        if let Some(h) = &r.r#match.host {
            out.push_str(&format!("  host = \"{}\"\n", hcl_string(h)));
        }
        if !r.r#match.methods.is_empty() {
            let methods: Vec<String> = r
                .r#match
                .methods
                .iter()
                .map(|m| format!("\"{}\"", m))
                .collect();
            out.push_str(&format!("  methods = [{}]\n", methods.join(", ")));
        }
        let action_type = match &r.action {
            RouteAction::Proxy { .. } => "proxy",
            RouteAction::Redirect { .. } => "redirect",
            RouteAction::Respond { .. } => "respond",
            RouteAction::Mock { .. } => "mock",
            RouteAction::Ai => "ai",
        };
        out.push_str(&format!("  action_type = \"{}\"\n", action_type));
        if r.auth_required {
            out.push_str("  auth_required = true\n");
        }
        if let Some(p) = r.priority {
            out.push_str(&format!("  priority = {}\n", p));
        }
        out.push_str("}\n\n");
    }
    for s in &gateway.services {
        out.push_str(&format!(
            "resource \"dwara_service\" \"{}\" {{\n  name = \"{}\"\n",
            hcl_name(&s.name),
            s.name
        ));
        if let Some(u) = &s.upstream {
            out.push_str(&format!("  upstream = \"{}\"\n", u));
        }
        if let Some(bp) = &s.base_path {
            out.push_str(&format!("  base_path = \"{}\"\n", hcl_string(bp)));
        }
        if let Some(ver) = &s.version {
            out.push_str(&format!("  version = \"{}\"\n", hcl_string(ver)));
        }
        out.push_str("}\n\n");
    }
    for u in &gateway.upstreams {
        out.push_str(&format!(
            "resource \"dwara_upstream\" \"{}\" {{\n  name = \"{}\"\n",
            hcl_name(&u.name),
            u.name
        ));
        out.push_str(&format!(
            "  load_balancer = \"{}\"\n",
            match u.load_balancer {
                LoadBalancer::RoundRobin => "round_robin",
                LoadBalancer::LeastRequests => "least_requests",
                LoadBalancer::Random => "random",
                LoadBalancer::IpHash => "ip_hash",
            }
        ));
        out.push_str(&format!(
            "  protocol = \"{}\"\n",
            match u.protocol {
                UpstreamProtocol::Http1 => "http1",
                UpstreamProtocol::Http2 => "http2",
                UpstreamProtocol::Https => "https",
            }
        ));
        out.push_str("  endpoints = [\n");
        for e in &u.endpoints {
            out.push_str(&format!(
                "    {{ address = \"{}\", port = {}, weight = {} }},\n",
                hcl_string(&e.address),
                e.port,
                e.weight
            ));
        }
        out.push_str("  ]\n}\n\n");
    }
    for c in &gateway.consumers {
        out.push_str(&format!(
            "resource \"dwara_consumer\" \"{}\" {{\n  name = \"{}\"\n}}\n\n",
            hcl_name(&c.name),
            c.name
        ));
    }
    out
}

/// Sanitize a name into a valid HCL resource label (lowercase
/// alphanumerics and hyphens only; other characters become hyphens).
fn hcl_name(name: &str) -> String {
    name.chars()
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

/// Escape a string for inclusion in an HCL double-quoted string.
fn hcl_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

// ---------------------------------------------------------------------------
// Plan diff (pure function)
// ---------------------------------------------------------------------------

/// One line of a plan diff: the kind of change and a human-readable
/// description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffEntry {
    Added {
        r#type: String,
        name: String,
    },
    Removed {
        r#type: String,
        name: String,
    },
    Changed {
        r#type: String,
        name: String,
        detail: String,
    },
}

/// Compute the diff between a desired state (the local tfstate) and the
/// actual gateway config (parsed from GET /config). Returns a list of
/// diff entries; an empty list means no drift (plan is clean).
pub fn plan_diff(desired: &TfState, actual: &Gateway) -> Vec<DiffEntry> {
    let actual_state = gateway_to_state(actual);
    let desired_map = index_resources(desired);
    let actual_map = index_resources(&actual_state);
    let mut entries = Vec::new();

    let all_keys: std::collections::BTreeSet<(String, String)> = desired_map
        .keys()
        .chain(actual_map.keys())
        .cloned()
        .collect();
    for (rtype, name) in all_keys {
        match (
            desired_map.get(&(rtype.clone(), name.clone())),
            actual_map.get(&(rtype.clone(), name.clone())),
        ) {
            (Some(_d), None) => entries.push(DiffEntry::Added {
                r#type: rtype,
                name,
            }),
            (None, Some(_a)) => entries.push(DiffEntry::Removed {
                r#type: rtype,
                name,
            }),
            (Some(d), Some(a)) => {
                if d != a {
                    entries.push(DiffEntry::Changed {
                        r#type: rtype,
                        name,
                        detail: summarize_diff(d, a),
                    });
                }
            }
            (None, None) => {}
        }
    }
    entries
}

/// Index a state's resources by (type, name) -> serialized attributes
/// (a stable JSON string for comparison).
fn index_resources(state: &TfState) -> BTreeMap<(String, String), String> {
    let mut map = BTreeMap::new();
    for res in &state.resources {
        let attrs = res
            .instances
            .first()
            .map(|i| i.attributes.clone())
            .unwrap_or(Value::Null);
        let key = (res.r#type.clone(), res.name.clone());
        let serialized = serde_json::to_string(&attrs).unwrap_or_default();
        map.insert(key, serialized);
    }
    map
}

/// Produce a short human-readable summary of what changed between two
/// attribute JSON values (top-level key-level diff).
fn summarize_diff(desired: &str, actual: &str) -> String {
    let d: Value = serde_json::from_str(desired).unwrap_or(Value::Null);
    let a: Value = serde_json::from_str(actual).unwrap_or(Value::Null);
    let mut changes = Vec::new();
    if let (Some(dobj), Some(aobj)) = (d.as_object(), a.as_object()) {
        let all_keys: std::collections::BTreeSet<&String> =
            dobj.keys().chain(aobj.keys()).collect();
        for k in all_keys {
            let dv = dobj.get(k);
            let av = aobj.get(k);
            if dv != av {
                changes.push(format!(
                    "{}: {} -> {}",
                    k,
                    av.map(|v| v.to_string())
                        .unwrap_or_else(|| "(absent)".to_string()),
                    dv.map(|v| v.to_string())
                        .unwrap_or_else(|| "(absent)".to_string()),
                ));
            }
        }
    }
    if changes.is_empty() {
        "content differs".to_string()
    } else {
        changes.join("; ")
    }
}

/// Format a list of diff entries as human-readable text (one line per
/// entry). Returns the text and whether any diff was present.
pub fn format_diff(entries: &[DiffEntry]) -> (String, bool) {
    if entries.is_empty() {
        return (
            "No changes. Infrastructure is up-to-date.\n".to_string(),
            false,
        );
    }
    let mut out = String::new();
    for e in entries {
        match e {
            DiffEntry::Added { r#type, name } => {
                out.push_str(&format!("  + {} {} will be created\n", r#type, name));
            }
            DiffEntry::Removed { r#type, name } => {
                out.push_str(&format!("  - {} {} will be destroyed\n", r#type, name));
            }
            DiffEntry::Changed {
                r#type,
                name,
                detail,
            } => {
                out.push_str(&format!(
                    "  ~ {} {} will be changed ({})\n",
                    r#type, name, detail
                ));
            }
        }
    }
    out.push_str(&format!("\nPlan: {} change(s).\n", entries.len()));
    (out, true)
}

// ---------------------------------------------------------------------------
// Apply: derive desired YAML from state
// ---------------------------------------------------------------------------

/// Derive the desired config YAML from a tfstate (the apply step when
/// no `--config` file is given). Reconstructs the Gateway from the
/// state, then serializes it to normalized YAML.
pub fn state_to_yaml(state: &TfState) -> Result<String, String> {
    let gateway = state_to_gateway(state)?;
    dwara_core::config::gateway_to_yaml(&gateway).map_err(|e| format!("serialize: {e}"))
}

// ---------------------------------------------------------------------------
// HTTP client (hyper, plaintext loopback — the dev admin target)
// ---------------------------------------------------------------------------

/// One admin API endpoint: a base URL (scheme + host + port). The tf
/// tool targets the dev admin (plaintext loopback, `DWARA_ADMIN_DEV=1`).
/// mTLS to a production admin is configured via the same `--ca` /
/// `--client-cert` / `--client-key` flags the admin client uses; the
/// dev/loopback round-trip is the primary target and is plaintext-only
/// here (TLS support is a documented follow-up).
pub struct AdminClient {
    authority: String,
}

impl AdminClient {
    /// Create a client for `admin_url` (e.g. `http://127.0.0.1:2019`).
    /// Only `http://` is supported in this implementation; `https://`
    /// returns an error pointing at the mTLS follow-up.
    pub fn new(admin_url: &str) -> Result<Self, String> {
        let (scheme, authority) = admin_url
            .strip_prefix("http://")
            .map(|a| ("http", a))
            .or_else(|| admin_url.strip_prefix("https://").map(|a| ("https", a)))
            .ok_or_else(|| format!("invalid admin URL: {admin_url} (expected http://host:port)"))?;
        if scheme == "https" {
            return Err("HTTPS admin (mTLS) is not wired in the tf tool yet; \
                 use the dev plaintext admin (DWARA_ADMIN_DEV=1)"
                .to_string());
        }
        Ok(AdminClient {
            authority: authority.trim_end_matches('/').to_string(),
        })
    }

    /// GET /config from the admin API. Returns the response body as a
    /// string (normalized YAML of the current published config).
    pub async fn get_config(&self) -> Result<String, String> {
        let stream = TcpStream::connect(&self.authority)
            .await
            .map_err(|e| format!("connect to {}: {e}", self.authority))?;
        let (mut tx, rx) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| format!("handshake: {e}"))?;
        let driver = tokio::spawn(async move {
            let _ = rx.await;
        });
        let req = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri("/config")
            .header(hyper::header::HOST, &self.authority)
            .header(hyper::header::CONNECTION, "close")
            .body(Full::<Bytes>::new(Bytes::new()))
            .map_err(|e| format!("build request: {e}"))?;
        let res = tx
            .send_request(req)
            .await
            .map_err(|e| format!("send request: {e}"))?;
        let status = res.status();
        let body = res
            .into_body()
            .collect()
            .await
            .map_err(|e| format!("read body: {e}"))?
            .to_bytes();
        driver.abort();
        if !status.is_success() {
            return Err(format!(
                "GET /config returned {status}: {}",
                String::from_utf8_lossy(&body)
            ));
        }
        Ok(String::from_utf8_lossy(&body).to_string())
    }

    /// PATCH /config with a YAML body (full-document replacement).
    /// Returns the response body as a string (JSON with generation,
    /// content_hash, routes).
    pub async fn patch_config(&self, yaml: &str) -> Result<String, String> {
        let stream = TcpStream::connect(&self.authority)
            .await
            .map_err(|e| format!("connect to {}: {e}", self.authority))?;
        let (mut tx, rx) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| format!("handshake: {e}"))?;
        let driver = tokio::spawn(async move {
            let _ = rx.await;
        });
        let body_bytes = Bytes::from(yaml.as_bytes().to_vec());
        let req = hyper::Request::builder()
            .method(hyper::Method::PATCH)
            .uri("/config")
            .header(hyper::header::HOST, &self.authority)
            .header(hyper::header::CONTENT_TYPE, "application/yaml")
            .header(hyper::header::CONTENT_LENGTH, body_bytes.len().to_string())
            .header(hyper::header::CONNECTION, "close")
            .body(Full::new(body_bytes))
            .map_err(|e| format!("build request: {e}"))?;
        let res = tx
            .send_request(req)
            .await
            .map_err(|e| format!("send request: {e}"))?;
        let status = res.status();
        let resp_body = res
            .into_body()
            .collect()
            .await
            .map_err(|e| format!("read body: {e}"))?
            .to_bytes();
        driver.abort();
        if !status.is_success() {
            return Err(format!(
                "PATCH /config returned {status}: {}",
                String::from_utf8_lossy(&resp_body)
            ));
        }
        Ok(String::from_utf8_lossy(&resp_body).to_string())
    }
}

// ---------------------------------------------------------------------------
// High-level operations (used by the CLI; also testable as pure fns)
// ---------------------------------------------------------------------------

/// Export: fetch the current config from the admin API and produce
/// (tfstate JSON, HCL text). This is the "state import" step — bring a
/// running gateway's config under management.
pub async fn export(
    admin_url: &str,
    _ca: Option<&str>,
    _client_cert: Option<&str>,
    _client_key: Option<&str>,
) -> Result<(String, String), String> {
    let client = AdminClient::new(admin_url)?;
    let yaml = client.get_config().await?;
    let gateway = dwara_core::config::parse_gateway(&yaml)
        .map_err(|e| format!("parse gateway config: {e}"))?;
    let state = gateway_to_state(&gateway);
    let state_json = state_to_json(&state)?;
    let hcl = gateway_to_hcl(&gateway);
    Ok((state_json, hcl))
}

/// Plan: read local tfstate, fetch the current config, compute the diff,
/// and return the formatted plan text and whether a diff was present.
pub async fn plan(admin_url: &str, state_path: &str) -> Result<(String, bool), String> {
    let state_text = std::fs::read_to_string(state_path)
        .map_err(|e| format!("cannot read state file {state_path}: {e}"))?;
    let state = state_from_json(&state_text)?;
    let client = AdminClient::new(admin_url)?;
    let yaml = client.get_config().await?;
    let gateway = dwara_core::config::parse_gateway(&yaml)
        .map_err(|e| format!("parse gateway config: {e}"))?;
    let entries = plan_diff(&state, &gateway);
    Ok(format_diff(&entries))
}

/// Apply: push the desired config to the gateway. If `config_yaml` is
/// given, use it directly; otherwise derive the YAML from the tfstate.
/// Returns the admin API's PATCH response body.
pub async fn apply(
    admin_url: &str,
    state_path: &str,
    config_yaml: Option<&str>,
) -> Result<String, String> {
    let desired_yaml = if let Some(yaml) = config_yaml {
        yaml.to_string()
    } else {
        let state_text = std::fs::read_to_string(state_path)
            .map_err(|e| format!("cannot read state file {state_path}: {e}"))?;
        let state = state_from_json(&state_text)?;
        state_to_yaml(&state)?
    };
    let client = AdminClient::new(admin_url)?;
    client.patch_config(&desired_yaml).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_gateway() -> Gateway {
        Gateway {
            listeners: vec![Listener {
                name: "main".to_string(),
                address: "127.0.0.1".to_string(),
                port: 8080,
                protocol: ListenerProtocol::Http,
                tls: None,
                proxy_protocol: false,
                policies: Vec::new(),
                authorization: None,
            }],
            routes: vec![Route {
                name: "api".to_string(),
                service: "api-service".to_string(),
                r#match: RouteMatch {
                    path: PathMatch {
                        kind: PathMatchKind::Prefix,
                        value: "/api".to_string(),
                    },
                    host: Some("api.example.com".to_string()),
                    methods: vec!["GET".to_string(), "POST".to_string()],
                    headers: BTreeMap::new(),
                    query: Vec::new(),
                    cookies: Vec::new(),
                    accept: None,
                },
                action: RouteAction::Proxy { rewrite: None },
                policies: Vec::new(),
                priority: Some(5),
                auth_required: true,
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
            }],
            services: vec![Service {
                name: "api-service".to_string(),
                upstream: Some("api-upstream".to_string()),
                split: None,
                sticky: None,
                base_path: Some("/v1".to_string()),
                version: Some("v1".to_string()),
                policies: Vec::new(),
                authorization: None,
            }],
            upstreams: vec![Upstream {
                name: "api-upstream".to_string(),
                load_balancer: LoadBalancer::RoundRobin,
                protocol: UpstreamProtocol::Http1,
                trusted_ca_file: None,
                endpoints: vec![
                    Endpoint {
                        address: "127.0.0.1".to_string(),
                        port: 9000,
                        weight: 1,
                    },
                    Endpoint {
                        address: "127.0.0.1".to_string(),
                        port: 9001,
                        weight: 2,
                    },
                ],
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
        }
    }

    #[test]
    fn state_round_trip_preserves_entities() {
        let gw = sample_gateway();
        let state = gateway_to_state(&gw);
        let json = state_to_json(&state).unwrap();
        let parsed = state_from_json(&json).unwrap();
        let gw2 = state_to_gateway(&parsed).unwrap();
        assert_eq!(gw2.listeners.len(), 1);
        assert_eq!(gw2.listeners[0].name, "main");
        assert_eq!(gw2.listeners[0].port, 8080);
        assert_eq!(gw2.routes.len(), 1);
        assert_eq!(gw2.routes[0].name, "api");
        assert_eq!(gw2.routes[0].service, "api-service");
        assert_eq!(gw2.routes[0].r#match.path.kind, PathMatchKind::Prefix);
        assert_eq!(gw2.routes[0].r#match.path.value, "/api");
        assert_eq!(
            gw2.routes[0].r#match.host.as_deref(),
            Some("api.example.com")
        );
        assert_eq!(gw2.routes[0].r#match.methods, vec!["GET", "POST"]);
        assert!(gw2.routes[0].auth_required);
        assert_eq!(gw2.routes[0].priority, Some(5));
        assert_eq!(gw2.services.len(), 1);
        assert_eq!(gw2.services[0].upstream.as_deref(), Some("api-upstream"));
        assert_eq!(gw2.upstreams.len(), 1);
        assert_eq!(gw2.upstreams[0].endpoints.len(), 2);
        assert_eq!(gw2.upstreams[0].endpoints[0].port, 9000);
        assert_eq!(gw2.upstreams[0].endpoints[1].port, 9001);
        assert_eq!(gw2.upstreams[0].endpoints[1].weight, 2);
    }

    #[test]
    fn hcl_generation_contains_resource_blocks() {
        let gw = sample_gateway();
        let hcl = gateway_to_hcl(&gw);
        assert!(hcl.contains("resource \"dwara_listener\" \"main\""));
        assert!(hcl.contains("resource \"dwara_route\" \"api\""));
        assert!(hcl.contains("resource \"dwara_service\" \"api-service\""));
        assert!(hcl.contains("resource \"dwara_upstream\" \"api-upstream\""));
        assert!(hcl.contains("127.0.0.1"));
        assert!(hcl.contains("9000"));
        assert!(hcl.contains("9001"));
    }

    #[test]
    fn plan_diff_detects_removed_route() {
        let gw = sample_gateway();
        // The desired state is empty (no routes); the actual gateway has
        // the route -> it shows as removed (desired wants to destroy it).
        let mut empty_gw = gw.clone();
        empty_gw.routes.clear();
        empty_gw.allow_empty_routes = true;
        let empty_state = gateway_to_state(&empty_gw);
        let entries = plan_diff(&empty_state, &gw);
        assert!(entries.iter().any(|e| matches!(
            e,
            DiffEntry::Removed {
                r#type,
                name,
            } if r#type == "dwara_route" && name == "api"
        )));
    }

    #[test]
    fn plan_diff_detects_added_route() {
        let gw = sample_gateway();
        let state = gateway_to_state(&gw);
        // The desired state has the route; the actual gateway is empty
        // -> it shows as added (desired wants to create it).
        let mut empty = gw.clone();
        empty.routes.clear();
        empty.allow_empty_routes = true;
        let entries = plan_diff(&state, &empty);
        assert!(entries.iter().any(|e| matches!(
            e,
            DiffEntry::Added {
                r#type,
                name,
            } if r#type == "dwara_route" && name == "api"
        )));
    }

    #[test]
    fn plan_diff_detects_changed_upstream() {
        let gw = sample_gateway();
        let state = gateway_to_state(&gw);
        let mut gw2 = gw.clone();
        gw2.upstreams[0].endpoints[0].port = 9999;
        let entries = plan_diff(&state, &gw2);
        assert!(entries.iter().any(|e| matches!(
            e,
            DiffEntry::Changed {
                r#type,
                name,
                ..
            } if r#type == "dwara_upstream" && name == "api-upstream"
        )));
    }

    #[test]
    fn plan_diff_clean_when_identical() {
        let gw = sample_gateway();
        let state = gateway_to_state(&gw);
        let entries = plan_diff(&state, &gw);
        assert!(entries.is_empty());
    }

    #[test]
    fn state_to_yaml_produces_valid_config() {
        let gw = sample_gateway();
        let state = gateway_to_state(&gw);
        let yaml = state_to_yaml(&state).unwrap();
        let gw2 = dwara_core::config::parse_gateway(&yaml).unwrap();
        assert_eq!(gw2.routes.len(), 1);
        assert_eq!(gw2.upstreams.len(), 1);
    }

    #[test]
    fn format_diff_no_changes() {
        let (text, has_diff) = format_diff(&[]);
        assert!(!has_diff);
        assert!(text.contains("No changes"));
    }

    #[test]
    fn format_diff_with_changes() {
        let entries = vec![
            DiffEntry::Added {
                r#type: "dwara_route".to_string(),
                name: "new".to_string(),
            },
            DiffEntry::Removed {
                r#type: "dwara_upstream".to_string(),
                name: "old".to_string(),
            },
        ];
        let (text, has_diff) = format_diff(&entries);
        assert!(has_diff);
        assert!(text.contains("+ dwara_route new"));
        assert!(text.contains("- dwara_upstream old"));
    }

    #[test]
    fn empty_state_round_trips() {
        let gw = Gateway {
            listeners: Vec::new(),
            routes: Vec::new(),
            services: Vec::new(),
            upstreams: Vec::new(),
            consumers: Vec::new(),
            policies: Vec::new(),
            global_policies: Vec::new(),
            authorization: None,
            trusted_proxies: Vec::new(),
            max_concurrent_requests: None,
            load_shed_dry_run: false,
            jwt_providers: Vec::new(),
            admin: None,
            allow_empty_routes: true,
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
        let state = gateway_to_state(&gw);
        assert!(state.resources.is_empty());
        let json = state_to_json(&state).unwrap();
        let parsed = state_from_json(&json).unwrap();
        let gw2 = state_to_gateway(&parsed).unwrap();
        assert!(gw2.routes.is_empty());
        assert!(gw2.allow_empty_routes);
    }
}
