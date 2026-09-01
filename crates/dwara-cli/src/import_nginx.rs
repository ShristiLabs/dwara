//! NGINX config import (DW-065): `dwara import nginx` reads an NGINX
//! config file and generates a Dwara config YAML with routes derived
//! from the NGINX `location` blocks.
//!
//! This is a switching-cost lever for teams migrating off NGINX to
//! Dwara. The import is a one-shot scaffolding step: it produces a
//! config the operator edits to add Dwara-specific features (authn,
//! rate limiting, etc.) that NGINX does not have native equivalents
//! for.
//!
//! ## Supported NGINX directives
//!
//! - `server` blocks with `listen` (port) and `server_name` (host)
//! - `location` blocks with `proxy_pass` (upstream URL)
//! - `location` match modifiers: exact (`=`), prefix (none), regex
//!   (`~` case-sensitive, `~*` case-insensitive)
//! - `upstream` blocks with `server` directives (endpoints)
//!
//! ## Unsupported constructs
//!
//! The import reports unsupported constructs so the operator knows
//! what to review manually:
//! - `if` directives (NGINX's `if` is notoriously unpredictable)
//! - `rewrite` directives (Dwara has its own rewrite system)
//! - `auth_basic` (Dwara has its own authn system)
//! - `limit_req` (Dwara has its own rate limiting)
//! - Custom modules (Lua, Perl, etc.)
//! - `try_files` (Dwara is a proxy, not a file server)
//!
//! No new dependencies: a minimal NGINX config parser is implemented
//! inline (NGINX config syntax is simple enough for a line-based
//! parser to handle the common cases).

use std::collections::BTreeMap;

use dwara_core::config::{
    Endpoint, Gateway, PathMatch, PathMatchKind, Route, RouteAction, RouteMatch, Service, Upstream,
};

use super::import::ImportResult;

/// Import an NGINX config and produce a Dwara config YAML.
///
/// Returns the generated config and a list of warnings about
/// unsupported constructs (appended as comments at the end of the
/// YAML).
pub fn import_nginx(config_text: &str) -> Result<ImportResult, String> {
    let nginx_conf = parse_nginx_config(config_text)?;
    let (gateway, warnings) = build_gateway_from_nginx(&nginx_conf);
    let route_count = gateway.routes.len();
    let mut yaml =
        dwara_core::config::gateway_to_yaml(&gateway).map_err(|e| format!("serialize: {e}"))?;

    // Append warnings as a comment block at the end of the YAML.
    if !warnings.is_empty() {
        yaml.push_str("\n# --- Import warnings ---\n");
        yaml.push_str("# The following NGINX constructs are not supported and were skipped.\n");
        yaml.push_str("# Review and handle them manually in Dwara config.\n");
        for w in &warnings {
            yaml.push_str(&format!("# - {w}\n"));
        }
    }

    Ok(ImportResult { yaml, route_count })
}

/// The parsed NGINX config: a list of `http`-level upstreams and
/// server blocks.
#[derive(Debug, Default)]
struct NginxConfig {
    upstreams: Vec<NginxUpstream>,
    servers: Vec<NginxServer>,
}

/// An NGINX `upstream` block.
#[derive(Debug, Default)]
struct NginxUpstream {
    name: String,
    servers: Vec<String>, // e.g. "127.0.0.1:8080"
}

/// An NGINX `server` block.
#[derive(Debug, Default)]
struct NginxServer {
    listen: Vec<u16>,
    server_name: Vec<String>,
    locations: Vec<NginxLocation>,
    warnings: Vec<String>,
}

/// An NGINX `location` block.
#[derive(Debug, Default)]
struct NginxLocation {
    /// The match modifier: "=", "", "~", "~*", "^~"
    modifier: String,
    /// The match path/pattern.
    path: String,
    /// The `proxy_pass` URL, if any.
    proxy_pass: Option<String>,
    /// Unsupported directives found in this location.
    warnings: Vec<String>,
}

/// Parse an NGINX config text into a minimal structure.
fn parse_nginx_config(text: &str) -> Result<NginxConfig, String> {
    let mut config = NginxConfig::default();
    let mut stack: Vec<BlockContext> = Vec::new();

    for (line_no, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Remove trailing comments (naive: doesn't handle # in strings).
        let line = if let Some(idx) = find_comment(line) {
            line[..idx].trim_end()
        } else {
            line
        };

        if line.is_empty() {
            continue;
        }

        // Check for block open (ends with `{`).
        if let Some(directive) = line.strip_suffix('{') {
            let directive = directive.trim();
            let parts: Vec<&str> = directive.splitn(2, char::is_whitespace).collect();
            let block_type = parts[0];
            let block_args = parts.get(1).unwrap_or(&"").trim();

            match block_type {
                "http" => stack.push(BlockContext::Http),
                "upstream" => {
                    let name = block_args.to_string();
                    // Pre-create the upstream so server directives can find it.
                    config.upstreams.push(NginxUpstream {
                        name: name.clone(),
                        servers: vec![],
                    });
                    stack.push(BlockContext::Upstream(name));
                }
                "server" => {
                    // Accept server blocks both inside http {} and at the
                    // top level (many NGINX configs omit the http wrapper
                    // in examples, and the test configs do too).
                    stack.push(BlockContext::Server(NginxServer::default()));
                }
                "location" => {
                    if let Some(BlockContext::Server(_)) = stack.last() {
                        let (modifier, path) = parse_location_args(block_args);
                        let loc = NginxLocation {
                            modifier,
                            path,
                            proxy_pass: None,
                            warnings: vec![],
                        };
                        stack.push(BlockContext::Location(loc));
                    }
                }
                _ => {
                    stack.push(BlockContext::Unknown);
                }
            }
            continue;
        }

        // Check for block close (`}`).
        if line == "}" {
            if let Some(ctx) = stack.pop() {
                match ctx {
                    BlockContext::Server(server) => {
                        // Accept server blocks at any nesting level (http {}
                        // or top-level).
                        config.servers.push(server);
                    }
                    BlockContext::Location(loc) => {
                        if let Some(BlockContext::Server(server)) = stack.last_mut() {
                            server.locations.push(loc);
                        }
                    }
                    _ => {}
                }
            }
            continue;
        }

        // Simple directive (inside a block).
        let parts: Vec<&str> = line.splitn(2, char::is_whitespace).collect();
        let directive = parts[0];
        let args = parts.get(1).unwrap_or(&"").trim().trim_end_matches(';');

        match stack.last_mut() {
            Some(BlockContext::Upstream(name)) => {
                if directive == "server" {
                    if let Some(u) = config.upstreams.iter_mut().find(|u| u.name == *name) {
                        u.servers.push(args.to_string());
                    }
                }
            }
            Some(BlockContext::Server(server)) => match directive {
                "listen" => {
                    if let Some(port) = parse_listen_port(args) {
                        server.listen.push(port);
                    }
                }
                "server_name" => {
                    server
                        .server_name
                        .extend(args.split_whitespace().map(String::from));
                }
                "auth_basic" | "auth_basic_user_file" => {
                    server.warnings.push(format!(
                        "line {}: {} -- use Dwara authn (API key / Basic / JWT / mTLS)",
                        line_no + 1,
                        directive
                    ));
                }
                "limit_req" | "limit_req_zone" => {
                    server.warnings.push(format!(
                        "line {}: {} -- use Dwara rate limiting",
                        line_no + 1,
                        directive
                    ));
                }
                _ if is_unsupported_directive(directive) => {
                    server.warnings.push(format!(
                        "line {}: {} -- unsupported, review manually",
                        line_no + 1,
                        directive
                    ));
                }
                _ => {}
            },
            Some(BlockContext::Location(loc)) => match directive {
                "proxy_pass" => {
                    loc.proxy_pass = Some(args.to_string());
                }
                "rewrite" => {
                    loc.warnings.push(format!(
                        "line {}: rewrite -- use Dwara path rewrite/regex rewrite",
                        line_no + 1
                    ));
                }
                "auth_basic" | "auth_basic_user_file" => {
                    loc.warnings.push(format!(
                        "line {}: {} -- use Dwara authn",
                        line_no + 1,
                        directive
                    ));
                }
                "limit_req" => {
                    loc.warnings.push(format!(
                        "line {}: limit_req -- use Dwara rate limiting",
                        line_no + 1
                    ));
                }
                "try_files" => {
                    loc.warnings.push(format!(
                        "line {}: try_files -- Dwara is a proxy, not a file server",
                        line_no + 1
                    ));
                }
                "if" => {
                    loc.warnings.push(format!(
                        "line {}: if -- NGINX if is not supported, use Dwara CEL conditions",
                        line_no + 1
                    ));
                }
                _ if is_unsupported_directive(directive) => {
                    loc.warnings.push(format!(
                        "line {}: {} -- unsupported, review manually",
                        line_no + 1,
                        directive
                    ));
                }
                _ => {}
            },
            _ => {}
        }
    }

    Ok(config)
}

/// The block context for the parser's stack.
#[derive(Debug)]
enum BlockContext {
    Http,
    Upstream(String),
    Server(NginxServer),
    Location(NginxLocation),
    Unknown,
}

/// Parse the `listen` directive args to extract the port.
fn parse_listen_port(args: &str) -> Option<u16> {
    let first = args.split_whitespace().next()?;
    let port_str = if let Some((_, port)) = first.rsplit_once(':') {
        port
    } else {
        first
    };
    port_str.parse::<u16>().ok()
}

/// Parse the `location` directive args to extract the modifier and path.
fn parse_location_args(args: &str) -> (String, String) {
    let args = args.trim();
    if let Some(rest) = args.strip_prefix('=') {
        ("=".to_string(), rest.trim().to_string())
    } else if let Some(rest) = args.strip_prefix("~*") {
        ("~*".to_string(), rest.trim().to_string())
    } else if let Some(rest) = args.strip_prefix('~') {
        ("~".to_string(), rest.trim().to_string())
    } else if let Some(rest) = args.strip_prefix("^~") {
        ("^~".to_string(), rest.trim().to_string())
    } else {
        ("".to_string(), args.to_string())
    }
}

/// Check if a directive is unsupported (generates a warning).
fn is_unsupported_directive(d: &str) -> bool {
    matches!(
        d,
        "lua_"
            | "perl_"
            | "auth_request"
            | "sub_filter"
            | "add_header"
            | "proxy_set_header"
            | "proxy_redirect"
            | "proxy_cache"
            | "proxy_buffering"
            | "proxy_next_upstream"
            | "proxy_connect_timeout"
            | "proxy_read_timeout"
            | "proxy_send_timeout"
            | "ssl_certificate"
            | "ssl_certificate_key"
            | "ssl_protocols"
            | "ssl_ciphers"
            | "client_max_body_size"
            | "client_body_timeout"
            | "send_timeout"
            | "keepalive_timeout"
            | "gzip"
            | "gzip_types"
            | "gzip_comp_level"
            | "access_log"
            | "error_log"
            | "root"
            | "index"
            | "return"
            | "set"
            | "map"
            | "geo"
            | "split_clients"
            | "include"
    )
}

/// Find a comment (`#`) in a line, respecting quoted strings.
fn find_comment(line: &str) -> Option<usize> {
    let mut in_single = false;
    let mut in_double = false;
    for (i, c) in line.char_indices() {
        match c {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => return Some(i),
            _ => {}
        }
    }
    None
}

/// Build a Dwara Gateway from the parsed NGINX config.
fn build_gateway_from_nginx(conf: &NginxConfig) -> (Gateway, Vec<String>) {
    let mut warnings = Vec::new();
    let mut services = BTreeMap::new();
    let mut upstreams = BTreeMap::new();
    let mut routes = Vec::new();

    // Convert NGINX upstreams to Dwara upstreams + services.
    for up in &conf.upstreams {
        let endpoints: Vec<Endpoint> = up
            .servers
            .iter()
            .filter_map(|s| parse_endpoint(s))
            .collect();

        if endpoints.is_empty() {
            warnings.push(format!(
                "upstream '{}' has no valid server endpoints",
                up.name
            ));
            continue;
        }

        let upstream_name = format!("{}-upstream", up.name);
        let service_name = format!("{}-service", up.name);

        upstreams.insert(
            upstream_name.clone(),
            Upstream {
                name: upstream_name.clone(),
                load_balancer: dwara_core::config::LoadBalancer::RoundRobin,
                protocol: dwara_core::config::UpstreamProtocol::Http1,
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
            },
        );

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

    // Convert NGINX server locations to Dwara routes.
    for server in &conf.servers {
        for loc in &server.locations {
            if loc.proxy_pass.is_none() {
                if !loc.path.is_empty() {
                    warnings.push(format!(
                        "location '{}' has no proxy_pass -- skipped (Dwara is a proxy)",
                        loc.path
                    ));
                }
                continue;
            }

            let proxy_pass = loc.proxy_pass.as_ref().unwrap();
            let (target, is_upstream_ref) = resolve_proxy_pass(proxy_pass, &conf.upstreams);

            let service_name = if is_upstream_ref {
                target
            } else {
                let endpoint = match parse_endpoint(&target) {
                    Some(e) => e,
                    None => {
                        warnings.push(format!(
                            "location '{}' proxy_pass '{}' -- could not parse endpoint",
                            loc.path, proxy_pass
                        ));
                        continue;
                    }
                };
                let idx = routes.len();
                let upstream_name = format!("route-{idx}-upstream");
                let svc_name = format!("route-{idx}-service");
                upstreams.insert(
                    upstream_name.clone(),
                    Upstream {
                        name: upstream_name.clone(),
                        load_balancer: dwara_core::config::LoadBalancer::RoundRobin,
                        protocol: dwara_core::config::UpstreamProtocol::Http1,
                        trusted_ca_file: None,
                        endpoints: vec![endpoint],
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
                    },
                );
                services.insert(
                    svc_name.clone(),
                    Service {
                        name: svc_name.clone(),
                        upstream: Some(upstream_name),
                        split: None,
                        sticky: None,
                        base_path: None,
                        version: None,
                        policies: Vec::new(),
                        authorization: None,
                    },
                );
                svc_name
            };

            let (match_type, path_value) = convert_location_match(&loc.modifier, &loc.path);

            let idx = routes.len();
            let route_name = format!("route-{idx}");
            routes.push(Route {
                name: route_name,
                service: service_name,
                r#match: RouteMatch {
                    path: PathMatch {
                        kind: match_type,
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
                request_validation: None,
                openapi: None,
                mirror: None,
                fault_injection: None,
                plugins: Vec::new(),
            });

            warnings.extend(loc.warnings.iter().cloned());
        }

        warnings.extend(server.warnings.iter().cloned());
    }

    let allow_empty_routes = routes.is_empty();
    let gateway = Gateway {
        listeners: Vec::new(),
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
    };

    (gateway, warnings)
}

/// Resolve a `proxy_pass` URL to a service name.
///
/// Returns (target, is_upstream_ref). If the proxy_pass references an
/// NGINX upstream (e.g. `proxy_pass http://my_upstream;`),
/// is_upstream_ref is true and target is the generated service name.
/// Otherwise, target is the host:port from the URL.
fn resolve_proxy_pass(url: &str, upstreams: &[NginxUpstream]) -> (String, bool) {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);

    let host = rest.split('/').next().unwrap_or(rest);

    for up in upstreams {
        if host == up.name {
            return (format!("{}-service", up.name), true);
        }
    }

    (host.to_string(), false)
}

/// Parse an endpoint string like "127.0.0.1:8080" into an Endpoint.
fn parse_endpoint(s: &str) -> Option<Endpoint> {
    let s = s.trim();
    let (host, port) = s.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    Some(Endpoint {
        address: host.to_string(),
        port,
        weight: 1,
    })
}

/// Convert an NGINX location match to a Dwara path match.
fn convert_location_match(modifier: &str, path: &str) -> (PathMatchKind, String) {
    match modifier {
        "=" => (PathMatchKind::Exact, path.to_string()),
        "~" | "~*" => {
            // Dwara regex paths must start with '/'. NGINX regex
            // patterns often start with '^' -- strip it and prepend '/'.
            let trimmed = path.strip_prefix('^').unwrap_or(path);
            let value = if trimmed.starts_with('/') {
                trimmed.to_string()
            } else {
                format!("/{trimmed}")
            };
            (PathMatchKind::Regex, value)
        }
        _ => (PathMatchKind::Prefix, path.to_string()),
    }
}
