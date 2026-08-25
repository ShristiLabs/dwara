//! Config compile pipeline: validate -> compile -> publish (feature analysis
//! section 9.2).
//!
//! The pipeline is split into a pure half and an effectful half:
//!
//! - [`validate`] checks semantic integrity that the schema deliberately
//!   deferred (reference resolution, duplicate names, port conflicts,
//!   credential well-formedness). It returns ALL issues, never fail-fast.
//! - [`compile`] turns a validated [`Gateway`] into a [`Compiled`] value:
//!   compiled route structures plus a content hash. This is where schema-valid
//!   config can still fail (invalid regex, conflicting route templates).
//! - [`ConfigState::compile_and_publish`] stamps a monotonic generation id and
//!   atomically installs the result behind an `ArcSwap`. Rollback semantics
//!   are "atomic not-publish": on ANY validation or compile failure the swap
//!   never happens and the currently-published snapshot remains untouched.
//!
//! Route matching model (v1):
//!
//! - `exact` routes are mounted in a `matchit` radix router; path parameters
//!   like `/users/{id}` are supported by the router itself.
//! - `regex` routes are compiled into a shared `regex::RegexSet`; the first
//!   matching pattern (declaration order) wins.
//! - `prefix` routes are kept in an ordered list and matched by
//!   longest-prefix at lookup time. `matchit` is exact-template matching, so
//!   prefix semantics are modeled explicitly rather than by mounting a
//!   trailing catch-all; that keeps parameter capture out of prefix routes.
//! - Lookup precedence: exact, then regex, then longest prefix.
//!
//! Content hash: a fast non-cryptographic `DefaultHasher` (SipHash-1-3) over
//! the normalized YAML serialization of the gateway. Its purpose is change
//! detection / generation identity, NOT cryptographic integrity; it is not
//! suitable for adversarial settings.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;

use crate::config::{
    gateway_to_yaml, Credential, Gateway, ListenerProtocol, PathMatchKind, Route, RouteAction,
    TlsMode,
};

/// One semantic-validation finding. Operators get every issue at once, not a
/// fail-fast first error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationIssue {
    /// Entity kind, e.g. `route`, `service`, `listener`.
    pub entity: String,
    /// Name of the offending entity.
    pub name: String,
    /// Field (or near-field locator) the issue concerns.
    pub field: String,
    pub message: String,
}

impl std::fmt::Display for ValidationIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} '{}.{}': {}",
            self.entity, self.name, self.field, self.message
        )
    }
}

/// Error produced by the compile pipeline. Validation failures carry every
/// issue; compile failures name the route and pattern at fault.
#[derive(Debug)]
pub enum CompileError {
    Validation(Vec<ValidationIssue>),
    InvalidRegex {
        route: String,
        pattern: String,
        message: String,
    },
    RouteConflict {
        route: String,
        pattern: String,
        message: String,
    },
    Internal(String),
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompileError::Validation(issues) => {
                write!(f, "config validation failed ({} issues)", issues.len())?;
                for i in issues {
                    write!(f, "\n  - {i}")?;
                }
                Ok(())
            }
            CompileError::InvalidRegex {
                route,
                pattern,
                message,
            } => write!(f, "route '{route}': invalid regex '{pattern}': {message}"),
            CompileError::RouteConflict {
                route,
                pattern,
                message,
            } => write!(
                f,
                "route '{route}': conflicting path template '{pattern}': {message}"
            ),
            CompileError::Internal(m) => write!(f, "internal compile error: {m}"),
        }
    }
}

impl std::error::Error for CompileError {}

fn issue(entity: &str, name: &str, field: &str, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        entity: entity.to_string(),
        name: name.to_string(),
        field: field.to_string(),
        message: message.into(),
    }
}

/// Check semantic integrity of a parsed [`Gateway`]. An empty Vec means valid.
pub fn validate(gateway: &Gateway) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();

    // Trusted proxies: each entry must be an IP address or CIDR (parsed by
    // the dataplane's trusted-proxy matcher; rejected here at compile time).
    for (i, entry) in gateway.trusted_proxies.iter().enumerate() {
        if crate::proxy::parse_ip_or_cidr(entry).is_none() {
            issues.push(issue(
                "gateway",
                "(root)",
                &format!("trusted_proxies[{i}]"),
                format!("'{entry}' is not an IP address or CIDR (e.g. 10.0.0.0/8 or ::1/128)"),
            ));
        }
    }

    // Duplicate names within each entity kind.
    let mut check_dups = |kind: &str, field: &str, names: Vec<&str>| {
        let mut seen = std::collections::BTreeSet::new();
        for name in names {
            if !seen.insert(name) {
                issues.push(issue(kind, name, field, "duplicate name"));
            }
        }
    };
    check_dups(
        "listener",
        "name",
        gateway.listeners.iter().map(|l| l.name.as_str()).collect(),
    );
    check_dups(
        "route",
        "name",
        gateway.routes.iter().map(|r| r.name.as_str()).collect(),
    );
    check_dups(
        "service",
        "name",
        gateway.services.iter().map(|s| s.name.as_str()).collect(),
    );
    check_dups(
        "upstream",
        "name",
        gateway.upstreams.iter().map(|u| u.name.as_str()).collect(),
    );
    check_dups(
        "consumer",
        "name",
        gateway.consumers.iter().map(|c| c.name.as_str()).collect(),
    );
    check_dups(
        "policy",
        "name",
        gateway.policies.iter().map(|p| p.name.as_str()).collect(),
    );

    // Listener sanity and bind conflicts.
    let mut binds = std::collections::BTreeSet::new();
    for l in &gateway.listeners {
        if l.port == 0 {
            issues.push(issue(
                "listener",
                &l.name,
                "port",
                "port 0 is not a valid gateway listen port (only meaningful as an ephemeral test bind)",
            ));
        }
        if l.address.trim().is_empty() {
            issues.push(issue("listener", &l.name, "address", "address is empty"));
        }
        match l.protocol {
            ListenerProtocol::Https => match &l.tls {
                None => issues.push(issue(
                    "listener",
                    &l.name,
                    "tls",
                    "protocol https requires a tls block",
                )),
                Some(t) => match t.mode {
                    TlsMode::Terminate => {
                        let has_pair = t.cert_file.is_some() || t.key_file.is_some();
                        if t.certificates.is_empty() || has_pair {
                            if t.cert_file.as_deref().unwrap_or("").trim().is_empty() {
                                issues.push(issue(
                                    "listener",
                                    &l.name,
                                    "tls.cert_file",
                                    "tls mode terminate requires a non-empty cert_file",
                                ));
                            }
                            if t.key_file.as_deref().unwrap_or("").trim().is_empty() {
                                issues.push(issue(
                                    "listener",
                                    &l.name,
                                    "tls.key_file",
                                    "tls mode terminate requires a non-empty key_file",
                                ));
                            }
                        }
                        if !t.sni_routes.is_empty() {
                            issues.push(issue(
                                "listener",
                                &l.name,
                                "tls.sni_routes",
                                "sni_routes only apply to tls mode passthrough",
                            ));
                        }
                        let mut seen_names = std::collections::BTreeSet::new();
                        for (i, c) in t.certificates.iter().enumerate() {
                            if c.server_names.is_empty() {
                                issues.push(issue(
                                    "listener",
                                    &l.name,
                                    &format!("tls.certificates[{i}].server_names"),
                                    "certificate entry lists no server_names",
                                ));
                            }
                            for n in &c.server_names {
                                if n.trim().is_empty() {
                                    issues.push(issue(
                                        "listener",
                                        &l.name,
                                        &format!("tls.certificates[{i}].server_names"),
                                        "server name is empty",
                                    ));
                                } else if !seen_names.insert(n.to_ascii_lowercase()) {
                                    issues.push(issue(
                                        "listener",
                                        &l.name,
                                        &format!("tls.certificates[{i}].server_names"),
                                        format!("duplicate server name '{n}'"),
                                    ));
                                }
                            }
                            if c.cert_file.trim().is_empty() {
                                issues.push(issue(
                                    "listener",
                                    &l.name,
                                    &format!("tls.certificates[{i}].cert_file"),
                                    "certificate entry requires a non-empty cert_file",
                                ));
                            }
                            if c.key_file.trim().is_empty() {
                                issues.push(issue(
                                    "listener",
                                    &l.name,
                                    &format!("tls.certificates[{i}].key_file"),
                                    "certificate entry requires a non-empty key_file",
                                ));
                            }
                        }
                    }
                    TlsMode::Passthrough => {
                        if t.cert_file.is_some() || t.key_file.is_some() {
                            issues.push(issue(
                                "listener",
                                &l.name,
                                "tls",
                                "tls mode passthrough ignores cert_file/key_file; remove them or use mode terminate",
                            ));
                        }
                        if !t.certificates.is_empty() {
                            issues.push(issue(
                                "listener",
                                &l.name,
                                "tls.certificates",
                                "tls mode passthrough does not terminate TLS; certificates do not apply",
                            ));
                        }
                        let mut seen_names = std::collections::BTreeSet::new();
                        for (i, r) in t.sni_routes.iter().enumerate() {
                            if r.server_names.is_empty() {
                                issues.push(issue(
                                    "listener",
                                    &l.name,
                                    &format!("tls.sni_routes[{i}].server_names"),
                                    "sni route lists no server_names",
                                ));
                            }
                            for n in &r.server_names {
                                if n.trim().is_empty() {
                                    issues.push(issue(
                                        "listener",
                                        &l.name,
                                        &format!("tls.sni_routes[{i}].server_names"),
                                        "server name is empty",
                                    ));
                                } else if !seen_names.insert(n.to_ascii_lowercase()) {
                                    issues.push(issue(
                                        "listener",
                                        &l.name,
                                        &format!("tls.sni_routes[{i}].server_names"),
                                        format!("duplicate server name '{n}'"),
                                    ));
                                }
                            }
                        }
                    }
                },
            },
            ListenerProtocol::Http => {
                if l.tls.is_some() {
                    issues.push(issue(
                        "listener",
                        &l.name,
                        "tls",
                        "protocol http must not carry a tls block (use protocol https for TLS)",
                    ));
                }
            }
        }
        if !binds.insert((l.address.as_str(), l.port)) {
            issues.push(issue(
                "listener",
                &l.name,
                "port",
                format!(
                    "address {}:{} already bound by another listener",
                    l.address, l.port
                ),
            ));
        }
    }

    let services: std::collections::BTreeSet<&str> =
        gateway.services.iter().map(|s| s.name.as_str()).collect();
    let upstreams: std::collections::BTreeSet<&str> =
        gateway.upstreams.iter().map(|u| u.name.as_str()).collect();
    let policies: std::collections::BTreeSet<&str> =
        gateway.policies.iter().map(|p| p.name.as_str()).collect();

    for l in &gateway.listeners {
        let Some(tls) = &l.tls else { continue };
        for (i, r) in tls.sni_routes.iter().enumerate() {
            if !upstreams.contains(r.upstream.as_str()) {
                issues.push(issue(
                    "listener",
                    &l.name,
                    &format!("tls.sni_routes[{i}].upstream"),
                    format!("references unknown upstream '{}'", r.upstream),
                ));
            }
        }
    }

    for s in &gateway.services {
        if !upstreams.contains(s.upstream.as_str()) {
            issues.push(issue(
                "service",
                &s.name,
                "upstream",
                format!("references unknown upstream '{}'", s.upstream),
            ));
        }
        for p in &s.policies {
            if !policies.contains(p.as_str()) {
                issues.push(issue(
                    "service",
                    &s.name,
                    "policies",
                    format!("references unknown policy '{p}'"),
                ));
            }
        }
    }

    for r in &gateway.routes {
        if !services.contains(r.service.as_str()) {
            issues.push(issue(
                "route",
                &r.name,
                "service",
                format!("references unknown service '{}'", r.service),
            ));
        }
        for p in &r.policies {
            if !policies.contains(p.as_str()) {
                issues.push(issue(
                    "route",
                    &r.name,
                    "policies",
                    format!("references unknown policy '{p}'"),
                ));
            }
        }
        let m = &r.r#match.path;
        if !m.value.starts_with('/') {
            issues.push(issue(
                "route",
                &r.name,
                "match.path.value",
                format!("path pattern '{}' must start with '/'", m.value),
            ));
        }
        if m.kind == PathMatchKind::Prefix && m.value.trim_end_matches('/').is_empty() {
            issues.push(issue(
                "route",
                &r.name,
                "match.path.value",
                format!(
                    "prefix '{}' would match every path (it trims to the empty string); \
                     use a regex route or an explicit catch-all route instead",
                    m.value
                ),
            ));
        }
        match r.action {
            RouteAction::Redirect {
                status,
                ref scheme,
                ref host,
                path: ref redirect_path,
            } => {
                if !(300..=399).contains(&status) {
                    issues.push(issue(
                        "route",
                        &r.name,
                        "action.status",
                        format!("redirect status {status} is not a 3xx redirect"),
                    ));
                }
                // Location is built into a HeaderValue at request time; a
                // hostile config must fail HERE, not panic the dataplane.
                if let Some(s) = scheme {
                    if !s.eq_ignore_ascii_case("http") && !s.eq_ignore_ascii_case("https") {
                        issues.push(issue(
                            "route",
                            &r.name,
                            "action.scheme",
                            format!("redirect scheme '{s}' must be http or https"),
                        ));
                    }
                }
                if let Some(h) = host {
                    if h.is_empty() || !h.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
                        issues.push(issue(
                            "route",
                            &r.name,
                            "action.host",
                            format!(
                                "redirect host '{h}' contains whitespace or control \
                                 characters and cannot form a Location header"
                            ),
                        ));
                    }
                }
                if let Some(p) = redirect_path {
                    if !p.is_empty() && !p.starts_with('/') {
                        issues.push(issue(
                            "route",
                            &r.name,
                            "action.path",
                            format!("redirect path '{p}' must start with '/' or be empty"),
                        ));
                    }
                    if !p.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
                        issues.push(issue(
                            "route",
                            &r.name,
                            "action.path",
                            format!(
                                "redirect path '{p}' contains control characters and \
                                 cannot form a Location header"
                            ),
                        ));
                    }
                }
            }
            RouteAction::Respond { status, .. } => {
                if !(100..=599).contains(&status) {
                    issues.push(issue(
                        "route",
                        &r.name,
                        "action.status",
                        format!("respond status {status} is not a valid HTTP status"),
                    ));
                }
            }
            RouteAction::Proxy {} => {}
        }
    }

    for u in &gateway.upstreams {
        if u.endpoints.is_empty() {
            issues.push(issue(
                "upstream",
                &u.name,
                "endpoints",
                "upstream has no endpoints",
            ));
        }
        for (i, e) in u.endpoints.iter().enumerate() {
            if e.address.trim().is_empty() {
                issues.push(issue(
                    "upstream",
                    &u.name,
                    &format!("endpoints[{i}].address"),
                    "endpoint address is empty",
                ));
            }
            if e.weight == 0 {
                issues.push(issue(
                    "upstream",
                    &u.name,
                    &format!("endpoints[{i}].weight"),
                    "endpoint weight must be > 0",
                ));
            }
        }
        if u.connection_cap == Some(0) {
            issues.push(issue(
                "upstream",
                &u.name,
                "connection_cap",
                "connection_cap must be > 0",
            ));
        }
        if let Some(t) = &u.timeouts {
            for (field, v) in [
                ("connect_ms", t.connect_ms),
                ("read_ms", t.read_ms),
                ("write_ms", t.write_ms),
            ] {
                if v == Some(0) {
                    issues.push(issue(
                        "upstream",
                        &u.name,
                        &format!("timeouts.{field}"),
                        "timeout must be > 0 milliseconds",
                    ));
                }
            }
        }
    }

    for c in &gateway.consumers {
        for (i, cred) in c.credentials.iter().enumerate() {
            let field = format!("credentials[{i}]");
            let problem = match cred {
                Credential::ApiKey { key } if key.is_empty() => Some("api key is empty"),
                Credential::Jwt { issuer, .. } if issuer.is_empty() => Some("jwt issuer is empty"),
                Credential::Mtls { fingerprint } if fingerprint.is_empty() => {
                    Some("mtls fingerprint is empty")
                }
                _ => None,
            };
            if let Some(m) = problem {
                issues.push(issue("consumer", &c.name, &field, m));
            }
        }
        for p in &c.policies {
            if !policies.contains(p.as_str()) {
                issues.push(issue(
                    "consumer",
                    &c.name,
                    "policies",
                    format!("references unknown policy '{p}'"),
                ));
            }
        }
    }

    for p in &gateway.policies {
        if let Some(rl) = &p.rate_limit {
            if rl.requests == 0 {
                issues.push(issue(
                    "policy",
                    &p.name,
                    "rate_limit.requests",
                    "rate limit requests must be > 0 (0 would block every request)",
                ));
            }
            if rl.window_seconds == 0 {
                issues.push(issue(
                    "policy",
                    &p.name,
                    "rate_limit.window_seconds",
                    "rate limit window_seconds must be > 0 (0 is a nonsensical window)",
                ));
            }
        }
    }

    issues
}

/// Compiled route structures for one snapshot. Path-only lookup (v1); host,
/// method, and header matching are applied by the dataplane after path
/// resolution (documented deferral to the M1 dataplane issues).
///
/// Prefix lookup is a linear scan over the prefix list, O(n) in the number
/// of prefix routes per request; fine at v1 route counts, revisit if route
/// tables grow large. Prefixes are pure byte prefixes with no segment
/// boundary: prefix `/v1` intentionally also matches `/v1anything`.
#[derive(Debug)]
pub struct RouteTable {
    exact: matchit::Router<usize>,
    /// (prefix, route index) for prefix-kind routes; longest prefix wins.
    prefixes: Vec<(String, usize)>,
    regex_set: regex::RegexSet,
    /// Route index per RegexSet member, in insertion order.
    regex_indices: Vec<usize>,
}

impl RouteTable {
    fn empty() -> Self {
        RouteTable {
            exact: matchit::Router::new(),
            prefixes: Vec::new(),
            regex_set: regex::RegexSet::empty(),
            regex_indices: Vec::new(),
        }
    }

    /// Resolve a request path to a route index. Precedence: exact template,
    /// then first regex match, then longest prefix. `None` means no route.
    pub fn find(&self, path: &str) -> Option<usize> {
        if let Ok(m) = self.exact.at(path) {
            return Some(*m.value);
        }
        let matches = self.regex_set.matches(path);
        if let Some(i) = matches.iter().next() {
            return Some(self.regex_indices[i]);
        }
        let mut best: Option<(usize, usize)> = None; // (prefix len, index)
        for (prefix, idx) in &self.prefixes {
            if path.starts_with(prefix.as_str()) && best.is_none_or(|(len, _)| prefix.len() > len) {
                best = Some((prefix.len(), *idx));
            }
        }
        best.map(|(_, idx)| idx)
    }
}

/// Output of the pure compile step: everything a [`Snapshot`] needs except
/// its generation id, which is assigned at publish time.
#[derive(Debug)]
pub struct Compiled {
    gateway: Arc<Gateway>,
    routes: Arc<RouteTable>,
    content_hash: u64,
}

impl Compiled {
    pub fn gateway(&self) -> &Gateway {
        &self.gateway
    }

    pub fn route_table(&self) -> &RouteTable {
        &self.routes
    }

    pub fn content_hash(&self) -> u64 {
        self.content_hash
    }
}

/// Immutable, fully compiled configuration generation, cheap to share.
#[derive(Debug)]
pub struct Snapshot {
    generation: u64,
    content_hash: u64,
    gateway: Arc<Gateway>,
    routes: Arc<RouteTable>,
}

impl Snapshot {
    /// The empty generation-0 snapshot a cold gateway serves before any
    /// config has been published.
    pub fn empty() -> Self {
        Snapshot {
            generation: 0,
            content_hash: 0,
            gateway: Arc::new(Gateway {
                trusted_proxies: vec![],
                listeners: Vec::new(),
                routes: Vec::new(),
                services: Vec::new(),
                upstreams: Vec::new(),
                consumers: Vec::new(),
                policies: Vec::new(),
            }),
            routes: Arc::new(RouteTable::empty()),
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn content_hash(&self) -> u64 {
        self.content_hash
    }

    pub fn gateway(&self) -> &Gateway {
        &self.gateway
    }

    pub fn route_table(&self) -> &RouteTable {
        &self.routes
    }

    /// Convenience: resolve a path to the matching route, if any.
    pub fn match_route(&self, path: &str) -> Option<&Route> {
        self.routes.find(path).map(|i| &self.gateway.routes[i])
    }
}

/// Identity of a successfully published snapshot, for logs/metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub generation: u64,
    /// Per-process change-detection token over the normalized config.
    /// NOT stable across Rust versions (SipHash internals may change) and
    /// NOT a content digest; never persist it, compare it across
    /// processes/versions, or treat it as cryptographic integrity.
    pub content_hash: u64,
    pub route_count: usize,
}

/// Pure compile: validated [`Gateway`] -> [`Compiled`]. Fails with
/// [`CompileError::Validation`] on semantic issues, or with
/// [`CompileError::InvalidRegex`] / [`CompileError::RouteConflict`] when
/// schema-valid config still cannot compile.
pub fn compile(gateway: &Gateway) -> Result<Compiled, CompileError> {
    let issues = validate(gateway);
    if !issues.is_empty() {
        return Err(CompileError::Validation(issues));
    }

    let mut exact = matchit::Router::new();
    let mut prefixes = Vec::new();
    let mut regex_patterns = Vec::new();
    let mut regex_indices = Vec::new();

    for (idx, route) in gateway.routes.iter().enumerate() {
        let path = &route.r#match.path;
        match path.kind {
            PathMatchKind::Exact => {
                exact
                    .insert(&path.value, idx)
                    .map_err(|e| CompileError::RouteConflict {
                        route: route.name.clone(),
                        pattern: path.value.clone(),
                        message: e.to_string(),
                    })?;
            }
            PathMatchKind::Prefix => {
                let prefix = path.value.trim_end_matches('/').to_string();
                prefixes.push((prefix, idx));
            }
            PathMatchKind::Regex => {
                regex::Regex::new(&path.value).map_err(|e| CompileError::InvalidRegex {
                    route: route.name.clone(),
                    pattern: path.value.clone(),
                    message: e.to_string(),
                })?;
                regex_patterns.push(path.value.clone());
                regex_indices.push(idx);
            }
        }
    }

    let regex_set =
        regex::RegexSet::new(regex_patterns).map_err(|e| CompileError::Internal(e.to_string()))?;

    let yaml = gateway_to_yaml(gateway)
        .map_err(|e| CompileError::Internal(format!("normalization failed: {e}")))?;
    let mut hasher = DefaultHasher::new();
    yaml.hash(&mut hasher);

    Ok(Compiled {
        gateway: Arc::new(gateway.clone()),
        routes: Arc::new(RouteTable {
            exact,
            prefixes,
            regex_set,
            regex_indices,
        }),
        content_hash: hasher.finish(),
    })
}

/// Holds the currently published [`Snapshot`] behind an `ArcSwap` and owns
/// the monotonic generation counter. Shared across the dataplane (read) and
/// the config source / hot reload (write, DW-006).
pub struct ConfigState {
    snapshot: ArcSwap<Snapshot>,
    generation: AtomicU64,
    /// Serializes publish attempts so generation ids stay gap-free and
    /// monotonic under concurrent writers.
    publish_lock: Mutex<()>,
}

impl Default for ConfigState {
    fn default() -> Self {
        ConfigState {
            snapshot: ArcSwap::from_pointee(Snapshot::empty()),
            generation: AtomicU64::new(0),
            publish_lock: Mutex::new(()),
        }
    }
}

impl ConfigState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Currently published snapshot (load is lock-free).
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.snapshot.load_full()
    }

    /// Validate, compile, and atomically publish. On ANY failure the
    /// currently-published snapshot is untouched (rollback = not-published);
    /// the generation counter is only advanced on success.
    pub fn compile_and_publish(&self, gateway: &Gateway) -> Result<SnapshotInfo, CompileError> {
        let _guard = self.publish_lock.lock().unwrap_or_else(|p| p.into_inner());
        let compiled = compile(gateway)?;
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let snapshot = Snapshot {
            generation,
            content_hash: compiled.content_hash,
            gateway: compiled.gateway,
            routes: compiled.routes,
        };
        let info = SnapshotInfo {
            generation,
            content_hash: snapshot.content_hash,
            route_count: snapshot.gateway.routes.len(),
        };
        self.snapshot.store(Arc::new(snapshot));
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Endpoint, Listener, ListenerProtocol, LoadBalancer, PathMatch, RouteMatch, Service,
        Upstream, UpstreamProtocol,
    };

    fn good_gateway() -> Gateway {
        Gateway {
            trusted_proxies: vec![],
            listeners: vec![Listener {
                name: "main".into(),
                address: "0.0.0.0".into(),
                port: 8080,
                protocol: ListenerProtocol::Http,
                tls: None,
            }],
            routes: vec![
                Route {
                    name: "users-get".into(),
                    service: "users-api".into(),
                    r#match: RouteMatch {
                        path: PathMatch {
                            kind: PathMatchKind::Exact,
                            value: "/v1/users/{id}".into(),
                        },
                        host: None,
                        methods: vec![],
                        headers: Default::default(),
                    },
                    action: RouteAction::Proxy {},
                    policies: vec![],
                },
                Route {
                    name: "static".into(),
                    service: "users-api".into(),
                    r#match: RouteMatch {
                        path: PathMatch {
                            kind: PathMatchKind::Prefix,
                            value: "/static".into(),
                        },
                        host: None,
                        methods: vec![],
                        headers: Default::default(),
                    },
                    action: RouteAction::Proxy {},
                    policies: vec![],
                },
                Route {
                    name: "legacy".into(),
                    service: "users-api".into(),
                    r#match: RouteMatch {
                        path: PathMatch {
                            kind: PathMatchKind::Regex,
                            value: r"/old/(foo|bar)".into(),
                        },
                        host: None,
                        methods: vec![],
                        headers: Default::default(),
                    },
                    action: RouteAction::Proxy {},
                    policies: vec![],
                },
            ],
            services: vec![Service {
                name: "users-api".into(),
                upstream: "users-pool".into(),
                base_path: None,
                version: None,
                policies: vec![],
            }],
            upstreams: vec![Upstream {
                name: "users-pool".into(),
                load_balancer: LoadBalancer::RoundRobin,
                protocol: UpstreamProtocol::Http1,
                endpoints: vec![Endpoint {
                    address: "127.0.0.1".into(),
                    port: 9001,
                    weight: 1,
                }],
                connection_cap: None,
                timeouts: None,
            }],
            consumers: vec![],
            policies: vec![],
        }
    }

    #[test]
    fn validate_reports_all_semantic_issues() {
        let mut gw = good_gateway();
        // Duplicate service name, dangling upstream ref, unknown policy,
        // duplicate listener port.
        gw.services.push(gw.services[0].clone());
        gw.services[0].upstream = "missing-pool".into();
        gw.routes[0].policies.push("nope".into());
        gw.listeners.push(Listener {
            name: "dupe".into(),
            address: "0.0.0.0".into(),
            port: 8080,
            protocol: ListenerProtocol::Http,
            tls: None,
        });
        let issues = validate(&gw);
        assert!(issues
            .iter()
            .any(|i| i.entity == "service" && i.field == "upstream"));
        assert!(issues
            .iter()
            .any(|i| i.entity == "service" && i.field == "name"));
        assert!(issues
            .iter()
            .any(|i| i.entity == "route" && i.field == "policies"));
        assert!(issues
            .iter()
            .any(|i| i.entity == "listener" && i.field == "port"));
        assert!(validate(&good_gateway()).is_empty());
    }

    #[test]
    fn compile_builds_route_table_with_precedence() {
        let gw = good_gateway();
        let compiled = compile(&gw).expect("good config compiles");
        let rt = compiled.route_table();
        assert_eq!(rt.find("/v1/users/42"), Some(0), "exact/param match");
        assert_eq!(rt.find("/static/app.js"), Some(1), "prefix match");
        assert_eq!(rt.find("/static/css/a.css"), Some(1));
        assert_eq!(rt.find("/old/foo"), Some(2), "regex match");
        assert_eq!(rt.find("/healthz"), None, "no route");
        assert_ne!(compiled.content_hash(), 0);
    }

    #[test]
    fn compile_rejects_invalid_regex() {
        let mut gw = good_gateway();
        gw.routes[2].r#match.path.value = "/old/(unclosed".into();
        match compile(&gw) {
            Err(CompileError::InvalidRegex { route, .. }) => assert_eq!(route, "legacy"),
            other => panic!("expected InvalidRegex, got {other:?}"),
        }
    }

    #[test]
    fn publish_is_atomic_on_failure() {
        let state = ConfigState::new();
        assert_eq!(state.snapshot().generation(), 0);
        let info = state.compile_and_publish(&good_gateway()).unwrap();
        assert_eq!(info.generation, 1);
        let before = state.snapshot();
        assert_eq!(
            before.match_route("/v1/users/7").map(|r| r.name.as_str()),
            Some("users-get")
        );

        let mut bad = good_gateway();
        bad.routes[0].service = "missing".into();
        assert!(matches!(
            state.compile_and_publish(&bad),
            Err(CompileError::Validation(_))
        ));

        let after = state.snapshot();
        assert_eq!(after.generation(), 1, "failed publish must not swap");
        assert_eq!(after.content_hash(), before.content_hash());
        assert!(after.match_route("/old/bar").is_some());

        // Recovery: the next successful publish advances the generation.
        let info2 = state.compile_and_publish(&good_gateway()).unwrap();
        assert_eq!(info2.generation, 2);
    }
}
