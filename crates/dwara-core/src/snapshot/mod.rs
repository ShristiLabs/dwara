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
use std::str::FromStr as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;

use crate::config::{
    gateway_to_yaml, Credential, Gateway, ListenerProtocol, PathMatchKind, PathRewrite, Route,
    RouteAction, TlsMode,
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

/// Compile-time check for a `trusted_ca_file` (#121): the file must
/// exist, be readable, and PARSE to at least one PEM certificate NOW, or
/// the config generation is rejected naming the field. A missing,
/// unreadable, or certificate-free trust bundle would otherwise publish
/// fine and fail every TLS dial to the affected upstream at request time
/// — and, the sharp case, DISABLE a JWT provider at authenticator build,
/// after which Bearer tokens pass through UNVERIFIED. Closing that torn
/// state here, at validation, is the whole point of the PEM dimension:
/// the runtime fail-closed paths (empty root store / provider disabled,
/// security/tls.rs and authn.rs) remain as a microsecond-race backstop
/// for a bundle that breaks between validate and build. PEM parsing uses
/// rustls-pki-types directly — an EXTERNAL crate, so this module's
/// position in the facade's `crate::` dependency order is untouched —
/// while anchor USABILITY (a parseable certificate the root store
/// rejects) stays enforced where the rustls root store lives, at
/// registry build.
fn check_trusted_ca_file(entity: &str, name: &str, path: &str, issues: &mut Vec<ValidationIssue>) {
    use rustls_pki_types::pem::PemObject;

    if let Err(e) = std::fs::File::open(path) {
        issues.push(issue(
            entity,
            name,
            "trusted_ca_file",
            format!("trusted_ca_file '{path}' is not a readable file: {e}"),
        ));
        return;
    }
    // Non-PEM text between blocks is skipped (real bundles carry
    // comments), so `Ok([])` means the file holds no CERTIFICATE
    // sections at all; an Err is a read failure (e.g. a directory:
    // File::open succeeds on Unix, the read does not) or a malformed
    // PEM block.
    let parsed = rustls_pki_types::CertificateDer::pem_file_iter(path).and_then(|iter| {
        iter.collect::<Result<Vec<rustls_pki_types::CertificateDer<'static>>, _>>()
    });
    match parsed {
        Ok(certs) if !certs.is_empty() => {}
        Ok(_) => issues.push(issue(
            entity,
            name,
            "trusted_ca_file",
            format!(
                "trusted_ca_file '{path}' holds no usable CA certificates \
                 (the PEM bundle must list at least one CERTIFICATE)"
            ),
        )),
        Err(e) => issues.push(issue(
            entity,
            name,
            "trusted_ca_file",
            format!(
                "trusted_ca_file '{path}' could not be parsed as a PEM \
                 certificate bundle: {e}"
            ),
        )),
    }
}

/// Validate one `authorization` block (#123: shared by every attachment
/// level — route, service, listener, consumer, and gateway/global). The
/// checks are identical at every level: consumer/group references must
/// resolve against the configured consumers, every IP ACL entry must
/// parse as an IP/CIDR (the trusted-proxies parser), a block carrying NO
/// rules at all is rejected (always an authoring mistake — omit the
/// block), and a `/0` entry in the ALLOW list is rejected (allow-all
/// filters nothing; the intended shape is `default: allow`; `/0` in the
/// DENY list is meaningful — deny-all — and accepted).
fn validate_authz(
    entity: &str,
    name: &str,
    authz: &crate::config::Authz,
    consumers: &std::collections::BTreeSet<&str>,
    consumer_groups: &std::collections::BTreeSet<&str>,
    issues: &mut Vec<ValidationIssue>,
) {
    let field_prefix = "authorization".to_string();
    let empty = authz.allowed_consumers.is_empty()
        && authz.denied_consumers.is_empty()
        && authz.allowed_groups.is_empty()
        && authz.denied_groups.is_empty()
        && authz.required_scopes.is_empty()
        && authz.required_claims.is_empty()
        && authz.ip_acl.is_none();
    if empty {
        issues.push(issue(
            entity,
            name,
            "authorization",
            "carries no rules (no consumers, groups, scopes, claims, or ip_acl) \
             and is always a mistake: omit the authorization block entirely",
        ));
    }
    for (side, entries) in [
        ("allowed_consumers", &authz.allowed_consumers),
        ("denied_consumers", &authz.denied_consumers),
    ] {
        for entry in entries.iter() {
            if !consumers.contains(entry.as_str()) {
                issues.push(issue(
                    entity,
                    name,
                    &format!("{field_prefix}.{side}"),
                    format!("references unknown consumer '{entry}'"),
                ));
            }
        }
    }
    for (side, entries) in [
        ("allowed_groups", &authz.allowed_groups),
        ("denied_groups", &authz.denied_groups),
    ] {
        for group in entries.iter() {
            if !consumer_groups.contains(group.as_str()) {
                issues.push(issue(
                    entity,
                    name,
                    &format!("{field_prefix}.{side}"),
                    format!("references group '{group}' that no consumer is a member of"),
                ));
            }
        }
    }
    if let Some(acl) = &authz.ip_acl {
        for (side, entries) in [("ip_acl.allow", &acl.allow), ("ip_acl.deny", &acl.deny)] {
            for (i, entry) in entries.iter().enumerate() {
                if crate::config::net::parse_ip_or_cidr(entry).is_none() {
                    issues.push(issue(
                        entity,
                        name,
                        &format!("{field_prefix}.{side}[{i}]"),
                        format!(
                            "'{entry}' is not an IP address or CIDR (e.g. 10.0.0.0/8 \
                             or 2001:db8::/32)"
                        ),
                    ));
                } else if side == "ip_acl.allow"
                    && crate::config::net::parse_ip_or_cidr(entry)
                        .is_some_and(|(_, prefix)| prefix == 0)
                {
                    issues.push(issue(
                        entity,
                        name,
                        &format!("{field_prefix}.{side}[{i}]"),
                        format!(
                            "'{entry}' allows every address and filters nothing; \
                             use 'default: allow' instead of an allow-all entry"
                        ),
                    ));
                }
            }
        }
    }
}

/// Check semantic integrity of a parsed [`Gateway`]. An empty Vec means valid.
pub fn validate(gateway: &Gateway) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();

    // Trusted proxies: each entry must be an IP address or CIDR (parsed by
    // the dataplane's trusted-proxy matcher; rejected here at compile time).
    for (i, entry) in gateway.trusted_proxies.iter().enumerate() {
        if crate::config::net::parse_ip_or_cidr(entry).is_none() {
            issues.push(issue(
                "gateway",
                "(root)",
                &format!("trusted_proxies[{i}]"),
                format!("'{entry}' is not an IP address or CIDR (e.g. 10.0.0.0/8 or ::1/128)"),
            ));
        }
    }

    if gateway.max_concurrent_requests == Some(0) {
        issues.push(issue(
            "gateway",
            "(root)",
            "max_concurrent_requests",
            "max_concurrent_requests must be > 0 (unlimited is expressed by \
             omitting the field, so an explicit 0 is rejected as ambiguous)",
        ));
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
    check_dups(
        "jwt_provider",
        "name",
        gateway
            .jwt_providers
            .iter()
            .map(|p| p.name.as_str())
            .collect(),
    );

    // JWT providers (DW-019): url shape, algorithm allowlist, refresh
    // cadence, and consumer references are compile-time checked — a
    // gateway must not boot (or reload) into an unverifiable provider.
    for p in &gateway.jwt_providers {
        match p.jwks_url.parse::<hyper::Uri>() {
            Ok(uri) => {
                if !matches!(uri.scheme_str(), Some("http") | Some("https")) || uri.host().is_none()
                {
                    issues.push(issue(
                        "jwt_provider",
                        &p.name,
                        "jwks_url",
                        format!("'{}' must be an absolute http(s) URL", p.jwks_url),
                    ));
                }
            }
            Err(_) => issues.push(issue(
                "jwt_provider",
                &p.name,
                "jwks_url",
                format!("'{}' is not a valid URL", p.jwks_url),
            )),
        }
        if p.algorithms.is_empty() {
            issues.push(issue(
                "jwt_provider",
                &p.name,
                "algorithms",
                "at least one algorithm must be allowed",
            ));
        }
        for a in &p.algorithms {
            let upper = a.to_ascii_uppercase();
            if matches!(upper.as_str(), "HS256" | "HS384" | "HS512" | "NONE") {
                issues.push(issue(
                    "jwt_provider",
                    &p.name,
                    "algorithms",
                    format!(
                        "algorithm '{a}' is not allowed: only asymmetric verification \
                         (RS*/ES*/PS*/EdDSA) is supported"
                    ),
                ));
            } else if jsonwebtoken::Algorithm::from_str(&upper).is_err() {
                issues.push(issue(
                    "jwt_provider",
                    &p.name,
                    "algorithms",
                    format!("unknown algorithm '{a}'"),
                ));
            }
        }
        if p.refresh_secs == 0 {
            issues.push(issue(
                "jwt_provider",
                &p.name,
                "refresh_secs",
                "refresh_secs must be > 0",
            ));
        }
        if let Some(consumer) = &p.consumer {
            if !gateway.consumers.iter().any(|c| &c.name == consumer) {
                issues.push(issue(
                    "jwt_provider",
                    &p.name,
                    "consumer",
                    format!("references unknown consumer '{consumer}'"),
                ));
            }
        }
        // trusted_ca_file (#121): the JWKS fetcher's TLS trust override
        // for private-CA issuers. It only applies to an `https://`
        // jwks_url — no TLS is negotiated toward an `http://` endpoint,
        // so there is nothing to verify and the field is an authoring
        // mistake. When it does apply, the bundle must be on disk and
        // readable at compile time (see check_trusted_ca_file).
        if let Some(ca) = &p.trusted_ca_file {
            // An unparseable URL already produced its own jwks_url issue
            // above; piling a CA complaint on a broken URL is noise.
            if let Ok(uri) = p.jwks_url.parse::<hyper::Uri>() {
                if uri
                    .scheme_str()
                    .is_some_and(|s| s.eq_ignore_ascii_case("https"))
                {
                    check_trusted_ca_file("jwt_provider", &p.name, ca, &mut issues);
                } else {
                    issues.push(issue(
                        "jwt_provider",
                        &p.name,
                        "trusted_ca_file",
                        "trusted_ca_file only applies to an https jwks_url (no TLS is \
                         negotiated toward an http endpoint)",
                    ));
                }
            }
        }
    }

    // Admin block (DW-022): when configured, the bind must parse as a
    // socket address and the mTLS material must be present and non-empty.
    // A client CA is REQUIRED (mTLS-only, decision 6): an admin block
    // without one is rejected here rather than serving no-auth TLS.
    if let Some(admin) = &gateway.admin {
        if admin.bind.trim().is_empty() {
            issues.push(issue(
                "admin",
                "(root)",
                "bind",
                "admin bind is empty (default 127.0.0.1:2019)",
            ));
        } else if admin.bind.parse::<std::net::SocketAddr>().is_err() {
            issues.push(issue(
                "admin",
                "(root)",
                "bind",
                format!(
                    "admin bind '{}' is not a valid address:port (e.g. 127.0.0.1:2019)",
                    admin.bind
                ),
            ));
        }
        let t = &admin.tls;
        for (field, value) in [
            ("tls.cert_file", &t.cert_file),
            ("tls.key_file", &t.key_file),
            ("tls.client_ca_file", &t.client_ca_file),
        ] {
            if value.trim().is_empty() {
                issues.push(issue(
                    "admin",
                    "(root)",
                    field,
                    format!("{field} is required (mTLS-only admin: server cert, key, and client CA must all be set)"),
                ));
            }
        }
    }

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
    let consumers: std::collections::BTreeSet<&str> =
        gateway.consumers.iter().map(|c| c.name.as_str()).collect();
    let consumer_groups: std::collections::BTreeSet<&str> = gateway
        .consumers
        .iter()
        .flat_map(|c| c.groups.iter().map(String::as_str))
        .collect();

    for l in &gateway.listeners {
        // Listener policy attachment (#123): same resolution rule as
        // route/service/consumer refs. Runs for EVERY listener (the
        // tls-scoped checks below skip tls-less listeners early).
        for p in &l.policies {
            if !policies.contains(p.as_str()) {
                issues.push(issue(
                    "listener",
                    &l.name,
                    "policies",
                    format!("references unknown policy '{p}'"),
                ));
            }
        }
        // Listener authorization (#123): shared shape checks with every
        // other attachment level.
        if let Some(authz) = &l.authorization {
            validate_authz(
                "listener",
                &l.name,
                authz,
                &consumers,
                &consumer_groups,
                &mut issues,
            );
        }
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

    // Gateway-level (global) policy attachment (#123): named
    // `global_policies` because `policies` at this level is the registry.
    for p in &gateway.global_policies {
        if !policies.contains(p.as_str()) {
            issues.push(issue(
                "gateway",
                "(root)",
                "global_policies",
                format!("references unknown policy '{p}'"),
            ));
        }
    }
    // Gateway-level (global) authorization (#123).
    if let Some(authz) = &gateway.authorization {
        validate_authz(
            "gateway",
            "(root)",
            authz,
            &consumers,
            &consumer_groups,
            &mut issues,
        );
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
        // Service authorization (#123): shared shape checks with every
        // other attachment level.
        if let Some(authz) = &s.authorization {
            validate_authz(
                "service",
                &s.name,
                authz,
                &consumers,
                &consumer_groups,
                &mut issues,
            );
        }
    }

    for r in &gateway.routes {
        if let Some(p) = r.priority {
            if p > 10 {
                issues.push(issue(
                    "route",
                    &r.name,
                    "priority",
                    format!("priority {p} is out of range: must be 0 (lowest) to 10 (highest)"),
                ));
            }
        }
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
        // Route authorization (DW-020): shared shape checks with every
        // other attachment level (see validate_authz).
        if let Some(authz) = &r.authorization {
            validate_authz(
                "route",
                &r.name,
                authz,
                &consumers,
                &consumer_groups,
                &mut issues,
            );
        }
        let m = &r.r#match.path;
        for (field, entries) in [
            ("match.query", &r.r#match.query),
            ("match.cookies", &r.r#match.cookies),
        ] {
            for e in entries.iter() {
                if e.name.trim().is_empty() {
                    issues.push(issue("route", &r.name, field, "matcher name is empty"));
                }
                if let Some(v) = &e.value {
                    if v.is_empty() {
                        issues.push(issue(
                            "route",
                            &r.name,
                            field,
                            format!("matcher '{}' carries an empty value; omit value for presence-only matching", e.name),
                        ));
                    }
                }
            }
        }
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
            RouteAction::Respond {
                status,
                ref headers,
                ..
            } => {
                if !(100..=599).contains(&status) {
                    issues.push(issue(
                        "route",
                        &r.name,
                        "action.status",
                        format!("respond status {status} is not a valid HTTP status"),
                    ));
                }
                for (name, value) in headers {
                    if hyper::header::HeaderName::from_bytes(name.as_bytes()).is_err() {
                        issues.push(issue(
                            "route",
                            &r.name,
                            "action.headers",
                            format!("respond header name '{name}' is not a valid HTTP header name"),
                        ));
                    }
                    if hyper::header::HeaderValue::from_str(value.as_str()).is_err() {
                        issues.push(issue(
                            "route",
                            &r.name,
                            "action.headers",
                            format!(
                                "respond header value for '{name}' contains characters that \
                                 cannot appear in an HTTP header value"
                            ),
                        ));
                    }
                }
            }
            RouteAction::Proxy { rewrite: None } => {}
            RouteAction::Proxy {
                rewrite: Some(ref rw),
            } => validate_rewrite(&r.name, rw, &mut issues),
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
        // trusted_ca_file (#121): the connector's TLS trust override for
        // private-CA upstreams. It only applies to the TLS protocols —
        // no TLS is negotiated toward an `http1` upstream, so there is
        // nothing to verify and the field is an authoring mistake (the
        // same reading as a listener's "protocol http must not carry a
        // tls block"). When it does apply, the bundle must be on disk
        // and readable at compile time.
        if let Some(ca) = &u.trusted_ca_file {
            let tls = matches!(
                u.protocol,
                crate::config::UpstreamProtocol::Https | crate::config::UpstreamProtocol::Http2
            );
            if tls {
                check_trusted_ca_file("upstream", &u.name, ca, &mut issues);
            } else {
                issues.push(issue(
                    "upstream",
                    &u.name,
                    "trusted_ca_file",
                    "trusted_ca_file only applies to TLS upstreams (protocol https or http2); no \
                     TLS is negotiated toward an http1 upstream",
                ));
            }
        }
        let mut seen_targets = std::collections::BTreeSet::new();
        let mut total_vnodes: u64 = 0;
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
            // Duplicate address:port corrupts shared balancer state (both
            // entries carry to the same live counter; guards would
            // double-decrement). Reject at validation time.
            if !seen_targets.insert((e.address.clone(), e.port)) {
                issues.push(issue(
                    "upstream",
                    &u.name,
                    &format!("endpoints[{i}].address"),
                    format!(
                        "duplicate endpoint {}/{}: address:port must be unique within an upstream",
                        e.address, e.port
                    ),
                ));
            }
            total_vnodes += crate::config::limits::KETAMA_VNODES * e.weight.max(1) as u64;
        }
        if u.load_balancer == crate::config::LoadBalancer::IpHash
            && total_vnodes > crate::config::limits::MAX_RING_VNODES
        {
            issues.push(issue(
                "upstream",
                &u.name,
                "endpoints.weight",
                format!(
                    "ip_hash ring too large: total vnodes (160 * sum of weights) must be at most {}",
                    crate::config::limits::MAX_RING_VNODES
                ),
            ));
        }
        if u.connection_cap == Some(0) {
            issues.push(issue(
                "upstream",
                &u.name,
                "connection_cap",
                "connection_cap must be > 0",
            ));
        }
        if u.max_pending == Some(0) {
            issues.push(issue(
                "upstream",
                &u.name,
                "max_pending",
                "max_pending must be > 0 (unbounded is expressed by omitting \
                 the field, so an explicit 0 is rejected as ambiguous)",
            ));
        }
        if let Some(b) = &u.breaker {
            for (field, v) in [
                (
                    "breaker.consecutive_failures",
                    u64::from(b.consecutive_failures),
                ),
                ("breaker.error_volume", u64::from(b.error_volume)),
                ("breaker.open_ms", b.open_ms),
                ("breaker.half_open_probes", u64::from(b.half_open_probes)),
            ] {
                if v == 0 {
                    issues.push(issue(
                        "upstream",
                        &u.name,
                        field,
                        "circuit breaker value must be > 0",
                    ));
                }
            }
            if !b.error_ratio.is_finite() || b.error_ratio <= 0.0 || b.error_ratio > 1.0 {
                issues.push(issue(
                    "upstream",
                    &u.name,
                    "breaker.error_ratio",
                    format!("error_ratio must be in (0, 1]; got {}", b.error_ratio),
                ));
            }
        }
        if u.slow_start_ms
            .is_some_and(|ms| ms > crate::config::limits::MAX_SLOW_START_MS)
        {
            issues.push(issue(
                "upstream",
                &u.name,
                "slow_start_ms",
                "slow_start_ms must be at most 10 minutes (600000)",
            ));
        }
        if let Some(h) = &u.health {
            // Every knob must be positive; the ratio additionally must be a
            // real fraction (0, 1]. NaN/inf compare false everywhere and
            // would silently disable ejection, so reject them explicitly.
            for (field, v) in [
                ("health.window_ms", h.window_ms),
                ("health.eject_ms", h.eject_ms),
            ] {
                if v == 0 {
                    issues.push(issue(
                        "upstream",
                        &u.name,
                        field,
                        "passive health value must be > 0",
                    ));
                }
            }
            for (field, v) in [
                ("health.consecutive_failures", h.consecutive_failures),
                ("health.failure_min_volume", h.failure_min_volume),
                ("health.half_open_probes", h.half_open_probes),
            ] {
                if v == 0 {
                    issues.push(issue(
                        "upstream",
                        &u.name,
                        field,
                        "passive health value must be > 0",
                    ));
                }
            }
            if !h.failure_ratio.is_finite() || h.failure_ratio <= 0.0 || h.failure_ratio > 1.0 {
                issues.push(issue(
                    "upstream",
                    &u.name,
                    "health.failure_ratio",
                    format!("failure_ratio must be in (0, 1]; got {}", h.failure_ratio),
                ));
            }
        }
        if let Some(a) = &u.active_health {
            // Active probes report into the passive ejection machinery, so
            // the passive block (which owns eject/half-open windows) is a
            // hard requirement.
            if u.health.is_none() {
                issues.push(issue(
                    "upstream",
                    &u.name,
                    "active_health",
                    "active health requires the passive `health` block (probe results report \
                     into the same ejection machinery)",
                ));
            }
            for (field, v) in [
                ("active_health.interval_ms", a.interval_ms),
                ("active_health.timeout_ms", a.timeout_ms),
            ] {
                if v == 0 {
                    issues.push(issue(
                        "upstream",
                        &u.name,
                        field,
                        "active health value must be > 0",
                    ));
                }
            }
            // jitter_ms == 0 is legal: it disables jitter entirely.
            for (field, v) in [
                ("active_health.success_threshold", a.success_threshold),
                ("active_health.failure_threshold", a.failure_threshold),
            ] {
                if v == 0 {
                    issues.push(issue(
                        "upstream",
                        &u.name,
                        field,
                        "active health threshold must be > 0",
                    ));
                }
            }
            if a.timeout_ms > a.interval_ms {
                issues.push(issue(
                    "upstream",
                    &u.name,
                    "active_health.timeout_ms",
                    "timeout_ms must be <= interval_ms (an overlapping probe would pile up)",
                ));
            }
            if a.jitter_ms > a.interval_ms {
                issues.push(issue(
                    "upstream",
                    &u.name,
                    "active_health.jitter_ms",
                    "jitter_ms must be <= interval_ms",
                ));
            }
            if a.kind == crate::config::ProbeKind::Http
                && (!a.path.starts_with('/') || a.path.bytes().any(|b| b.is_ascii_control()))
            {
                issues.push(issue(
                    "upstream",
                    &u.name,
                    "active_health.path",
                    format!(
                        "probe path '{}' must start with '/' and contain no control characters",
                        a.path
                    ),
                ));
            }
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
        if let Some(r) = &u.retries {
            if r.attempts > crate::config::limits::MAX_RETRY_ATTEMPTS {
                issues.push(issue(
                    "upstream",
                    &u.name,
                    "retries.attempts",
                    format!(
                        "retries.attempts must be at most {} (retries beyond the first attempt)",
                        crate::config::limits::MAX_RETRY_ATTEMPTS
                    ),
                ));
            }
            if r.backoff_base_ms == 0 {
                issues.push(issue(
                    "upstream",
                    &u.name,
                    "retries.backoff_base_ms",
                    "backoff_base_ms must be > 0",
                ));
            }
            if r.backoff_cap_ms < r.backoff_base_ms {
                issues.push(issue(
                    "upstream",
                    &u.name,
                    "retries.backoff_cap_ms",
                    "backoff_cap_ms must be >= backoff_base_ms",
                ));
            }
            if r.budget_percent == 0 || r.budget_percent > 100 {
                issues.push(issue(
                    "upstream",
                    &u.name,
                    "retries.budget_percent",
                    "budget_percent must be in (0, 100]",
                ));
            }
            for (i, status) in r.retry_statuses.iter().enumerate() {
                if !(400..=599).contains(status) {
                    issues.push(issue(
                        "upstream",
                        &u.name,
                        &format!("retries.retry_statuses[{i}]"),
                        format!("retry status {status} is not a 4xx/5xx status"),
                    ));
                }
            }
        }
    }

    for c in &gateway.consumers {
        // The consumer name is injected upstream as the X-Consumer-Name
        // header value; non-visible-ASCII names cannot be represented in a
        // header and would silently break the identity injection (DW-019
        // review). Reject at compile time instead.
        if c.name.is_empty() || !c.name.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            issues.push(issue(
                "consumer",
                &c.name,
                "name",
                "consumer name must be non-empty visible ASCII (0x21-0x7E): it is injected \
                 upstream as the X-Consumer-Name header value",
            ));
        }
        if let Some(p) = c.priority {
            if p > 10 {
                issues.push(issue(
                    "consumer",
                    &c.name,
                    "priority",
                    format!("priority {p} is out of range: must be 0 (lowest) to 10 (highest)"),
                ));
            }
        }
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
        // Consumer authorization (#123): shared shape checks with every
        // other attachment level.
        if let Some(authz) = &c.authorization {
            validate_authz(
                "consumer",
                &c.name,
                authz,
                &consumers,
                &consumer_groups,
                &mut issues,
            );
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
        for (i, rule) in p.rate_limits.iter().enumerate() {
            let field = format!("rate_limits[{i}]");
            if rule.selector.is_empty() {
                issues.push(issue(
                    "policy",
                    &p.name,
                    &format!("{field}.selector"),
                    "rate limit selector must name at least one key component",
                ));
            }
            let rp = &rule.requests_per;
            if rp.per_second.is_none() && rp.minute.is_none() && rp.hour.is_none() {
                issues.push(issue(
                    "policy",
                    &p.name,
                    &format!("{field}.requests_per"),
                    "rate limit rule must set at least one window (s, minute, hour)",
                ));
            }
            for (window, value) in [
                ("s", rp.per_second),
                ("minute", rp.minute),
                ("hour", rp.hour),
            ] {
                if value == Some(0) {
                    issues.push(issue(
                        "policy",
                        &p.name,
                        &format!("{field}.requests_per.{window}"),
                        "rate limit window rate must be > 0 (0 would block every request)",
                    ));
                }
            }
            if rule.burst == Some(0) {
                issues.push(issue(
                    "policy",
                    &p.name,
                    &format!("{field}.burst"),
                    "rate limit burst must be >= 1 when present (omit for the default)",
                ));
            }
        }
    }

    issues
}

/// Validate a proxy-action path rewrite (shape only; regex COMPILATION is
/// checked in [`compile`], like the regex path-match kind).
fn validate_rewrite(route: &str, rw: &PathRewrite, issues: &mut Vec<ValidationIssue>) {
    match rw {
        PathRewrite::StripPrefix {} => {}
        PathRewrite::ReplacePrefix {
            prefix,
            replacement,
        } => {
            if !prefix.starts_with('/') {
                issues.push(issue(
                    "route",
                    route,
                    "action.rewrite.prefix",
                    format!("replace_prefix prefix '{prefix}' must start with '/'"),
                ));
            }
            if !replacement.is_empty() && !replacement.starts_with('/') {
                issues.push(issue(
                    "route",
                    route,
                    "action.rewrite.replacement",
                    format!(
                        "replace_prefix replacement '{replacement}' must start with '/' or be \
                         empty (empty turns the prefix into the root path)"
                    ),
                ));
            }
        }
        PathRewrite::Regex {
            pattern,
            substitution,
        } => {
            if pattern.is_empty() {
                issues.push(issue(
                    "route",
                    route,
                    "action.rewrite.pattern",
                    "rewrite regex pattern is empty",
                ));
            }
            if substitution.is_empty() {
                issues.push(issue(
                    "route",
                    route,
                    "action.rewrite.substitution",
                    "rewrite substitution is empty (use replace_prefix or strip_prefix to \
                     remove path material)",
                ));
            } else {
                // The substitution must expand to an absolute path or be a
                // pure capture expansion: reject anything that starts with
                // a literal (a relative result cannot be reparsed as a
                // request URI, and the dataplane would silently forward the
                // ORIGINAL path). Whitespace, '?', and '#' would corrupt
                // the path/query split; control characters never belong.
                if !substitution.starts_with(['/', '$', '{']) {
                    issues.push(issue(
                        "route",
                        route,
                        "action.rewrite.substitution",
                        format!(
                            "rewrite substitution '{substitution}' must start with '/' (or a \
                             capture reference like '$1' / '${{name}}') so it expands to an \
                             absolute path"
                        ),
                    ));
                }
                if substitution
                    .chars()
                    .any(|c| c.is_whitespace() || c == '?' || c == '#' || c.is_control())
                {
                    issues.push(issue(
                        "route",
                        route,
                        "action.rewrite.substitution",
                        format!(
                            "rewrite substitution '{substitution}' must not contain \
                             whitespace, '?', '#', or control characters"
                        ),
                    ));
                }
            }
        }
    }
}

/// Compiled route structures for one snapshot. Path-only lookup (v1); host,
/// method, header, query, and cookie matching are applied by the dataplane
/// after path resolution (see `proxy::route_applies`).
///
/// # Route precedence (canonical spec, DW-010)
///
/// A request path resolves to AT MOST ONE route, chosen across three
/// path-match kinds in a fixed order:
///
/// 1. **Exact** — `matchit` radix templates (`type: exact`). Within this
///    kind, `matchit`'s specificity rules apply: static segments beat
///    parameters (`/users/active` before `/users/{id}`). Templates that
///    would conflict are rejected at compile time
///    ([`CompileError::RouteConflict`]), so there is no ambiguity here.
/// 2. **Regex** — a shared `RegexSet` over all `type: regex` routes. When
///    several patterns match, the FIRST-DECLARED route in config order
///    wins (`RegexSet` returns matches in insertion order and lookup takes
///    the first).
/// 3. **Prefix** — byte-prefix matching (no segment boundary: `/v1` also
///    matches `/v1anything`). The LONGEST matching prefix wins; equal-length
///    ties go to the FIRST-DECLARED route (strict `>` comparison keeps the
///    earlier entry).
///
/// Cross-kind precedence is therefore: exact beats regex beats prefix,
/// regardless of declaration order and regardless of how "specific" a
/// regex or prefix looks. A shorter exact template beats a longer regex.
/// The prefix stored is the configured value with trailing `/` trimmed,
/// so `/v1/` and `/v1` are the same prefix and equal-length ties are
/// possible (first declared wins).
///
/// Non-path criteria (host, method, headers, query, cookies) are applied
/// AFTER this resolution; a criteria miss does NOT fall through to the
/// next candidate — the request is unmatched (404 in v1).
///
/// Prefix lookup is a linear scan over the prefix list, O(n) in the number
/// of prefix routes per request; fine at v1 route counts, revisit if route
/// tables grow large.
#[derive(Debug)]
pub struct RouteTable {
    exact: matchit::Router<usize>,
    /// (prefix, route index) for prefix-kind routes; longest prefix wins.
    prefixes: Vec<(String, usize)>,
    regex_set: regex::RegexSet,
    /// Route index per RegexSet member, in insertion order.
    regex_indices: Vec<usize>,
    /// Compiled `path_rewrite.regex` pattern per route index (None where
    /// the action carries no regex rewrite). Validation guarantees these
    /// compiled at config-compile time, never at request time.
    rewrite_regexes: Vec<Option<regex::Regex>>,
}

impl RouteTable {
    fn empty() -> Self {
        RouteTable {
            exact: matchit::Router::new(),
            prefixes: Vec::new(),
            regex_set: regex::RegexSet::empty(),
            regex_indices: Vec::new(),
            rewrite_regexes: Vec::new(),
        }
    }

    /// Resolve a request path to a route index. Precedence: exact template,
    /// then first regex match, then longest prefix. `None` means no route.
    pub fn find(&self, path: &str) -> Option<usize> {
        self.find_full(path).map(|(idx, _)| idx)
    }

    /// Like [`RouteTable::find`] but also returns the path parameters
    /// captured by an exact-template match (`{name}` segments), as
    /// (name, value) pairs in template order. Regex- and prefix-kind
    /// routes return an empty parameter list.
    pub fn find_full(&self, path: &str) -> Option<(usize, Vec<(String, String)>)> {
        if let Ok(m) = self.exact.at(path) {
            let params = m
                .params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            return Some((*m.value, params));
        }
        let matches = self.regex_set.matches(path);
        if let Some(i) = matches.iter().next() {
            return Some((self.regex_indices[i], Vec::new()));
        }
        let mut best: Option<(usize, usize)> = None; // (prefix len, index)
        for (prefix, idx) in &self.prefixes {
            if path.starts_with(prefix.as_str()) && best.is_none_or(|(len, _)| prefix.len() > len) {
                best = Some((prefix.len(), *idx));
            }
        }
        best.map(|(_, idx)| (idx, Vec::new()))
    }

    /// The compiled rewrite regex for `idx`, if the route's proxy action
    /// carries a `path_rewrite.regex`.
    pub fn rewrite_regex(&self, idx: usize) -> Option<&regex::Regex> {
        self.rewrite_regexes.get(idx).and_then(|r| r.as_ref())
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
                global_policies: Vec::new(),
                authorization: None,
                max_concurrent_requests: None,
                jwt_providers: Vec::new(),
                admin: None,
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
    let mut rewrite_regexes: Vec<Option<regex::Regex>> = vec![None; gateway.routes.len()];

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
        if let RouteAction::Proxy {
            rewrite: Some(PathRewrite::Regex { pattern, .. }),
        } = &route.action
        {
            let compiled = regex::Regex::new(pattern).map_err(|e| CompileError::InvalidRegex {
                route: route.name.clone(),
                pattern: pattern.clone(),
                message: e.to_string(),
            })?;
            rewrite_regexes[idx] = Some(compiled);
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
            rewrite_regexes,
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
