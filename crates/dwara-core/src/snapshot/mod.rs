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
//! suitable for adversarial settings. The same hashing step backs a public
//! per-entity variant ([`entity_content_hash`]) so tooling can compare
//! single entities the way the gateway compares whole generations.

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
fn check_trusted_ca_file(
    entity: &str,
    name: &str,
    field: &str,
    path: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    use rustls_pki_types::pem::PemObject;

    if let Err(e) = std::fs::File::open(path) {
        issues.push(issue(
            entity,
            name,
            field,
            format!("{field} '{path}' is not a readable file: {e}"),
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
            field,
            format!(
                "{field} '{path}' holds no usable CA certificates \
                 (the PEM bundle must list at least one CERTIFICATE)"
            ),
        )),
        Err(e) => issues.push(issue(
            entity,
            name,
            field,
            format!(
                "{field} '{path}' could not be parsed as a PEM \
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
        && authz.ip_acl.is_none()
        && authz.geoip.is_none();
    if empty {
        issues.push(issue(
            entity,
            name,
            "authorization",
            "carries no rules (no consumers, groups, scopes, claims, ip_acl, \
             or geoip) and is always a mistake: omit the authorization block \
             entirely",
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

/// Validate one `cors` block (DW-027). The origin list must be a
/// non-empty closed set of well-formed `http(s)` origins (or `*`);
/// wildcard origins/headers cannot combine with credentials (Fetch spec:
/// `*` is not a valid allow-origin/allow-headers value on a credentialed
/// response); methods must be valid HTTP tokens; header lists must hold
/// valid header names (or `*` for `allowed_headers` only).
fn validate_cors(name: &str, cors: &crate::config::Cors, issues: &mut Vec<ValidationIssue>) {
    if cors.allowed_origins.is_empty() {
        issues.push(issue(
            "route",
            name,
            "cors.allowed_origins",
            "allowed_origins is empty: a cors block with no origins filters nothing \
             and is always a mistake; omit the cors block to disable CORS",
        ));
    }
    let wildcard = cors.allowed_origins.iter().any(|o| o == "*");
    if wildcard && cors.allow_credentials {
        issues.push(issue(
            "route",
            name,
            "cors.allowed_origins",
            "'*' cannot be combined with allow_credentials (the Fetch spec forbids \
             wildcard credentialed responses); list explicit origins instead",
        ));
    }
    for (i, origin) in cors.allowed_origins.iter().enumerate() {
        if origin == "*" {
            continue;
        }
        // Normalize exactly like the runtime matcher: lowercase scheme
        // and host, default port dropped. Anything the matcher would not
        // itself accept is an authoring error caught here.
        if crate::config::normalize_origin(origin).is_none() {
            issues.push(issue(
                "route",
                name,
                &format!("cors.allowed_origins[{i}]"),
                format!(
                    "'{origin}' is not a well-formed origin (expected scheme://host[:port] \
                     with an http or https scheme and no path, e.g. https://api.example.com, \
                     or the single entry '*')"
                ),
            ));
        }
    }
    if wildcard && cors.allowed_origins.len() > 1 {
        issues.push(issue(
            "route",
            name,
            "cors.allowed_origins",
            "'*' cannot be combined with other origins ('*' already matches everything)",
        ));
    }
    for (i, m) in cors.allowed_methods.iter().enumerate() {
        if hyper::Method::from_bytes(m.as_bytes()).is_err() {
            issues.push(issue(
                "route",
                name,
                &format!("cors.allowed_methods[{i}]"),
                format!("'{m}' is not a valid HTTP method token"),
            ));
        }
    }
    let header_lists = [
        ("cors.allowed_headers", &cors.allowed_headers, true),
        ("cors.expose_headers", &cors.expose_headers, false),
    ];
    for (field, list, allows_wildcard) in header_lists {
        for (i, h) in list.iter().enumerate() {
            if h == "*" {
                if !allows_wildcard {
                    issues.push(issue(
                        "route",
                        name,
                        &format!("{field}[{i}]"),
                        "'*' is only valid in allowed_headers (expose_headers must name \
                         the headers to expose)",
                    ));
                } else if cors.allow_credentials {
                    issues.push(issue(
                        "route",
                        name,
                        &format!("{field}[{i}]"),
                        "'*' cannot be combined with allow_credentials (the Fetch spec \
                         forbids wildcard allow-headers on credentialed preflights); \
                         list explicit header names instead",
                    ));
                }
                continue;
            }
            if hyper::header::HeaderName::from_bytes(h.as_bytes()).is_err() {
                issues.push(issue(
                    "route",
                    name,
                    &format!("{field}[{i}]"),
                    format!("'{h}' is not a valid HTTP header name"),
                ));
            }
        }
    }
}

/// Validate one `compression` block (DW-027): non-empty duplicate-free
/// algorithm list, level within 0-22 (per-algorithm clamping happens at
/// encode time), and non-empty content-type prefixes.
fn validate_compression(
    name: &str,
    compression: &crate::config::Compression,
    issues: &mut Vec<ValidationIssue>,
) {
    if compression.algorithms.is_empty() {
        issues.push(issue(
            "route",
            name,
            "compression.algorithms",
            "algorithms is empty: a compression block with no algorithms compresses \
             nothing and is always a mistake; omit the compression block to disable it",
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for (i, a) in compression.algorithms.iter().enumerate() {
        if !seen.insert(a) {
            issues.push(issue(
                "route",
                name,
                &format!("compression.algorithms[{i}]"),
                format!("algorithm '{a:?}' is listed more than once"),
            ));
        }
    }
    if let Some(level) = compression.level {
        if level > 22 {
            issues.push(issue(
                "route",
                name,
                "compression.level",
                format!(
                    "level {level} is out of range: 0-22 (clamped per algorithm: \
                         gzip 0-9, brotli 0-11, zstd 0-22)"
                ),
            ));
        }
    }
    for (field, entries) in [
        ("compression.content_types", &compression.content_types),
        (
            "compression.excluded_content_types",
            &compression.excluded_content_types,
        ),
    ] {
        for (i, entry) in entries.iter().enumerate() {
            let t = entry.trim().to_lowercase();
            if t.is_empty() || t.contains(char::is_whitespace) {
                issues.push(issue(
                    "route",
                    name,
                    &format!("{field}[{i}]"),
                    format!(
                        "'{entry}' is not a content-type prefix (expected a non-empty \
                         token like 'text/' or 'application/json')"
                    ),
                ));
            }
        }
    }
}

/// Validate one `request_limits` block (DW-027): at least one limit set,
/// every set limit >= 1.
fn validate_request_limits(
    name: &str,
    limits: &crate::config::RequestLimits,
    issues: &mut Vec<ValidationIssue>,
) {
    if limits.max_body_bytes.is_none()
        && limits.max_header_count.is_none()
        && limits.max_header_bytes.is_none()
    {
        issues.push(issue(
            "route",
            name,
            "limits",
            "carries no limits (no max_body_bytes, max_header_count, or max_header_bytes) \
             and is always a mistake: omit the limits block entirely",
        ));
    }
    if let Some(0) = limits.max_body_bytes {
        issues.push(issue(
            "route",
            name,
            "limits.max_body_bytes",
            "max_body_bytes must be > 0 (0 would reject every request with a body)",
        ));
    }
    if let Some(0) = limits.max_header_count {
        issues.push(issue(
            "route",
            name,
            "limits.max_header_count",
            "max_header_count must be > 0",
        ));
    }
    if let Some(0) = limits.max_header_bytes {
        issues.push(issue(
            "route",
            name,
            "limits.max_header_bytes",
            "max_header_bytes must be > 0",
        ));
    }
}

/// Validate one `deprecation` block (DW-048): a block with no dates has
/// no effect (omit it); dates must be IMF-fixdate HTTP-dates (the only
/// form RFC 9110 generators may send — see `config::versioning`); a
/// sunset already in the past advertises a removal that already happened
/// (rejected: remove the route or extend the date — this also stops a
/// long-lived deployment from silently re-publishing a stale sunset;
/// a rejected hot reload keeps the running generation, so the operator
/// must fix the date to publish ANY new config carrying it, which is the
/// fail-closed intent); sunset must not precede since; and `uri`
/// documents the `Deprecation` header, so it requires `since`. The
/// past-sunset check reads the wall clock: it is a compile-time policy
/// gate, not a per-request one.
fn validate_deprecation(
    name: &str,
    dep: &crate::config::Deprecation,
    issues: &mut Vec<ValidationIssue>,
) {
    let since = dep
        .since
        .as_deref()
        .and_then(crate::config::versioning::parse_http_date);
    let sunset = dep
        .sunset
        .as_deref()
        .and_then(crate::config::versioning::parse_http_date);
    // The no-dates check reads the RAW fields: a garbage `since` with no
    // `sunset` is a date-format error, not an empty block (reporting it
    // as both would be noise).
    if dep.since.is_none() && dep.sunset.is_none() {
        issues.push(issue(
            "route",
            name,
            "deprecation",
            "carries no dates (no since or sunset) and emits nothing: omit the \
             deprecation block entirely",
        ));
    }
    for (field, value) in [
        ("deprecation.since", &dep.since),
        ("deprecation.sunset", &dep.sunset),
    ] {
        if let Some(v) = value {
            if crate::config::versioning::parse_http_date(v).is_none() {
                issues.push(issue(
                    "route",
                    name,
                    field,
                    format!(
                        "'{v}' is not a valid HTTP-date: use the IMF-fixdate form \
                         (e.g. 'Sun, 06 Nov 1994 08:49:37 GMT')"
                    ),
                ));
            }
        }
    }
    if let Some(s) = since {
        if s.unix_seconds() < 0 {
            issues.push(issue(
                "route",
                name,
                "deprecation.since",
                "since must be 1970 or later (the RFC 9745 Deprecation header renders it \
                 as a Unix-time structured date)",
            ));
        }
    }
    if let Some(s) = sunset {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if s.unix_seconds() < now {
            issues.push(issue(
                "route",
                name,
                "deprecation.sunset",
                format!(
                    "sunset date '{}' is in the past: the route should be removed or the \
                     date extended, not advertise a removal that already happened",
                    dep.sunset.as_deref().unwrap_or_default()
                ),
            ));
        }
        if let Some(since_date) = since {
            if s.unix_seconds() < since_date.unix_seconds() {
                issues.push(issue(
                    "route",
                    name,
                    "deprecation.sunset",
                    "sunset is before since (the route would be removed before it is \
                     deprecated)",
                ));
            }
        }
    }
    if let Some(uri) = &dep.uri {
        if since.is_none() {
            issues.push(issue(
                "route",
                name,
                "deprecation.uri",
                "uri requires since: the Link rel=\"deprecation\" it emits documents the \
                 Deprecation header, which only since produces",
            ));
        }
        // The Link header is built as `<uri>; rel="deprecation"` — the
        // URI must parse AND carry no byte that breaks out of the angle
        // brackets or the quoted param.
        let parseable = match uri.parse::<hyper::Uri>() {
            Ok(u) => matches!(u.scheme_str(), Some("http") | Some("https")) && u.host().is_some(),
            Err(_) => false,
        };
        if !parseable || uri.bytes().any(|b| matches!(b, b'<' | b'>' | b'"')) {
            issues.push(issue(
                "route",
                name,
                "deprecation.uri",
                format!(
                    "'{uri}' must be an absolute http(s) URL with no '<', '>', or '\"' \
                         (it is emitted inside a Link header)"
                ),
            ));
        }
    }
}

/// Validate one `maintenance` block (DW-041): `retry_after_secs` 0 would
/// invite an immediate retry stampede against the route the operator just
/// took down (the whole point of the header is "come back later"), and an
/// empty `message` is indistinguishable from an absent one (omit it for
/// the default text).
fn validate_maintenance(
    name: &str,
    maintenance: &crate::config::Maintenance,
    issues: &mut Vec<ValidationIssue>,
) {
    if maintenance.retry_after_secs == Some(0) {
        issues.push(issue(
            "route",
            name,
            "maintenance.retry_after_secs",
            "retry_after_secs must be > 0 (0 tells clients to retry immediately against a \
             route that is down; omit the field for the 60s default)",
        ));
    }
    if maintenance
        .message
        .as_deref()
        .is_some_and(|m| m.trim().is_empty())
    {
        issues.push(issue(
            "route",
            name,
            "maintenance.message",
            "message is empty: omit the field for the default 'route under maintenance' text",
        ));
    }
}

/// Validate one `transforms` block (DW-028): no empty containers (a
/// transforms block that transforms nothing is an authoring mistake),
/// representable header names and values, no framing/hop-by-hop header
/// names (the body pipeline owns framing; `deny`-listing them here is
/// the request-smuggling guard — see `config::transforms`), sane
/// query-component bytes, and JSON pointers that parse (the shared
/// grammar in `config::transforms`, the same agreement validation
/// holds with every other runtime grammar).
fn validate_transforms(
    name: &str,
    transforms: &crate::config::transforms::Transforms,
    issues: &mut Vec<ValidationIssue>,
) {
    if transforms.request.is_none() && transforms.response.is_none() {
        issues.push(issue(
            "route",
            name,
            "transforms",
            "carries neither request nor response (nothing to transform) and is always a \
             mistake: omit the transforms block entirely",
        ));
    }
    if let Some(req) = &transforms.request {
        if req.headers.is_none() && req.query.is_none() && req.body.is_none() {
            issues.push(issue(
                "route",
                name,
                "transforms.request",
                "carries no headers, query, or body block and is always a mistake: omit it",
            ));
        }
        if let Some(headers) = &req.headers {
            validate_header_ops(name, "transforms.request.headers", headers, true, issues);
        }
        if let Some(query) = &req.query {
            validate_query_ops(name, "transforms.request.query", query, issues);
        }
        if let Some(body) = &req.body {
            validate_json_body(name, "transforms.request.body", &body.json, issues);
        }
    }
    if let Some(resp) = &transforms.response {
        if resp.headers.is_none() && resp.body.is_none() {
            issues.push(issue(
                "route",
                name,
                "transforms.response",
                "carries no headers or body block and is always a mistake: omit it",
            ));
        }
        if let Some(headers) = &resp.headers {
            validate_header_ops(name, "transforms.response.headers", headers, false, issues);
        }
        if let Some(body) = &resp.body {
            validate_json_body(name, "transforms.response.body", &body.json, issues);
        }
    }
}

/// Validate one header-ops block. `request_side` selects the forbidden
/// set: the request side forbids `host` (the gateway names the origin
/// it dials) and the framing pair; the response side forbids the
/// framing pair plus `content-encoding` (only the compression pipeline
/// may manage it — an op that stripped it without decoding would
/// corrupt the body, and one that added it would misdescribe bytes it
/// did not encode).
fn validate_header_ops(
    route: &str,
    field: &str,
    ops: &crate::config::transforms::HeaderOps,
    request_side: bool,
    issues: &mut Vec<ValidationIssue>,
) {
    use crate::config::transforms as t;
    if ops.set.is_empty() && ops.add.is_empty() && ops.remove.is_empty() && ops.rename.is_empty() {
        issues.push(issue(
            "route",
            route,
            field,
            "carries no set, add, remove, or rename entries and is always a mistake: omit it",
        ));
    }
    let names: Vec<(&str, String)> = ops
        .set
        .keys()
        .map(|k| ("set", k.clone()))
        .chain(ops.add.keys().map(|k| ("add", k.clone())))
        .chain(ops.remove.iter().map(|k| ("remove", k.clone())))
        .chain(ops.rename.keys().map(|k| ("rename", k.clone())))
        .chain(ops.rename.values().map(|k| ("rename (to)", k.clone())))
        .collect();
    for (op, header) in &names {
        if hyper::header::HeaderName::from_bytes(header.as_bytes()).is_err() {
            issues.push(issue(
                "route",
                route,
                field,
                format!("'{header}' ({op}) is not a valid HTTP header name"),
            ));
            continue;
        }
        let forbidden = if request_side {
            t::is_forbidden_request_header(header)
        } else {
            t::is_forbidden_response_header(header)
        };
        if forbidden {
            issues.push(issue(
                "route",
                route,
                field,
                format!(
                    "'{header}' ({op}) is a framing/hop-by-hop header the gateway's body \
                     pipeline owns: transforms may not touch it (request smuggling and \
                     body-corruption guard)"
                ),
            ));
        }
    }
    for (op, value) in ops
        .set
        .values()
        .map(|v| ("set", v))
        .chain(ops.add.values().map(|v| ("add", v)))
    {
        if hyper::header::HeaderValue::from_str(value).is_err() {
            issues.push(issue(
                "route",
                route,
                field,
                format!(
                    "the '{op}' value '{value}' is not representable in an HTTP header \
                     (control characters and non-visible bytes are rejected)"
                ),
            ));
        }
    }
    for (from, to) in &ops.rename {
        if from == to {
            issues.push(issue(
                "route",
                route,
                field,
                format!("rename '{from}' -> '{to}' is a no-op: rename to a different name"),
            ));
        }
    }
}

/// Validate one query-ops block (DW-028): names and values must be
/// plain ASCII without the query structural bytes (`&` separates
/// pairs, `=` separates key from value, `#` would start a fragment).
/// Everything else the runtime percent-encodes on emit.
fn validate_query_ops(
    route: &str,
    field: &str,
    ops: &crate::config::transforms::QueryOps,
    issues: &mut Vec<ValidationIssue>,
) {
    if ops.set.is_empty() && ops.add.is_empty() && ops.remove.is_empty() && ops.rename.is_empty() {
        issues.push(issue(
            "route",
            route,
            field,
            "carries no set, add, remove, or rename entries and is always a mistake: omit it",
        ));
    }
    let check = |kind: &str, key: &str, value: Option<&str>, issues: &mut Vec<ValidationIssue>| {
        let bad_name = key.is_empty()
            || key.bytes().any(|b| {
                !b.is_ascii() || b.is_ascii_control() || matches!(b, b'&' | b'=' | b'#' | b' ')
            });
        if bad_name {
            issues.push(issue(
                "route",
                route,
                field,
                format!(
                    "the {kind} name '{key}' is not a plain query name (non-empty ASCII, no \
                     '&', '=', '#', or spaces)"
                ),
            ));
        }
        if let Some(v) = value {
            if v.bytes()
                .any(|b| !b.is_ascii() || b.is_ascii_control() || matches!(b, b'&' | b'#'))
            {
                issues.push(issue(
                    "route",
                    route,
                    field,
                    format!(
                        "the {kind} value '{v}' is not representable in a query string \
                         (ASCII without '&' or '#')"
                    ),
                ));
            }
        }
    };
    for (k, v) in &ops.set {
        check("set", k, Some(v), issues);
    }
    for (k, v) in &ops.add {
        check("add", k, Some(v), issues);
    }
    for k in &ops.remove {
        check("remove", k, None, issues);
    }
    for (from, to) in &ops.rename {
        check("rename", from, None, issues);
        check("rename (to)", to, None, issues);
        if from == to {
            issues.push(issue(
                "route",
                route,
                field,
                format!("rename '{from}' -> '{to}' is a no-op: rename to a different key"),
            ));
        }
    }
}

/// Validate one JSON body transform (DW-028): non-empty ops, a positive
/// cap, pointers that parse (the shared `config::transforms` grammar),
/// and no `remove` of the whole document.
fn validate_json_body(
    route: &str,
    field: &str,
    json: &crate::config::transforms::JsonBodyTransform,
    issues: &mut Vec<ValidationIssue>,
) {
    use crate::config::transforms as t;
    if json.ops.is_empty() {
        issues.push(issue(
            "route",
            route,
            &format!("{field}.json.ops"),
            "ops is empty: a body transform that transforms nothing is always a mistake \
             (and still pays the content-type gate); omit the body block",
        ));
    }
    if json.max_bytes == 0 {
        issues.push(issue(
            "route",
            route,
            &format!("{field}.json.max_bytes"),
            "max_bytes must be > 0 (0 would fail every body against the transform cap)",
        ));
    }
    for (i, op) in json.ops.iter().enumerate() {
        let path = match op {
            t::JsonOp::Set { path, .. } => path,
            t::JsonOp::Remove { path } => path,
        };
        match t::JsonPointer::parse(path) {
            None => issues.push(issue(
                "route",
                route,
                &format!("{field}.json.ops[{i}].path"),
                format!(
                    "'{path}' is not an RFC 6901 JSON pointer (start with '/', use ~0 and ~1 \
                     for '~' and '/', e.g. /items/0/id; '' addresses the whole document)"
                ),
            )),
            Some(pointer) => {
                if matches!(op, t::JsonOp::Remove { .. }) && pointer.is_root() {
                    issues.push(issue(
                        "route",
                        route,
                        &format!("{field}.json.ops[{i}].path"),
                        "remove at the root pointer ('') would delete the whole document — \
                         there is no 'no body' state to forward; use set at the root to \
                         replace it",
                    ));
                }
            }
        }
    }
}

/// Validate one `security_headers` block (DW-028): at least one header
/// opted in, HSTS directives that compose (0 is the RFC 6797 deletion
/// signal this policy cannot express; the subdomains/preload
/// directives are meaningless without a max-age, and the preload list
/// requires includeSubDomains), and a CSP that is non-empty and
/// representable in an HTTP header (the runtime's silent-skip backstop
/// must stay unreachable).
fn validate_security_headers(
    name: &str,
    sh: &crate::config::transforms::SecurityHeaders,
    issues: &mut Vec<ValidationIssue>,
) {
    if sh.hsts_max_age_secs.is_none()
        && !sh.nosniff
        && sh.content_security_policy.is_none()
        && sh.frame_options.is_none()
    {
        issues.push(issue(
            "route",
            name,
            "security_headers",
            "carries no policy (no HSTS, nosniff, CSP, or frame_options) and is always a \
             mistake: omit the security_headers block to disable injection",
        ));
    }
    if sh.hsts_max_age_secs == Some(0) {
        issues.push(issue(
            "route",
            name,
            "security_headers.hsts_max_age_secs",
            "hsts_max_age_secs must be > 0 (max-age=0 is the RFC 6797 deletion signal — \
             delete the field to stop emitting HSTS on this route)",
        ));
    }
    if sh.hsts_max_age_secs.is_none() && (sh.hsts_include_subdomains || sh.hsts_preload) {
        issues.push(issue(
            "route",
            name,
            "security_headers.hsts_include_subdomains",
            "include_subdomains/preload require hsts_max_age_secs: the directives only \
             exist inside a Strict-Transport-Security header, which a max-age starts",
        ));
    }
    if sh.hsts_preload && !sh.hsts_include_subdomains {
        issues.push(issue(
            "route",
            name,
            "security_headers.hsts_preload",
            "preload requires include_subdomains (the HSTS preload list rejects entries \
             without it; emitting a header the list would refuse is an authoring mistake)",
        ));
    }
    if sh
        .content_security_policy
        .as_deref()
        .is_some_and(|p| p.trim().is_empty())
    {
        issues.push(issue(
            "route",
            name,
            "security_headers.content_security_policy",
            "content_security_policy is empty: omit the field to stop emitting CSP on \
             this route",
        ));
    }
    if let Some(csp) = sh.content_security_policy.as_deref() {
        // The runtime stamps the policy inside a representable-only skip
        // (`if let Ok(v) = HeaderValue::from_str(..)`); validation keeps
        // that skip unreachable, so a publishable config can never carry
        // a CSP the edge would silently not emit. The realistic trap is a
        // YAML block scalar's trailing newline.
        if !csp.trim().is_empty() && hyper::header::HeaderValue::from_str(csp).is_err() {
            issues.push(issue(
                "route",
                name,
                "security_headers.content_security_policy",
                "content_security_policy is not representable in an HTTP header (control \
                 characters are rejected — including the trailing newline a YAML block \
                 scalar adds)",
            ));
        }
    }
}

/// Validate one `cache` block (DW-037): bounded ttl/stale window/body
/// cap, and a vary list whose entries are real header names, dedupli-
/// cated, and not one of the names the variance model forbids; the
/// DW-038 coalescing wait bound (the grammar lives in `config::cache`,
/// the same validate/compile split as every other route block).
fn validate_route_cache(
    name: &str,
    cache: &crate::config::cache::RouteCache,
    issues: &mut Vec<ValidationIssue>,
) {
    use crate::config::cache::{
        forbidden_vary_reason, MAX_CACHE_MAX_BODY_BYTES, MAX_CACHE_STALE_SECS, MAX_CACHE_TTL_SECS,
        MAX_CACHE_VARY_HEADERS, MAX_COALESCE_WAIT_MS,
    };
    if cache.ttl_secs == 0 {
        issues.push(issue(
            "route",
            name,
            "cache.ttl_secs",
            "ttl_secs must be >= 1 (a zero lifetime would expire every entry immediately; \
             omit the cache block to disable caching)",
        ));
    } else if cache.ttl_secs > MAX_CACHE_TTL_SECS {
        issues.push(issue(
            "route",
            name,
            "cache.ttl_secs",
            format!(
                "ttl_secs must be <= {MAX_CACHE_TTL_SECS} (24 h; longer freshness belongs to a \
                 CDN in front of the gateway)"
            ),
        ));
    }
    if let Some(swr) = cache.stale_while_revalidate_secs {
        if swr > MAX_CACHE_STALE_SECS {
            issues.push(issue(
                "route",
                name,
                "cache.stale_while_revalidate_secs",
                format!(
                    "stale_while_revalidate_secs must be <= {MAX_CACHE_STALE_SECS} (24 h, \
                     symmetric with the ttl bound)"
                ),
            ));
        }
    }
    if cache.max_body_bytes == 0 {
        issues.push(issue(
            "route",
            name,
            "cache.max_body_bytes",
            "max_body_bytes must be >= 1 (0 would store nothing; omit the cache block to \
             disable caching)",
        ));
    } else if cache.max_body_bytes > MAX_CACHE_MAX_BODY_BYTES {
        issues.push(issue(
            "route",
            name,
            "cache.max_body_bytes",
            format!(
                "max_body_bytes must be <= {MAX_CACHE_MAX_BODY_BYTES} (16 MiB; larger bodies \
                 stream through unstored)"
            ),
        ));
    }
    if cache.vary.len() > MAX_CACHE_VARY_HEADERS {
        issues.push(issue(
            "route",
            name,
            "cache.vary",
            format!(
                "at most {MAX_CACHE_VARY_HEADERS} vary headers per route (each multiplies the \
                 entry key space)"
            ),
        ));
    }
    let mut seen: Vec<String> = Vec::new();
    for (i, raw) in cache.vary.iter().enumerate() {
        let trimmed = raw.trim();
        let lowered = trimmed.to_ascii_lowercase();
        let field = format!("cache.vary[{i}]");
        if lowered.is_empty()
            || lowered != trimmed
            || lowered.starts_with('-')
            || lowered.ends_with('-')
            || !lowered
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'-' || b.is_ascii_digit())
        {
            issues.push(issue(
                "route",
                name,
                &field,
                format!("'{raw}' is not a header name (use the trimmed lowercase form)"),
            ));
            continue;
        }
        if let Some(reason) = forbidden_vary_reason(&lowered) {
            issues.push(issue(
                "route",
                name,
                &field,
                format!("'{lowered}' cannot vary: {reason}"),
            ));
            continue;
        }
        if seen.contains(&lowered) {
            issues.push(issue(
                "route",
                name,
                &field,
                format!("duplicate vary header '{lowered}' (deduplicate the list)"),
            ));
        }
        seen.push(lowered);
    }
    // DW-038: the coalescing follower wait bound. 0 would time every
    // follower out before the leader could possibly answer (a wait is
    // the only reason the block exists); a minute-plus wait just parks
    // clients behind a leader the route's own timeouts already bound.
    if let Some(coalescing) = &cache.coalescing {
        if coalescing.wait_ms == 0 {
            issues.push(issue(
                "route",
                name,
                "cache.coalescing.wait_ms",
                "wait_ms must be >= 1 (0 would fail every follower open before the leader \
                 answers; omit the coalescing block to disable coalescing)",
            ));
        } else if coalescing.wait_ms > MAX_COALESCE_WAIT_MS {
            issues.push(issue(
                "route",
                name,
                "cache.coalescing.wait_ms",
                format!(
                    "wait_ms must be <= {MAX_COALESCE_WAIT_MS} (60 s; a follower parked longer \
                     is a stuck request from the client's point of view)"
                ),
            ));
        }
    }
}

/// Validate one `masking` block (DW-029): a positive cap, at least one
/// pointer somewhere (a masking policy that masks nothing is an
/// authoring mistake), pointers that parse and are not the root, and
/// group names that resolve against some config consumer's membership
/// — a typo'd group name silently never masks, which is fail-OPEN, the
/// exact posture this policy forbids (same check, and same store-only
/// caveat, as authorization group rules).
fn validate_masking(
    name: &str,
    masking: &crate::config::transforms::Masking,
    consumer_groups: &std::collections::BTreeSet<&str>,
    issues: &mut Vec<ValidationIssue>,
) {
    use crate::config::transforms as t;
    if masking.fields.is_empty() && masking.groups.is_empty() {
        issues.push(issue(
            "route",
            name,
            "masking",
            "carries no fields and no groups (nothing to mask) and is always a mistake: \
             omit the masking block to disable masking on this route",
        ));
    }
    if masking.max_bytes == 0 {
        issues.push(issue(
            "route",
            name,
            "masking.max_bytes",
            "max_bytes must be > 0 (0 would fail every response against the masking cap)",
        ));
    }
    let check_pointer =
        |field: String, path: &str, issues: &mut Vec<ValidationIssue>| match t::JsonPointer::parse(
            path,
        ) {
            None => issues.push(issue(
                "route",
                name,
                &field,
                format!(
                    "'{path}' is not an RFC 6901 JSON pointer (start with '/', use ~0 and ~1 for \
                 '~' and '/', e.g. /items/0/id)"
                ),
            )),
            Some(pointer) => {
                if pointer.is_root() {
                    issues.push(issue(
                    "route",
                    name,
                    &field,
                    "the root pointer ('') would replace the whole document with the sentinel — \
                     a body the route cannot usefully serve; mask fields, not the document",
                ));
                }
            }
        };
    for (i, path) in masking.fields.iter().enumerate() {
        check_pointer(format!("masking.fields[{i}]"), path, issues);
    }
    for (group, paths) in &masking.groups {
        if group.trim().is_empty() {
            issues.push(issue(
                "route",
                name,
                "masking.groups",
                format!("group key '{group}' is empty: group names are non-empty strings"),
            ));
        }
        if !consumer_groups.contains(group.as_str()) {
            issues.push(issue(
                "route",
                name,
                "masking.groups",
                format!(
                    "group '{group}' matches no configured consumer's groups membership — a \
                     typo here silently never masks (fail-open); grant a consumer the group \
                     or fix the name (store-managed consumers carry groups the config cannot \
                     see, the known caveat of this check)"
                ),
            ));
        }
        if paths.is_empty() {
            issues.push(issue(
                "route",
                name,
                "masking.groups",
                format!(
                    "group '{group}' carries no pointers and is always a mistake: omit \
                         the entry (the route floor still applies to the group's consumers)"
                ),
            ));
        }
        for (i, path) in paths.iter().enumerate() {
            check_pointer(format!("masking.groups.{group}[{i}]"), path, issues);
        }
    }
}

/// Validate the `gateway.analytics` block (DW-043): the database path
/// must be non-empty (it is opened at startup — an empty string would
/// silently create a throwaway temp database), `flush_ms` bounded
/// (a sub-100 ms flush tick is timer churn; past 60 s the writer's
/// latency is the rollup grace's problem, not a useful knob),
/// retention monotone (a coarser table may not expire before a finer
/// one — the cascade would be recomputing from deleted history), and
/// dimensions name-valid (`[a-z0-9_]{1,32}` — the name is the rollup
/// table's `dim` key), header-representable, unique, and at most 16
/// (every dimension multiplies rollup cardinality).
fn validate_analytics(gateway: &Gateway, issues: &mut Vec<ValidationIssue>) {
    let Some(a) = &gateway.analytics else { return };
    if a.path.trim().is_empty() {
        issues.push(issue(
            "gateway",
            "(root)",
            "analytics.path",
            "analytics.path is empty: the database path must name a real file \
             (an empty path would open a throwaway temp database, losing every \
             record)",
        ));
    }
    if let Some(flush) = a.flush_ms {
        if !(100..=60_000).contains(&flush) {
            issues.push(issue(
                "gateway",
                "(root)",
                "analytics.flush_ms",
                format!(
                    "flush_ms {flush} is out of range: must be 100..=60000 \
                     (below 100 is timer churn; above 60000 adds nothing the \
                     rollup grace does not already cover)"
                ),
            ));
        }
    }
    if let Some(r) = &a.retention {
        let e = r.effective();
        let names = ["raw_ms", "m1_ms", "m5_ms", "h1_ms", "d1_ms"];
        for i in 0..5 {
            let v = e[i];
            let cap: i64 = match i {
                0 => 7 * 86_400_000,     // raw: a week
                1 => 30 * 86_400_000,    // 1m: a month
                2 => 90 * 86_400_000,    // 5m: a quarter
                3 => 365 * 86_400_000,   // 1h: a year
                _ => 3_650 * 86_400_000, // 1d: a decade
            };
            if v > cap {
                issues.push(issue(
                    "gateway",
                    "(root)",
                    &format!("analytics.retention.{}", names[i]),
                    format!(
                        "{} {} ms exceeds the cap {} ms (bounded disk is the \
                         point of the store)",
                        names[i], v, cap
                    ),
                ));
            }
        }
        for w in 0..4 {
            if e[w + 1] < e[w] {
                issues.push(issue(
                    "gateway",
                    "(root)",
                    &format!("analytics.retention.{}", names[w + 1]),
                    format!(
                        "{} {} ms is shorter than {} {} ms: a coarser \
                         rollup may not expire before the finer table it \
                         cascades from",
                        names[w + 1],
                        e[w + 1],
                        names[w],
                        e[w]
                    ),
                ));
            }
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for (i, dim) in a.dimensions.iter().enumerate() {
        let field = format!("analytics.dimensions[{i}]");
        let name_ok = !dim.name.is_empty()
            && dim.name.len() <= 32
            && dim
                .name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if !name_ok {
            issues.push(issue(
                "gateway",
                "(root)",
                &format!("{field}.name"),
                format!(
                    "dimension name '{}' is invalid: lowercase [a-z0-9_], \
                     1..=32 bytes (it is the rollup dimension key)",
                    dim.name
                ),
            ));
        }
        match hyper::header::HeaderName::try_from(dim.header.as_str()) {
            Ok(_) => {}
            Err(e) => issues.push(issue(
                "gateway",
                "(root)",
                &format!("{field}.header"),
                format!("header name '{}' is not representable: {e}", dim.header),
            )),
        }
        if !seen.insert(dim.name.to_ascii_lowercase()) {
            issues.push(issue(
                "gateway",
                "(root)",
                &format!("{field}.name"),
                format!(
                    "duplicate dimension name '{}' (each name is one rollup key)",
                    dim.name
                ),
            ));
        }
    }
    if a.dimensions.len() > 16 {
        issues.push(issue(
            "gateway",
            "(root)",
            "analytics.dimensions",
            format!(
                "{} dimensions declared; at most 16 (each multiplies rollup \
                 cardinality)",
                a.dimensions.len()
            ),
        ));
    }
}

/// Validate GeoIP rules (DW-050): every `authorization.geoip`
/// predicate anywhere in the config (gateway/listener/service/route/
/// consumer — the five Authz attachment points) needs a
/// `gateway.geoip` database (an unevaluable gate is an authoring
/// error, never a silent pass), and country entries must be two ASCII
/// letters.
fn validate_geoip(gateway: &Gateway, issues: &mut Vec<ValidationIssue>) {
    fn check(a: Option<&crate::config::Authz>, where_: &str, issues: &mut Vec<ValidationIssue>) {
        let Some(rules) = a.and_then(|a| a.geoip.as_ref()) else {
            return;
        };
        for c in rules
            .allowed_countries
            .iter()
            .chain(&rules.denied_countries)
        {
            if c.len() != 2 || !c.chars().all(|ch| ch.is_ascii_alphabetic()) {
                issues.push(issue(
                    "gateway",
                    where_,
                    "authorization.geoip.countries",
                    format!("country code '{c}' is not two ASCII letters (ISO 3166-1 alpha-2)"),
                ));
            }
        }
    }
    let has_rules = |a: Option<&crate::config::Authz>| a.is_some_and(|a| a.geoip.is_some());
    let any = gateway
        .authorization
        .as_ref()
        .is_some_and(|a| has_rules(Some(a)))
        || gateway
            .listeners
            .iter()
            .any(|l| has_rules(l.authorization.as_ref()))
        || gateway
            .services
            .iter()
            .any(|s| has_rules(s.authorization.as_ref()))
        || gateway
            .routes
            .iter()
            .any(|r| has_rules(r.authorization.as_ref()))
        || gateway
            .consumers
            .iter()
            .any(|c| has_rules(c.authorization.as_ref()));
    match &gateway.geoip {
        None if any => issues.push(issue(
            "gateway",
            "(root)",
            "geoip",
            "authorization.geoip rules require a gateway.geoip database block \
             (without one the gate cannot be evaluated)",
        )),
        Some(g) if g.path.trim().is_empty() => issues.push(issue(
            "gateway",
            "(root)",
            "geoip.path",
            "geoip.path is empty: name a real .mmdb file or remove the block",
        )),
        _ => {}
    }
    check(gateway.authorization.as_ref(), "(root)", issues);
    for l in &gateway.listeners {
        check(
            l.authorization.as_ref(),
            &format!("listeners[{}]", l.name),
            issues,
        );
    }
    for s in &gateway.services {
        check(
            s.authorization.as_ref(),
            &format!("services[{}]", s.name),
            issues,
        );
    }
    for r in &gateway.routes {
        check(
            r.authorization.as_ref(),
            &format!("routes[{}]", r.name),
            issues,
        );
    }
    for c in &gateway.consumers {
        check(
            c.authorization.as_ref(),
            &format!("consumers[{}]", c.name),
            issues,
        );
    }
}

/// Validate consumer request budgets (DW-033): a `quotas` block must
/// set at least one budget, and every set budget must be > 0 (a 0
/// budget would deny the consumer's first request; "no budget" is the
/// omitted field). Quota enforcement additionally needs the state
/// store at RUNTIME (`DWARA_STATE_DB`), which config validation
/// deliberately cannot see — without one the block is inert and the
/// dataplane warns (see `state::quotas`).
fn validate_quotas(gateway: &Gateway, issues: &mut Vec<ValidationIssue>) {
    for c in &gateway.consumers {
        let Some(q) = &c.quotas else {
            continue;
        };
        let field = format!("consumers[{}].quotas", c.name);
        if q.daily_requests.is_none() && q.monthly_requests.is_none() {
            issues.push(issue(
                "consumer",
                &c.name,
                &field,
                "sets no budget: at least one of daily_requests or monthly_requests \
                 must be present (omit the quotas block entirely for no budgets)",
            ));
        }
        for (name, value) in [
            ("daily_requests", q.daily_requests),
            ("monthly_requests", q.monthly_requests),
        ] {
            if value == Some(0) {
                issues.push(issue(
                    "consumer",
                    &c.name,
                    &format!("{field}.{name}"),
                    format!(
                        "{name} must be > 0 (a zero budget denies the consumer's \
                             first request; no budget is the omitted field)"
                    ),
                ));
            }
        }
    }
}

/// Validate the `gateway.webhooks` list (DW-044): every URL must be an
/// absolute http(s) URL, every `events` entry must name an emitted kind
/// (unknown spellings are rejected; `quota_near_limit` IS emitted since
/// DW-033), header names/values must be
/// representable (with `${...}` references resolved NOW, the DW-045
/// compile-time contract — an unresolvable reference fails the
/// generation closed, and the issue names the reference, never the
/// value), the retry knobs must be in bounds, and a duplicate URL is
/// rejected (two identical targets would double-deliver every event).
fn validate_webhooks(gateway: &Gateway, issues: &mut Vec<ValidationIssue>) {
    let mut seen_urls = std::collections::BTreeSet::new();
    for (i, hook) in gateway.webhooks.iter().enumerate() {
        let field = format!("webhooks[{i}]");
        match hook.url.parse::<hyper::Uri>() {
            Ok(uri) => {
                if !matches!(uri.scheme_str(), Some("http") | Some("https")) || uri.host().is_none()
                {
                    issues.push(issue(
                        "gateway",
                        "(root)",
                        &format!("{field}.url"),
                        format!(
                            "'{}' must be an absolute http(s) URL with a host \
                             (e.g. https://hooks.example.com/alerts)",
                            hook.url
                        ),
                    ));
                }
            }
            Err(_) => issues.push(issue(
                "gateway",
                "(root)",
                &format!("{field}.url"),
                format!("'{}' is not a valid URL", hook.url),
            )),
        }
        if !seen_urls.insert(hook.url.trim().to_string()) {
            issues.push(issue(
                "gateway",
                "(root)",
                &format!("{field}.url"),
                format!(
                    "duplicate webhook url '{}' (an event would be delivered \
                     twice; merge their events lists instead)",
                    hook.url
                ),
            ));
        }
        if hook.events.is_empty() {
            issues.push(issue(
                "gateway",
                "(root)",
                &format!("{field}.events"),
                "events is empty: a webhook subscribing to nothing never fires \
                 and is always a mistake; omit the entry",
            ));
        }
        for (j, kind) in hook.events.iter().enumerate() {
            if crate::events::EventKind::from_config(kind).is_none() {
                issues.push(issue(
                    "gateway",
                    "(root)",
                    &format!("{field}.events[{j}]"),
                    format!(
                        "unknown event kind '{kind}' (emitted kinds: {})",
                        crate::events::EventKind::ALL
                            .iter()
                            .map(|k| k.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ));
            }
        }
        for (name, value) in &hook.headers {
            if hyper::header::HeaderName::from_bytes(name.as_bytes()).is_err() {
                issues.push(issue(
                    "gateway",
                    "(root)",
                    &format!("{field}.headers"),
                    format!("header name '{name}' is not a valid HTTP header name"),
                ));
                continue;
            }
            // DW-045: resolve the value NOW (literals pass through) so an
            // unresolvable reference fails the generation closed; then the
            // RESOLVED bytes must be representable as a header value. The
            // issue names the header and the reason, never the value.
            let problem = match crate::config::credentials::resolve_configured_secret(value) {
                Ok(resolved) => {
                    if hyper::header::HeaderValue::from_str(&resolved).is_err() {
                        Some(
                            "the header value (after secret-reference resolution) \
                             contains characters that cannot appear in an HTTP \
                             header value"
                                .to_string(),
                        )
                    } else {
                        None
                    }
                }
                Err(message) => Some(message),
            };
            if let Some(message) = problem {
                issues.push(issue(
                    "gateway",
                    "(root)",
                    &format!("{field}.headers"),
                    format!("header '{name}': {message}"),
                ));
            }
        }
        if hook.timeout_ms == 0 || hook.timeout_ms > crate::config::limits::MAX_WEBHOOK_TIMEOUT_MS {
            issues.push(issue(
                "gateway",
                "(root)",
                &format!("{field}.timeout_ms"),
                format!(
                    "timeout_ms must be in 1..={} (one total budget per delivery, \
                     shared by every retry attempt)",
                    crate::config::limits::MAX_WEBHOOK_TIMEOUT_MS
                ),
            ));
        }
        if hook.max_attempts == 0 || hook.max_attempts > crate::config::limits::MAX_WEBHOOK_ATTEMPTS
        {
            issues.push(issue(
                "gateway",
                "(root)",
                &format!("{field}.max_attempts"),
                format!(
                    "max_attempts must be in 1..={} (total attempts per delivery)",
                    crate::config::limits::MAX_WEBHOOK_ATTEMPTS
                ),
            ));
        }
        if hook.backoff_base_ms == 0 {
            issues.push(issue(
                "gateway",
                "(root)",
                &format!("{field}.backoff_base_ms"),
                "backoff_base_ms must be > 0",
            ));
        }
        if hook.backoff_cap_ms < hook.backoff_base_ms {
            issues.push(issue(
                "gateway",
                "(root)",
                &format!("{field}.backoff_cap_ms"),
                "backoff_cap_ms must be >= backoff_base_ms",
            ));
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

    // Load-shed monitor mode (DW-041) is only meaningful with a cap: an
    // uncapped gateway never sheds, so the flag would be a silent no-op
    // that reads as monitoring coverage. Rejected rather than ignored so
    // the config cannot imply a guarantee it does not provide.
    if gateway.load_shed_dry_run && gateway.max_concurrent_requests.is_none() {
        issues.push(issue(
            "gateway",
            "(root)",
            "load_shed_dry_run",
            "load_shed_dry_run requires max_concurrent_requests: an uncapped gateway \
             never sheds, so the flag would be a silent no-op (set a cap, or omit \
             the flag)",
        ));
    }

    // HMAC signing policy bounds (DW-036): a zero-second window rejects
    // every signed request with any clock drift at all, and an unbounded
    // one pins nonce-cache memory for the process lifetime (nonces are
    // remembered for twice the window).
    if let Some(hmac) = &gateway.hmac_auth {
        let skew = hmac.max_clock_skew_secs;
        if !(1..=3600).contains(&skew) {
            issues.push(issue(
                "gateway",
                "(root)",
                "hmac_auth.max_clock_skew_secs",
                format!(
                    "max_clock_skew_secs {skew} is out of range: must be 1..=3600 seconds \
                     (0 rejects every signer with any clock drift; a larger window pins \
                     replay-nonce memory for its whole duration)"
                ),
            ));
        }
    }

    // DW-044: alert/event webhook targets.
    validate_webhooks(gateway, &mut issues);

    // DW-043: the embedded analytics store block.
    validate_analytics(gateway, &mut issues);

    // DW-050: geo rules need a database; countries must be alpha-2.
    validate_geoip(gateway, &mut issues);

    // DW-033: consumer request budgets.
    validate_quotas(gateway, &mut issues);

    // Zero-route guard (#129, maintainer decision): a route-less config is
    // schema-valid, and a truncated/torn write (truncate-then-save) lands
    // exactly here — publishing it would drop all routing mid-run. Rejected
    // unless the operator explicitly opted in for a deliberate admin-only
    // shape. Applies to cold start and hot reload alike (compile runs both).
    if gateway.routes.is_empty() && !gateway.allow_empty_routes {
        issues.push(issue(
            "gateway",
            "(root)",
            "routes",
            "routes is empty: publishing an empty route set drops all routing \
             (every request would 404), and a truncated or torn config write \
             is schema-valid here — set allow_empty_routes: true if this \
             route-less shape is deliberate",
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
        // DW-046: the retired-key grace is a bounded safety window —
        // past a week it is no longer bridging a rotation, it is
        // keeping a retired key alive on purpose.
        if let Some(grace) = p.retired_key_grace_secs {
            if grace > 604_800 {
                issues.push(issue(
                    "jwt_provider",
                    &p.name,
                    "retired_key_grace_secs",
                    format!(
                        "retired_key_grace_secs {grace} exceeds the 604800 cap \
                         (7 days): a longer window would keep a retired issuer \
                         key verifying indefinitely"
                    ),
                ));
            }
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
                    check_trusted_ca_file(
                        "jwt_provider",
                        &p.name,
                        "trusted_ca_file",
                        ca,
                        &mut issues,
                    );
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
                        // #124: a client-CA bundle turns the terminate
                        // listener into one that verifies client
                        // certificates (optional at the TLS layer, matched
                        // against mtls credentials at authn). The same
                        // compile-time PEM check as trusted_ca_file: a
                        // broken bundle would otherwise surface as a
                        // listener-build failure at startup.
                        if let Some(ca) = &t.client_ca_file {
                            check_trusted_ca_file(
                                "listener",
                                &l.name,
                                "tls.client_ca_file",
                                ca,
                                &mut issues,
                            );
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
                        // DW-030: PROXY acceptance needs the HTTP pipeline
                        // that consumes the client address (ACL, rate
                        // keys, XFF); a passthrough listener splices raw
                        // bytes and would silently ignore the knob.
                        if l.proxy_protocol {
                            issues.push(issue(
                                "listener",
                                &l.name,
                                "proxy_protocol",
                                "proxy_protocol cannot be combined with tls mode passthrough: \
                                 passthrough splices raw bytes and never runs the pipeline that \
                                 consumes the PROXY client address (use protocol http, or https \
                                 with mode terminate)",
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
                        if t.client_ca_file.is_some() {
                            issues.push(issue(
                                "listener",
                                &l.name,
                                "tls.client_ca_file",
                                "tls mode passthrough does not terminate TLS; client certificates \
                                 cannot be verified (use mode terminate)",
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
        // Route-scoped edge policies (DW-027): CORS, response
        // compression, request limits.
        if let Some(cors) = &r.cors {
            validate_cors(&r.name, cors, &mut issues);
        }
        if let Some(compression) = &r.compression {
            validate_compression(&r.name, compression, &mut issues);
        }
        if let Some(limits) = &r.limits {
            validate_request_limits(&r.name, limits, &mut issues);
        }
        if let Some(dep) = &r.deprecation {
            validate_deprecation(&r.name, dep, &mut issues);
        }
        if let Some(maintenance) = &r.maintenance {
            validate_maintenance(&r.name, maintenance, &mut issues);
        }
        // Route-scoped transforms + security headers (DW-028).
        if let Some(transforms) = &r.transforms {
            validate_transforms(&r.name, transforms, &mut issues);
        }
        if let Some(sh) = &r.security_headers {
            validate_security_headers(&r.name, sh, &mut issues);
        }
        // Response field masking (DW-029).
        if let Some(masking) = &r.masking {
            validate_masking(&r.name, masking, &consumer_groups, &mut issues);
        }
        // Response caching (DW-037).
        if let Some(cache) = &r.cache {
            validate_route_cache(&r.name, cache, &mut issues);
        }
        // Per-route method allowlist (DW-030): every entry must be a
        // valid HTTP method token (the same grammar cors.allowed_methods
        // checks) and the list must not repeat an entry case-insensitively
        // — a duplicate would only ever be an authoring artifact, and the
        // 405's Allow header echoes the list verbatim.
        {
            let mut seen_methods = std::collections::BTreeSet::new();
            for (i, m) in r.methods.iter().enumerate() {
                if m.trim().is_empty() {
                    issues.push(issue(
                        "route",
                        &r.name,
                        &format!("methods[{i}]"),
                        "method is empty or only whitespace",
                    ));
                } else if hyper::Method::from_bytes(m.as_bytes()).is_err() {
                    issues.push(issue(
                        "route",
                        &r.name,
                        &format!("methods[{i}]"),
                        format!("'{m}' is not a valid HTTP method token"),
                    ));
                } else if !seen_methods.insert(m.to_ascii_lowercase()) {
                    issues.push(issue(
                        "route",
                        &r.name,
                        &format!("methods[{i}]"),
                        format!("duplicate method '{m}' (matching is case-insensitive)"),
                    ));
                }
            }
        }
        // Per-route SLO objectives (DW-052): targets must be achievable
        // percentages, a latency target without a threshold can never
        // evaluate, and a threshold without a target would silently use
        // the default (it does — the error is only for the impossible
        // combination).
        if let Some(slo) = &r.slo {
            if !(0.0..=100.0).contains(&slo.availability) || slo.availability <= 0.0 {
                issues.push(issue(
                    "route",
                    &r.name,
                    "slo.availability",
                    format!(
                        "availability {} is out of range: a percentage in (0, 100] \
                         (100 = every request must be non-5xx)",
                        slo.availability
                    ),
                ));
            }
            if let Some(ms) = slo.latency_ms {
                if !(1.0..=600_000.0).contains(&ms) {
                    issues.push(issue(
                        "route",
                        &r.name,
                        "slo.latency_ms",
                        format!(
                            "latency_ms {ms} is out of range: 1..=600000 (the \
                             whole-request budget; nothing sensible is faster \
                             than 1 ms or slower than the 10-minute class of \
                             timeouts)"
                        ),
                    ));
                }
            }
            if let Some(t) = slo.latency_target {
                if !(0.0..=100.0).contains(&t) || t <= 0.0 {
                    issues.push(issue(
                        "route",
                        &r.name,
                        "slo.latency_target",
                        format!(
                            "latency_target {t} is out of range: a percentage in \
                             (0, 100]"
                        ),
                    ));
                }
            }
            if slo.latency_target.is_some() && slo.latency_ms.is_none() {
                issues.push(issue(
                    "route",
                    &r.name,
                    "slo.latency_target",
                    "latency_target without latency_ms: the objective has no \
                     threshold to measure against",
                ));
            }
        }
        // Media-type criterion (DW-048): the shared grammar in
        // config::versioning is the whole check — a value that is not a
        // bare type/subtype can never match and is an authoring error.
        if let Some(accept) = &r.r#match.accept {
            if crate::config::versioning::normalize_media_type(accept).is_none() {
                issues.push(issue(
                    "route",
                    &r.name,
                    "match.accept",
                    format!(
                        "'{accept}' is not a bare media type: use type/subtype like \
                         'application/vnd.acme.v2+json' (parameters and wildcards are not \
                         supported; wildcards never match a versioned route)"
                    ),
                ));
            }
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
                check_trusted_ca_file("upstream", &u.name, "trusted_ca_file", ca, &mut issues);
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
            // double-decrement). Reject at validation time. The target is
            // compared TRIMMED, exactly like the empty-address check
            // above: " 127.0.0.1" and "127.0.0.1" are the same endpoint
            // (#128, DW-011 review).
            if !seen_targets.insert((e.address.trim(), e.port)) {
                issues.push(issue(
                    "upstream",
                    &u.name,
                    &format!("endpoints[{i}].address"),
                    format!(
                        "duplicate endpoint {}/{}: address:port must be unique within an upstream",
                        e.address.trim(),
                        e.port
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
            // DW-030: 0 is LEGAL here (it disables happy-eyeballs racing
            // instead of unbounding it — the house zero-disables pattern);
            // only the upper bound applies.
            if t.happy_eyeballs_ms
                .is_some_and(|ms| ms > crate::config::limits::MAX_HAPPY_EYEBALLS_MS)
            {
                issues.push(issue(
                    "upstream",
                    &u.name,
                    "timeouts.happy_eyeballs_ms",
                    format!(
                        "happy_eyeballs_ms must be at most {} (0 disables racing)",
                        crate::config::limits::MAX_HAPPY_EYEBALLS_MS
                    ),
                ));
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

    // DW-036: hmac key ids are the SELECTOR a signed request presents;
    // a duplicate would make consumer resolution ambiguous. First
    // declarant wins the map, later ones get the issue.
    let mut hmac_key_ids: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
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
            // DW-036: cross-consumer key-id uniqueness (see the map's
            // declaration note above).
            if let Credential::Hmac { key_id, .. } = cred {
                match hmac_key_ids.get_key_value(key_id.as_str()) {
                    Some((_, other_consumer)) => {
                        issues.push(issue(
                            "consumer",
                            &c.name,
                            &field,
                            format!(
                                "hmac key_id '{key_id}' is already declared by consumer \
                                 '{other_consumer}' (key ids select the credential a signed \
                                 request presents; they must be unique)"
                            ),
                        ));
                    }
                    None => {
                        hmac_key_ids.insert(key_id.as_str(), c.name.as_str());
                    }
                }
            }
            let problem = match cred {
                Credential::ApiKey { key } if key.is_empty() => {
                    Some("api key is empty".to_string())
                }
                // DW-045: an api key may be a ${...} reference. Resolve it
                // NOW (config-compile time) so an unresolvable secret fails
                // the generation closed — the same contract as
                // trusted_ca_file. Reference-shaped but malformed values
                // fail equally: treating a typo'd reference as a literal
                // key would silently install garbage bytes as the key.
                // Messages name the reference, never a resolved value.
                Credential::ApiKey { key } => {
                    match crate::config::credentials::parse_secret_reference(key) {
                        None => None,
                        Some(Ok(reference)) => reference.resolve().err(),
                        Some(Err(malformed)) => Some(malformed),
                    }
                }
                // DW-036: an hmac signing credential. The key id is the
                // PRESENTED selector (a header value), so it must be
                // representable: non-empty visible ASCII, bounded length.
                // The secret follows the same reference contract as api
                // keys (resolve at compile time, fail closed naming the
                // reference). Duplicate key ids across ALL consumers are
                // rejected inside the loop below (an ambiguous selector
                // cannot pick a consumer deterministically).
                Credential::Hmac { key_id, secret } => {
                    if key_id.is_empty() {
                        Some("hmac key_id is empty".to_string())
                    } else if !key_id.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
                        Some(
                            "hmac key_id must be visible ASCII (0x21-0x7E): it is presented \
                             as the X-Dwara-Key-Id header value"
                                .to_string(),
                        )
                    } else if key_id.len() > 128 {
                        Some("hmac key_id is longer than 128 bytes".to_string())
                    } else if secret.is_empty() {
                        Some("hmac secret is empty".to_string())
                    } else {
                        match crate::config::credentials::parse_secret_reference(secret) {
                            None => None,
                            Some(Ok(reference)) => reference.resolve().err(),
                            Some(Err(malformed)) => Some(malformed),
                        }
                    }
                }
                Credential::Jwt { issuer, .. } if issuer.is_empty() => {
                    Some("jwt issuer is empty".to_string())
                }
                // #124: an mtls credential matches a verified client
                // certificate by subject CN or by fingerprint — exactly
                // one of the two must carry a non-empty value. Both-set
                // is rejected because only the subject would ever be
                // matched (the fingerprint would sit inert).
                Credential::Mtls {
                    subject,
                    fingerprint,
                } => {
                    let s = subject.as_deref().unwrap_or("");
                    let f = fingerprint.as_deref().unwrap_or("");
                    if s.is_empty() && f.is_empty() {
                        Some(
                            "mtls credential must set subject or fingerprint (both are empty)"
                                .to_string(),
                        )
                    } else if subject.is_some() && s.is_empty() {
                        Some("mtls subject is empty".to_string())
                    } else if fingerprint.is_some() && f.is_empty() {
                        Some("mtls fingerprint is empty".to_string())
                    } else if subject.is_some() && fingerprint.is_some() {
                        Some(
                            "mtls credential must set subject or fingerprint, not both \
                             (both are set; only the subject would be matched)"
                                .to_string(),
                        )
                    } else {
                        None
                    }
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
    /// Precompiled CORS origin matcher per route index (DW-027): `None`
    /// where the route carries no `cors` block, mirroring
    /// `Route::cors` exactly so the proxy's config read and matcher
    /// lookup stay in lockstep.
    cors_origins: Vec<Option<crate::config::CompiledCorsOrigins>>,
    /// Precompiled compression content-type filter per route index
    /// (DW-027), mirroring `Route::compression` the same way.
    compression_types: Vec<Option<crate::config::CompiledContentTypeFilter>>,
    /// Precompiled deprecation header values per route index (DW-048),
    /// mirroring `Route::deprecation` the same way: HTTP-dates are
    /// parsed once here, never per response.
    deprecations: Vec<Option<crate::config::CompiledDeprecation>>,
    /// Normalized `match.accept` media type per route index (DW-048),
    /// mirroring `Route::r#match.accept` exactly (`None` = no
    /// criterion). Normalizing here — trim + lowercase via the shared
    /// `config::versioning` grammar — keeps the raw config string out
    /// of the request path, so a padded or mixed-case spelling matches
    /// exactly like its canonical form. Validation guarantees every
    /// configured value normalizes; a `None` for a configured one is
    /// the same unreachable-skip contract as the compilations above
    /// (`compile` has already run validation by then).
    accept_media_types: Vec<Option<String>>,
    /// Precompiled request JSON body transforms per route index
    /// (DW-028), mirroring `routes[idx].transforms.request.body.json`
    /// exactly: pointers parsed once here, never per request. Header
    /// and query ops carry no parseable grammar (names are checked by
    /// validation and applied verbatim), so they deliberately have no
    /// compiled form — only the JSON pointers need precompute.
    request_body_ops: Vec<Option<crate::config::transforms::CompiledJsonTransform>>,
    /// Precompiled response JSON body transforms per route index
    /// (DW-028), same mirroring as `request_body_ops`.
    response_body_ops: Vec<Option<crate::config::transforms::CompiledJsonTransform>>,
    /// Precompiled response field masking policies per route index
    /// (DW-029), mirroring `routes[idx].masking`: pointers parsed once
    /// here; the per-request union with the consumer's groups is
    /// resolved at apply time (group membership is per-request state).
    masking: Vec<Option<crate::config::transforms::CompiledMasking>>,
    /// Precompiled response-cache policies per route index (DW-037),
    /// mirroring `routes[idx].cache` with the policy-derived vary folds
    /// (`match.accept` -> `Accept`, `cors` -> `Origin`) resolved once.
    caches: Vec<Option<std::sync::Arc<crate::config::cache::CompiledRouteCache>>>,
}

impl RouteTable {
    fn empty() -> Self {
        RouteTable {
            exact: matchit::Router::new(),
            prefixes: Vec::new(),
            regex_set: regex::RegexSet::empty(),
            regex_indices: Vec::new(),
            rewrite_regexes: Vec::new(),
            cors_origins: Vec::new(),
            compression_types: Vec::new(),
            deprecations: Vec::new(),
            accept_media_types: Vec::new(),
            request_body_ops: Vec::new(),
            response_body_ops: Vec::new(),
            masking: Vec::new(),
            caches: Vec::new(),
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

    /// The precompiled CORS origin matcher for route `idx` (`None`: the
    /// route carries no `cors` block — exactly mirroring
    /// `gateway().routes[idx].cors`).
    pub fn cors_origins(&self, idx: usize) -> Option<&crate::config::CompiledCorsOrigins> {
        self.cors_origins.get(idx).and_then(|o| o.as_ref())
    }

    /// The precompiled compression content-type filter for route `idx`
    /// (`None`: the route carries no `compression` block — exactly
    /// mirroring `gateway().routes[idx].compression`).
    pub fn compression_types(
        &self,
        idx: usize,
    ) -> Option<&crate::config::CompiledContentTypeFilter> {
        self.compression_types.get(idx).and_then(|t| t.as_ref())
    }

    /// The precompiled deprecation header values for route `idx` (`None`:
    /// the route carries no `deprecation` block — exactly mirroring
    /// `gateway().routes[idx].deprecation`).
    pub fn deprecation(&self, idx: usize) -> Option<&crate::config::CompiledDeprecation> {
        self.deprecations.get(idx).and_then(|d| d.as_ref())
    }

    /// The normalized `match.accept` media type for route `idx` (`None`:
    /// the route carries no accept criterion — exactly mirroring
    /// `gateway().routes[idx].r#match.accept`). This is the comparison
    /// key the proxy's Accept criterion must use, never the raw config
    /// string.
    pub fn accept_media_type(&self, idx: usize) -> Option<&str> {
        self.accept_media_types.get(idx).and_then(|a| a.as_deref())
    }

    /// The precompiled REQUEST JSON body transform for route `idx`
    /// (`None`: the route transforms no request bodies — exactly
    /// mirroring `gateway().routes[idx].transforms.request.body`).
    pub fn request_body_ops(
        &self,
        idx: usize,
    ) -> Option<&crate::config::transforms::CompiledJsonTransform> {
        self.request_body_ops.get(idx).and_then(|t| t.as_ref())
    }

    /// The precompiled RESPONSE JSON body transform for route `idx`
    /// (`None`: the route transforms no response bodies — exactly
    /// mirroring `gateway().routes[idx].transforms.response.body`).
    pub fn response_body_ops(
        &self,
        idx: usize,
    ) -> Option<&crate::config::transforms::CompiledJsonTransform> {
        self.response_body_ops.get(idx).and_then(|t| t.as_ref())
    }

    /// The precompiled response field masking policy for route `idx`
    /// (`None`: the route masks nothing — exactly mirroring
    /// `gateway().routes[idx].masking`).
    pub fn masking(&self, idx: usize) -> Option<&crate::config::transforms::CompiledMasking> {
        self.masking.get(idx).and_then(|m| m.as_ref())
    }

    /// The precompiled response-cache policy for route `idx` (`None`:
    /// the route's responses are never cached — exactly mirroring
    /// `gateway().routes[idx].cache`, with the policy-derived vary
    /// folds already resolved).
    pub fn cache(
        &self,
        idx: usize,
    ) -> Option<&std::sync::Arc<crate::config::cache::CompiledRouteCache>> {
        self.caches.get(idx).and_then(|c| c.as_ref())
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
                load_shed_dry_run: false,
                jwt_providers: Vec::new(),
                admin: None,
                allow_empty_routes: false,
                hmac_auth: None,
                webhooks: Vec::new(),
                analytics: None,
                geoip: None,
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

/// The single hashing step behind both the whole-gateway content hash
/// in [`compile`] and the per-entity [`entity_content_hash`]: a
/// `DefaultHasher` (SipHash-1-3) over a normalized YAML serialization.
fn normalized_hash(yaml: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    yaml.hash(&mut hasher);
    hasher.finish()
}

/// Per-entity content hash: the entity's normalized YAML serialization
/// (stable field order, defaulted-empty fields omitted — the same
/// normalization `gateway_to_yaml` applies to a whole [`Gateway`])
/// through the same `DefaultHasher` as the snapshot content hash. Two
/// entities of one kind hash equal exactly when their normalized
/// serializations are equal, so source key order and omitted defaults
/// do not affect the result. Same caveats as
/// [`SnapshotInfo::content_hash`]: a per-process change-detection
/// token, not stable across Rust versions, not a content digest.
pub fn entity_content_hash<T: serde::Serialize>(entity: &T) -> Result<u64, String> {
    let yaml =
        serde_yaml_ng::to_string(entity).map_err(|e| format!("normalization failed: {e}"))?;
    Ok(normalized_hash(&yaml))
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
    let content_hash = normalized_hash(&yaml);

    // DW-027 edge-policy matching state, precompiled per route index in
    // lockstep with `Route::cors` / `Route::compression` (built from the
    // same route list, so lookups mirror the config the proxy reads):
    // normalized CORS origins and lowercased content-type prefixes are
    // computed once here instead of on every request.
    let cors_origins = gateway
        .routes
        .iter()
        .map(|r| {
            r.cors
                .as_ref()
                .map(crate::config::CompiledCorsOrigins::compile)
        })
        .collect();
    let compression_types = gateway
        .routes
        .iter()
        .map(|r| {
            r.compression
                .as_ref()
                .map(crate::config::CompiledContentTypeFilter::compile)
        })
        .collect();
    // DW-048: the deprecation header values, parsed from their config
    // HTTP-dates once here (validation guarantees they parse; the
    // filter_map fallback documents the same unreachable-skip contract
    // as the CORS/compression compilations above).
    let deprecations = gateway
        .routes
        .iter()
        .map(|r| {
            r.deprecation
                .as_ref()
                .map(crate::config::CompiledDeprecation::compile)
        })
        .collect();
    // DW-048: the accept criterion's comparison key, normalized once
    // here instead of on every request — validation guarantees every
    // configured value normalizes, so the None fallback is unreachable
    // (the same skip contract as the compilations above). Without this
    // the raw config string reached the hot path, and a padded
    // `match.accept` published cleanly only to 404 every request.
    let accept_media_types = gateway
        .routes
        .iter()
        .map(|r| {
            r.r#match
                .accept
                .as_deref()
                .and_then(crate::config::versioning::normalize_media_type)
        })
        .collect();
    // DW-028: the JSON body transforms' pointers, parsed once here
    // (validation guarantees they parse; the same unreachable-skip
    // contract as the compilations above). Header and query ops have
    // no parseable grammar and deliberately ride the config value.
    let request_body_ops = gateway
        .routes
        .iter()
        .map(|r| {
            r.transforms
                .as_ref()
                .and_then(|t| t.request.as_ref())
                .and_then(|req| req.body.as_ref())
                .map(|b| crate::config::transforms::CompiledJsonTransform::compile(&b.json))
        })
        .collect();
    let response_body_ops = gateway
        .routes
        .iter()
        .map(|r| {
            r.transforms
                .as_ref()
                .and_then(|t| t.response.as_ref())
                .and_then(|resp| resp.body.as_ref())
                .map(|b| crate::config::transforms::CompiledJsonTransform::compile(&b.json))
        })
        .collect();
    // DW-029: masking pointers, parsed once here (validation guarantees
    // they parse; the same unreachable-skip contract). Group membership
    // varies per request, so the union resolves at apply time.
    let masking = gateway
        .routes
        .iter()
        .map(|r| {
            r.masking
                .as_ref()
                .map(crate::config::transforms::CompiledMasking::compile)
        })
        .collect();
    // DW-037: compiled cache policies, including the policy-derived
    // vary folds (`match.accept` -> Accept, `cors` -> Origin) resolved
    // once here so the request path never re-derives the vary set.
    let caches = gateway
        .routes
        .iter()
        .map(|r| {
            r.cache.as_ref().map(|c| {
                std::sync::Arc::new(crate::config::cache::CompiledRouteCache::compile(
                    c,
                    r.r#match.accept.is_some(),
                    r.cors.is_some(),
                ))
            })
        })
        .collect();

    Ok(Compiled {
        gateway: Arc::new(gateway.clone()),
        routes: Arc::new(RouteTable {
            exact,
            prefixes,
            regex_set,
            regex_indices,
            rewrite_regexes,
            cors_origins,
            compression_types,
            deprecations,
            accept_media_types,
            request_body_ops,
            response_body_ops,
            masking,
            caches,
        }),
        content_hash,
    })
}

/// Holds the currently published [`Snapshot`] behind an `ArcSwap` and owns
/// the monotonic generation counter. Shared across the dataplane (read) and
/// the config source / hot reload (write, DW-006). May carry the process's
/// [`crate::events::EventBus`] (DW-044): every publish outcome emits one event
/// (`config_published` / `config_rejected`) onto it, which is why the bus
/// sits in a domain BELOW this one.
pub struct ConfigState {
    snapshot: ArcSwap<Snapshot>,
    generation: AtomicU64,
    /// Serializes publish attempts so generation ids stay gap-free and
    /// monotonic under concurrent writers.
    publish_lock: Mutex<()>,
    /// The event bus publish outcomes emit onto (DW-044). Attached at
    /// construction ([`ConfigState::with_event_bus`]) or by the dataplane
    /// ([`ConfigState::attach_event_bus`], first attach wins). Interior
    /// mutability because the bus is created before/independently of the
    /// state in some wiring orders (the binary creates both up front; a
    /// bare `ConfigState::new` gets one when a `DataPlane` is built from
    /// it, so config events are never silently missing in a live
    /// gateway).
    events: std::sync::RwLock<Option<Arc<crate::events::EventBus>>>,
}

impl Default for ConfigState {
    fn default() -> Self {
        ConfigState {
            snapshot: ArcSwap::from_pointee(Snapshot::empty()),
            generation: AtomicU64::new(0),
            publish_lock: Mutex::new(()),
            events: std::sync::RwLock::new(None),
        }
    }
}

impl ConfigState {
    pub fn new() -> Self {
        Self::default()
    }

    /// New state with its event bus attached from the start (DW-044):
    /// the binary's wiring, so the very first (startup) publish already
    /// emits onto the bus the deliverer will drain.
    pub fn with_event_bus(bus: Arc<crate::events::EventBus>) -> Self {
        let state = Self::default();
        state.attach_event_bus(bus);
        state
    }

    /// Attach the event bus if none is attached yet (first attach wins;
    /// a live bus is never swapped underneath an emitter). Idempotent.
    pub fn attach_event_bus(&self, bus: Arc<crate::events::EventBus>) {
        let mut slot = self.events.write().expect("event bus slot poisoned");
        if slot.is_none() {
            *slot = Some(bus);
        }
    }

    /// The attached event bus, if any (the dataplane adopts/creates it).
    pub fn event_bus(&self) -> Option<Arc<crate::events::EventBus>> {
        self.events.read().expect("event bus slot poisoned").clone()
    }

    /// The emitter for publish outcomes (a no-op handle when no bus is
    /// attached — `None` at the call site keeps emission optional in
    /// unwired constructions).
    fn event_emitter(&self) -> Option<crate::events::Emitter> {
        self.event_bus().map(|bus| bus.emitter())
    }

    /// Currently published snapshot (load is lock-free).
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.snapshot.load_full()
    }

    /// Validate, compile, and atomically publish. On ANY failure the
    /// currently-published snapshot is untouched (rollback = not-published);
    /// the generation counter is only advanced on success.
    ///
    /// DW-044: emits `config_published` (generation, content hash, route
    /// count) on success and `config_rejected` (issue count, plus the
    /// generation still running) on failure — every publish path (cold
    /// start, hot reload, admin POST) funnels through here, so one
    /// emission site covers them all. Emission is the bus's bounded
    /// non-blocking hand-off; a full queue drops and counts.
    pub fn compile_and_publish(&self, gateway: &Gateway) -> Result<SnapshotInfo, CompileError> {
        let _guard = self.publish_lock.lock().unwrap_or_else(|p| p.into_inner());
        let emitter = self.event_emitter();
        let compiled = match compile(gateway) {
            Ok(compiled) => compiled,
            Err(err) => {
                if let Some(emitter) = &emitter {
                    let issue_count = match &err {
                        CompileError::Validation(issues) => issues.len(),
                        // A compile-stage failure (regex, route conflict)
                        // is one named problem; its Display carries it.
                        _ => 1,
                    };
                    emitter.emit(
                        crate::events::EventKind::ConfigRejected,
                        crate::events::EventPayload {
                            issue_count: Some(issue_count),
                            generation: Some(self.snapshot.load().generation),
                            ..crate::events::EventPayload::default()
                        },
                    );
                }
                return Err(err);
            }
        };
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
        if let Some(emitter) = &emitter {
            emitter.emit(
                crate::events::EventKind::ConfigPublished,
                crate::events::EventPayload {
                    generation: Some(info.generation),
                    content_hash: Some(info.content_hash),
                    route_count: Some(info.route_count),
                    ..crate::events::EventPayload::default()
                },
            );
        }
        Ok(info)
    }
}
