//! Operator CLI logic (DW-022, decision 6): the pure halves of the
//! `dwara-cli` subcommands, kept library-shaped so tests (and future
//! callers) exercise exactly what the binary runs.
//!
//! Exit-code contract (documented, load-bearing):
//!
//! - `validate`: 0 = valid config; 1 = ANY schema/parse/validation/
//!   compile issue (all issues are printed, never fail-fast).
//! - `lint`: 0 = no advisory warnings; 2 = warnings found; 1 = the file
//!   could not be parsed/validated at all (fix that first — linting an
//!   invalid config would report noise). The distinct 2 keeps "your
//!   config is wrong" and "your config compiles but smells" separable
//!   in scripts.
//!
//! Lint rules are ADVISORY findings beyond validation (see
//! [`lint_config`]): they flag config that compiles and routes traffic
//! but likely does not do what the author meant.
//!
//! The [`loadgen`] module holds the DW-024 macro load-generator rig
//! (public for reuse and testing; the `dwara-loadgen` binary is a thin
//! wrapper over it).

use std::collections::{BTreeMap, BTreeSet};

pub mod import;
// DW-065: NGINX config import (migration lever).
pub mod import_nginx;
pub mod loadgen;
// DW-057: Plugin scaffolding (`dwara plugin new`).
pub mod plugin_scaffold;

use dwara_core::config::{gateway_to_yaml, parse_gateway, Gateway, PathMatchKind};
use dwara_core::snapshot::{compile, entity_content_hash, validate};

/// Result of validating a config document end to end.
pub enum ValidateOutcome {
    /// Parsed, validated, compiled; carries the route count.
    Valid { routes: usize },
    /// Every problem found (parse error, validation issues, compile
    /// errors), human-formatted one per line.
    Invalid(Vec<String>),
}

/// Parse + validate + compile-dry-run a config document. This is the
/// same pipeline the gateway runs at startup and reload.
pub fn validate_config_text(text: &str) -> ValidateOutcome {
    let gateway = match parse_gateway(text) {
        Ok(g) => g,
        Err(err) => return ValidateOutcome::Invalid(vec![format!("parse failed: {err}")]),
    };
    let issues = validate(&gateway);
    if !issues.is_empty() {
        return ValidateOutcome::Invalid(
            issues
                .iter()
                .map(|i| format!("config error: {i}"))
                .collect(),
        );
    }
    match compile(&gateway) {
        Ok(_) => ValidateOutcome::Valid {
            routes: gateway.routes.len(),
        },
        Err(err) => ValidateOutcome::Invalid(vec![format!("{err}")]),
    }
}

/// Normalize a config document: parse, then re-serialize with
/// `gateway_to_yaml` (stable field order, defaulted-empty collections
/// omitted). Round-trip guarantee: the output parses back to the same
/// typed value.
pub fn format_config_text(text: &str) -> Result<String, String> {
    let gateway = parse_gateway(text).map_err(|e| format!("parse failed: {e}"))?;
    gateway_to_yaml(&gateway).map_err(|e| format!("serialize failed: {e}"))
}

/// Compile both documents and report route/upstream/consumer deltas as
/// plain text: `+ kind name` (added), `- kind name` (removed), and
/// `~ kind name` (present in both sides under the same name but with
/// different content — changed endpoints, timeouts, credentials, ...
/// detected by comparing per-entity content hashes of the normalized
/// serialization, so source key order never shows up as a change).
/// Returns Err when either side is invalid (a diff against a broken
/// config is meaningless).
pub fn diff_configs(a_text: &str, b_text: &str) -> Result<String, String> {
    let parse = |t| parse_gateway(t).map_err(|e| format!("parse failed: {e}"));
    let a = parse(a_text)?;
    let b = parse(b_text)?;
    for (side, gw) in [("a", &a), ("b", &b)] {
        let issues = validate(gw);
        if !issues.is_empty() {
            let mut m = vec![format!("config {side} is invalid:")];
            m.extend(issues.iter().map(|i| format!("  {i}")));
            return Err(m.join("\n"));
        }
    }
    // Name -> per-entity content hash, per kind. Validation has run, so
    // names are unique within each kind and keying is safe.
    let mut out = String::new();
    let mut deltas = 0usize;
    for (label, ha, hb) in [
        (
            "route",
            hash_by_name(
                a.routes
                    .iter()
                    .map(|r| (r.name.as_str(), entity_content_hash(r))),
            )?,
            hash_by_name(
                b.routes
                    .iter()
                    .map(|r| (r.name.as_str(), entity_content_hash(r))),
            )?,
        ),
        (
            "upstream",
            hash_by_name(
                a.upstreams
                    .iter()
                    .map(|u| (u.name.as_str(), entity_content_hash(u))),
            )?,
            hash_by_name(
                b.upstreams
                    .iter()
                    .map(|u| (u.name.as_str(), entity_content_hash(u))),
            )?,
        ),
        (
            "consumer",
            hash_by_name(
                a.consumers
                    .iter()
                    .map(|c| (c.name.as_str(), entity_content_hash(c))),
            )?,
            hash_by_name(
                b.consumers
                    .iter()
                    .map(|c| (c.name.as_str(), entity_content_hash(c))),
            )?,
        ),
    ] {
        let names_a: BTreeSet<&str> = ha.keys().copied().collect();
        let names_b: BTreeSet<&str> = hb.keys().copied().collect();
        for added in names_b.difference(&names_a) {
            out.push_str(&format!("+ {label} {added}\n"));
            deltas += 1;
        }
        for removed in names_a.difference(&names_b) {
            out.push_str(&format!("- {label} {removed}\n"));
            deltas += 1;
        }
        // Same name on both sides: report it only when the content
        // differs (the defect this fixes — name-set comparison alone
        // silently passed same-name changes).
        for changed in names_a.intersection(&names_b) {
            if ha[changed] != hb[changed] {
                out.push_str(&format!("~ {label} {changed}\n"));
                deltas += 1;
            }
        }
    }
    if deltas == 0 {
        out.push_str("no route/upstream/consumer differences\n");
    }
    Ok(out)
}

/// Collect one entity kind's `(name, content hash)` pairs into a map,
/// propagating any serialization failure.
fn hash_by_name<'a>(
    pairs: impl Iterator<Item = (&'a str, Result<u64, String>)>,
) -> Result<BTreeMap<&'a str, u64>, String> {
    pairs.map(|(name, hash)| hash.map(|h| (name, h))).collect()
}

/// One advisory lint finding: `kind/name: message`.
pub struct LintWarning {
    pub kind: &'static str,
    pub name: String,
    pub message: String,
}

impl std::fmt::Display for LintWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}: {}", self.kind, self.name, self.message)
    }
}

/// Advisory lint rules BEYOND validation (a lint-clean config still
/// validates; these findings are about intent, not correctness):
///
/// - `prefix-duplicate`: two prefix routes with the identical pattern;
///   the earlier-declared one wins the equal-length tie, so the later
///   route can never match (validation does not see this — longest
///   prefix ties are resolved silently at lookup time).
/// - `regex-shadowed-by-exact`: an exact route whose path fully matches
///   a regex route's pattern; that path is always served by the exact
///   route (lookup precedence), so the regex can never see it.
/// - `consumer-unused`: no authorization rule at any level (allowed/
///   denied lists) and no JWT provider binds the consumer. Static
///   over-approximation: a consumer can also be used purely by
///   presenting credentials at runtime, so this is advisory, not an
///   error.
/// - `policy-unused`: the policy is attached to no consumer, route,
///   service, listener, or gateway (global).
/// - `upstream-unreferenced`: no service targets the upstream.
///
/// Listener port duplication across listeners is deliberately NOT a
/// lint rule — validation already rejects conflicting binds.
pub fn lint_config(gateway: &Gateway) -> Vec<LintWarning> {
    let mut warnings = Vec::new();

    // prefix-duplicate: equal-length ties resolve to the FIRST declared
    // prefix route, so later duplicates are dead config.
    let mut seen_prefixes: BTreeSet<&str> = BTreeSet::new();
    for route in &gateway.routes {
        if route.r#match.path.kind == PathMatchKind::Prefix
            && !seen_prefixes.insert(&route.r#match.path.value)
        {
            warnings.push(LintWarning {
                kind: "route",
                name: route.name.clone(),
                message: format!(
                    "duplicate prefix pattern '{}' (an earlier prefix route wins equal-length ties; this route never matches)",
                    route.r#match.path.value
                ),
            });
        }
    }

    // regex-shadowed-by-exact: exact lookup happens first.
    for route in &gateway.routes {
        let path = &route.r#match.path;
        if path.kind != PathMatchKind::Regex {
            continue;
        }
        let Ok(re) = regex::Regex::new(&path.value) else {
            // Invalid regex is a validation/compile failure, not lint.
            continue;
        };
        let shadowed_by = gateway
            .routes
            .iter()
            .find(|other| {
                other.r#match.path.kind == PathMatchKind::Exact
                    && re.is_match_at(&other.r#match.path.value, 0)
                    && re
                        .find_at(&other.r#match.path.value, 0)
                        .is_some_and(|m| m.end() == other.r#match.path.value.len())
            })
            .map(|other| other.name.clone());
        if let Some(exact) = shadowed_by {
            warnings.push(LintWarning {
                kind: "route",
                name: route.name.clone(),
                message: format!(
                    "regex '{}' is shadowed for path(s) it matches by exact route '{exact}' \
                     (exact lookup wins); those paths never reach this route",
                    path.value
                ),
            });
        }
    }

    // consumer-unused: referenced by no authorization rule (at ANY
    // attachment level — route, service, listener, gateway, or another
    // consumer's block) and bound to no JWT provider.
    let mut consumers_used: BTreeSet<&str> = BTreeSet::new();
    let mut authz_blocks: Vec<&dwara_core::config::Authz> = Vec::new();
    for route in &gateway.routes {
        if let Some(a) = &route.authorization {
            authz_blocks.push(a);
        }
    }
    for s in &gateway.services {
        if let Some(a) = &s.authorization {
            authz_blocks.push(a);
        }
    }
    for l in &gateway.listeners {
        if let Some(a) = &l.authorization {
            authz_blocks.push(a);
        }
    }
    if let Some(a) = &gateway.authorization {
        authz_blocks.push(a);
    }
    for c in &gateway.consumers {
        if let Some(a) = &c.authorization {
            authz_blocks.push(a);
        }
    }
    for authz in authz_blocks {
        for c in authz
            .allowed_consumers
            .iter()
            .chain(&authz.denied_consumers)
        {
            consumers_used.insert(c);
        }
    }
    for p in &gateway.jwt_providers {
        if let Some(c) = &p.consumer {
            consumers_used.insert(c);
        }
    }
    for c in &gateway.consumers {
        if !consumers_used.contains(c.name.as_str()) {
            warnings.push(LintWarning {
                kind: "consumer",
                name: c.name.clone(),
                message:
                    "unused: referenced by no authorization rule and bound to no jwt provider \
                          (advisory: runtime credential use is not statically visible)"
                        .to_string(),
            });
        }
    }

    // policy-unused (#123: every attachment level counts — consumer,
    // route, service, listener, and gateway/global).
    let mut policies_used: BTreeSet<&str> = BTreeSet::new();
    for r in &gateway.routes {
        policies_used.extend(r.policies.iter().map(String::as_str));
    }
    for s in &gateway.services {
        policies_used.extend(s.policies.iter().map(String::as_str));
    }
    for c in &gateway.consumers {
        policies_used.extend(c.policies.iter().map(String::as_str));
    }
    for l in &gateway.listeners {
        policies_used.extend(l.policies.iter().map(String::as_str));
    }
    policies_used.extend(gateway.global_policies.iter().map(String::as_str));
    for p in &gateway.policies {
        if !policies_used.contains(p.name.as_str()) {
            warnings.push(LintWarning {
                kind: "policy",
                name: p.name.clone(),
                message: "unused: attached to no consumer, route, service, listener, or \
                          gateway"
                    .to_string(),
            });
        }
    }

    // upstream-unreferenced (DW-040: a split target counts as a
    // reference too).
    for u in &gateway.upstreams {
        let referenced = gateway.services.iter().any(|s| {
            s.upstream.as_deref() == Some(u.name.as_str())
                || s.split
                    .as_ref()
                    .is_some_and(|sp| sp.targets.iter().any(|t| t.upstream == u.name))
        });
        if !referenced {
            warnings.push(LintWarning {
                kind: "upstream",
                name: u.name.clone(),
                message: "unreferenced: no service targets this upstream".to_string(),
            });
        }
    }

    warnings
}
