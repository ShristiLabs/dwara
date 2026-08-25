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

use std::collections::BTreeSet;

use dwara_core::config::{gateway_to_yaml, parse_gateway, Gateway, PathMatchKind};
use dwara_core::snapshot::{compile, validate};

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
/// plain text (`+ kind name` / `- kind name`). Returns Err when either
/// side is invalid (a diff against a broken config is meaningless).
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
    let mut out = String::new();
    let mut deltas = 0usize;
    for (label, a_names, b_names) in [
        (
            "route",
            a.routes.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            b.routes.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
        ),
        (
            "upstream",
            a.upstreams
                .iter()
                .map(|u| u.name.as_str())
                .collect::<Vec<_>>(),
            b.upstreams
                .iter()
                .map(|u| u.name.as_str())
                .collect::<Vec<_>>(),
        ),
        (
            "consumer",
            a.consumers
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>(),
            b.consumers
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>(),
        ),
    ] {
        let sa: BTreeSet<&str> = a_names.into_iter().collect();
        let sb: BTreeSet<&str> = b_names.into_iter().collect();
        for added in sb.difference(&sa) {
            out.push_str(&format!("+ {label} {added}\n"));
            deltas += 1;
        }
        for removed in sa.difference(&sb) {
            out.push_str(&format!("- {label} {removed}\n"));
            deltas += 1;
        }
    }
    if deltas == 0 {
        out.push_str("no route/upstream/consumer differences\n");
    }
    Ok(out)
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
/// - `consumer-unused`: no route authorization (allowed/denied lists)
///   and no JWT provider binds the consumer. Static over-approximation:
///   a consumer can also be used purely by presenting credentials at
///   runtime, so this is advisory, not an error.
/// - `policy-unused`: the policy is attached to no route, service, or
///   consumer.
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

    // consumer-unused: referenced by no authorization rule and bound to
    // no JWT provider.
    let mut consumers_used: BTreeSet<&str> = BTreeSet::new();
    for route in &gateway.routes {
        if let Some(authz) = &route.authorization {
            for c in authz
                .allowed_consumers
                .iter()
                .chain(&authz.denied_consumers)
            {
                consumers_used.insert(c);
            }
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
                    "unused: referenced by no route authorization and bound to no jwt provider \
                          (advisory: runtime credential use is not statically visible)"
                        .to_string(),
            });
        }
    }

    // policy-unused.
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
    for p in &gateway.policies {
        if !policies_used.contains(p.name.as_str()) {
            warnings.push(LintWarning {
                kind: "policy",
                name: p.name.clone(),
                message: "unused: attached to no route, service, or consumer".to_string(),
            });
        }
    }

    // upstream-unreferenced.
    for u in &gateway.upstreams {
        if !gateway.services.iter().any(|s| s.upstream == u.name) {
            warnings.push(LintWarning {
                kind: "upstream",
                name: u.name.clone(),
                message: "unreferenced: no service targets this upstream".to_string(),
            });
        }
    }

    warnings
}
