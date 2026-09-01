//! AI model governance (DW-084): per-team model allowlists and the
//! shadow-audit switch.
//!
//! A team is a POLICY name (the same vocabulary the token budgets use
//! for `scope: policy`): every consumer attaching a policy that
//! carries an allowlist entry is restricted to that allowlist's
//! client-facing model aliases. The check runs BEFORE routing, against
//! the alias the client put in the request body, so a disallowed (or
//! typo'd) alias is blocked at the edge with a 403
//! `model_denied_by_policy` rather than surfacing as a provider 404.
//!
//! # Resolution (deny-wins intersection)
//!
//! The binding allowlists for one request are EVERY policy in the
//! frozen precedence chain (consumer > route > service > listener >
//! global) that has a `team_allowlists` entry. The model must be in
//! ALL of them — the intersection, deny-anywhere-wins (the same
//! principle as authz). A consumer with no binding allowlist policy
//! is unrestricted (fail-open, the DW-017 default posture).
//!
//! # Audit
//!
//! When `ai.governance.audit` is true, BOTH allowed and denied
//! attempts are recorded into the `ai_governance_events` analytics
//! table for shadow review (the admin `/analytics/governance-audit`
//! endpoint reads it). When false, only the denial metric fires — no
//! per-event audit rows. Denied requests are ALWAYS audited when the
//! governance block is present (the done-when requirement: a blocked
//! attempt appears in the audit log); the `audit` flag extends
//! recording to ALLOWED calls for spend-by-team shadow review.
//!
//! # Dependency direction
//!
//! `ai` depends on `config` only (see `scripts/check_deps.py`); this
//! module reads `config::ai::AiConfig` and nothing else. The audit
//! RECORD DTO lives in `analytics` (a plain struct, not importing
//! `ai`) — the dataplane converts at the call site, keeping the
//! dependency direction downward.

use crate::config::ai::AiConfig;
use std::collections::{BTreeMap, BTreeSet};

/// The per-generation compiled governance rules (DW-084): the
/// team_allowlists map plus the audit switch. Built at dataplane
/// refresh from the published config; immutable once built. Stored on
/// the dataplane behind an ArcSwap and swapped on reload, so a
/// governance change applies to the next request with no restart.
#[derive(Debug, Clone, Default)]
pub struct GovernanceEngine {
    /// Policy name -> its allowed model aliases (config-declared).
    allowlists: BTreeMap<String, BTreeSet<String>>,
    /// Whether to record allowed calls too (shadow audit).
    audit: bool,
}

/// The governance check verdict for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceVerdict {
    /// The model alias is allowed (or no binding allowlist governs
    /// the request — fail-open).
    Allow,
    /// The model alias is denied by a binding allowlist. `reason` is
    /// the human-readable denial cause (the metric label and the audit
    /// row's reason column).
    Deny {
        /// The denying policy (team) name — the FIRST binding
        /// allowlist that did not contain the alias (deny-wins walks
        /// the chain in precedence order).
        policy: String,
        /// A short reason string (the metric label value).
        reason: String,
    },
}

impl GovernanceVerdict {
    /// Whether this is a denial.
    pub fn is_deny(&self) -> bool {
        matches!(self, GovernanceVerdict::Deny { .. })
    }

    /// The reason label for the denial metric (empty for an allow).
    pub fn reason_label(&self) -> &str {
        match self {
            GovernanceVerdict::Allow => "",
            GovernanceVerdict::Deny { reason, .. } => reason,
        }
    }
}

impl GovernanceEngine {
    /// Compile from the `ai:` config block's governance map. Absent
    /// or empty governance yields an empty engine (no allowlists ->
    /// every consumer is unrestricted, fail-open).
    pub fn compile(cfg: Option<&AiConfig>) -> Self {
        let Some(cfg) = cfg else {
            return GovernanceEngine::default();
        };
        let Some(gov) = &cfg.governance else {
            return GovernanceEngine::default();
        };
        let allowlists = gov
            .team_allowlists
            .iter()
            .map(|(policy, models)| {
                (
                    policy.clone(),
                    models.iter().cloned().collect::<BTreeSet<String>>(),
                )
            })
            .collect();
        GovernanceEngine {
            allowlists,
            audit: gov.audit,
        }
    }

    /// Whether the engine carries any allowlists (cheap dataplane
    /// skip — an empty engine allows everything and records nothing).
    pub fn is_empty(&self) -> bool {
        self.allowlists.is_empty()
    }

    /// Whether to record ALLOWED calls into the audit table (the
    /// shadow-audit switch). Denied calls are always recorded when the
    /// engine is non-empty.
    pub fn audit(&self) -> bool {
        self.audit
    }

    /// Check one request's model alias against the binding allowlists.
    /// Walks the frozen precedence chain (consumer > route > service >
    /// listener > global) and, for every policy that has an allowlist
    /// entry, requires the alias to be in it (deny-wins intersection).
    /// A consumer with no binding allowlist policy is allowed
    /// (fail-open).
    ///
    /// `consumer` is the authenticated consumer name (None for an
    /// anonymous request — anonymous requests have no consumer-level
    /// policies, so the walk starts at the route level).
    #[allow(clippy::too_many_arguments)]
    pub fn check(
        &self,
        consumer: Option<&str>,
        consumer_policies: &[String],
        route_policies: &[String],
        service_policies: &[String],
        listener_policies: &[String],
        global_policies: &[String],
        model_alias: &str,
    ) -> GovernanceVerdict {
        if self.allowlists.is_empty() {
            return GovernanceVerdict::Allow;
        }
        // Walk the precedence chain. For each policy that has an
        // allowlist, the alias must be in it — deny-wins. The FIRST
        // denying policy is named in the verdict (the most specific
        // level, matching the chain order).
        let levels: [&[String]; 5] = [
            consumer_policies,
            route_policies,
            service_policies,
            listener_policies,
            global_policies,
        ];
        let _ = consumer; // consumer name is not a policy; policies carry the allowlists
        for level in levels {
            for name in level {
                if let Some(allowlist) = self.allowlists.get(name) {
                    if !allowlist.contains(model_alias) {
                        return GovernanceVerdict::Deny {
                            policy: name.clone(),
                            reason: "model_not_in_team_allowlist".to_string(),
                        };
                    }
                }
            }
        }
        GovernanceVerdict::Allow
    }
}
