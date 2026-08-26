//! Request authorization (DW-020, feature analysis sections 4.7 and 4.15).
//!
//! Authorization answers "is this caller ALLOWED here?" after
//! authentication (DW-019) has answered "who is this caller?". One
//! route's rules live in [`crate::config::Authz`]; this module
//! evaluates them against the request's identity, consumer groups, and
//! EFFECTIVE client IP.
//!
//! # Semantics (frozen)
//!
//! - **403 vs 401**: a DENIED authenticated (or anonymous-but-
//!   IP-gated) request answers 403 "forbidden"; an anonymous request on
//!   a route whose authorization carries identity rules answers 401
//!   (authentication is implied by identity rules). The one
//!   anonymous-permitting case is an `ip_acl`-ONLY [`Authz`] — IP allow
//!   can grant anonymous access (documented exception; an operator
//!   writing `ip_acl` and nothing else wants an IP gate, not a login
//!   wall). `auth_required` on the route still independently forces
//!   authentication regardless of authorization.
//! - **Within one Authz, deny wins**: `denied_consumers` /
//!   `denied_groups` beat `allowed_*` at the same level; in the IP ACL
//!   the deny list is checked before the allow list.
//! - **IP ACL against the EFFECTIVE client IP**: the
//!   `X-Forwarded-For`-resolved client when the direct peer is inside
//!   `gateway.trusted_proxies` (the DW-009 chain — see
//!   [`effective_client_ip`]), otherwise the direct peer. A spoofed XFF
//!   from an untrusted peer never influences the decision.
//! - **Scopes**: every `required_scopes` entry must appear in the JWT
//!   `scope` claim, which may be a space-separated string
//!   (`"read write"`) or an array of strings (flattened by `authn` to
//!   the space-separated form). API-key/Basic identities carry no
//!   claims and never satisfy scope rules.
//! - **Claims**: `required_claims` is exact string equality on the
//!   stringified claim value; a listed claim absent from the token
//!   fails the match. Only string- and number-valued claims are
//!   captured on the identity (`authn` drops bool/null/object
//!   claims), so such a claim can never satisfy a `required_claims`
//!   entry. ALL comparisons — consumers, groups, scopes, claims —
//!   are case-sensitive.
//!
//! # Precedence chain (done-when of DW-020)
//!
//! Rules attach at five levels with the frozen gateway precedence
//! consumer > route > service > listener > global. [`authorize`]
//! resolves the chain through [`AuthzChain`]:
//!
//! 1. A **deny at ANY level wins** — a consumer-level deny beats a
//!    route-level allow, and vice versa. Denials are absolute.
//! 2. Otherwise the **most specific level with rules governs**: its own
//!    evaluation is the verdict (allow or deny under its rules), and
//!    less-specific levels are not consulted. A level without an
//!    [`Authz`] (or with an empty one) is transparent.
//!
//! Live links today: the ROUTE level (`routes[].authorization`). The
//! consumer, service, listener, and global links have no config
//! attachment points yet — the chain structure exists and unit tests
//! exercise the merge with synthetic links; each link activates when
//! its config field lands.
//!
//! # Failure posture
//!
//! Authorization failures are logged server-side only (via the
//! decision's `reason` when warranted); clients receive a generic 403
//! body with no rule detail (which list matched, which claim was absent
//! — none of it is their business).

use std::net::IpAddr;

use crate::config::net::{ip_in_net, parse_ip_or_cidr, peer_is_trusted};
use crate::config::{Authz, IpAcl, IpAclDefault};
use crate::security::authn::Identity;

/// The outcome of an authorization decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The request is authorized (or no rules applied).
    Allow,
    /// The request is rejected. `unauthenticated` selects 401 (with the
    /// authenticator's challenge) over 403; `reason` is server-side
    /// detail, never sent to the client.
    Deny {
        unauthenticated: bool,
        reason: &'static str,
    },
}

/// Everything one authorization evaluation needs to know about the
/// request.
pub struct AuthzContext<'a> {
    pub identity: Option<&'a Identity>,
    /// Group memberships of the authenticated consumer (from the CONFIG
    /// consumer record; store-only consumers have none — documented
    /// limitation).
    pub consumer_groups: &'a [String],
    pub peer_ip: IpAddr,
    /// The XFF-resolved client IP when the peer is a trusted proxy,
    /// else the peer (see [`effective_client_ip`]).
    pub effective_ip: IpAddr,
}

/// Resolve the EFFECTIVE client IP (DW-009 trusted-proxy chain).
///
/// - Peer NOT in `trusted_proxies`: the peer itself (an inbound XFF is
///   untrusted and ignored — spoofing gains nothing).
/// - Peer trusted: walk the inbound XFF chain right-to-left; the
///   rightmost address that is NOT itself a trusted proxy is the
///   client. If every entry is trusted (or the XFF is absent/unparseable),
///   the leftmost parseable entry stands in; with nothing parseable the
///   peer (the closest trusted hop) is used.
///
///   Documented weakness: when the WHOLE XFF chain is trusted, the
///   leftmost entry is CLIENT-SUPPLIED and therefore spoofable by
///   anything that can speak to a trusted proxy — a request from inside
///   the trusted space can present an arbitrary leftmost address and
///   be evaluated against it. There is no more-credible source to
///   prefer in that shape; treat trusted space as hostile to the
///   extent you rely on IP ACLs.
pub fn effective_client_ip(trusted: &[String], peer: IpAddr, xff: Option<&str>) -> IpAddr {
    if !peer_is_trusted(trusted, peer) {
        return peer;
    }
    let Some(xff) = xff else { return peer };
    let entries: Vec<Option<IpAddr>> = xff
        .split(',')
        .map(|e| e.trim().parse::<IpAddr>().ok())
        .collect();
    for ip in entries.iter().rev().flatten() {
        if !peer_is_trusted(trusted, *ip) {
            return *ip;
        }
    }
    entries.iter().flatten().copied().next().unwrap_or(peer)
}

/// Evaluate one IP ACL against an IP. Deny list first (a deny match
/// wins over any allow match), then allow, then the configured default.
fn ip_acl_decision(acl: &IpAcl, ip: IpAddr) -> Decision {
    if acl.deny.iter().any(|e| ip_matches(e, ip)) {
        return Decision::Deny {
            unauthenticated: false,
            reason: "ip denied by acl deny list",
        };
    }
    if acl.allow.iter().any(|e| ip_matches(e, ip)) {
        return Decision::Allow;
    }
    match acl.default {
        IpAclDefault::Allow => Decision::Allow,
        IpAclDefault::Deny => Decision::Deny {
            unauthenticated: false,
            reason: "ip matched neither acl list and the default is deny",
        },
    }
}

fn ip_matches(entry: &str, ip: IpAddr) -> bool {
    parse_ip_or_cidr(entry).is_some_and(|(net, prefix)| ip_in_net(ip, net, prefix))
}

/// Whether an [`Authz`] carries any identity-typed rule (consumer,
/// group, scope, claim). Presence of any of these implies
/// authentication: an anonymous request is rejected 401.
fn has_identity_rules(authz: &Authz) -> bool {
    !authz.allowed_consumers.is_empty()
        || !authz.denied_consumers.is_empty()
        || !authz.allowed_groups.is_empty()
        || !authz.denied_groups.is_empty()
        || !authz.required_scopes.is_empty()
        || !authz.required_claims.is_empty()
}

/// Evaluate ONE [`Authz`] block. `None` means the block imposes nothing
/// (no rules at all — a transparent level); `Some(Allow)` /
/// `Some(Deny)` is this level's verdict.
///
/// Public for testing the single-level authorization contract.
pub fn evaluate_one(authz: &Authz, ctx: &AuthzContext<'_>) -> Option<Decision> {
    if !has_identity_rules(authz) && authz.ip_acl.is_none() {
        return None;
    }
    // IP gate first: a deny-list hit (or closed-default miss) rejects
    // before any identity consideration; an allow passes the gate and
    // the identity rules (if any) still apply on top.
    if let Some(acl) = &authz.ip_acl {
        if let Decision::Deny { reason, .. } = ip_acl_decision(acl, ctx.effective_ip) {
            return Some(Decision::Deny {
                unauthenticated: false,
                reason,
            });
        }
    }
    if !has_identity_rules(authz) {
        // ip_acl-only: the one anonymous-permitting shape.
        return Some(Decision::Allow);
    }
    let Some(identity) = ctx.identity else {
        return Some(Decision::Deny {
            unauthenticated: true,
            reason: "authorization rules require an authenticated identity",
        });
    };
    // Consumer rules; deny beats allow at the same level.
    if authz
        .denied_consumers
        .iter()
        .any(|c| c == &identity.consumer_name)
    {
        return Some(Decision::Deny {
            unauthenticated: false,
            reason: "consumer is denied",
        });
    }
    if !authz.allowed_consumers.is_empty()
        && !authz
            .allowed_consumers
            .iter()
            .any(|c| c == &identity.consumer_name)
    {
        return Some(Decision::Deny {
            unauthenticated: false,
            reason: "consumer is not in the allowed set",
        });
    }
    // Group rules (config consumers only carry groups).
    if authz
        .denied_groups
        .iter()
        .any(|g| ctx.consumer_groups.iter().any(|c| c == g))
    {
        return Some(Decision::Deny {
            unauthenticated: false,
            reason: "consumer's group is denied",
        });
    }
    if !authz.allowed_groups.is_empty()
        && !authz
            .allowed_groups
            .iter()
            .any(|g| ctx.consumer_groups.iter().any(|c| c == g))
    {
        return Some(Decision::Deny {
            unauthenticated: false,
            reason: "consumer is in none of the allowed groups",
        });
    }
    // Scopes: every required scope must appear in the `scope` claim
    // (space-separated string; arrays were flattened by authn).
    let granted_scopes: Vec<&str> = identity
        .claims
        .get("scope")
        .map(|s| s.split_whitespace().collect())
        .unwrap_or_default();
    if authz
        .required_scopes
        .iter()
        .any(|s| !granted_scopes.contains(&s.as_str()))
    {
        return Some(Decision::Deny {
            unauthenticated: false,
            reason: "a required scope is absent",
        });
    }
    // Claims: exact string equality on stringified values.
    if authz
        .required_claims
        .iter()
        .any(|(name, want)| identity.claims.get(name) != Some(want))
    {
        return Some(Decision::Deny {
            unauthenticated: false,
            reason: "a required claim is absent or mismatched",
        });
    }
    Some(Decision::Allow)
}

/// The five authorization levels in frozen precedence order (most
/// specific first). Levels without an [`Authz`] attachment today pass
/// `None`; the chain structure is the DW-020 done-when — links activate
/// as their config fields land.
pub struct AuthzChain<'a> {
    pub consumer: Option<&'a Authz>,
    pub route: Option<&'a Authz>,
    pub service: Option<&'a Authz>,
    pub listener: Option<&'a Authz>,
    pub global: Option<&'a Authz>,
}

impl<'a> AuthzChain<'a> {
    fn links(&self) -> [Option<&'a Authz>; 5] {
        [
            self.consumer,
            self.route,
            self.service,
            self.listener,
            self.global,
        ]
    }
}

/// Resolve the precedence chain. Merge semantics (documented, frozen):
///
/// 1. A deny at ANY level wins (denials are absolute; a consumer-level
///    deny beats a route-level allow and vice versa).
/// 2. Otherwise the most specific level WITH rules governs: its verdict
///    is final and less-specific levels are not consulted.
pub fn authorize(chain: &AuthzChain<'_>, ctx: &AuthzContext<'_>) -> Decision {
    let mut governing: Option<Decision> = None;
    for link in chain.links() {
        let Some(authz) = link else { continue };
        match evaluate_one(authz, ctx) {
            // A deny anywhere is absolute — report it immediately.
            Some(decision @ Decision::Deny { .. }) => return decision,
            // The first (most specific) deciding level governs.
            Some(decision) => {
                if governing.is_none() {
                    governing = Some(decision);
                }
            }
            None => {}
        }
    }
    governing.unwrap_or(Decision::Allow)
}
