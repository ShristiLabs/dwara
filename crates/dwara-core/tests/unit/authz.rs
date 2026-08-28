//! Unit tests for `security::authz` (relocated from src).

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use dwara_core::config::{Authz, IpAcl, IpAclDefault};
use dwara_core::security::authn::Identity;
use dwara_core::security::authz::*;
use dwara_core::state::store::CredentialKind;

fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn authz() -> Authz {
    Authz {
        allowed_consumers: vec![],
        denied_consumers: vec![],
        allowed_groups: vec![],
        denied_groups: vec![],
        required_scopes: vec![],
        required_claims: BTreeMap::new(),
        ip_acl: None,
    }
}

fn identity(consumer: &str, claims: &[(&str, &str)]) -> Identity {
    Identity {
        consumer_name: consumer.to_string(),
        credential_kind: CredentialKind::Jwt,
        groups: Vec::new(),
        claims: claims
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        body_digest: None,
    }
}

fn ctx<'a>(
    identity: Option<&'a Identity>,
    groups: &'a [String],
    effective_ip: IpAddr,
) -> AuthzContext<'a> {
    AuthzContext {
        identity,
        consumer_groups: groups,
        peer_ip: ip(10, 0, 0, 1),
        effective_ip,
    }
}

#[test]
fn effective_ip_uses_peer_when_untrusted() {
    let trusted = vec!["10.0.0.0/8".to_string()];
    let peer = ip(203, 0, 113, 9);
    assert_eq!(
        effective_client_ip(&trusted, peer, Some("10.0.0.2, 198.51.100.7")),
        peer,
        "untrusted peer: inbound XFF is ignored"
    );
}

#[test]
fn effective_ip_walks_xff_rightmost_untrusted() {
    let trusted = vec!["10.0.0.0/8".to_string()];
    let peer = ip(10, 0, 0, 1);
    assert_eq!(
        effective_client_ip(&trusted, peer, Some("198.51.100.7, 10.0.0.5, 10.0.0.6")),
        ip(198, 51, 100, 7),
        "rightmost non-trusted entry is the client"
    );
    // All entries trusted: leftmost stands in.
    assert_eq!(
        effective_client_ip(&trusted, peer, Some("10.1.2.3, 10.4.5.6")),
        ip(10, 1, 2, 3)
    );
    // Garbage / absent XFF: the trusted peer.
    assert_eq!(effective_client_ip(&trusted, peer, Some("not-an-ip")), peer);
    assert_eq!(effective_client_ip(&trusted, peer, None), peer);
}

#[test]
fn ip_acl_deny_beats_allow_and_default_denies() {
    let mut acl_authz = authz();
    acl_authz.ip_acl = Some(IpAcl {
        allow: vec!["10.0.0.0/8".to_string()],
        deny: vec!["10.0.0.99".to_string()],
        default: IpAclDefault::Allow,
    });
    let deny_hit = evaluate_one(&acl_authz, &ctx(None, &[], ip(10, 0, 0, 99))).unwrap();
    assert_eq!(
        deny_hit,
        Decision::Deny {
            unauthenticated: false,
            reason: "ip denied by acl deny list"
        }
    );
    // Allow-list hit passes (anonymous: ip-only authz).
    assert_eq!(
        evaluate_one(&acl_authz, &ctx(None, &[], ip(10, 1, 2, 3))).unwrap(),
        Decision::Allow
    );
    // Neither list: default allow.
    assert_eq!(
        evaluate_one(&acl_authz, &ctx(None, &[], ip(192, 0, 2, 1))).unwrap(),
        Decision::Allow
    );
    // Closed mode.
    acl_authz.ip_acl = Some(IpAcl {
        allow: vec!["10.0.0.0/8".to_string()],
        deny: vec![],
        default: IpAclDefault::Deny,
    });
    assert!(matches!(
        evaluate_one(&acl_authz, &ctx(None, &[], ip(192, 0, 2, 1))).unwrap(),
        Decision::Deny {
            unauthenticated: false,
            ..
        }
    ));
    assert_eq!(
        evaluate_one(&acl_authz, &ctx(None, &[], ip(10, 9, 9, 9))).unwrap(),
        Decision::Allow
    );
}

#[test]
fn identity_rules_imply_authentication() {
    let mut a = authz();
    a.allowed_consumers = vec!["acme".to_string()];
    assert!(matches!(
        evaluate_one(&a, &ctx(None, &[], ip(10, 0, 0, 1))).unwrap(),
        Decision::Deny {
            unauthenticated: true,
            ..
        }
    ));
}

#[test]
fn consumer_rules_deny_beats_allow() {
    let id = identity("acme", &[]);
    let mut a = authz();
    a.allowed_consumers = vec!["acme".to_string(), "beta".to_string()];
    a.denied_consumers = vec!["acme".to_string()];
    assert!(matches!(
        evaluate_one(&a, &ctx(Some(&id), &[], ip(1, 1, 1, 1))).unwrap(),
        Decision::Deny { .. }
    ));
    // Not in the allowed set.
    let id2 = identity("gamma", &[]);
    assert!(matches!(
        evaluate_one(&a, &ctx(Some(&id2), &[], ip(1, 1, 1, 1))).unwrap(),
        Decision::Deny { .. }
    ));
    // In the allowed set, not denied.
    let id3 = identity("beta", &[]);
    assert_eq!(
        evaluate_one(&a, &ctx(Some(&id3), &[], ip(1, 1, 1, 1))).unwrap(),
        Decision::Allow
    );
}

#[test]
fn group_scopes_and_claims_evaluate() {
    let mut a = authz();
    a.allowed_groups = vec!["gold".to_string()];
    let groups = vec!["silver".to_string()];
    let id = identity("acme", &[]);
    assert!(matches!(
        evaluate_one(&a, &ctx(Some(&id), &groups, ip(1, 1, 1, 1))).unwrap(),
        Decision::Deny { .. }
    ));
    let groups_ok = vec!["gold".to_string(), "silver".to_string()];
    assert_eq!(
        evaluate_one(&a, &ctx(Some(&id), &groups_ok, ip(1, 1, 1, 1))).unwrap(),
        Decision::Allow
    );

    // Scopes: space-separated claim.
    let mut s = authz();
    s.required_scopes = vec!["read".to_string(), "write".to_string()];
    let reader = identity("acme", &[("scope", "read")]);
    assert!(matches!(
        evaluate_one(&s, &ctx(Some(&reader), &[], ip(1, 1, 1, 1))).unwrap(),
        Decision::Deny { .. }
    ));
    let writer = identity("acme", &[("scope", "read admin write")]);
    assert_eq!(
        evaluate_one(&s, &ctx(Some(&writer), &[], ip(1, 1, 1, 1))).unwrap(),
        Decision::Allow
    );
    // Flattened array form (authn joins with spaces) reads the same.
    let writer_arr = identity("acme", &[("scope", "read write")]);
    assert_eq!(
        evaluate_one(&s, &ctx(Some(&writer_arr), &[], ip(1, 1, 1, 1))).unwrap(),
        Decision::Allow
    );

    // Claims: exact match; absent fails.
    let mut c = authz();
    c.required_claims = BTreeMap::from([("tenant".to_string(), "acme".to_string())]);
    let ok = identity("acme", &[("tenant", "acme")]);
    assert_eq!(
        evaluate_one(&c, &ctx(Some(&ok), &[], ip(1, 1, 1, 1))).unwrap(),
        Decision::Allow
    );
    let wrong = identity("acme", &[("tenant", "other")]);
    let absent = identity("acme", &[("other", "x")]);
    assert!(matches!(
        evaluate_one(&c, &ctx(Some(&wrong), &[], ip(1, 1, 1, 1))).unwrap(),
        Decision::Deny { .. }
    ));
    assert!(matches!(
        evaluate_one(&c, &ctx(Some(&absent), &[], ip(1, 1, 1, 1))).unwrap(),
        Decision::Deny { .. }
    ));
}

#[test]
fn chain_deny_at_any_level_wins() {
    let id = identity("acme", &[]);
    let mut route = authz();
    route.allowed_consumers = vec!["acme".to_string()];
    let mut consumer = authz();
    consumer.denied_consumers = vec!["acme".to_string()];
    let c = ctx(Some(&id), &[], ip(1, 1, 1, 1));
    // Consumer-level deny beats route-level allow.
    assert!(matches!(
        authorize(
            &AuthzChain {
                consumer: Some(&consumer),
                route: Some(&route),
                service: None,
                listener: None,
                global: None,
            },
            &c
        ),
        Decision::Deny { .. }
    ));
    // Route-level deny beats service-level allow.
    let mut service = authz();
    service.allowed_consumers = vec!["acme".to_string()];
    let mut route_deny = authz();
    route_deny.denied_consumers = vec!["acme".to_string()];
    assert!(matches!(
        authorize(
            &AuthzChain {
                consumer: None,
                route: Some(&route_deny),
                service: Some(&service),
                listener: None,
                global: None,
            },
            &c
        ),
        Decision::Deny { .. }
    ));
}

#[test]
fn chain_most_specific_governs_when_no_deny() {
    let id = identity("acme", &[]);
    let mut route = authz();
    route.allowed_consumers = vec!["acme".to_string()];
    let mut global = authz();
    global.denied_consumers = vec!["someone-else".to_string()];
    let c = ctx(Some(&id), &[], ip(1, 1, 1, 1));
    // No level denies THIS request; the most specific deciding level
    // (route allow) governs even though a less specific level exists.
    assert_eq!(
        authorize(
            &AuthzChain {
                consumer: None,
                route: Some(&route),
                service: None,
                listener: None,
                global: Some(&global),
            },
            &c
        ),
        Decision::Allow
    );
    // With no route rules, the global deny for someone-else does not
    // affect acme.
    let outsider = identity("someone-else", &[]);
    let c2 = ctx(Some(&outsider), &[], ip(1, 1, 1, 1));
    assert!(matches!(
        authorize(
            &AuthzChain {
                consumer: None,
                route: None,
                service: None,
                listener: None,
                global: Some(&global),
            },
            &c2
        ),
        Decision::Deny { .. }
    ));
    // Empty chain: allow.
    assert_eq!(
        authorize(
            &AuthzChain {
                consumer: None,
                route: None,
                service: None,
                listener: None,
                global: None,
            },
            &c
        ),
        Decision::Allow
    );
}
