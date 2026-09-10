//! Unit tests for `security::cedar` (relocated from src).

use dwara_core::security::cedar::{CedarAuthorizer, CedarDecision, CedarRequest};

const SIMPLE_POLICY: &str = r#"
permit (
    principal == User::"alice",
    action == Action::"read",
    resource == Route::"api-v1"
);
"#;

const ENTITIES_JSON: &str = r#"[
    {
        "uid": {"__entity": {"type": "User", "id": "alice"}},
        "attrs": {},
        "parents": []
    },
    {
        "uid": {"__entity": {"type": "Route", "id": "api-v1"}},
        "attrs": {},
        "parents": []
    }
]"#;

#[test]
fn allow_when_policy_matches() {
    let authz = CedarAuthorizer::new(SIMPLE_POLICY, Some(ENTITIES_JSON), None).unwrap();
    let req = CedarRequest {
        principal: r#"User::"alice""#.to_string(),
        action: r#"Action::"read""#.to_string(),
        resource: r#"Route::"api-v1""#.to_string(),
        context: None,
    };
    let decision = authz.is_authorized(&req).unwrap();
    assert_eq!(decision, CedarDecision::Allow);
}

#[test]
fn deny_when_principal_does_not_match() {
    let authz = CedarAuthorizer::new(SIMPLE_POLICY, Some(ENTITIES_JSON), None).unwrap();
    let req = CedarRequest {
        principal: r#"User::"bob""#.to_string(),
        action: r#"Action::"read""#.to_string(),
        resource: r#"Route::"api-v1""#.to_string(),
        context: None,
    };
    let decision = authz.is_authorized(&req).unwrap();
    assert_eq!(decision, CedarDecision::Deny);
}

#[test]
fn deny_when_action_does_not_match() {
    let authz = CedarAuthorizer::new(SIMPLE_POLICY, Some(ENTITIES_JSON), None).unwrap();
    let req = CedarRequest {
        principal: r#"User::"alice""#.to_string(),
        action: r#"Action::"write""#.to_string(),
        resource: r#"Route::"api-v1""#.to_string(),
        context: None,
    };
    let decision = authz.is_authorized(&req).unwrap();
    assert_eq!(decision, CedarDecision::Deny);
}

#[test]
fn deny_when_resource_does_not_match() {
    let authz = CedarAuthorizer::new(SIMPLE_POLICY, Some(ENTITIES_JSON), None).unwrap();
    let req = CedarRequest {
        principal: r#"User::"alice""#.to_string(),
        action: r#"Action::"read""#.to_string(),
        resource: r#"Route::"api-v2""#.to_string(),
        context: None,
    };
    let decision = authz.is_authorized(&req).unwrap();
    assert_eq!(decision, CedarDecision::Deny);
}

#[test]
fn empty_authorizer_denies_everything() {
    let authz = CedarAuthorizer::empty();
    let req = CedarRequest {
        principal: r#"User::"alice""#.to_string(),
        action: r#"Action::"read""#.to_string(),
        resource: r#"Route::"api-v1""#.to_string(),
        context: None,
    };
    let decision = authz.is_authorized(&req).unwrap();
    assert_eq!(decision, CedarDecision::Deny);
}

#[test]
fn policy_with_context() {
    let policy = r#"
permit (
    principal == User::"alice",
    action == Action::"read",
    resource == Route::"api-v1"
) when {
    context.ip == "10.0.0.1"
};
"#;
    let authz = CedarAuthorizer::new(policy, Some(ENTITIES_JSON), None).unwrap();

    // Allow with matching context.
    let req = CedarRequest {
        principal: r#"User::"alice""#.to_string(),
        action: r#"Action::"read""#.to_string(),
        resource: r#"Route::"api-v1""#.to_string(),
        context: Some(serde_json::json!({"ip": "10.0.0.1"})),
    };
    assert_eq!(authz.is_authorized(&req).unwrap(), CedarDecision::Allow);

    // Deny with non-matching context.
    let req = CedarRequest {
        principal: r#"User::"alice""#.to_string(),
        action: r#"Action::"read""#.to_string(),
        resource: r#"Route::"api-v1""#.to_string(),
        context: Some(serde_json::json!({"ip": "10.0.0.2"})),
    };
    assert_eq!(authz.is_authorized(&req).unwrap(), CedarDecision::Deny);
}

#[test]
fn policy_parse_error_on_invalid_syntax() {
    assert!(CedarAuthorizer::new("invalid policy !!!", None, None).is_err());
}

#[test]
fn policy_count() {
    let authz = CedarAuthorizer::new(SIMPLE_POLICY, Some(ENTITIES_JSON), None).unwrap();
    assert_eq!(authz.policy_count(), 1);
}

#[test]
fn forbid_policy_takes_precedence() {
    let policy = r#"
permit (
    principal == User::"alice",
    action == Action::"read",
    resource == Route::"api-v1"
);
forbid (
    principal == User::"alice",
    action == Action::"read",
    resource == Route::"api-v1"
);
"#;
    let authz = CedarAuthorizer::new(policy, Some(ENTITIES_JSON), None).unwrap();
    let req = CedarRequest {
        principal: r#"User::"alice""#.to_string(),
        action: r#"Action::"read""#.to_string(),
        resource: r#"Route::"api-v1""#.to_string(),
        context: None,
    };
    // Forbid wins over permit.
    assert_eq!(authz.is_authorized(&req).unwrap(), CedarDecision::Deny);
}

// --- Hot reload (CFG-07, #241) -------------------------------------------

use dwara_core::security::cedar::HotReloadCedarAuthorizer;

const BOB_POLICY: &str = r#"
permit (
    principal == User::"bob",
    action == Action::"read",
    resource == Route::"api-v1"
);
"#;

#[test]
fn hot_reload_starts_with_initial_policy() {
    let authz = HotReloadCedarAuthorizer::from_sources(SIMPLE_POLICY, Some(ENTITIES_JSON), None)
        .unwrap();
    let req = CedarRequest {
        principal: r#"User::"alice""#.to_string(),
        action: r#"Action::"read""#.to_string(),
        resource: r#"Route::"api-v1""#.to_string(),
        context: None,
    };
    assert_eq!(authz.is_authorized(&req).unwrap(), CedarDecision::Allow);
}

#[test]
fn hot_reload_swaps_policy_set_atomically() {
    let authz = HotReloadCedarAuthorizer::from_sources(SIMPLE_POLICY, Some(ENTITIES_JSON), None)
        .unwrap();

    // Alice is allowed by the initial policy.
    let alice_req = CedarRequest {
        principal: r#"User::"alice""#.to_string(),
        action: r#"Action::"read""#.to_string(),
        resource: r#"Route::"api-v1""#.to_string(),
        context: None,
    };
    assert_eq!(authz.is_authorized(&alice_req).unwrap(), CedarDecision::Allow);

    // Reload with a policy that only allows Bob.
    authz.reload_from_sources(BOB_POLICY, Some(ENTITIES_JSON), None)
        .unwrap();

    // Alice is now denied.
    assert_eq!(authz.is_authorized(&alice_req).unwrap(), CedarDecision::Deny);

    // Bob is now allowed.
    let bob_req = CedarRequest {
        principal: r#"User::"bob""#.to_string(),
        action: r#"Action::"read""#.to_string(),
        resource: r#"Route::"api-v1""#.to_string(),
        context: None,
    };
    assert_eq!(authz.is_authorized(&bob_req).unwrap(), CedarDecision::Allow);
}

#[test]
fn hot_reload_does_not_swap_on_compile_error() {
    let authz = HotReloadCedarAuthorizer::from_sources(SIMPLE_POLICY, Some(ENTITIES_JSON), None)
        .unwrap();
    let alice_req = CedarRequest {
        principal: r#"User::"alice""#.to_string(),
        action: r#"Action::"read""#.to_string(),
        resource: r#"Route::"api-v1""#.to_string(),
        context: None,
    };

    // Attempt to reload with invalid policy — should fail.
    let result = authz.reload_from_sources("invalid policy syntax {{{", None, None);
    assert!(result.is_err());

    // The original policy is still active.
    assert_eq!(authz.is_authorized(&alice_req).unwrap(), CedarDecision::Allow);
}

#[test]
fn hot_reload_policy_count_reflects_current_set() {
    let authz = HotReloadCedarAuthorizer::from_sources(SIMPLE_POLICY, Some(ENTITIES_JSON), None)
        .unwrap();
    assert_eq!(authz.policy_count(), 1);

    // Reload with a policy set that has two policies.
    let two_policies = r#"
permit (
    principal == User::"alice",
    action == Action::"read",
    resource == Route::"api-v1"
);
permit (
    principal == User::"bob",
    action == Action::"read",
    resource == Route::"api-v1"
);
"#;
    authz.reload_from_sources(two_policies, Some(ENTITIES_JSON), None)
        .unwrap();
    assert_eq!(authz.policy_count(), 2);
}

// --- OPA bundle revision tracking (DP-07, #241) -------------------------

#[test]
fn opa_bundle_revision_starts_none() {
    use dwara_core::security::cedar::opa::OpaClient;
    use std::time::Duration;
    let client = OpaClient::new(
        "http://opa:8181/v1/data/dwara/allow".to_string(),
        Duration::from_secs(60),
        Duration::from_secs(5),
    );
    assert_eq!(client.bundle_revision(), None);
}

#[test]
fn opa_parse_url_https() {
    use dwara_core::security::cedar::opa::OpaClient;
    use std::time::Duration;
    let _client = OpaClient::new(
        "https://opa.internal:8443/v1/data/allow".to_string(),
        Duration::from_secs(60),
        Duration::from_secs(5),
    );
}
