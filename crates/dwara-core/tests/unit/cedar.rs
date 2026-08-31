//! Unit tests for `security::cedar` (relocated from src).

#![cfg(feature = "cedar")]

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
