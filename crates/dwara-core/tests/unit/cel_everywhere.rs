//! Unit tests for `cel::everywhere` (relocated from src).

#![cfg(feature = "cel")]

use dwara_core::cel::everywhere::{
    compile_for, evaluate_for, CelUseSite, HeaderTransform, PolicyCondition, RateLimitKey,
    RequestContext, RouteCondition,
};
use dwara_core::cel::{value_to_bool, value_to_string, CelProgram};

// --- RequestContext ---

#[test]
fn request_context_builds_cel_context() {
    let ctx = RequestContext::new("/api/v1/users", "GET", "example.com")
        .with_header("x-api-key", "abc123")
        .with_query("page", "1");

    let cel_ctx = ctx.to_cel_context().unwrap();

    // Evaluate an expression that uses the context.
    let program = CelProgram::compile("request.path == \"/api/v1/users\"").unwrap();
    let result = program.evaluate(&cel_ctx).unwrap();
    assert_eq!(value_to_bool(&result), Some(true));
}

// --- Use-site 1: Route conditions (golden tests) ---

#[test]
fn route_condition_path_prefix() {
    let cond = RouteCondition::compile("request.path.startsWith(\"/api/\")").unwrap();
    let ctx = RequestContext::new("/api/v1/users", "GET", "example.com");
    assert!(cond.matches(&ctx).unwrap());
}

#[test]
fn route_condition_path_prefix_no_match() {
    let cond = RouteCondition::compile("request.path.startsWith(\"/api/\")").unwrap();
    let ctx = RequestContext::new("/web/index.html", "GET", "example.com");
    assert!(!cond.matches(&ctx).unwrap());
}

#[test]
fn route_condition_method_check() {
    let cond = RouteCondition::compile("request.method == \"POST\"").unwrap();
    let ctx = RequestContext::new("/api/v1", "POST", "example.com");
    assert!(cond.matches(&ctx).unwrap());
}

#[test]
fn route_condition_header_check() {
    let cond = RouteCondition::compile("request.headers[\"x-version\"] == \"v2\"").unwrap();
    let ctx = RequestContext::new("/api", "GET", "example.com").with_header("x-version", "v2");
    assert!(cond.matches(&ctx).unwrap());
}

#[test]
fn route_condition_combined() {
    let cond =
        RouteCondition::compile("request.path.startsWith(\"/api/\") && request.method == \"GET\"")
            .unwrap();
    let ctx = RequestContext::new("/api/v1", "GET", "example.com");
    assert!(cond.matches(&ctx).unwrap());
}

#[test]
fn route_condition_host_check() {
    let cond = RouteCondition::compile("request.host == \"api.example.com\"").unwrap();
    let ctx = RequestContext::new("/api", "GET", "api.example.com");
    assert!(cond.matches(&ctx).unwrap());
}

#[test]
fn route_condition_query_check() {
    let cond = RouteCondition::compile("request.query[\"debug\"] == \"true\"").unwrap();
    let ctx = RequestContext::new("/api", "GET", "example.com").with_query("debug", "true");
    assert!(cond.matches(&ctx).unwrap());
}

#[test]
fn route_condition_must_be_bool() {
    let cond = RouteCondition::compile("request.path").unwrap();
    let ctx = RequestContext::new("/api", "GET", "example.com");
    let err = cond.matches(&ctx).unwrap_err();
    assert!(err.contains("bool"));
}

// --- Use-site 2: Header transforms (golden tests) ---

#[test]
fn header_transform_static_value() {
    let transform = HeaderTransform::compile("\"application/json\"").unwrap();
    let ctx = RequestContext::new("/api", "GET", "example.com");
    assert_eq!(transform.evaluate(&ctx).unwrap(), "application/json");
}

#[test]
fn header_transform_from_path() {
    let transform =
        HeaderTransform::compile("request.path.startsWith(\"/v2/\") ? \"v2\" : \"v1\"").unwrap();
    let ctx = RequestContext::new("/v2/users", "GET", "example.com");
    assert_eq!(transform.evaluate(&ctx).unwrap(), "v2");
}

#[test]
fn header_transform_from_header() {
    let transform = HeaderTransform::compile("request.headers[\"x-forwarded-for\"]").unwrap();
    let ctx = RequestContext::new("/api", "GET", "example.com")
        .with_header("x-forwarded-for", "203.0.113.1");
    assert_eq!(transform.evaluate(&ctx).unwrap(), "203.0.113.1");
}

#[test]
fn header_transform_concat() {
    let transform = HeaderTransform::compile("request.method + \"-\" + request.path").unwrap();
    let ctx = RequestContext::new("/api/v1", "GET", "example.com");
    assert_eq!(transform.evaluate(&ctx).unwrap(), "GET-/api/v1");
}

#[test]
fn header_transform_must_be_string() {
    let transform = HeaderTransform::compile("1 + 2").unwrap();
    let ctx = RequestContext::new("/api", "GET", "example.com");
    let err = transform.evaluate(&ctx).unwrap_err();
    assert!(err.contains("string"));
}

// --- Use-site 3: Rate-limit key derivation (golden tests) ---

#[test]
fn rate_limit_key_from_api_key_header() {
    let key = RateLimitKey::compile("request.headers[\"x-api-key\"]").unwrap();
    let ctx = RequestContext::new("/api", "GET", "example.com").with_header("x-api-key", "abc123");
    assert_eq!(key.derive(&ctx).unwrap(), "abc123");
}

#[test]
fn rate_limit_key_from_path() {
    let key = RateLimitKey::compile("request.path").unwrap();
    let ctx = RequestContext::new("/api/v1/users", "GET", "example.com");
    assert_eq!(key.derive(&ctx).unwrap(), "/api/v1/users");
}

#[test]
fn rate_limit_key_combined() {
    let key =
        RateLimitKey::compile("request.headers[\"x-api-key\"] + \":\" + request.path").unwrap();
    let ctx =
        RequestContext::new("/api/v1", "GET", "example.com").with_header("x-api-key", "abc123");
    assert_eq!(key.derive(&ctx).unwrap(), "abc123:/api/v1");
}

#[test]
fn rate_limit_key_from_host() {
    let key = RateLimitKey::compile("request.host").unwrap();
    let ctx = RequestContext::new("/api", "GET", "api.example.com");
    assert_eq!(key.derive(&ctx).unwrap(), "api.example.com");
}

#[test]
fn rate_limit_key_must_be_string() {
    let key = RateLimitKey::compile("true").unwrap();
    let ctx = RequestContext::new("/api", "GET", "example.com");
    let err = key.derive(&ctx).unwrap_err();
    assert!(err.contains("string"));
}

// --- Use-site 4: Policy conditions (golden tests) ---

#[test]
fn policy_condition_ip_allowlist() {
    let cond = PolicyCondition::compile("request.headers[\"x-real-ip\"] == \"10.0.0.1\"").unwrap();
    let ctx =
        RequestContext::new("/api", "GET", "example.com").with_header("x-real-ip", "10.0.0.1");
    assert!(cond.applies(&ctx).unwrap());
}

#[test]
fn policy_condition_method_restriction() {
    let cond = PolicyCondition::compile("request.method == \"DELETE\"").unwrap();
    let ctx = RequestContext::new("/api/v1/users/123", "DELETE", "example.com");
    assert!(cond.applies(&ctx).unwrap());
}

#[test]
fn policy_condition_path_and_method() {
    let cond = PolicyCondition::compile(
        "request.path.startsWith(\"/admin/\") && request.method != \"GET\"",
    )
    .unwrap();
    let ctx = RequestContext::new("/admin/settings", "POST", "example.com");
    assert!(cond.applies(&ctx).unwrap());
}

#[test]
fn policy_condition_host_based() {
    let cond = PolicyCondition::compile("request.host.endsWith(\".internal\")").unwrap();
    let ctx = RequestContext::new("/api", "GET", "gateway.internal");
    assert!(cond.applies(&ctx).unwrap());
}

#[test]
fn policy_condition_must_be_bool() {
    let cond = PolicyCondition::compile("request.path").unwrap();
    let ctx = RequestContext::new("/api", "GET", "example.com");
    let err = cond.applies(&ctx).unwrap_err();
    assert!(err.contains("bool"));
}

// --- Unified API ---

#[test]
fn compile_for_route_condition() {
    let program = compile_for(CelUseSite::RouteCondition, "request.path == \"/api\"").unwrap();
    let ctx = RequestContext::new("/api", "GET", "example.com");
    let result = evaluate_for(CelUseSite::RouteCondition, &program, &ctx).unwrap();
    assert_eq!(value_to_bool(&result), Some(true));
}

#[test]
fn compile_for_header_transform() {
    let program = compile_for(CelUseSite::HeaderTransform, "\"text/plain\"").unwrap();
    let ctx = RequestContext::new("/api", "GET", "example.com");
    let result = evaluate_for(CelUseSite::HeaderTransform, &program, &ctx).unwrap();
    assert_eq!(value_to_string(&result), Some("text/plain".to_string()));
}

#[test]
fn compile_for_rate_limit_key() {
    let program = compile_for(CelUseSite::RateLimitKey, "request.headers[\"x-api-key\"]").unwrap();
    let ctx = RequestContext::new("/api", "GET", "example.com").with_header("x-api-key", "key123");
    let result = evaluate_for(CelUseSite::RateLimitKey, &program, &ctx).unwrap();
    assert_eq!(value_to_string(&result), Some("key123".to_string()));
}

#[test]
fn compile_for_policy_condition() {
    let program = compile_for(CelUseSite::PolicyCondition, "request.method == \"GET\"").unwrap();
    let ctx = RequestContext::new("/api", "GET", "example.com");
    let result = evaluate_for(CelUseSite::PolicyCondition, &program, &ctx).unwrap();
    assert_eq!(value_to_bool(&result), Some(true));
}

#[test]
fn evaluate_for_type_check_route_condition() {
    let program = compile_for(CelUseSite::RouteCondition, "\"not a bool\"").unwrap();
    let ctx = RequestContext::new("/api", "GET", "example.com");
    let err = evaluate_for(CelUseSite::RouteCondition, &program, &ctx).unwrap_err();
    assert!(err.contains("bool"));
}

#[test]
fn evaluate_for_type_check_header_transform() {
    let program = compile_for(CelUseSite::HeaderTransform, "true").unwrap();
    let ctx = RequestContext::new("/api", "GET", "example.com");
    let err = evaluate_for(CelUseSite::HeaderTransform, &program, &ctx).unwrap_err();
    assert!(err.contains("string"));
}

#[test]
fn cel_use_site_names() {
    assert_eq!(CelUseSite::RouteCondition.name(), "route condition");
    assert_eq!(CelUseSite::HeaderTransform.name(), "header transform");
    assert_eq!(CelUseSite::RateLimitKey.name(), "rate-limit key");
    assert_eq!(CelUseSite::PolicyCondition.name(), "policy condition");
}

#[test]
fn cel_use_site_expected_types() {
    assert_eq!(CelUseSite::RouteCondition.expected_type(), "bool");
    assert_eq!(CelUseSite::HeaderTransform.expected_type(), "string");
    assert_eq!(CelUseSite::RateLimitKey.expected_type(), "string");
    assert_eq!(CelUseSite::PolicyCondition.expected_type(), "bool");
}

#[test]
fn route_condition_source() {
    let cond = RouteCondition::compile("request.path == \"/api\"").unwrap();
    assert_eq!(cond.source(), "request.path == \"/api\"");
}

#[test]
fn header_transform_source() {
    let transform = HeaderTransform::compile("\"value\"").unwrap();
    assert_eq!(transform.source(), "\"value\"");
}

#[test]
fn rate_limit_key_source() {
    let key = RateLimitKey::compile("request.path").unwrap();
    assert_eq!(key.source(), "request.path");
}

#[test]
fn policy_condition_source() {
    let cond = PolicyCondition::compile("true").unwrap();
    assert_eq!(cond.source(), "true");
}
