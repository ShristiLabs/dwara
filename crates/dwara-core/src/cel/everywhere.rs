//! CEL everywhere (DW-059).
//!
//! One CEL surface across four use-sites, following the APISIX
//! `expr`/Kong expressions-router precedent of a single expression
//! language rather than a bespoke DSL per feature.
//!
//! ## Use-sites
//!
//! 1. **Expression matchers in routes** -- a CEL expression that
//!    evaluates to a bool; if true, the route matches.
//! 2. **Header/transform logic** -- a CEL expression that evaluates
//!    to a string; the result is used as the header value.
//! 3. **Rate-limit key derivation** -- a CEL expression that
//!    evaluates to a string; the result is used as the rate-limit
//!    key (e.g. `request.headers["x-api-key"]`).
//! 4. **Policy conditions** -- a CEL expression that evaluates to a
//!    bool; if true, the policy applies.
//!
//! ## Request context
//!
//! All four use-sites share the same request context: a `request`
//! variable with `path`, `method`, `headers`, `query`, `host` fields.
//! This is the standard CEL request variable that the gateway
//! populates per-request.
//!
//! ## Feature gate
//!
//! The `cel` cargo feature must be enabled (this module builds on the
//! DW-058 CEL engine).

use std::collections::HashMap;

use super::{value_to_bool, value_to_string, CelContext, CelProgram, Value};

// ---------------------------------------------------------------------------
// Request context builder
// ---------------------------------------------------------------------------

/// The standard request context for CEL evaluation.
///
/// All four use-sites share this context. The gateway populates it
/// per-request with the request's path, method, headers, query, and
/// host.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub path: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub query: HashMap<String, String>,
    pub host: String,
}

impl RequestContext {
    /// Create a new request context.
    pub fn new(path: &str, method: &str, host: &str) -> Self {
        Self {
            path: path.to_string(),
            method: method.to_string(),
            headers: HashMap::new(),
            query: HashMap::new(),
            host: host.to_string(),
        }
    }

    /// Add a header.
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }

    /// Add a query parameter.
    pub fn with_query(mut self, name: &str, value: &str) -> Self {
        self.query.insert(name.to_string(), value.to_string());
        self
    }

    /// Build a CelContext from this request context.
    pub fn to_cel_context(&self) -> Result<CelContext, String> {
        let mut ctx = CelContext::new();
        // Build the request as a serde_json::Value so nested maps
        // serialize correctly for the cel-interpreter.
        let request = serde_json::json!({
            "path": self.path,
            "method": self.method,
            "host": self.host,
            "headers": self.headers,
            "query": self.query,
        });
        ctx.add_var("request", &request)?;
        Ok(ctx)
    }
}

// ---------------------------------------------------------------------------
// Use-site 1: Expression matchers in routes
// ---------------------------------------------------------------------------

/// A CEL-based route match condition.
///
/// The expression must evaluate to a bool. If true, the route
/// matches. Compiled once at config publish time; evaluated per-request.
#[derive(Debug)]
pub struct RouteCondition {
    program: CelProgram,
}

impl RouteCondition {
    /// Compile a route condition expression.
    pub fn compile(expr: &str) -> Result<Self, String> {
        let program =
            CelProgram::compile(expr).map_err(|e| format!("route condition compile: {e}"))?;
        Ok(Self { program })
    }

    /// Evaluate the condition against a request context.
    pub fn matches(&self, ctx: &RequestContext) -> Result<bool, String> {
        let cel_ctx = ctx.to_cel_context()?;
        let result = self
            .program
            .evaluate(&cel_ctx)
            .map_err(|e| format!("route condition evaluate: {e}"))?;
        value_to_bool(&result).ok_or_else(|| "route condition must evaluate to bool".to_string())
    }

    /// The original source expression.
    pub fn source(&self) -> &str {
        self.program.source()
    }
}

// ---------------------------------------------------------------------------
// Use-site 2: Header/transform logic
// ---------------------------------------------------------------------------

/// A CEL-based header transform expression.
///
/// The expression must evaluate to a string. The result is used as
/// the header value. Compiled once at config publish time; evaluated
/// per-request.
#[derive(Debug)]
pub struct HeaderTransform {
    program: CelProgram,
}

impl HeaderTransform {
    /// Compile a header transform expression.
    pub fn compile(expr: &str) -> Result<Self, String> {
        let program =
            CelProgram::compile(expr).map_err(|e| format!("header transform compile: {e}"))?;
        Ok(Self { program })
    }

    /// Evaluate the transform against a request context.
    pub fn evaluate(&self, ctx: &RequestContext) -> Result<String, String> {
        let cel_ctx = ctx.to_cel_context()?;
        let result = self
            .program
            .evaluate(&cel_ctx)
            .map_err(|e| format!("header transform evaluate: {e}"))?;
        value_to_string(&result)
            .ok_or_else(|| "header transform must evaluate to string".to_string())
    }

    /// The original source expression.
    pub fn source(&self) -> &str {
        self.program.source()
    }
}

// ---------------------------------------------------------------------------
// Use-site 3: Rate-limit key derivation
// ---------------------------------------------------------------------------

/// A CEL-based rate-limit key derivation expression.
///
/// The expression must evaluate to a string. The result is used as
/// the rate-limit key. Compiled once at config publish time; evaluated
/// per-request.
#[derive(Debug)]
pub struct RateLimitKey {
    program: CelProgram,
}

impl RateLimitKey {
    /// Compile a rate-limit key expression.
    pub fn compile(expr: &str) -> Result<Self, String> {
        let program =
            CelProgram::compile(expr).map_err(|e| format!("rate-limit key compile: {e}"))?;
        Ok(Self { program })
    }

    /// Evaluate the key derivation against a request context.
    pub fn derive(&self, ctx: &RequestContext) -> Result<String, String> {
        let cel_ctx = ctx.to_cel_context()?;
        let result = self
            .program
            .evaluate(&cel_ctx)
            .map_err(|e| format!("rate-limit key evaluate: {e}"))?;
        value_to_string(&result).ok_or_else(|| "rate-limit key must evaluate to string".to_string())
    }

    /// The original source expression.
    pub fn source(&self) -> &str {
        self.program.source()
    }
}

// ---------------------------------------------------------------------------
// Use-site 4: Policy conditions
// ---------------------------------------------------------------------------

/// A CEL-based policy condition.
///
/// The expression must evaluate to a bool. If true, the policy
/// applies. Compiled once at config publish time; evaluated per-request.
#[derive(Debug)]
pub struct PolicyCondition {
    program: CelProgram,
}

impl PolicyCondition {
    /// Compile a policy condition expression.
    pub fn compile(expr: &str) -> Result<Self, String> {
        let program =
            CelProgram::compile(expr).map_err(|e| format!("policy condition compile: {e}"))?;
        Ok(Self { program })
    }

    /// Evaluate the condition against a request context.
    pub fn applies(&self, ctx: &RequestContext) -> Result<bool, String> {
        let cel_ctx = ctx.to_cel_context()?;
        let result = self
            .program
            .evaluate(&cel_ctx)
            .map_err(|e| format!("policy condition evaluate: {e}"))?;
        value_to_bool(&result).ok_or_else(|| "policy condition must evaluate to bool".to_string())
    }

    /// The original source expression.
    pub fn source(&self) -> &str {
        self.program.source()
    }
}

// ---------------------------------------------------------------------------
// Unified API: compile any use-site
// ---------------------------------------------------------------------------

/// The kind of CEL use-site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CelUseSite {
    RouteCondition,
    HeaderTransform,
    RateLimitKey,
    PolicyCondition,
}

impl CelUseSite {
    /// The human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            CelUseSite::RouteCondition => "route condition",
            CelUseSite::HeaderTransform => "header transform",
            CelUseSite::RateLimitKey => "rate-limit key",
            CelUseSite::PolicyCondition => "policy condition",
        }
    }

    /// The expected result type.
    pub fn expected_type(&self) -> &'static str {
        match self {
            CelUseSite::RouteCondition | CelUseSite::PolicyCondition => "bool",
            CelUseSite::HeaderTransform | CelUseSite::RateLimitKey => "string",
        }
    }
}

/// Compile a CEL expression for a specific use-site.
pub fn compile_for(use_site: CelUseSite, expr: &str) -> Result<CelProgram, String> {
    CelProgram::compile(expr).map_err(|e| format!("{} compile: {e}", use_site.name()))
}

/// Evaluate a CEL program for a specific use-site, checking the result type.
pub fn evaluate_for(
    use_site: CelUseSite,
    program: &CelProgram,
    ctx: &RequestContext,
) -> Result<Value, String> {
    let cel_ctx = ctx.to_cel_context()?;
    let result = program
        .evaluate(&cel_ctx)
        .map_err(|e| format!("{} evaluate: {e}", use_site.name()))?;

    // Type-check the result.
    let type_ok = match use_site {
        CelUseSite::RouteCondition | CelUseSite::PolicyCondition => {
            matches!(result, Value::Bool(_))
        }
        CelUseSite::HeaderTransform | CelUseSite::RateLimitKey => {
            matches!(result, Value::String(_))
        }
    };

    if !type_ok {
        return Err(format!(
            "{} must evaluate to {}, got {:?}",
            use_site.name(),
            use_site.expected_type(),
            result
        ));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let cond = RouteCondition::compile(
            "request.path.startsWith(\"/api/\") && request.method == \"GET\"",
        )
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
            HeaderTransform::compile("request.path.startsWith(\"/v2/\") ? \"v2\" : \"v1\"")
                .unwrap();
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
        let ctx =
            RequestContext::new("/api", "GET", "example.com").with_header("x-api-key", "abc123");
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
        let cond =
            PolicyCondition::compile("request.headers[\"x-real-ip\"] == \"10.0.0.1\"").unwrap();
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
        let program =
            compile_for(CelUseSite::RateLimitKey, "request.headers[\"x-api-key\"]").unwrap();
        let ctx =
            RequestContext::new("/api", "GET", "example.com").with_header("x-api-key", "key123");
        let result = evaluate_for(CelUseSite::RateLimitKey, &program, &ctx).unwrap();
        assert_eq!(value_to_string(&result), Some("key123".to_string()));
    }

    #[test]
    fn compile_for_policy_condition() {
        let program =
            compile_for(CelUseSite::PolicyCondition, "request.method == \"GET\"").unwrap();
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
}
