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
