//! Cedar policy engine integration (DW-060).
//!
//! This module provides a thin wrapper around the `cedar-policy` crate,
//! offering:
//!
//! - [`CedarAuthorizer`] — a compiled Cedar policy set + entity store,
//!   ready to evaluate authorization requests.
//! - [`CedarRequest`] — an authorization request (principal, action,
//!   resource, context).
//! - [`CedarDecision`] — the authorization decision (Allow or Deny).
//!
//! ## Design (section 6-Extensibility, §9.3)
//!
//! Cedar is Rust-native (AWS), so authz becomes fine-grained data
//! (policies), not code, without an FFI boundary. Policies are
//! compiled once at config publish time and embedded in the snapshot.
//! The request path only evaluates — it never parses or compiles.
//!
//! ## Feature gate
//!
//! The `cedar` cargo feature must be enabled. Without it, the module
//! is not compiled and config fields that reference Cedar policies are
//! accepted but inert.

use std::sync::Arc;

pub mod opa;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema,
};

/// A compiled Cedar authorizer: a policy set + entity store, ready to
/// evaluate authorization requests.
///
/// Created at config publish time by [`CedarAuthorizer::new`]. The
/// authorizer is immutable and can be safely shared across threads
/// (Arc internals).
#[derive(Clone)]
pub struct CedarAuthorizer {
    policies: Arc<PolicySet>,
    entities: Arc<Entities>,
    schema: Option<Arc<Schema>>,
}

/// A Cedar authorization request.
#[derive(Clone, Debug)]
pub struct CedarRequest {
    /// The principal (who is making the request), e.g.
    /// `User::"alice"`.
    pub principal: String,
    /// The action being performed, e.g. `Action::"read"`.
    pub action: String,
    /// The resource being accessed, e.g. `Route::"api-v1"`.
    pub resource: String,
    /// Additional context (a JSON object serialized as a Cedar context).
    pub context: Option<serde_json::Value>,
}

/// The result of a Cedar authorization check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CedarDecision {
    Allow,
    Deny,
}

/// An error from the Cedar policy engine.
#[derive(Debug)]
pub enum CedarError {
    /// Failed to parse the policy set.
    PolicyParse(String),
    /// Failed to parse the entity store.
    EntityParse(String),
    /// Failed to parse the schema.
    SchemaParse(String),
    /// Failed to build the request.
    RequestBuild(String),
    /// Authorization evaluation failed.
    AuthzError(String),
}

impl std::fmt::Display for CedarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PolicyParse(s) => write!(f, "Cedar policy parse error: {s}"),
            Self::EntityParse(s) => write!(f, "Cedar entity parse error: {s}"),
            Self::SchemaParse(s) => write!(f, "Cedar schema parse error: {s}"),
            Self::RequestBuild(s) => write!(f, "Cedar request build error: {s}"),
            Self::AuthzError(s) => write!(f, "Cedar authz error: {s}"),
        }
    }
}

impl std::error::Error for CedarError {}

impl CedarAuthorizer {
    /// Create a new authorizer from a policy set source string, an
    /// entities JSON string, and an optional schema JSON string.
    ///
    /// This is the compile step. It should be called at config publish
    /// time, never on the request path.
    pub fn new(
        policies_src: &str,
        entities_json: Option<&str>,
        schema_json: Option<&str>,
    ) -> Result<Self, CedarError> {
        let policy_set: PolicySet = policies_src
            .parse::<PolicySet>()
            .map_err(|e: cedar_policy::ParseErrors| CedarError::PolicyParse(e.to_string()))?;

        let entities = if let Some(json) = entities_json {
            Entities::from_json_str(json, None)
                .map_err(|e| CedarError::EntityParse(e.to_string()))?
        } else {
            Entities::empty()
        };

        let schema = if let Some(json) = schema_json {
            Some(Arc::new(
                Schema::from_json_str(json).map_err(|e| CedarError::SchemaParse(e.to_string()))?,
            ))
        } else {
            None
        };

        Ok(Self {
            policies: Arc::new(policy_set),
            entities: Arc::new(entities),
            schema,
        })
    }

    /// Create an empty authorizer (denies everything).
    pub fn empty() -> Self {
        Self {
            policies: Arc::new(PolicySet::new()),
            entities: Arc::new(Entities::empty()),
            schema: None,
        }
    }

    /// Evaluate an authorization request.
    ///
    /// This is the hot-path call. It evaluates the compiled policies
    /// against the request and returns a decision.
    pub fn is_authorized(&self, req: &CedarRequest) -> Result<CedarDecision, CedarError> {
        let principal = parse_euid(&req.principal)
            .map_err(|e| CedarError::RequestBuild(format!("principal: {e}")))?;
        let action = parse_euid(&req.action)
            .map_err(|e| CedarError::RequestBuild(format!("action: {e}")))?;
        let resource = parse_euid(&req.resource)
            .map_err(|e| CedarError::RequestBuild(format!("resource: {e}")))?;

        let context = if let Some(ctx_json) = &req.context {
            Context::from_json_value(ctx_json.clone(), None)
                .map_err(|e| CedarError::RequestBuild(format!("context: {e}")))?
        } else {
            Context::empty()
        };

        let request = Request::new(principal, action, resource, context, self.schema.as_deref())
            .map_err(|e| CedarError::RequestBuild(e.to_string()))?;

        let authorizer = Authorizer::new();
        let response = authorizer.is_authorized(&request, &self.policies, &self.entities);
        match response.decision() {
            Decision::Allow => Ok(CedarDecision::Allow),
            Decision::Deny => {
                for err in response.diagnostics().errors() {
                    tracing::debug!(
                        error = %err,
                        "Cedar policy denied request"
                    );
                }
                Ok(CedarDecision::Deny)
            }
        }
    }

    /// The number of policies in the set.
    pub fn policy_count(&self) -> usize {
        self.policies.policies().count()
    }
}

/// Parse a Cedar entity UID from a string like `User::"alice"`.
fn parse_euid(s: &str) -> Result<EntityUid, String> {
    s.parse::<EntityUid>().map_err(|e| format!("{e}"))
}
