//! The AI provider-adapter pack (DW-075): one client dialect in,
//! three provider dialects out.
//!
//! Clients send OpenAI chat-completions shaped requests to a route
//! whose action is `ai`; the gateway resolves the request's `model`
//! through the [`AiRuntime`] alias table, translates the request to
//! the serving provider's wire format via that provider's
//! [`ProviderAdapter`], places the call
//! through the provider's named UPSTREAM (the same pooling, TLS,
//! timeout, breaker, and health machinery every other upstream gets),
//! and translates the response back to the OpenAI shape. The provider
//! model identifier never reaches the client; the client's alias never
//! reaches the provider.
//!
//! # Layout
//!
//! - [`types`] — the canonical chat vocabulary every adapter shares
//! - [`adapter`] — the [`ProviderAdapter`]
//!   trait, the pure-translation seam DW-076 (routing/failover)
//!   composes on, and the domain error type
//! - [`adapters`] — the OpenAI, Anthropic, and Gemini dialect impls
//! - [`openai_compat`] — the client-facing facade (parse/serialize)
//! - [`sse`] — hand-rolled SSE framing (in-house by the locked M4
//!   dependency decision)
//! - [`guardrails`] — the DW-082 guardrail engine (prompt-injection,
//!   PII, banned-content, output schema enforcement)
//! - [`semantic_cache`] — the DW-083 semantic cache
//!   (embedding-similarity cache for AI prompts; feature-gated behind
//!   the `semantic_cache` cargo feature)
//! - [`policy`] — the DW-085 routing-policy engine (within-request
//!   escalation via an external classifier, and latency-vs-cost
//!   static selection)
//!
//! # Dependency direction
//!
//! `ai` depends on `config` only (the `ai:` block's schema types). The
//! transport lives in `dataplane` (`dataplane::ai_proxy`), which may
//! depend on everything; DW-076's failover wraps the call, DW-077
//! wires the streaming path, DW-078/079 meter it — none of them need
//! to touch adapter internals, which is the point of the trait.

pub mod adapter;
pub mod adapters;
pub mod budget;
pub mod cost;
pub mod governance;
pub mod guardrails;
pub mod logging;
pub mod openai_compat;
pub mod policy;
pub mod redaction;
pub mod routing;
pub mod semantic_cache;
pub mod sse;
pub mod stream;
pub mod types;

use crate::config::ai::{AiConfig, AiProviderKind};
use std::collections::BTreeMap;
use std::sync::Arc;

pub use adapter::{adapter_for, AiError, ProviderAdapter, ProviderErrorBody, ProviderRequest};

/// One compiled provider: everything a request needs after the model
/// alias resolves, with the auth value already RESOLVED (DW-045
/// compile-time contract — validation resolved it once at publish;
/// re-resolution here keeps the runtime table self-sufficient and a
/// reload picks up rotated env/file values).
#[derive(Debug, Clone)]
pub struct CompiledProvider {
    pub name: String,
    pub kind: AiProviderKind,
    /// Name of the upstream that carries the transport.
    pub upstream: String,
    /// Resolved auth header pairs (name, value). SECRET: never logged,
    /// never echoed; the redaction walk in `config` covers config
    /// echoes and this value lives only here and on the wire.
    pub auth_headers: Vec<(String, String)>,
}

/// One routable provider/model pair (DW-076): a failover-chain member
/// or a canary version. `version` is the canary attribution label
/// (None for plain chain targets).
#[derive(Debug, Clone, PartialEq)]
pub struct RouteTarget {
    /// The provider NAME (lookup key into the provider pool).
    pub provider: String,
    /// The provider's own model identifier.
    pub provider_model: String,
    /// The canary version name this target serves, if any.
    pub version: Option<String>,
}

/// The compiled alias entry (DW-076): either a failover chain
/// (primary first), a canary split, or a routing policy (DW-085).
/// A policy alias composes over OTHER aliases' routing plans, so it
/// has no provider/model pair of its own — validation enforces that
/// `routing_policy` is mutually exclusive with `failover` and
/// `canary`.
#[derive(Debug, Clone)]
pub enum CompiledModel {
    /// `[primary, alternates...]` in config order.
    Chain(Vec<RouteTarget>),
    /// Weighted versions; the pick is deterministic per request id.
    Canary(Vec<(u32, RouteTarget)>),
    /// A routing policy (DW-085): within-request escalation or
    /// latency-vs-cost selection. The policy is evaluated per
    /// request (async — a FallbackChain policy may call an external
    /// classifier service).
    Policy(Arc<policy::CompiledRoutingPolicy>),
}

/// The per-generation compiled AI table (DW-075): the provider pool
/// with resolved credentials plus the model alias map. Built at
/// dataplane refresh from the published config; immutable once
/// built.
#[derive(Debug, Clone, Default)]
pub struct AiRuntime {
    providers: BTreeMap<String, CompiledProvider>,
    models: BTreeMap<String, CompiledModel>,
}

impl AiRuntime {
    /// Compile from the `ai:` config block. `None` when the block is
    /// absent (no AI surface). Secret references that fail to resolve
    /// here (a validate-vs-build race with the environment, or a file
    /// deleted since publish) fail the PROVIDER closed: the provider
    /// compiles without its auth header and every call to it will
    /// surface the provider's own 401 — the loud, attributable
    /// failure — while an error log records why.
    pub fn compile(cfg: Option<&AiConfig>) -> Option<AiRuntime> {
        let cfg = cfg?;
        let mut providers = BTreeMap::new();
        for p in &cfg.providers {
            let mut auth_headers = Vec::new();
            if let Some(auth) = &p.auth {
                match crate::config::credentials::resolve_configured_secret(&auth.value) {
                    Ok(value) => auth_headers.push((auth.header.clone(), value)),
                    Err(message) => tracing::error!(
                        code = "ai_provider_auth_unresolved",
                        provider = %p.name,
                        "ai provider auth could not be resolved at compile \
                         time; calls to this provider will be sent \
                         UNAUTHENTICATED and fail at the provider: {message}"
                    ),
                }
            }
            providers.insert(
                p.name.clone(),
                CompiledProvider {
                    name: p.name.clone(),
                    kind: p.kind,
                    upstream: p.upstream.clone(),
                    auth_headers,
                },
            );
        }
        // DW-085: two-pass compile. Policy aliases compose over plain
        // chain/canary aliases (they resolve named aliases to their
        // primary RouteTarget), so the plain aliases must be compiled
        // first. A policy alias cannot reference another policy alias
        // (nested policies are not allowed); the first pass skips
        // policy aliases, and the second pass compiles them against
        // the first-pass map.
        let mut first_pass: BTreeMap<String, CompiledModel> = BTreeMap::new();
        for (alias, m) in &cfg.models {
            if m.routing_policy.is_some() {
                continue;
            }
            first_pass.insert(alias.clone(), compile_model(m));
        }
        let mut models = first_pass.clone();
        for (alias, m) in &cfg.models {
            if let Some(policy_name) = &m.routing_policy {
                if let Some(policy_cfg) = cfg.routing_policies.get(policy_name) {
                    if let Some(compiled) =
                        policy::CompiledRoutingPolicy::compile(policy_name, policy_cfg, &first_pass)
                    {
                        models.insert(alias.clone(), CompiledModel::Policy(Arc::new(compiled)));
                    }
                }
            }
        }
        Some(AiRuntime { providers, models })
    }

    /// Resolve a model alias to its provider and provider model id
    /// (the DW-075 single-target view; failover lists and canary
    /// splits resolve to the same primary).
    pub fn resolve<'a>(&'a self, alias: &str) -> Option<(&'a CompiledProvider, &'a str)> {
        let target = self.primary_target(alias)?;
        let provider = self.providers.get(&target.provider)?;
        Some((provider, target.provider_model.as_str()))
    }

    /// The compiled model entry for an alias (routing introspection
    /// and tests).
    pub fn model(&self, alias: &str) -> Option<&CompiledModel> {
        self.models.get(alias)
    }

    /// Route one request (DW-076): the ordered candidate list to try.
    /// A canary alias yields exactly ONE candidate — the deterministic
    /// weighted pick for `pick_key` (the request id); a failover alias
    /// yields `[primary, alternates...]`. An empty result means the
    /// alias does not exist. Policy aliases (DW-085) return an empty
    /// list here — they need the async
    /// [`route_with_policy`](Self::route_with_policy) path (the
    /// classifier call is async). The sync `route` stays for tests
    /// and the non-policy dataplane path.
    pub fn route<'a>(&'a self, alias: &str, pick_key: &str) -> Vec<&'a RouteTarget> {
        match self.models.get(alias) {
            Some(CompiledModel::Chain(chain)) => chain.iter().collect(),
            Some(CompiledModel::Canary(versions)) => {
                vec![routing::weighted_pick(versions, pick_key)]
            }
            Some(CompiledModel::Policy(_)) => Vec::new(),
            None => Vec::new(),
        }
    }

    /// Route one request with policy evaluation (DW-085). Like
    /// [`route`](Self::route) but handles Policy variants by calling
    /// the async [`evaluate`](policy::CompiledRoutingPolicy::evaluate)
    /// method. Returns owned [`RouteTarget`]s (the policy path
    /// constructs them dynamically) plus an optional
    /// [`PolicyDecision`](policy::PolicyDecision) the dataplane records
    /// as a metric (None for non-policy models). For non-policy
    /// models, delegates to the sync routing logic. An empty result
    /// means the alias does not exist.
    pub async fn route_with_policy(
        &self,
        alias: &str,
        pick_key: &str,
        prompt_text: &str,
    ) -> (Vec<RouteTarget>, Option<policy::PolicyDecision>) {
        match self.models.get(alias) {
            Some(CompiledModel::Chain(chain)) => (chain.to_vec(), None),
            Some(CompiledModel::Canary(versions)) => (
                vec![routing::weighted_pick(versions, pick_key).clone()],
                None,
            ),
            Some(CompiledModel::Policy(policy)) => {
                let (targets, decision) = policy.evaluate(prompt_text).await;
                (targets, Some(decision))
            }
            None => (Vec::new(), None),
        }
    }

    /// The compiled provider by name.
    pub fn provider(&self, name: &str) -> Option<&CompiledProvider> {
        self.providers.get(name)
    }

    /// The primary target of an alias (first chain entry; the first
    /// canary version for split aliases — used by the DW-075
    /// single-target `resolve`).
    fn primary_target(&self, alias: &str) -> Option<&RouteTarget> {
        match self.models.get(alias)? {
            CompiledModel::Chain(chain) => chain.first(),
            CompiledModel::Canary(versions) => versions.first().map(|(_, t)| t),
            // A policy alias has no single primary target — it is
            // evaluated per request.
            CompiledModel::Policy(_) => None,
        }
    }

    /// Number of compiled providers (config introspection/tests).
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Number of model aliases (config introspection/tests).
    pub fn model_count(&self) -> usize {
        self.models.len()
    }
}

/// Compile one alias config entry into its routing plan (DW-076).
/// A canary list wins when present; otherwise the chain is
/// `[primary] + failover`.
fn compile_model(m: &crate::config::ai::AiModel) -> CompiledModel {
    if !m.canary.is_empty() {
        return CompiledModel::Canary(
            m.canary
                .iter()
                .map(|v| {
                    (
                        v.weight,
                        RouteTarget {
                            provider: v.provider.clone(),
                            provider_model: v.provider_model.clone(),
                            version: Some(v.version.clone()),
                        },
                    )
                })
                .collect(),
        );
    }
    let mut chain = vec![RouteTarget {
        provider: m.provider.clone(),
        provider_model: m.provider_model.clone(),
        version: None,
    }];
    chain.extend(m.failover.iter().map(|f| RouteTarget {
        provider: f.provider.clone(),
        provider_model: f.provider_model.clone(),
        version: None,
    }));
    CompiledModel::Chain(chain)
}
