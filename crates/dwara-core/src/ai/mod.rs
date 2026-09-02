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
pub mod experiments;
pub mod governance;
pub mod guardrails;
pub mod logging;
pub mod mcp;
pub mod openai_compat;
pub mod policy;
pub mod redaction;
pub mod routing;
pub mod semantic_cache;
pub mod sse;
pub mod stream;
pub mod types;

use crate::config::ai::{AiConfig, AiProviderKind};
use crate::config::Gateway;
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
/// (primary first), a canary split, a routing policy (DW-085), or an
/// A/B test experiment (DW-086). A policy alias composes over OTHER
/// aliases' routing plans, so it has no provider/model pair of its
/// own — validation enforces that `routing_policy` is mutually
/// exclusive with `failover` and `canary`. An experiment alias
/// composes over OTHER aliases' routing plans too — validation
/// enforces that `ab_test` is mutually exclusive with `failover`,
/// `canary`, and `routing_policy`.
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
    /// An A/B test experiment (DW-086): two or more variants, each
    /// naming a model alias (and an optional prompt version). The
    /// experiment is evaluated per request (a deterministic weighted
    /// pick by request id selects a variant). Arc'd because the
    /// compiled test carries resolved targets and prompt messages.
    Experiment(Arc<experiments::CompiledAbTest>),
}

/// The per-generation compiled AI table (DW-075): the provider pool
/// with resolved credentials plus the model alias map. Built at
/// dataplane refresh from the published config; immutable once
/// built.
#[derive(Debug, Clone, Default)]
pub struct AiRuntime {
    providers: BTreeMap<String, CompiledProvider>,
    models: BTreeMap<String, CompiledModel>,
    /// The compiled MCP gateway (DW-087), built from the `ai.mcp`
    /// config block. None when the config has no `ai.mcp` block.
    mcp: Option<Arc<mcp::CompiledMcp>>,
}

impl AiRuntime {
    /// Compile from the `ai:` config block. `None` when the block is
    /// absent (no AI surface). Secret references that fail to resolve
    /// here (a validate-vs-build race with the environment, or a file
    /// deleted since publish) fail the PROVIDER closed: the provider
    /// compiles without its auth header and every call to it will
    /// surface the provider's own 401 — the loud, attributable
    /// failure — while an error log records why.
    pub fn compile(cfg: Option<&AiConfig>, gateway: &Gateway) -> Option<AiRuntime> {
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
        // DW-085/DW-086: three-pass compile. Policy aliases and
        // experiment aliases compose over plain chain/canary aliases
        // (they resolve named aliases to their primary RouteTarget),
        // so the plain aliases must be compiled first. A policy alias
        // cannot reference another policy alias (nested policies are
        // not allowed); an experiment alias cannot reference another
        // experiment alias (nested experiments are not allowed). The
        // first pass skips policy and experiment aliases, the second
        // pass compiles policy aliases against the first-pass map,
        // and the third pass compiles experiment aliases against the
        // first-pass map (experiment variants reference plain
        // aliases only, not policy aliases).
        let mut first_pass: BTreeMap<String, CompiledModel> = BTreeMap::new();
        for (alias, m) in &cfg.models {
            if m.routing_policy.is_some() || m.ab_test.is_some() {
                continue;
            }
            first_pass.insert(alias.clone(), compile_model(m));
        }
        // Second pass: policy aliases.
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
        // Third pass: experiment aliases.
        for (alias, m) in &cfg.models {
            if let Some(test_name) = &m.ab_test {
                if let Some(experiments_cfg) = &cfg.experiments {
                    if let Some(test_cfg) = experiments_cfg.ab_tests.get(test_name) {
                        if let Some(compiled) = experiments::CompiledAbTest::compile(
                            test_name,
                            test_cfg,
                            &first_pass,
                            Some(experiments_cfg),
                        ) {
                            models.insert(
                                alias.clone(),
                                CompiledModel::Experiment(Arc::new(compiled)),
                            );
                        }
                    }
                }
            }
        }
        // DW-087: compile the MCP gateway (tools, sessions, path).
        let mcp = cfg
            .mcp
            .as_ref()
            .and_then(|mcp_cfg| mcp::CompiledMcp::compile(mcp_cfg, gateway))
            .map(Arc::new);
        Some(AiRuntime {
            providers,
            models,
            mcp,
        })
    }

    /// The compiled MCP gateway (DW-087); None when no `ai.mcp` block.
    pub fn mcp(&self) -> Option<&Arc<mcp::CompiledMcp>> {
        self.mcp.as_ref()
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
    /// alias does not exist. Policy aliases (DW-085) and experiment
    /// aliases (DW-086) return an empty list here — they need the
    /// async [`route_with_policy`](Self::route_with_policy) path (the
    /// classifier call is async for policies; the experiment pick is
    /// sync but returns an [`experiments::ExperimentDecision`] the dataplane
    /// records). The sync `route` stays for tests and the non-policy
    /// dataplane path.
    pub fn route<'a>(&'a self, alias: &str, pick_key: &str) -> Vec<&'a RouteTarget> {
        match self.models.get(alias) {
            Some(CompiledModel::Chain(chain)) => chain.iter().collect(),
            Some(CompiledModel::Canary(versions)) => {
                vec![routing::weighted_pick(versions, pick_key)]
            }
            Some(CompiledModel::Policy(_)) => Vec::new(),
            Some(CompiledModel::Experiment(_)) => Vec::new(),
            None => Vec::new(),
        }
    }

    /// DW-091: like [`route`](Self::route) but for canary aliases the
    /// single picked candidate carries its INDEX (0 = baseline, 1 =
    /// canary for a 2-version canary split). The auto-canary
    /// controller needs the index to record the outcome on the
    /// correct side. Returns `(candidates, canary_index)` where
    /// `canary_index` is `Some(idx)` only for canary aliases.
    pub fn route_with_canary_index<'a>(
        &'a self,
        alias: &str,
        pick_key: &str,
    ) -> (Vec<&'a RouteTarget>, Option<usize>) {
        match self.models.get(alias) {
            Some(CompiledModel::Chain(chain)) => (chain.iter().collect(), None),
            Some(CompiledModel::Canary(versions)) => {
                let (target, idx) = routing::weighted_pick_with_index(versions, pick_key);
                (vec![target], Some(idx))
            }
            Some(CompiledModel::Policy(_)) => (Vec::new(), None),
            Some(CompiledModel::Experiment(_)) => (Vec::new(), None),
            None => (Vec::new(), None),
        }
    }

    /// Route one request with policy/experiment evaluation (DW-085 /
    /// DW-086). Like [`route`](Self::route) but handles Policy
    /// variants by calling the async
    /// [`evaluate`](policy::CompiledRoutingPolicy::evaluate) method,
    /// and Experiment variants by doing the deterministic weighted
    /// pick. Returns owned [`RouteTarget`]s plus an optional
    /// [`PolicyDecision`](policy::PolicyDecision) the dataplane
    /// records as a metric (None for non-policy models). For
    /// experiment models, the [`experiments::ExperimentDecision`] is returned
    /// separately via [`route_experiment`](Self::route_experiment).
    /// For non-policy/non-experiment models, delegates to the sync
    /// routing logic. An empty result means the alias does not exist.
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
            Some(CompiledModel::Experiment(test)) => {
                let variant = test.pick(pick_key);
                (vec![variant.target.clone()], None)
            }
            None => (Vec::new(), None),
        }
    }

    /// DW-091: like [`route_with_policy`](Self::route_with_policy) but
    /// also returns the canary index (0 = baseline, 1 = canary for a
    /// 2-version canary split) when the alias is a canary alias. The
    /// auto-canary controller needs the index to record the outcome
    /// on the correct side. Returns `(candidates, policy_decision,
    /// canary_index)`.
    pub async fn route_with_policy_and_canary_index(
        &self,
        alias: &str,
        pick_key: &str,
        prompt_text: &str,
    ) -> (
        Vec<RouteTarget>,
        Option<policy::PolicyDecision>,
        Option<usize>,
    ) {
        match self.models.get(alias) {
            Some(CompiledModel::Chain(chain)) => (chain.to_vec(), None, None),
            Some(CompiledModel::Canary(versions)) => {
                let (target, idx) = routing::weighted_pick_with_index(versions, pick_key);
                (vec![target.clone()], None, Some(idx))
            }
            Some(CompiledModel::Policy(policy)) => {
                let (targets, decision) = policy.evaluate(prompt_text).await;
                (targets, Some(decision), None)
            }
            Some(CompiledModel::Experiment(test)) => {
                let variant = test.pick(pick_key);
                (vec![variant.target.clone()], None, None)
            }
            None => (Vec::new(), None, None),
        }
    }

    /// Route one request for an experiment alias (DW-086): the
    /// deterministic weighted pick selects a variant, returning the
    /// [`RouteTarget`] and the [`experiments::ExperimentDecision`] for analytics
    /// attribution. Returns None when the alias is not an experiment
    /// alias or does not exist.
    pub fn route_experiment(
        &self,
        alias: &str,
        pick_key: &str,
    ) -> Option<(RouteTarget, experiments::ExperimentDecision)> {
        match self.models.get(alias)? {
            CompiledModel::Experiment(test) => {
                let variant = test.pick(pick_key);
                Some((
                    variant.target.clone(),
                    experiments::ExperimentDecision {
                        experiment: test.name.clone(),
                        variant: variant.name.clone(),
                        model: variant.target.provider_model.clone(),
                    },
                ))
            }
            _ => None,
        }
    }

    /// The compiled experiment for an alias (introspection/tests).
    pub fn experiment(&self, alias: &str) -> Option<&Arc<experiments::CompiledAbTest>> {
        match self.models.get(alias)? {
            CompiledModel::Experiment(test) => Some(test),
            _ => None,
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
            // An experiment alias has no single primary target — it
            // is evaluated per request (the variant pick).
            CompiledModel::Experiment(_) => None,
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

    /// DW-091: rebuild the canary split for `alias` with new weights
    /// and return a new runtime with the replacement. The providers
    /// and other models are shared (Arc bump / clone). `new_weights`
    /// is the new weight per canary version in config order (baseline
    /// first, canary second for a 2-version canary). The total weight
    /// MUST stay constant (the caller enforces this). Returns `None`
    /// when the alias is not a canary alias or the weight count does
    /// not match the version count.
    pub fn with_rebuilt_canary(&self, alias: &str, new_weights: &[u32]) -> Option<AiRuntime> {
        let model = self.models.get(alias)?;
        let CompiledModel::Canary(versions) = model else {
            return None;
        };
        if new_weights.len() != versions.len() {
            return None;
        }
        let new_versions: Vec<(u32, RouteTarget)> = versions
            .iter()
            .zip(new_weights.iter())
            .map(|((_, target), w)| (*w, target.clone()))
            .collect();
        let mut new_models = self.models.clone();
        new_models.insert(alias.to_string(), CompiledModel::Canary(new_versions));
        Some(AiRuntime {
            providers: self.providers.clone(),
            models: new_models,
            mcp: self.mcp.clone(),
        })
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
