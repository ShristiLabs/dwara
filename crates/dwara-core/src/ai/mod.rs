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
pub mod openai_compat;
pub mod routing;
pub mod sse;
pub mod stream;
pub mod types;

use crate::config::ai::{AiConfig, AiProviderKind};
use std::collections::BTreeMap;

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
/// (primary first) or a canary split, never both (validation).
#[derive(Debug, Clone)]
pub enum CompiledModel {
    /// `[primary, alternates...]` in config order.
    Chain(Vec<RouteTarget>),
    /// Weighted versions; the pick is deterministic per request id.
    Canary(Vec<(u32, RouteTarget)>),
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
        let models = cfg
            .models
            .iter()
            .map(|(alias, m)| (alias.clone(), compile_model(m)))
            .collect();
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
    /// alias does not exist.
    pub fn route<'a>(&'a self, alias: &str, pick_key: &str) -> Vec<&'a RouteTarget> {
        match self.models.get(alias) {
            Some(CompiledModel::Chain(chain)) => chain.iter().collect(),
            Some(CompiledModel::Canary(versions)) => {
                vec![routing::weighted_pick(versions, pick_key)]
            }
            None => Vec::new(),
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
