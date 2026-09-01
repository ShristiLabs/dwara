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
pub mod openai_compat;
pub mod sse;
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

/// The per-generation compiled AI table (DW-075): the provider pool
/// with resolved credentials plus the model alias map. Built at
/// dataplane refresh from the published config; immutable once
/// built.
#[derive(Debug, Clone, Default)]
pub struct AiRuntime {
    providers: BTreeMap<String, CompiledProvider>,
    models: BTreeMap<String, (String, String)>,
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
            .map(|(alias, m)| {
                (
                    alias.clone(),
                    (m.provider.clone(), m.provider_model.clone()),
                )
            })
            .collect();
        Some(AiRuntime { providers, models })
    }

    /// Resolve a model alias to its provider and provider model id.
    pub fn resolve<'a>(&'a self, alias: &str) -> Option<(&'a CompiledProvider, &'a str)> {
        let (provider_name, provider_model) = self.models.get(alias)?;
        let provider = self.providers.get(provider_name)?;
        Some((provider, provider_model.as_str()))
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
