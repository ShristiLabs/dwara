//! The `ai:` configuration block (DW-075): AI provider adapters.
//!
//! This is the source shape only — the runtime translation lives in the
//! AI domain one level up (see the `ai` module's `AiRuntime`), which
//! consumes these types at compile time. The block is ADDITIVE to the
//! gateway schema: absent (the default), the gateway has no AI surface
//! at all; present, it declares the provider pool (`providers:`) and
//! the model alias table (`models:`) that map an OpenAI-shaped client
//! request onto a concrete provider call.
//!
//! Design notes (DW-075):
//!
//! - A provider names an UPSTREAM (`upstreams:` entry), not a raw base
//!   URL: the provider's transport — endpoint set, TLS trust, connection
//!   pooling, timeouts, breaker, passive health — is the SAME machinery
//!   every other upstream gets, and the adapter layer stays pure
//!   request/response translation with no HTTP client of its own. A
//!   multi-region provider pool is then just an upstream with several
//!   endpoints.
//! - Authentication is a verbatim header (`auth.header` + `auth.value`)
//!   rather than a per-provider auth enum: providers disagree on the
//!   convention (OpenAI wants `Authorization: Bearer ...`, Anthropic
//!   `x-api-key: ...`, Gemini `x-goog-api-key: ...`), and a verbatim
//!   pair expresses all of them without the schema growing a variant
//!   per provider. `value` is secret-bearing: inline values are
//!   redacted in every config echo (DW-045) and `${...}` references
//!   resolve at config-compile time, failing the generation closed when
//!   unresolvable.
//! - `models:` is a map from the MODEL ALIAS the client names in the
//!   request body to the provider that serves it plus the provider's own
//!   model identifier. The alias is what the gateway echoes back in the
//!   response; the provider model never leaks to the client.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The `ai:` top-level block (DW-075). Absent: no AI surface. Present:
/// validation requires at least one provider and at least one model —
/// an `ai:` block that can never serve a model is an authoring error,
/// not a silently inert config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiConfig {
    /// The provider pool. Each entry names an upstream that carries the
    /// transport and the adapter `kind` that carries the wire translation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<AiProvider>,
    /// Model alias table: the `model` value a client puts in its request
    /// body maps to the provider that serves it and the provider's own
    /// model identifier. The alias is echoed back to the client; the
    /// `provider_model` never leaves the gateway.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub models: BTreeMap<String, AiModel>,
}

/// One AI provider (DW-075 `ai.providers[]`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiProvider {
    /// Provider name; unique within the `ai:` block. Referenced by
    /// `ai.models[].provider`.
    pub name: String,
    /// Wire-protocol adapter kind. Selects the request/response
    /// translation applied to every call routed to this provider.
    pub kind: AiProviderKind,
    /// Name of the `upstreams:` entry that carries this provider's
    /// transport (endpoints, TLS trust, pooling, timeouts, breaker).
    /// The adapter builds provider-specific paths; the endpoint's
    /// authority becomes the dialed host, exactly like a proxy route.
    pub upstream: String,
    /// Authentication attached to every call to this provider: a
    /// verbatim header. Optional — a provider behind an internal network
    /// (a self-hosted gateway fronting an Ollama-style endpoint, for
    /// example) may need none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AiProviderAuth>,
}

/// The wire protocol an adapter speaks (DW-075).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AiProviderKind {
    /// OpenAI chat-completions API (`POST /v1/chat/completions`). Also
    /// the dialect spoken by OpenAI-compatible servers (vLLM, Ollama's
    /// compatibility endpoint, and others) — point the upstream at one
    /// of those and this adapter speaks to it unchanged.
    Openai,
    /// Anthropic messages API (`POST /v1/messages`).
    Anthropic,
    /// Google Gemini `generateContent` API
    /// (`POST /v1beta/models/{model}:generateContent`).
    Gemini,
}

/// Verbatim authentication header for a provider (DW-075
/// `ai.providers[].auth`). `value` is SECRET-BEARING: an inline value is
/// replaced by the redaction placeholder in every config echo, and a
/// `${...}` reference is resolved at config-compile time (DW-045).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiProviderAuth {
    /// Header name (e.g. `Authorization`, `x-api-key`,
    /// `x-goog-api-key`). Must be a valid HTTP header name.
    pub header: String,
    /// Header value, verbatim (e.g. `Bearer ${OPENAI_API_KEY}` —
    /// reference resolution covers the whole value, so the `Bearer `
    /// prefix belongs INSIDE the referenced variable or the literal).
    /// Inline values are redacted in config echoes; never logged.
    pub value: String,
}

/// One model alias mapping (DW-075 `ai.models{alias}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiModel {
    /// Name of the `ai.providers[]` entry that serves this alias.
    pub provider: String,
    /// The provider's own model identifier (e.g. `gpt-4o-mini`,
    /// `claude-sonnet-4-5`, `gemini-2.5-flash`), sent to the provider
    /// in place of the alias.
    pub provider_model: String,
    /// Ordered failover chain (DW-076): when the primary target
    /// answers 429 or a 5xx, or its transport errors, the gateway
    /// retries the next entry — a DIFFERENT provider/model pair, never
    /// a re-send to the provider that just failed (its upstream's
    /// breaker owns same-provider retries). The client sees one
    /// response. Absent (the default): no failover, the primary's
    /// answer is final. Cannot be combined with `canary` on the same
    /// alias (validation rejects the pairing): failover is an
    /// availability chain for a single logical model; a canary split
    /// is deliberately serving multiple versions at once — mixing the
    /// two would retry a canary request onto the stable version and
    /// silently undo the experiment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failover: Vec<AiModelTarget>,
    /// Weighted canary split (DW-076): traffic for this alias
    /// distributes across the listed versions by a deterministic
    /// weighted hash of the request id (the same slot semantics as
    /// traffic splitting: ratios hold per request, and re-sending a
    /// request with the same id lands on the same version). Each
    /// version names exactly one provider/model pair and carries no
    /// failover of its own. Absent (the default): no split. Cannot be
    /// combined with `failover` on the same alias.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub canary: Vec<AiCanaryVersion>,
}

/// One provider/model pair an alias can route to (DW-076): the primary
/// shape reused by failover entries and canary versions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiModelTarget {
    /// Name of the `ai.providers[]` entry.
    pub provider: String,
    /// The provider's own model identifier.
    pub provider_model: String,
}

/// One weighted version of a canary split (DW-076
/// `ai.models.<alias>.canary[]`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiCanaryVersion {
    /// Version name — the analytics/metrics attribution label for
    /// requests this version served. Unique within the alias; bounded
    /// label (config entity).
    pub version: String,
    /// Relative weight (>= 1). A weight of 0 is not allowed here (the
    /// split machinery parks traffic by RE-BALANCING weights, and a
    /// zero-weight canary entry that still exists would read as
    /// coverage it does not have) — remove the entry to park it.
    pub weight: u32,
    /// Name of the `ai.providers[]` entry serving this version.
    pub provider: String,
    /// The provider's own model identifier for this version.
    pub provider_model: String,
}
