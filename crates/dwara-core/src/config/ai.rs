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

/// Serde skip helper: elide `audit` when false (the default).
fn is_false(b: &bool) -> bool {
    !*b
}

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
    /// Per-model pricing table (DW-079): the key is the PROVIDER MODEL
    /// identifier (the actual model the provider charges for, e.g.
    /// `gpt-4o-mini`), NOT the client-facing alias. Costs are integer
    /// micro-USD per 1 000 tokens (1 000 000 micro-USD = $1.00 — no
    /// floating-point money). Spend = usage x price, aggregated per
    /// key/team/model (DW-079). Absent (the default): no pricing, so
    /// cost attribution records zero cost (the budget cost window and
    /// the spend store stay live but inert until prices are declared).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pricing: BTreeMap<String, AiPricing>,
    /// Model governance (DW-084): per-team (policy) model allowlists
    /// and the shadow-audit switch. Absent (the default): no
    /// governance — every consumer may call every configured alias,
    /// and no governance audit events are recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance: Option<AiGovernance>,
    /// Prompt/response logging (DW-081): opt-in capture of the
    /// canonical prompt and response with PII redaction, sampling,
    /// and retention. Absent (the default): no capture — privacy-first
    /// (no prompt or response text is ever stored). When present and
    /// `enabled: true`, a redaction pass scrubs PII/secrets before
    /// storage, `sample_rate` controls volume, and `retention_secs`
    /// ages records out. Per-consumer `ai_logging` overrides respect
    /// tenant preference (see [`crate::config::Consumer::ai_logging`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging: Option<AiLogging>,
    /// Guardrails (DW-082): prompt-injection heuristics, PII
    /// detection, banned-content filters, and output schema
    /// enforcement as a middleware chain on the AI proxy action.
    /// Absent (the default): no guardrails — every prompt and
    /// response passes through uninspected. When present, each rule
    /// inspects the prompt (before the provider call) and/or the
    /// response (after), and blocks, redacts, or logs per its
    /// `action`. Policy-scoped rules apply only to consumers
    /// attaching a listed policy; an empty `policies` list applies
    /// to all. Schema enforcement requires the `openapi_validation`
    /// cargo feature (jsonschema); without it, schema rules are
    /// accepted but inert.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guardrails: Option<AiGuardrails>,
    /// Semantic cache (DW-083 `ai.semantic_cache`): an
    /// embedding-similarity cache for AI prompts. A paraphrased
    /// prompt within the cosine-similarity threshold returns the
    /// cached response with no provider call and no token spend.
    /// Uses an external embedding service (OpenAI-compatible
    /// /v1/embeddings API) and a pure-Rust HNSW ANN index
    /// (`hnsw_rs`). Feature-gated behind the `semantic_cache` cargo
    /// feature; without it the config is accepted but the cache is a
    /// no-op. Absent (the default): no semantic cache.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_cache: Option<SemanticCacheConfig>,
    /// Routing policies (DW-085 `ai.routing_policies`): named
    /// within-request escalation or latency-vs-cost selection plans,
    /// keyed by name. A model alias declares `routing_policy: <name>`
    /// to be served by one; the policy is evaluated per request (a
    /// FallbackChain policy may call an external classifier service;
    /// a LatencyCost policy picks deterministically at compile time).
    /// Absent (the default): no routing policies.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub routing_policies: BTreeMap<String, AiRoutingPolicy>,
}

/// Model governance (DW-084 `ai.governance`): per-team model
/// allowlists plus a shadow-audit switch. A team is a POLICY name
/// (the same vocabulary the token budgets use for `scope: policy`):
/// every consumer attaching a policy with an allowlist entry is
/// restricted to that allowlist's aliases. The check runs BEFORE
/// routing, against the client-facing alias (the `model` value in
/// the request body), so a typo or a renamed alias is blocked at the
/// edge rather than surfacing as a provider 404. Multiple policies
/// with allowlists that bind one request intersect (deny-wins): the
/// model must be in EVERY binding allowlist, matching the authz
/// deny-anywhere-wins principle. Consumers with no binding allowlist
/// policy are unrestricted (fail-open, the DW-017 default posture).
/// `audit: true` records BOTH allowed and denied attempts into the
/// `ai_governance_events` analytics table for shadow review.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiGovernance {
    /// Per-policy (team) model allowlists. The key is the POLICY name
    /// (the team), the value is the list of allowed client-facing
    /// model aliases. A consumer attaching a policy listed here may
    /// only call the aliases in its allowlist; a consumer attaching
    /// no listed policy is unrestricted. Validation rejects an
    /// allowlist entry that names an alias absent from `ai.models`
    /// (an authoring error, not a runtime 404).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub team_allowlists: BTreeMap<String, Vec<String>>,
    /// When true, record model usage for shadow audit: BOTH allowed
    /// calls and denied attempts land in the `ai_governance_events`
    /// analytics table (the admin `/analytics/governance-audit`
    /// endpoint reads it). When false (the default), only the
    /// denial metric fires — no per-event audit rows are written.
    #[serde(default, skip_serializing_if = "is_false")]
    pub audit: bool,
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
    /// A routing policy name (DW-085): when set, this alias is served
    /// by the named entry in `ai.routing_policies` instead of a plain
    /// failover chain or canary split. The policy is evaluated per
    /// request (a FallbackChain policy may call an external classifier
    /// service to decide cheap-vs-expensive; a LatencyCost policy
    /// picks deterministically). Cannot be combined with `failover`
    /// or `canary` on the same alias (validation enforces mutual
    /// exclusivity): a policy alias composes over OTHER aliases'
    /// routing plans, so it has no primary provider/model pair of its
    /// own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing_policy: Option<String>,
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

/// Per-model token pricing (DW-079 `ai.pricing.<provider_model>`).
/// Costs are integer MICRO-USD per 1 000 tokens (1 000 000 micro-USD =
/// $1.00 — no floating-point money). The key in the parent map is the
/// PROVIDER MODEL identifier (the actual model the provider charges
/// for), not the client-facing alias. Spend is computed as
/// `input_tokens * input_per_1k_micros / 1000 + output_tokens *
/// output_per_1k_micros / 1000` (integer micro-USD, saturating).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiPricing {
    /// Micro-USD per 1 000 input (prompt) tokens.
    pub input_per_1k_micros: u64,
    /// Micro-USD per 1 000 output (completion) tokens.
    pub output_per_1k_micros: u64,
}

/// Default sampling rate: capture all when enabled (1.0).
fn default_sample_rate() -> f64 {
    1.0
}

/// Default retention: 7 days in seconds (604800).
fn default_retention_secs() -> u64 {
    604_800
}

/// Default redaction replacement string.
fn default_replacement() -> String {
    "[REDACTED]".to_string()
}

/// Prompt/response logging (DW-081 `ai.logging`): opt-in capture of
/// the canonical prompt and response with PII redaction, sampling,
/// and retention. Capture is OFF by default (privacy-first): the
/// `enabled` field defaults to false, so an `ai.logging` block
/// without `enabled: true` captures nothing. When on, a redaction
/// pass scrubs PII/secrets before storage, `sample_rate` controls
/// volume, and `retention_secs` ages records out. Per-consumer
/// `ai_logging` overrides respect tenant preference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiLogging {
    /// Master switch. Default false (privacy-first): no prompt or
    /// response text is stored unless this is explicitly true.
    #[serde(default)]
    pub enabled: bool,
    /// Sampling rate 0.0..=1.0. Default 1.0 (capture all when
    /// enabled). The sample decision is deterministic per request
    /// (a hash of the request id), so a re-send with the same id
    /// lands on the same decision.
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,
    /// Retention in seconds. Records older than this are deleted by
    /// the analytics maintenance tick. Default 7 days (604800).
    #[serde(default = "default_retention_secs")]
    pub retention_secs: u64,
    /// PII redaction patterns. Built-in defaults (emails, phone
    /// numbers, API keys, credit card numbers) are always active
    /// when redaction is on; custom patterns are added to the set.
    #[serde(default)]
    pub redaction: RedactionConfig,
}

/// PII redaction configuration (DW-081 `ai.logging.redaction`).
/// Built-in patterns scrub common PII/secrets; custom patterns add
/// deployment-specific scrubbing. All patterns are compiled into a
/// single `regex::RegexSet` for one-pass efficiency.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RedactionConfig {
    /// Additional regex patterns to scrub (beyond the built-in
    /// defaults). Each is a Rust `regex` crate pattern; invalid
    /// patterns fail validation at publish time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<String>,
    /// Replacement string for redacted content. Default
    /// `"[REDACTED]"`.
    #[serde(default = "default_replacement")]
    pub replacement: String,
}

/// Guardrails (DW-082 `ai.guardrails`): a list of rules that inspect
/// prompts and responses for prompt-injection, PII, banned content,
/// and output schema conformance. Each rule is one check applied at
/// the prompt phase (before the provider call) and/or the response
/// phase (after). Policy-scoped rules apply only to consumers
/// attaching a listed policy; an empty `policies` list applies to
/// all. See [`AiGuardrailRule`] for the per-rule shape.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiGuardrails {
    /// Guardrail rules. Each rule is one check applied to prompts
    /// and/or responses, in declaration order. Rule names must be
    /// unique (validation rejects duplicates).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<AiGuardrailRule>,
}

/// One guardrail rule (DW-082 `ai.guardrails.rules[]`). A rule
/// declares a `kind` (what to check), an `action` (what to do on a
/// match), a `phase` (prompt, response, or both), the patterns or
/// schema to check against, and the policies it attaches to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiGuardrailRule {
    /// Rule name (for logging/metrics attribution). Must be unique
    /// within the guardrails block (validation rejects duplicates).
    pub name: String,
    /// Guardrail kind: what the rule checks.
    pub kind: AiGuardrailKind,
    /// Action on match: `block` (return an error to the client),
    /// `redact` (scrub the match and continue — prompt phase only),
    /// or `log` (observe only, dry-run — the request proceeds).
    pub action: AiGuardrailAction,
    /// When to apply: `prompt` (before the provider call), `response`
    /// (after), or `both`. Default `both`.
    #[serde(default = "default_guardrail_phase")]
    pub phase: AiGuardrailPhase,
    /// Patterns for injection/pii/banned kinds (regex strings). Each
    /// is a Rust `regex` crate pattern; invalid patterns fail
    /// validation at publish time. For `pii` kind, the built-in PII
    /// patterns (email, phone, API key, credit card) are always
    /// active alongside any custom patterns declared here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<String>,
    /// JSON schema for output schema enforcement (`schema` kind
    /// only). The response content (parsed as JSON) is validated
    /// against this schema; a violation blocks the response.
    /// Requires the `openapi_validation` cargo feature (jsonschema);
    /// without it, schema rules are accepted but inert.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<serde_json::Value>,
    /// Policy names this rule attaches to. Empty (the default) means
    /// the rule applies to ALL consumers. When non-empty, the rule
    /// applies only to consumers whose attached policies (the
    /// consumer > route > service > listener > global chain) include
    /// at least one listed name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<String>,
}

/// The default guardrail phase: `both`.
fn default_guardrail_phase() -> AiGuardrailPhase {
    AiGuardrailPhase::Both
}

/// Guardrail kind (DW-082 `ai.guardrails.rules[].kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AiGuardrailKind {
    /// Prompt-injection heuristics: pattern matching for common
    /// injection attempts ("ignore previous instructions", role
    /// injection, instruction override). Applied at the prompt
    /// phase.
    Injection,
    /// PII detection: the built-in PII patterns (email, phone, API
    /// key, credit card) plus any custom patterns. Applied at the
    /// prompt phase; `redact` action scrubs the PII before the
    /// provider call.
    Pii,
    /// Banned-content filter: pattern matching against a banned
    /// content list. Applied at the prompt and/or response phase per
    /// the rule's `phase`.
    Banned,
    /// Output schema enforcement: the response content is validated
    /// against the declared JSON schema. Applied at the response
    /// phase (non-streaming only — streaming cannot validate a
    /// schema on partial content). Requires the
    /// `openapi_validation` cargo feature.
    Schema,
}

/// Guardrail action (DW-082 `ai.guardrails.rules[].action`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AiGuardrailAction {
    /// Block the request/response: return a 400 error to the client
    /// with code `guardrail_blocked` (prompt) or
    /// `response_schema_violation` / `guardrail_blocked` (response).
    Block,
    /// Redact the match and continue: scrub the PII/banned content
    /// from the prompt before the provider call. Prompt phase only.
    Redact,
    /// Log only (dry-run): record the match but allow the request
    /// through. Use to tune thresholds before switching to `block`.
    Log,
}

/// Guardrail phase (DW-082 `ai.guardrails.rules[].phase`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AiGuardrailPhase {
    /// Apply at the prompt phase (before the provider call).
    Prompt,
    /// Apply at the response phase (after the provider call, before
    /// the response is returned to the client).
    Response,
    /// Apply at both phases.
    Both,
}

/// Default semantic-cache cosine-similarity threshold: 0.85.
fn default_semantic_cache_threshold() -> f64 {
    0.85
}

/// Default semantic-cache TTL: 1 hour (3600 s).
fn default_semantic_cache_ttl() -> u64 {
    3600
}

/// Default semantic-cache max entries: 10 000.
fn default_semantic_cache_max_entries() -> usize {
    10_000
}

/// Default semantic-cache embedding-service timeout: 5 s (5000 ms).
fn default_semantic_cache_embedding_timeout_ms() -> u64 {
    5000
}

/// Semantic cache config (DW-083 `ai.semantic_cache`): an
/// embedding-similarity cache for AI prompts. A paraphrased prompt
/// within the cosine-similarity threshold returns the cached response
/// with no provider call and no token spend. Uses an external
/// embedding service (OpenAI-compatible /v1/embeddings API) to
/// vectorize prompts and `hnsw_rs` (pure Rust HNSW) for approximate
/// nearest neighbor search. Feature-gated behind the
/// `semantic_cache` cargo feature; without it the config is accepted
/// but the cache is a no-op.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SemanticCacheConfig {
    /// Whether the semantic cache is enabled. Default false: an
    /// `ai.semantic_cache` block without `enabled: true` caches
    /// nothing (the engine compiles but stays inert).
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,
    /// The URL of the external embedding service (OpenAI-compatible
    /// /v1/embeddings API). Required when enabled. Validation
    /// rejects an empty or non-http(s) URL.
    pub embedding_url: String,
    /// The model name passed to the embedding service in the
    /// `model` field of the POST body.
    pub embedding_model: String,
    /// The dimension of the embedding vectors. Must match what the
    /// embedding service returns for the configured model;
    /// validation rejects 0.
    pub embedding_dim: usize,
    /// Cosine similarity threshold (0.0 to 1.0, inclusive). A cached
    /// entry is returned only if its cosine similarity to the query
    /// embedding is >= this threshold. Higher = stricter matching
    /// (fewer hits, more accurate). Default 0.85.
    #[serde(default = "default_semantic_cache_threshold")]
    pub threshold: f64,
    /// TTL for cached entries in seconds. Entries older than this are
    /// considered stale and not returned. Default 3600 (1 hour).
    #[serde(default = "default_semantic_cache_ttl")]
    pub ttl_secs: u64,
    /// Maximum number of entries to cache. When the cache is full,
    /// it is reset (all entries evicted, the HNSW index rebuilt).
    /// Default 10 000.
    #[serde(default = "default_semantic_cache_max_entries")]
    pub max_entries: usize,
    /// Timeout for the embedding service HTTP call in milliseconds.
    /// Default 5000 (5 seconds).
    #[serde(default = "default_semantic_cache_embedding_timeout_ms")]
    pub embedding_timeout_ms: u64,
    /// Optional API key for the embedding service (sent as
    /// `Authorization: Bearer <key>`). Can be a `${...}` secret
    /// reference (resolved at config-compile time). Inline values
    /// are redacted in config echoes; never logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_api_key: Option<String>,
}

// -------------------------------------------------------------------------
// DW-085: routing policies (fallback chains + latency-cost selection).
// -------------------------------------------------------------------------

/// Default classifier complexity threshold: 0.5.
fn default_classifier_threshold() -> f64 {
    0.5
}

/// Default classifier HTTP timeout: 1000 ms.
fn default_classifier_timeout_ms() -> u64 {
    1000
}

/// A routing policy (DW-085 `ai.routing_policies.<name>`):
/// within-request escalation or latency-vs-cost selection. Keyed by
/// name in `ai.routing_policies`. An alias declares
/// `routing_policy: <name>` to be served by one; the policy is
/// evaluated per request and composes over DW-076 routing (the
/// candidate aliases it names are themselves plain chain/canary
/// aliases). Internally tagged by `kind` so the YAML shape is:
///
/// ```yaml
/// routing_policies:
///   my-policy:
///     kind: fallback_chain
///     cheap: cheap-model
///     escalate_to: expensive-model
///     classifier_url: http://...
///     classifier_model: complexity
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum AiRoutingPolicy {
    /// Cheap-model-first with complexity-signal escalation (DW-085).
    /// Calls an external classifier service to estimate prompt
    /// complexity; simple prompts (score < threshold) use the cheap
    /// model, complex prompts (score >= threshold) escalate to the
    /// costlier model. On classifier error, fails open to the cheap
    /// model (the safe default).
    FallbackChain(AiFallbackChainPolicy),
    /// Latency-vs-cost routing (DW-085): static config-based
    /// selection. The operator declares cost/latency scores per
    /// candidate and a preference; the policy picks deterministically
    /// at compile time (no runtime metrics needed).
    LatencyCost(AiLatencyCostPolicy),
}

/// A fallback-chain routing policy (DW-085 `kind: fallback_chain`):
/// cheap-model-first with complexity-signal escalation. The
/// `cheap` and `escalate_to` fields name OTHER model aliases (plain
/// chain/canary aliases — a policy composes over DW-076 routing, so
/// it has no provider/model pair of its own).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiFallbackChainPolicy {
    /// The model alias to use for simple prompts (the cheap model).
    /// Must reference an existing alias in `ai.models` (validation
    /// rejects a typo at publish time).
    pub cheap: String,
    /// The model alias to escalate to for complex prompts. Must
    /// reference an existing alias in `ai.models`.
    pub escalate_to: String,
    /// The URL of the external classifier service. The service must
    /// accept a POST with `{"model": "...", "input": "..."}` and
    /// return `{"data": [{"score": 0.0-1.0}]}` (the OpenAI-compatible
    /// embeddings response shape, with `score` in place of
    /// `embedding`). Validation rejects an empty or non-http(s) URL.
    pub classifier_url: String,
    /// The model name to pass to the classifier service in the
    /// `model` field of the POST body.
    pub classifier_model: String,
    /// Complexity score threshold (0.0 to 1.0, inclusive). A score
    /// at or above the threshold triggers escalation to the costlier
    /// model; a score below the threshold uses the cheap model.
    /// Default 0.5.
    #[serde(default = "default_classifier_threshold")]
    pub threshold: f64,
    /// Timeout for the classifier HTTP call in milliseconds. Default
    /// 1000 (1 second). Validation rejects 0.
    #[serde(default = "default_classifier_timeout_ms")]
    pub timeout_ms: u64,
    /// Optional API key for the classifier service (sent as
    /// `Authorization: Bearer <key>`). Can be a `${...}` secret
    /// reference (resolved at config-compile time). Inline values
    /// are redacted in config echoes; never logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
}

/// A latency-vs-cost routing policy (DW-085 `kind: latency_cost`):
/// static config-based selection. The operator declares cost/latency
/// scores per candidate and a preference; the policy sorts candidates
/// at compile time and picks the best one deterministically (no
/// runtime metrics needed).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiLatencyCostPolicy {
    /// The candidate models with their cost/latency scores. Each
    /// `model` must reference an existing alias in `ai.models`.
    /// Validation rejects an empty list.
    pub candidates: Vec<AiLatencyCostCandidate>,
    /// The selection preference: `cost` (cheapest), `latency`
    /// (fastest), or `balanced` (best cost/latency sum).
    pub preference: AiLatencyPreference,
}

/// One candidate in a latency-vs-cost policy (DW-085
/// `ai.routing_policies.<name>.candidates[]`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiLatencyCostCandidate {
    /// The model alias to route to. Must reference an existing alias
    /// in `ai.models`.
    pub model: String,
    /// Relative cost score (1-10, where 1 = cheapest). Validation
    /// rejects values outside 1-10.
    pub cost: u32,
    /// Relative latency score (1-10, where 1 = fastest). Validation
    /// rejects values outside 1-10.
    pub latency: u32,
}

/// The latency-vs-cost selection preference (DW-085
/// `ai.routing_policies.<name>.preference`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AiLatencyPreference {
    /// Pick the cheapest candidate (lowest `cost` score).
    Cost,
    /// Pick the fastest candidate (lowest `latency` score).
    Latency,
    /// Pick the best cost/latency ratio (lowest `cost + latency`
    /// sum).
    Balanced,
}
