//! The [`ProviderAdapter`] trait (DW-075): the seam every provider
//! dialect implements and every higher layer composes on.
//!
//! An adapter is a PURE TRANSLATOR. It holds no state, opens no
//! connections, and knows nothing about routing or failover — it turns
//! a [`ChatRequest`] into a provider
//! HTTP request shape, and provider JSON back into the canonical types.
//! Transport (endpoints, TLS, pooling, timeouts, breakers) belongs to
//! the named upstream; composing behaviors (DW-076 routing/failover,
//! DW-078 budgets) wrap the CALL, not the adapter — which is why the
//! trait has no I/O: composition layers stay free to retry or reroute a
//! translated request without re-translating.
//!
//! Streaming (DW-077 wires the gateway side): adapters translate one
//! SSE data payload at a time via [`ProviderAdapter::parse_stream_event`];
//! SSE framing itself is dialect-independent and lives in
//! [`crate::ai::sse`].

use crate::ai::types::{ChatRequest, ChatResponse, StreamEvent};
use crate::config::ai::AiProviderKind;
use http::HeaderName;
use serde_json::Value;

use crate::ai::adapters::anthropic::AnthropicAdapter;
use crate::ai::adapters::gemini::GeminiAdapter;
use crate::ai::adapters::openai::OpenAiAdapter;

/// The error type of the AI domain: client-side malformation, adapter
/// translation failure, or a provider-reported error response.
#[derive(Debug, Clone, PartialEq)]
pub enum AiError {
    /// The CLIENT's request cannot be served (malformed JSON, missing
    /// model, unsupported streaming until DW-077, ...). Message is safe
    /// to return to the client.
    InvalidRequest(String),
    /// The provider's payload could not be translated (unexpected
    /// shape). Message names the offending field; safe for logs and
    /// client responses.
    Translation(String),
    /// The provider answered a non-success status. Carries the
    /// provider's message/type/code for pass-through. Constructed by
    /// the TRANSPORT layer: the dataplane's `ai_proxy` maps provider
    /// errors to responses directly via `parse_error` today, and DW-076's
    /// failover transport is the intended constructor of this variant
    /// (a retry decision matches on it) — which is why the variant
    /// exists before anything builds it.
    Provider {
        status: u16,
        message: String,
        error_type: Option<String>,
        code: Option<String>,
    },
}

impl AiError {
    /// A short, stable classification for metrics and logs.
    pub fn kind(&self) -> &'static str {
        match self {
            AiError::InvalidRequest(_) => "invalid_request",
            AiError::Translation(_) => "translation",
            AiError::Provider { .. } => "provider",
        }
    }
}

impl std::fmt::Display for AiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AiError::InvalidRequest(m) => write!(f, "invalid request: {m}"),
            AiError::Translation(m) => write!(f, "translation failure: {m}"),
            AiError::Provider {
                status,
                message,
                error_type,
                code,
            } => {
                write!(f, "provider error {status}")?;
                if let Some(t) = error_type {
                    write!(f, " type={t}")?;
                }
                if let Some(c) = code {
                    write!(f, " code={c}")?;
                }
                write!(f, ": {message}")
            }
        }
    }
}

impl std::error::Error for AiError {}

/// A provider HTTP request produced by an adapter: everything the
/// transport layer needs to place the call through the provider's
/// upstream. The URI is a PATH (+query) only — the upstream endpoint
/// supplies the authority, exactly like a proxy route.
#[derive(Debug, Clone)]
pub struct ProviderRequest {
    /// Always POST for the shipped dialects; carried for shape honesty.
    pub method: http::Method,
    /// Request path and query, provider-specific.
    pub path: String,
    /// Dialect-required headers (content type, provider version
    /// stamps). AUTH headers are NOT included — they come from the
    /// provider's config, applied by the transport so adapters never
    /// touch credentials.
    pub headers: Vec<(HeaderName, String)>,
    /// The provider request body as JSON.
    pub body: Value,
}

/// A provider error body normalized for pass-through.
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderErrorBody {
    pub message: String,
    pub error_type: Option<String>,
    pub code: Option<String>,
}

/// The translation contract of one provider dialect (DW-075). Pure
/// functions over the canonical types; implementations are stateless
/// singletons (see [`adapter_for`]).
pub trait ProviderAdapter: Send + Sync {
    /// The dialect this adapter speaks.
    fn kind(&self) -> AiProviderKind;

    /// Translate a canonical request into this provider's HTTP shape.
    /// `provider_model` is the mapped provider model identifier that
    /// must REPLACE the client's alias in the outbound body.
    fn build_request(
        &self,
        req: &ChatRequest,
        provider_model: &str,
    ) -> Result<ProviderRequest, AiError>;

    /// Translate a provider success body (HTTP 200) into the canonical
    /// [`ChatResponse`].
    fn parse_response(&self, body: &Value) -> Result<ChatResponse, AiError>;

    /// Extract the error message/type/code from a provider error body
    /// (any shape the provider uses). Never fails — a best-effort
    /// generic message is produced when the body is not understood.
    fn parse_error(&self, body: &Value) -> ProviderErrorBody;

    /// Translate ONE provider SSE data payload into zero or more
    /// canonical stream events (DW-077 wires the gateway streaming
    /// path; verified per adapter in DW-075 tests).
    fn parse_stream_event(&self, data: &Value) -> Result<Vec<StreamEvent>, AiError>;

    /// The dialect's end-of-stream data sentinel, if it has one
    /// (OpenAI `[DONE]`; Anthropic/Gemini use typed events instead).
    fn stream_done_sentinel(&self) -> Option<&'static str> {
        None
    }
}

static OPENAI_ADAPTER: OpenAiAdapter = OpenAiAdapter;
static ANTHROPIC_ADAPTER: AnthropicAdapter = AnthropicAdapter;
static GEMINI_ADAPTER: GeminiAdapter = GeminiAdapter;

/// The adapter singleton for a provider kind. Adapters are stateless —
/// one instance per dialect serves every request.
pub fn adapter_for(kind: AiProviderKind) -> &'static dyn ProviderAdapter {
    match kind {
        AiProviderKind::Openai => &OPENAI_ADAPTER,
        AiProviderKind::Anthropic => &ANTHROPIC_ADAPTER,
        AiProviderKind::Gemini => &GEMINI_ADAPTER,
    }
}
