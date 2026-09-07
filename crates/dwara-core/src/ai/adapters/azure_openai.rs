//! The Azure OpenAI provider adapter (AI-01).
//!
//! Azure OpenAI speaks the SAME chat-completions body dialect as OpenAI
//! (the request/response JSON is identical), but differs in two
//! transport-level details:
//!
//! - **URL format**: Azure uses deployment-based URLs
//!   `/openai/deployments/{deployment}/chat/completions?api-version=...`
//!   instead of OpenAI's `/v1/chat/completions`. The `{deployment}` is
//!   the provider model identifier (the `provider_model` the alias maps
//!   to), and the `api-version` query parameter is required.
//! - **Authentication**: Azure uses `api-key: {key}` instead of
//!   `Authorization: Bearer {key}`. The auth header is still configured
//!   verbatim via `ai.providers[].auth` (the adapter does not touch
//!   credentials); the operator sets `header: api-key` + `value: ...`.
//!
//! This adapter DELEGATES the body translation to the OpenAI adapter
//! (the body is identical) and OVERRIDES the path to the Azure
//! deployment format. The default API version is `2024-10-21` (a stable
//! GA version); the operator can override it via the `other` map key
//! `api_version` (a dialect-specific parameter preserved by the
//! canonical request).
//!
//! Streaming: Azure uses the same SSE format as OpenAI, including the
//! `data: [DONE]` sentinel, so the OpenAI stream-event parser applies
//! unchanged.

use crate::ai::adapter::{AiError, ProviderAdapter, ProviderErrorBody, ProviderRequest};
use crate::ai::adapters::openai::OpenAiAdapter;
use crate::ai::types::{ChatRequest, ChatResponse, StreamEvent};
use crate::config::ai::AiProviderKind;

/// The default Azure OpenAI API version (a stable GA release). The
/// operator can override per-request via `other.api_version`.
const DEFAULT_AZURE_API_VERSION: &str = "2024-10-21";

/// The Azure OpenAI adapter (AI-01). Stateless singleton; delegates
/// body translation to the OpenAI adapter and overrides the path.
pub struct AzureOpenAiAdapter;

impl ProviderAdapter for AzureOpenAiAdapter {
    fn kind(&self) -> AiProviderKind {
        AiProviderKind::AzureOpenai
    }

    fn build_request(
        &self,
        req: &ChatRequest,
        provider_model: &str,
    ) -> Result<ProviderRequest, AiError> {
        // Delegate the body translation to the OpenAI adapter.
        let mut pr = OpenAiAdapter.build_request(req, provider_model)?;
        // Override the path to the Azure deployment URL format. The
        // `provider_model` is the deployment name. The API version
        // comes from the `other` map (a dialect-specific parameter)
        // or falls back to the default.
        let api_version = req
            .other
            .get("api_version")
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_AZURE_API_VERSION);
        pr.path = format!(
            "/openai/deployments/{provider_model}/chat/completions?api-version={api_version}"
        );
        // Azure requires `api-key: {key}` — the auth header is applied
        // by the transport from the provider's config. No additional
        // headers are needed here (the transport adds content-type and
        // auth).
        Ok(pr)
    }

    fn parse_response(&self, body: &serde_json::Value) -> Result<ChatResponse, AiError> {
        // The response body is identical to OpenAI's.
        OpenAiAdapter.parse_response(body)
    }

    fn parse_error(&self, body: &serde_json::Value) -> ProviderErrorBody {
        // Azure error bodies are OpenAI-shaped (`{"error": {"message":
        // ..., "code": ...}}`).
        OpenAiAdapter.parse_error(body)
    }

    fn parse_stream_event(&self, data: &serde_json::Value) -> Result<Vec<StreamEvent>, AiError> {
        // Azure SSE frames are OpenAI-shaped.
        OpenAiAdapter.parse_stream_event(data)
    }

    fn stream_done_sentinel(&self) -> Option<&'static str> {
        // Azure uses the same `[DONE]` sentinel as OpenAI.
        OpenAiAdapter.stream_done_sentinel()
    }
}

use serde_json::Value;
