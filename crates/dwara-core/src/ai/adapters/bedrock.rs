//! The AWS Bedrock provider adapter (AI-01).
//!
//! AWS Bedrock hosts foundation models (Anthropic Claude, Meta Llama,
//! Mistral, etc.) behind a unified invoke API. For Claude models,
//! Bedrock's `InvokeModel` endpoint accepts the SAME Anthropic messages
//! body format as the native Anthropic API (`POST /v1/messages`), so
//! this adapter DELEGATES the body translation to the Anthropic adapter
//! and OVERRIDES the path to the Bedrock invoke format:
//!
//! ```text
//! POST /model/{provider_model}/invoke
//! ```
//!
//! where `{provider_model}` is the Bedrock model identifier (e.g.
//! `anthropic.claude-3-5-sonnet-20241022-v2:0`).
//!
//! # SigV4 signing
//!
//! Bedrock requires AWS Signature Version 4 (SigV4) on every request.
//! SigV4 is a request-signing scheme that adds an `Authorization`
//! header computed from the AWS access key ID, secret access key,
//! region, service name (`bedrock`), and the canonical request (method,
//! path, headers, body hash). The signing is applied by the TRANSPORT
//! layer (the dataplane's `ai_proxy`), not the adapter — the adapter is
//! a pure translator and never touches credentials. The operator
//! configures AWS credentials via the provider's `auth` header (the
//! transport applies them) or via environment variables
//! (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`) that
//! the transport resolves at request time.
//!
//! In the current implementation, SigV4 signing is NOT yet wired in the
//! transport — the adapter produces the correct path and body, but the
//! transport applies the verbatim `auth` header from the provider's
//! config (the same mechanism every other provider uses). A future
//! extension will add SigV4 signing as a transport-level concern. Until
//! then, Bedrock providers that accept a static API key (or a proxy
//! that handles signing upstream) work unchanged; raw Bedrock endpoints
//! requiring SigV4 will return 403 until the signing is wired.
//!
//! # Streaming
//!
//! Bedrock streaming uses a different endpoint (`/model/{id}/invoke-
//! with-response-stream`) and a different event format (AWS Event
//! Stream, not SSE). The current adapter does NOT translate Bedrock
//! streaming events; a streaming request to a Bedrock provider will
//! fall back to non-streaming (the `stream` flag is dropped). A future
//! extension will add Bedrock event-stream parsing.

use crate::ai::adapter::{AiError, ProviderAdapter, ProviderErrorBody, ProviderRequest};
use crate::ai::adapters::anthropic::AnthropicAdapter;
use crate::ai::types::{ChatRequest, ChatResponse, StreamEvent};
use crate::config::ai::AiProviderKind;

/// The AWS Bedrock adapter (AI-01). Stateless singleton; delegates body
/// translation to the Anthropic adapter (Bedrock Claude models use the
/// Anthropic messages format) and overrides the path to the Bedrock
/// invoke format.
pub struct BedrockAdapter;

impl ProviderAdapter for BedrockAdapter {
    fn kind(&self) -> AiProviderKind {
        AiProviderKind::Bedrock
    }

    fn build_request(
        &self,
        req: &ChatRequest,
        provider_model: &str,
    ) -> Result<ProviderRequest, AiError> {
        // Delegate the body translation to the Anthropic adapter
        // (Bedrock Claude models accept the Anthropic messages body).
        let mut pr = AnthropicAdapter.build_request(req, provider_model)?;
        // Override the path to the Bedrock invoke format. The
        // `provider_model` is the Bedrock model identifier (e.g.
        // `anthropic.claude-3-5-sonnet-20241022-v2:0`). URL-encode the
        // model id (it contains colons and dots).
        let encoded_model = url_encode(provider_model);
        pr.path = format!("/model/{encoded_model}/invoke");
        // Bedrock does not use the Anthropic version header; remove it
        // (the Anthropic adapter sets `anthropic-version`). The
        // transport applies the auth header from the provider config.
        pr.headers
            .retain(|(name, _)| name.as_str() != "anthropic-version");
        Ok(pr)
    }

    fn parse_response(&self, body: &serde_json::Value) -> Result<ChatResponse, AiError> {
        // Bedrock returns the same response body as the Anthropic API.
        AnthropicAdapter.parse_response(body)
    }

    fn parse_error(&self, body: &serde_json::Value) -> ProviderErrorBody {
        // Bedrock error bodies follow the AWS JSON format
        // (`{"message": ...}`); the Anthropic parser handles the
        // common `{"error": {"message": ...}}` shape, and the
        // best-effort fallback covers the AWS shape.
        AnthropicAdapter.parse_error(body)
    }

    fn parse_stream_event(&self, data: &serde_json::Value) -> Result<Vec<StreamEvent>, AiError> {
        // Bedrock streaming uses AWS Event Stream format, not SSE.
        // The current adapter does not translate Bedrock streaming
        // events; this method is not called for Bedrock providers
        // (streaming is dropped at the transport level until the
        // event-stream parser is added).
        AnthropicAdapter.parse_stream_event(data)
    }
}

/// Minimal URL-encoding for the path segment: encodes colons (which
/// Bedrock model IDs contain) and other reserved characters. This is
/// NOT a general-purpose URL encoder — it covers the characters that
/// appear in Bedrock model identifiers.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}
