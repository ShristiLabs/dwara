//! The AI proxy action (DW-075): the dataplane half of the
//! provider-adapter pack.
//!
//! Runs when a route's action is `ai`: parse the client's OpenAI
//! chat-completions body, resolve the model alias through the
//! generation's [`AiRuntime`](crate::ai::AiRuntime), translate via the
//! provider's [`ProviderAdapter`](crate::ai::adapter::ProviderAdapter),
//! place the call through the provider's UPSTREAM (pooling, TLS,
//! timeouts, breaker, health — the standard machinery), and translate
//! the response back. All failures answer in the OpenAI error shape so
//! standard client SDKs parse them; the gateway's request id rides
//! along inside `error.request_id`.
//!
//! Body bounds: an AI request must be read whole to translate it (the
//! zero-buffering rule yields here by necessity, opt-in by choosing
//! the action), and both directions are capped INCREMENTALLY — the
//! read aborts as soon as the cap is crossed, never after buffering
//! the whole body — at [`MAX_AI_REQUEST_BYTES`] inbound and
//! [`MAX_AI_PROVIDER_RESPONSE_BYTES`] from the provider, so a hostile
//! or runaway peer cannot turn the translation into an unbounded
//! buffer.
//!
//! Streaming: `stream: true` answers 400 (`streaming_not_supported`)
//! until DW-077 wires the zero-buffer SSE pass-through. The adapters
//! already translate delta shapes (verified per adapter in
//! `tests/ai_adapters.rs`), so the streaming pipeline composes on top
//! without adapter changes.

use crate::ai::adapter::adapter_for;
use crate::ai::openai_compat;
use crate::ai::types::ChatRequest;
use crate::dataplane::proxy::{DataPlane, Generation, ProxyBody};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Body;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use std::pin::pin;
use std::sync::Arc;

/// Inbound AI request body cap: 16 MiB, generous against long-context
/// requests while bounding the translation buffer.
pub const MAX_AI_REQUEST_BYTES: usize = 16 * 1024 * 1024;

/// Provider response body cap: 32 MiB (non-streaming completions of
/// extreme length). Provider ERROR bodies are capped tighter at
/// [`MAX_AI_ERROR_BYTES`] — they are never legitimately large.
pub const MAX_AI_PROVIDER_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

/// Provider error body cap: 1 MiB.
pub const MAX_AI_ERROR_BYTES: usize = 1024 * 1024;

/// Serve one `ai` route action (called from `dispatch_action` in the
/// proxy module). `rec` is the request's access record: the provider's
/// upstream name is attributed there so analytics and the access log
/// see which provider served the call.
#[allow(clippy::too_many_arguments)]
pub(super) async fn serve_ai<B>(
    req: Request<B>,
    route_name: &str,
    gen: &Arc<Generation>,
    dp: &Arc<DataPlane>,
    rid: &str,
    rec: &mut crate::observability::AccessRecord,
) -> Response<ProxyBody>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    // The generation's compiled AI table; absent only when validation
    // was bypassed (defensive: every publish path validates).
    let Some(runtime) = gen.ai() else {
        return ai_error_response(
            // Validation rejects an ai route action without an ai
            // block, so reaching here is a config-invariant violation,
            // not a client error — 5xx, not 404.
            StatusCode::INTERNAL_SERVER_ERROR,
            "this gateway has no ai block configured",
            "api_error",
            Some("ai_not_configured"),
            rid,
        );
    };

    // 1. Read the request body, bounded incrementally.
    let (_parts, body) = req.into_parts();
    let bytes = match bounded_collect(body, MAX_AI_REQUEST_BYTES, "request", rid).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    // 2. Parse the OpenAI-shaped body into the canonical request.
    let json_body: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            return ai_error_response(
                StatusCode::BAD_REQUEST,
                &format!("request body is not valid JSON: {e}"),
                "invalid_request_error",
                Some("invalid_json"),
                rid,
            )
        }
    };
    let chat_req: ChatRequest = match openai_compat::parse_chat_request(&json_body) {
        Ok(r) => r,
        Err(e) => {
            return ai_error_response(
                StatusCode::BAD_REQUEST,
                &e.to_string(),
                openai_compat::error_type_of(&e),
                None,
                rid,
            )
        }
    };

    // 3. Streaming arrives with DW-077 (module docs).
    if chat_req.stream {
        return ai_error_response(
            StatusCode::BAD_REQUEST,
            "streaming is not supported on this gateway yet (the streaming \
             pipeline is a planned feature); send stream: false or use a \
             proxy route to the provider",
            "invalid_request_error",
            Some("streaming_not_supported"),
            rid,
        );
    }

    // 4. Resolve the model alias to its provider.
    let Some((provider, provider_model)) = runtime.resolve(&chat_req.model) else {
        return ai_error_response(
            StatusCode::NOT_FOUND,
            &format!("the model '{}' does not exist", chat_req.model),
            "invalid_request_error",
            Some("model_not_found"),
            rid,
        );
    };
    let adapter = adapter_for(provider.kind);

    // 5. Translate to the provider's wire format.
    let provider_req = match adapter.build_request(&chat_req, provider_model) {
        Ok(r) => r,
        Err(e) => {
            dp.observability_arc().record_ai_request(
                &provider.name,
                route_name,
                "translation_error",
            );
            return ai_error_response(
                StatusCode::BAD_REQUEST,
                &e.to_string(),
                openai_compat::error_type_of(&e),
                None,
                rid,
            );
        }
    };

    // 6. Place the call through the provider's upstream.
    let Some(handle) = gen.registry().get(&provider.upstream) else {
        tracing::error!(
            code = "ai_provider_upstream_missing",
            provider = %provider.name,
            upstream = %provider.upstream,
            "ai provider's upstream is not in the registry (validate-vs-build race)"
        );
        return ai_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the provider's transport is unavailable",
            "api_error",
            Some("provider_transport_unavailable"),
            rid,
        );
    };
    let mut outbound = Request::builder()
        .method(Method::POST)
        .uri(&provider_req.path)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(hyper::header::ACCEPT, "application/json");
    for (name, value) in &provider_req.headers {
        if let Ok(v) = hyper::header::HeaderValue::from_str(value) {
            outbound = outbound.header(name.clone(), v);
        }
    }
    // Provider auth from the compiled table (resolved at compile time;
    // adapters never see credentials). Applied last so nothing
    // overrides it; unrepresentable values skip loudly.
    for (name, value) in &provider.auth_headers {
        match (
            hyper::header::HeaderName::from_bytes(name.as_bytes()),
            hyper::header::HeaderValue::from_str(value),
        ) {
            (Ok(n), Ok(v)) => {
                outbound = outbound.header(n, v);
            }
            _ => {
                tracing::error!(
                    code = "ai_provider_auth_header_invalid",
                    provider = %provider.name,
                    "provider auth header is not representable; call is sent unauthenticated"
                );
            }
        }
    }
    let body_bytes = serde_json::to_vec(&provider_req.body).unwrap_or_default();
    let outbound = match outbound.body(Full::new(Bytes::from(body_bytes))) {
        Ok(r) => r,
        Err(_) => {
            return ai_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the translated request could not be built",
                "api_error",
                None,
                rid,
            )
        }
    };
    rec.upstream = Some(provider.upstream.clone());
    rec.attempts = 1;
    let upstream_resp = match handle.send(outbound).await {
        Ok(r) => r,
        Err(e) => {
            dp.observability_arc()
                .record_ai_request(&provider.name, route_name, "transport_error");
            tracing::warn!(
                code = "ai_provider_unreachable",
                request_id = %rid,
                provider = %provider.name,
                upstream = %provider.upstream,
                "ai provider call failed: {e}"
            );
            return ai_error_response(
                StatusCode::BAD_GATEWAY,
                "the model provider could not be reached",
                "api_error",
                Some("provider_unreachable"),
                rid,
            );
        }
    };

    // 7. Translate the response.
    let status = upstream_resp.status();
    let (up_parts, up_body) = upstream_resp.into_parts();
    if !status.is_success() {
        let err_bytes =
            match bounded_collect(up_body, MAX_AI_ERROR_BYTES, "provider error", rid).await {
                Ok(b) => b,
                Err(resp) => return resp,
            };
        let value: serde_json::Value = serde_json::from_slice(&err_bytes).unwrap_or_default();
        let parsed = adapter.parse_error(&value);
        dp.observability_arc()
            .record_ai_request(&provider.name, route_name, "provider_error");
        let body = openai_compat::error_body(
            &parsed.message,
            parsed.error_type.as_deref().unwrap_or("api_error"),
            parsed.code.as_deref(),
            rid,
        );
        return response_with_json(status, &body, &up_parts.headers);
    }
    let ok_bytes =
        match bounded_collect(up_body, MAX_AI_PROVIDER_RESPONSE_BYTES, "response", rid).await {
            Ok(b) => b,
            Err(resp) => return resp,
        };
    let value: serde_json::Value = match serde_json::from_slice(&ok_bytes) {
        Ok(v) => v,
        Err(e) => {
            dp.observability_arc().record_ai_request(
                &provider.name,
                route_name,
                "translation_error",
            );
            tracing::warn!(
                code = "ai_provider_body_invalid",
                request_id = %rid,
                provider = %provider.name,
                "provider 200 response was not valid JSON: {e}"
            );
            return ai_error_response(
                StatusCode::BAD_GATEWAY,
                "the model provider returned a malformed response",
                "api_error",
                Some("provider_malformed_response"),
                rid,
            );
        }
    };
    let chat_resp = match adapter.parse_response(&value) {
        Ok(r) => r,
        Err(e) => {
            dp.observability_arc().record_ai_request(
                &provider.name,
                route_name,
                "translation_error",
            );
            tracing::warn!(
                code = "ai_provider_body_untranslatable",
                request_id = %rid,
                provider = %provider.name,
                "provider 200 response could not be translated: {e}"
            );
            return ai_error_response(
                StatusCode::BAD_GATEWAY,
                "the model provider returned a response the gateway could not translate",
                "api_error",
                Some("provider_untranslatable_response"),
                rid,
            );
        }
    };
    if let Some(usage) = chat_resp.usage {
        dp.observability_arc().record_ai_tokens(
            &provider.name,
            usage.prompt_tokens.unwrap_or(0),
            usage.completion_tokens.unwrap_or(0),
        );
    }
    dp.observability_arc()
        .record_ai_request(&provider.name, route_name, "success");
    let body = openai_compat::response_to_openai(&chat_resp, &chat_req.model, rid);
    tracing::info!(
        code = "ai_request_served",
        request_id = %rid,
        route = %route_name,
        provider = %provider.name,
        model = %chat_req.model,
        upstream = %provider.upstream,
        "ai chat completion translated and served"
    );
    response_with_json(StatusCode::OK, &body, &up_parts.headers)
}

/// Collect a body up to `cap` bytes, aborting the read the moment the
/// cap is crossed (the producer is dropped mid-stream — an over-cap
/// body is never buffered whole). Over-cap answers 413 inbound / 502
/// provider-side, in the AI error shape.
async fn bounded_collect<B>(
    body: B,
    cap: usize,
    what: &str,
    rid: &str,
) -> Result<Bytes, Response<ProxyBody>>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let mut buf: Vec<u8> = Vec::new();
    let mut body = pin!(body);
    while let Some(frame) = body.as_mut().frame().await {
        let frame = frame.map_err(|e| {
            let e = e.into();
            ai_error_response(
                StatusCode::BAD_REQUEST,
                &format!("the {what} body could not be read: {e}"),
                if what == "request" {
                    "invalid_request_error"
                } else {
                    "api_error"
                },
                None,
                rid,
            )
        })?;
        if let Some(data) = frame.data_ref() {
            if buf.len() + data.len() > cap {
                return Err(ai_error_response(
                    if what == "request" {
                        StatusCode::PAYLOAD_TOO_LARGE
                    } else {
                        StatusCode::BAD_GATEWAY
                    },
                    &format!("the {what} body exceeds the gateway's {cap}-byte limit"),
                    if what == "request" {
                        "invalid_request_error"
                    } else {
                        "api_error"
                    },
                    Some("body_too_large"),
                    rid,
                ));
            }
            buf.extend_from_slice(data);
        }
    }
    Ok(Bytes::from(buf))
}

/// Build an AI-route error response (OpenAI error shape).
fn ai_error_response(
    status: StatusCode,
    message: &str,
    error_type: &str,
    code: Option<&str>,
    rid: &str,
) -> Response<ProxyBody> {
    let body = openai_compat::error_body(message, error_type, code, rid);
    response_with_json(status, &body, &HeaderMap::new())
}

/// Build a JSON response. The provider's `x-request-id` (when sent) is
/// carried through for correlation; every other provider header is
/// dropped — the gateway authored this response.
fn response_with_json(
    status: StatusCode,
    body: &serde_json::Value,
    provider_headers: &HeaderMap,
) -> Response<ProxyBody> {
    let mut builder = Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json");
    if let Some(v) = provider_headers.get("x-request-id") {
        builder = builder.header("x-request-id", v);
    }
    builder
        .body(ProxyBody::Full(Full::new(Bytes::from(body.to_string()))))
        .expect("static JSON response is valid")
}
