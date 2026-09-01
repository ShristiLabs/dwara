//! The AI proxy action (DW-075): the dataplane half of the
//! provider-adapter pack — extended by DW-076 with routing and
//! failover.
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
//! # Routing and failover (DW-076)
//!
//! `AiRuntime::route` turns the alias into an ordered candidate list:
//! `[primary, failover...]` for a chained alias, or exactly one
//! deterministically-picked canary version for a split alias (see
//! `ai::routing`). The action walks the candidates and advances on
//! RETRYABLE outcomes — a 429, a 5xx, a transport error, or a
//! dialect-specific translation rejection — and treats everything
//! else as final. Failover is invisible to the client by
//! construction: a provider response is read and translated WHOLE
//! before any byte reaches the client, so a failing candidate emits
//! nothing client-visible. Same-provider retries are deliberately not
//! the chain's job — the provider's upstream breaker owns those; the
//! chain only ever moves to a DIFFERENT provider/model pair. Usage and
//! request metrics attribute to the provider and canary version that
//! actually served; the access record follows the serving provider.
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

    // 4. Route (DW-076): the ordered candidate list for this alias —
    // [primary, failover...] for a chained alias, the deterministic
    // canary pick for a split alias. Empty means the alias does not
    // exist.
    let candidates = runtime.route(&chat_req.model, rid);
    if candidates.is_empty() {
        return ai_error_response(
            StatusCode::NOT_FOUND,
            &format!("the model '{}' does not exist", chat_req.model),
            "invalid_request_error",
            Some("model_not_found"),
            rid,
        );
    }

    // 5. Walk the candidates (DW-076 failover). Retryable outcomes —
    // a 429, a 5xx, a transport error, or a per-dialect translation
    // rejection — advance to the NEXT candidate; anything else is
    // final. Nothing reaches the client until a candidate SUCCEEDS
    // (the provider response is read whole before translation), so
    // failover is invisible to the client. Same-provider retries are
    // not the chain's job: the provider's upstream breaker owns those.
    let obs = dp.observability_arc();
    let mut attempts: u32 = 0;
    let mut last_transport_error = true;
    let mut fallback_response: Response<ProxyBody> = ai_error_response(
        StatusCode::BAD_GATEWAY,
        "no provider could serve the model",
        "api_error",
        Some("provider_unreachable"),
        rid,
    );
    for target in candidates {
        attempts += 1;
        let version = target.version.as_deref().unwrap_or("default");
        let Some(provider) = runtime.provider(&target.provider) else {
            tracing::error!(
                code = "ai_provider_missing",
                request_id = %rid,
                provider = %target.provider,
                "routed provider is not in the compiled table (validate-vs-build race)"
            );
            obs.record_ai_request(&target.provider, route_name, "transport_error", version);
            continue;
        };
        let adapter = adapter_for(provider.kind);

        // Translate for THIS provider (the provider model differs per
        // candidate). A per-dialect rejection may not exist in the
        // next dialect, so it advances rather than failing the request.
        let provider_req = match adapter.build_request(&chat_req, &target.provider_model) {
            Ok(r) => r,
            Err(e) => {
                obs.record_ai_request(&provider.name, route_name, "translation_error", version);
                tracing::info!(
                    code = "ai_provider_translation_rejected",
                    request_id = %rid,
                    provider = %provider.name,
                    "candidate rejected the conversation: {e}"
                );
                fallback_response = ai_error_response(
                    StatusCode::BAD_REQUEST,
                    &e.to_string(),
                    openai_compat::error_type_of(&e),
                    None,
                    rid,
                );
                last_transport_error = false;
                continue;
            }
        };

        let Some(handle) = gen.registry().get(&provider.upstream) else {
            tracing::error!(
                code = "ai_provider_upstream_missing",
                request_id = %rid,
                provider = %provider.name,
                upstream = %provider.upstream,
                "ai provider's upstream is not in the registry (validate-vs-build race)"
            );
            obs.record_ai_request(&provider.name, route_name, "transport_error", version);
            continue;
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
        // Provider auth from the compiled table (resolved at compile
        // time; adapters never see credentials). Applied last so
        // nothing overrides it; unrepresentable values skip loudly.
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
                obs.record_ai_request(&provider.name, route_name, "transport_error", version);
                continue;
            }
        };
        // Attribution follows the SERVING (or last attempted)
        // provider across the failover walk (DW-076).
        rec.upstream = Some(provider.upstream.clone());
        rec.attempts = attempts;
        let upstream_resp = match handle.send(outbound).await {
            Ok(r) => r,
            Err(e) => {
                obs.record_ai_request(&provider.name, route_name, "transport_error", version);
                tracing::warn!(
                    code = "ai_provider_unreachable",
                    request_id = %rid,
                    provider = %provider.name,
                    upstream = %provider.upstream,
                    "ai provider call failed: {e}"
                );
                last_transport_error = true;
                continue;
            }
        };

        let status = upstream_resp.status();
        let (up_parts, up_body) = upstream_resp.into_parts();
        let retryable = status.as_u16() == 429 || status.is_server_error();
        if !status.is_success() {
            let err_bytes =
                match bounded_collect(up_body, MAX_AI_ERROR_BYTES, "provider error", rid).await {
                    Ok(b) => b,
                    Err(resp) => return resp,
                };
            let value: serde_json::Value = serde_json::from_slice(&err_bytes).unwrap_or_default();
            let parsed = adapter.parse_error(&value);
            obs.record_ai_request(&provider.name, route_name, "provider_error", version);
            let body = openai_compat::error_body(
                &parsed.message,
                parsed.error_type.as_deref().unwrap_or("api_error"),
                parsed.code.as_deref(),
                rid,
            );
            let resp = response_with_json(status, &body, &up_parts.headers);
            if retryable {
                // 429/5xx is transient — try the next candidate; if
                // none succeed, the LAST provider's answer is the one
                // the client sees (closest to the truth of the outage).
                tracing::info!(
                    code = "ai_provider_failover",
                    request_id = %rid,
                    provider = %provider.name,
                    status = status.as_u16(),
                    "transient provider error; failing over to the next candidate"
                );
                fallback_response = resp;
                last_transport_error = false;
                continue;
            }
            // Other 4xx (bad request, bad key) is deterministic —
            // retrying another provider would only re-diagnose it.
            return resp;
        }
        let ok_bytes =
            match bounded_collect(up_body, MAX_AI_PROVIDER_RESPONSE_BYTES, "response", rid).await {
                Ok(b) => b,
                Err(resp) => {
                    // An over-cap or unreadable SUCCESS body is
                    // provider-specific (a runaway completion), exactly
                    // like a malformed one below: record it, stash the
                    // 502, and let the next candidate answer. (The
                    // inbound "request" cap and the cheap "provider
                    // error" cap stay FINAL — the first is a client
                    // problem, the second is already on an error path.)
                    obs.record_ai_request(&provider.name, route_name, "translation_error", version);
                    tracing::warn!(
                        code = "ai_provider_body_over_cap",
                        request_id = %rid,
                        provider = %provider.name,
                        "provider 200 response exceeded the body cap or failed mid-read"
                    );
                    fallback_response = resp;
                    last_transport_error = false;
                    continue;
                }
            };
        let value: serde_json::Value = match serde_json::from_slice(&ok_bytes) {
            Ok(v) => v,
            Err(e) => {
                obs.record_ai_request(&provider.name, route_name, "translation_error", version);
                tracing::warn!(
                    code = "ai_provider_body_invalid",
                    request_id = %rid,
                    provider = %provider.name,
                    "provider 200 response was not valid JSON: {e}"
                );
                // A malformed 200 body is provider-specific; the next
                // candidate may be healthy.
                fallback_response = ai_error_response(
                    StatusCode::BAD_GATEWAY,
                    "the model provider returned a malformed response",
                    "api_error",
                    Some("provider_malformed_response"),
                    rid,
                );
                last_transport_error = false;
                continue;
            }
        };
        let chat_resp = match adapter.parse_response(&value) {
            Ok(r) => r,
            Err(e) => {
                obs.record_ai_request(&provider.name, route_name, "translation_error", version);
                tracing::warn!(
                    code = "ai_provider_body_untranslatable",
                    request_id = %rid,
                    provider = %provider.name,
                    "provider 200 response could not be translated: {e}"
                );
                fallback_response = ai_error_response(
                    StatusCode::BAD_GATEWAY,
                    "the model provider returned a response the gateway could not translate",
                    "api_error",
                    Some("provider_untranslatable_response"),
                    rid,
                );
                last_transport_error = false;
                continue;
            }
        };
        if let Some(usage) = chat_resp.usage {
            // Usage attributes to the SERVING provider and canary
            // version (DW-076; the input DW-079 cost metering reads).
            obs.record_ai_tokens(
                &provider.name,
                usage.prompt_tokens.unwrap_or(0),
                usage.completion_tokens.unwrap_or(0),
                version,
            );
        }
        obs.record_ai_request(&provider.name, route_name, "success", version);
        let body = openai_compat::response_to_openai(&chat_resp, &chat_req.model, rid);
        tracing::info!(
            code = "ai_request_served",
            request_id = %rid,
            route = %route_name,
            provider = %provider.name,
            model = %chat_req.model,
            version = %version,
            attempts = attempts,
            upstream = %provider.upstream,
            "ai chat completion translated and served"
        );
        return response_with_json(StatusCode::OK, &body, &up_parts.headers);
    }

    // 6. Every candidate failed. The last stashed provider answer is
    // the most truthful response; a pure-transport exhaustion keeps
    // the generic 502.
    rec.attempts = attempts.max(1);
    if attempts > 1 {
        tracing::warn!(
            code = "ai_failover_exhausted",
            request_id = %rid,
            model = %chat_req.model,
            attempts = attempts,
            transport_only = last_transport_error,
            "all providers failed for the model"
        );
    }
    fallback_response
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
