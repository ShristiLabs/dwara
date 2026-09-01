//! The AI proxy action (DW-075): the dataplane half of the
//! provider-adapter pack — extended by DW-076 with routing and
//! failover.
//!
//! Runs when a route's action is `ai`: parse the client's OpenAI
//! chat-completions body, resolve the model alias through the
//! generation's [`AiRuntime`](crate::ai::AiRuntime), translate via the
//! provider's [`ProviderAdapter`],
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
//! Streaming (DW-077): `stream: true` requests stream back to the
//! client as `text/event-stream`, translated frame-by-frame with ZERO
//! added buffering ([`AiStreamBody`] + [`StreamTranslator`]): each
//! complete provider frame becomes client frames in the same poll.
//! Token counts are provider-reported only (locked decision) and
//! accumulate mid-stream into one terminal usage chunk; the gateway
//! owns the `data: [DONE]` terminator. The failover chain applies
//! until the streaming response is returned (the commit point); after
//! the first forwarded frame a provider abort ends the stream cleanly
//! with an error chunk — already-forwarded content stands.

use crate::ai::adapter::{adapter_for, ProviderAdapter};
use crate::ai::openai_compat;
use crate::ai::stream::StreamTranslator;
use crate::ai::types::{ChatRequest, Usage};
use crate::dataplane::proxy::{DataPlane, Generation, ProxyBody};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Body;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use std::pin::pin;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

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
    identity: Option<&crate::security::authn::Identity>,
    listener_name: &str,
) -> Response<ProxyBody>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    // AI token budget pre-check (DW-078): BEFORE the request body is
    // even read — a holder whose window is exhausted never reaches a
    // provider. The resolution mirrors the rate-limit chain (consumer
    // > route > service > listener > global, most-specific budget
    // governs); unbudgeted holders resolve no guard and skip.
    let budget = {
        let engine = dp.ai_budgets();
        if engine.is_empty() {
            None
        } else {
            let consumer = identity.map(|id| id.consumer_name.as_str());
            let gateway = gen.snapshot.gateway();
            let route_cfg = gateway.routes.iter().find(|r| r.name == route_name);
            let route_policies: &[String] = route_cfg.map(|r| r.policies.as_slice()).unwrap_or(&[]);
            let service_policies: &[String] = route_cfg
                .map(|r| crate::ai::budget::service_policies_of(gateway, &r.service))
                .unwrap_or(&[]);
            let consumer_policies: &[String] = consumer
                .map(|c| crate::ai::budget::consumer_policies_of(gateway, c))
                .unwrap_or(&[]);
            let listener_policies = crate::ai::budget::listener_policies_of(gateway, listener_name);
            engine.resolve(
                consumer,
                consumer_policies,
                route_policies,
                service_policies,
                listener_policies,
                &gateway.global_policies,
            )
        }
    };
    if let Some(guard) = &budget {
        let now_s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let crate::ai::budget::BudgetVerdict::Denied {
            kind,
            retry_after_s,
        } = guard.check(now_s)
        {
            rec.rate_limited = true;
            dp.observability_arc()
                .record_ai_budget_denied(kind.as_str());
            tracing::info!(
                code = "ai_budget_exceeded",
                request_id = %rid,
                route = %route_name,
                kind = kind.as_str(),
                retry_after_s,
                "AI token budget exhausted; rejecting before provider contact"
            );
            let body = openai_compat::error_body(
                "the token budget for this window is exhausted; retry later",
                "rate_limit_error",
                Some("ai_budget_exceeded"),
                rid,
            );
            return Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("retry-after", retry_after_s.to_string())
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(ProxyBody::Full(Full::new(Bytes::from(body.to_string()))))
                .expect("static 429 response is valid");
        }
    }

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
    let mut chat_req: ChatRequest = match openai_compat::parse_chat_request(&json_body) {
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

    // DW-084: model governance pre-route check. The requested model
    // alias is checked against the consumer's binding team allowlists
    // BEFORE routing — a disallowed (or typo'd) alias is blocked at
    // the edge with 403 `model_denied_by_policy` rather than
    // surfacing as a provider 404. The resolution mirrors the
    // rate-limit/budget chain (consumer > route > service > listener
    // > global, deny-wins intersection); a consumer with no binding
    // allowlist policy is allowed (fail-open).
    let governance = dp.ai_governance();
    let governance_verdict = if governance.is_empty() {
        crate::ai::governance::GovernanceVerdict::Allow
    } else {
        let consumer = identity.map(|id| id.consumer_name.as_str());
        let gateway = gen.snapshot.gateway();
        let route_cfg = gateway.routes.iter().find(|r| r.name == route_name);
        let route_policies: &[String] = route_cfg.map(|r| r.policies.as_slice()).unwrap_or(&[]);
        let service_policies: &[String] = route_cfg
            .map(|r| crate::ai::budget::service_policies_of(gateway, &r.service))
            .unwrap_or(&[]);
        let consumer_policies: &[String] = consumer
            .map(|c| crate::ai::budget::consumer_policies_of(gateway, c))
            .unwrap_or(&[]);
        let listener_policies = crate::ai::budget::listener_policies_of(gateway, listener_name);
        governance.check(
            consumer,
            consumer_policies,
            route_policies,
            service_policies,
            listener_policies,
            &gateway.global_policies,
            &chat_req.model,
        )
    };
    let governance_consumer = identity
        .map(|id| id.consumer_name.clone())
        .unwrap_or_else(|| "anonymous".to_string());
    let governance_team = match &governance_verdict {
        crate::ai::governance::GovernanceVerdict::Deny { policy, .. } => policy.clone(),
        crate::ai::governance::GovernanceVerdict::Allow => String::new(),
    };
    if let crate::ai::governance::GovernanceVerdict::Deny { reason, .. } = &governance_verdict {
        dp.observability_arc().record_ai_governance_denied(reason);
        tracing::info!(
            code = "model_denied_by_policy",
            request_id = %rid,
            route = %route_name,
            consumer = %governance_consumer,
            model = %chat_req.model,
            reason = %reason,
            "AI model governance denied the requested model before routing"
        );
        // DW-084: a blocked attempt is ALWAYS audited (the done-when
        // requirement) when the governance block is present — the
        // `audit` flag only extends recording to ALLOWED calls.
        if let Some(analytics) = dp.analytics() {
            analytics.offer_ai_governance_event(crate::analytics::AiGovernanceEvent {
                ts_ms: now_ms(),
                consumer: governance_consumer.clone(),
                team: governance_team.clone(),
                model: chat_req.model.clone(),
                verdict: "deny".to_string(),
                reason: reason.clone(),
            });
        }
        let body = openai_compat::error_body(
            &format!(
                "the model '{}' is not allowed for this consumer by the \
                 team allowlist policy",
                chat_req.model
            ),
            "invalid_request_error",
            Some("model_denied_by_policy"),
            rid,
        );
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(ProxyBody::Full(Full::new(Bytes::from(body.to_string()))))
            .expect("static 403 response is valid");
    }
    // DW-084: when the audit switch is on, record ALLOWED calls too
    // (shadow review — which team called which model).
    if governance.audit() {
        if let Some(analytics) = dp.analytics() {
            analytics.offer_ai_governance_event(crate::analytics::AiGovernanceEvent {
                ts_ms: now_ms(),
                consumer: governance_consumer.clone(),
                team: governance_team.clone(),
                model: chat_req.model.clone(),
                verdict: "allow".to_string(),
                reason: String::new(),
            });
        }
    }

    // 3. Streaming (DW-077): the request is passed through with
    // usage reporting FORCED on the provider call — the stream
    // metrics and the (upcoming) token budgets need provider-reported
    // counts even when the client did not ask for the usage chunk,
    // and the terminal usage chunk we emit is the documented
    // include_usage shape either way.
    let stream_requested = chat_req.stream;
    if stream_requested {
        chat_req.stream_options_include_usage = true;
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
        let attempt_started = std::time::Instant::now();
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
        // Streaming pass-through (DW-077): a 200 SSE response streams
        // to the client frame-by-frame with zero added buffering. This
        // is the failover COMMIT point — returning the streaming
        // response forwards headers (and then chunks) to the client,
        // so no later candidate can replace anything from here on.
        if stream_requested && is_event_stream(&up_parts.headers) {
            obs.record_ai_request(&provider.name, route_name, "success", version);
            tracing::info!(
                code = "ai_stream_started",
                request_id = %rid,
                route = %route_name,
                provider = %provider.name,
                model = %chat_req.model,
                version = %version,
                attempts = attempts,
                upstream = %provider.upstream,
                "ai stream established; forwarding begins"
            );
            // DW-079: compute the consumer and team strings BEFORE
            // moving `budget` into the stream body.
            let consumer_name = identity
                .map(|id| id.consumer_name.clone())
                .unwrap_or_else(|| "anonymous".to_string());
            let team = budget
                .as_ref()
                .map(|g| g.team_key().to_string())
                .unwrap_or_default();
            let body = super::ai_proxy::AiStreamBody::new(
                up_body,
                adapter,
                format!("chatcmpl-{rid}"),
                chat_req.model.clone(),
                provider.name.clone(),
                target.provider_model.clone(),
                version.to_string(),
                attempt_started,
                Arc::clone(&obs),
                rid.to_string(),
                budget,
                dp.ai_pricing(),
                dp.analytics(),
                consumer_name,
                team,
            );
            return Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "text/event-stream")
                .header(hyper::header::CACHE_CONTROL, "no-cache")
                .body(ProxyBody::Ai(Box::new(body)))
                .expect("streaming response is valid");
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
            // DW-079: price the call through the dataplane's compiled
            // pricing table (swapped on reload, so a pricing change
            // applies to the next request with no restart). Unknown
            // model -> 0 (fail-open).
            let pricing = dp.ai_pricing();
            let cost = pricing.cost_micros(&target.provider_model, usage);
            if cost > 0 {
                obs.record_ai_cost(&provider.name, &target.provider_model, cost);
            }
            // Budget spend (DW-078): the provider-reported usage is
            // recorded against the requesting holder's windows AFTER
            // the call — check-then-spend; the crossing (if any) is
            // already priced into the next pre-check.
            if let Some(guard) = &budget {
                guard.spend(now_epoch_s(), usage, cost);
            }
            // DW-079: record the spend dimensions into the analytics
            // store for billing reconciliation. The team field is the
            // policy-scoped budget's key (the policy name) when a
            // team budget binds, else empty.
            if let Some(analytics) = dp.analytics() {
                let consumer_name = identity
                    .map(|id| id.consumer_name.as_str())
                    .unwrap_or("anonymous");
                let team = budget
                    .as_ref()
                    .map(|g| g.team_key().to_string())
                    .unwrap_or_default();
                let prompt = usage.prompt_tokens.unwrap_or(0);
                let completion = usage.completion_tokens.unwrap_or(0);
                let total = usage
                    .total_tokens
                    .unwrap_or_else(|| prompt.saturating_add(completion));
                analytics.offer_ai_spend(crate::analytics::AiSpendRecord {
                    ts_ms: now_ms(),
                    consumer: consumer_name.to_string(),
                    team,
                    provider: provider.name.clone(),
                    model: target.provider_model.clone(),
                    version: version.to_string(),
                    prompt_tokens: prompt,
                    completion_tokens: completion,
                    total_tokens: total,
                    cost_micros: cost,
                });
            }
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

/// Current Unix seconds (budget window indexing).
fn now_epoch_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Current Unix milliseconds (DW-079 spend record timestamping).
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Whether provider response headers declare an SSE body.
fn is_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("text/event-stream"))
        .unwrap_or(false)
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

// ---------------------------------------------------------------------------
// The streaming body (DW-077)
// ---------------------------------------------------------------------------

/// Per-stream accounting shared by the body and its metrics hooks.
struct StreamGauges {
    provider: String,
    version: String,
    chunks: u64,
    first_token_recorded: bool,
    started: std::time::Instant,
    /// Set once terminal metrics have been recorded (clean end OR
    /// drop): the counters must fire exactly once per stream.
    closed: bool,
}

/// The zero-buffer AI streaming body (DW-077): wraps the provider's
/// upstream body, translates each COMPLETE provider SSE frame into
/// OpenAI-shaped client frames as the bytes arrive, and forwards them
/// in the same poll — nothing waits for the stream to finish. Usage
/// events accumulate (provider-reported only) and are emitted as one
/// terminal chunk; the gateway owns the `data: [DONE]` terminator. A
/// provider body error after forwarding becomes a terminal error
/// chunk (already-forwarded content stands), never a reset.
///
/// Infallible by construction: every failure mode is expressed as
/// terminal frames, so the client stream always ends cleanly.
pub struct AiStreamBody {
    /// The provider's body — until the budget cutoff DROPS it (the
    /// upstream cancel then propagates immediately, regardless of how
    /// the client behaves; see `cut_off`).
    inner: Option<crate::dataplane::upstream::UpstreamBody>,
    translator: StreamTranslator,
    adapter: &'static dyn ProviderAdapter,
    /// Synthesized terminal frames waiting to be forwarded.
    tail: std::collections::VecDeque<String>,
    gauges: StreamGauges,
    obs: std::sync::Arc<crate::observability::Observability>,
    /// The requesting holder's budget (DW-078): checked as usage
    /// events accumulate — a crossing cuts the stream off.
    budget: Option<crate::ai::budget::BudgetGuard>,
    /// The serving provider's model id (the DW-079 pricing key).
    provider_model: String,
    /// The request id (the cutoff event's correlation handle).
    rid: String,
    /// Budget cutoff fired: the provider body was dropped AT the
    /// cutoff so the upstream request is cancelled immediately — a
    /// stalled client that never drains the tail must not keep the
    /// provider generating billed tokens. Only the synthesized tail
    /// remains to forward.
    cut_off: bool,
    /// Budget spend watermarks (DW-078): the accumulated totals
    /// already spent. The provider's usage report GROWS as the stream
    /// runs (input tokens at message_start, output at message_delta),
    /// so every spend is the DELTA above the watermark — each
    /// reported token is counted exactly once no matter how many
    /// chunks the report arrived in.
    budget_spent_tokens: u64,
    budget_spent_cost_micros: u64,
    /// DW-079: the dataplane's compiled pricing table (for pricing
    /// the stream's terminal usage).
    pricing: std::sync::Arc<crate::ai::cost::PricingTable>,
    /// DW-079: the analytics store (for recording the spend record at
    /// stream close). None when analytics is off.
    analytics: Option<std::sync::Arc<crate::analytics::EmbeddedAnalytics>>,
    /// DW-079: the consumer name for spend attribution.
    consumer: String,
    /// DW-079: the team key for spend attribution (policy name when
    /// a team budget binds, else empty).
    team: String,
    /// DW-079: whether the spend record has been recorded (exactly
    /// once per stream, at close).
    spend_recorded: bool,
}

impl AiStreamBody {
    /// Build the body for a provider stream whose headers resolved
    /// successfully. `started` is the request's send instant (first-
    /// token latency measures from there).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        inner: crate::dataplane::upstream::UpstreamBody,
        adapter: &'static dyn ProviderAdapter,
        response_id: String,
        model_alias: String,
        provider: String,
        provider_model: String,
        version: String,
        started: std::time::Instant,
        obs: std::sync::Arc<crate::observability::Observability>,
        rid: String,
        budget: Option<crate::ai::budget::BudgetGuard>,
        pricing: std::sync::Arc<crate::ai::cost::PricingTable>,
        analytics: Option<std::sync::Arc<crate::analytics::EmbeddedAnalytics>>,
        consumer: String,
        team: String,
    ) -> Self {
        AiStreamBody {
            inner: Some(inner),
            translator: StreamTranslator::new(response_id, model_alias, openai_compat::unix_now()),
            adapter,
            tail: std::collections::VecDeque::new(),
            gauges: StreamGauges {
                provider,
                version,
                chunks: 0,
                first_token_recorded: false,
                started,
                closed: false,
            },
            obs,
            budget,
            provider_model,
            rid,
            cut_off: false,
            budget_spent_tokens: 0,
            budget_spent_cost_micros: 0,
            pricing,
            analytics,
            consumer,
            team,
            spend_recorded: false,
        }
    }

    /// Spend the provider-reported usage GROWTH since the last spend
    /// (DW-078). The translator's usage is an ACCUMULATOR that grows
    /// as the provider reports (input tokens early, output late), so
    /// only the delta above the watermark is NEW spend — each
    /// reported token is counted exactly once regardless of how many
    /// chunks its report spanned. Returns whether the token window
    /// crossed its limit on THIS spend (the mid-stream cutoff signal).
    fn budget_spend_delta(&mut self) -> bool {
        let Some(guard) = &self.budget else {
            return false;
        };
        let usage = self.translator.usage();
        let total = usage.total_tokens.unwrap_or_else(|| {
            usage
                .prompt_tokens
                .unwrap_or(0)
                .saturating_add(usage.completion_tokens.unwrap_or(0))
        });
        let tokens = total.saturating_sub(self.budget_spent_tokens);
        let cost_total = self.pricing.cost_micros(&self.provider_model, usage);
        let cost = cost_total.saturating_sub(self.budget_spent_cost_micros);
        if tokens == 0 && cost == 0 {
            return false;
        }
        // Watermarks advance to the accumulated totals (max, so a
        // provider that revises a count downward never re-spends the
        // difference later).
        self.budget_spent_tokens = total.max(self.budget_spent_tokens);
        self.budget_spent_cost_micros = cost_total.max(self.budget_spent_cost_micros);
        guard.spend(
            now_epoch_s(),
            Usage {
                total_tokens: Some(tokens),
                ..Usage::default()
            },
            cost,
        )
    }

    /// Mid-stream cutoff check (DW-078). Called after each translated
    /// batch: the batch's NEW usage is spent against the holder's
    /// window, and a crossing (only detectable when the dialect
    /// reports usage mid-stream — Anthropic's message_start input
    /// tokens) cuts the stream.
    fn budget_tick(&mut self) {
        if self.budget.is_none() {
            return;
        }
        let crossed = self.budget_spend_delta();
        if crossed && !self.cut_off && !self.translator.is_ended() {
            self.cut_off = true;
            // Drop the provider body NOW: an upstream request is
            // cancelled the moment its body is dropped, however slowly
            // (or never) the client drains the cutoff tail below — the
            // cancel must not wait on client behavior. The tail still
            // reaches the client: the cutoff event, then [DONE].
            self.inner = None;
            self.obs.record_ai_budget_denied("tokens");
            tracing::warn!(
                code = "ai_budget_exceeded_midstream",
                request_id = %self.rid,
                "token budget crossed mid-stream; cutting off and cancelling the provider stream"
            );
            self.tail
                .push_back(crate::ai::budget::BudgetGuard::cutoff_frame(&self.rid));
            self.tail.push_back("data: [DONE]\n\n".to_string());
        }
    }

    /// Record per-chunk accounting for a translated batch.
    fn note_chunks(&mut self, count: usize, first: bool) {
        for _ in 0..count {
            self.obs.record_ai_stream_chunk(&self.gauges.provider);
        }
        self.gauges.chunks += count as u64;
        if first && !self.gauges.first_token_recorded {
            self.gauges.first_token_recorded = true;
            self.obs.record_ai_first_token(
                &self.gauges.provider,
                self.gauges.started.elapsed().as_secs_f64(),
            );
        }
    }

    /// Terminal metrics: exactly once per stream. Records duration and
    /// the accumulated provider-reported usage (the DW-079 input; the
    /// version label carries the canary attribution, DW-076).
    fn close(&mut self) {
        if self.gauges.closed {
            return;
        }
        self.gauges.closed = true;
        self.obs.record_ai_stream_end(
            &self.gauges.provider,
            self.gauges.started.elapsed().as_secs_f64(),
        );
        let usage = self.translator.usage();
        // Terminal budget spend (DW-078): the not-yet-spent delta. A
        // dialect that reports usage only in its final events spends
        // here (its mid-stream ticks saw nothing) — enforced by the
        // next pre-check; mid-stream cutoff was impossible for it.
        // After a cutoff the stream's spend is already recorded.
        if !self.cut_off {
            self.budget_spend_delta();
        }
        if usage.prompt_tokens.is_some() || usage.completion_tokens.is_some() {
            self.obs.record_ai_tokens(
                &self.gauges.provider,
                usage.prompt_tokens.unwrap_or(0),
                usage.completion_tokens.unwrap_or(0),
                &self.gauges.version,
            );
        }
        // DW-079: record the spend dimensions into the analytics
        // store (exactly once per stream). The terminal usage is the
        // accumulated provider-reported total; cost is priced through
        // the dataplane's pricing table.
        if !self.spend_recorded {
            self.spend_recorded = true;
            let prompt = usage.prompt_tokens.unwrap_or(0);
            let completion = usage.completion_tokens.unwrap_or(0);
            let total = usage
                .total_tokens
                .unwrap_or_else(|| prompt.saturating_add(completion));
            let cost = self.pricing.cost_micros(&self.provider_model, usage);
            if cost > 0 {
                self.obs
                    .record_ai_cost(&self.gauges.provider, &self.provider_model, cost);
            }
            if let Some(analytics) = &self.analytics {
                analytics.offer_ai_spend(crate::analytics::AiSpendRecord {
                    ts_ms: now_ms(),
                    consumer: self.consumer.clone(),
                    team: self.team.clone(),
                    provider: self.gauges.provider.clone(),
                    model: self.provider_model.clone(),
                    version: self.gauges.version.clone(),
                    prompt_tokens: prompt,
                    completion_tokens: completion,
                    total_tokens: total,
                    cost_micros: cost,
                });
            }
        }
    }
}

impl hyper::body::Body for AiStreamBody {
    type Data = Bytes;
    type Error = super::proxy::ProxyBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, super::proxy::ProxyBodyError>>> {
        let this = self.get_mut();
        loop {
            // Drain synthesized terminal frames first: one data frame
            // per poll (flushes reach the client per frame).
            if let Some(text) = this.tail.pop_front() {
                if this.tail.is_empty() && this.translator.is_ended() {
                    // The last terminal frame: close after it is
                    // handed over. The NEXT poll returns None.
                    this.close();
                }
                return Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from(text)))));
            }
            if this.translator.is_ended() {
                return Poll::Ready(None);
            }
            // The provider body is gone once the budget cutoff dropped
            // it (eager upstream cancel): the synthesized tail above is
            // the stream's entire remainder.
            let Some(inner) = this.inner.as_mut() else {
                return Poll::Ready(None);
            };
            match Pin::new(inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    let Some(data) = frame.data_ref().cloned() else {
                        continue; // trailers / non-data frames pass by
                    };
                    let (frames, chunks, first) = this.translator.feed(data.as_ref(), this.adapter);
                    this.note_chunks(chunks, first);
                    this.budget_tick();
                    if this.translator.is_ended() {
                        this.tail.extend(this.translator.finish());
                    }
                    if frames.is_empty() {
                        // Bytes only continued a partial frame; keep
                        // polling (or drain the tail next loop).
                        continue;
                    }
                    let mut joined = String::new();
                    for f in frames {
                        joined.push_str(&f);
                    }
                    return Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from(joined)))));
                }
                Poll::Ready(Some(Err(e))) => {
                    // Mid-stream provider abort: already-forwarded
                    // content stands; the client stream ends cleanly
                    // with an error chunk and the terminator.
                    tracing::warn!(
                        code = "ai_stream_aborted",
                        provider = %this.gauges.provider,
                        "provider stream aborted mid-flight: {e}"
                    );
                    this.tail.extend(
                        this.translator
                            .abort_tail("the model provider closed the stream"),
                    );
                    continue;
                }
                Poll::Ready(None) => {
                    // Clean end: flush any unterminated frame, then
                    // the terminal usage chunk and the terminator.
                    let (frames, chunks, first) = this.translator.flush_partial(this.adapter);
                    this.note_chunks(chunks, first);
                    let mut joined = String::new();
                    for f in frames {
                        joined.push_str(&f);
                    }
                    this.tail.extend(this.translator.finish());
                    if joined.is_empty() {
                        continue;
                    }
                    return Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from(joined)))));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        false
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::default()
    }
}

impl Drop for AiStreamBody {
    fn drop(&mut self) {
        // A client that hangs up mid-stream still owes its terminal
        // metrics (duration histogram; usage if reported).
        self.close();
    }
}
