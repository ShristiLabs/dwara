//! AI route action end-to-end tests (DW-075): the full gateway path —
//! client (OpenAI shape) -> route action -> adapter translation ->
//! provider upstream -> translated response — against in-process mock
//! providers that speak each dialect's wire format and RECORD what
//! they received (path, auth header, body), so the translation is
//! verified against what the provider actually sees, not what the
//! gateway thinks it sent.

mod support;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use support::{body_of, dataplane_from, h1_client, spawn_backend_async, spawn_gateway, uri};

/// What one mock provider captured, and what it answered.
#[derive(Debug, Clone)]
struct ProviderCapture {
    method: Method,
    path: String,
    auth_header: Option<(String, String)>,
    body: Value,
}

/// A mock provider speaking one dialect: records the request and
/// answers with a canned dialect-correct success body.
fn mock_provider(kind: &'static str) -> (u16, Arc<Mutex<Vec<ProviderCapture>>>) {
    let captures: Arc<Mutex<Vec<ProviderCapture>>> = Arc::new(Mutex::new(Vec::new()));
    let caps = Arc::clone(&captures);
    let port = futures_executor_block_on(spawn_backend_async(move |req: Request<Incoming>| {
        let caps = Arc::clone(&caps);
        let kind = kind;
        async move {
            let (parts, body) = req.into_parts();
            let bytes = body.collect().await.unwrap().to_bytes();
            let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            let auth_header = parts
                .headers
                .iter()
                .find(|(name, _)| {
                    matches!(
                        name.as_str(),
                        "authorization" | "x-api-key" | "x-goog-api-key"
                    )
                })
                .map(|(n, v)| {
                    (
                        n.as_str().to_string(),
                        String::from_utf8_lossy(v.as_bytes()).into_owned(),
                    )
                });
            caps.lock().unwrap().push(ProviderCapture {
                method: parts.method.clone(),
                path: parts.uri.path().to_string(),
                auth_header,
                body: parsed,
            });
            let resp: Value = match kind {
                "openai" => json!({
                    "id": "chatcmpl-mock",
                    "object": "chat.completion",
                    "model": "gpt-4o-mini-2024-07-18",
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": "openai says hi"},
                        "finish_reason": "stop"
                    }],
                    "usage": {"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14}
                }),
                "anthropic" => json!({
                    "id": "msg_mock",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-sonnet-4-5",
                    "content": [{"type": "text", "text": "anthropic says hi"}],
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 11, "output_tokens": 3}
                }),
                _ => json!({
                    "candidates": [{
                        "content": {"parts": [{"text": "gemini says hi"}]},
                        "finishReason": "STOP"
                    }],
                    "usageMetadata": {
                        "promptTokenCount": 11, "candidatesTokenCount": 3, "totalTokenCount": 14
                    }
                }),
            };
            Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .body(Full::new(Bytes::from(resp.to_string())))
                    .unwrap(),
            )
        }
    }));
    (port, captures)
}

/// Drive a one-shot async spawn helper on the tokio runtime the test
/// already has (spawn_backend_async is async; the tests are #[tokio::test]).
fn futures_executor_block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))
}

/// Gateway YAML: one ai route `/v1/chat/completions`, three providers
/// (one per dialect) each with its own upstream, three model aliases.
fn ai_yaml(openai_port: u16, anthropic_port: u16, gemini_port: u16) -> String {
    format!(
        "routes:\n\
         - name: chat\n\
         \x20 service: ai-svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /v1\n\
         \x20 action:\n\
         \x20   type: ai\n\
         services:\n\
         - name: ai-svc\n\
         \x20 upstream: openai-pool\n\
         upstreams:\n\
         - name: openai-pool\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {openai_port}\n\
         - name: anthropic-pool\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {anthropic_port}\n\
         - name: gemini-pool\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {gemini_port}\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: openai\n\
         \x20   kind: openai\n\
         \x20   upstream: openai-pool\n\
         \x20   auth:\n\
         \x20     header: Authorization\n\
         \x20     value: Bearer sk-openai-test\n\
         \x20 - name: anthropic\n\
         \x20   kind: anthropic\n\
         \x20   upstream: anthropic-pool\n\
         \x20   auth:\n\
         \x20     header: x-api-key\n\
         \x20     value: sk-ant-test\n\
         \x20 - name: gemini\n\
         \x20   kind: gemini\n\
         \x20   upstream: gemini-pool\n\
         \x20   auth:\n\
         \x20     header: x-goog-api-key\n\
         \x20     value: goog-test\n\
         \x20 models:\n\
         \x20   gpt-4o-mini:\n\
         \x20     provider: openai\n\
         \x20     provider_model: gpt-4o-mini-2024-07-18\n\
         \x20   claude-sonnet:\n\
         \x20     provider: anthropic\n\
         \x20     provider_model: claude-sonnet-4-5\n\
         \x20   gemini-flash:\n\
         \x20     provider: gemini\n\
         \x20     provider_model: gemini-2.5-flash\n"
    )
}

/// The SAME client call (OpenAI chat-completions shape) against three
/// providers by model alias — the DW-075 done-when, end to end.
#[tokio::test(flavor = "multi_thread")]
async fn same_client_call_serves_three_providers() {
    let (openai_port, openai_caps) = mock_provider("openai");
    let (anthropic_port, anthropic_caps) = mock_provider("anthropic");
    let (gemini_port, gemini_caps) = mock_provider("gemini");
    let dp = dataplane_from(&ai_yaml(openai_port, anthropic_port, gemini_port));
    let port = spawn_gateway(dp).await;
    let client = h1_client();

    let cases = [
        // (alias, expected text, provider path the mock must see)
        (
            "gpt-4o-mini",
            "openai says hi",
            "/v1/chat/completions",
            "openai",
        ),
        (
            "claude-sonnet",
            "anthropic says hi",
            "/v1/messages",
            "anthropic",
        ),
        (
            "gemini-flash",
            "gemini says hi",
            "/v1beta/models/gemini-2.5-flash:generateContent",
            "gemini",
        ),
    ];
    for (alias, expected_text, expected_path, provider) in cases {
        let body = json!({
            "model": alias,
            "messages": [{"role": "system", "content": "be terse"},
                         {"role": "user", "content": "hello"}],
            "max_tokens": 64
        });
        let resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(uri(port, "/v1/chat/completions"))
                    .header("content-type", "application/json")
                    .body(Full::new(Bytes::from(body.to_string())))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "alias {alias}");
        let (status, bytes) = body_of(resp).await;
        assert_eq!(status, StatusCode::OK);
        let out: Value = serde_json::from_slice(&bytes).unwrap();
        // The client ALWAYS sees the OpenAI shape with its own alias.
        assert_eq!(out["object"], "chat.completion", "alias {alias}: {out}");
        assert_eq!(out["model"], alias);
        assert_eq!(out["choices"][0]["message"]["content"], expected_text);
        assert_eq!(out["choices"][0]["finish_reason"], "stop");
        assert_eq!(out["usage"]["total_tokens"], 14);
        // The serving provider's mock captured the dialect request.
        let caps = match provider {
            "openai" => &openai_caps,
            "anthropic" => &anthropic_caps,
            _ => &gemini_caps,
        };
        let captured = caps.lock().unwrap();
        assert_eq!(captured.len(), 1, "alias {alias}");
        let c = &captured[0];
        assert_eq!(c.method, Method::POST);
        assert_eq!(c.path, expected_path, "alias {alias}");
        // The provider model (not the alias) is what the provider saw.
        let sent = serde_json::to_string(&c.body).unwrap();
        assert!(
            !sent.contains(&format!("\"{alias}\"")),
            "alias leaked: {sent}"
        );
        // Auth arrived per provider convention (hyper normalizes
        // header names to lowercase on the wire).
        let expected_auth = match provider {
            "openai" => ("authorization", "Bearer sk-openai-test"),
            "anthropic" => ("x-api-key", "sk-ant-test"),
            _ => ("x-goog-api-key", "goog-test"),
        };
        assert_eq!(
            c.auth_header,
            Some((expected_auth.0.to_string(), expected_auth.1.to_string())),
            "alias {alias}"
        );
    }

    // Anthropic got its system message LIFTED and max_tokens honored.
    let ac = anthropic_caps.lock().unwrap();
    assert_eq!(ac[0].body["system"], "be terse");
    assert_eq!(ac[0].body["max_tokens"], 64);
    assert_eq!(ac[0].body["messages"][0]["role"], "user");
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_model_answers_404_model_not_found() {
    let (openai_port, _) = mock_provider("openai");
    let (anthropic_port, _) = mock_provider("anthropic");
    let (gemini_port, _) = mock_provider("gemini");
    let dp = dataplane_from(&ai_yaml(openai_port, anthropic_port, gemini_port));
    let port = spawn_gateway(dp).await;
    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(port, "/v1/chat/completions"))
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(
                    json!({"model": "nope", "messages": [{"role": "user", "content": "hi"}]})
                        .to_string(),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, bytes) = body_of(resp).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let out: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(out["error"]["code"], "model_not_found");
    assert_eq!(out["error"]["type"], "invalid_request_error");
    assert!(out["error"]["request_id"].as_str().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_body_and_streaming_answer_400() {
    let (openai_port, _) = mock_provider("openai");
    let (anthropic_port, _) = mock_provider("anthropic");
    let (gemini_port, _) = mock_provider("gemini");
    let dp = dataplane_from(&ai_yaml(openai_port, anthropic_port, gemini_port));
    let port = spawn_gateway(dp).await;
    let client = h1_client();

    // Not JSON at all.
    let resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(port, "/v1/chat/completions"))
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from_static(b"not json")))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, bytes) = body_of(resp).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let out: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(out["error"]["code"], "invalid_json");

    // Missing model.
    let resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(port, "/v1/chat/completions"))
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(
                    json!({"messages": [{"role": "user", "content": "hi"}]}).to_string(),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _) = body_of(resp).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // stream: true until DW-077.
    let resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(port, "/v1/chat/completions"))
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(
                    json!({
                        "model": "gpt-4o-mini",
                        "messages": [{"role": "user", "content": "hi"}],
                        "stream": true
                    })
                    .to_string(),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, bytes) = body_of(resp).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let out: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(out["error"]["code"], "streaming_not_supported");
}

#[tokio::test(flavor = "multi_thread")]
async fn provider_error_passes_through_translated() {
    // A provider that answers 429 in the Anthropic error shape.
    let port_backend = futures_executor_block_on(spawn_backend_async(
        |_req: Request<Incoming>| async move {
            Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .header("content-type", "application/json")
                    .body(Full::new(Bytes::from(
                        json!({
                            "type": "error",
                            "error": {"type": "rate_limit_error", "message": "Number of requests too high"}
                        })
                        .to_string(),
                    )))
                    .unwrap(),
            )
        },
    ));
    let yaml = format!(
        "routes:\n\
         - name: chat\n\
         \x20 service: ai-svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /v1\n\
         \x20 action:\n\
         \x20   type: ai\n\
         services:\n\
         - name: ai-svc\n\
         \x20 upstream: anthropic-pool\n\
         upstreams:\n\
         - name: anthropic-pool\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port_backend}\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: anthropic\n\
         \x20   kind: anthropic\n\
         \x20   upstream: anthropic-pool\n\
         \x20 models:\n\
         \x20   claude-sonnet:\n\
         \x20     provider: anthropic\n\
         \x20     provider_model: claude-sonnet-4-5\n"
    );
    let dp = dataplane_from(&yaml);
    let port = spawn_gateway(dp).await;
    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(port, "/v1/chat/completions"))
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(
                    json!({
                        "model": "claude-sonnet",
                        "messages": [{"role": "user", "content": "hi"}]
                    })
                    .to_string(),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, bytes) = body_of(resp).await;
    // Provider status passes through verbatim (DW-076 adds failover on
    // top of exactly this signal).
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let out: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(out["error"]["message"], "Number of requests too high");
    assert_eq!(out["error"]["type"], "rate_limit_error");
}

#[tokio::test(flavor = "multi_thread")]
async fn unreachable_provider_answers_502() {
    let dead = support::dead_port();
    let yaml = format!(
        "routes:\n\
         - name: chat\n\
         \x20 service: ai-svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /v1\n\
         \x20 action:\n\
         \x20   type: ai\n\
         services:\n\
         - name: ai-svc\n\
         \x20 upstream: openai-pool\n\
         upstreams:\n\
         - name: openai-pool\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {dead}\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: openai\n\
         \x20   kind: openai\n\
         \x20   upstream: openai-pool\n\
         \x20 models:\n\
         \x20   gpt-4o-mini:\n\
         \x20     provider: openai\n\
         \x20     provider_model: gpt-4o-mini\n"
    );
    let dp = dataplane_from(&yaml);
    let port = spawn_gateway(dp).await;
    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(port, "/v1/chat/completions"))
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(
                    json!({
                        "model": "gpt-4o-mini",
                        "messages": [{"role": "user", "content": "hi"}]
                    })
                    .to_string(),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, bytes) = body_of(resp).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let out: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(out["error"]["code"], "provider_unreachable");
}

#[test]
fn ai_config_schema_is_strict_and_validation_catches_errors() {
    use dwara_core::config::parse_gateway;
    use dwara_core::snapshot::validate;

    // Well-formed minimal ai block parses and validates clean.
    let good = parse_gateway(
        "routes:\n\
         - name: r\n\
         \x20 service: s\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /v1\n\
         \x20 action:\n\
         \x20   type: ai\n\
         services:\n\
         - name: s\n\
         \x20 upstream: u\n\
         upstreams:\n\
         - name: u\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 9000\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: p\n\
         \x20   kind: anthropic\n\
         \x20   upstream: u\n\
         \x20 models:\n\
         \x20   alias:\n\
         \x20     provider: p\n\
         \x20     provider_model: m\n",
    )
    .expect("ai config parses");
    assert!(
        validate(&good).is_empty(),
        "valid ai config: {:?}",
        validate(&good)
    );

    // Unknown provider kind is a parse error (deny_unknown_fields on
    // the enum).
    assert!(parse_gateway(
        "ai:\n\
         \x20 providers:\n\
         \x20 - name: p\n\
         \x20   kind: martian\n\
         \x20   upstream: u\n\
         upstreams:\n\
         - name: u\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 9000\n"
    )
    .is_err());

    // Unknown field inside the block is rejected.
    assert!(parse_gateway(
        "ai:\n\
         \x20 providers: []\n\
         \x20 bogus: true\n"
    )
    .is_err());

    // ai route action without an ai block: validation issue.
    let no_ai = parse_gateway(
        "routes:\n\
         - name: r\n\
         \x20 service: s\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /v1\n\
         \x20 action:\n\
         \x20   type: ai\n\
         services:\n\
         - name: s\n\
         \x20 upstream: u\n\
         upstreams:\n\
         - name: u\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 9000\n",
    )
    .unwrap();
    let issues = validate(&no_ai);
    assert!(
        issues.iter().any(|i| i.field == "action.type"),
        "ai-without-block flagged: {issues:?}"
    );

    // Provider referencing an unknown upstream: issue naming it.
    let bad_upstream = parse_gateway(
        "ai:\n\
         \x20 providers:\n\
         \x20 - name: p\n\
         \x20   kind: openai\n\
         \x20   upstream: missing\n\
         \x20 models:\n\
         \x20   alias:\n\
         \x20     provider: p\n\
         \x20     provider_model: m\n",
    )
    .unwrap();
    let issues = validate(&bad_upstream);
    assert!(
        issues.iter().any(|i| i.field == "ai.providers[].upstream"),
        "unknown upstream flagged: {issues:?}"
    );

    // Model alias referencing an unknown provider: issue.
    let bad_provider_ref = parse_gateway(
        "ai:\n\
         \x20 providers:\n\
         \x20 - name: p\n\
         \x20   kind: openai\n\
         \x20   upstream: u\n\
         \x20 models:\n\
         \x20   alias:\n\
         \x20     provider: other\n\
         \x20     provider_model: m\n\
         upstreams:\n\
         - name: u\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 9000\n",
    )
    .unwrap();
    let issues = validate(&bad_provider_ref);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "ai.models[alias].provider"),
        "unknown provider ref flagged: {issues:?}"
    );

    // An unresolvable secret reference fails the generation closed
    // (DW-045 compile-time contract).
    let bad_secret = parse_gateway(
        "ai:\n\
         \x20 providers:\n\
         \x20 - name: p\n\
         \x20   kind: openai\n\
         \x20   upstream: u\n\
         \x20   auth:\n\
         \x20     header: Authorization\n\
         \x20     value: ${DW_AI_TEST_DEFINITELY_UNSET}\n\
         \x20 models:\n\
         \x20   alias:\n\
         \x20     provider: p\n\
         \x20     provider_model: m\n\
         upstreams:\n\
         - name: u\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 9000\n",
    )
    .unwrap();
    let issues = validate(&bad_secret);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "ai.providers[].auth.value"),
        "unresolvable secret flagged: {issues:?}"
    );
}

#[test]
fn inline_provider_auth_is_redacted_in_config_echoes() {
    use dwara_core::config::parse_gateway;
    let gw = parse_gateway(
        "ai:\n\
         \x20 providers:\n\
         \x20 - name: p\n\
         \x20   kind: openai\n\
         \x20   upstream: u\n\
         \x20   auth:\n\
         \x20     header: Authorization\n\
         \x20     value: Bearer sk-live-123456\n\
         upstreams:\n\
         - name: u\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 9000\n",
    )
    .unwrap();
    let redacted = gw.redacted();
    let ai = redacted.ai.unwrap();
    let value = &ai.providers[0].auth.as_ref().unwrap().value;
    assert!(value.starts_with("${redacted:sha256:"), "got {value:?}");
    assert!(!value.contains("sk-live"));
}

// ---------------------------------------------------------------------------
// Gap-fill tests (tester pass): no-auth providers, hot-reload of the
// alias table, the inbound body cap, and publish-time rejection of
// unresolvable secrets.
// ---------------------------------------------------------------------------

/// A provider with NO auth block: the outbound request must carry no
/// Authorization/x-api-key/x-goog-api-key header at all.
#[tokio::test(flavor = "multi_thread")]
async fn provider_without_auth_sends_no_auth_header() {
    let (port_backend, caps) = mock_provider("openai");
    let yaml = format!(
        "routes:\n\
         - name: chat\n\
         \x20 service: ai-svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /v1\n\
         \x20 action:\n\
         \x20   type: ai\n\
         services:\n\
         - name: ai-svc\n\
         \x20 upstream: openai-pool\n\
         upstreams:\n\
         - name: openai-pool\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port_backend}\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: internal\n\
         \x20   kind: openai\n\
         \x20   upstream: openai-pool\n\
         \x20 models:\n\
         \x20   local-model:\n\
         \x20     provider: internal\n\
         \x20     provider_model: llama3\n"
    );
    let dp = dataplane_from(&yaml);
    let port = spawn_gateway(dp).await;
    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(port, "/v1/chat/completions"))
                .header("content-type", "application/json")
                // A CLIENT Authorization must not leak to the provider
                // either: the gateway authors the provider request.
                .header("authorization", "Bearer client-should-not-pass")
                .body(Full::new(Bytes::from(
                    json!({
                        "model": "local-model",
                        "messages": [{"role": "user", "content": "hi"}]
                    })
                    .to_string(),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    let captured = caps.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert!(
        captured[0].auth_header.is_none(),
        "no auth header on an unauthenticated provider: {:?}",
        captured[0].auth_header
    );
}

/// The alias table is per GENERATION: republishing with a different
/// provider behind the same alias (and refreshing) serves from the new
/// provider with no restart.
#[tokio::test(flavor = "multi_thread")]
async fn model_alias_change_applies_on_reload() {
    let (openai_port, openai_caps) = mock_provider("openai");
    let (anthropic_port, anthropic_caps) = mock_provider("anthropic");
    let state = support::state_from(&ai_yaml(openai_port, anthropic_port, openai_port));
    let dp = Arc::new(dwara_core::dataplane::proxy::DataPlane::new(Arc::clone(
        &state,
    )));
    let port = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();

    let ask = |model: &'static str| {
        let body = json!({
            "model": model,
            "messages": [{"role": "user", "content": "hi"}]
        });
        Request::builder()
            .method(Method::POST)
            .uri(uri(port, "/v1/chat/completions"))
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap()
    };

    // Generation 1: the alias serves OpenAI.
    let resp = client.request(ask("gpt-4o-mini")).await.unwrap();
    let (_, bytes) = body_of(resp).await;
    let out: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(out["choices"][0]["message"]["content"], "openai says hi");

    // Generation 2: flip the SAME alias to the Anthropic provider.
    let original = ai_yaml(openai_port, anthropic_port, openai_port);
    let yaml2 = original.replacen(
        "provider: openai\n      provider_model: gpt-4o-mini-2024-07-18",
        "provider: anthropic\n      provider_model: claude-sonnet-4-5",
        1,
    );
    assert_ne!(
        yaml2, original,
        "the fixture must actually flip the alias (pattern drifted)"
    );
    let gateway = dwara_core::config::parse_gateway(&yaml2).expect("reload config parses");
    state
        .compile_and_publish(&gateway)
        .expect("reload publishes");
    dp.refresh();

    let resp = client.request(ask("gpt-4o-mini")).await.unwrap();
    let (status, bytes) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    let out: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        out["choices"][0]["message"]["content"], "anthropic says hi",
        "the SAME alias now serves the new provider"
    );
    assert_eq!(out["model"], "gpt-4o-mini", "alias still echoed");
    // The anthropic mock saw exactly the post-reload call on its
    // dialect path.
    let ac = anthropic_caps.lock().unwrap();
    assert!(ac.iter().any(|c| c.path == "/v1/messages"));
    let oc = openai_caps.lock().unwrap();
    assert_eq!(oc.len(), 1, "only the pre-reload call hit openai");
}

/// The inbound AI body cap: a request over 16 MiB answers 413 in the
/// AI error shape without contacting any provider.
#[tokio::test(flavor = "multi_thread")]
async fn request_body_over_cap_answers_413() {
    let (openai_port, caps) = mock_provider("openai");
    let dp = dataplane_from(&ai_yaml(openai_port, openai_port, openai_port));
    let port = spawn_gateway(dp).await;
    // One MiB over the cap: valid JSON shape, giant string value.
    let filler = "x".repeat(17 * 1024 * 1024);
    let body = json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": filler}]
    });
    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(port, "/v1/chat/completions"))
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(body.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, bytes) = body_of(resp).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let out: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(out["error"]["code"], "body_too_large");
    assert_eq!(out["error"]["type"], "invalid_request_error");
    assert!(caps.lock().unwrap().is_empty(), "no provider contact");
}

/// Publish-time fail-closed: an unresolvable secret reference in a
/// provider's auth rejects the generation (the old one keeps serving).
#[test]
fn unresolvable_auth_reference_rejects_the_publish() {
    let gateway = dwara_core::config::parse_gateway(
        "allow_empty_routes: true\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: p\n\
         \x20   kind: openai\n\
         \x20   upstream: u\n\
         \x20   auth:\n\
         \x20     header: Authorization\n\
         \x20     value: ${DW_TESTER_AI_SECRET_DEFINITELY_UNSET}\n\
         \x20 models:\n\
         \x20   alias:\n\
         \x20     provider: p\n\
         \x20     provider_model: m\n\
         upstreams:\n\
         - name: u\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 9000\n",
    )
    .unwrap();
    let state = std::sync::Arc::new(dwara_core::snapshot::ConfigState::new());
    let err = state
        .compile_and_publish(&gateway)
        .expect_err("unresolvable secret must fail the publish");
    let msg = err.to_string();
    assert!(
        msg.contains("DW_TESTER_AI_SECRET_DEFINITELY_UNSET"),
        "the error names the variable: {msg}"
    );
    assert!(
        !msg.contains("Bearer"),
        "the error never carries resolved/literal secret material: {msg}"
    );
    // The rejected publish left the generation at 0.
    assert_eq!(state.snapshot().generation(), 0);
}

// ---------------------------------------------------------------------------
// Review-loop verification (tester round 2): the high-severity finding
// (gemini functionResponse required an object) proven fixed END TO END —
// facade parse -> adapter -> provider — not just at the adapter layer.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn gemini_route_wraps_scalar_tool_output_end_to_end() {
    let (gemini_port, gemini_caps) = mock_provider("gemini");
    let dp = dataplane_from(&ai_yaml(gemini_port, gemini_port, gemini_port));
    let port = spawn_gateway(dp).await;
    // An OpenAI-shaped tool conversation whose tool result is the bare
    // number 42 (JSON string content — a calculator tool's output).
    let body = json!({
        "model": "gemini-flash",
        "messages": [
            {"role": "user", "content": "calc 6*7"},
            {"role": "assistant", "content": null, "tool_calls": [{
                "id": "c1", "type": "function",
                "function": {"name": "calc", "arguments": "{\"expr\":\"6*7\"}"}
            }]},
            {"role": "tool", "tool_call_id": "c1", "content": "42"}
        ]
    });
    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(port, "/v1/chat/completions"))
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(body.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    // The provider received a WRAPPED object in functionResponse
    // (Gemini's wire contract), with the name resolved from history.
    let caps = gemini_caps.lock().unwrap();
    assert_eq!(caps.len(), 1);
    let contents = caps[0].body["contents"].as_array().unwrap();
    let fr = contents
        .iter()
        .flat_map(|c| c["parts"].as_array().into_iter().flatten())
        .find(|p| p.get("functionResponse").is_some())
        .expect("functionResponse part reached the provider");
    assert_eq!(fr["functionResponse"]["name"], "calc");
    assert_eq!(
        fr["functionResponse"]["response"],
        json!({"result": 42}),
        "the bare scalar arrived wrapped, not bare"
    );
}
