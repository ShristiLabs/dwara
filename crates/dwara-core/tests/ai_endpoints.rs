//! AI-02: endpoint breadth beyond chat — integration tests for the
//! passthrough endpoints (embeddings, images, audio, moderation).
//!
//! These tests verify that non-chat AI endpoints are proxied as a
//! passthrough: the request body is forwarded to the provider's
//! upstream as-is, and the response is returned as-is. Model
//! governance (allowlist check) still applies.

mod support;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::StatusCode;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use support::{dataplane_from, h1_client, spawn_backend_async, spawn_gateway, uri};

/// A mock backend that echoes the request body as the response (the
/// passthrough should forward the body verbatim, so the echo confirms
/// no translation was applied).
async fn echo_backend() -> (u16, Arc<Mutex<u32>>) {
    let calls = Arc::new(Mutex::new(0u32));
    let calls_clone = Arc::clone(&calls);
    let handler = move |req: hyper::Request<Incoming>| {
        let calls = Arc::clone(&calls_clone);
        async move {
            *calls.lock().unwrap() += 1;
            let bytes = req.into_body().collect().await.unwrap().to_bytes();
            let resp = hyper::Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(http_body_util::Full::new(bytes))
                .unwrap();
            Ok::<_, std::convert::Infallible>(resp)
        }
    };
    let port = spawn_backend_async(handler).await;
    (port, calls)
}

/// A mock backend that returns a fixed OpenAI chat completion response
/// (used to verify the chat pipeline still works with the new endpoint
/// field).
async fn chat_mock_backend() -> (u16, Arc<Mutex<u32>>) {
    let calls = Arc::new(Mutex::new(0u32));
    let calls_clone = Arc::clone(&calls);
    let handler = move |_req: hyper::Request<Incoming>| {
        let calls = Arc::clone(&calls_clone);
        async move {
            *calls.lock().unwrap() += 1;
            let body = json!({
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "created": 1234567890,
                "model": "gpt-4o",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "hi"},
                    "finish_reason": "stop"
                }],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
            });
            let resp = hyper::Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(http_body_util::Full::new(Bytes::from(body.to_string())))
                .unwrap();
            Ok::<_, std::convert::Infallible>(resp)
        }
    };
    let port = spawn_backend_async(handler).await;
    (port, calls)
}

/// Build a gateway config with an AI route using the `embeddings`
/// endpoint.
fn embeddings_yaml(port: u16) -> String {
    format!(
        "routes:\n\
         - name: r\n\
         \x20 service: ai-svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /v1/embeddings\n\
         \x20 action:\n\
         \x20   type: ai\n\
         \x20   endpoint: embeddings\n\
         services:\n\
         - name: ai-svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port}\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: p\n\
         \x20   kind: openai\n\
         \x20   upstream: up\n\
         \x20 models:\n\
         \x20   chat:\n\
         \x20     provider: p\n\
         \x20     provider_model: text-embedding-3-small\n"
    )
}

/// Build a gateway config with an AI route using the `images`
/// endpoint.
fn images_yaml(port: u16) -> String {
    format!(
        "routes:\n\
         - name: r\n\
         \x20 service: ai-svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /v1/images/generations\n\
         \x20 action:\n\
         \x20   type: ai\n\
         \x20   endpoint: images\n\
         services:\n\
         - name: ai-svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port}\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: p\n\
         \x20   kind: openai\n\
         \x20   upstream: up\n\
         \x20 models:\n\
         \x20   chat:\n\
         \x20     provider: p\n\
         \x20     provider_model: dall-e-3\n"
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn embeddings_passthrough_forwards_body_as_is() {
    let (port, calls) = echo_backend().await;
    let dp = dataplane_from(&embeddings_yaml(port));
    let gw = spawn_gateway(dp).await;

    let body = json!({
        "model": "chat",
        "input": "hello world",
    });
    let resp = h1_client()
        .request(
            hyper::Request::builder()
                .method("POST")
                .uri(uri(gw, "/v1/embeddings"))
                .header("content-type", "application/json")
                .body(http_body_util::Full::new(Bytes::from(body.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let (_, resp_body) = support::body_of(resp).await;
    let resp_json: Value = serde_json::from_slice(&resp_body).unwrap();
    // The echo backend returns the request body verbatim — confirming
    // the passthrough forwarded it without translation.
    assert_eq!(resp_json["model"], "chat");
    assert_eq!(resp_json["input"], "hello world");
    assert_eq!(*calls.lock().unwrap(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn images_passthrough_forwards_body_as_is() {
    let (port, calls) = echo_backend().await;
    let dp = dataplane_from(&images_yaml(port));
    let gw = spawn_gateway(dp).await;

    let body = json!({
        "model": "chat",
        "prompt": "a cat",
        "n": 1,
        "size": "1024x1024",
    });
    let resp = h1_client()
        .request(
            hyper::Request::builder()
                .method("POST")
                .uri(uri(gw, "/v1/images/generations"))
                .header("content-type", "application/json")
                .body(http_body_util::Full::new(Bytes::from(body.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let (_, resp_body) = support::body_of(resp).await;
    let resp_json: Value = serde_json::from_slice(&resp_body).unwrap();
    assert_eq!(resp_json["prompt"], "a cat");
    assert_eq!(*calls.lock().unwrap(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn passthrough_returns_404_for_unknown_model() {
    let (port, _calls) = echo_backend().await;
    let dp = dataplane_from(&embeddings_yaml(port));
    let gw = spawn_gateway(dp).await;

    let body = json!({
        "model": "nonexistent",
        "input": "hello",
    });
    let resp = h1_client()
        .request(
            hyper::Request::builder()
                .method("POST")
                .uri(uri(gw, "/v1/embeddings"))
                .header("content-type", "application/json")
                .body(http_body_util::Full::new(Bytes::from(body.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn chat_endpoint_still_works_with_endpoint_field() {
    // The default endpoint is `chat`; an AI route without an explicit
    // `endpoint` field should still use the chat translation pipeline.
    let (port, calls) = chat_mock_backend().await;
    let yaml = format!(
        "routes:\n\
         - name: r\n\
         \x20 service: ai-svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /v1/chat/completions\n\
         \x20 action:\n\
         \x20   type: ai\n\
         services:\n\
         - name: ai-svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port}\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: p\n\
         \x20   kind: openai\n\
         \x20   upstream: up\n\
         \x20 models:\n\
         \x20   chat:\n\
         \x20     provider: p\n\
         \x20     provider_model: gpt-4o\n"
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;

    let body = json!({
        "model": "chat",
        "messages": [{"role": "user", "content": "hi"}],
    });
    let resp = h1_client()
        .request(
            hyper::Request::builder()
                .method("POST")
                .uri(uri(gw, "/v1/chat/completions"))
                .header("content-type", "application/json")
                .body(http_body_util::Full::new(Bytes::from(body.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    // The chat endpoint should work — the mock returns a valid OpenAI
    // chat completion response that the chat pipeline can translate.
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(*calls.lock().unwrap(), 1);
}
