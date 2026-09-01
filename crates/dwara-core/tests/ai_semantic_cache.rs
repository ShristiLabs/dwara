//! AI semantic cache tests (DW-083): embedding-similarity caching for
//! AI prompts — through the real gateway with a mock provider and a
//! mock embedding service.
//!
//! Feature-gated: the entire suite compiles only with the
//! `semantic_cache` cargo feature (the engine is a no-op stub without
//! it). Run with:
//! `cargo test -p dwara-core --features semantic_cache --test ai_semantic_cache`.

#![cfg(feature = "semantic_cache")]

mod support;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use support::{dataplane_from, h1_client, spawn_backend_async, spawn_gateway, uri};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Embedding dimension used by the mock embedding service. Small
/// enough to be fast, large enough that bag-of-words hashing spreads
/// words across distinct dimensions.
const EMBED_DIM: usize = 64;

/// A deterministic bag-of-words embedding: each whitespace-delimited
/// token hashes to one dimension (set to 1.0), so two prompts sharing
/// most tokens produce near-identical vectors (high cosine
/// similarity). Tokens unique to one prompt lower the similarity.
/// The vector is L2-normalized so cosine similarity is a plain dot
/// product.
fn bow_embedding(text: &str) -> Vec<f32> {
    let mut vec = vec![0.0f32; EMBED_DIM];
    for token in text.split_whitespace() {
        let mut h: u64 = 0;
        for b in token.as_bytes() {
            h = h.wrapping_mul(31).wrapping_add(*b as u64);
        }
        let idx = (h % EMBED_DIM as u64) as usize;
        vec[idx] += 1.0;
    }
    // L2-normalize.
    let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for x in &mut vec {
            *x /= norm;
        }
    }
    vec
}

/// A mock embedding service: POST with `{"model": ..., "input": text}`,
/// responds `{"data": [{"embedding": [...]}]}` using the bag-of-words
/// embedding. Records the inputs it saw (for test assertions).
fn mock_embedding_service() -> (u16, Arc<Mutex<Vec<String>>>) {
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let s = Arc::clone(&seen);
    let port = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(spawn_backend_async(
            move |req: Request<Incoming>| {
                let s = Arc::clone(&s);
                async move {
                    let (_parts, body) = req.into_parts();
                    let bytes = body.collect().await.unwrap().to_bytes();
                    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                    let input = v
                        .get("input")
                        .and_then(|i| i.as_str())
                        .unwrap_or("")
                        .to_string();
                    {
                        let mut g = s.lock().unwrap();
                        g.push(input.clone());
                    }
                    let embedding = bow_embedding(&input);
                    let payload = json!({
                        "object": "list",
                        "data": [{"object": "embedding", "index": 0, "embedding": embedding}],
                        "model": "mock-embed",
                        "usage": {"prompt_tokens": 5, "total_tokens": 5}
                    });
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from(payload.to_string())))
                            .unwrap(),
                    )
                }
            },
        ))
    });
    (port, seen)
}

/// A mock OpenAI-dialect provider: non-streaming, returns a fixed JSON
/// completion with usage. Counts how many times it was called (so
/// tests can verify cache hits/misses by provider call count).
fn openai_mock_counting() -> (u16, Arc<Mutex<u64>>) {
    let seen: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
    let s = Arc::clone(&seen);
    let port = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(spawn_backend_async(
            move |req: Request<Incoming>| {
                let s = Arc::clone(&s);
                async move {
                    {
                        let mut g = s.lock().unwrap();
                        *g += 1;
                    }
                    let (_parts, body) = req.into_parts();
                    let _ = body.collect().await;
                    let payload = json!({
                        "id": "chatcmpl-test",
                        "object": "chat.completion",
                        "choices": [{
                            "index": 0,
                            "message": {"role": "assistant", "content": "hello there"},
                            "finish_reason": "stop"
                        }],
                        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
                    });
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from(payload.to_string())))
                            .unwrap(),
                    )
                }
            },
        ))
    });
    (port, seen)
}

/// A mock OpenAI-dialect provider that returns a DISTINCTIVE content
/// per call (so a cache hit returns the FIRST call's content, proving
/// no provider call was made).
fn openai_mock_distinct() -> (u16, Arc<Mutex<u64>>) {
    let seen: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
    let s = Arc::clone(&seen);
    let port = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(spawn_backend_async(
            move |req: Request<Incoming>| {
                let s = Arc::clone(&s);
                async move {
                    let n = {
                        let mut g = s.lock().unwrap();
                        *g += 1;
                        *g
                    };
                    let (_parts, body) = req.into_parts();
                    let _ = body.collect().await;
                    let payload = json!({
                        "id": format!("chatcmpl-{n}"),
                        "object": "chat.completion",
                        "choices": [{
                            "index": 0,
                            "message": {"role": "assistant", "content": format!("response-{n}")},
                            "finish_reason": "stop"
                        }],
                        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
                    });
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from(payload.to_string())))
                            .unwrap(),
                    )
                }
            },
        ))
    });
    (port, seen)
}

/// Gateway YAML: an ai route, an openai provider, one model alias, a
/// consumer with a credential, and a semantic_cache block pointing at
/// the mock embedding service. `extra_models` appends additional
/// model aliases (for cross-model tests).
fn semantic_cache_yaml(provider_port: u16, sem_cache_yaml: &str, extra_models: &str) -> String {
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
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {provider_port}\n\
         consumers:\n\
         - name: acme\n\
         \x20 credentials:\n\
         \x20 - type: api_key\n\
         \x20   key: acme-key\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: p\n\
         \x20   kind: openai\n\
         \x20   upstream: up\n\
         \x20 models:\n\
         \x20   test:\n\
         \x20     provider: p\n\
         \x20     provider_model: gpt-test\n{extra_models}\n{sem_cache_yaml}"
    )
}

/// The default semantic_cache YAML block (enabled, threshold 0.5 so
/// paraphrases with shared words hit).
fn sem_cache_block(embed_port: u16) -> String {
    format!(
        "  semantic_cache:\n\
         \x20   enabled: true\n\
         \x20   embedding_url: http://127.0.0.1:{embed_port}/v1/embeddings\n\
         \x20   embedding_model: mock-embed\n\
         \x20   embedding_dim: {EMBED_DIM}\n\
         \x20   threshold: 0.5\n\
         \x20   ttl_secs: 3600\n\
         \x20   max_entries: 10000\n\
         \x20   embedding_timeout_ms: 5000"
    )
}

/// Send a non-streaming chat request with the given content.
async fn ask(port: u16, content: &str) -> (StatusCode, Value) {
    let body = json!({
        "model": "test",
        "messages": [{"role": "user", "content": content}]
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri(port, "/v1/chat/completions"))
        .header("content-type", "application/json")
        .header("x-api-key", "acme-key")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();
    let resp = h1_client().request(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// Send a chat request with a specified model alias.
async fn ask_model(port: u16, model: &str, content: &str) -> (StatusCode, Value) {
    let body = json!({
        "model": model,
        "messages": [{"role": "user", "content": content}]
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri(port, "/v1/chat/completions"))
        .header("content-type", "application/json")
        .header("x-api-key", "acme-key")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();
    let resp = h1_client().request(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// Send a streaming chat request.
async fn ask_stream(port: u16, content: &str) -> StatusCode {
    let body = json!({
        "model": "test",
        "messages": [{"role": "user", "content": content}],
        "stream": true
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri(port, "/v1/chat/completions"))
        .header("content-type", "application/json")
        .header("x-api-key", "acme-key")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();
    let resp = h1_client().request(req).await.unwrap();
    let status = resp.status();
    // Drain the body.
    let _ = resp.into_body().collect().await;
    status
}

/// Wait for the fire-and-forget store task to land its entry in the
/// cache. The store runs in a spawned task after the response is
/// sent, so a subsequent request may race it. Poll the embedding
/// service's seen-inputs list until it has at least `n` entries.
async fn wait_for_embed_calls(seen: &Arc<Mutex<Vec<String>>>, n: usize) {
    for _ in 0..200 {
        if seen.lock().unwrap().len() >= n {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("embedding service did not see {n} calls in time");
}

// ---------------------------------------------------------------------------
// 1. Paraphrased prompt within threshold returns cached response
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn paraphrased_prompt_hits_cache() {
    let (provider_port, provider_calls) = openai_mock_distinct();
    let (embed_port, embed_seen) = mock_embedding_service();
    let dp = dataplane_from(&semantic_cache_yaml(
        provider_port,
        &sem_cache_block(embed_port),
        "",
    ));
    let gw = spawn_gateway(dp.clone()).await;

    // First request: hits the provider, stores the response.
    let (s1, v1) = ask(gw, "what is the capital of france").await;
    assert_eq!(s1, StatusCode::OK);
    let content1 = v1["choices"][0]["message"]["content"].as_str().unwrap();
    assert_eq!(content1, "response-1");
    // Wait for the fire-and-forget store to complete.
    wait_for_embed_calls(&embed_seen, 1).await;

    // Second request: a paraphrase sharing most words. The bag-of-words
    // embedding makes these near-identical (cosine similarity > 0.5).
    let (s2, v2) = ask(gw, "what is the capital of france?").await;
    assert_eq!(s2, StatusCode::OK);
    // A cache hit returns the FIRST response (no provider call).
    let content2 = v2["choices"][0]["message"]["content"].as_str().unwrap();
    assert_eq!(
        content2, "response-1",
        "paraphrased prompt should hit the cache and return the first response"
    );

    // The provider was called exactly once (the second request hit the
    // cache).
    let calls = *provider_calls.lock().unwrap();
    assert_eq!(
        calls, 1,
        "the second request should hit the cache, not the provider"
    );
}

// ---------------------------------------------------------------------------
// 2. Prompt outside threshold does not hit
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn dissimilar_prompt_misses_cache() {
    let (provider_port, provider_calls) = openai_mock_counting();
    let (embed_port, embed_seen) = mock_embedding_service();
    let dp = dataplane_from(&semantic_cache_yaml(
        provider_port,
        &sem_cache_block(embed_port),
        "",
    ));
    let gw = spawn_gateway(dp.clone()).await;

    // First request: about weather.
    let (s1, _v1) = ask(gw, "weather rain snow cold").await;
    assert_eq!(s1, StatusCode::OK);
    wait_for_embed_calls(&embed_seen, 1).await;

    // Second request: completely different words (no overlap).
    let (s2, _v2) = ask(gw, "python java rust golang").await;
    assert_eq!(s2, StatusCode::OK);

    // Both hit the provider (no shared words -> low similarity -> miss).
    let calls = *provider_calls.lock().unwrap();
    assert_eq!(calls, 2, "dissimilar prompts should both hit the provider");
}

// ---------------------------------------------------------------------------
// 3. Cost savings: N requests with M cache hits -> provider calls = N - M
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn cost_savings_provider_calls() {
    let (provider_port, provider_calls) = openai_mock_counting();
    let (embed_port, _embed_seen) = mock_embedding_service();
    let dp = dataplane_from(&semantic_cache_yaml(
        provider_port,
        &sem_cache_block(embed_port),
        "",
    ));
    let gw = spawn_gateway(dp.clone()).await;

    // 5 requests: 2 unique semantic clusters (cats, weather) with
    // paraphrases. The clusters share NO words so they do not
    // cross-hit at threshold 0.5.
    let prompts = [
        "cats feline pet animal",
        "cats feline pet animal please",
        "weather rain snow cold",
        "cats feline pet animal now",
        "weather rain snow cold please",
    ];
    for p in &prompts {
        let (s, _) = ask(gw, p).await;
        assert_eq!(s, StatusCode::OK);
        // Give the fire-and-forget store time to land between requests.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // 2 unique semantic clusters (cats, dogs) -> 2 provider calls.
    // The "please"/"now" suffixes share most words with the base
    // prompt, so they hit the cache.
    let calls = *provider_calls.lock().unwrap();
    assert!(
        calls <= 3,
        "expected at most 3 provider calls (2 unique + 1 race), got {calls}"
    );
    assert!(
        calls >= 2,
        "expected at least 2 provider calls (2 unique prompts), got {calls}"
    );
}

// ---------------------------------------------------------------------------
// 4. TTL expiry evicts entries
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn ttl_expiry_evicts() {
    let (provider_port, provider_calls) = openai_mock_counting();
    let (embed_port, embed_seen) = mock_embedding_service();
    // TTL of 1 second.
    let sem_cache = format!(
        "  semantic_cache:\n\
         \x20   enabled: true\n\
         \x20   embedding_url: http://127.0.0.1:{embed_port}/v1/embeddings\n\
         \x20   embedding_model: mock-embed\n\
         \x20   embedding_dim: {EMBED_DIM}\n\
         \x20   threshold: 0.5\n\
         \x20   ttl_secs: 1\n\
         \x20   max_entries: 10000\n\
         \x20   embedding_timeout_ms: 5000"
    );
    let dp = dataplane_from(&semantic_cache_yaml(provider_port, &sem_cache, ""));
    let gw = spawn_gateway(dp.clone()).await;

    // First request: caches the response.
    let (s1, _v1) = ask(gw, "hello world greeting").await;
    assert_eq!(s1, StatusCode::OK);
    wait_for_embed_calls(&embed_seen, 1).await;

    // Wait for TTL to expire (> 1 second).
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

    // Second request: same prompt, but the entry is stale -> miss.
    let (s2, _v2) = ask(gw, "hello world greeting").await;
    assert_eq!(s2, StatusCode::OK);

    let calls = *provider_calls.lock().unwrap();
    assert_eq!(calls, 2, "a stale entry (past TTL) should miss the cache");
}

// ---------------------------------------------------------------------------
// 5. Streaming requests bypass the cache
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn streaming_bypasses_cache() {
    let (provider_port, provider_calls) = openai_mock_counting();
    let (embed_port, embed_seen) = mock_embedding_service();
    let dp = dataplane_from(&semantic_cache_yaml(
        provider_port,
        &sem_cache_block(embed_port),
        "",
    ));
    let gw = spawn_gateway(dp.clone()).await;

    // First request: non-streaming, caches the response.
    let (s1, _v1) = ask(gw, "write a poem about stars").await;
    assert_eq!(s1, StatusCode::OK);
    wait_for_embed_calls(&embed_seen, 1).await;

    // Second request: streaming, same prompt. Streaming bypasses the
    // cache (cannot cache a stream), so it hits the provider.
    let s2 = ask_stream(gw, "write a poem about stars").await;
    assert_eq!(s2, StatusCode::OK);

    // Third request: non-streaming, same prompt. Should hit the cache
    // (the streaming request did not store, but the first did).
    let (s3, _v3) = ask(gw, "write a poem about stars").await;
    assert_eq!(s3, StatusCode::OK);

    let calls = *provider_calls.lock().unwrap();
    // First (store) + streaming (bypass) = 2. The third hits the cache.
    assert_eq!(
        calls, 2,
        "streaming bypasses the cache; the third non-streaming request hits it"
    );
}

// ---------------------------------------------------------------------------
// 6. Disabled by default (no semantic_cache config -> inert)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn disabled_by_default() {
    let (provider_port, provider_calls) = openai_mock_counting();
    let (_embed_port, _embed_seen) = mock_embedding_service();
    // No semantic_cache block at all.
    let dp = dataplane_from(&semantic_cache_yaml(provider_port, "", ""));
    let gw = spawn_gateway(dp.clone()).await;

    // Two identical requests: both hit the provider (no cache).
    let (s1, _v1) = ask(gw, "hello world").await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, _v2) = ask(gw, "hello world").await;
    assert_eq!(s2, StatusCode::OK);

    let calls = *provider_calls.lock().unwrap();
    assert_eq!(
        calls, 2,
        "without a semantic_cache config, the cache is inert"
    );
}

// ---------------------------------------------------------------------------
// 7. Cache reset when full (max_entries = 1)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn cache_reset_when_full() {
    let (provider_port, provider_calls) = openai_mock_counting();
    let (embed_port, embed_seen) = mock_embedding_service();
    // max_entries = 1: the cache resets after the second store.
    let sem_cache = format!(
        "  semantic_cache:\n\
         \x20   enabled: true\n\
         \x20   embedding_url: http://127.0.0.1:{embed_port}/v1/embeddings\n\
         \x20   embedding_model: mock-embed\n\
         \x20   embedding_dim: {EMBED_DIM}\n\
         \x20   threshold: 0.5\n\
         \x20   ttl_secs: 3600\n\
         \x20   max_entries: 1\n\
         \x20   embedding_timeout_ms: 5000"
    );
    let dp = dataplane_from(&semantic_cache_yaml(provider_port, &sem_cache, ""));
    let gw = spawn_gateway(dp.clone()).await;

    // First request: caches the response (1 entry).
    let (s1, _v1) = ask(gw, "alpha beta gamma").await;
    assert_eq!(s1, StatusCode::OK);
    wait_for_embed_calls(&embed_seen, 1).await;

    // Second request: different prompt. The store sees the cache is
    // full (1 entry), resets, then stores. So the first entry is gone.
    let (s2, _v2) = ask(gw, "delta epsilon zeta").await;
    assert_eq!(s2, StatusCode::OK);
    wait_for_embed_calls(&embed_seen, 2).await;

    // Third request: same as the first. The first entry was evicted
    // by the reset, so this is a miss -> provider call.
    let (s3, _v3) = ask(gw, "alpha beta gamma").await;
    assert_eq!(s3, StatusCode::OK);

    let calls = *provider_calls.lock().unwrap();
    assert_eq!(
        calls, 3,
        "the first entry was evicted by the reset; the third request misses"
    );
}

// ---------------------------------------------------------------------------
// 8. Different models do not cross-hit
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn different_models_do_not_cross_hit() {
    let (provider_port, provider_calls) = openai_mock_counting();
    let (embed_port, embed_seen) = mock_embedding_service();
    // Two model aliases.
    let extra_models = "    test2:\n      provider: p\n      provider_model: gpt-test-2\n";
    let dp = dataplane_from(&semantic_cache_yaml(
        provider_port,
        &sem_cache_block(embed_port),
        extra_models,
    ));
    let gw = spawn_gateway(dp.clone()).await;

    // First request: model "test", caches the response.
    let (s1, _v1) = ask_model(gw, "test", "hello world greeting").await;
    assert_eq!(s1, StatusCode::OK);
    wait_for_embed_calls(&embed_seen, 1).await;

    // Second request: same prompt, model "test2". The cache is
    // per-model, so this is a miss -> provider call.
    let (s2, _v2) = ask_model(gw, "test2", "hello world greeting").await;
    assert_eq!(s2, StatusCode::OK);

    let calls = *provider_calls.lock().unwrap();
    assert_eq!(
        calls, 2,
        "a different model alias is a miss even at high similarity"
    );
}
