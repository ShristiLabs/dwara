//! AI prompt/response logging tests (DW-081): opt-in capture with
//! PII redaction, sampling, retention, and per-consumer toggle —
//! through the real gateway with a mock provider and the embedded
//! analytics store.

mod support;

use bytes::Bytes;
use dwara_core::analytics::{query, AiPromptLogRecord, EmbeddedAnalytics};
use dwara_core::config::ANALYTICS_DEFAULT_RETENTION_MS;
use dwara_core::proxy::DataPlane;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use support::{dataplane_from, h1_client, spawn_backend_async, spawn_gateway, uri};
use tokio::sync::watch;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// A mock OpenAI-dialect provider: non-streaming, returns a JSON
/// completion with usage. Records the request count.
fn openai_mock() -> (u16, Arc<Mutex<u64>>) {
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

/// Gateway YAML: an ai route, an OpenAI provider, one model alias,
/// a consumer with a credential, and an optional `ai.logging` block.
fn logging_yaml(port: u16, logging_yaml: &str, consumer_ai_logging: &str) -> String {
    let consumer_extra = if consumer_ai_logging.is_empty() {
        String::new()
    } else {
        format!("\n  ai_logging: {consumer_ai_logging}")
    };
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
         \x20     port: {port}\n\
         consumers:\n\
         - name: acme\n\
         \x20 credentials:\n\
         \x20 - type: api_key\n\
         \x20   key: acme-key{consumer_extra}\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: p\n\
         \x20   kind: openai\n\
         \x20   upstream: up\n\
         \x20 models:\n\
         \x20   gpt-4:\n\
         \x20     provider: p\n\
         \x20     provider_model: gpt-4o-mini\n{logging_yaml}"
    )
}

/// Attach analytics to the dataplane and spawn the writer.
struct AnalyticsHandle {
    _dir: tempfile::TempDir,
    store: Arc<EmbeddedAnalytics>,
    _workers: Vec<tokio::task::JoinHandle<()>>,
    _shutdown: tokio::sync::watch::Sender<()>,
}

fn attach_analytics(dp: &Arc<DataPlane>) -> AnalyticsHandle {
    let dir = tempfile::tempdir().unwrap();
    let store = EmbeddedAnalytics::open(
        &dir.path().join("a.db").display().to_string(),
        ANALYTICS_DEFAULT_RETENTION_MS,
        100,
        0,
    )
    .unwrap();
    dp.set_analytics(Arc::clone(&store));
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let _workers = store.spawn_workers(shutdown_rx);
    AnalyticsHandle {
        _dir: dir,
        store,
        _workers,
        _shutdown: shutdown_tx,
    }
}

/// Send a chat completion request through the gateway.
async fn send_chat(port: u16, model: &str, content: &str) -> Value {
    let client = h1_client();
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
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Wait for the prompt log writer to flush (poll until count > 0 or
/// timeout).
async fn wait_for_prompt_logs(store: &Arc<EmbeddedAnalytics>, expected: usize) {
    for _ in 0..100 {
        let count = store
            .query(|c| {
                c.query_row::<i64, _, _>("SELECT COUNT(*) FROM ai_prompt_logs", [], |r| r.get(0))
            })
            .unwrap_or(0);
        if count >= expected as i64 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("prompt logs did not flush within 1s (expected {expected})");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// When logging is OFF (the default), no prompt logs are captured.
#[tokio::test(flavor = "multi_thread")]
async fn logging_off_captures_nothing() {
    let (backend_port, seen) = openai_mock();
    let yaml = logging_yaml(backend_port, "", "");
    let dp = dataplane_from(&yaml);
    let port = spawn_gateway(Arc::clone(&dp)).await;
    let _h = attach_analytics(&dp);

    let resp = send_chat(port, "gpt-4", "hello world").await;
    assert!(resp["choices"][0]["message"]["content"].as_str().unwrap() == "hello there");
    assert_eq!(*seen.lock().unwrap(), 1);

    // No prompt logs should be written.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let count = _h
        .store
        .query(|c| {
            c.query_row::<i64, _, _>("SELECT COUNT(*) FROM ai_prompt_logs", [], |r| r.get(0))
        })
        .unwrap();
    assert_eq!(
        count, 0,
        "no prompt logs should be captured when logging is off"
    );
}

/// When logging is ON, the prompt and response are captured and
/// redacted.
#[tokio::test(flavor = "multi_thread")]
async fn logging_on_captures_and_redacts() {
    let (backend_port, seen) = openai_mock();
    let logging = "  logging:\n    enabled: true\n    sample_rate: 1.0\n    retention_secs: 3600\n";
    let yaml = logging_yaml(backend_port, logging, "");
    let dp = dataplane_from(&yaml);
    let port = spawn_gateway(Arc::clone(&dp)).await;
    let _h = attach_analytics(&dp);

    let _resp = send_chat(port, "gpt-4", "my email is alice@example.com").await;
    assert_eq!(*seen.lock().unwrap(), 1);

    wait_for_prompt_logs(&_h.store, 1).await;

    let rows = _h
        .store
        .query(|c| {
            query::prompt_logs(
                c,
                &query::PromptLogQuery {
                    from_ms: 0,
                    to_ms: i64::MAX,
                    consumer: None,
                    limit: None,
                },
            )
        })
        .unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.consumer, "acme");
    assert_eq!(row.route, "chat");
    assert_eq!(row.provider, "p");
    assert_eq!(row.model, "gpt-4o-mini");
    assert!(!row.stream);

    // The prompt JSON should be redacted: the email must NOT appear.
    assert!(
        !row.prompt_json.contains("alice@example.com"),
        "PII must be redacted from the prompt: got {}",
        row.prompt_json
    );
    assert!(
        row.prompt_json.contains("[REDACTED]"),
        "the redaction sentinel must appear: got {}",
        row.prompt_json
    );
}

/// Per-consumer override: a consumer with `ai_logging: false` is not
/// captured even when global logging is on.
#[tokio::test(flavor = "multi_thread")]
async fn per_consumer_override_disables_capture() {
    let (backend_port, seen) = openai_mock();
    let logging = "  logging:\n    enabled: true\n    sample_rate: 1.0\n    retention_secs: 3600\n";
    let yaml = logging_yaml(backend_port, logging, "false");
    let dp = dataplane_from(&yaml);
    let port = spawn_gateway(Arc::clone(&dp)).await;
    let _h = attach_analytics(&dp);

    let _resp = send_chat(port, "gpt-4", "hello").await;
    assert_eq!(*seen.lock().unwrap(), 1);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let count = _h
        .store
        .query(|c| {
            c.query_row::<i64, _, _>("SELECT COUNT(*) FROM ai_prompt_logs", [], |r| r.get(0))
        })
        .unwrap();
    assert_eq!(count, 0, "per-consumer override should disable capture");
}

/// Direct insert and query: the offer_ai_prompt_log + prompt_logs
/// query path works end-to-end without the gateway.
#[tokio::test(flavor = "multi_thread")]
async fn prompt_log_direct_insert_and_query() {
    let dir = tempfile::tempdir().unwrap();
    let store = EmbeddedAnalytics::open(
        &dir.path().join("a.db").display().to_string(),
        ANALYTICS_DEFAULT_RETENTION_MS,
        50,
        0,
    )
    .unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let _workers = store.spawn_workers(shutdown_rx);

    store.offer_ai_prompt_log(AiPromptLogRecord {
        ts_ms: 1000,
        request_id: "req-1".into(),
        consumer: "acme".into(),
        route: "chat".into(),
        provider: "p".into(),
        model: "gpt-4o-mini".into(),
        version: "".into(),
        prompt_json: r#"{"model":"gpt-4"}"#.into(),
        response_json: r#"{"choices":[]}"#.into(),
        stream: false,
    });
    store.offer_ai_prompt_log(AiPromptLogRecord {
        ts_ms: 2000,
        request_id: "req-2".into(),
        consumer: "beta".into(),
        route: "chat".into(),
        provider: "p".into(),
        model: "gpt-4o-mini".into(),
        version: "".into(),
        prompt_json: r#"{"model":"gpt-4"}"#.into(),
        response_json: r#"{"streamed":true}"#.into(),
        stream: true,
    });

    // Wait for flush.
    for _ in 0..100 {
        let count = store
            .query(|c| {
                c.query_row::<i64, _, _>("SELECT COUNT(*) FROM ai_prompt_logs", [], |r| r.get(0))
            })
            .unwrap();
        if count == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // Query all.
    let rows = store
        .query(|c| {
            query::prompt_logs(
                c,
                &query::PromptLogQuery {
                    from_ms: 0,
                    to_ms: i64::MAX,
                    consumer: None,
                    limit: None,
                },
            )
        })
        .unwrap();
    assert_eq!(rows.len(), 2);
    // Newest first.
    assert_eq!(rows[0].request_id, "req-2");
    assert!(rows[0].stream);
    assert_eq!(rows[1].request_id, "req-1");
    assert!(!rows[1].stream);

    // Query by consumer.
    let rows = store
        .query(|c| {
            query::prompt_logs(
                c,
                &query::PromptLogQuery {
                    from_ms: 0,
                    to_ms: i64::MAX,
                    consumer: Some("acme".into()),
                    limit: None,
                },
            )
        })
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].request_id, "req-1");

    drop(shutdown_tx);
}

/// The prompt-logs query rejects an invalid range (from >= to).
#[tokio::test(flavor = "multi_thread")]
async fn prompt_log_query_rejects_bad_range() {
    let q = query::PromptLogQuery {
        from_ms: 100,
        to_ms: 100,
        consumer: None,
        limit: None,
    };
    assert!(q.validate().is_err());
}

/// The prompt-logs query respects the limit.
#[tokio::test(flavor = "multi_thread")]
async fn prompt_log_query_respects_limit() {
    let dir = tempfile::tempdir().unwrap();
    let store = EmbeddedAnalytics::open(
        &dir.path().join("a.db").display().to_string(),
        ANALYTICS_DEFAULT_RETENTION_MS,
        50,
        0,
    )
    .unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let _workers = store.spawn_workers(shutdown_rx);

    for i in 0..10 {
        store.offer_ai_prompt_log(AiPromptLogRecord {
            ts_ms: 1000 + i,
            request_id: format!("req-{i}"),
            consumer: "acme".into(),
            route: "chat".into(),
            provider: "p".into(),
            model: "gpt-4o-mini".into(),
            version: "".into(),
            prompt_json: "{}".into(),
            response_json: "{}".into(),
            stream: false,
        });
    }

    // Wait for flush.
    for _ in 0..100 {
        let count = store
            .query(|c| {
                c.query_row::<i64, _, _>("SELECT COUNT(*) FROM ai_prompt_logs", [], |r| r.get(0))
            })
            .unwrap();
        if count == 10 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    let rows = store
        .query(|c| {
            query::prompt_logs(
                c,
                &query::PromptLogQuery {
                    from_ms: 0,
                    to_ms: i64::MAX,
                    consumer: None,
                    limit: Some(3),
                },
            )
        })
        .unwrap();
    assert_eq!(rows.len(), 3);

    drop(shutdown_tx);
}

/// Validation: an invalid sample_rate fails at publish.
#[tokio::test(flavor = "multi_thread")]
async fn validation_rejects_invalid_sample_rate() {
    let (backend_port, _) = openai_mock();
    let logging = "  logging:\n    enabled: true\n    sample_rate: 2.0\n    retention_secs: 3600\n";
    let yaml = logging_yaml(backend_port, logging, "");
    // The dataplane_from helper calls validate; an invalid config
    // should produce validation issues. We test via the snapshot
    // pipeline directly.
    let gateway: dwara_core::config::Gateway =
        serde_yaml_ng::from_str(&yaml).unwrap_or_else(|e| panic!("YAML parse error: {e}"));
    let issues = dwara_core::snapshot::validate(&gateway);
    let has_sample_rate_issue = issues.iter().any(|i| i.field.contains("sample_rate"));
    assert!(
        has_sample_rate_issue,
        "validation should reject sample_rate > 1.0: issues = {:?}",
        issues
    );
}

/// Validation: an invalid regex pattern fails at publish.
#[tokio::test(flavor = "multi_thread")]
async fn validation_rejects_invalid_regex() {
    let (backend_port, _) = openai_mock();
    let logging = "  logging:\n    enabled: true\n    sample_rate: 1.0\n    retention_secs: 3600\n    redaction:\n      patterns:\n        - '[invalid('\n";
    let yaml = logging_yaml(backend_port, logging, "");
    let gateway: dwara_core::config::Gateway =
        serde_yaml_ng::from_str(&yaml).unwrap_or_else(|e| panic!("YAML parse error: {e}"));
    let issues = dwara_core::snapshot::validate(&gateway);
    let has_regex_issue = issues.iter().any(|i| i.field.contains("patterns"));
    assert!(
        has_regex_issue,
        "validation should reject invalid regex: issues = {:?}",
        issues
    );
}

/// Validation: retention_secs == 0 when enabled fails at publish.
#[tokio::test(flavor = "multi_thread")]
async fn validation_rejects_zero_retention_when_enabled() {
    let (backend_port, _) = openai_mock();
    let logging = "  logging:\n    enabled: true\n    sample_rate: 1.0\n    retention_secs: 0\n";
    let yaml = logging_yaml(backend_port, logging, "");
    let gateway: dwara_core::config::Gateway =
        serde_yaml_ng::from_str(&yaml).unwrap_or_else(|e| panic!("YAML parse error: {e}"));
    let issues = dwara_core::snapshot::validate(&gateway);
    let has_retention_issue = issues.iter().any(|i| i.field.contains("retention_secs"));
    assert!(
        has_retention_issue,
        "validation should reject retention_secs == 0 when enabled: issues = {:?}",
        issues
    );
}
