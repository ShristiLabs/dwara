//! AI prompt experimentation tests (DW-086): A/B model comparison,
//! prompt versioning, regression evals, feedback ingestion, and
//! verdict computation. Tests exercise the real gateway with mock
//! providers, the embedded analytics store, and the state store for
//! prompt overrides.

mod support;

use bytes::Bytes;
use dwara_core::ai::experiments::{compute_verdict, run_eval};
use dwara_core::analytics::{AiFeedbackRecord, EmbeddedAnalytics};
use dwara_core::config::ai::AiExperiments;
use dwara_core::config::ANALYTICS_DEFAULT_RETENTION_MS;
use dwara_core::proxy::DataPlane;
use dwara_core::snapshot::validate;
use dwara_core::state::store::StateStore;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use support::{body_of, dataplane_from, h1_client, spawn_backend_async, spawn_gateway, uri};
use tokio::sync::watch;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// What one mock provider captured (the messages it saw, so tests
/// can verify prompt-version system-message prepending).
#[derive(Debug, Clone)]
struct Capture {
    #[allow(dead_code)]
    model_in_body: String,
    messages: Vec<Value>,
}

/// A mock OpenAI-dialect provider that answers 200 with a fixed
/// response, recording the `model` field and the `messages` array it
/// saw. The `label` is the content the response carries (so the test
/// can tell which provider served).
fn mock_provider(label: &'static str) -> (u16, Arc<Mutex<Vec<Capture>>>) {
    let captures: Arc<Mutex<Vec<Capture>>> = Arc::new(Mutex::new(Vec::new()));
    let caps = Arc::clone(&captures);
    let port = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(spawn_backend_async(
            move |req: Request<Incoming>| {
                let caps = Arc::clone(&caps);
                let label = label;
                async move {
                    let (_parts, body) = req.into_parts();
                    let bytes = body.collect().await.unwrap().to_bytes();
                    let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                    let model = parsed
                        .get("model")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let messages = parsed
                        .get("messages")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    caps.lock().unwrap().push(Capture {
                        model_in_body: model,
                        messages,
                    });
                    let resp = json!({
                        "id": "r",
                        "choices": [{
                            "index": 0,
                            "message": {"role": "assistant", "content": label},
                            "finish_reason": "stop"
                        }],
                        "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}
                    });
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from(resp.to_string())))
                            .unwrap(),
                    )
                }
            },
        ))
    });
    (port, captures)
}

/// A mock OpenAI-dialect provider that returns a FIXED content string
/// for every request (used by eval tests, where the scorer compares
/// the output against the expected value).
fn mock_eval_provider(fixed_content: &'static str) -> u16 {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(spawn_backend_async(
            move |req: Request<Incoming>| {
                let fixed_content = fixed_content;
                async move {
                    let (_parts, body) = req.into_parts();
                    let _ = body.collect().await.unwrap().to_bytes();
                    let resp = json!({
                        "id": "r",
                        "choices": [{
                            "index": 0,
                            "message": {"role": "assistant", "content": fixed_content},
                            "finish_reason": "stop"
                        }],
                        "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}
                    });
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from(resp.to_string())))
                            .unwrap(),
                    )
                }
            },
        ))
    })
}

/// Gateway YAML: an `ai` route, two openai-kind providers on
/// separate upstreams, two model aliases (control + treatment), and
/// an `ab_test` experiment alias `chat` that splits between them.
fn ab_test_yaml(control_port: u16, treatment_port: u16, experiments_yaml: &str) -> String {
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
         \x20 upstream: up-a\n\
         upstreams:\n\
         - name: up-a\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {control_port}\n\
         - name: up-b\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {treatment_port}\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: p-a\n\
         \x20   kind: openai\n\
         \x20   upstream: up-a\n\
         \x20 - name: p-b\n\
         \x20   kind: openai\n\
         \x20   upstream: up-b\n\
         \x20 models:\n\
         \x20   control:\n\
         \x20     provider: p-a\n\
         \x20     provider_model: control-model\n\
         \x20   treatment:\n\
         \x20     provider: p-b\n\
         \x20     provider_model: treatment-model\n\
         \x20   chat:\n\
         \x20     provider: p-a\n\
         \x20     provider_model: placeholder\n\
         \x20     ab_test: my-test\n{experiments_yaml}"
    )
}

/// Send a chat request with the given model alias and request id.
async fn ask_with_rid(port: u16, model: &str, rid: &str) -> (StatusCode, Value) {
    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(port, "/v1/chat/completions"))
                .header("content-type", "application/json")
                .header("x-request-id", rid)
                .body(Full::new(Bytes::from(
                    json!({
                        "model": model,
                        "messages": [{"role": "user", "content": "hi"}],
                        "max_tokens": 8
                    })
                    .to_string(),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, bytes) = body_of(resp).await;
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

/// Open an analytics store in a temp dir, attach it to the dataplane,
/// and spawn the background writers.
struct AnalyticsHandle {
    _dir: tempfile::TempDir,
    _shutdown_tx: watch::Sender<()>,
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
        _shutdown_tx: shutdown_tx,
    }
}

/// Wait for experiment assignment records to flush (bounded poll on
/// the store's ai_experiment_assignments row count).
fn wait_for_assignments(dp: &Arc<DataPlane>, expected: i64) {
    let store = dp.analytics().expect("analytics attached");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let count: i64 = store
            .query(|c| {
                c.query_row("SELECT COUNT(*) FROM ai_experiment_assignments", [], |r| {
                    r.get(0)
                })
            })
            .unwrap_or(0);
        if count >= expected {
            return;
        }
        if std::time::Instant::now() > deadline {
            panic!("timed out waiting for {expected} assignments, got {count}");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Wait for feedback records to flush (bounded poll on the store's
/// ai_feedback row count).
fn wait_for_feedback(store: &Arc<EmbeddedAnalytics>, expected: i64) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let count: i64 = store
            .query(|c| c.query_row("SELECT COUNT(*) FROM ai_feedback", [], |r| r.get(0)))
            .unwrap_or(0);
        if count >= expected {
            return;
        }
        if std::time::Instant::now() > deadline {
            panic!("timed out waiting for {expected} feedback records, got {count}");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Assert-style helper: true when the rendered metrics text contains
/// EVERY fragment.
fn has_all(metrics: &str, frags: &[&str]) -> bool {
    frags.iter().all(|f| metrics.contains(f))
}

// ---------------------------------------------------------------------------
// 1. A/B test assignment is deterministic per request id
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn ab_test_assignment_deterministic() {
    let (control_port, control_caps) = mock_provider("control says hi");
    let (treatment_port, treatment_caps) = mock_provider("treatment says hi");
    let experiments = "  experiments:\n    ab_tests:\n      my-test:\n        variants:\n        - name: control\n          model: control\n          weight: 5\n        - name: treatment\n          model: treatment\n          weight: 5\n";
    let dp = dataplane_from(&ab_test_yaml(control_port, treatment_port, experiments));
    let port = spawn_gateway(Arc::clone(&dp)).await;

    // Same request id -> same variant every time.
    let mut results = Vec::new();
    for _ in 0..3 {
        let (status, body) = ask_with_rid(port, "chat", "req-deterministic-001").await;
        assert_eq!(status, StatusCode::OK);
        results.push(
            body["choices"][0]["message"]["content"]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }
    // All three responses came from the same variant.
    assert_eq!(results.len(), 3);
    assert!(
        results.iter().all(|r| r == "control says hi")
            || results.iter().all(|r| r == "treatment says hi"),
        "same request id must always land on the same variant: {:?}",
        results
    );

    // The variant-selection metric fired.
    let metrics = dp.observability().render();
    assert!(has_all(
        &metrics,
        &["dwara_ai_experiment_variant_selections_total", "my-test"]
    ));
    // Only one provider was contacted (the selected variant's).
    let control_count = control_caps.lock().unwrap().len();
    let treatment_count = treatment_caps.lock().unwrap().len();
    assert_eq!(control_count + treatment_count, 3);
    assert!(control_count == 0 || treatment_count == 0);
}

// ---------------------------------------------------------------------------
// 2. A/B test assignment is recorded to analytics
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn ab_test_assignment_records_to_analytics() {
    let (control_port, _) = mock_provider("control says hi");
    let (treatment_port, _) = mock_provider("treatment says hi");
    let experiments = "  experiments:\n    ab_tests:\n      my-test:\n        variants:\n        - name: control\n          model: control\n          weight: 5\n        - name: treatment\n          model: treatment\n          weight: 5\n";
    let dp = dataplane_from(&ab_test_yaml(control_port, treatment_port, experiments));
    let _analytics = attach_analytics(&dp);
    let port = spawn_gateway(Arc::clone(&dp)).await;

    let (status, _) = ask_with_rid(port, "chat", "req-analytics-001").await;
    assert_eq!(status, StatusCode::OK);
    wait_for_assignments(&dp, 1);

    let store = dp.analytics().unwrap();
    let rows = store
        .query(|c| {
            c.query_row(
                "SELECT experiment, variant, request_id FROM ai_experiment_assignments LIMIT 1",
                [],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )
        })
        .unwrap();
    assert_eq!(rows.0, "my-test");
    assert!(
        rows.1 == "control" || rows.1 == "treatment",
        "variant must be one of the configured variants: {}",
        rows.1
    );
    assert_eq!(rows.2, "req-analytics-001");
}

// ---------------------------------------------------------------------------
// 3. Prompt version prepends a system message to the request
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn prompt_version_prepends_system_message() {
    let (control_port, control_caps) = mock_provider("control says hi");
    let (treatment_port, _) = mock_provider("treatment says hi");
    let experiments = "  experiments:\n    prompts:\n      greeting:\n        versions:\n          v1:\n            system: You are a helpful assistant.\n        active: v1\n    ab_tests:\n      my-test:\n        variants:\n        - name: control\n          model: control\n          prompt: greeting/v1\n          weight: 5\n        - name: treatment\n          model: treatment\n          weight: 5\n";
    let dp = dataplane_from(&ab_test_yaml(control_port, treatment_port, experiments));
    let port = spawn_gateway(Arc::clone(&dp)).await;

    // Find a request id that lands on the control variant (which has
    // the prompt). Try a few ids; the pick is deterministic.
    let mut found = false;
    for i in 0..20 {
        let rid = format!("req-prompt-{i}");
        let (status, body) = ask_with_rid(port, "chat", &rid).await;
        assert_eq!(status, StatusCode::OK);
        if body["choices"][0]["message"]["content"] == "control says hi" {
            // The control provider received the system message.
            let caps = control_caps.lock().unwrap();
            assert!(!caps.is_empty(), "control provider should have been called");
            let last = caps.last().unwrap();
            // The first message should be the system message from the
            // prompt version.
            assert_eq!(last.messages[0]["role"], "system");
            assert_eq!(last.messages[0]["content"], "You are a helpful assistant.");
            found = true;
            break;
        }
    }
    assert!(found, "no request id landed on the control variant");
}

// ---------------------------------------------------------------------------
// 4. Prompt override via state store changes the active version
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn prompt_override_via_state() {
    use dwara_core::ai::experiments::active_prompt_system;

    // Build an AiExperiments config with two versions.
    let mut prompts = std::collections::BTreeMap::new();
    let mut versions = std::collections::BTreeMap::new();
    versions.insert(
        "v1".to_string(),
        dwara_core::config::ai::AiPromptVersion {
            system: "default system message".to_string(),
        },
    );
    versions.insert(
        "v2".to_string(),
        dwara_core::config::ai::AiPromptVersion {
            system: "overridden system message".to_string(),
        },
    );
    prompts.insert(
        "greeting".to_string(),
        dwara_core::config::ai::AiPromptVersions {
            versions,
            active: "v1".to_string(),
        },
    );
    let experiments = AiExperiments {
        prompts,
        ..Default::default()
    };

    // Without an override, the active version is v1.
    assert_eq!(
        active_prompt_system(Some(&experiments), &[], "greeting"),
        Some("default system message".to_string())
    );

    // Open an in-memory state store and set an override to v2.
    let store = StateStore::open_in_memory().unwrap();
    store.set_prompt_override("greeting", "v2").unwrap();

    // Read the override back and apply it.
    let override_version = store.get_prompt_override("greeting").unwrap();
    assert_eq!(override_version.as_deref(), Some("v2"));
    let overrides = match override_version {
        Some(v) => vec![("greeting".to_string(), v)],
        None => vec![],
    };
    assert_eq!(
        active_prompt_system(Some(&experiments), &overrides, "greeting"),
        Some("overridden system message".to_string())
    );

    // Clear the override: reverts to v1.
    store.clear_prompt_override("greeting").unwrap();
    let override_version = store.get_prompt_override("greeting").unwrap();
    assert!(override_version.is_none());
    assert_eq!(
        active_prompt_system(Some(&experiments), &[], "greeting"),
        Some("default system message".to_string())
    );
}

// ---------------------------------------------------------------------------
// 5. Eval exact_match scorer
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn eval_exact_match_scorer() {
    let provider_port = mock_eval_provider("hello world");
    let mut evals = std::collections::BTreeMap::new();
    evals.insert(
        "exact-eval".to_string(),
        dwara_core::config::ai::AiEval {
            prompt: None,
            golden_set: vec![
                dwara_core::config::ai::AiEvalCase {
                    input: "say hello world".to_string(),
                    expected: "hello world".to_string(),
                    scorer: Some("exact_match".to_string()),
                },
                dwara_core::config::ai::AiEvalCase {
                    input: "say goodbye".to_string(),
                    expected: "goodbye".to_string(),
                    scorer: Some("exact_match".to_string()),
                },
            ],
        },
    );
    let experiments = AiExperiments {
        evals,
        ..Default::default()
    };
    let eval = &experiments.evals["exact-eval"];
    let result = run_eval(
        "exact-eval",
        eval,
        "test-model",
        "",
        &format!("http://127.0.0.1:{provider_port}/v1/chat/completions"),
        None,
        "test-model",
        None,
        5000,
    )
    .await;
    // The mock always returns "hello world": case 0 passes, case 1
    // fails.
    assert_eq!(result.cases.len(), 2);
    assert!(result.cases[0].passed);
    assert!(!result.cases[1].passed);
    assert_eq!(result.passed_count(), 1);
    assert_eq!(result.pass_rate(), 0.5);
}

// ---------------------------------------------------------------------------
// 6. Eval contains scorer
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn eval_contains_scorer() {
    let provider_port = mock_eval_provider("the quick brown fox jumps");
    let mut evals = std::collections::BTreeMap::new();
    evals.insert(
        "contains-eval".to_string(),
        dwara_core::config::ai::AiEval {
            prompt: None,
            golden_set: vec![dwara_core::config::ai::AiEvalCase {
                input: "tell me about foxes".to_string(),
                expected: "brown fox".to_string(),
                scorer: Some("contains".to_string()),
            }],
        },
    );
    let experiments = AiExperiments {
        evals,
        ..Default::default()
    };
    let eval = &experiments.evals["contains-eval"];
    let result = run_eval(
        "contains-eval",
        eval,
        "test-model",
        "",
        &format!("http://127.0.0.1:{provider_port}/v1/chat/completions"),
        None,
        "test-model",
        None,
        5000,
    )
    .await;
    assert_eq!(result.cases.len(), 1);
    assert!(result.cases[0].passed, "contains scorer should pass");
    assert_eq!(result.passed_count(), 1);
    assert_eq!(result.pass_rate(), 1.0);
}

// ---------------------------------------------------------------------------
// 7. Eval regex scorer
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn eval_regex_scorer() {
    let provider_port = mock_eval_provider("Order #12345 confirmed");
    let mut evals = std::collections::BTreeMap::new();
    evals.insert(
        "regex-eval".to_string(),
        dwara_core::config::ai::AiEval {
            prompt: None,
            golden_set: vec![dwara_core::config::ai::AiEvalCase {
                input: "confirm order".to_string(),
                expected: r"Order #\d+".to_string(),
                scorer: Some("regex".to_string()),
            }],
        },
    );
    let experiments = AiExperiments {
        evals,
        ..Default::default()
    };
    let eval = &experiments.evals["regex-eval"];
    let result = run_eval(
        "regex-eval",
        eval,
        "test-model",
        "",
        &format!("http://127.0.0.1:{provider_port}/v1/chat/completions"),
        None,
        "test-model",
        None,
        5000,
    )
    .await;
    assert_eq!(result.cases.len(), 1);
    assert!(result.cases[0].passed, "regex scorer should match");
    assert_eq!(result.passed_count(), 1);
    assert_eq!(result.pass_rate(), 1.0);
}

// ---------------------------------------------------------------------------
// 8. Feedback ingestion via analytics (direct, no admin API mTLS)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn feedback_ingestion() {
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

    store.offer_ai_feedback(AiFeedbackRecord {
        ts_ms: now_ms(),
        request_id: "req-feedback-001".to_string(),
        label: "thumbs_up".to_string(),
        comment: "great response".to_string(),
        consumer: "acme".to_string(),
        model: "chat".to_string(),
    });

    wait_for_feedback(&store, 1);

    let rows = store
        .query(|c| {
            c.query_row(
                "SELECT request_id, label, comment, consumer, model FROM ai_feedback LIMIT 1",
                [],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                    ))
                },
            )
        })
        .unwrap();
    assert_eq!(rows.0, "req-feedback-001");
    assert_eq!(rows.1, "thumbs_up");
    assert_eq!(rows.2, "great response");
    assert_eq!(rows.3, "acme");
    assert_eq!(rows.4, "chat");

    let _ = shutdown_tx.send(());
}

// ---------------------------------------------------------------------------
// 9. Verdict computation: winner has higher pass rate
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn verdict_computation() {
    let provider_port = mock_eval_provider("correct answer");

    // Build an eval config with one case expecting "correct answer".
    let mut evals = std::collections::BTreeMap::new();
    evals.insert(
        "verdict-eval".to_string(),
        dwara_core::config::ai::AiEval {
            prompt: None,
            golden_set: vec![dwara_core::config::ai::AiEvalCase {
                input: "say correct answer".to_string(),
                expected: "correct answer".to_string(),
                scorer: Some("exact_match".to_string()),
            }],
        },
    );
    let experiments = AiExperiments {
        evals,
        ..Default::default()
    };
    let eval = &experiments.evals["verdict-eval"];
    let url = format!("http://127.0.0.1:{provider_port}/v1/chat/completions");

    // Run the eval against variant "a" (passes: output matches).
    let result_a = run_eval(
        "verdict-eval",
        eval,
        "model-a",
        "a",
        &url,
        None,
        "model-a",
        None,
        5000,
    )
    .await;
    assert!(result_a.cases[0].passed);

    // Run the eval against variant "b" with a different expected
    // value (fails: output does not match).
    let mut evals_b = std::collections::BTreeMap::new();
    evals_b.insert(
        "verdict-eval".to_string(),
        dwara_core::config::ai::AiEval {
            prompt: None,
            golden_set: vec![dwara_core::config::ai::AiEvalCase {
                input: "say correct answer".to_string(),
                expected: "wrong answer".to_string(),
                scorer: Some("exact_match".to_string()),
            }],
        },
    );
    let experiments_b = AiExperiments {
        evals: evals_b,
        ..Default::default()
    };
    let eval_b = &experiments_b.evals["verdict-eval"];
    let result_b = run_eval(
        "verdict-eval",
        eval_b,
        "model-b",
        "b",
        &url,
        None,
        "model-b",
        None,
        5000,
    )
    .await;
    assert!(!result_b.cases[0].passed);

    // Compute the verdict: variant "a" has a higher pass rate.
    let verdict = compute_verdict("my-test", &[result_a, result_b]);
    assert_eq!(verdict.winner.as_deref(), Some("a"));
    assert_eq!(verdict.pass_rates.len(), 2);
}

// ---------------------------------------------------------------------------
// 10. Validation rejects ab_test with failover
// ---------------------------------------------------------------------------

#[test]
fn validation_rejects_ab_test_with_failover() {
    use dwara_core::config::parse_gateway;

    let yaml = "\
allow_empty_routes: true\n\
ai:\n\
\x20 providers:\n\
\x20 - name: p-a\n\
\x20   kind: openai\n\
\x20   upstream: u\n\
\x20 models:\n\
\x20   control:\n\
\x20     provider: p-a\n\
\x20     provider_model: m\n\
\x20   chat:\n\
\x20     provider: p-a\n\
\x20     provider_model: m\n\
\x20     failover:\n\
\x20       - provider: p-a\n\
\x20         provider_model: m2\n\
\x20     ab_test: my-test\n\
\x20 experiments:\n\
\x20   ab_tests:\n\
\x20     my-test:\n\
\x20       variants:\n\
\x20       - name: v1\n\
\x20         model: control\n\
\x20         weight: 1\n\
\x20       - name: v2\n\
\x20         model: control\n\
\x20         weight: 1\n\
upstreams:\n\
- name: u\n\
\x20 endpoints:\n\
\x20   - address: 127.0.0.1\n\
\x20     port: 9000\n";
    let gw = parse_gateway(yaml).unwrap();
    let issues = validate(&gw);
    assert!(
        issues.iter().any(|i| i
            .message
            .contains("cannot declare an ab_test together with")),
        "expected mutual-exclusivity rejection: {:?}",
        issues
    );
}

// ---------------------------------------------------------------------------
// 11. Validation rejects missing ab_test reference
// ---------------------------------------------------------------------------

#[test]
fn validation_rejects_missing_ab_test_reference() {
    use dwara_core::config::parse_gateway;

    let yaml = "\
allow_empty_routes: true\n\
ai:\n\
\x20 providers:\n\
\x20 - name: p-a\n\
\x20   kind: openai\n\
\x20   upstream: u\n\
\x20 models:\n\
\x20   chat:\n\
\x20     provider: p-a\n\
\x20     provider_model: m\n\
\x20     ab_test: nope\n\
upstreams:\n\
- name: u\n\
\x20 endpoints:\n\
\x20   - address: 127.0.0.1\n\
\x20     port: 9000\n";
    let gw = parse_gateway(yaml).unwrap();
    let issues = validate(&gw);
    assert!(
        issues.iter().any(|i| i.field == "ai.models[chat].ab_test"
            && i.message.contains("references unknown A/B test")),
        "expected missing-ab-test-reference rejection: {:?}",
        issues
    );
}

// ---------------------------------------------------------------------------
// 12. Validation rejects nested ab_test (variant model is itself an
//     experiment alias)
// ---------------------------------------------------------------------------

#[test]
fn validation_rejects_nested_ab_test() {
    use dwara_core::config::parse_gateway;

    let yaml = "\
allow_empty_routes: true\n\
ai:\n\
\x20 providers:\n\
\x20 - name: p-a\n\
\x20   kind: openai\n\
\x20   upstream: u\n\
\x20 models:\n\
\x20   plain:\n\
\x20     provider: p-a\n\
\x20     provider_model: m\n\
\x20   inner:\n\
\x20     provider: p-a\n\
\x20     provider_model: m\n\
\x20     ab_test: inner-test\n\
\x20   outer:\n\
\x20     provider: p-a\n\
\x20     provider_model: m\n\
\x20     ab_test: outer-test\n\
\x20 experiments:\n\
\x20   ab_tests:\n\
\x20     inner-test:\n\
\x20       variants:\n\
\x20       - name: v1\n\
\x20         model: plain\n\
\x20         weight: 1\n\
\x20       - name: v2\n\
\x20         model: plain\n\
\x20         weight: 1\n\
\x20     outer-test:\n\
\x20       variants:\n\
\x20       - name: v1\n\
\x20         model: inner\n\
\x20         weight: 1\n\
\x20       - name: v2\n\
\x20         model: plain\n\
\x20         weight: 1\n\
upstreams:\n\
- name: u\n\
\x20 endpoints:\n\
\x20   - address: 127.0.0.1\n\
\x20     port: 9000\n";
    let gw = parse_gateway(yaml).unwrap();
    let issues = validate(&gw);
    assert!(
        issues.iter().any(|i| i
            .message
            .contains("nested policies/experiments are not allowed")),
        "expected nested-experiment rejection: {:?}",
        issues
    );
}

// ---------------------------------------------------------------------------
// 13. Validation rejects ab_test with less than two variants
// ---------------------------------------------------------------------------

#[test]
fn validation_rejects_ab_test_with_less_than_two_variants() {
    use dwara_core::config::parse_gateway;

    let yaml = "\
allow_empty_routes: true\n\
ai:\n\
\x20 providers:\n\
\x20 - name: p-a\n\
\x20   kind: openai\n\
\x20   upstream: u\n\
\x20 models:\n\
\x20   control:\n\
\x20     provider: p-a\n\
\x20     provider_model: m\n\
\x20   chat:\n\
\x20     provider: p-a\n\
\x20     provider_model: m\n\
\x20     ab_test: my-test\n\
\x20 experiments:\n\
\x20   ab_tests:\n\
\x20     my-test:\n\
\x20       variants:\n\
\x20       - name: v1\n\
\x20         model: control\n\
\x20         weight: 1\n\
upstreams:\n\
- name: u\n\
\x20 endpoints:\n\
\x20   - address: 127.0.0.1\n\
\x20     port: 9000\n";
    let gw = parse_gateway(yaml).unwrap();
    let issues = validate(&gw);
    assert!(
        issues
            .iter()
            .any(|i| i.message.contains("at least 2 variants")),
        "expected less-than-two-variants rejection: {:?}",
        issues
    );
}

// ---------------------------------------------------------------------------
// 14. Validation rejects invalid prompt reference in a variant
// ---------------------------------------------------------------------------

#[test]
fn validation_rejects_invalid_prompt_reference() {
    use dwara_core::config::parse_gateway;

    let yaml = "\
allow_empty_routes: true\n\
ai:\n\
\x20 providers:\n\
\x20 - name: p-a\n\
\x20   kind: openai\n\
\x20   upstream: u\n\
\x20 models:\n\
\x20   control:\n\
\x20     provider: p-a\n\
\x20     provider_model: m\n\
\x20   chat:\n\
\x20     provider: p-a\n\
\x20     provider_model: m\n\
\x20     ab_test: my-test\n\
\x20 experiments:\n\
\x20   prompts:\n\
\x20     greeting:\n\
\x20       versions:\n\
\x20         v1:\n\
\x20           system: hello\n\
\x20       active: v1\n\
\x20   ab_tests:\n\
\x20     my-test:\n\
\x20       variants:\n\
\x20       - name: v1\n\
\x20         model: control\n\
\x20         prompt: greeting/nonexistent\n\
\x20         weight: 1\n\
\x20       - name: v2\n\
\x20         model: control\n\
\x20         weight: 1\n\
upstreams:\n\
- name: u\n\
\x20 endpoints:\n\
\x20   - address: 127.0.0.1\n\
\x20     port: 9000\n";
    let gw = parse_gateway(yaml).unwrap();
    let issues = validate(&gw);
    assert!(
        issues
            .iter()
            .any(|i| i.message.contains("references unknown prompt version")),
        "expected invalid-prompt-reference rejection: {:?}",
        issues
    );
}

// ---------------------------------------------------------------------------
// 15. Validation rejects invalid scorer name
// ---------------------------------------------------------------------------

#[test]
fn validation_rejects_invalid_scorer() {
    use dwara_core::config::parse_gateway;

    let yaml = "\
allow_empty_routes: true\n\
ai:\n\
\x20 providers:\n\
\x20 - name: p-a\n\
\x20   kind: openai\n\
\x20   upstream: u\n\
\x20 models:\n\
\x20   control:\n\
\x20     provider: p-a\n\
\x20     provider_model: m\n\
\x20 experiments:\n\
\x20   evals:\n\
\x20     my-eval:\n\
\x20       golden_set:\n\
\x20       - input: say hi\n\
\x20         expected: hi\n\
\x20         scorer: invalid\n\
upstreams:\n\
- name: u\n\
\x20 endpoints:\n\
\x20   - address: 127.0.0.1\n\
\x20     port: 9000\n";
    let gw = parse_gateway(yaml).unwrap();
    let issues = validate(&gw);
    assert!(
        issues
            .iter()
            .any(|i| i.message.contains("unknown scorer") && i.message.contains("invalid")),
        "expected invalid-scorer rejection: {:?}",
        issues
    );
}

// ---------------------------------------------------------------------------
// 16. Validation rejects invalid regex pattern in a regex scorer
// ---------------------------------------------------------------------------

#[test]
fn validation_rejects_invalid_regex_scorer() {
    use dwara_core::config::parse_gateway;

    let yaml = "\
allow_empty_routes: true\n\
ai:\n\
\x20 providers:\n\
\x20 - name: p-a\n\
\x20   kind: openai\n\
\x20   upstream: u\n\
\x20 models:\n\
\x20   control:\n\
\x20     provider: p-a\n\
\x20     provider_model: m\n\
\x20 experiments:\n\
\x20   evals:\n\
\x20     my-eval:\n\
\x20       golden_set:\n\
\x20       - input: say hi\n\
\x20         expected: '[invalid('\n\
\x20         scorer: regex\n\
upstreams:\n\
- name: u\n\
\x20 endpoints:\n\
\x20   - address: 127.0.0.1\n\
\x20     port: 9000\n";
    let gw = parse_gateway(yaml).unwrap();
    let issues = validate(&gw);
    assert!(
        issues
            .iter()
            .any(|i| i.message.contains("invalid regex pattern")),
        "expected invalid-regex rejection: {:?}",
        issues
    );
}
