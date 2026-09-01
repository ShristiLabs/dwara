//! AI routing-policy tests (DW-085): within-request escalation via
//! an external classifier service (FallbackChain), and static
//! latency-vs-cost selection (LatencyCost). The policies compose
//! over DW-076 routing — the candidate aliases they name are plain
//! chain/canary aliases, and the policy returns a flat candidate
//! list the dataplane walks with the same failover loop.

mod support;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use support::{
    body_of, dataplane_from, dead_port, h1_client, spawn_backend_async, spawn_gateway, uri,
};

/// What one mock provider captured.
#[derive(Debug, Clone)]
struct Capture {
    model_in_body: String,
}

/// A mock AI provider that answers 200 with a fixed response body,
/// recording the `model` field it saw. The `label` is the content
/// the response carries (so the test can tell which provider served).
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
                    caps.lock().unwrap().push(Capture {
                        model_in_body: parsed
                            .get("model")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
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

/// A mock classifier service that returns a FIXED complexity score
/// for every request. The test sets the score via the `score`
/// parameter; the service echoes it back in the
/// `{"data": [{"score": ...}]}` shape.
fn mock_classifier(score: f64) -> u16 {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(spawn_backend_async(
            move |req: Request<Incoming>| {
                async move {
                    // Drain the request body (the classifier POST).
                    let (_parts, body) = req.into_parts();
                    let _ = body.collect().await.unwrap().to_bytes();
                    let resp = json!({"data": [{"score": score}]});
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

/// A mock classifier service that always returns 500 (to test the
/// fail-open path).
fn mock_classifier_error() -> u16 {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(spawn_backend_async(
            move |req: Request<Incoming>| async move {
                let (_parts, body) = req.into_parts();
                let _ = body.collect().await.unwrap().to_bytes();
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header("content-type", "application/json")
                        .body(Full::new(Bytes::from(
                            json!({"error": "classifier down"}).to_string(),
                        )))
                        .unwrap(),
                )
            },
        ))
    })
}

/// Gateway YAML: an `ai` route, two openai-kind providers on
/// separate upstreams, two model aliases (cheap + expensive), and a
/// fallback_chain routing policy that the `chat` alias uses.
fn fallback_chain_yaml(
    cheap_port: u16,
    expensive_port: u16,
    classifier_port: u16,
    threshold: f64,
) -> String {
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
         \x20     port: {cheap_port}\n\
         - name: up-b\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {expensive_port}\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: p-cheap\n\
         \x20   kind: openai\n\
         \x20   upstream: up-a\n\
         \x20 - name: p-expensive\n\
         \x20   kind: openai\n\
         \x20   upstream: up-b\n\
         \x20 models:\n\
         \x20   cheap:\n\
         \x20     provider: p-cheap\n\
         \x20     provider_model: cheap-model\n\
         \x20   expensive:\n\
         \x20     provider: p-expensive\n\
         \x20     provider_model: expensive-model\n\
         \x20   chat:\n\
         \x20     provider: p-cheap\n\
         \x20     provider_model: placeholder\n\
         \x20     routing_policy: fc\n\
         \x20 routing_policies:\n\
         \x20   fc:\n\
         \x20     kind: fallback_chain\n\
         \x20     cheap: cheap\n\
         \x20     escalate_to: expensive\n\
         \x20     classifier_url: http://127.0.0.1:{classifier_port}/classify\n\
         \x20     classifier_model: complexity\n\
         \x20     threshold: {threshold}\n\
         \x20     timeout_ms: 2000\n"
    )
}

/// Gateway YAML for a latency_cost policy with two candidates.
fn latency_cost_yaml(cheap_port: u16, expensive_port: u16, preference: &str) -> String {
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
         \x20     port: {cheap_port}\n\
         - name: up-b\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {expensive_port}\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: p-cheap\n\
         \x20   kind: openai\n\
         \x20   upstream: up-a\n\
         \x20 - name: p-expensive\n\
         \x20   kind: openai\n\
         \x20   upstream: up-b\n\
         \x20 models:\n\
         \x20   cheap:\n\
         \x20     provider: p-cheap\n\
         \x20     provider_model: cheap-model\n\
         \x20   expensive:\n\
         \x20     provider: p-expensive\n\
         \x20     provider_model: expensive-model\n\
         \x20   chat:\n\
         \x20     provider: p-cheap\n\
         \x20     provider_model: placeholder\n\
         \x20     routing_policy: lc\n\
         \x20 routing_policies:\n\
         \x20   lc:\n\
         \x20     kind: latency_cost\n\
         \x20     preference: {preference}\n\
         \x20     candidates:\n\
         \x20       - model: cheap\n\
         \x20         cost: 1\n\
         \x20         latency: 8\n\
         \x20       - model: expensive\n\
         \x20         cost: 9\n\
         \x20         latency: 2\n"
    )
}

async fn ask(port: u16, model: &str, content: &str) -> (StatusCode, Value) {
    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(port, "/v1/chat/completions"))
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(
                    json!({
                        "model": model,
                        "messages": [{"role": "user", "content": content}],
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

/// Assert-style helper: true when the rendered metrics text contains
/// EVERY fragment.
fn has_all(metrics: &str, frags: &[&str]) -> bool {
    frags.iter().all(|f| metrics.contains(f))
}

// -------------------------------------------------------------------------
// FallbackChain policy tests.
// -------------------------------------------------------------------------

/// A simple prompt (classifier score 0.2 < threshold 0.5) routes to
/// the cheap model.
#[tokio::test(flavor = "multi_thread")]
async fn fallback_chain_simple_prompt_routes_to_cheap() {
    let classifier_port = mock_classifier(0.2);
    let (cheap_port, cheap_caps) = mock_provider("cheap says hi");
    let (expensive_port, expensive_caps) = mock_provider("expensive says hi");
    let dp = dataplane_from(&fallback_chain_yaml(
        cheap_port,
        expensive_port,
        classifier_port,
        0.5,
    ));
    let port = spawn_gateway(Arc::clone(&dp)).await;

    let (status, body) = ask(port, "chat", "simple prompt").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["choices"][0]["message"]["content"], "cheap says hi");

    // The cheap provider saw the cheap model id; the expensive
    // provider was never contacted.
    assert_eq!(cheap_caps.lock().unwrap().len(), 1);
    assert_eq!(cheap_caps.lock().unwrap()[0].model_in_body, "cheap-model");
    assert!(expensive_caps.lock().unwrap().is_empty());

    // The cheap-selection metric fired.
    let metrics = dp.observability().render();
    assert!(has_all(
        &metrics,
        &["dwara_ai_routing_policy_cheap_total", "policy=\"fc\""]
    ));
}

/// A complex prompt (classifier score 0.8 >= threshold 0.5)
/// escalates to the expensive model.
#[tokio::test(flavor = "multi_thread")]
async fn fallback_chain_complex_prompt_escalates() {
    let classifier_port = mock_classifier(0.8);
    let (cheap_port, cheap_caps) = mock_provider("cheap says hi");
    let (expensive_port, expensive_caps) = mock_provider("expensive says hi");
    let dp = dataplane_from(&fallback_chain_yaml(
        cheap_port,
        expensive_port,
        classifier_port,
        0.5,
    ));
    let port = spawn_gateway(Arc::clone(&dp)).await;

    let (status, body) = ask(port, "chat", "a very complex prompt").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["choices"][0]["message"]["content"],
        "expensive says hi"
    );

    // The expensive provider saw the expensive model id; the cheap
    // provider was never contacted.
    assert!(cheap_caps.lock().unwrap().is_empty());
    assert_eq!(expensive_caps.lock().unwrap().len(), 1);
    assert_eq!(
        expensive_caps.lock().unwrap()[0].model_in_body,
        "expensive-model"
    );

    // The escalation metric fired.
    let metrics = dp.observability().render();
    assert!(has_all(
        &metrics,
        &["dwara_ai_routing_policy_escalations_total", "policy=\"fc\""]
    ));
}

/// When the classifier service errors, the policy fails open to the
/// cheap model (the safe default).
#[tokio::test(flavor = "multi_thread")]
async fn fallback_chain_classifier_error_fails_open_to_cheap() {
    let classifier_port = mock_classifier_error();
    let (cheap_port, cheap_caps) = mock_provider("cheap says hi");
    let (expensive_port, expensive_caps) = mock_provider("expensive says hi");
    let dp = dataplane_from(&fallback_chain_yaml(
        cheap_port,
        expensive_port,
        classifier_port,
        0.5,
    ));
    let port = spawn_gateway(Arc::clone(&dp)).await;

    let (status, body) = ask(port, "chat", "any prompt").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["choices"][0]["message"]["content"], "cheap says hi");

    // The cheap provider served the request; the expensive provider
    // was never contacted.
    assert_eq!(cheap_caps.lock().unwrap().len(), 1);
    assert!(expensive_caps.lock().unwrap().is_empty());

    // The cheap-selection metric fired (fail-open counts as a cheap
    // selection, not an escalation).
    let metrics = dp.observability().render();
    assert!(has_all(
        &metrics,
        &["dwara_ai_routing_policy_cheap_total", "policy=\"fc\""]
    ));
}

/// When the classifier service is unreachable (dead port), the
/// policy fails open to the cheap model.
#[tokio::test(flavor = "multi_thread")]
async fn fallback_chain_classifier_unreachable_fails_open() {
    let classifier_port = dead_port();
    let (cheap_port, cheap_caps) = mock_provider("cheap says hi");
    let (expensive_port, expensive_caps) = mock_provider("expensive says hi");
    let dp = dataplane_from(&fallback_chain_yaml(
        cheap_port,
        expensive_port,
        classifier_port,
        0.5,
    ));
    let port = spawn_gateway(dp).await;

    let (status, body) = ask(port, "chat", "any prompt").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["choices"][0]["message"]["content"], "cheap says hi");
    assert_eq!(cheap_caps.lock().unwrap().len(), 1);
    assert!(expensive_caps.lock().unwrap().is_empty());
}

// -------------------------------------------------------------------------
// LatencyCost policy tests.
// -------------------------------------------------------------------------

/// preference=cost picks the cheapest candidate (cost 1 < cost 9).
#[tokio::test(flavor = "multi_thread")]
async fn latency_cost_picks_cheapest() {
    let (cheap_port, cheap_caps) = mock_provider("cheap says hi");
    let (expensive_port, expensive_caps) = mock_provider("expensive says hi");
    let dp = dataplane_from(&latency_cost_yaml(cheap_port, expensive_port, "cost"));
    let port = spawn_gateway(Arc::clone(&dp)).await;

    let (status, body) = ask(port, "chat", "any prompt").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["choices"][0]["message"]["content"], "cheap says hi");
    assert_eq!(cheap_caps.lock().unwrap().len(), 1);
    assert!(expensive_caps.lock().unwrap().is_empty());

    let metrics = dp.observability().render();
    assert!(has_all(
        &metrics,
        &[
            "dwara_ai_routing_policy_latency_cost_selections_total",
            "policy=\"lc\""
        ]
    ));
}

/// preference=latency picks the fastest candidate (latency 2 <
/// latency 8).
#[tokio::test(flavor = "multi_thread")]
async fn latency_cost_picks_fastest() {
    let (cheap_port, cheap_caps) = mock_provider("cheap says hi");
    let (expensive_port, expensive_caps) = mock_provider("expensive says hi");
    let dp = dataplane_from(&latency_cost_yaml(cheap_port, expensive_port, "latency"));
    let port = spawn_gateway(dp).await;

    let (status, body) = ask(port, "chat", "any prompt").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["choices"][0]["message"]["content"],
        "expensive says hi"
    );
    assert!(cheap_caps.lock().unwrap().is_empty());
    assert_eq!(expensive_caps.lock().unwrap().len(), 1);
}

/// preference=balanced picks the best cost+latency sum (cheap: 1+8=9,
/// expensive: 9+2=11 — cheap wins).
#[tokio::test(flavor = "multi_thread")]
async fn latency_cost_picks_balanced() {
    let (cheap_port, cheap_caps) = mock_provider("cheap says hi");
    let (expensive_port, expensive_caps) = mock_provider("expensive says hi");
    let dp = dataplane_from(&latency_cost_yaml(cheap_port, expensive_port, "balanced"));
    let port = spawn_gateway(dp).await;

    let (status, body) = ask(port, "chat", "any prompt").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["choices"][0]["message"]["content"], "cheap says hi");
    assert_eq!(cheap_caps.lock().unwrap().len(), 1);
    assert!(expensive_caps.lock().unwrap().is_empty());
}

// -------------------------------------------------------------------------
// Validation tests.
// -------------------------------------------------------------------------

/// Validation rejects a model that declares both `routing_policy`
/// and `failover`.
#[test]
fn validation_rejects_policy_with_failover() {
    use dwara_core::config::parse_gateway;
    use dwara_core::snapshot::validate;

    let yaml = "\
allow_empty_routes: true\n\
ai:\n\
\x20 providers:\n\
\x20 - name: p-a\n\
\x20   kind: openai\n\
\x20   upstream: u\n\
\x20 models:\n\
\x20   cheap:\n\
\x20     provider: p-a\n\
\x20     provider_model: m\n\
\x20   chat:\n\
\x20     provider: p-a\n\
\x20     provider_model: m\n\
\x20     failover:\n\
\x20       - provider: p-a\n\
\x20         provider_model: m2\n\
\x20     routing_policy: fc\n\
\x20 routing_policies:\n\
\x20   fc:\n\
\x20     kind: fallback_chain\n\
\x20     cheap: cheap\n\
\x20     escalate_to: cheap\n\
\x20     classifier_url: http://x\n\
\x20     classifier_model: c\n\
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
            .contains("cannot declare a routing_policy together with")),
        "expected mutual-exclusivity rejection: {:?}",
        issues
    );
}

/// Validation rejects a model that references a non-existent policy.
#[test]
fn validation_rejects_missing_policy_reference() {
    use dwara_core::config::parse_gateway;
    use dwara_core::snapshot::validate;

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
\x20     routing_policy: nope\n\
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
            .any(|i| i.field == "ai.models[chat].routing_policy"
                && i.message.contains("references unknown routing policy")),
        "expected missing-policy-reference rejection: {:?}",
        issues
    );
}

/// Validation rejects a FallbackChain policy whose `cheap` alias
/// does not exist.
#[test]
fn validation_rejects_fallback_chain_missing_cheap() {
    use dwara_core::config::parse_gateway;
    use dwara_core::snapshot::validate;

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
\x20     routing_policy: fc\n\
\x20 routing_policies:\n\
\x20   fc:\n\
\x20     kind: fallback_chain\n\
\x20     cheap: nope\n\
\x20     escalate_to: chat\n\
\x20     classifier_url: http://x\n\
\x20     classifier_model: c\n\
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
            .any(|i| i.field == "ai.routing_policies[fallback_chain].cheap"
                && i.message.contains("references unknown model alias")),
        "expected missing-cheap-alias rejection: {:?}",
        issues
    );
}

/// Validation rejects a LatencyCost policy with an out-of-range cost
/// score.
#[test]
fn validation_rejects_latency_cost_out_of_range_score() {
    use dwara_core::config::parse_gateway;
    use dwara_core::snapshot::validate;

    let yaml = "\
allow_empty_routes: true\n\
ai:\n\
\x20 providers:\n\
\x20 - name: p-a\n\
\x20   kind: openai\n\
\x20   upstream: u\n\
\x20 models:\n\
\x20   cheap:\n\
\x20     provider: p-a\n\
\x20     provider_model: m\n\
\x20   chat:\n\
\x20     provider: p-a\n\
\x20     provider_model: m\n\
\x20     routing_policy: lc\n\
\x20 routing_policies:\n\
\x20   lc:\n\
\x20     kind: latency_cost\n\
\x20     preference: cost\n\
\x20     candidates:\n\
\x20       - model: cheap\n\
\x20         cost: 99\n\
\x20         latency: 1\n\
upstreams:\n\
- name: u\n\
\x20 endpoints:\n\
\x20   - address: 127.0.0.1\n\
\x20     port: 9000\n";
    let gw = parse_gateway(yaml).unwrap();
    let issues = validate(&gw);
    assert!(
        issues.iter().any(
            |i| i.field == "ai.routing_policies[latency_cost].candidates[0].cost"
                && i.message.contains("1..=10")
        ),
        "expected out-of-range cost rejection: {:?}",
        issues
    );
}

/// Validation rejects a nested policy reference (a policy alias
/// referenced by another policy).
#[test]
fn validation_rejects_nested_policy_reference() {
    use dwara_core::config::parse_gateway;
    use dwara_core::snapshot::validate;

    let yaml = "\
allow_empty_routes: true\n\
ai:\n\
\x20 providers:\n\
\x20 - name: p-a\n\
\x20   kind: openai\n\
\x20   upstream: u\n\
\x20 models:\n\
\x20   cheap:\n\
\x20     provider: p-a\n\
\x20     provider_model: m\n\
\x20   inner:\n\
\x20     provider: p-a\n\
\x20     provider_model: m\n\
\x20     routing_policy: lc-inner\n\
\x20   outer:\n\
\x20     provider: p-a\n\
\x20     provider_model: m\n\
\x20     routing_policy: lc-outer\n\
\x20 routing_policies:\n\
\x20   lc-inner:\n\
\x20     kind: latency_cost\n\
\x20     preference: cost\n\
\x20     candidates:\n\
\x20       - model: cheap\n\
\x20         cost: 1\n\
\x20         latency: 1\n\
\x20   lc-outer:\n\
\x20     kind: latency_cost\n\
\x20     preference: cost\n\
\x20     candidates:\n\
\x20       - model: inner\n\
\x20         cost: 1\n\
\x20         latency: 1\n\
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
            .any(|i| i.message.contains("nested policies are not allowed")),
        "expected nested-policy rejection: {:?}",
        issues
    );
}

// -------------------------------------------------------------------------
// Cost-savings measurement test.
// -------------------------------------------------------------------------

/// Over a workload of N requests with M escalations, the cheap model
/// is called N-M times and the expensive model is called M times.
/// The classifier returns a score based on the prompt content: a
/// prompt containing "complex" gets 0.9, everything else gets 0.1.
#[tokio::test(flavor = "multi_thread")]
async fn fallback_chain_cost_savings_measured() {
    // A classifier that returns 0.9 for prompts containing "complex"
    // and 0.1 otherwise.
    let classifier_port = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(spawn_backend_async(
            move |req: Request<Incoming>| async move {
                let (_parts, body) = req.into_parts();
                let bytes = body.collect().await.unwrap().to_bytes();
                let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                let input = parsed
                    .get("input")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let score = if input.contains("complex") { 0.9 } else { 0.1 };
                let resp = json!({"data": [{"score": score}]});
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .body(Full::new(Bytes::from(resp.to_string())))
                        .unwrap(),
                )
            },
        ))
    });
    let (cheap_port, cheap_caps) = mock_provider("cheap");
    let (expensive_port, expensive_caps) = mock_provider("expensive");
    let dp = dataplane_from(&fallback_chain_yaml(
        cheap_port,
        expensive_port,
        classifier_port,
        0.5,
    ));
    let port = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();

    let n = 10;
    let mut expected_escalations = 0;
    for i in 0..n {
        let content = if i % 3 == 0 {
            expected_escalations += 1;
            format!("complex prompt {i}")
        } else {
            format!("simple prompt {i}")
        };
        let resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(uri(port, "/v1/chat/completions"))
                    .header("content-type", "application/json")
                    .header("x-request-id", format!("rid-fc-{i}"))
                    .body(Full::new(Bytes::from(
                        json!({
                            "model": "chat",
                            "messages": [{"role": "user", "content": content}],
                            "max_tokens": 8
                        })
                        .to_string(),
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, _) = body_of(resp).await;
        assert_eq!(status, StatusCode::OK, "request {i}");
    }

    let cheap_count = cheap_caps.lock().unwrap().len();
    let expensive_count = expensive_caps.lock().unwrap().len();
    assert_eq!(cheap_count + expensive_count, n);
    assert_eq!(expensive_count, expected_escalations);
    assert_eq!(cheap_count, n - expected_escalations);

    // The metrics reflect the split.
    let metrics = dp.observability().render();
    assert!(has_all(
        &metrics,
        &["dwara_ai_routing_policy_escalations_total", "policy=\"fc\""]
    ));
    assert!(has_all(
        &metrics,
        &["dwara_ai_routing_policy_cheap_total", "policy=\"fc\""]
    ));
}
