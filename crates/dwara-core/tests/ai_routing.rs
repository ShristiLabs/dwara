//! AI routing and failover tests (DW-076): the candidate walk in the
//! dataplane's AI action — failover on transient provider failures,
//! the deterministic weighted canary split, and attribution of usage
//! to the provider/version that actually served.

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

/// A mock provider that answers every request with `status` (and a
/// dialect-correct success body for 200s), recording what it saw.
fn mock_provider(status: u16, text: &'static str) -> (u16, Arc<Mutex<Vec<Capture>>>) {
    let captures: Arc<Mutex<Vec<Capture>>> = Arc::new(Mutex::new(Vec::new()));
    let caps = Arc::clone(&captures);
    let port = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(spawn_backend_async(
            move |req: Request<Incoming>| {
                let caps = Arc::clone(&caps);
                let status = status;
                let text = text;
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
                    let resp: Value = if status == 200 {
                        json!({
                            "id": "r",
                            "choices": [{
                                "index": 0,
                                "message": {"role": "assistant", "content": text},
                                "finish_reason": "stop"
                            }],
                            "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}
                        })
                    } else {
                        json!({"error": {"message": format!("provider says {status}"), "type": "server_error"}})
                    };
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::from_u16(status).unwrap())
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

/// Gateway YAML: an `ai` route plus the given model-alias YAML
/// fragment, with two openai-kind providers on separate upstreams.
fn routing_yaml(primary_port: u16, alternate_port: u16, models_yaml: &str) -> String {
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
         \x20     port: {primary_port}\n\
         - name: up-b\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {alternate_port}\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: p-a\n\
         \x20   kind: openai\n\
         \x20   upstream: up-a\n\
         \x20 - name: p-b\n\
         \x20   kind: openai\n\
         \x20   upstream: up-b\n\
         \x20 models:\n{models_yaml}"
    )
}

async fn ask(port: u16, model: &str) -> (StatusCode, Value) {
    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(port, "/v1/chat/completions"))
                .header("content-type", "application/json")
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

/// The done-when: a provider outage (429) transparently fails over to
/// the configured alternate and the client sees a successful response,
/// with BOTH attempts visible in the metrics.
#[tokio::test(flavor = "multi_thread")]
async fn failover_on_429_serves_the_alternate() {
    let (primary_port, primary_caps) = mock_provider(429, "primary");
    let (alt_port, alt_caps) = mock_provider(200, "alternate says hi");
    let models = "   chat:\n     provider: p-a\n     provider_model: model-a\n     failover:\n     - provider: p-b\n       provider_model: model-b\n";
    let dp = dataplane_from(&routing_yaml(primary_port, alt_port, models));
    let port = spawn_gateway(Arc::clone(&dp)).await;

    let (status, body) = ask(port, "chat").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["choices"][0]["message"]["content"],
        "alternate says hi"
    );

    // Both providers saw the request; the alternate got model-b.
    assert_eq!(primary_caps.lock().unwrap().len(), 1);
    let alt = alt_caps.lock().unwrap();
    assert_eq!(alt.len(), 1);
    assert_eq!(alt[0].model_in_body, "model-b");

    // Attribution: the 429 attempt counted against p-a, the success
    // against p-b (the DW-079 metering input).
    let metrics = dp.observability().render();
    assert!(metrics.contains("dwara_ai_requests_total{"));
    assert!(has_all(
        &metrics,
        &["provider=\"p-a\"", "outcome=\"provider_error\""]
    ));
    assert!(has_all(
        &metrics,
        &["provider=\"p-b\"", "outcome=\"success\""]
    ));
}

/// A 5xx fails over exactly like a 429.
#[tokio::test(flavor = "multi_thread")]
async fn failover_on_500_serves_the_alternate() {
    let (primary_port, _) = mock_provider(500, "primary");
    let (alt_port, _) = mock_provider(200, "from the alternate");
    let models = "   chat:\n     provider: p-a\n     provider_model: model-a\n     failover:\n     - provider: p-b\n       provider_model: model-b\n";
    let dp = dataplane_from(&routing_yaml(primary_port, alt_port, models));
    let port = spawn_gateway(dp).await;
    let (status, body) = ask(port, "chat").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["choices"][0]["message"]["content"],
        "from the alternate"
    );
}

/// A transport error (unreachable upstream) fails over too.
#[tokio::test(flavor = "multi_thread")]
async fn failover_on_transport_error_serves_the_alternate() {
    let dead = dead_port();
    let (alt_port, alt_caps) = mock_provider(200, "backup alive");
    let models = "   chat:\n     provider: p-a\n     provider_model: model-a\n     failover:\n     - provider: p-b\n       provider_model: model-b\n";
    let dp = dataplane_from(&routing_yaml(dead, alt_port, models));
    let port = spawn_gateway(Arc::clone(&dp)).await;
    let (status, body) = ask(port, "chat").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["choices"][0]["message"]["content"], "backup alive");
    assert_eq!(alt_caps.lock().unwrap().len(), 1);
    // The transport failure is attributed.
    let metrics = dp.observability().render();
    assert!(has_all(
        &metrics,
        &["provider=\"p-a\"", "outcome=\"transport_error\""]
    ));
}

/// When every candidate fails, the client sees the LAST provider's
/// answer (the closest to the truth of the outage).
#[tokio::test(flavor = "multi_thread")]
async fn exhausted_chain_returns_the_last_provider_error() {
    let (primary_port, _) = mock_provider(429, "primary");
    let (alt_port, _) = mock_provider(503, "alternate");
    let models = "   chat:\n     provider: p-a\n     provider_model: model-a\n     failover:\n     - provider: p-b\n       provider_model: model-b\n";
    let dp = dataplane_from(&routing_yaml(primary_port, alt_port, models));
    let port = spawn_gateway(dp).await;
    let (status, body) = ask(port, "chat").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["message"], "provider says 503");
}

/// Non-transient provider errors (a 404) are FINAL: no failover, the
/// alternate is never contacted.
#[tokio::test(flavor = "multi_thread")]
async fn non_retryable_error_does_not_fail_over() {
    let (primary_port, _) = mock_provider(404, "primary");
    let (alt_port, alt_caps) = mock_provider(200, "alternate");
    let models = "   chat:\n     provider: p-a\n     provider_model: model-a\n     failover:\n     - provider: p-b\n       provider_model: model-b\n";
    let dp = dataplane_from(&routing_yaml(primary_port, alt_port, models));
    let port = spawn_gateway(dp).await;
    let (status, body) = ask(port, "chat").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["message"], "provider says 404");
    assert!(
        alt_caps.lock().unwrap().is_empty(),
        "the alternate must not be contacted on a deterministic error"
    );
}

/// Without a failover list, a 429 passes straight through (DW-075
/// behavior preserved).
#[tokio::test(flavor = "multi_thread")]
async fn no_failover_list_means_passthrough() {
    let (primary_port, _) = mock_provider(429, "primary");
    let (alt_port, alt_caps) = mock_provider(200, "alternate");
    let models = "   chat:\n     provider: p-a\n     provider_model: model-a\n";
    let dp = dataplane_from(&routing_yaml(primary_port, alt_port, models));
    let port = spawn_gateway(dp).await;
    let (status, _) = ask(port, "chat").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(alt_caps.lock().unwrap().is_empty());
}

/// The done-when: a weighted canary across two model versions
/// delivers the configured split (deterministic per request id) and
/// attributes serving by version in the metrics.
#[tokio::test(flavor = "multi_thread")]
async fn canary_split_converges_and_attributes_by_version() {
    let (stable_port, stable_caps) = mock_provider(200, "stable");
    let (canary_port, canary_caps) = mock_provider(200, "canary");
    let models = "   chat:\n     provider: p-a\n     provider_model: placeholder\n     canary:\n     - version: stable\n       weight: 9\n       provider: p-a\n       provider_model: model-stable\n     - version: canary\n       weight: 1\n       provider: p-b\n       provider_model: model-canary\n";
    let dp = dataplane_from(&routing_yaml(stable_port, canary_port, models));
    let port = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();

    let mut served_by = vec![];
    for i in 0..200 {
        let resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(uri(port, "/v1/chat/completions"))
                    .header("content-type", "application/json")
                    .header("x-request-id", format!("rid-canary-{i}"))
                    .body(Full::new(Bytes::from(
                        json!({"model": "chat", "messages": [{"role": "user", "content": "hi"}]})
                            .to_string(),
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, bytes) = body_of(resp).await;
        assert_eq!(status, StatusCode::OK, "request {i}");
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        served_by.push(
            body["choices"][0]["message"]["content"]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }
    let stable = served_by.iter().filter(|s| *s == "stable").count();
    let canary = served_by.iter().filter(|s| *s == "canary").count();
    assert_eq!(stable + canary, 200);
    // 9:1 configured: a deterministic hash of 200 distinct ids must
    // land in a wide window around 180/20 — and never degenerate to
    // one side (that would mean the pick is constant).
    assert!(
        (150..=200).contains(&stable),
        "stable served {stable}/200 — split degenerated"
    );
    assert!(
        canary >= 5,
        "canary served {canary}/200 — split degenerated"
    );
    // The provider saw the VERSION's model id, not the placeholder.
    assert!(stable_caps
        .lock()
        .unwrap()
        .iter()
        .all(|c| c.model_in_body == "model-stable"));
    assert!(canary_caps
        .lock()
        .unwrap()
        .iter()
        .all(|c| c.model_in_body == "model-canary"));

    // Determinism: the SAME request id always lands on the same side.
    for _ in 0..3 {
        let resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(uri(port, "/v1/chat/completions"))
                    .header("content-type", "application/json")
                    .header("x-request-id", "rid-canary-7")
                    .body(Full::new(Bytes::from(
                        json!({"model": "chat", "messages": [{"role": "user", "content": "hi"}]})
                            .to_string(),
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (_, bytes) = body_of(resp).await;
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let side = body["choices"][0]["message"]["content"].as_str().unwrap();
        let first = served_by[7].clone();
        assert_eq!(side, first, "same request id must pick the same version");
    }

    // Attribution: both version labels exist with success outcomes.
    let metrics = dp.observability().render();
    assert!(has_all(
        &metrics,
        &["outcome=\"success\"", "version=\"stable\""]
    ));
    assert!(has_all(
        &metrics,
        &["outcome=\"success\"", "version=\"canary\""]
    ));
    // Token usage attributed per version too (DW-079 input).
    assert!(metrics.contains("dwara_ai_tokens_total{"));
    assert!(has_all(
        &metrics,
        &["dwara_ai_tokens_total", "version=\"stable\""]
    ));
    assert!(has_all(
        &metrics,
        &["dwara_ai_tokens_total", "version=\"canary\""]
    ));
}

/// The compiled routing plan: chain order preserved, canary yields one
/// deterministic target per key, missing alias yields none.
#[test]
fn runtime_route_plans_chains_and_canaries() {
    use dwara_core::ai::{CompiledModel, RouteTarget};
    use dwara_core::config::ai::{
        AiCanaryVersion, AiConfig, AiModel, AiModelTarget, AiProvider, AiProviderKind,
    };

    let cfg = AiConfig {
        providers: vec![
            AiProvider {
                name: "p-a".into(),
                kind: AiProviderKind::Openai,
                upstream: "u".into(),
                auth: None,
            },
            AiProvider {
                name: "p-b".into(),
                kind: AiProviderKind::Anthropic,
                upstream: "u".into(),
                auth: None,
            },
        ],
        models: [
            (
                "chained".to_string(),
                AiModel {
                    provider: "p-a".into(),
                    provider_model: "m1".into(),
                    failover: vec![AiModelTarget {
                        provider: "p-b".into(),
                        provider_model: "m2".into(),
                    }],
                    canary: vec![],
                    routing_policy: None,
                    ab_test: None,
                },
            ),
            (
                "split".to_string(),
                AiModel {
                    provider: "p-a".into(),
                    provider_model: "placeholder".into(),
                    failover: vec![],
                    canary: vec![
                        AiCanaryVersion {
                            version: "v1".into(),
                            weight: 9,
                            provider: "p-a".into(),
                            provider_model: "m1".into(),
                        },
                        AiCanaryVersion {
                            version: "v2".into(),
                            weight: 1,
                            provider: "p-b".into(),
                            provider_model: "m2".into(),
                        },
                    ],
                    routing_policy: None,
                    ab_test: None,
                },
            ),
        ]
        .into_iter()
        .collect(),
        pricing: std::collections::BTreeMap::new(),
        governance: None,
        logging: None,
        guardrails: None,
        semantic_cache: None,
        routing_policies: std::collections::BTreeMap::new(),
        experiments: None,
    };
    let rt = dwara_core::ai::AiRuntime::compile(Some(&cfg)).unwrap();

    // Chain: primary first, alternates in order.
    let chain = rt.route("chained", "any-key");
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].provider, "p-a");
    assert_eq!(chain[1].provider_model, "m2");
    assert!(chain.iter().all(|t| t.version.is_none()));

    // Canary: exactly one target per key, deterministic per key.
    let pick = rt.route("split", "rid-1");
    assert_eq!(pick.len(), 1);
    assert!(pick[0].version.is_some());
    for key in ["rid-1", "rid-2", "rid-3"] {
        assert_eq!(
            rt.route("split", key)[0].provider_model,
            pick_key_model(&rt, key)
        );
    }
    // The compiled entry shapes are what validation promised.
    assert!(matches!(rt.model("chained"), Some(CompiledModel::Chain(_))));
    assert!(matches!(rt.model("split"), Some(CompiledModel::Canary(_))));
    // Missing alias: no candidates.
    assert!(rt.route("missing", "k").is_empty());
    assert!(rt.resolve("missing").is_none());
    // Primary resolve of a split alias still answers (first version).
    let (provider, model) = rt.resolve("split").unwrap();
    assert_eq!(provider.name, "p-a");
    assert_eq!(model, "m1");

    fn pick_key_model(rt: &dwara_core::ai::AiRuntime, key: &str) -> String {
        rt.route("split", key)[0].provider_model.clone()
    }
    let _: Option<&RouteTarget> = None;
}

/// Validation matrix (DW-076): mutual exclusion, unknown provider
/// refs, duplicate chain pairs, zero weights, duplicate version names.
#[test]
fn routing_validation_catches_authoring_errors() {
    use dwara_core::config::parse_gateway;
    use dwara_core::snapshot::validate;

    let base = |models: &str| {
        format!(
            "allow_empty_routes: true\n\
             ai:\n\
             \x20 providers:\n\
             \x20 - name: p-a\n\
             \x20   kind: openai\n\
             \x20   upstream: u\n\
             \x20 - name: p-b\n\
             \x20   kind: anthropic\n\
             \x20   upstream: u\n\
             \x20 models:\n{models}\n\
             upstreams:\n\
             - name: u\n\
             \x20 endpoints:\n\
             \x20   - address: 127.0.0.1\n\
             \x20     port: 9000\n"
        )
    };

    // Valid chain + valid canary (on separate aliases) pass.
    let good = parse_gateway(&base(
        "   chained:\n     provider: p-a\n     provider_model: m\n     failover:\n     - provider: p-b\n       provider_model: m2\n   split:\n     provider: p-a\n     provider_model: m\n     canary:\n     - version: v1\n       weight: 9\n       provider: p-a\n       provider_model: m1\n     - version: v2\n       weight: 1\n       provider: p-b\n       provider_model: m2\n",
    ))
    .unwrap();
    assert!(validate(&good).is_empty(), "{:?}", validate(&good));

    // Both failover and canary on ONE alias: rejected.
    let both = parse_gateway(&base(
        "   chat:\n     provider: p-a\n     provider_model: m\n     failover:\n     - provider: p-b\n       provider_model: m2\n     canary:\n     - version: v1\n       weight: 9\n       provider: p-a\n       provider_model: m1\n",
    ))
    .unwrap();
    assert!(validate(&both).iter().any(|i| i
        .message
        .contains("cannot declare both failover and canary")));

    // Unknown provider in the chain: rejected, named.
    let unknown = parse_gateway(&base(
        "   chat:\n     provider: p-a\n     provider_model: m\n     failover:\n     - provider: nope\n       provider_model: m2\n",
    ))
    .unwrap();
    assert!(validate(&unknown)
        .iter()
        .any(|i| i.field == "ai.models[chat].failover[0].provider"));

    // Duplicate provider/model pair in the chain: rejected.
    let dup = parse_gateway(&base(
        "   chat:\n     provider: p-a\n     provider_model: m\n     failover:\n     - provider: p-a\n       provider_model: m\n",
    ))
    .unwrap();
    assert!(validate(&dup)
        .iter()
        .any(|i| i.message.contains("duplicates the provider/model pair")));

    // Zero weight: rejected.
    let zero = parse_gateway(&base(
        "   chat:\n     provider: p-a\n     provider_model: m\n     canary:\n     - version: v1\n       weight: 0\n       provider: p-a\n       provider_model: m1\n",
    ))
    .unwrap();
    assert!(validate(&zero)
        .iter()
        .any(|i| i.field == "ai.models[chat].canary[0].weight"));

    // Duplicate version names: rejected.
    let dupver = parse_gateway(&base(
        "   chat:\n     provider: p-a\n     provider_model: m\n     canary:\n     - version: v1\n       weight: 5\n       provider: p-a\n       provider_model: m1\n     - version: v1\n       weight: 5\n       provider: p-b\n       provider_model: m2\n",
    ));
    let dupver = dupver.unwrap();
    assert!(validate(&dupver)
        .iter()
        .any(|i| i.message.contains("duplicate version name")));

    // --- length bounds (review loop 1) ---

    let canary_entries = |n: usize| {
        let mut y =
            String::from("   chat:\n     provider: p-a\n     provider_model: m\n     canary:\n");
        for i in 0..n {
            let prov = if i % 2 == 0 { "p-a" } else { "p-b" };
            y.push_str(&format!(
                "     - version: v{i}\n       weight: 1\n       provider: {prov}\n       provider_model: m{i}\n"
            ));
        }
        y
    };
    let failover_entries = |n: usize| {
        let mut y =
            String::from("   chat:\n     provider: p-a\n     provider_model: m0\n     failover:\n");
        // Unique provider/model pairs across the chain.
        let pairs = [
            ("p-b", "m1"),
            ("p-a", "m1"),
            ("p-b", "m2"),
            ("p-a", "m2"),
            ("p-b", "m3"),
        ];
        for (prov, model) in pairs.iter().take(n) {
            y.push_str(&format!(
                "     - provider: {prov}\n       provider_model: {model}\n"
            ));
        }
        y
    };

    // Canary with ONE version is not a split: rejected.
    let one = parse_gateway(&base(&canary_entries(1))).unwrap();
    assert!(validate(&one)
        .iter()
        .any(|i| i.field == "ai.models[chat].canary" && i.message.contains("2..=8")));

    // Canary with NINE versions: rejected.
    let nine = parse_gateway(&base(&canary_entries(9))).unwrap();
    assert!(validate(&nine).iter().any(|i| i.message.contains("2..=8")));

    // Failover with FIVE alternates: rejected.
    let five = parse_gateway(&base(&failover_entries(5))).unwrap();
    assert!(validate(&five)
        .iter()
        .any(|i| i.field == "ai.models[chat].failover" && i.message.contains("at most 4")));

    // Boundaries accepted: canary 2 and 8, failover 4.
    for n in [2usize, 8] {
        let ok = parse_gateway(&base(&canary_entries(n))).unwrap();
        assert!(
            validate(&ok).is_empty(),
            "canary {n} must be valid: {:?}",
            validate(&ok)
        );
    }
    let four = parse_gateway(&base(&failover_entries(4))).unwrap();
    assert!(validate(&four).is_empty(), "{:?}", validate(&four));
}

/// One `label_match("a=\"b\"", ...)` helper: renders a metric line
/// fragment with the given label substrings in order-insensitive
/// containment (the text format sorts labels alphabetically, so a
/// contains-check per fragment is exact enough).
/// Assert-style helper: true when the rendered metrics text contains
/// EVERY fragment (the text format renders labels alphabetically, so
/// fragments are matched independently rather than as one string).
fn has_all(metrics: &str, frags: &[&str]) -> bool {
    frags.iter().all(|f| metrics.contains(f))
}

// ---------------------------------------------------------------------------
// Gap-fill tests (tester pass): deep chains, translation-rejection
// failover, generation-following canary ramps, cross-dialect versions,
// and exact attempt accounting.
// ---------------------------------------------------------------------------

/// A three-provider variant of the fixture YAML (p-a/p-b/p-c on
/// separate upstreams; kinds configurable per provider).
fn three_provider_yaml(
    port_a: u16,
    port_b: u16,
    port_c: u16,
    kind_a: &str,
    kind_b: &str,
    models_yaml: &str,
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
         \x20     port: {port_a}\n\
         - name: up-b\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port_b}\n\
         - name: up-c\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port_c}\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: p-a\n\
         \x20   kind: {kind_a}\n\
         \x20   upstream: up-a\n\
         \x20 - name: p-b\n\
         \x20   kind: {kind_b}\n\
         \x20   upstream: up-b\n\
         \x20 - name: p-c\n\
         \x20   kind: openai\n\
         \x20   upstream: up-c\n\
         \x20 models:\n{models_yaml}"
    )
}

/// A THREE-deep chain: primary 429s, first alternate 429s, second
/// alternate serves. The client sees success; every candidate was
/// tried in order.
#[tokio::test(flavor = "multi_thread")]
async fn three_deep_chain_walks_every_candidate_in_order() {
    let (port_a, caps_a) = mock_provider(429, "a");
    let (port_b, caps_b) = mock_provider(429, "b");
    let (port_c, caps_c) = mock_provider(200, "third time lucky");
    let models = "   chat:\n     provider: p-a\n     provider_model: m1\n     failover:\n     - provider: p-b\n       provider_model: m2\n     - provider: p-c\n       provider_model: m3\n";
    let dp = dataplane_from(&three_provider_yaml(
        port_a, port_b, port_c, "openai", "openai", models,
    ));
    let port = spawn_gateway(dp).await;
    let (status, body) = ask(port, "chat").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["choices"][0]["message"]["content"], "third time lucky");
    assert_eq!(caps_a.lock().unwrap().len(), 1);
    assert_eq!(caps_b.lock().unwrap().len(), 1);
    assert_eq!(caps_c.lock().unwrap().len(), 1);
    // The serving candidate sent ITS model id.
    assert_eq!(caps_c.lock().unwrap()[0].model_in_body, "m3");
}

/// A translation rejection fails over: the Anthropic adapter rejects a
/// tool message with no tool_call_id at BUILD time (before any HTTP),
/// and the OpenAI candidate accepts the same conversation.
#[tokio::test(flavor = "multi_thread")]
async fn translation_rejection_fails_over_to_the_next_dialect() {
    // The anthropic upstream is LIVE: zero captured requests proves
    // the rejection happened client-side, not at the provider.
    let (port_ant, caps_ant) = mock_provider(200, "anthropic (unreached)");
    let (port_oai, caps_oai) = mock_provider(200, "openai accepted it");
    let models = "   chat:\n     provider: p-a\n     provider_model: m1\n     failover:\n     - provider: p-b\n       provider_model: m2\n";
    // p-a is the ANTHROPIC-kind provider; p-b the openai one.
    let yaml = three_provider_yaml(port_ant, port_oai, port_ant, "anthropic", "openai", models);
    let dp = dataplane_from(&yaml);
    let port = spawn_gateway(Arc::clone(&dp)).await;
    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(port, "/v1/chat/completions"))
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(
                    json!({
                        "model": "chat",
                        "messages": [
                            {"role": "user", "content": "run the tool"},
                            {"role": "assistant", "content": null, "tool_calls": [{
                                "id": "c1", "type": "function",
                                "function": {"name": "f", "arguments": "{}"}
                            }]},
                            // A tool answer with NO tool_call_id:
                            // anthropic's adapter rejects the build,
                            // openai's accepts it.
                            {"role": "tool", "content": "done"}
                        ]
                    })
                    .to_string(),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, bytes) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        body["choices"][0]["message"]["content"],
        "openai accepted it"
    );
    assert!(
        caps_ant.lock().unwrap().is_empty(),
        "the rejecting dialect was never contacted over HTTP"
    );
    assert_eq!(caps_oai.lock().unwrap().len(), 1);
    // The rejection is attributed to the rejecting provider.
    let metrics = dp.observability().render();
    assert!(has_all(
        &metrics,
        &[
            "dwara_ai_requests_total",
            "provider=\"p-a\"",
            "outcome=\"translation_error\""
        ]
    ));
}

/// Canary weight RAMPING follows the generation: 9:1 then a RE-BALANCED
/// 5:5 republish shifts the split without a restart, and per-id
/// determinism holds within each generation.
#[tokio::test(flavor = "multi_thread")]
async fn canary_ramp_rebalance_applies_on_republish() {
    let (port_a, _) = mock_provider(200, "stable");
    let (port_b, _) = mock_provider(200, "canary");
    let split_yaml = |wa: u32, wb: u32| {
        let models = format!(
            "   chat:\n     provider: p-a\n     provider_model: placeholder\n     canary:\n     - version: stable\n       weight: {wa}\n       provider: p-a\n       provider_model: m-stable\n     - version: canary\n       weight: {wb}\n       provider: p-b\n       provider_model: m-canary\n"
        );
        routing_yaml(port_a, port_b, &models)
    };
    let state = support::state_from(&split_yaml(9, 1));
    let dp = Arc::new(dwara_core::dataplane::proxy::DataPlane::new(Arc::clone(
        &state,
    )));
    let port = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();

    let side_of = |bytes: Bytes| -> String {
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        body["choices"][0]["message"]["content"]
            .as_str()
            .unwrap()
            .to_string()
    };

    // Generation 1: 9:1 over 100 fixed ids.
    let ids: Vec<String> = (0..100).map(|i| format!("rid-ramp-{i}")).collect();
    let mut stable1 = 0;
    for rid in &ids {
        let resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(uri(port, "/v1/chat/completions"))
                    .header("content-type", "application/json")
                    .header("x-request-id", rid.as_str())
                    .body(Full::new(Bytes::from(
                        json!({"model": "chat", "messages": [{"role": "user", "content": "hi"}]})
                            .to_string(),
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (_, bytes) = body_of(resp).await;
        if side_of(bytes) == "stable" {
            stable1 += 1;
        }
    }
    assert!(
        (70..=100).contains(&stable1),
        "9:1 split degenerated: stable={stable1}/100"
    );

    // Generation 2: RE-BALANCED to 5:5 (total stays 10 — the DW-040
    // ramp rule: change weights by re-balancing, not growing).
    let gateway = dwara_core::config::parse_gateway(&split_yaml(5, 5)).expect("ramp config parses");
    state.compile_and_publish(&gateway).expect("ramp publishes");
    dp.refresh();

    let mut stable2 = 0;
    for rid in &ids {
        let resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(uri(port, "/v1/chat/completions"))
                    .header("content-type", "application/json")
                    .header("x-request-id", rid.as_str())
                    .body(Full::new(Bytes::from(
                        json!({"model": "chat", "messages": [{"role": "user", "content": "hi"}]})
                            .to_string(),
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (_, bytes) = body_of(resp).await;
        if side_of(bytes) == "stable" {
            stable2 += 1;
        }
    }
    assert!(
        (30..=70).contains(&stable2),
        "5:5 rebalance did not apply: stable={stable2}/100 (was {stable1} at 9:1)"
    );
}

/// Canary versions may live on DIFFERENT provider kinds: one openai and
/// one anthropic version, both serving their own dialect.
#[tokio::test(flavor = "multi_thread")]
async fn canary_versions_span_provider_kinds() {
    let (port_oai, caps_oai) = mock_provider(200, "openai side");
    // p-c's upstream is irrelevant to this test; park it on a dead port.
    let port_ant = dead_port();
    // An anthropic-dialect success body so the anthropic adapter can
    // translate it: reuse mock_provider only for capture; the response
    // shape below matters. Simpler: both versions on the openai KIND
    // but through different upstreams is already covered; for a true
    // cross-dialect split the anthropic mock must answer in its
    // dialect. Spawn a dedicated anthropic-dialect mock.
    let caps_ant2: Arc<Mutex<Vec<Capture>>> = Arc::new(Mutex::new(Vec::new()));
    let caps = Arc::clone(&caps_ant2);
    let port_ant2 = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(spawn_backend_async(
            move |req: Request<Incoming>| {
                let caps = Arc::clone(&caps);
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
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from(
                                json!({
                                    "id": "msg",
                                    "content": [{"type": "text", "text": "anthropic side"}],
                                    "stop_reason": "end_turn",
                                    "usage": {"input_tokens": 3, "output_tokens": 2}
                                })
                                .to_string(),
                            )))
                            .unwrap(),
                    )
                }
            },
        ))
    });
    let models = "   chat:\n     provider: p-a\n     provider_model: placeholder\n     canary:\n     - version: v-openai\n       weight: 5\n       provider: p-a\n       provider_model: m-openai\n     - version: v-anthropic\n       weight: 5\n       provider: p-b\n       provider_model: m-anthropic\n";
    // p-b is anthropic-kind in three_provider_yaml via kind_b.
    let yaml = three_provider_yaml(port_oai, port_ant2, port_ant, "openai", "anthropic", models);
    let dp = dataplane_from(&yaml);
    let port = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();

    let mut saw_openai = false;
    let mut saw_anthropic = false;
    for i in 0..40 {
        let resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(uri(port, "/v1/chat/completions"))
                    .header("content-type", "application/json")
                    .header("x-request-id", format!("rid-xdialect-{i}"))
                    .body(Full::new(Bytes::from(
                        json!({"model": "chat", "messages": [{"role": "user", "content": "hi"}]})
                            .to_string(),
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, bytes) = body_of(resp).await;
        assert_eq!(status, StatusCode::OK);
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        match body["choices"][0]["message"]["content"].as_str().unwrap() {
            "openai side" => saw_openai = true,
            "anthropic side" => saw_anthropic = true,
            other => panic!("unknown side {other}"),
        }
    }
    assert!(
        saw_openai && saw_anthropic,
        "the split never crossed dialects"
    );
    // The anthropic mock received its dialect's request with ITS model.
    let ant = caps_ant2.lock().unwrap();
    assert!(!ant.is_empty());
    assert!(ant.iter().all(|c| c.model_in_body == "m-anthropic"));
    assert!(caps_oai
        .lock()
        .unwrap()
        .iter()
        .all(|c| c.model_in_body == "m-openai"));
}

/// Exact accounting: ONE failed-over client request produces exactly
/// one provider_error and one success across the whole metrics family.
#[tokio::test(flavor = "multi_thread")]
async fn failed_over_request_counts_exactly_one_error_and_one_success() {
    let (primary_port, _) = mock_provider(429, "primary");
    let (alt_port, _) = mock_provider(200, "alternate");
    let models = "   chat:\n     provider: p-a\n     provider_model: m1\n     failover:\n     - provider: p-b\n       provider_model: m2\n";
    let dp = dataplane_from(&routing_yaml(primary_port, alt_port, models));
    let port = spawn_gateway(Arc::clone(&dp)).await;
    let (status, _) = ask(port, "chat").await;
    assert_eq!(status, StatusCode::OK);

    let metrics = dp.observability().render();
    let mut provider_error = 0i64;
    let mut success = 0i64;
    let mut total = 0i64;
    for line in metrics
        .lines()
        .filter(|l| l.starts_with("dwara_ai_requests_total{"))
    {
        let value: i64 = line.rsplit(' ').next().unwrap_or("0").parse().unwrap_or(0);
        total += value;
        if line.contains("outcome=\"provider_error\"") {
            provider_error += value;
        }
        if line.contains("outcome=\"success\"") {
            success += value;
        }
    }
    assert_eq!(provider_error, 1, "exactly one provider_error attempt");
    assert_eq!(success, 1, "exactly one success");
    assert_eq!(total, 2, "no double counting anywhere in the family");
}

/// Review-loop fix pinned end to end: a provider whose 200 response
/// exceeds the body cap is treated like a malformed one — the chain
/// ADVANCES and the client sees the alternate's answer, not the 502.
/// (33 MiB body: one JSON string just over the 32 MiB cap; loopback
/// transfer of a pre-built buffer is fast, so the test stays light.)
#[tokio::test(flavor = "multi_thread")]
async fn over_cap_success_body_fails_over_to_the_alternate() {
    // A mock returning a valid OpenAI-shaped body whose content string
    // is 33 MiB — over MAX_AI_PROVIDER_RESPONSE_BYTES (32 MiB).
    let giant: String = "x".repeat(33 * 1024 * 1024);
    let giant_body = json!({
        "id": "r",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": giant},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    })
    .to_string();
    let giant_bytes = Bytes::from(giant_body);
    let (giant_port, giant_caps) = {
        let captures: Arc<Mutex<Vec<Capture>>> = Arc::new(Mutex::new(Vec::new()));
        let caps = Arc::clone(&captures);
        let port = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(spawn_backend_async(
                move |req: Request<Incoming>| {
                    let caps = Arc::clone(&caps);
                    let body = giant_bytes.clone();
                    async move {
                        let (_parts, req_body) = req.into_parts();
                        let bytes = req_body.collect().await.unwrap().to_bytes();
                        let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                        caps.lock().unwrap().push(Capture {
                            model_in_body: parsed
                                .get("model")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                        });
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "application/json")
                                .body(Full::new(body))
                                .unwrap(),
                        )
                    }
                },
            ))
        });
        (port, captures)
    };
    let (alt_port, alt_caps) = mock_provider(200, "sane alternate");
    let models = "   chat:\n     provider: p-a\n     provider_model: m1\n     failover:\n     - provider: p-b\n       provider_model: m2\n";
    let dp = dataplane_from(&routing_yaml(giant_port, alt_port, models));
    let port = spawn_gateway(Arc::clone(&dp)).await;

    let (status, body) = ask(port, "chat").await;
    assert_eq!(status, StatusCode::OK, "the client must see the alternate");
    assert_eq!(body["choices"][0]["message"]["content"], "sane alternate");
    // Both providers were tried; the over-cap attempt is attributed as
    // a translation-class failure of the runaway provider.
    assert_eq!(giant_caps.lock().unwrap().len(), 1);
    assert_eq!(alt_caps.lock().unwrap().len(), 1);
    let metrics = dp.observability().render();
    assert!(has_all(
        &metrics,
        &[
            "dwara_ai_requests_total",
            "provider=\"p-a\"",
            "outcome=\"translation_error\""
        ]
    ));
    assert!(has_all(
        &metrics,
        &[
            "dwara_ai_requests_total",
            "provider=\"p-b\"",
            "outcome=\"success\""
        ]
    ));
}
