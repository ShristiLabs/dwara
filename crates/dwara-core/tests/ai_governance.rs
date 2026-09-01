//! AI model governance tests (DW-084): per-team model allowlists,
//! shadow-audit recording, and validation — through the real gateway
//! with a mock provider and the embedded analytics store.

mod support;

use bytes::Bytes;
use dwara_core::analytics::{query, AiGovernanceEvent, EmbeddedAnalytics};
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

/// A concrete error type for the channel body (Box<dyn Error> does
/// not implement Error itself — the trait is not Sized).
#[derive(Debug)]
struct ChanErr(String);

impl std::fmt::Display for ChanErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ChanErr {}

struct ChanBody {
    rx: tokio::sync::mpsc::Receiver<Result<Bytes, ChanErr>>,
}

impl hyper::body::Body for ChanBody {
    type Data = Bytes;
    type Error = ChanErr;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, ChanErr>>> {
        match self.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(Ok(b))) => {
                std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(b))))
            }
            std::task::Poll::Ready(Some(Err(e))) => std::task::Poll::Ready(Some(Err(e))),
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// An anthropic-dialect mock: non-streaming answers a JSON completion
/// with usage input=N out=M. Records the request count.
fn anthropic_mock() -> (u16, Arc<Mutex<u64>>) {
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
                    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, ChanErr>>(2);
                    let payload = json!({
                        "id": "msg",
                        "content": [{"type": "text", "text": "answer"}],
                        "stop_reason": "end_turn",
                        "usage": {"input_tokens": 10, "output_tokens": 5}
                    });
                    let _ = tx.send(Ok(Bytes::from(payload.to_string()))).await;
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(ChanBody { rx })
                            .unwrap(),
                    )
                }
            },
        ))
    });
    (port, seen)
}

/// Gateway YAML: an ai route, an anthropic provider, two model
/// aliases (cheap + costly), a consumer with a credential, an
/// optional governance block, and an optional second consumer.
fn gov_yaml(port: u16, governance_yaml: &str, second_consumer_attach: &str) -> String {
    let second = if second_consumer_attach.is_empty() {
        String::new()
    } else {
        format!(
            "- name: beta\n  credentials:\n  - type: api_key\n    key: beta-key\n  policies:\n  {second_consumer_attach}"
        )
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
         \x20   key: acme-key\n\
         \x20 policies:\n\
         \x20 - low-cost-only\n\
         {second}\n\
         policies:\n\
         - name: low-cost-only\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: p\n\
         \x20   kind: anthropic\n\
         \x20   upstream: up\n\
         \x20 models:\n\
         \x20   cheap:\n\
         \x20     provider: p\n\
         \x20     provider_model: claude-cheap\n\
         \x20   costly:\n\
         \x20     provider: p\n\
         \x20     provider_model: claude-costly\n{governance_yaml}"
    )
}

/// Like [`gov_yaml`] but declares an EXTRA policy (so the governance
/// block can reference it — validation rejects an allowlist for a
/// policy that does not exist) and has the beta consumer attach both
/// `low-cost-only` and the extra policy.
fn gov_yaml_with_extra_policy(port: u16, governance_yaml: &str, extra_policy: &str) -> String {
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
         \x20   key: acme-key\n\
         \x20 policies:\n\
         \x20 - low-cost-only\n\
         - name: beta\n\
         \x20 credentials:\n\
         \x20 - type: api_key\n\
         \x20   key: beta-key\n\
         \x20 policies:\n\
         \x20 - low-cost-only\n\
         \x20 - {extra_policy}\n\
         policies:\n\
         - name: low-cost-only\n\
         - name: {extra_policy}\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: p\n\
         \x20   kind: anthropic\n\
         \x20   upstream: up\n\
         \x20 models:\n\
         \x20   cheap:\n\
         \x20     provider: p\n\
         \x20     provider_model: claude-cheap\n\
         \x20   costly:\n\
         \x20     provider: p\n\
         \x20     provider_model: claude-costly\n{governance_yaml}"
    )
}

/// Send a chat request with the given model alias and API key.
async fn ask(port: u16, key: &str, model: &str) -> (StatusCode, Value) {
    let body = json!({
        "model": model,
        "messages": [{"role": "user", "content": "hi"}]
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri(port, "/v1/chat/completions"))
        .header("content-type", "application/json")
        .header("x-api-key", key)
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();
    let resp = h1_client().request(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// Open an analytics store in a temp dir, attach it to the dataplane,
/// and spawn the background writers (raw + spend + governance).
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

/// Wait for governance events to flush (bounded poll on the store's
/// ai_governance_events row count).
fn wait_for_governance(dp: &Arc<DataPlane>, expected: i64) {
    let store = dp.analytics().expect("analytics attached");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let count: i64 = store
            .query(|c| {
                c.query_row("SELECT COUNT(*) FROM ai_governance_events", [], |r| {
                    r.get(0)
                })
            })
            .unwrap_or(0);
        if count >= expected {
            return;
        }
        if std::time::Instant::now() > deadline {
            panic!("timed out waiting for {expected} governance events, got {count}");
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

// ---------------------------------------------------------------------------
// 1. A team allowed only a low-cost model is blocked from a costlier one
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn low_cost_team_blocked_from_costly_model() {
    let (port, seen) = anthropic_mock();
    let gov = "  governance:\n    team_allowlists:\n      low-cost-only:\n      - cheap\n    audit: true\n";
    let dp = dataplane_from(&gov_yaml(port, gov, ""));
    let _analytics = attach_analytics(&dp);
    let gw = spawn_gateway(dp.clone()).await;

    // Allowed: cheap model.
    let (s1, _v1) = ask(gw, "acme-key", "cheap").await;
    assert_eq!(s1, StatusCode::OK);

    // Blocked: costly model.
    let (s2, v2) = ask(gw, "acme-key", "costly").await;
    assert_eq!(s2, StatusCode::FORBIDDEN);
    assert_eq!(v2["error"]["code"], "model_denied_by_policy");

    // The provider mock saw only the allowed call (the denied one
    // never reached a provider).
    let provider_count = *seen.lock().unwrap();
    assert_eq!(
        provider_count, 1,
        "the denied request never reached the provider"
    );
}

// ---------------------------------------------------------------------------
// 2. The blocked attempt appears in the governance audit
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn blocked_attempt_appears_in_governance_audit() {
    let (port, _seen) = anthropic_mock();
    let gov = "  governance:\n    team_allowlists:\n      low-cost-only:\n      - cheap\n    audit: true\n";
    let dp = dataplane_from(&gov_yaml(port, gov, ""));
    let _analytics = attach_analytics(&dp);
    let gw = spawn_gateway(dp.clone()).await;

    // Allowed + denied = 2 governance events.
    let (s1, _) = ask(gw, "acme-key", "cheap").await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, _) = ask(gw, "acme-key", "costly").await;
    assert_eq!(s2, StatusCode::FORBIDDEN);
    wait_for_governance(&dp, 2);

    let store = dp.analytics().unwrap();
    let now = now_ms();
    let rows = store
        .query(|c| {
            query::governance_audit(
                c,
                &query::GovernanceAuditQuery {
                    from_ms: now - 60_000,
                    to_ms: now + 60_000,
                    limit: None,
                },
            )
        })
        .unwrap();
    assert_eq!(rows.len(), 2, "both allow and deny events recorded");
    // Newest first: the deny is the second request.
    let deny = rows
        .iter()
        .find(|r| r.verdict == "deny")
        .expect("a deny row");
    assert_eq!(deny.consumer, "acme");
    assert_eq!(deny.team, "low-cost-only");
    assert_eq!(deny.model, "costly");
    assert_eq!(deny.reason, "model_not_in_team_allowlist");
    let allow = rows
        .iter()
        .find(|r| r.verdict == "allow")
        .expect("an allow row");
    assert_eq!(allow.consumer, "acme");
    assert_eq!(allow.model, "cheap");
}

// ---------------------------------------------------------------------------
// 3. An allowed call with audit=true is recorded in governance events
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn allowed_call_recorded_when_audit_on() {
    let (port, _seen) = anthropic_mock();
    let gov = "  governance:\n    team_allowlists:\n      low-cost-only:\n      - cheap\n      - costly\n    audit: true\n";
    let dp = dataplane_from(&gov_yaml(port, gov, ""));
    let _analytics = attach_analytics(&dp);
    let gw = spawn_gateway(dp.clone()).await;

    // Both models allowed (both in the allowlist).
    let (s1, _) = ask(gw, "acme-key", "cheap").await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, _) = ask(gw, "acme-key", "costly").await;
    assert_eq!(s2, StatusCode::OK);
    wait_for_governance(&dp, 2);

    let store = dp.analytics().unwrap();
    let now = now_ms();
    let rows = store
        .query(|c| {
            query::governance_audit(
                c,
                &query::GovernanceAuditQuery {
                    from_ms: now - 60_000,
                    to_ms: now + 60_000,
                    limit: None,
                },
            )
        })
        .unwrap();
    assert_eq!(rows.len(), 2);
    // Both are allow events.
    assert!(rows.iter().all(|r| r.verdict == "allow"));
    let models: Vec<&str> = rows.iter().map(|r| r.model.as_str()).collect();
    assert!(models.contains(&"cheap"));
    assert!(models.contains(&"costly"));
}

// ---------------------------------------------------------------------------
// 4. A consumer with no allowlist policy is allowed (fail-open)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn no_allowlist_policy_is_allowed_fail_open() {
    let (port, _seen) = anthropic_mock();
    // Governance with an allowlist for a DIFFERENT policy than the
    // consumer attaches — the consumer has no binding allowlist.
    // The "other-team" policy must exist (validation rejects a
    // typo'd policy name), so we declare it alongside low-cost-only.
    let gov =
        "  governance:\n    team_allowlists:\n      other-team:\n      - cheap\n    audit: true\n";
    let yaml = gov_yaml_with_extra_policy(port, gov, "other-team");
    let dp = dataplane_from(&yaml);
    let _analytics = attach_analytics(&dp);
    let gw = spawn_gateway(dp.clone()).await;

    // The consumer attaches "low-cost-only" which has NO allowlist
    // entry in the governance block — fail-open, both models allowed.
    let (s1, _) = ask(gw, "acme-key", "cheap").await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, _) = ask(gw, "acme-key", "costly").await;
    assert_eq!(s2, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// 5. Multiple policies with allowlists: model must be in ALL (deny-wins)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn multiple_allowlists_intersect_deny_wins() {
    let (port, _seen) = anthropic_mock();
    // Two policies with allowlists: low-cost-only allows [cheap, costly],
    // strict-team allows [cheap] only. The consumer attaches BOTH.
    // The model must be in BOTH (intersection) — costly is denied.
    let gov = "  governance:\n    team_allowlists:\n      low-cost-only:\n      - cheap\n      - costly\n      strict-team:\n      - cheap\n    audit: true\n";
    let yaml = gov_yaml_with_extra_policy(port, gov, "strict-team");
    let dp = dataplane_from(&yaml);
    let _analytics = attach_analytics(&dp);
    let gw = spawn_gateway(dp.clone()).await;

    // The beta consumer attaches both low-cost-only (via the base
    // yaml) and strict-team (via the extra policy attachment).
    // cheap is in both allowlists -> allowed.
    let (s1, _) = ask(gw, "acme-key", "cheap").await;
    assert_eq!(s1, StatusCode::OK);
    // costly is in low-cost-only but NOT in strict-team -> denied.
    // The acme consumer only attaches low-cost-only, so costly IS
    // allowed for acme. Use beta (which attaches both) to test the
    // intersection.
    let (s2, v2) = ask(gw, "beta-key", "costly").await;
    assert_eq!(s2, StatusCode::FORBIDDEN);
    assert_eq!(v2["error"]["code"], "model_denied_by_policy");
    // cheap is in both -> allowed for beta too.
    let (s3, _) = ask(gw, "beta-key", "cheap").await;
    assert_eq!(s3, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// 6. Validation rejects an allowlist referencing a non-existent model
// ---------------------------------------------------------------------------

#[test]
fn validation_rejects_nonexistent_model_alias_in_allowlist() {
    use dwara_core::config::parse_gateway;
    use dwara_core::snapshot::validate;

    let yaml = "allow_empty_routes: true\n\
         policies:\n\
         - name: low-cost-only\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: p\n\
         \x20   kind: openai\n\
         \x20   upstream: u\n\
         \x20 models:\n\
         \x20   cheap:\n\
         \x20     provider: p\n\
         \x20     provider_model: m\n\
         \x20 governance:\n\
         \x20   team_allowlists:\n\
         \x20     low-cost-only:\n\
         \x20     - cheap\n\
         \x20     - nonexistent-alias\n\
         upstreams:\n\
         - name: u\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 9000\n";
    let gateway = parse_gateway(yaml).expect("fixture parses");
    let issues = validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.message.contains("unknown model alias")
                && i.message.contains("nonexistent-alias")),
        "validation should reject the non-existent alias: {:?}",
        issues
    );

    // A valid allowlist (only existing aliases) passes.
    let yaml_ok = "allow_empty_routes: true\n\
         policies:\n\
         - name: low-cost-only\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: p\n\
         \x20   kind: openai\n\
         \x20   upstream: u\n\
         \x20 models:\n\
         \x20   cheap:\n\
         \x20     provider: p\n\
         \x20     provider_model: m\n\
         \x20 governance:\n\
         \x20   team_allowlists:\n\
         \x20     low-cost-only:\n\
         \x20     - cheap\n\
         upstreams:\n\
         - name: u\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 9000\n";
    let gateway_ok = parse_gateway(yaml_ok).expect("fixture parses");
    let issues_ok = validate(&gateway_ok);
    assert!(
        !issues_ok
            .iter()
            .any(|i| i.field.contains("team_allowlists")),
        "a valid allowlist should not produce governance issues: {:?}",
        issues_ok
    );
}

// ---------------------------------------------------------------------------
// 7. Direct governance event insert + query (no gateway, deterministic)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn governance_event_direct_insert_and_query() {
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

    store.offer_ai_governance_event(AiGovernanceEvent {
        ts_ms: 1000,
        consumer: "acme".to_string(),
        team: "low-cost-only".to_string(),
        model: "costly".to_string(),
        verdict: "deny".to_string(),
        reason: "model_not_in_team_allowlist".to_string(),
    });
    store.offer_ai_governance_event(AiGovernanceEvent {
        ts_ms: 2000,
        consumer: "acme".to_string(),
        team: "".to_string(),
        model: "cheap".to_string(),
        verdict: "allow".to_string(),
        reason: "".to_string(),
    });

    // Wait for the writer to flush both records.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let count: i64 = store
            .query(|c| {
                c.query_row("SELECT COUNT(*) FROM ai_governance_events", [], |r| {
                    r.get(0)
                })
            })
            .unwrap_or(0);
        if count >= 2 {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("timed out waiting for 2 governance events, got {count}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let rows = store
        .query(|c| {
            query::governance_audit(
                c,
                &query::GovernanceAuditQuery {
                    from_ms: 0,
                    to_ms: 10_000,
                    limit: None,
                },
            )
        })
        .unwrap();
    assert_eq!(rows.len(), 2);
    // Newest first: ts_ms=2000 (allow) first.
    assert_eq!(rows[0].ts_ms, 2000);
    assert_eq!(rows[0].verdict, "allow");
    assert_eq!(rows[0].model, "cheap");
    assert_eq!(rows[1].ts_ms, 1000);
    assert_eq!(rows[1].verdict, "deny");
    assert_eq!(rows[1].model, "costly");
    assert_eq!(rows[1].reason, "model_not_in_team_allowlist");

    // Clean shutdown: drain the channel.
    let _ = shutdown_tx.send(());
}

// ---------------------------------------------------------------------------
// 8. Governance engine unit tests (no gateway)
// ---------------------------------------------------------------------------

#[test]
fn governance_engine_allow_when_no_allowlists() {
    use dwara_core::ai::governance::{GovernanceEngine, GovernanceVerdict};
    let engine = GovernanceEngine::default();
    assert!(engine.is_empty());
    let verdict = engine.check(
        Some("acme"),
        &["p".to_string()],
        &[],
        &[],
        &[],
        &[],
        "any-model",
    );
    assert_eq!(verdict, GovernanceVerdict::Allow);
}

#[test]
fn governance_engine_deny_when_model_not_in_allowlist() {
    use dwara_core::ai::governance::{GovernanceEngine, GovernanceVerdict};
    use dwara_core::config::ai::{AiConfig, AiGovernance};
    let mut allowlists = std::collections::BTreeMap::new();
    allowlists.insert("low-cost".to_string(), vec!["cheap".to_string()]);
    let cfg = AiConfig {
        providers: vec![],
        models: std::collections::BTreeMap::new(),
        pricing: std::collections::BTreeMap::new(),
        governance: Some(AiGovernance {
            team_allowlists: allowlists,
            audit: false,
        }),
        logging: None,
        guardrails: None,
    };
    let engine = GovernanceEngine::compile(Some(&cfg));
    assert!(!engine.is_empty());
    // cheap is allowed.
    let v1 = engine.check(
        Some("acme"),
        &["low-cost".to_string()],
        &[],
        &[],
        &[],
        &[],
        "cheap",
    );
    assert_eq!(v1, GovernanceVerdict::Allow);
    // costly is denied.
    let v2 = engine.check(
        Some("acme"),
        &["low-cost".to_string()],
        &[],
        &[],
        &[],
        &[],
        "costly",
    );
    assert_eq!(
        v2,
        GovernanceVerdict::Deny {
            policy: "low-cost".to_string(),
            reason: "model_not_in_team_allowlist".to_string(),
        }
    );
}

#[test]
fn governance_engine_deny_wins_across_multiple_policies() {
    use dwara_core::ai::governance::{GovernanceEngine, GovernanceVerdict};
    use dwara_core::config::ai::{AiConfig, AiGovernance};
    let mut allowlists = std::collections::BTreeMap::new();
    allowlists.insert(
        "broad".to_string(),
        vec!["cheap".to_string(), "costly".to_string()],
    );
    allowlists.insert("strict".to_string(), vec!["cheap".to_string()]);
    let cfg = AiConfig {
        providers: vec![],
        models: std::collections::BTreeMap::new(),
        pricing: std::collections::BTreeMap::new(),
        governance: Some(AiGovernance {
            team_allowlists: allowlists,
            audit: false,
        }),
        logging: None,
        guardrails: None,
    };
    let engine = GovernanceEngine::compile(Some(&cfg));
    // Consumer attaches both broad + strict. cheap is in both -> allow.
    let v1 = engine.check(
        Some("acme"),
        &["broad".to_string(), "strict".to_string()],
        &[],
        &[],
        &[],
        &[],
        "cheap",
    );
    assert_eq!(v1, GovernanceVerdict::Allow);
    // costly is in broad but NOT in strict -> deny (deny-wins).
    let v2 = engine.check(
        Some("acme"),
        &["broad".to_string(), "strict".to_string()],
        &[],
        &[],
        &[],
        &[],
        "costly",
    );
    assert!(matches!(v2, GovernanceVerdict::Deny { .. }));
}
