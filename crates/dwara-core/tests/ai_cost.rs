//! AI cost attribution & metering tests (DW-079): pricing table
//! computation, spend recording into the analytics store, spend query
//! aggregation, CSV/JSON export reconciliation, pricing-table reload,
//! and per-team spend tracking — through the real gateway with mock
//! providers and the embedded analytics store.

mod support;

use bytes::Bytes;
use dwara_core::ai::cost::PricingTable;
use dwara_core::ai::types::Usage;
use dwara_core::analytics::{query, rollup, AiSpendRecord, EmbeddedAnalytics};
use dwara_core::config::ai::{AiConfig, AiPricing};
use dwara_core::config::ANALYTICS_DEFAULT_RETENTION_MS;
use dwara_core::proxy::DataPlane;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::pin::Pin;
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
        mut self: Pin<&mut Self>,
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

/// What the provider mock saw.
#[derive(Debug, Clone, Default)]
struct Seen {
    count: u64,
}

/// An anthropic-dialect mock: non-streaming answers a JSON completion
/// with usage input=N out=M.
fn anthropic_mock(input_tokens: u64, output_tokens: u64) -> (u16, Arc<Mutex<Seen>>) {
    let seen: Arc<Mutex<Seen>> = Arc::new(Mutex::new(Seen::default()));
    let s = Arc::clone(&seen);
    let port = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(spawn_backend_async(
            move |req: Request<Incoming>| {
                let s = Arc::clone(&s);
                let input = input_tokens;
                let output = output_tokens;
                async move {
                    {
                        let mut g = s.lock().unwrap();
                        g.count += 1;
                    }
                    let (_parts, body) = req.into_parts();
                    let _ = body.collect().await;
                    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, ChanErr>>(2);
                    let payload = json!({
                        "id": "msg",
                        "content": [{"type": "text", "text": "answer"}],
                        "stop_reason": "end_turn",
                        "usage": {"input_tokens": input, "output_tokens": output}
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

/// Gateway YAML: an ai route, an anthropic provider, a consumer with a
/// credential, and an optional pricing table + budget policy.
fn cost_yaml(
    port: u16,
    pricing_yaml: &str,
    budget_yaml: &str,
    attach: &str,
    second_consumer: bool,
) -> String {
    let consumer_attach = if attach == "consumer" {
        "     - ai-budget\n"
    } else {
        ""
    };
    let second = if second_consumer {
        "- name: beta\n  credentials:\n  - type: api_key\n    key: beta-key\n  policies:\n  - ai-budget\n"
    } else {
        ""
    };
    let route_attach = if attach == "route" {
        "     - ai-budget\n"
    } else {
        ""
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
         \x20 policies:\n{route_attach}\
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
         \x20 policies:\n{consumer_attach}\
         {second}\
         policies:\n\
         - name: ai-budget\n{budget_yaml}\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: p\n\
         \x20   kind: anthropic\n\
         \x20   upstream: up\n\
         \x20 models:\n\
         \x20   chat:\n\
         \x20     provider: p\n\
         \x20     provider_model: claude-x\n{pricing_yaml}"
    )
}

async fn ask(port: u16, key: &str) -> (StatusCode, Bytes) {
    let body = json!({
        "model": "chat",
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
    (status, bytes)
}

/// Open an analytics store in a temp dir, attach it to the dataplane,
/// and spawn the background writers (raw + spend). Returns the temp
/// dir (kept alive for the test's duration) and the shutdown sender.
struct AnalyticsHandle {
    _dir: tempfile::TempDir,
    _shutdown_tx: watch::Sender<()>,
}

/// Attach analytics + spawn workers. The store is set on the dataplane
/// and the spend writer is spawned so `offer_ai_spend` records are
/// flushed to the `ai_spend` table.
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

/// Wait for spend records to flush (bounded poll on the store's
/// ai_spend row count).
fn wait_for_spend(dp: &Arc<DataPlane>, expected: i64) {
    let store = dp.analytics().expect("analytics attached");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let count: i64 = store
            .query(|c| c.query_row("SELECT COUNT(*) FROM ai_spend", [], |r| r.get(0)))
            .unwrap_or(0);
        if count >= expected {
            return;
        }
        if std::time::Instant::now() > deadline {
            panic!("timed out waiting for {expected} spend records, got {count}");
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
// 1. Pricing table computes correct cost
// ---------------------------------------------------------------------------

#[test]
fn pricing_table_computes_correct_cost() {
    let mut pricing = BTreeMap::new();
    pricing.insert(
        "claude-x".to_string(),
        AiPricing {
            input_per_1k_micros: 3_000,   // $3.00 per 1M tokens
            output_per_1k_micros: 15_000, // $15.00 per 1M tokens
        },
    );
    let cfg = AiConfig {
        providers: vec![],
        models: BTreeMap::new(),
        pricing,
        governance: None,
        logging: None,
    };
    let table = PricingTable::compile(Some(&cfg));

    // 1000 input + 500 output:
    // input_cost  = 1000 * 3000 / 1000 = 3000 micros
    // output_cost = 500  * 15000 / 1000 = 7500 micros
    // total = 10500 micros
    let usage = Usage {
        prompt_tokens: Some(1000),
        completion_tokens: Some(500),
        total_tokens: Some(1500),
    };
    assert_eq!(table.cost_micros("claude-x", usage), 10_500);
}

// ---------------------------------------------------------------------------
// 2. Unknown model -> cost 0
// ---------------------------------------------------------------------------

#[test]
fn unknown_model_costs_zero() {
    let table = PricingTable::default();
    let usage = Usage {
        prompt_tokens: Some(1000),
        completion_tokens: Some(500),
        total_tokens: Some(1500),
    };
    assert_eq!(table.cost_micros("nonexistent", usage), 0);
}

// ---------------------------------------------------------------------------
// 3. Spend recorded per consumer/model; query returns correct aggregation
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn spend_recorded_per_consumer_and_queryable() {
    let (port, _seen) = anthropic_mock(100, 200);
    let pricing = "  pricing:\n    claude-x:\n      input_per_1k_micros: 3000\n      output_per_1k_micros: 15000\n";
    let dp = dataplane_from(&cost_yaml(port, pricing, "", "consumer", false));
    let _analytics = attach_analytics(&dp);
    let gw = spawn_gateway(dp.clone()).await;

    // Two requests from acme: each 100 in + 200 out.
    let (s1, _) = ask(gw, "acme-key").await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, _) = ask(gw, "acme-key").await;
    assert_eq!(s2, StatusCode::OK);

    // Wait for both spend records to flush.
    wait_for_spend(&dp, 2);

    let store = dp.analytics().unwrap();
    let now = now_ms();
    let from = now - 60_000;

    // Query grouped by consumer.
    let rows = store
        .query(|c| {
            query::spend_summary(
                c,
                &query::SpendQuery {
                    from_ms: from,
                    to_ms: now + 60_000,
                    group_by: vec!["consumer".to_string()],
                    limit: None,
                },
            )
        })
        .unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.key, vec!["acme"]);
    assert_eq!(row.request_count, 2);
    assert_eq!(row.prompt_tokens, 200); // 100 * 2
    assert_eq!(row.completion_tokens, 400); // 200 * 2
    assert_eq!(row.total_tokens, 600); // 300 * 2
                                       // cost per request: 100*3000/1000 + 200*15000/1000 = 300 + 3000 = 3300
                                       // two requests: 6600
    assert_eq!(row.cost_micros, 6600);

    // Query grouped by model.
    let rows = store
        .query(|c| {
            query::spend_summary(
                c,
                &query::SpendQuery {
                    from_ms: from,
                    to_ms: now + 60_000,
                    group_by: vec!["model".to_string()],
                    limit: None,
                },
            )
        })
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].key, vec!["claude-x"]);
    assert_eq!(rows[0].cost_micros, 6600);
}

// ---------------------------------------------------------------------------
// 4. CSV/JSON export includes spend columns; reconciles with query
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn csv_export_includes_spend_columns() {
    use dwara_core::analytics::exports::{self, ExportFormat, WindowKind};
    use std::collections::HashMap;

    let (port, _seen) = anthropic_mock(100, 200);
    let pricing = "  pricing:\n    claude-x:\n      input_per_1k_micros: 3000\n      output_per_1k_micros: 15000\n";
    let dp = dataplane_from(&cost_yaml(port, pricing, "", "consumer", false));
    let analytics = attach_analytics(&dp);
    let gw = spawn_gateway(dp.clone()).await;

    // One request from acme.
    let (s, _) = ask(gw, "acme-key").await;
    assert_eq!(s, StatusCode::OK);
    wait_for_spend(&dp, 1);

    let store = dp.analytics().unwrap();

    // Wait for the raw access record to flush, then manually roll it
    // up (the maintain() inside run_export uses a 60s grace period that
    // skips the current minute; roll_raw_range bypasses it so the
    // per-consumer rows appear in the export immediately).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let count: i64 = store
            .query(|c| c.query_row("SELECT COUNT(*) FROM raw", [], |r| r.get(0)))
            .unwrap_or(0);
        if count >= 1 {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("timed out waiting for raw access record to flush");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let now = now_ms();
    // Roll up everything up to now+120s (well past the current minute).
    // The export reads from 1-hour rollups (gran 2), so we must cascade
    // raw -> 1m -> 5m -> 1h manually (maintain()'s 60s grace skips the
    // current window at every stage).
    store
        .query(|c| {
            rollup::roll_raw_range(c, 0, now + 120_000)?;
            rollup::cascade_range(c, 0, 0, now + 120_000)?;
            rollup::cascade_range(c, 1, 0, now + 120_000)?;
            Ok(())
        })
        .unwrap();

    // Use a daily window containing now.
    let window_start = now - (now % 86_400_000);
    let out_dir = analytics._dir.path().join("out");
    let out_str = out_dir.to_str().unwrap().to_string();

    fn no_quota(_: i64, _: i64) -> HashMap<String, exports::QuotaFigures> {
        HashMap::new()
    }

    let run = exports::run_export(
        &store,
        &out_str,
        WindowKind::Daily,
        window_start,
        &[ExportFormat::Csv, ExportFormat::Json],
        &no_quota,
        now + 60_000,
    );
    assert_eq!(run.status, "ok", "{}", run.error);

    // The CSV file exists and includes the spend columns.
    let csv_files: Vec<_> = std::fs::read_dir(&out_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "csv"))
        .collect();
    assert!(!csv_files.is_empty(), "a CSV file was written");
    let csv = std::fs::read_to_string(csv_files[0].path()).unwrap();
    assert!(csv.contains("prompt_tokens"));
    assert!(csv.contains("completion_tokens"));
    assert!(csv.contains("total_tokens"));
    assert!(csv.contains("cost_micros"));
    // The acme row carries the spend values.
    let acme_line = csv
        .lines()
        .find(|l| l.starts_with("acme,"))
        .expect("acme row in CSV");
    // cost per request: 100*3000/1000 + 200*15000/1000 = 3300
    assert!(acme_line.contains("3300"), "CSV row has cost: {acme_line}");

    // The JSON file includes spend_by_model.
    let json_files: Vec<_> = std::fs::read_dir(&out_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .collect();
    assert!(!json_files.is_empty(), "a JSON file was written");
    let json: Value =
        serde_json::from_str(&std::fs::read_to_string(json_files[0].path()).unwrap()).unwrap();
    let by_model = json["spend_by_model"]
        .as_array()
        .expect("spend_by_model array");
    assert_eq!(by_model.len(), 1);
    assert_eq!(by_model[0]["model"], "claude-x");
    assert_eq!(by_model[0]["cost_micros"], 3300);
    assert_eq!(by_model[0]["request_count"], 1);
}

// ---------------------------------------------------------------------------
// 5. Pricing table change on reload takes effect on next request
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn pricing_change_on_reload_takes_effect() {
    use support::state_from;

    let (port, _seen) = anthropic_mock(1000, 1000);
    // Start with pricing: 1000 input + 1000 output.
    let pricing_v1 = "  pricing:\n    claude-x:\n      input_per_1k_micros: 1000\n      output_per_1k_micros: 1000\n";
    let state = state_from(&cost_yaml(port, pricing_v1, "", "consumer", false));
    let dp = DataPlane::new(state.clone());
    let _analytics = attach_analytics(&dp);
    let gw = spawn_gateway(dp.clone()).await;

    // Request 1: cost = 1000*1000/1000 + 1000*1000/1000 = 2000.
    let (s1, _) = ask(gw, "acme-key").await;
    assert_eq!(s1, StatusCode::OK);
    wait_for_spend(&dp, 1);

    let store = dp.analytics().unwrap();
    let now = now_ms();
    let rows = store
        .query(|c| {
            query::spend_summary(
                c,
                &query::SpendQuery {
                    from_ms: now - 60_000,
                    to_ms: now + 60_000,
                    group_by: vec![],
                    limit: None,
                },
            )
        })
        .unwrap();
    assert_eq!(rows[0].cost_micros, 2000, "v1 pricing: 2000 micros");

    // Reload with v2 pricing: 2000 input + 2000 output.
    let pricing_v2 = "  pricing:\n    claude-x:\n      input_per_1k_micros: 2000\n      output_per_1k_micros: 2000\n";
    let gateway =
        dwara_core::config::parse_gateway(&cost_yaml(port, pricing_v2, "", "consumer", false))
            .unwrap();
    state.compile_and_publish(&gateway).unwrap();
    // The dataplane's refresh picks up the new generation.
    dp.refresh();

    // Request 2: cost = 1000*2000/1000 + 1000*2000/1000 = 4000.
    let (s2, _) = ask(gw, "acme-key").await;
    assert_eq!(s2, StatusCode::OK);
    wait_for_spend(&dp, 2);

    // The total is 2000 (v1) + 4000 (v2) = 6000.
    let rows = store
        .query(|c| {
            query::spend_summary(
                c,
                &query::SpendQuery {
                    from_ms: now - 60_000,
                    to_ms: now + 120_000,
                    group_by: vec![],
                    limit: None,
                },
            )
        })
        .unwrap();
    assert_eq!(
        rows[0].cost_micros, 6000,
        "total after reload: 2000 + 4000 = 6000"
    );
    assert_eq!(rows[0].request_count, 2);
}

// ---------------------------------------------------------------------------
// 6. Per-team spend tracked when a policy-scoped budget is configured
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn per_team_spend_tracked() {
    let (port, _seen) = anthropic_mock(100, 200);
    let pricing = "  pricing:\n    claude-x:\n      input_per_1k_micros: 3000\n      output_per_1k_micros: 15000\n";
    // Team budget (scope: policy) attached at the route level so both
    // consumers share it.
    let budget = "  token_budget:\n    tokens_per_min: 100000\n    scope: policy\n";
    let dp = dataplane_from(&cost_yaml(port, pricing, budget, "route", true));
    let _analytics = attach_analytics(&dp);
    let gw = spawn_gateway(dp.clone()).await;

    // Two consumers (acme + beta) both hit the route with the team budget.
    let (s1, _) = ask(gw, "acme-key").await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, _) = ask(gw, "beta-key").await;
    assert_eq!(s2, StatusCode::OK);
    wait_for_spend(&dp, 2);

    let store = dp.analytics().unwrap();
    let now = now_ms();

    // Query grouped by team: both consumers' spend rolls up under the
    // policy name "ai-budget".
    let rows = store
        .query(|c| {
            query::spend_summary(
                c,
                &query::SpendQuery {
                    from_ms: now - 60_000,
                    to_ms: now + 60_000,
                    group_by: vec!["team".to_string()],
                    limit: None,
                },
            )
        })
        .unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.key, vec!["ai-budget"]);
    assert_eq!(row.request_count, 2);
    // cost per request: 100*3000/1000 + 200*15000/1000 = 3300
    // two requests: 6600
    assert_eq!(row.cost_micros, 6600);

    // Query grouped by consumer: each consumer has its own row.
    let rows = store
        .query(|c| {
            query::spend_summary(
                c,
                &query::SpendQuery {
                    from_ms: now - 60_000,
                    to_ms: now + 60_000,
                    group_by: vec!["consumer".to_string()],
                    limit: None,
                },
            )
        })
        .unwrap();
    assert_eq!(rows.len(), 2);
    let names: Vec<String> = rows.iter().map(|r| r.key[0].clone()).collect();
    assert!(names.contains(&"acme".to_string()));
    assert!(names.contains(&"beta".to_string()));
}

// ---------------------------------------------------------------------------
// 7. Direct spend record + query (no gateway, deterministic)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn spend_record_direct_insert_and_query() {
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

    // Offer records directly (the fire-and-forget channel).
    store.offer_ai_spend(AiSpendRecord {
        ts_ms: 1000,
        consumer: "acme".to_string(),
        team: "".to_string(),
        provider: "p".to_string(),
        model: "claude-x".to_string(),
        version: "".to_string(),
        prompt_tokens: 100,
        completion_tokens: 200,
        total_tokens: 300,
        cost_micros: 3300,
    });
    store.offer_ai_spend(AiSpendRecord {
        ts_ms: 2000,
        consumer: "acme".to_string(),
        team: "".to_string(),
        provider: "p".to_string(),
        model: "gpt-4o".to_string(),
        version: "".to_string(),
        prompt_tokens: 50,
        completion_tokens: 50,
        total_tokens: 100,
        cost_micros: 500,
    });

    // Wait for the writer to flush both records.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let count: i64 = store
            .query(|c| c.query_row("SELECT COUNT(*) FROM ai_spend", [], |r| r.get(0)))
            .unwrap_or(0);
        if count >= 2 {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("timed out waiting for 2 spend records, got {count}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let rows = store
        .query(|c| {
            query::spend_summary(
                c,
                &query::SpendQuery {
                    from_ms: 0,
                    to_ms: 10_000,
                    group_by: vec!["model".to_string()],
                    limit: None,
                },
            )
        })
        .unwrap();
    assert_eq!(rows.len(), 2);
    // Ordered by cost descending: claude-x (3300) first.
    assert_eq!(rows[0].key, vec!["claude-x".to_string()]);
    assert_eq!(rows[0].cost_micros, 3300);
    assert_eq!(rows[1].key, vec!["gpt-4o".to_string()]);
    assert_eq!(rows[1].cost_micros, 500);

    // Clean shutdown: drain the channel.
    let _ = shutdown_tx.send(());
}
