//! Consumer request budgets (DW-033, feature analysis 4.9): the
//! quota/metering integration suite.
//!
//! Drives `proxy::handle` directly (respond-action routes: no upstream
//! needed) with an authenticated, quota-configured consumer, and pins:
//!
//! - a budget answers 429 with `Retry-After` (whole seconds to the
//!   window reset) and `X-RateLimit-Limit` / `-Remaining` / `-Reset`
//!   from the binding budget — the same header contract DW-017 set;
//! - usage counters are DURABLE: a store reopened from the same file
//!   (the restart shape) keeps refusing at the same budget; budgets
//!   compose (daily AND monthly; the monthly wall's reset is what the
//!   429 advertises when monthly binds);
//! - anonymous traffic and credential-less consumers are not
//!   quota-gated (budgets live on consumer config);
//! - quotas and rate limits are SEPARATE mechanisms that stack (a tiny
//!   GCRA window 429s with rate headers; a tiny budget 429s with
//!   budget headers — each family's headers identify their own
//!   mechanism's limits);
//! - metering: the denial lands in `dwara_quota_denied_total`, the
//!   usage gauges render at scrape time, and the analytics store
//!   records the refused request against the consumer (the
//!   per-consumer usage axis);
//! - `quota_near_limit` fires ONCE per (consumer, budget, window);
//! - quota config without a state store is INERT (fail-open: budgets
//!   cannot be enforced without counters — the documented once-per-
//!   process warn, never a per-request outage);
//! - budgets are isolated per consumer (no shared counters);
//! - a reload's new budget applies live (quota config is read from the
//!   current generation; there is no quota engine to rebuild);
//! - budgets wider than u32 admit without truncation (the 429 builder
//!   and headers are u64 since quotas are u64 config);
//! - validation: a zero budget and an empty quotas block are rejected;
//!   unknown fields never parse.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use bytes::Bytes;
use dwara_core::config::parse_gateway;
use dwara_core::observability::ListenerLabel;
use dwara_core::proxy::DataPlane;
use dwara_core::snapshot::ConfigState;
use dwara_core::state::store::{sync_consumers_from_config, StateStore};
use http_body_util::{BodyExt, Full};
use hyper::header::{HeaderMap, RETRY_AFTER};
use hyper::{Request, StatusCode};

mod support;

use support::envelope_code;

fn ip(a: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, a))
}

/// The quota test config: consumer `acme` (api-key auth) with budgets
/// `daily`/`monthly`, consumer `free` with credentials and NO quotas
/// (the unbudgeted control), and one respond route. Anonymous traffic
/// hits the same route (no `auth_required`).
fn quota_yaml(daily: Option<u64>, monthly: Option<u64>) -> String {
    let mut quotas = String::new();
    if let Some(d) = daily {
        quotas.push_str(&format!("      daily_requests: {d}\n"));
    }
    if let Some(m) = monthly {
        quotas.push_str(&format!("      monthly_requests: {m}\n"));
    }
    let quotas_block = if quotas.is_empty() {
        String::new()
    } else {
        format!("    quotas:\n{quotas}")
    };
    format!(
        "consumers:
  - name: acme
    credentials:
      - type: api_key
        key: acme-key
{quotas_block}  - name: free
    credentials:
      - type: api_key
        key: free-key
routes:
  - name: r
    service: svc
    match: {{ path: {{ type: prefix, value: /r }} }}
    action: {{ type: respond, status: 200, body: ok }}
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{{ address: 127.0.0.1, port: 1 }}]
"
    )
}

/// Build a dataplane whose state store (in-memory or file) is seeded
/// from the config (consumer rows + credential hashes) and attached.
fn quota_dataplane(yaml: &str, store: Arc<StateStore>) -> Arc<DataPlane> {
    let gateway = parse_gateway(yaml).expect("test config parses");
    let state = Arc::new(ConfigState::new());
    state
        .compile_and_publish(&gateway)
        .expect("test config publishes");
    sync_consumers_from_config(&store, &gateway, None).expect("consumer seed");
    let dp = DataPlane::new(state);
    dp.set_state_store(store);
    dp
}

fn req_with_key(path: &str, key: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .uri(path)
        .header("x-api-key", key)
        .extension(ListenerLabel(std::sync::Arc::from("edge")))
        .body(Full::new(Bytes::new()))
        .unwrap()
}

async fn status_body(
    resp: hyper::Response<dwara_core::proxy::ProxyBody>,
) -> (StatusCode, HeaderMap, String) {
    let (parts, body) = resp.into_parts();
    let bytes = body
        .collect()
        .await
        .unwrap_or_else(|e| panic!("body read failed: {e}"))
        .to_bytes();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    (parts.status, parts.headers, text)
}

fn rate_headers(h: &HeaderMap) -> Option<(u64, u64, u64)> {
    let get = |n: &str| -> Option<u64> {
        h.get(format!("x-ratelimit-{n}"))
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
    };
    Some((get("limit")?, get("remaining")?, get("reset")?))
}

fn now_epoch_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn daily_budget_answers_429_with_retry_after_and_budget_headers() {
    let store = Arc::new(StateStore::open_in_memory().unwrap());
    let dp = quota_dataplane(&quota_yaml(Some(2), None), store);
    let peer = ip(1);
    for _expected_remaining in [1, 0] {
        let (status, headers, body) =
            status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "acme-key")).await)
                .await;
        assert_eq!(status, StatusCode::OK, "within budget: {body}");
        // Allowed responses carry no quota headers (documented: the
        // X-RateLimit-* family on successes belongs to the rate limiter
        // when it applies; no rate policy applies here).
        assert!(
            rate_headers(&headers).is_none(),
            "no rate headers without a rate policy or a denial"
        );
    }
    let (status, headers, body) =
        status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "acme-key")).await)
            .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(envelope_code(body.as_bytes()), "rate_limit_exceeded");
    let retry: u64 = headers
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .expect("Retry-After on quota 429");
    let (limit, remaining, reset) = rate_headers(&headers).expect("budget headers on 429");
    assert_eq!(limit, 2, "the budget's cap is the advertised limit");
    assert_eq!(remaining, 0);
    let now = now_epoch_s();
    assert!(retry >= 1, "Retry-After is at least one second");
    // The daily reset is the next UTC midnight: bounded by a day, and
    // in the future.
    assert!(reset > now, "Reset is a future unix epoch second");
    assert!(reset <= now + 86_400, "Reset is within one day");
    // Further requests keep refusing (denials do not consume) and the
    // headers stay honest.
    let (status2, headers2, _) =
        status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "acme-key")).await)
            .await;
    assert_eq!(status2, StatusCode::TOO_MANY_REQUESTS);
    let (_, remaining2, _) = rate_headers(&headers2).unwrap();
    assert_eq!(remaining2, 0);
}

#[tokio::test]
async fn anonymous_traffic_and_unbudgeted_consumers_are_not_gated() {
    let store = Arc::new(StateStore::open_in_memory().unwrap());
    let dp = quota_dataplane(&quota_yaml(Some(1), None), store);
    let peer = ip(2);
    // Anonymous: no identity, no consumer config, no budget — the
    // route allows anonymous traffic (no auth_required).
    for _ in 0..5 {
        let req = Request::builder()
            .uri("/r")
            .extension(ListenerLabel(std::sync::Arc::from("edge")))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (status, headers, _) =
            status_body(dwara_core::proxy::handle(&dp, peer, req).await).await;
        assert_eq!(status, StatusCode::OK);
        assert!(rate_headers(&headers).is_none());
    }
    // Authenticated but quota-free consumer: unlimited by budgets.
    for _ in 0..5 {
        let (status, _, _) =
            status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "free-key")).await)
                .await;
        assert_eq!(status, StatusCode::OK);
    }
}

#[tokio::test]
async fn monthly_budget_binds_with_month_scale_reset_and_composes_with_daily() {
    let store = Arc::new(StateStore::open_in_memory().unwrap());
    // Daily budget the burst fits inside; monthly budget it exceeds.
    let dp = quota_dataplane(&quota_yaml(Some(10), Some(2)), store);
    let peer = ip(3);
    for _ in 0..2 {
        let (status, _, _) =
            status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "acme-key")).await)
                .await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, headers, _) =
        status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "acme-key")).await)
            .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let (limit, remaining, reset) = rate_headers(&headers).expect("monthly budget binds");
    assert_eq!(limit, 2, "the MONTHLY cap binds the headers");
    assert_eq!(remaining, 0);
    let now = now_epoch_s();
    // Month-scale reset: further out than a day, within 32 days.
    assert!(
        reset > now + 86_400 && reset <= now + 32 * 86_400,
        "monthly reset is month-scale: reset={reset} now={now}"
    );
    let retry: u64 = headers
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap();
    assert!(retry > 86_400, "Retry-After is month-scale: {retry}");
}

#[tokio::test]
async fn usage_counters_survive_a_restart() {
    // The crash/restart shape: a FILE-backed store, exhausted, then
    // reopened from disk and attached to a FRESH dataplane (new config
    // state, new process semantics) — the budget must still refuse.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    let yaml = quota_yaml(Some(2), None);
    {
        let store = Arc::new(StateStore::open(&path).unwrap());
        let dp = quota_dataplane(&yaml, Arc::clone(&store));
        let peer = ip(4);
        for _ in 0..2 {
            let (status, _, _) = status_body(
                dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "acme-key")).await,
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }
        let (status, _, _) =
            status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "acme-key")).await)
                .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    }
    // Restart: reopen the SAME file, re-seed (idempotent), serve again.
    let store2 = Arc::new(StateStore::open(&path).unwrap());
    let dp2 = quota_dataplane(&yaml, Arc::clone(&store2));
    let peer = ip(4);
    let (status, headers, _) =
        status_body(dwara_core::proxy::handle(&dp2, peer, req_with_key("/r", "acme-key")).await)
            .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the counter persisted across the store reopen"
    );
    let (limit, remaining, _) = rate_headers(&headers).unwrap();
    assert_eq!((limit, remaining), (2, 0));
}

#[tokio::test]
async fn quotas_and_rate_limits_are_separate_mechanisms() {
    // One consumer, BOTH a rate-limit policy (per-minute 3, ip+route
    // selector) and a generous budget (1000/day): the 4th request 429s
    // from the RATE LIMITER (limit 3 headers, the RL family counted).
    let yaml = format!(
        "policies:
  - name: rl
    rate_limits:
      - selector: [ip]
        requests_per: {{ minute: 3 }}
{}",
        quota_yaml(Some(1000), None).replace(
            "routes:\n  - name: r\n",
            "routes:\n  - name: r\n    policies: [rl]\n"
        )
    );
    let store = Arc::new(StateStore::open_in_memory().unwrap());
    let dp = quota_dataplane(&yaml, store);
    let peer = ip(5);
    for _ in 0..3 {
        let (status, _, _) =
            status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "acme-key")).await)
                .await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, headers, _) =
        status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "acme-key")).await)
            .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let (limit, _, _) = rate_headers(&headers).unwrap();
    assert_eq!(limit, 3, "the GCRA window (3/min) binds, not the budget");
    // And the mirrored case lives in daily_budget_answers_429...: a
    // tight budget with no rate policy binds with the budget's cap.
}

#[tokio::test]
async fn quota_denial_metering_reaches_metrics_and_analytics() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::open_in_memory().unwrap());
    let dp = quota_dataplane(&quota_yaml(Some(1), None), store);
    // Attach the embedded analytics store (DW-043) with a fast writer
    // flush so the completion records land without a long sleep.
    let analytics = dwara_core::analytics::EmbeddedAnalytics::open(
        dir.path().join("analytics.db").to_str().unwrap(),
        dwara_core::analytics::DEFAULT_RETENTION_MS,
        20,
    )
    .unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
    analytics.spawn_workers(shutdown_rx);
    dp.set_analytics(analytics.clone());

    let peer = ip(6);
    let (status, _, _) =
        status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "acme-key")).await)
            .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) =
        status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "acme-key")).await)
            .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // Metrics: the denial counter and (scrape-time) the usage gauges.
    let metrics_req = Request::builder()
        .uri("/metrics")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = dwara_core::proxy::handle(&dp, peer, metrics_req).await;
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        body.contains("dwara_quota_denied_total{budget=\"daily\",consumer=\"acme\"} 1"),
        "denial counter renders: {body}"
    );
    assert!(
        body.contains("dwara_quota_used{budget=\"daily\",consumer=\"acme\"} 1"),
        "usage gauge renders the spent unit: {body}"
    );
    assert!(
        body.contains("dwara_quota_limit{budget=\"daily\",consumer=\"acme\"} 1"),
        "limit gauge renders: {body}"
    );

    // Analytics sink: the refusal is a completed request record against
    // the consumer with rate_limited set — the per-consumer usage axis.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let rows = analytics
        .query(|c| {
            let mut stmt = c.prepare("SELECT consumer, status, rate_limited FROM raw")?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .unwrap();
    // The /metrics scrape above is itself a completed (anonymous)
    // request; the consumer rows are the metering story.
    let acme: Vec<_> = rows
        .iter()
        .filter(|(c, _, _)| c == "acme")
        .cloned()
        .collect();
    assert_eq!(acme.len(), 2, "both acme completions recorded: {rows:?}");
    assert_eq!(acme[0], ("acme".to_string(), 200, 0));
    assert_eq!(acme[1], ("acme".to_string(), 429, 1));
    shutdown_tx.send(()).unwrap();
}

#[tokio::test]
async fn quota_near_limit_fires_once_per_window() {
    let store = Arc::new(StateStore::open_in_memory().unwrap());
    // Budget 5: the 4th request (80%) is the crossing; the 5th is over
    // but must NOT re-notify.
    let dp = quota_dataplane(&quota_yaml(Some(5), None), store);
    // The dataplane adopted/created the state's bus; take the receiver
    // before driving traffic so nothing is drained by a deliverer.
    let mut rx = dp.events().take_receiver().expect("fresh receiver");

    let peer = ip(7);
    for i in 0..5 {
        let (status, _, _) =
            status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "acme-key")).await)
                .await;
        assert_eq!(status, StatusCode::OK, "request {i}");
    }
    // Exactly one quota_near_limit event is queued (the crossing at
    // request 4); drain with a short deadline and count.
    let mut near_limit = 0usize;
    while let Ok(ev) = rx.try_recv() {
        if matches!(ev.kind, dwara_core::events::EventKind::QuotaNearLimit) {
            near_limit += 1;
            assert_eq!(ev.payload.consumer.as_deref(), Some("acme"));
            assert_eq!(ev.payload.detail, Some("daily"));
            assert_eq!(ev.payload.used, Some(4));
            assert_eq!(ev.payload.limit, Some(5));
        }
    }
    assert_eq!(near_limit, 1, "one edge-triggered notice per window");
    // Over the wall: a 6th request 429s; still no second notice.
    let (status, _, _) =
        status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "acme-key")).await)
            .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    while let Ok(ev) = rx.try_recv() {
        assert!(
            !matches!(ev.kind, dwara_core::events::EventKind::QuotaNearLimit),
            "denials never re-notify the same window"
        );
    }
}

#[test]
fn quota_config_validation_rejects_zero_and_empty_budgets() {
    let store_shape = quota_yaml(Some(2), None);
    assert!(parse_gateway(&store_shape).is_ok());

    let zero = quota_yaml(Some(0), None);
    let gw = parse_gateway(&zero).unwrap();
    let issues = dwara_core::snapshot::validate(&gw);
    assert!(
        issues
            .iter()
            .any(|i| i.field.contains("daily_requests") && i.message.contains("must be > 0")),
        "zero daily budget rejected: {issues:?}"
    );

    let empty = quota_yaml(None, None).replace("  - name: free", "    quotas: {}\n  - name: free");
    assert!(
        parse_gateway(&empty).is_ok(),
        "an explicit empty block parses"
    );
    let gw = parse_gateway(&empty).unwrap();
    let issues = dwara_core::snapshot::validate(&gw);
    assert!(
        issues
            .iter()
            .any(|i| i.field.ends_with(".quotas") && i.message.contains("no budget")),
        "empty quotas block rejected: {issues:?}"
    );

    let unknown = store_shape.replace("daily_requests", "daily_req");
    assert!(
        parse_gateway(&unknown).is_err(),
        "deny_unknown_fields rejects misspelled budget fields"
    );
}

#[tokio::test]
async fn quota_config_without_a_state_store_is_inert_fail_open() {
    // Budgets need durable counters; without DWARA_STATE_DB there are
    // none, so enforcement is impossible — the documented posture is
    // fail-open with a once-per-process warn, never a 429/500 loop.
    let gateway = parse_gateway(&quota_yaml(Some(1), None)).unwrap();
    let state = Arc::new(ConfigState::new());
    state.compile_and_publish(&gateway).unwrap();
    // NOTE: no store attached, no consumer sync — pure-config operation.
    let dp = DataPlane::new(state);
    let peer = ip(8);
    for _ in 0..5 {
        let (status, headers, _) =
            status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "acme-key")).await)
                .await;
        assert_eq!(status, StatusCode::OK, "inert budgets never refuse");
        assert!(rate_headers(&headers).is_none());
    }
}

#[tokio::test]
async fn budgets_are_isolated_per_consumer() {
    // Two budgeted consumers, each cap 1: exhausting one must not touch
    // the other's counter (counters key on the consumer's store row).
    let yaml = "consumers:
  - name: acme
    credentials:
      - type: api_key
        key: acme-key
    quotas:
      daily_requests: 1
  - name: beta
    credentials:
      - type: api_key
        key: beta-key
    quotas:
      daily_requests: 1
routes:
  - name: r
    service: svc
    match: { path: { type: prefix, value: /r } }
    action: { type: respond, status: 200, body: ok }
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";
    let store = Arc::new(StateStore::open_in_memory().unwrap());
    let dp = quota_dataplane(yaml, store);
    let peer = ip(9);
    // acme spends its single unit and hits the wall.
    let (status, _, _) =
        status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "acme-key")).await)
            .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) =
        status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "acme-key")).await)
            .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    // beta's budget is untouched: its own first unit still admits.
    let (status, _, _) =
        status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "beta-key")).await)
            .await;
    assert_eq!(status, StatusCode::OK, "sibling budget unaffected");
    let (status, _, _) =
        status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "beta-key")).await)
            .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn reload_budget_change_applies_live() {
    // Quota budgets are read from the current generation's consumer
    // config (no compiled engine to rebuild, unlike the rate limiter):
    // publishing a larger cap must admit again against the SAME
    // persisted counter.
    let yaml1 = quota_yaml(Some(1), None);
    let gateway = parse_gateway(&yaml1).unwrap();
    let state = Arc::new(ConfigState::new());
    state.compile_and_publish(&gateway).unwrap();
    let store = Arc::new(StateStore::open_in_memory().unwrap());
    sync_consumers_from_config(&store, &gateway, None).unwrap();
    let dp = DataPlane::new(Arc::clone(&state));
    dp.set_state_store(Arc::clone(&store));
    let peer = ip(10);
    let (status, _, _) =
        status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "acme-key")).await)
            .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) =
        status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "acme-key")).await)
            .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "cap 1 spent");

    // Reload with cap 2: the same counter (used=1) now has room.
    let gateway2 = parse_gateway(&quota_yaml(Some(2), None)).unwrap();
    state.compile_and_publish(&gateway2).unwrap();
    dp.refresh();
    let (status, _, _) =
        status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "acme-key")).await)
            .await;
    assert_eq!(status, StatusCode::OK, "the reloaded cap admits");
    let (status, headers, _) =
        status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "acme-key")).await)
            .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "cap 2 now spent");
    let (limit, remaining, _) = rate_headers(&headers).expect("budget headers on 429");
    assert_eq!((limit, remaining), (2, 0), "headers reflect the NEW cap");
}

#[tokio::test]
async fn budgets_wider_than_u32_admit_without_truncation() {
    // Quotas are u64 config; the 429 builder and its headers were
    // widened accordingly. A cap beyond u32::MAX must parse, admit,
    // and count (no truncation, no panic) — pinning the widening.
    let beyond_u32 = u64::from(u32::MAX) + 1;
    let store = Arc::new(StateStore::open_in_memory().unwrap());
    let dp = quota_dataplane(&quota_yaml(Some(beyond_u32), None), store);
    let peer = ip(11);
    for _ in 0..3 {
        let (status, _, _) =
            status_body(dwara_core::proxy::handle(&dp, peer, req_with_key("/r", "acme-key")).await)
                .await;
        assert_eq!(status, StatusCode::OK);
    }
}
