//! AI token budget tests (DW-078): pre-check rejection before provider
//! contact, mid-stream cutoff, window independence, and policy
//! precedence — through the real gateway with mock providers.

mod support;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use serde_json::{json, Value};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use support::{dataplane_from, h1_client, spawn_backend_async, spawn_gateway, uri};

/// What the provider mock saw.
#[derive(Debug, Clone)]
struct Seen {
    count: u64,
    wants_stream: bool,
}

/// An anthropic-dialect mock: non-streaming answers a JSON completion
/// with usage input=N out=M; streaming reports input tokens in
/// message_start (EARLY — the mid-stream cutoff signal) and output
/// tokens in message_delta. The token numbers are per-request
/// parameters so tests shape spend precisely.
fn anthropic_mock(input_tokens: u64, output_tokens: u64) -> (u16, Arc<Mutex<Seen>>) {
    let first = format!(
        "event: message_start\ndata: {}\n\nevent: content_block_delta\ndata: {}\n\n",
        json!({"type": "message_start", "message": {"usage": {"input_tokens": input_tokens}}}),
        json!({"type": "content_block_delta", "index": 0,
               "delta": {"type": "text_delta", "text": "partial answer"}}),
    );
    let second = format!(
        "event: message_delta\ndata: {}\n\nevent: message_stop\ndata: {}\n\n",
        json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"},
               "usage": {"output_tokens": output_tokens}}),
        json!({"type": "message_stop"}),
    );
    anthropic_mock_script(
        input_tokens,
        output_tokens,
        vec![
            (std::time::Duration::ZERO, first),
            (std::time::Duration::from_millis(50), second),
        ],
    )
}

/// [`anthropic_mock`] with a caller-written STREAM: each step sleeps
/// its delay and then writes its batch as one body frame. Tests that
/// shape a stream's usage reports precisely (downward revisions,
/// minute-boundary straddles) write the wire themselves; the
/// non-streaming branch is unchanged.
fn anthropic_mock_script(
    input_tokens: u64,
    output_tokens: u64,
    stream_steps: Vec<(std::time::Duration, String)>,
) -> (u16, Arc<Mutex<Seen>>) {
    let seen: Arc<Mutex<Seen>> = Arc::new(Mutex::new(Seen {
        count: 0,
        wants_stream: false,
    }));
    let s = Arc::clone(&seen);
    let port = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(spawn_backend_async(
            move |req: Request<Incoming>| {
                let s = Arc::clone(&s);
                let input = input_tokens;
                let output = output_tokens;
                let steps = stream_steps.clone();
                async move {
                    let (_parts, body) = req.into_parts();
                    let bytes = body.collect().await.unwrap().to_bytes();
                    let wants_stream = String::from_utf8_lossy(&bytes).contains("\"stream\":true");
                    {
                        let mut g = s.lock().unwrap();
                        g.count += 1;
                        g.wants_stream = wants_stream;
                    }
                    if wants_stream {
                        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, ChanErr>>(4);
                        tokio::spawn(async move {
                            for (delay, batch) in steps {
                                tokio::time::sleep(delay).await;
                                if tx.send(Ok(Bytes::from(batch))).await.is_err() {
                                    break;
                                }
                            }
                        });
                        return Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "text/event-stream")
                                .body(ChanBody { rx })
                                .unwrap(),
                        );
                    }
                    // Same body type as the streaming branch (the
                    // closure must return one Response type): one
                    // channel frame carrying the whole JSON.
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
/// credential, and the given budget policy attached (consumer or
/// route level).
fn budget_yaml(port: u16, budget_yaml: &str, attach: &str, second_consumer: bool) -> String {
    let consumer_attach = if attach == "consumer" {
        "     - ai-budget\n"
    } else {
        ""
    };
    let second = if second_consumer {
        "- name: beta\n  credentials:\n  - type: api_key\n    key: beta-key\n"
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
         \x20     provider_model: claude-x\n"
    )
}

async fn ask(
    port: u16,
    key: &str,
    stream: bool,
) -> (StatusCode, Bytes, Option<Vec<String>>, Option<u64>) {
    ask_with(port, Some(key), stream).await
}

/// [`ask`] with an OPTIONAL credential: `None` sends no key at all —
/// an anonymous caller on a route without `auth_required` (an invalid
/// PRESENTED key would 401 instead, which is a different path).
async fn ask_with(
    port: u16,
    key: Option<&str>,
    stream: bool,
) -> (StatusCode, Bytes, Option<Vec<String>>, Option<u64>) {
    let mut body = json!({
        "model": "chat",
        "messages": [{"role": "user", "content": "hi"}]
    });
    if stream {
        body["stream"] = json!(true);
    }
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(uri(port, "/v1/chat/completions"))
        .header("content-type", "application/json");
    if let Some(key) = key {
        req = req.header("x-api-key", key);
    }
    let resp = h1_client()
        .request(req.body(Full::new(Bytes::from(body.to_string()))).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let mut body = resp.into_body();
    let mut text = String::new();
    while let Some(frame) = body.frame().await {
        if let Some(data) = frame.expect("client body ok").data_ref() {
            text.push_str(&String::from_utf8_lossy(data));
        }
    }
    let mut frames = Vec::new();
    let mut rest = text.as_str();
    while let Some(i) = rest.find("\n\n") {
        frames.push(rest[..i + 2].to_string());
        rest = &rest[i + 2..];
    }
    let retry_after = headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    (
        status,
        Bytes::from(text),
        if frames.is_empty() {
            None
        } else {
            Some(frames)
        },
        retry_after,
    )
}

/// Current Unix seconds (the budget window index basis).
fn epoch_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is past the epoch")
        .as_secs()
}

/// Sleep until `lead_s` seconds before the next epoch-minute boundary
/// (aiming at the FOLLOWING boundary when the current minute cannot
/// give that lead). The boundary itself is the fixture under test, so
/// this wait is setup, not synchronization; loopback request handling
/// runs in single-digit milliseconds, making `lead_s` seconds of
/// margin generous.
async fn align_to_minute(lead_s: u64) {
    loop {
        let to_boundary = 60 - (epoch_s() % 60);
        if to_boundary > lead_s {
            tokio::time::sleep(std::time::Duration::from_secs(to_boundary - lead_s)).await;
            return;
        }
        // Too close to this boundary: aim at the next one.
        tokio::time::sleep(std::time::Duration::from_secs(to_boundary + 1)).await;
    }
}

/// The done-when: a consumer over its tokens/min budget is rejected
/// BEFORE the request reaches the provider (the provider saw exactly
/// the requests that were served).
#[tokio::test(flavor = "multi_thread")]
async fn exhausted_budget_rejects_before_provider_contact() {
    // Budget 500 tokens/min; each request spends 300 (100 in + 200 out).
    let (port, seen) = anthropic_mock(100, 200);
    let budget = "  token_budget:\n    tokens_per_min: 500\n";
    let dp = dataplane_from(&budget_yaml(port, budget, "consumer", false));
    let gw = spawn_gateway(dp).await;

    // Request 1: allowed, spends 300.
    let (s1, _, _, _) = ask(gw, "acme-key", false).await;
    assert_eq!(s1, StatusCode::OK);
    // Request 2: 300 spent, 200 remaining — still allowed (spends 300,
    // crossing the window; overrun bounded by one request, documented).
    let (s2, _, _, _) = ask(gw, "acme-key", false).await;
    assert_eq!(s2, StatusCode::OK);
    // Request 3: 600 >= 500 — rejected BEFORE the provider, with a
    // Retry-After bounded by the minute window.
    let (s3, body3, _, retry_after) = ask(gw, "acme-key", false).await;
    assert_eq!(s3, StatusCode::TOO_MANY_REQUESTS);
    let v: Value = serde_json::from_slice(&body3).unwrap();
    assert_eq!(v["error"]["code"], "ai_budget_exceeded");
    assert_eq!(v["error"]["type"], "rate_limit_error");
    let ra = retry_after.expect("429 carries Retry-After");
    assert!(
        (1..=60).contains(&ra),
        "retry-after counts to the minute boundary, got {ra}"
    );
    // The provider saw EXACTLY the two served requests.
    assert_eq!(
        seen.lock().unwrap().count,
        2,
        "the rejected request never reached the provider"
    );
}

/// Mid-stream cutoff (the hard case): the anthropic mock reports input
/// tokens EARLY — a stream that alone crosses the window is cut off
/// deterministically: partial content stands, the documented
/// over-budget event arrives, then [DONE]; no further provider frames
/// are consumed.
#[tokio::test(flavor = "multi_thread")]
async fn mid_stream_crossing_cuts_off_with_documented_event() {
    // Budget 500; the stream's message_start alone reports 600 input
    // tokens — the crossing is visible on the FIRST usage event.
    let (port, seen) = anthropic_mock(600, 50);
    let budget = "  token_budget:\n    tokens_per_min: 500\n";
    let dp = dataplane_from(&budget_yaml(port, budget, "consumer", false));
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    let (status, _bytes, frames, _) = ask(gw, "acme-key", true).await;
    assert_eq!(status, StatusCode::OK);
    let frames = frames.expect("a streamed response");
    let cutoff = frames
        .iter()
        .find(|f| f.contains("ai_budget_exceeded"))
        .expect("the documented over-budget event frame");
    assert!(cutoff.contains("rate_limit_error"));
    assert!(cutoff.contains("exhausted"));
    // The terminator follows the cutoff event.
    assert_eq!(frames.last().unwrap().trim(), "data: [DONE]");
    // The denial is counted.
    let metrics = dp.observability().render();
    assert!(metrics.contains("dwara_ai_budget_denied_total"));
    assert!(metrics.contains("kind=\"tokens\""));
    // The cutoff's spend (the 600 reported input tokens) is RECORDED:
    // a follow-up request in the same window is denied by the
    // PRE-CHECK, before the provider — which saw exactly one request.
    let (s2, body2, _, _) = ask(gw, "acme-key", false).await;
    assert_eq!(s2, StatusCode::TOO_MANY_REQUESTS);
    let v: Value = serde_json::from_slice(&body2).unwrap();
    assert_eq!(v["error"]["code"], "ai_budget_exceeded");
    assert_eq!(
        seen.lock().unwrap().count,
        1,
        "the post-cutoff request never reached the provider"
    );
}

/// Clean-completing streams spend EXACTLY the provider-reported
/// tokens: the report grows across chunks (input tokens at
/// message_start, output at message_delta) and each reported token
/// must be counted ONCE — not once per chunk it was visible in, and
/// not again at stream close.
#[tokio::test(flavor = "multi_thread")]
async fn completed_streams_spend_exactly_the_reported_tokens() {
    // Each stream reports 150 tokens total (100 in + 50 out).
    let (port, seen) = anthropic_mock(100, 50);
    let budget = "  token_budget:\n    tokens_per_min: 400\n";
    let dp = dataplane_from(&budget_yaml(port, budget, "consumer", false));
    let gw = spawn_gateway(dp).await;

    // Three clean streams: pre-checks see 0, 150, then 300 spent —
    // all inside 400. The third stream's spend crosses the window
    // while it runs (450; overrun bounded by one request, the
    // documented check-then-spend) but is never cut off: the
    // crossing coincides with the stream's own terminal events.
    for i in 0..3 {
        let (status, _bytes, frames, _) = ask(gw, "acme-key", true).await;
        assert_eq!(status, StatusCode::OK, "stream {} must be allowed", i + 1);
        let frames = frames.expect("a streamed response");
        assert!(
            !frames.iter().any(|f| f.contains("ai_budget_exceeded")),
            "in-budget streams must never be cut off"
        );
        assert_eq!(frames.last().unwrap().trim(), "data: [DONE]");
    }
    // The ledger holds exactly 450 (3 x 150): the next pre-check
    // denies BEFORE the provider, which saw exactly the three served
    // streams. (With per-chunk re-spending, the SECOND stream alone
    // would already have exhausted the window.)
    let (s4, body4, _, retry_after) = ask(gw, "acme-key", false).await;
    assert_eq!(s4, StatusCode::TOO_MANY_REQUESTS);
    let v: Value = serde_json::from_slice(&body4).unwrap();
    assert_eq!(v["error"]["code"], "ai_budget_exceeded");
    let ra = retry_after.expect("429 carries Retry-After");
    assert!(
        (1..=60).contains(&ra),
        "retry-after within the minute window: {ra}"
    );
    assert_eq!(
        seen.lock().unwrap().count,
        3,
        "the denied request never reached the provider"
    );
}

/// Windows are independent (the done-when): tokens/min exhaustion is
/// a 60-second wall; the cost/day window does not move without
/// prices. With the DW-079 seam returning 0 cost, a cost-configured
/// budget never denies.
#[tokio::test(flavor = "multi_thread")]
async fn cost_window_is_independent_and_inert_until_priced() {
    let (port, _) = anthropic_mock(100, 100);
    let budget = "  token_budget:\n    tokens_per_min: 1000\n    cost_per_day_micros: 1\n    scope: policy\n";
    // scope: policy — a SHARED (team) budget: two consumers spend one
    // ledger entry.
    let dp = dataplane_from(&budget_yaml(port, budget, "consumer", true));
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    // Both consumers share the team budget: together they spend 400
    // of 1000. Neither denied.
    let (sa, _, _, _) = ask(gw, "acme-key", false).await;
    let (sb, _, _, _) = ask(gw, "beta-key", false).await;
    assert_eq!(sa, StatusCode::OK);
    assert_eq!(sb, StatusCode::OK);
    // Cost window: 1 micro-USD/day configured, but the pricing seam
    // (DW-079) returns 0 — no cost denied. The seam is honest: the
    // window is enforced, the INPUT is not priced yet.
    let metrics = dp.observability().render();
    assert!(
        !metrics.contains("kind=\"cost\""),
        "cost is inert until DW-079 prices it"
    );
}

/// Policy precedence: a consumer-attached budget GOVERNS over a
/// route-attached one (most specific level wins — a budget is a
/// limit-of-totals, not an AND rule).
#[tokio::test(flavor = "multi_thread")]
async fn consumer_budget_governs_over_route_budget() {
    let (port, _seen) = anthropic_mock(100, 100);
    // Consumer-attached: 150/min. Route-attached: 1_000_000/min. The
    // consumer level governs (most specific binding for a budget).
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
         \x20 policies:\n\
         \x20 - route-cap\n\
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
         \x20 - ai-budget\n\
         policies:\n\
         - name: ai-budget\n\
         \x20 token_budget:\n\
         \x20   tokens_per_min: 150\n\
         - name: route-cap\n\
         \x20 token_budget:\n\
         \x20   tokens_per_min: 1000000\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: p\n\
         \x20   kind: anthropic\n\
         \x20   upstream: up\n\
         \x20 models:\n\
         \x20   chat:\n\
         \x20     provider: p\n\
         \x20     provider_model: claude-x\n"
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;
    // One request spends 200 > 150: the next pre-check denies under
    // the CONSUMER budget (the route's 1M would allow).
    let (s1, _, _, _) = ask(gw, "acme-key", false).await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, body2, _, _) = ask(gw, "acme-key", false).await;
    assert_eq!(s2, StatusCode::TOO_MANY_REQUESTS);
    let v: Value = serde_json::from_slice(&body2).unwrap();
    assert_eq!(v["error"]["code"], "ai_budget_exceeded");
}

/// The spend ledger SURVIVES a config reload: budget RULES swap with
/// the generation, but a reload must never reset a live 60-second
/// window (a reset would silently re-open an exhausted budget on every
/// config touch).
#[tokio::test(flavor = "multi_thread")]
async fn budget_spend_survives_config_reload() {
    // Budget 500/min; each request spends 300 (100 in + 200 out).
    let (port, seen) = anthropic_mock(100, 200);
    let yaml = budget_yaml(
        port,
        "  token_budget:\n    tokens_per_min: 500\n",
        "consumer",
        false,
    );
    let state = support::state_from(&yaml);
    let dp = Arc::new(dwara_core::dataplane::proxy::DataPlane::new(Arc::clone(
        &state,
    )));
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    // Request 1: allowed, spends 300.
    let (s1, _, _, _) = ask(gw, "acme-key", false).await;
    assert_eq!(s1, StatusCode::OK);

    // Reload: republish the config (a new generation with the SAME
    // budget rules — only the ledger carrying matters here).
    let gateway = dwara_core::config::parse_gateway(&yaml).expect("reload config parses");
    state
        .compile_and_publish(&gateway)
        .expect("reload publishes");
    dp.refresh();

    // Request 2: the pre-check must see the CARRIED 300 — allowed
    // (spends 300 more, total 600 > 500).
    let (s2, _, _, _) = ask(gw, "acme-key", false).await;
    assert_eq!(s2, StatusCode::OK, "carried spend is below the window");
    // Request 3: 600 >= 500 — denied ONLY because the reload carried
    // the spend (a reset ledger would leave 300 < 500 and allow this).
    let (s3, body3, _, _) = ask(gw, "acme-key", false).await;
    assert_eq!(s3, StatusCode::TOO_MANY_REQUESTS);
    let v: Value = serde_json::from_slice(&body3).unwrap();
    assert_eq!(v["error"]["code"], "ai_budget_exceeded");
    assert_eq!(
        seen.lock().unwrap().count,
        2,
        "the denied request never reached the provider"
    );
}

/// A client that hangs up mid-stream still OWES its spend: dropping the
/// body closes it, and close() spends the un-spent delta — tokens the
/// provider already reported must land in the ledger even though nobody
/// drained the stream.
#[tokio::test(flavor = "multi_thread")]
async fn client_disconnect_mid_stream_still_spends_the_reported_tokens() {
    // Budget 200/min. The stream reports 100 input tokens in its FIRST
    // batch and 50 output tokens 50ms later; the client reads one frame
    // (the first batch is already translated — and spent — by then) and
    // drops the body. Whether the second batch beats the upstream
    // cancellation is a race, so the recorded spend lands in
    // [100, 150]; the assertions below hold across the whole range.
    let (port, seen) = anthropic_mock(100, 50);
    let dp = dataplane_from(&budget_yaml(
        port,
        "  token_budget:\n    tokens_per_min: 200\n",
        "consumer",
        false,
    ));
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    // Open the stream, read exactly ONE frame, then hang up.
    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(gw, "/v1/chat/completions"))
                .header("content-type", "application/json")
                .header("x-api-key", "acme-key")
                .body(Full::new(Bytes::from(
                    json!({
                        "model": "chat",
                        "messages": [{"role": "user", "content": "hi"}],
                        "stream": true
                    })
                    .to_string(),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body();
    let first = Pin::new(&mut body)
        .frame()
        .await
        .expect("first frame arrives");
    assert!(first.expect("ok frame").data_ref().is_some());
    drop(body);
    // Bounded settle for the cancellation and the Drop-path spend (a
    // wait-for-side-effect with a bound, not a synchronization sleep).
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    // A follow-up non-stream request (spends 150): the pre-check sees
    // the carried [100, 150] < 200 — allowed — and the spend lands at
    // [250, 300] >= 200. WITHOUT the Drop-path spend the ledger would
    // hold 0 from the disconnected stream and the final request below
    // would be allowed (150 < 200).
    let (s2, _, _, _) = ask(gw, "acme-key", false).await;
    assert_eq!(s2, StatusCode::OK);
    let (s3, body3, _, _) = ask(gw, "acme-key", false).await;
    assert_eq!(s3, StatusCode::TOO_MANY_REQUESTS);
    let v: Value = serde_json::from_slice(&body3).unwrap();
    assert_eq!(v["error"]["code"], "ai_budget_exceeded");
    assert_eq!(
        seen.lock().unwrap().count,
        2,
        "the disconnected stream and one follow-up reached the provider"
    );
}

/// Mixed scopes, anonymous caller: a route-level CONSUMER-scoped
/// budget cannot bind a request with no identity — the precedence walk
/// must CONTINUE past it (not abort) so the less-specific
/// policy-scoped (team) budget later in the chain still governs. An
/// early abort here would silently unlimit anonymous traffic on the
/// route.
#[tokio::test(flavor = "multi_thread")]
async fn anonymous_caller_binds_the_policy_budget_behind_a_consumer_scoped_one() {
    let (port, seen) = anthropic_mock(100, 100); // 200 tokens/request
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
         \x20 policies:\n\
         \x20 - route-budget\n\
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
         policies:\n\
         - name: route-budget\n\
         \x20 token_budget:\n\
         \x20   tokens_per_min: 1000000\n\
         - name: team-budget\n\
         \x20 token_budget:\n\
         \x20   tokens_per_min: 150\n\
         \x20   scope: policy\n\
         global_policies:\n\
         - team-budget\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: p\n\
         \x20   kind: anthropic\n\
         \x20   upstream: up\n\
         \x20 models:\n\
         \x20   chat:\n\
         \x20     provider: p\n\
         \x20     provider_model: claude-x\n"
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;

    // No credential presented (the route does not require one): the
    // consumer-scoped route budget is skipped and the GLOBAL team
    // budget (150/min) binds.
    let (s1, _, _, _) = ask_with(gw, None, false).await;
    assert_eq!(s1, StatusCode::OK);
    // The anonymous caller spent 200 into the SHARED team window: the
    // next anonymous pre-check denies BEFORE the provider. (With the
    // walk aborting at the consumer-scoped candidate, this request
    // would be unlimited and answer 200.)
    let (s2, body2, _, _) = ask_with(gw, None, false).await;
    assert_eq!(s2, StatusCode::TOO_MANY_REQUESTS);
    let v: Value = serde_json::from_slice(&body2).unwrap();
    assert_eq!(v["error"]["code"], "ai_budget_exceeded");
    assert_eq!(
        seen.lock().unwrap().count,
        1,
        "the denied anonymous request never reached the provider"
    );
}

/// Watermark monotonicity: a provider that REVISES a usage count
/// downward mid-stream never re-spends and never refunds — the ledger
/// holds the MAXIMUM reported total. The stream reports 200 input
/// tokens, revises them down to 100, then adds 50 output (final
/// reported total 150); the ledger must hold 200.
#[tokio::test(flavor = "multi_thread")]
async fn downward_usage_revision_never_respends_or_refunds() {
    let open = format!(
        "event: message_start\ndata: {}\n\nevent: content_block_delta\ndata: {}\n\n",
        json!({"type": "message_start", "message": {"usage": {"input_tokens": 200}}}),
        json!({"type": "content_block_delta", "index": 0,
               "delta": {"type": "text_delta", "text": "partial answer"}}),
    );
    // A second message_start revising the input count DOWNWARD (the
    // usage accumulator replaces reported fields; the budget's
    // watermark is what keeps the ledger monotonic).
    let revision = format!(
        "event: message_start\ndata: {}\n\n",
        json!({"type": "message_start", "message": {"usage": {"input_tokens": 100}}}),
    );
    let close = format!(
        "event: message_delta\ndata: {}\n\nevent: message_stop\ndata: {}\n\n",
        json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"},
               "usage": {"output_tokens": 50}}),
        json!({"type": "message_stop"}),
    );
    let (port, seen) = anthropic_mock_script(
        100,
        100, // non-streaming follow-ups spend 200 each
        vec![
            (std::time::Duration::ZERO, open),
            (std::time::Duration::from_millis(50), revision),
            (std::time::Duration::from_millis(50), close),
        ],
    );
    // Budget 400/min: the held max (200) leaves room for exactly one
    // 200-token follow-up. A re-spending implementation would already
    // sit over 400 after the stream; a refunding one (ledger revised
    // down to 150) would admit two.
    let dp = dataplane_from(&budget_yaml(
        port,
        "  token_budget:\n    tokens_per_min: 400\n",
        "consumer",
        false,
    ));
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    let (status, _bytes, frames, _) = ask(gw, "acme-key", true).await;
    assert_eq!(status, StatusCode::OK);
    let frames = frames.expect("a streamed response");
    assert!(
        !frames.iter().any(|f| f.contains("ai_budget_exceeded")),
        "the held max (200) is inside the window; no cutoff"
    );
    assert_eq!(frames.last().unwrap().trim(), "data: [DONE]");

    // Follow-up 1: the ledger holds 200 (the max), so 200 < 400 —
    // allowed, landing exactly at 400.
    let (s2, _, _, _) = ask(gw, "acme-key", false).await;
    assert_eq!(
        s2,
        StatusCode::OK,
        "the ledger holds the max (200), not 450 or 150"
    );
    // Follow-up 2: 400 >= 400 — denied before the provider.
    let (s3, body3, _, _) = ask(gw, "acme-key", false).await;
    assert_eq!(s3, StatusCode::TOO_MANY_REQUESTS);
    let v: Value = serde_json::from_slice(&body3).unwrap();
    assert_eq!(v["error"]["code"], "ai_budget_exceeded");
    assert_eq!(
        seen.lock().unwrap().count,
        2,
        "the stream and one follow-up reached the provider"
    );
}

/// A stream that STRADDLES an epoch-minute boundary spends into BOTH
/// windows: each tick's delta lands in the window the tick RAN in
/// (fixed epoch-minute semantics — there is no cross-window carry, no
/// reconciliation at close). Batch 1 (120 input tokens) is spent a few
/// seconds before a boundary; batch 2 (80 output) a few seconds after
/// it: the old minute holds 120, the new one holds 80. The observable
/// half is the new minute — a follow-up request is judged against 80
/// alone, where an implementation that dumps the whole stream into the
/// closing window (200 > 150) would both cut the stream off and 429
/// the follow-up. (The old minute's 120 rolls off with the boundary;
/// window-roll semantics are pinned in the unit suite.)
#[tokio::test(flavor = "multi_thread")]
async fn stream_spanning_a_minute_boundary_spends_into_both_windows() {
    let open = format!(
        "event: message_start\ndata: {}\n\nevent: content_block_delta\ndata: {}\n\n",
        json!({"type": "message_start", "message": {"usage": {"input_tokens": 120}}}),
        json!({"type": "content_block_delta", "index": 0,
               "delta": {"type": "text_delta", "text": "partial answer"}}),
    );
    let close = format!(
        "event: message_delta\ndata: {}\n\nevent: message_stop\ndata: {}\n\n",
        json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"},
               "usage": {"output_tokens": 80}}),
        json!({"type": "message_stop"}),
    );
    // Batch 2 lands ~2s AFTER the boundary the test aligns to (5s of
    // lead + 7s of scripted delay) — generous margins on loopback.
    let (port, seen) = anthropic_mock_script(
        100,
        100, // non-streaming follow-ups spend 200 each
        vec![
            (std::time::Duration::ZERO, open),
            (std::time::Duration::from_secs(7), close),
        ],
    );
    let dp = dataplane_from(&budget_yaml(
        port,
        "  token_budget:\n    tokens_per_min: 150\n",
        "consumer",
        false,
    ));
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    align_to_minute(5).await;
    let (status, _bytes, frames, _) = ask(gw, "acme-key", true).await;
    assert_eq!(status, StatusCode::OK);
    let frames = frames.expect("a streamed response");
    assert!(
        !frames.iter().any(|f| f.contains("ai_budget_exceeded")),
        "neither window ever holds more than 150: 120 before the \
         boundary, 80 after — a whole-stream-into-one-window spend \
         would cut off here"
    );
    assert_eq!(frames.last().unwrap().trim(), "data: [DONE]");

    // The NEW minute holds only the post-boundary delta (80): the
    // follow-up is admitted against it, spends 200, and the request
    // after that hits the 150 wall.
    let (s2, _, _, _) = ask(gw, "acme-key", false).await;
    assert_eq!(
        s2,
        StatusCode::OK,
        "the post-boundary window holds 80, not the stream's 200"
    );
    let (s3, body3, _, _) = ask(gw, "acme-key", false).await;
    assert_eq!(s3, StatusCode::TOO_MANY_REQUESTS);
    let v: Value = serde_json::from_slice(&body3).unwrap();
    assert_eq!(v["error"]["code"], "ai_budget_exceeded");
    assert_eq!(
        seen.lock().unwrap().count,
        2,
        "the stream and one follow-up reached the provider"
    );
}

/// Reload pruning: a budget holder REMOVED from the config has its
/// ledger entry pruned at refresh, so re-adding the holder later
/// starts from a clean window instead of the stale spend. (Two
/// reloads: only the removal prunes, but only the re-ADD makes it
/// observable — a removed key is never read again while it is gone.)
#[tokio::test(flavor = "multi_thread")]
async fn reload_prunes_removed_budget_holders_from_the_ledger() {
    let (port, seen) = anthropic_mock(100, 200); // 300 tokens/request
    let with_budget = budget_yaml(
        port,
        "  token_budget:\n    tokens_per_min: 250\n    scope: policy\n",
        "consumer",
        false,
    );
    let without_budget = budget_yaml(port, "", "consumer", false);
    let state = support::state_from(&with_budget);
    let dp = Arc::new(dwara_core::dataplane::proxy::DataPlane::new(Arc::clone(
        &state,
    )));
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    // Request 1 spends 300 into the team key ("ai-budget"): the next
    // pre-check would deny (300 >= 250).
    let (s1, _, _, _) = ask(gw, "acme-key", false).await;
    assert_eq!(s1, StatusCode::OK);

    // Reload 1 drops the budget (the key "ai-budget" is no longer
    // derivable — its windows are pruned); reload 2 restores it.
    for yaml in [without_budget.as_str(), with_budget.as_str()] {
        let gateway = dwara_core::config::parse_gateway(yaml).expect("reload config parses");
        state
            .compile_and_publish(&gateway)
            .expect("reload publishes");
        dp.refresh();
    }

    // With the pruning, the restored team budget starts from an EMPTY
    // window: this request is admitted (and spends 300, hitting the
    // wall for the one after). Without pruning the restored budget
    // would inherit the stale 300 and 429 here.
    let (s2, _, _, _) = ask(gw, "acme-key", false).await;
    assert_eq!(
        s2,
        StatusCode::OK,
        "the restored budget starts from a pruned ledger"
    );
    let (s3, body3, _, _) = ask(gw, "acme-key", false).await;
    assert_eq!(s3, StatusCode::TOO_MANY_REQUESTS);
    let v: Value = serde_json::from_slice(&body3).unwrap();
    assert_eq!(v["error"]["code"], "ai_budget_exceeded");
    assert_eq!(
        seen.lock().unwrap().count,
        2,
        "the two served requests reached the provider"
    );
}

/// Validation: empty budgets, zero fields.
#[test]
fn budget_validation_rejects_empty_and_zero() {
    use dwara_core::config::parse_gateway;
    use dwara_core::snapshot::validate;

    let base = |budget: &str| {
        format!(
            "allow_empty_routes: true\n\
             policies:\n\
             - name: b\n{budget}\
             ai:\n\
             \x20 providers:\n\
             \x20 - name: p\n\
             \x20   kind: openai\n\
             \x20   upstream: u\n\
             \x20 models:\n\
             \x20   chat:\n\
             \x20     provider: p\n\
             \x20     provider_model: m\n\
             upstreams:\n\
             - name: u\n\
             \x20 endpoints:\n\
             \x20   - address: 127.0.0.1\n\
             \x20     port: 9000\n"
        )
    };

    // Valid.
    let good = parse_yaml(&base("  token_budget:\n    tokens_per_min: 100\n"));
    assert!(validate(&good).is_empty(), "{:?}", validate(&good));

    // Empty budget block.
    let empty = parse_yaml(&base("  token_budget:\n    scope: consumer\n"));
    assert!(validate(&empty)
        .iter()
        .any(|i| i.field == "token_budget" && i.message.contains("bounds nothing")));

    // Zero tokens.
    let zero = parse_yaml(&base("  token_budget:\n    tokens_per_min: 0\n"));
    assert!(validate(&zero)
        .iter()
        .any(|i| i.field == "token_budget.tokens_per_min"));

    // Zero cost.
    let zc = parse_yaml(&base("  token_budget:\n    cost_per_day_micros: 0\n"));
    assert!(validate(&zc)
        .iter()
        .any(|i| i.field == "token_budget.cost_per_day_micros"));

    fn parse_yaml(y: &str) -> dwara_core::config::Gateway {
        parse_gateway(y).expect("fixture parses")
    }
}

/// The mock's streaming error type.
#[derive(Debug)]
struct ChanErr(String);

impl std::fmt::Display for ChanErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ChanErr {}

/// A hyper body backed by an mpsc channel.
struct ChanBody {
    rx: tokio::sync::mpsc::Receiver<Result<Bytes, ChanErr>>,
}

impl hyper::body::Body for ChanBody {
    type Data = Bytes;
    type Error = ChanErr;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, ChanErr>>> {
        let this = self.get_mut();
        match std::pin::Pin::new(&mut this.rx).poll_recv(cx) {
            std::task::Poll::Ready(Some(Ok(b))) => {
                std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(b))))
            }
            std::task::Poll::Ready(Some(Err(e))) => std::task::Poll::Ready(Some(Err(e))),
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}
