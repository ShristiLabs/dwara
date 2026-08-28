//! Alert & event webhooks, end to end (DW-044, feature analysis section
//! 5 "Platform"): the real emission points (breaker transitions,
//! endpoint ejection/recovery, config published/rejected) through the
//! real event bus and deliverer into a real local webhook receiver, plus
//! the failure-isolation pins:
//!
//! - a breaker opening under fault injection delivers `breaker_opened`
//!   (with the upstream label and the rule that tripped) while the
//!   dataplane keeps answering fail-fast 503s;
//! - passive-health ejection and recovery deliver
//!   `endpoint_ejected` / `endpoint_recovered` with both labels;
//! - the config publish pipeline delivers `config_published` and
//!   `config_rejected` (issue count; the running generation survives);
//! - a DEAD webhook target (connection refused) never affects the
//!   dataplane: requests complete, `/healthz` answers, retries stay
//!   bounded, and the failure lands in
//!   `dwara_webhook_events_total{outcome="failed"}`;
//! - a HUNG target is cut off by its per-delivery budget and does not
//!   stall the queue — the next event delivers to a target swapped in
//!   by a re-publish;
//! - secret-reference headers resolve (DW-045) and the POST shape is
//!   the documented envelope.
//!
//! The unit side (envelope bytes, bus drop policy, retry machinery
//! against scripted sinks, validation) lives in `tests/unit/webhooks.rs`.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dwara_core::config::parse_gateway;
use dwara_core::events::refresh_event_gauges;
use dwara_core::proxy::DataPlane;
use dwara_core::snapshot::ConfigState;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use tokio::sync::watch;

mod support;

use support::{dead_port, h1_client, spawn_backend, spawn_gateway, uri};

/// One captured webhook delivery.
#[derive(Clone, Debug)]
struct Hook {
    path: String,
    query: Option<String>,
    headers: hyper::HeaderMap,
    body: Bytes,
}

/// A webhook receiver: a local HTTP server capturing every delivery.
async fn spawn_hook_receiver() -> (u16, Arc<Mutex<Vec<Hook>>>) {
    let captured: Arc<Mutex<Vec<Hook>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&captured);
    let port = support::spawn_backend_async(move |req: Request<Incoming>| {
        let sink = Arc::clone(&sink);
        async move {
            let (parts, body) = req.into_parts();
            let bytes = body.collect().await.unwrap().to_bytes();
            sink.lock().unwrap().push(Hook {
                path: parts.uri.path().to_string(),
                query: parts.uri.query().map(|q| q.to_string()),
                headers: parts.headers.clone(),
                body: bytes,
            });
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
        }
    })
    .await;
    (port, captured)
}

/// Bounded poll until `n` deliveries are captured (never a bare sleep
/// as synchronization).
async fn wait_for_hooks(captured: &Arc<Mutex<Vec<Hook>>>, n: usize) -> Vec<Hook> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        {
            let hooks = captured.lock().unwrap();
            if hooks.len() >= n {
                return hooks.clone();
            }
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {n} webhook delivery(ies)"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Bounded poll until the rendered metrics contain the
/// `dwara_webhook_events_total` series for `kind`/`outcome`.
async fn wait_for_outcome(dp: &Arc<DataPlane>, kind: &str, outcome: &str) {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        refresh_event_gauges(dp.events(), dp.observability());
        let rendered = dp.observability().render();
        if rendered.lines().any(|l| {
            l.contains("dwara_webhook_events_total")
                && l.contains(&format!("kind=\"{kind}\""))
                && l.contains(&format!("outcome=\"{outcome}\""))
        }) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for dwara_webhook_events_total{{kind=\"{kind}\",\
             outcome=\"{outcome}\"}} in\n{rendered}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// The `gateway.webhooks` block for one target.
fn webhooks_yaml(url: &str, events: &str, extra: &str) -> String {
    format!("webhooks:\n- url: {url}\n  events: [{events}]\n{extra}")
}

/// Spawn the deliverer, keeping the shutdown sender ALIVE (a dropped
/// watch sender is itself the shutdown signal); abort + drop on return.
fn deliverer(dp: &Arc<DataPlane>) -> (tokio::task::JoinHandle<()>, watch::Sender<()>) {
    let (shutdown, rx) = watch::channel(());
    (dp.spawn_webhook_deliverer(rx), shutdown)
}

fn hook_json(hook: &Hook) -> serde_json::Value {
    serde_json::from_slice(&hook.body).expect("the delivery body is the JSON envelope")
}

// --- 1. breaker open under fault injection --------------------------------

#[tokio::test]
async fn breaker_open_under_fault_injection_delivers_the_event() {
    // First 3 requests fail with 500; everything after succeeds.
    let (backend, _count) = spawn_backend(
        |n, _m, _p, _b| {
            if n <= 3 {
                status(500)
            } else {
                status(200)
            }
        },
        Duration::ZERO,
    )
    .await;
    let (hook_port, captured) = spawn_hook_receiver().await;
    let yaml = support::gateway_yaml(
        &webhooks_yaml(
            &format!("http://127.0.0.1:{hook_port}/hook"),
            "breaker_opened",
            "  timeout_ms: 1000\n",
        ),
        backend,
        None,
        "  breaker:\n    consecutive_failures: 3\n    open_ms: 60000\n",
    );
    let dp = support::dataplane_from(&yaml);
    let (deliverer, _shutdown) = deliverer(&dp);
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();

    let started = Instant::now();
    for _ in 0..3 {
        let (status, _) = support::body_of(client.get(uri(gw, "/api/x")).await.unwrap()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }
    // The breaker opens ON the third failure: the 4th request fails fast.
    let (status, body) = support::body_of(client.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(support::envelope_code(&body), "upstream_circuit_open");

    let hooks = wait_for_hooks(&captured, 1).await;
    assert_eq!(hooks.len(), 1, "exactly one delivery for one transition");
    let json = hook_json(&hooks[0]);
    assert_eq!(json["kind"], "breaker_opened");
    assert_eq!(json["payload"]["upstream"], "up");
    assert_eq!(json["payload"]["detail"], "consecutive_failures");
    assert!(json["id"].as_str().unwrap().starts_with("evt-"));
    assert!(json["gateway"].as_str().unwrap().starts_with("dwara-"));
    assert!(
        json["timestamp"].as_str().unwrap().ends_with('Z'),
        "RFC 3339 UTC timestamp: {}",
        json["timestamp"]
    );

    // The event is counted on the bus even though the queue drained.
    refresh_event_gauges(dp.events(), dp.observability());
    let rendered = dp.observability().render();
    assert!(
        rendered.contains("dwara_events_emitted_total"),
        "{rendered}"
    );

    // The webhook machinery added nothing to the request path.
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "webhook delivery never gates the dataplane: {:?}",
        started.elapsed()
    );
    deliverer.abort();
}

fn status(code: u16) -> Response<Full<Bytes>> {
    Response::builder()
        .status(code)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

// --- 2. endpoint ejection and recovery ------------------------------------

#[tokio::test]
async fn ejection_and_recovery_deliver_both_events() {
    // Two failures eject the only endpoint; the next request rides the
    // all-ejected fail-open path, succeeds, and recovers the endpoint.
    let (backend, _count) = spawn_backend(
        |n, _m, _p, _b| {
            if n <= 2 {
                status(500)
            } else {
                status(200)
            }
        },
        Duration::ZERO,
    )
    .await;
    let (hook_port, captured) = spawn_hook_receiver().await;
    let yaml = support::gateway_yaml(
        &webhooks_yaml(
            &format!("http://127.0.0.1:{hook_port}/hook"),
            "endpoint_ejected, endpoint_recovered",
            "",
        ),
        backend,
        None,
        "  health:\n    consecutive_failures: 2\n    eject_ms: 30000\n",
    );
    let dp = support::dataplane_from(&yaml);
    let (deliverer, _shutdown) = deliverer(&dp);
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();

    for _ in 0..2 {
        let (status, _) = support::body_of(client.get(uri(gw, "/api/x")).await.unwrap()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }
    let hooks = wait_for_hooks(&captured, 1).await;
    assert_eq!(hook_json(&hooks[0])["kind"], "endpoint_ejected");
    assert_eq!(
        hook_json(&hooks[0])["payload"]["endpoint"],
        format!("127.0.0.1:{backend}"),
        "the payload names the endpoint"
    );
    assert_eq!(hook_json(&hooks[0])["payload"]["upstream"], "up");

    // Fail-open pick reaches the ejected endpoint, succeeds, recovers it.
    let (status, _) = support::body_of(client.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "fail-open traffic reaches the pool");
    let hooks = wait_for_hooks(&captured, 2).await;
    assert_eq!(hook_json(&hooks[1])["kind"], "endpoint_recovered");
    assert_eq!(
        hook_json(&hooks[1])["payload"]["endpoint"],
        format!("127.0.0.1:{backend}")
    );
    deliverer.abort();
}

// --- 3. config published / rejected ---------------------------------------

#[tokio::test]
async fn config_publish_and_rejection_both_deliver() {
    let (backend, _count) = spawn_backend(|_n, _m, _p, _b| status(200), Duration::ZERO).await;
    let (hook_port, captured) = spawn_hook_receiver().await;
    let webhooks = webhooks_yaml(
        &format!("http://127.0.0.1:{hook_port}/hook"),
        "config_published, config_rejected",
        "",
    );
    let good = support::gateway_yaml(&webhooks, backend, None, "");

    // The dataplane exists BEFORE the first publish so its deliverer and
    // target watch are live; the initial generation is the empty one.
    let state = Arc::new(ConfigState::new());
    let dp = DataPlane::new(Arc::clone(&state));
    state
        .compile_and_publish(&parse_gateway(&good).unwrap())
        .expect("first publish");
    dp.refresh();
    let (deliverer, _shutdown) = deliverer(&dp);

    // The queued startup publish (generation 1) is the FIRST delivery:
    // the bus existed before that publish, so the deliverer drains it
    // even though it spawned later.
    let hooks = wait_for_hooks(&captured, 1).await;
    assert_eq!(hook_json(&hooks[0])["kind"], "config_published");
    assert_eq!(hook_json(&hooks[0])["payload"]["generation"], 1);

    // Publish #2: valid (compile_and_publish publishes every call; the
    // generation is the observable difference), delivered as
    // config_published.
    let info = state
        .compile_and_publish(&parse_gateway(&good).unwrap())
        .expect("second publish");
    let hooks = wait_for_hooks(&captured, 2).await;
    let json = hook_json(&hooks[1]);
    assert_eq!(json["kind"], "config_published");
    assert_eq!(json["payload"]["generation"], info.generation);
    assert_eq!(json["payload"]["route_count"], 1);

    // Publish #3: invalid (unknown service reference) — rejected, the
    // running generation survives, and the event carries the issue count.
    let bad = support::gateway_yaml(&webhooks, backend, None, "")
        .replace("  service: svc", "  service: missing");
    let before = state.snapshot().generation();
    state
        .compile_and_publish(&parse_gateway(&bad).unwrap())
        .expect_err("invalid config is rejected");
    assert_eq!(state.snapshot().generation(), before, "generation kept");
    let hooks = wait_for_hooks(&captured, 3).await;
    let json = hook_json(&hooks[2]);
    assert_eq!(json["kind"], "config_rejected");
    assert_eq!(json["payload"]["issue_count"], 1);
    assert_eq!(json["payload"]["generation"], before);
    deliverer.abort();
}

// --- 4. dead webhook target -------------------------------------------------

#[tokio::test]
async fn a_dead_webhook_never_touches_the_dataplane_and_fails_loudly() {
    let (backend, _count) = spawn_backend(
        |n, _m, _p, _b| {
            if n <= 3 {
                status(500)
            } else {
                status(200)
            }
        },
        Duration::ZERO,
    )
    .await;
    // Nothing listens here: every connect is refused instantly.
    let dead = dead_port();
    let yaml = support::gateway_yaml(
        &webhooks_yaml(
            &format!("http://127.0.0.1:{dead}/hook"),
            "breaker_opened",
            "  timeout_ms: 1000\n",
        ),
        backend,
        None,
        "  breaker:\n    consecutive_failures: 3\n    open_ms: 60000\n",
    );
    let dp = support::dataplane_from(&yaml);
    let (deliverer, _shutdown) = deliverer(&dp);
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();

    // Open the breaker (the event's retries all hit the dead port).
    let started = Instant::now();
    for _ in 0..4 {
        let _ = client.get(uri(gw, "/api/x")).await.unwrap();
    }
    // The dataplane is unaffected: the reserved liveness path answers
    // while deliveries are failing.
    let (health, _) = support::body_of(client.get(uri(gw, "/healthz")).await.unwrap()).await;
    assert_eq!(health, StatusCode::OK);
    let (ready, _) = support::body_of(client.get(uri(gw, "/readyz")).await.unwrap()).await;
    assert_eq!(ready, StatusCode::OK);

    // Retries are bounded (3 attempts against instant refusals + backoff
    // land well under the per-delivery budget).
    wait_for_outcome(&dp, "breaker_opened", "failed").await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "bounded retries: {:?}",
        started.elapsed()
    );
    deliverer.abort();
}

// --- 5. hung target: budget + queue not stalled ------------------------------

#[tokio::test]
async fn a_hung_target_times_out_and_does_not_stall_the_queue() {
    let (backend, _count) = spawn_backend(
        |n, _m, _p, _b| {
            if n <= 3 {
                status(500)
            } else {
                status(200)
            }
        },
        Duration::ZERO,
    )
    .await;
    // Accepts connections and never answers.
    let hung = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hung_port = hung.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = hung.accept().await {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(stream);
            });
        }
    });
    let (hook_port, captured) = spawn_hook_receiver().await;
    let yaml = support::gateway_yaml(
        &webhooks_yaml(
            &format!("http://127.0.0.1:{hung_port}/hook"),
            "breaker_opened, config_published",
            "  timeout_ms: 300\n",
        ),
        backend,
        None,
        "  breaker:\n    consecutive_failures: 3\n    open_ms: 60000\n",
    );
    let state = Arc::new(ConfigState::new());
    let dp = DataPlane::new(Arc::clone(&state));
    state
        .compile_and_publish(&parse_gateway(&yaml).unwrap())
        .unwrap();
    dp.refresh();
    let (deliverer, _shutdown) = deliverer(&dp);
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();

    // Open the breaker: the delivery hangs into its 300ms budget, then
    // fails — the dataplane never noticed.
    for _ in 0..4 {
        let _ = client.get(uri(gw, "/api/x")).await.unwrap();
    }
    let started = Instant::now();
    wait_for_outcome(&dp, "breaker_opened", "failed").await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the per-delivery budget bounds a hung target: {:?}",
        started.elapsed()
    );

    // The queue is NOT stalled: re-publish with a healthy target (the
    // watch updates on refresh) — the publish's OWN event must arrive.
    let healthy = support::gateway_yaml(
        &webhooks_yaml(
            &format!("http://127.0.0.1:{hook_port}/hook"),
            "breaker_opened, config_published",
            "  timeout_ms: 1000\n",
        ),
        backend,
        None,
        "  breaker:\n    consecutive_failures: 3\n    open_ms: 60000\n",
    );
    let info = state
        .compile_and_publish(&parse_gateway(&healthy).unwrap())
        .unwrap();
    dp.refresh();
    let hooks = wait_for_hooks(&captured, 1).await;
    let json = hook_json(&hooks[0]);
    assert_eq!(json["kind"], "config_published");
    assert_eq!(json["payload"]["generation"], info.generation);
    deliverer.abort();
}

// --- 6. secret-reference headers + POST shape -------------------------------

#[tokio::test]
async fn secret_reference_headers_resolve_and_the_post_shape_is_the_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let token_path = dir.path().join("token");
    std::fs::write(&token_path, "tok-1234567890\n").unwrap();
    let (backend, _count) = spawn_backend(|_n, _m, _p, _b| status(200), Duration::ZERO).await;
    let (hook_port, captured) = spawn_hook_receiver().await;
    let webhooks = webhooks_yaml(
        &format!("http://127.0.0.1:{hook_port}/hook?topic=alerts"),
        "config_published",
        &format!(
            "  headers:\n    X-Hook-Token: ${{file:{}}}\n",
            token_path.display()
        ),
    );
    let yaml = support::gateway_yaml(&webhooks, backend, None, "");
    let state = Arc::new(ConfigState::new());
    let dp = DataPlane::new(Arc::clone(&state));
    state
        .compile_and_publish(&parse_gateway(&yaml).unwrap())
        .unwrap();
    dp.refresh();
    let (deliverer, _shutdown) = deliverer(&dp);
    // Any publish emits; one is enough here.
    state
        .compile_and_publish(&parse_gateway(&yaml).unwrap())
        .unwrap();

    let hooks = wait_for_hooks(&captured, 1).await;
    let hook = &hooks[0];
    assert_eq!(hook.path, "/hook", "path preserved from the URL");
    assert_eq!(hook.query.as_deref(), Some("topic=alerts"));
    // The DW-045 file reference resolved at compile time (one trailing
    // newline trimmed) and reached the receiver.
    assert_eq!(
        hook.headers.get("x-hook-token").unwrap(),
        "tok-1234567890",
        "the secret reference resolved into the delivered header"
    );
    assert_eq!(
        hook.headers.get("content-type").unwrap(),
        "application/json"
    );
    assert_eq!(hook.headers.get("user-agent").unwrap(), "dwara-webhook");
    assert_eq!(
        hook.headers.get("content-length").unwrap(),
        hook.body.len().to_string().as_str()
    );
    assert_eq!(hook_json(hook)["kind"], "config_published");
    deliverer.abort();
}
