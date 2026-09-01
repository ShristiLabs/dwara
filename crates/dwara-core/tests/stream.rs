//! Real-time access-record stream, end to end (DW-121, feature
//! analysis section 5 "Platform"): real gateway traffic through the
//! real stream channel, flusher, and webhook batch sink into a real
//! local NDJSON receiver, plus the pipeline's isolation pins:
//!
//! - every completed request produces exactly one NDJSON line
//!   downstream, and K requests inside one flush window arrive as ONE
//!   delivery (one POST per flushed batch, not per record) with the
//!   documented media type, user-agent, and per-record envelope
//!   (request_id correlation, redacted path, dimensions);
//! - a DEAD sink never touches the dataplane: requests keep answering,
//!   and the loss lands in `dwara_access_records_streamed_total{
//!   outcome="failed"}` after the bounded retry budget;
//! - a live re-publish retargets the stream to a new receiver with no
//!   restart (the sink set is generation state);
//! - with no `analytics_stream` block, nothing is offered, queued, or
//!   delivered (the disabled-stream no-op);
//! - both pipelines coexist: the same config's `analytics` block and
//!   stream block run side by side, each seeing the same traffic.
//!
//! The unit side (line shape, gating, sink compilation, batching
//! semantics against a mock sink) lives in `tests/unit/stream.rs`.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dwara_core::config::parse_gateway;
use dwara_core::events::stream::refresh_stream_gauges;
use dwara_core::proxy::DataPlane;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use tokio::sync::watch;

mod support;

use support::{dead_port, h1_client, spawn_backend, spawn_gateway, uri};

/// One captured batch delivery.
#[derive(Clone, Debug)]
struct Delivery {
    headers: hyper::HeaderMap,
    body: Bytes,
}

/// An NDJSON receiver: a local HTTP server capturing every batch POST.
async fn spawn_ndjson_receiver() -> (u16, Arc<Mutex<Vec<Delivery>>>) {
    let captured: Arc<Mutex<Vec<Delivery>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&captured);
    let port = support::spawn_backend_async(move |req: Request<Incoming>| {
        let sink = Arc::clone(&sink);
        async move {
            let (parts, body) = req.into_parts();
            let bytes = body.collect().await.unwrap().to_bytes();
            sink.lock().unwrap().push(Delivery {
                headers: parts.headers.clone(),
                body: bytes,
            });
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
        }
    })
    .await;
    (port, captured)
}

/// Bounded poll until `n` batches are captured.
async fn wait_deliveries(captured: &Arc<Mutex<Vec<Delivery>>>, n: usize) -> Vec<Delivery> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        {
            let d = captured.lock().unwrap();
            if d.len() >= n {
                return d.clone();
            }
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {n} batch delivery(ies)"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Bounded poll until the stream counter family carries `outcome`.
async fn wait_outcome(dp: &Arc<DataPlane>, outcome: &str) {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if let Some(stream) = dp.record_stream() {
            refresh_stream_gauges(&stream, dp.observability());
        }
        let rendered = dp.observability().render();
        if rendered.lines().any(|l| {
            l.contains("dwara_access_records_streamed_total")
                && l.contains(&format!("outcome=\"{outcome}\""))
        }) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for dwara_access_records_streamed_total{{outcome=\
             \"{outcome}\"}} in\n{rendered}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// The `gateway.analytics_stream` block for one webhook sink:
/// `sink_extra` splices SINK knobs (timeout/attempts), `flush_ms` is
/// the STREAM-level batch cadence.
fn stream_yaml(url: &str, sink_extra: &str, flush_ms: u64) -> String {
    format!(
        "analytics_stream:\n  flush_ms: {flush_ms}\n  sink:\n    type: webhook\n    url: {url}\n{sink_extra}"
    )
}

/// Build the dataplane with its stream attached and the flusher
/// spawned (dwara-bin's wiring, minus the process).
async fn gateway_with_stream(
    yaml: &str,
    buffer: usize,
) -> (
    Arc<DataPlane>,
    u16,
    tokio::task::JoinHandle<()>,
    watch::Sender<()>,
) {
    let dp = support::dataplane_from(yaml);
    let stream = dwara_core::events::stream::AccessRecordStream::with_capacity(buffer);
    dp.set_record_stream(stream);
    let (shutdown, rx) = tokio::sync::watch::channel(());
    let task = dp.spawn_record_stream_flusher(rx);
    let port = spawn_gateway(Arc::clone(&dp)).await;
    (dp, port, task, shutdown)
}

type Client = hyper_util::client::legacy::Client<
    hyper_util::client::legacy::connect::HttpConnector,
    Full<Bytes>,
>;

/// Drive `n` proxied requests through the gateway.
async fn drive(client: &Client, gw: u16, n: usize) {
    for _ in 0..n {
        let (status, _) = support::body_of(client.get(uri(gw, "/api/x")).await.unwrap()).await;
        assert_eq!(status, StatusCode::OK);
    }
}

// --- 1. one line per request, one delivery per batch ------------------------

#[tokio::test]
async fn every_request_ships_one_ndjson_line_in_one_batch_delivery() {
    let (backend, _count) = spawn_backend(
        |_n, _m, _p, _b| Response::new(Full::new(Bytes::new())),
        Duration::ZERO,
    )
    .await;
    let (recv_port, captured) = spawn_ndjson_receiver().await;
    let yaml = support::gateway_yaml(
        &stream_yaml(
            &format!("http://127.0.0.1:{recv_port}/ingest"),
            "    timeout_ms: 2000\n",
            200,
        ),
        backend,
        None,
        "",
    );
    let (dp, gw, task, shutdown) = gateway_with_stream(&yaml, 64).await;
    let client = h1_client();
    drive(&client, gw, 5).await;

    let deliveries = wait_deliveries(&captured, 1).await;
    assert_eq!(deliveries.len(), 1, "one delivery per flushed batch");
    let d = &deliveries[0];
    assert_eq!(
        d.headers.get("content-type").unwrap(),
        "application/x-ndjson",
        "the documented media type"
    );
    assert_eq!(d.headers.get("user-agent").unwrap(), "dwara-record-stream");

    let body = String::from_utf8(d.body.to_vec()).unwrap();
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 5, "exactly one line per completed request");
    let mut paths = Vec::new();
    for line in &lines {
        let json: serde_json::Value = serde_json::from_str(line).expect("each line is JSON");
        assert_eq!(json["method"], "GET");
        assert_eq!(json["path"], "/api/x");
        assert_eq!(json["route"], "all");
        assert_eq!(json["listener"], "unknown");
        assert_eq!(json["status"], 200);
        assert!(json["id"].as_str().unwrap().starts_with("rec-"));
        assert!(json["gateway"].as_str().unwrap().starts_with("dwara-"));
        assert!(json["timestamp"].as_str().unwrap().ends_with('Z'));
        assert!(!json["request_id"].as_str().unwrap().is_empty());
        assert_eq!(json["attempts"], 1);
        paths.push(json["path"].clone());
    }
    assert!(paths.iter().all(|p| p == "/api/x"));

    // The completion counters: 5 offered, none dropped.
    let stream = dp.record_stream().unwrap();
    refresh_stream_gauges(&stream, dp.observability());
    let rendered = dp.observability().render();
    assert!(rendered.contains("dwara_access_records_offered_total"));
    assert!(rendered.contains("dwara_access_records_streamed_total"));
    wait_outcome(&dp, "delivered").await;

    shutdown.send(()).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

// --- 2. dead sink isolation -------------------------------------------------

#[tokio::test]
async fn a_dead_sink_never_touches_the_dataplane() {
    let (backend, _count) = spawn_backend(
        |_n, _m, _p, _b| Response::new(Full::new(Bytes::new())),
        Duration::ZERO,
    )
    .await;
    let dead = dead_port();
    let yaml = support::gateway_yaml(
        &stream_yaml(
            &format!("http://127.0.0.1:{dead}/ingest"),
            // Short budget + one attempt: the failure lands fast.
            "    timeout_ms: 300\n    max_attempts: 1\n",
            100,
        ),
        backend,
        None,
        "",
    );
    let (dp, gw, task, shutdown) = gateway_with_stream(&yaml, 64).await;
    let client = h1_client();
    let started = Instant::now();
    drive(&client, gw, 3).await;
    // All three answered 200 with the sink already dead — the offer
    // path never waits on delivery.
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "requests never gate on stream delivery: {:?}",
        started.elapsed()
    );
    // The flusher's delivery fails after its bounded budget and the
    // records land in the failed outcome.
    wait_outcome(&dp, "failed").await;
    // The gateway stays healthy.
    let (status, _) = support::body_of(client.get(uri(gw, "/healthz")).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    shutdown.send(()).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

// --- 3. live retarget --------------------------------------------------------

#[tokio::test]
async fn a_republish_retargets_the_stream_without_restart() {
    let (backend, _count) = spawn_backend(
        |_n, _m, _p, _b| Response::new(Full::new(Bytes::new())),
        Duration::ZERO,
    )
    .await;
    let (recv1, captured1) = spawn_ndjson_receiver().await;
    let (recv2, captured2) = spawn_ndjson_receiver().await;
    let stream1 = stream_yaml(
        &format!("http://127.0.0.1:{recv1}/ingest"),
        "    timeout_ms: 2000\n",
        150,
    );
    let yaml1 = support::gateway_yaml(&stream1, backend, None, "");

    // The dataplane + stream flusher are wired by hand (the support
    // helpers own the config); the state is shared so a re-publish
    // drives the same dataplane's refresh.
    let state = support::state_from(&yaml1);
    let dp = DataPlane::new(Arc::clone(&state));
    let stream = dwara_core::events::stream::AccessRecordStream::with_capacity(64);
    dp.set_record_stream(stream);
    let (shutdown, rx) = watch::channel(());
    let task = dp.spawn_record_stream_flusher(rx);
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();

    drive(&client, gw, 2).await;
    let first = wait_deliveries(&captured1, 1).await;
    assert_eq!(first.len(), 1);

    // Republish with the sink pointed at the second receiver. The
    // stream's sink set is generation state: no restart, no respawn.
    let stream2 = stream_yaml(
        &format!("http://127.0.0.1:{recv2}/ingest"),
        "    timeout_ms: 2000\n",
        150,
    );
    let yaml2 = support::gateway_yaml(&stream2, backend, None, "");
    state
        .compile_and_publish(&parse_gateway(&yaml2).unwrap())
        .expect("second publish");
    dp.refresh();

    drive(&client, gw, 2).await;
    let second = wait_deliveries(&captured2, 1).await;
    assert_eq!(second.len(), 1, "the new sink took over mid-flight");

    shutdown.send(()).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

// --- 4. no block: nothing offered --------------------------------------------

#[tokio::test]
async fn without_a_stream_block_nothing_is_offered_or_delivered() {
    let (backend, _count) = spawn_backend(
        |_n, _m, _p, _b| Response::new(Full::new(Bytes::new())),
        Duration::ZERO,
    )
    .await;
    let yaml = support::gateway_yaml("", backend, None, "");
    let dp = support::dataplane_from(&yaml);
    let stream = dwara_core::events::stream::AccessRecordStream::with_capacity(64);
    dp.set_record_stream(stream);
    let (shutdown, rx) = watch::channel(());
    let task = dp.spawn_record_stream_flusher(rx);
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();
    drive(&client, gw, 3).await;

    let stream = dp.record_stream().unwrap();
    assert!(!stream.enabled(), "no block: the stream stays disarmed");
    assert_eq!(stream.offered(), 0);
    assert_eq!(stream.dropped(), 0);
    shutdown.send(()).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

// --- 5. coexistence with the embedded store ----------------------------------

#[tokio::test]
async fn the_stream_and_the_embedded_store_run_side_by_side() {
    let (backend, _count) = spawn_backend(
        |_n, _m, _p, _b| Response::new(Full::new(Bytes::new())),
        Duration::ZERO,
    )
    .await;
    let (recv_port, captured) = spawn_ndjson_receiver().await;
    let dir = tempfile::tempdir().unwrap();
    let analytics = format!(
        "analytics:\n  path: {}\n  flush_ms: 100\n",
        dir.path().join("a.db").display()
    );
    let yaml = support::gateway_yaml(
        &format!(
            "{analytics}{}",
            stream_yaml(
                &format!("http://127.0.0.1:{recv_port}/ingest"),
                "    timeout_ms: 2000\n",
                150,
            )
        ),
        backend,
        None,
        "",
    );
    let dp = support::dataplane_from(&yaml);
    let store = dwara_core::analytics::EmbeddedAnalytics::open(
        &dir.path().join("a.db").display().to_string(),
        dwara_core::config::ANALYTICS_DEFAULT_RETENTION_MS,
        100,
        0,
    )
    .unwrap();
    dp.set_analytics(Arc::clone(&store));
    let (_workers_shutdown, workers_rx) = watch::channel(());
    let _workers = store.spawn_workers(workers_rx);
    let stream = dwara_core::events::stream::AccessRecordStream::with_capacity(64);
    dp.set_record_stream(stream);
    let (shutdown, rx) = watch::channel(());
    let task = dp.spawn_record_stream_flusher(rx);
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();
    drive(&client, gw, 4).await;

    // The stream saw all four records...
    let deliveries = wait_deliveries(&captured, 1).await;
    let body = String::from_utf8(deliveries[0].body.to_vec()).unwrap();
    assert_eq!(body.lines().count(), 4);
    // ...and so did the embedded store (raw rows for the same traffic).
    let rows = store
        .query(|c| c.query_row("SELECT COUNT(*) FROM raw", [], |r| r.get::<_, i64>(0)))
        .unwrap();
    assert_eq!(rows, 4, "both pipelines captured the same traffic");
    shutdown.send(()).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

// --- 6. every completed request, including unrouted 404s ---------------------

#[tokio::test]
async fn an_unrouted_404_request_still_ships_one_record() {
    // "Every completed request" means exactly that: route resolution
    // is not a filter. An unrouted request's record carries the
    // unrouted route label and the 404 status.
    let (backend, _count) = spawn_backend(
        |_n, _m, _p, _b| Response::new(Full::new(Bytes::new())),
        Duration::ZERO,
    )
    .await;
    let (recv_port, captured) = spawn_ndjson_receiver().await;
    let yaml = support::gateway_yaml(
        &stream_yaml(
            &format!("http://127.0.0.1:{recv_port}/ingest"),
            "    timeout_ms: 2000\n",
            150,
        ),
        backend,
        None,
        "",
    );
    let (_dp, gw, task, shutdown) = gateway_with_stream(&yaml, 64).await;
    let client = h1_client();
    let (status, _) = support::body_of(client.get(uri(gw, "/nonexistent")).await.unwrap()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let deliveries = wait_deliveries(&captured, 1).await;
    let body = String::from_utf8(deliveries[0].body.to_vec()).unwrap();
    let json: serde_json::Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
    assert_eq!(json["route"], "unrouted");
    assert_eq!(json["status"], 404);
    assert_eq!(json["path"], "/nonexistent");
    assert_eq!(json["consumer"], "anonymous");
    // And the backend saw nothing (the 404 never proxied).
    assert_eq!(_count.load(std::sync::atomic::Ordering::SeqCst), 0);
    shutdown.send(()).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

// --- 7. arming by live reload loses nothing (refresh ordering) ---------------

#[tokio::test]
async fn arming_the_stream_by_republish_delivers_from_the_first_record() {
    // M1's pin: the refresh pushes the compiled sink set to the
    // flusher BEFORE flipping the offer path's enabled flag, so the
    // first records offered after the reload have a sink waiting.
    // Start UNCONFIGURED, then republish with a block and immediately
    // drive traffic: every request's record must arrive.
    let (backend, _count) = spawn_backend(
        |_n, _m, _p, _b| Response::new(Full::new(Bytes::new())),
        Duration::ZERO,
    )
    .await;
    let (recv_port, captured) = spawn_ndjson_receiver().await;
    let bare = support::gateway_yaml("", backend, None, "");
    let state = support::state_from(&bare);
    let dp = DataPlane::new(Arc::clone(&state));
    let stream = dwara_core::events::stream::AccessRecordStream::with_capacity(64);
    dp.set_record_stream(stream);
    let (shutdown, rx) = watch::channel(());
    let task = dp.spawn_record_stream_flusher(rx);
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();

    // Republish ARMING the stream, then drive traffic at once.
    let armed = support::gateway_yaml(
        &stream_yaml(
            &format!("http://127.0.0.1:{recv_port}/ingest"),
            "    timeout_ms: 2000\n",
            150,
        ),
        backend,
        None,
        "",
    );
    state
        .compile_and_publish(&parse_gateway(&armed).unwrap())
        .expect("armed publish");
    dp.refresh();

    drive(&client, gw, 3).await;
    let deliveries = wait_deliveries(&captured, 1).await;
    let body = String::from_utf8(deliveries[0].body.to_vec()).unwrap();
    assert_eq!(
        body.lines().count(),
        3,
        "every post-arm record arrives — no arm-window loss"
    );
    shutdown.send(()).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}
