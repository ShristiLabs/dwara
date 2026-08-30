//! Unit tests for the access-record stream (DW-121): the NDJSON line
//! shape and its redaction contract, identity assignment, the
//! offer-path gating and drop accounting, sink compilation (shared
//! endpoint grammar, secret-reference headers, fail-closed), and the
//! flusher's batching semantics (record-count trigger, cadence tick,
//! strict ordering, per-record byte cap) against a capturing mock
//! sink. The end-to-end pin (request -> batch delivered to a real
//! HTTP receiver, dead-sink isolation, live retarget) lives in
//! `tests/stream.rs`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use dwara_core::config::{AnalyticsStreamConfig, AnalyticsStreamSink, AnalyticsStreamWebhook};
use dwara_core::events::stream::{
    compile_stream_targets, AccessRecordStream, RecordSink, StreamRecord, StreamTargets,
    MAX_RECORD_BYTES,
};
use dwara_core::observability::{AccessRecord, Observability};
use tokio::sync::watch;

// --- helpers --------------------------------------------------------------

fn access_record(path: &str) -> AccessRecord {
    let mut rec = AccessRecord::new(
        "req-test-000001".to_string(),
        "GET".to_string(),
        path.to_string(),
        "edge".to_string(),
    );
    rec.route = "billing".to_string();
    rec.consumer = "acme".to_string();
    rec.upstream = Some("billing-v1".to_string());
    rec.endpoint = Some("10.0.0.4:8443".to_string());
    rec.attempts = 1;
    rec.status = 200;
    rec.duration_ms = 4.2;
    rec.custom.push(("plan".to_string(), "gold".to_string()));
    rec
}

fn stream_record(path: &str) -> StreamRecord {
    StreamRecord::from_access(
        &access_record(path),
        "rec-00000000-000001".to_string(),
        Arc::from("dwara-test"),
        784_111_777_012,
    )
}

fn webhook_sink_cfg(url: &str) -> AnalyticsStreamConfig {
    AnalyticsStreamConfig {
        sink: AnalyticsStreamSink::Webhook(AnalyticsStreamWebhook {
            url: url.to_string(),
            headers: Default::default(),
            timeout_ms: 2000,
            max_attempts: 3,
            backoff_base_ms: 100,
            backoff_cap_ms: 1000,
        }),
        buffer: None,
        flush_ms: None,
        batch_max: None,
    }
}

/// A capturing mock sink: records every batch's (body, record count)
/// and optionally stalls the first delivery to prove the flusher's
/// inline-order model (later batches wait behind it) without any real
/// network.
#[derive(Default)]
struct MockSink {
    batches: Mutex<Vec<(Bytes, usize)>>,
}

#[async_trait::async_trait]
impl RecordSink for MockSink {
    async fn deliver_batch(&self, batch: Bytes, records: usize) -> bool {
        self.batches.lock().unwrap().push((batch, records));
        true
    }
}

/// Drive the flusher against a mock sink: returns the sink, a target
/// sender (tests retarget live), and the task handle. The shutdown
/// sender stays alive for the test's duration.
async fn flusher_with(
    batch_max: usize,
    flush_ms: u64,
) -> (
    Arc<MockSink>,
    watch::Sender<StreamTargets>,
    Arc<AccessRecordStream>,
    tokio::task::JoinHandle<()>,
    watch::Sender<()>,
    Arc<Observability>,
) {
    let stream = AccessRecordStream::with_capacity(64);
    stream.set_enabled(true);
    let rx = stream.take_receiver().unwrap();
    let sink = Arc::new(MockSink::default());
    let targets = StreamTargets {
        sinks: vec![Arc::clone(&sink) as Arc<dyn RecordSink>],
        flush_ms,
        batch_max,
    };
    let (tx, watch_rx) = watch::channel(targets);
    let (shutdown, shutdown_rx) = watch::channel(());
    let obs = Arc::new(Observability::new());
    let task = tokio::spawn(dwara_core::events::stream::run_stream_flusher(
        rx,
        watch_rx,
        Arc::clone(&obs),
        shutdown_rx,
    ));
    (sink, tx, stream, task, shutdown, obs)
}

/// Bounded poll until the mock captured `n` batches.
async fn wait_batches(sink: &Arc<MockSink>, n: usize) -> Vec<(Bytes, usize)> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        {
            let b = sink.batches.lock().unwrap();
            if b.len() >= n {
                return b.clone();
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {n} batch(es)"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// --- line shape ------------------------------------------------------------

#[test]
fn the_line_is_one_ndjson_object_with_the_redacted_field_set() {
    let line = stream_record("/v1/invoices").line();
    assert!(line.ends_with('\n'), "one NDJSON line, newline-terminated");
    let json: serde_json::Value =
        serde_json::from_str(line.trim_end()).expect("the line is one JSON object");
    assert_eq!(json["id"], "rec-00000000-000001");
    assert_eq!(json["gateway"], "dwara-test");
    assert_eq!(
        json["timestamp"], "1994-11-06T08:49:37.012Z",
        "RFC 3339 UTC, millisecond precision (784_111_777_012 ms)"
    );
    assert_eq!(json["request_id"], "req-test-000001");
    assert_eq!(json["listener"], "edge");
    assert_eq!(json["route"], "billing");
    assert_eq!(json["consumer"], "acme");
    assert_eq!(json["upstream"], "billing-v1");
    assert_eq!(json["endpoint"], "10.0.0.4:8443");
    assert_eq!(json["method"], "GET");
    assert_eq!(json["path"], "/v1/invoices");
    assert_eq!(json["status"], 200);
    assert_eq!(json["duration_ms"], 4.2);
    assert_eq!(json["attempts"], 1);
    assert_eq!(json["rate_limited"], false);
    assert_eq!(json["broken"], false);
    assert_eq!(json["shed"], false);
    assert_eq!(json["dimensions"]["plan"], "gold");
    // The redaction contract: the serialized object carries exactly
    // the access record's fields — no headers, no query, no
    // credentials anywhere in the line.
    let mut keys: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "attempts",
            "broken",
            "consumer",
            "dimensions",
            "duration_ms",
            "endpoint",
            "gateway",
            "id",
            "listener",
            "method",
            "path",
            "rate_limited",
            "request_id",
            "route",
            "shed",
            "status",
            "timestamp",
            "upstream",
        ]
    );
}

#[test]
fn empty_optionals_serialize_as_empty_strings_not_nulls() {
    let rec = AccessRecord::new("r".into(), "GET".into(), "/x".into(), "l".into());
    let line = StreamRecord::from_access(&rec, "rec-x".into(), Arc::from("dwara-test"), 0).line();
    let json: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
    assert_eq!(json["upstream"], "");
    assert_eq!(json["endpoint"], "");
    assert_eq!(json["consumer"], "anonymous");
    assert_eq!(json["route"], "unrouted");
    // No dimensions key material: an empty map serializes as {}.
    assert_eq!(json["dimensions"], serde_json::json!({}));
}

// --- offer path ------------------------------------------------------------

#[test]
fn a_disabled_stream_offers_nothing_and_allocates_nothing() {
    let stream = AccessRecordStream::with_capacity(8);
    assert!(!stream.enabled(), "a fresh stream starts disarmed");
    stream.offer(&access_record("/x"));
    assert_eq!(stream.offered(), 0, "disabled offers are not counted");
    assert_eq!(stream.dropped(), 0);
    // Arming applies immediately; disarming stops the flow.
    stream.set_enabled(true);
    stream.offer(&access_record("/x"));
    assert_eq!(stream.offered(), 1);
    stream.set_enabled(false);
    stream.offer(&access_record("/x"));
    assert_eq!(stream.offered(), 1, "still exactly one queued offer");
}

#[test]
fn a_full_channel_drops_and_counts_and_never_blocks() {
    let stream = AccessRecordStream::with_capacity(2);
    stream.set_enabled(true);
    // Nobody drains: two offers fill the queue, the third drops.
    stream.offer(&access_record("/1"));
    stream.offer(&access_record("/2"));
    stream.offer(&access_record("/3"));
    assert_eq!(stream.offered(), 2);
    assert_eq!(
        stream.dropped(),
        1,
        "the over-cap offer is dropped, counted"
    );
}

#[test]
fn record_ids_are_unique_and_instance_prefixed() {
    let stream = AccessRecordStream::with_capacity(64);
    stream.set_enabled(true);
    let mut rx = stream.take_receiver().unwrap();
    stream.offer(&access_record("/1"));
    stream.offer(&access_record("/2"));
    assert!(stream.instance().starts_with("dwara-"));
    // Ids are assigned by the stream's own counter, observable through
    // the receiver (drain both and compare).
    let mut ids = Vec::new();
    while let Ok(r) = rx.try_recv() {
        ids.push(r.id);
    }
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);
    assert!(ids.iter().all(|id| id.starts_with("rec-")));
}

// --- sink compilation --------------------------------------------------------

#[test]
fn the_webhook_sink_compiles_through_the_shared_endpoint_grammar() {
    let obs = Arc::new(Observability::new());
    let targets =
        compile_stream_targets(Some(&webhook_sink_cfg("http://127.0.0.1:9/ingest")), &obs);
    assert_eq!(targets.sinks.len(), 1);
    assert_eq!(
        targets.flush_ms,
        dwara_core::config::DEFAULT_STREAM_FLUSH_MS
    );
    assert_eq!(
        targets.batch_max,
        dwara_core::config::DEFAULT_STREAM_BATCH_MAX as usize
    );

    // No block: the disabled state.
    let empty = compile_stream_targets(None, &obs);
    assert!(empty.sinks.is_empty());
}

#[test]
fn an_uncompilable_sink_fails_closed_to_the_disabled_state() {
    let obs = Arc::new(Observability::new());
    let bad = webhook_sink_cfg("not-a-url");
    let targets = compile_stream_targets(Some(&bad), &obs);
    assert!(
        targets.sinks.is_empty(),
        "a broken sink leaves the stream disabled, not half-armed"
    );
}

// --- flusher batching --------------------------------------------------------

#[tokio::test]
async fn batch_max_records_flush_as_one_delivery_in_order() {
    let (sink, _tx, stream, task, shutdown, _obs) = flusher_with(3, 60_000).await;
    for i in 0..3 {
        stream.offer(&access_record(&format!("/r{i}")));
    }
    let batches = wait_batches(&sink, 1).await;
    assert_eq!(batches.len(), 1, "one delivery per flushed batch");
    assert_eq!(batches[0].1, 3, "all three records in the batch");
    let body = String::from_utf8(batches[0].0.clone().to_vec()).unwrap();
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 3);
    // Strict order: r0, r1, r2 — the receiver's arrival contract.
    assert!(lines[0].contains("\"path\":\"/r0\""));
    assert!(lines[1].contains("\"path\":\"/r1\""));
    assert!(lines[2].contains("\"path\":\"/r2\""));
    shutdown.send(()).unwrap();
    let _ = task.await;
}

#[tokio::test]
async fn the_cadence_tick_flushes_a_partial_batch() {
    // batch_max far above the traffic, flush_ms short: the tick is the
    // trigger, and a partial batch (fewer records than batch_max)
    // ships.
    let (sink, _tx, stream, task, shutdown, _obs) = flusher_with(100, 100).await;
    stream.offer(&access_record("/only"));
    let batches = wait_batches(&sink, 1).await;
    assert_eq!(batches[0].1, 1);
    assert!(String::from_utf8(batches[0].0.to_vec())
        .unwrap()
        .contains("\"path\":\"/only\""));
    shutdown.send(()).unwrap();
    let _ = task.await;
}

#[tokio::test]
async fn a_live_retarget_changes_the_generation_state() {
    let (sink, tx, stream, task, shutdown, _obs) = flusher_with(2, 60_000).await;
    // Replace the sink set entirely (a reload's compiled state): the
    // next batch routes to the NEW sink only.
    let sink2 = Arc::new(MockSink::default());
    tx.send(StreamTargets {
        sinks: vec![Arc::clone(&sink2) as Arc<dyn RecordSink>],
        flush_ms: 60_000,
        batch_max: 1,
    })
    .unwrap();
    stream.offer(&access_record("/after-swap"));
    let batches = wait_batches(&sink2, 1).await;
    assert_eq!(batches.len(), 1);
    assert!(
        sink.batches.lock().unwrap().is_empty(),
        "the retired sink receives nothing after the swap"
    );
    shutdown.send(()).unwrap();
    let _ = task.await;
}

#[tokio::test]
async fn shutdown_drains_the_queue_into_one_final_batch() {
    let stream = AccessRecordStream::with_capacity(64);
    stream.set_enabled(true);
    // No flusher running yet: offers queue only.
    stream.offer(&access_record("/1"));
    stream.offer(&access_record("/2"));
    let rx = stream.take_receiver().unwrap();
    let sink = Arc::new(MockSink::default());
    let (tx, watch_rx) = watch::channel(StreamTargets {
        sinks: vec![Arc::clone(&sink) as Arc<dyn RecordSink>],
        flush_ms: 60_000,
        batch_max: 100,
    });
    let (shutdown, shutdown_rx) = watch::channel(());
    let task = tokio::spawn(dwara_core::events::stream::run_stream_flusher(
        rx,
        watch_rx,
        Arc::new(Observability::new()),
        shutdown_rx,
    ));
    shutdown.send(()).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    let batches = sink.batches.lock().unwrap().clone();
    assert_eq!(batches.len(), 1, "the queued records flushed once at stop");
    assert_eq!(batches[0].1, 2);
    drop(tx);
}

#[tokio::test]
async fn an_over_cap_record_is_dropped_and_counted_not_truncated() {
    let (sink, _tx, stream, task, shutdown, _obs) = flusher_with(100, 100).await;
    let huge = format!("/{}", "a".repeat(MAX_RECORD_BYTES));
    stream.offer(&access_record("/good"));
    stream.offer(&access_record(&huge));
    let batches = wait_batches(&sink, 1).await;
    let body = String::from_utf8(batches[0].0.to_vec()).unwrap();
    assert!(
        body.contains("\"path\":\"/good\""),
        "the well-formed record still ships"
    );
    assert!(
        !body.contains("aaaaaa"),
        "the over-cap record is dropped whole, never truncated into the batch"
    );
    assert_eq!(batches[0].1, 1);
    shutdown.send(()).unwrap();
    let _ = task.await;
}

// --- validation --------------------------------------------------------------

fn validate_stream_yaml(stream: &str) -> Vec<String> {
    let yaml = format!(
        "{stream}routes:\n\
         - name: all\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 9999\n"
    );
    let gateway = dwara_core::config::parse_gateway(&yaml).unwrap();
    dwara_core::snapshot::validate(&gateway)
        .into_iter()
        .map(|i| format!("{i}"))
        .collect()
}

#[test]
fn a_well_formed_stream_block_validates() {
    let issues = validate_stream_yaml(
        "analytics_stream:\n  buffer: 4096\n  flush_ms: 500\n  batch_max: 64\n  sink:\n    type: webhook\n    url: https://collector.example.com/ingest\n    headers:\n      X-Token: literal\n",
    );
    assert!(issues.is_empty(), "{issues:?}");
}

#[test]
fn stream_validation_rejects_the_shared_delivery_grammar_violations() {
    // Bad URL scheme.
    let issues = validate_stream_yaml(
        "analytics_stream:\n  sink:\n    type: webhook\n    url: ftp://x/ingest\n",
    );
    let joined = issues.join("\n");
    assert!(joined.contains("analytics_stream.sink.webhook.url"));
    assert!(joined.contains("absolute http(s) URL"));

    // Unresolvable secret reference in a header (DW-045 compile-time
    // contract; the issue names the reference, never a value).
    let issues = validate_stream_yaml(
        "analytics_stream:\n  sink:\n    type: webhook\n    url: http://127.0.0.1:9/x\n    headers:\n      X-Token: ${file:/nonexistent/secret}\n",
    );
    let joined = issues.join("\n");
    assert!(joined.contains("X-Token"), "{joined}");

    // Retry knob bounds (the shared webhook engine's).
    let issues = validate_stream_yaml(
        "analytics_stream:\n  sink:\n    type: webhook\n    url: http://127.0.0.1:9/x\n    timeout_ms: 0\n    max_attempts: 99\n    backoff_base_ms: 0\n",
    );
    let joined = issues.join("\n");
    assert!(joined.contains("timeout_ms must be in"));
    assert!(joined.contains("max_attempts must be in"));
    assert!(joined.contains("backoff_base_ms must be > 0"));

    // Cap below base.
    let issues = validate_stream_yaml(
        "analytics_stream:\n  sink:\n    type: webhook\n    url: http://127.0.0.1:9/x\n    backoff_base_ms: 2000\n    backoff_cap_ms: 1000\n",
    );
    let joined = issues.join("\n");
    assert!(joined.contains("backoff_cap_ms must be >= backoff_base_ms"));
}

#[test]
fn stream_validation_rejects_out_of_bounds_pipeline_knobs() {
    let issues = validate_stream_yaml(
        "analytics_stream:\n  buffer: 4\n  flush_ms: 5\n  batch_max: 0\n  sink:\n    type: webhook\n    url: http://127.0.0.1:9/x\n",
    );
    let joined = issues.join("\n");
    assert!(joined.contains("buffer must be in"), "{joined}");
    assert!(joined.contains("flush_ms must be in"));
    assert!(joined.contains("batch_max must be in"));
}

// --- the webhook sink on the wire (scripted receiver) ------------------------

/// A tokio scripted sink: connection N (0-based) is read as one full
/// HTTP request (head + Content-Length body) and answered with
/// `responses[N]` (later connections repeat the last entry). Mirrors
/// the webhooks suite's sink. Also captures the raw request head.
async fn scripted_sink(responses: &[&[u8]]) -> (u16, Arc<Mutex<Vec<String>>>, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let conns = Arc::new(AtomicUsize::new(0));
    let heads: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&conns);
    let head_sink = Arc::clone(&heads);
    let responses: Vec<Vec<u8>> = responses.iter().map(|r| r.to_vec()).collect();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            let n = seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let Some(response) = responses.get(n).or_else(|| responses.last()).cloned() else {
                continue;
            };
            let head_sink = Arc::clone(&head_sink);
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt as _;
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.readable().await {
                        Ok(()) => {}
                        Err(_) => return,
                    }
                    match stream.try_read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&buf).into_owned();
                let len: usize = head
                    .lines()
                    .find_map(|l| l.split_once(':'))
                    .filter(|(n, _)| n.trim().eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, v)| v.trim().parse().ok())
                    .unwrap_or(0);
                let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
                let mut have = buf.len() - head_end - 4;
                while have < len {
                    match stream.readable().await {
                        Ok(()) => {}
                        Err(_) => return,
                    }
                    match stream.try_read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => have += n,
                    }
                }
                head_sink.lock().unwrap().push(head);
                let _ = stream.write_all(&response).await;
                let _ = stream.flush().await;
            });
        }
    });
    (port, heads, conns)
}

const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
const SERVICE_UNAVAILABLE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
const NOT_FOUND: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

/// The value of `dwara_access_records_streamed_total{outcome}` (the
/// counter's sample value, not the sample count).
fn streamed_value(obs: &Observability, outcome: &str) -> u64 {
    let needle = format!("dwara_access_records_streamed_total{{outcome=\"{outcome}\"}}");
    obs.render()
        .lines()
        .find(|l| l.starts_with(&needle))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Count SINK attempts (connections) recorded by the scripted sink.
fn attempts(conns: &Arc<AtomicUsize>) -> usize {
    conns.load(Ordering::SeqCst)
}

#[tokio::test]
async fn the_webhook_sink_retries_transient_failures_and_counts_records() {
    let (port, heads, conns) = scripted_sink(&[SERVICE_UNAVAILABLE, SERVICE_UNAVAILABLE, OK]).await;
    let obs = Arc::new(Observability::new());
    let cfg = AnalyticsStreamWebhook {
        url: format!("http://127.0.0.1:{port}/ingest"),
        headers: Default::default(),
        timeout_ms: 2000,
        max_attempts: 3,
        backoff_base_ms: 20,
        backoff_cap_ms: 100,
    };
    let sink = dwara_core::events::stream::WebhookRecordSink::compile(&cfg, Arc::clone(&obs))
        .expect("well-formed sink compiles");
    // One batch of three lines.
    let mut body = String::new();
    for i in 0..3 {
        body.push_str(&stream_record(&format!("/w{i}")).line());
    }
    let accepted = sink.deliver_batch(Bytes::from(body.clone()), 3).await;
    assert!(accepted, "the third attempt's 200 accepts the batch");
    assert_eq!(attempts(&conns), 3, "exactly one connection per attempt");
    // The wire shape: NDJSON media type, the stream's user-agent, and
    // the full body on every attempt.
    let heads = heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 3);
    for head in &heads {
        assert!(head
            .to_lowercase()
            .contains("content-type: application/x-ndjson"));
        assert!(head.contains("user-agent: dwara-record-stream"));
        assert!(head.contains(&format!("content-length: {}", body.len())));
    }
    assert!(heads[0].contains("POST /ingest HTTP/1.1"), "path preserved");
    // Outcome counting is by RECORDS: one delivered batch of 3 -> +3.
    assert_eq!(streamed_value(&obs, "delivered"), 3);
    assert_eq!(streamed_value(&obs, "failed"), 0);
}

#[tokio::test]
async fn a_non_transient_answer_fails_the_batch_once_without_retry() {
    let (port, _heads, conns) = scripted_sink(&[NOT_FOUND]).await;
    let obs = Arc::new(Observability::new());
    let cfg = AnalyticsStreamWebhook {
        url: format!("http://127.0.0.1:{port}/ingest"),
        headers: Default::default(),
        timeout_ms: 2000,
        max_attempts: 5,
        backoff_base_ms: 20,
        backoff_cap_ms: 100,
    };
    let sink =
        dwara_core::events::stream::WebhookRecordSink::compile(&cfg, Arc::clone(&obs)).unwrap();
    let accepted = sink.deliver_batch(Bytes::from("x\n"), 1).await;
    assert!(!accepted);
    assert_eq!(attempts(&conns), 1, "a 4xx answer is this delivery's fault");
    assert_eq!(streamed_value(&obs, "failed"), 1);
    assert_eq!(streamed_value(&obs, "delivered"), 0);
}

#[tokio::test]
async fn secret_reference_headers_resolve_onto_the_wire() {
    // DW-045 compile-time resolution, pinned on the wire for the sink
    // (validation covers rejection; this pins the positive path).
    let secret = tempfile::tempdir().unwrap();
    let path = secret.path().join("token");
    std::fs::write(&path, "tok-123").unwrap();
    let (port, heads, _conns) = scripted_sink(&[OK]).await;
    let obs = Arc::new(Observability::new());
    let mut headers = std::collections::BTreeMap::new();
    headers.insert(
        "Authorization".to_string(),
        format!("${{file:{}}}", path.display()),
    );
    let cfg = AnalyticsStreamWebhook {
        url: format!("http://127.0.0.1:{port}/ingest"),
        headers,
        timeout_ms: 2000,
        max_attempts: 1,
        backoff_base_ms: 10,
        backoff_cap_ms: 10,
    };
    let sink =
        dwara_core::events::stream::WebhookRecordSink::compile(&cfg, Arc::clone(&obs)).unwrap();
    assert!(sink.deliver_batch(Bytes::from("x\n"), 1).await);
    let heads = heads.lock().unwrap().clone();
    let lower = heads[0].to_lowercase();
    assert!(
        lower.contains("authorization: tok-123"),
        "the resolved value rides the wire: {}",
        heads[0]
    );
}

// --- flusher: byte cap and cadence reschedule --------------------------------

#[tokio::test]
async fn the_batch_byte_cap_flushes_before_the_cadence_tick_could() {
    // batch_max unreachable, flush_ms 60 s: only the byte cap can
    // flush within the 5 s bound — 5 000 records of ~450 bytes each
    // comfortably exceed the 2 MiB cap.
    let (sink, _tx, stream, task, shutdown, _obs) = flusher_with(usize::MAX, 60_000).await;
    let fat = format!("/{}", "p".repeat(200));
    for _ in 0..5_000 {
        stream.offer(&access_record(&fat));
    }
    let batches = wait_batches(&sink, 1).await;
    let (body, records) = &batches[0];
    assert!(
        *records < 5_000,
        "the byte cap split the stream before all records ({records})"
    );
    assert!(
        body.len() <= dwara_core::events::stream::MAX_BATCH_BYTES + MAX_RECORD_BYTES,
        "one batch never exceeds the cap by more than one line ({})",
        body.len()
    );
    shutdown.send(()).unwrap();
    let _ = task.await;
}

#[tokio::test]
async fn a_cadence_change_reschedules_the_flusher_live() {
    // Start at a 60 s cadence, then swap the generation to 100 ms: the
    // queued record must flush promptly — proof the ticker rebuilt.
    let (sink, tx, stream, task, shutdown, _obs) = flusher_with(100, 60_000).await;
    stream.offer(&access_record("/first"));
    tokio::time::sleep(Duration::from_millis(50)).await;
    tx.send(StreamTargets {
        sinks: vec![Arc::clone(&sink) as Arc<dyn RecordSink>],
        flush_ms: 100,
        batch_max: 100,
    })
    .unwrap();
    stream.offer(&access_record("/second"));
    let batches = wait_batches(&sink, 1).await;
    assert!(batches[0].1 >= 1);
    shutdown.send(()).unwrap();
    let _ = task.await;
}

// --- concurrency accounting ---------------------------------------------------

#[test]
fn concurrent_offers_account_every_record_exactly_once() {
    let stream = AccessRecordStream::with_capacity(100);
    stream.set_enabled(true);
    let total = 4 * 250;
    std::thread::scope(|s| {
        for _ in 0..4 {
            let st = &stream;
            s.spawn(move || {
                for _ in 0..250 {
                    st.offer(&access_record("/c"));
                }
            });
        }
    });
    assert_eq!(stream.offered() + stream.dropped(), total as u64);
    assert!(stream.offered() <= 100, "the channel bound holds");
}

#[tokio::test]
async fn a_disable_with_a_queued_tail_counts_it_as_dropped() {
    // M2: records already queued when the generation empties the sink
    // set must land in outcome="dropped" — the accounting identity
    // offered == delivered + failed + dropped holds through a
    // deliberate disable.
    let (sink, tx, stream, task, shutdown, obs) = flusher_with(100, 60_000).await;
    stream.offer(&access_record("/t1"));
    stream.offer(&access_record("/t2"));
    // The generation disables the stream (empty sink set) with a fast
    // cadence so the tail flushes promptly.
    tx.send(StreamTargets {
        sinks: Vec::new(),
        flush_ms: 100,
        batch_max: 100,
    })
    .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if streamed_value(&obs, "dropped") >= 2 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the queued tail never landed in outcome=dropped; render:\n{}",
            obs.render()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        sink.batches.lock().unwrap().is_empty(),
        "the disabled flush delivered nothing"
    );
    shutdown.send(()).unwrap();
    let _ = task.await;
}
