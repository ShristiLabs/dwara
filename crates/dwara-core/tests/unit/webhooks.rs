//! Unit tests for the event bus and webhook delivery (DW-044): the
//! envelope shape, the kind set, the bus's bounded non-blocking emit
//! contract, target compilation (URL decomposition, secret-reference
//! headers), and the delivery retry/budget machinery against scripted
//! local sinks. The end-to-end pin (emission point -> webhook received)
//! lives in `tests/webhooks.rs`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dwara_core::config::Webhook;
use dwara_core::events::webhook::{deliver, envelope_json, rfc3339_ms, WebhookTarget};
use dwara_core::events::{Event, EventBus, EventKind, EventPayload};
use dwara_core::observability::Observability;

// --- helpers --------------------------------------------------------------

fn target(url: &str, events: &[&str]) -> Webhook {
    Webhook {
        url: url.to_string(),
        events: events.iter().map(|s| s.to_string()).collect(),
        headers: Default::default(),
        timeout_ms: 2000,
        max_attempts: 3,
        backoff_base_ms: 100,
        backoff_cap_ms: 1000,
    }
}

fn event(kind: EventKind, payload: EventPayload) -> Event {
    Event {
        id: "evt-test-000001".to_string(),
        kind,
        timestamp_ms: 784_111_777_012,
        gateway: "dwara-test".to_string(),
        payload,
    }
}

/// Counted occurrences of `dwara_webhook_events_total{kind,outcome}` in
/// the rendered families (0 when the series does not exist yet).
fn outcome_count(obs: &Observability, kind: &str, outcome: &str) -> u32 {
    let needle = format!("outcome=\"{outcome}\"");
    obs.render()
        .lines()
        .filter(|l| {
            l.contains("dwara_webhook_events_total")
                && l.contains(&needle)
                && l.contains(&format!("kind=\"{kind}\""))
        })
        .count() as u32
}

/// A tokio scripted sink: connection N (0-based) is read as one full
/// HTTP request (head + Content-Length body) and answered with
/// `responses[N]` (later connections repeat the last entry). Returns
/// the port and a connection counter. Mirrors the otlp suite's sink.
async fn scripted_sink(responses: &[&[u8]]) -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let conns = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&conns);
    let responses: Vec<Vec<u8>> = responses.iter().map(|r| r.to_vec()).collect();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            let n = seen.fetch_add(1, Ordering::SeqCst);
            let Some(response) = responses.get(n).or_else(|| responses.last()).cloned() else {
                continue;
            };
            tokio::spawn(async move {
                // Read exactly one request (head + body); the client
                // waits for our answer, so draining to EOF would
                // deadlock.
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
                use tokio::io::AsyncWriteExt as _;
                let _ = stream.write_all(&response).await;
                let _ = stream.flush().await;
            });
        }
    });
    (port, conns)
}

const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
const SERVICE_UNAVAILABLE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
const NOT_FOUND: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

// --- event kinds ----------------------------------------------------------

#[test]
fn the_kind_set_is_closed_and_snake_cased() {
    assert_eq!(EventKind::ALL.len(), 10, "one kind per emission site");
    for kind in EventKind::ALL {
        assert_eq!(
            EventKind::from_config(kind.as_str()),
            Some(*kind),
            "{} round-trips through its config spelling",
            kind.as_str()
        );
        assert!(
            kind.as_str()
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_'),
            "{} is snake_case",
            kind.as_str()
        );
    }
    // The quota kind is EMITTED since DW-033 (near-limit crossing);
    // unknown spellings are still rejected.
    assert_eq!(
        EventKind::from_config("quota_near_limit"),
        Some(EventKind::QuotaNearLimit)
    );
    assert_eq!(EventKind::from_config("nope"), None);
}

// --- envelope -------------------------------------------------------------

#[test]
fn rfc3339_formats_known_instants_with_millisecond_precision() {
    assert_eq!(rfc3339_ms(0), "1970-01-01T00:00:00.000Z");
    // The RFC 9110 example instant (Sun, 06 Nov 1994 08:49:37 GMT).
    assert_eq!(rfc3339_ms(784_111_777_000), "1994-11-06T08:49:37.000Z");
    assert_eq!(rfc3339_ms(784_111_777_012), "1994-11-06T08:49:37.012Z");
    // Leap day (2000-02-29) and the last millisecond before 2016-03-01.
    assert_eq!(rfc3339_ms(951_825_600_123), "2000-02-29T12:00:00.123Z");
    assert_eq!(rfc3339_ms(1_456_790_399_999), "2016-02-29T23:59:59.999Z");
}

#[test]
fn the_envelope_is_one_stable_json_object() {
    let event = event(
        EventKind::BreakerOpened,
        EventPayload::breaker("billing", Some("error_ratio")),
    );
    let json: serde_json::Value = serde_json::from_str(&envelope_json(&event)).unwrap();
    // serde_json serializes objects in sorted-key order without the
    // `preserve_order` feature; the contract is the SET of keys and each
    // key's value, not byte order.
    let mut keys: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["gateway", "id", "kind", "payload", "timestamp"]);
    assert_eq!(json["id"], "evt-test-000001");
    assert_eq!(json["kind"], "breaker_opened");
    assert_eq!(json["timestamp"], "1994-11-06T08:49:37.012Z");
    assert_eq!(json["gateway"], "dwara-test");
    assert_eq!(json["payload"]["upstream"], "billing");
    assert_eq!(json["payload"]["detail"], "error_ratio");
    // Unset payload fields are OMITTED, not nulled.
    assert!(json["payload"].get("endpoint").is_none());
    assert!(json["payload"].get("generation").is_none());
}

#[test]
fn config_payloads_carry_the_publish_facts() {
    let published = event(
        EventKind::ConfigPublished,
        EventPayload {
            generation: Some(7),
            content_hash: Some(0xdeadbeef),
            route_count: Some(12),
            ..EventPayload::default()
        },
    );
    let json: serde_json::Value = serde_json::from_str(&envelope_json(&published)).unwrap();
    assert_eq!(json["kind"], "config_published");
    assert_eq!(json["payload"]["generation"], 7);
    assert_eq!(json["payload"]["route_count"], 12);
    assert!(json["payload"].get("upstream").is_none());
}

// --- bus ------------------------------------------------------------------

#[tokio::test]
async fn emit_hands_the_event_to_the_receiver() {
    let (bus, mut rx) = EventBus::with_receiver(8);
    let emitter = bus.emitter();
    emitter.emit(
        EventKind::BreakerOpened,
        EventPayload::breaker("up", Some("consecutive_failures")),
    );
    let received = rx.recv().await.expect("event queued");
    assert_eq!(received.kind, EventKind::BreakerOpened);
    assert_eq!(received.payload.upstream.as_deref(), Some("up"));
    assert_eq!(received.payload.detail, Some("consecutive_failures"));
    assert_eq!(received.gateway, bus.instance());
    assert!(received.id.starts_with("evt-"), "ids use the evt- shape");
    assert_eq!(bus.emitted_total(), 1);
    assert_eq!(bus.dropped_total(), 0);
}

#[tokio::test]
async fn a_full_queue_drops_newest_and_counts_never_blocks() {
    let (bus, mut rx) = EventBus::with_receiver(1);
    let emitter = bus.emitter();
    let started = Instant::now();
    for i in 0..5 {
        emitter.emit(
            EventKind::EndpointEjected,
            EventPayload::endpoint("up", &format!("127.0.0.1:{i}")),
        );
    }
    // Emission of 5 events into a 1-slot queue must be effectively
    // instant: drops, not waits.
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "emit must never block: {:?}",
        started.elapsed()
    );
    assert_eq!(bus.emitted_total(), 1, "the queued event counts once");
    assert_eq!(bus.dropped_total(), 4, "every overflow is counted");
    let only = rx.recv().await.expect("the one queued event");
    assert_eq!(only.kind, EventKind::EndpointEjected);
    // Drop-NEWEST: the FIRST event kept its place in line.
    assert_eq!(only.payload.endpoint.as_deref(), Some("127.0.0.1:0"));
}

#[tokio::test]
async fn emitting_with_no_receiver_counts_the_drop() {
    let bus = EventBus::with_capacity(4);
    let rx = bus.take_receiver().expect("fresh bus holds its receiver");
    drop(rx);
    bus.emitter()
        .emit(EventKind::ConfigPublished, EventPayload::default());
    assert_eq!(bus.emitted_total(), 0);
    assert_eq!(bus.dropped_total(), 1);
    // The single-consumer receiver can be taken exactly once.
    assert!(bus.take_receiver().is_none());
}

#[test]
fn the_instance_label_identifies_the_process() {
    let id = dwara_core::events::generate_instance_id();
    let rest = id.strip_prefix("dwara-").expect("dwara- prefix");
    assert!(
        rest.split('-').count() == 2,
        "pid and boot-time components: {id}"
    );
}

// --- target compilation ---------------------------------------------------

#[tokio::test]
async fn targets_decompose_urls_and_filter_kinds() {
    let compiled = WebhookTarget::compile(&target(
        "https://hooks.example.com:8443/alerts?id=1",
        &["breaker_opened", "config_published"],
    ))
    .unwrap();
    assert!(compiled.wants(EventKind::BreakerOpened));
    assert!(compiled.wants(EventKind::ConfigPublished));
    assert!(!compiled.wants(EventKind::BreakerClosed));
    assert!(!compiled.wants(EventKind::EndpointEjected));
    assert_eq!(compiled.url(), "https://hooks.example.com:8443/alerts?id=1");

    // Defaults: scheme-implied port, no port suffix in the Host header.
    let plain =
        WebhookTarget::compile(&target("http://127.0.0.1/hook", &["breaker_opened"])).unwrap();
    assert!(!plain.wants(EventKind::ConfigPublished));

    // Bad URLs and unknown kinds fail compilation with pointed errors.
    assert!(WebhookTarget::compile(&target("ftp://x/y", &["breaker_opened"])).is_err());
    assert!(WebhookTarget::compile(&target("http://", &["breaker_opened"])).is_err());
    assert!(WebhookTarget::compile(&target("http://x/y", &["nope"])).is_err());
    // The quota kind is emitted since DW-033: it compiles and is wanted.
    let quota = WebhookTarget::compile(&target("http://x/y", &["quota_near_limit"])).unwrap();
    assert!(quota.wants(EventKind::QuotaNearLimit));
    assert!(!quota.wants(EventKind::BreakerOpened));
}

#[tokio::test]
async fn secret_reference_headers_resolve_at_compile_time() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    std::fs::write(&path, "sekrit-token\n").unwrap();
    let mut cfg = target("http://127.0.0.1:9/hook", &["breaker_opened"]);
    cfg.headers.insert(
        "X-Hook-Token".to_string(),
        format!("${{file:{}}}", path.display()),
    );
    cfg.headers
        .insert("X-Static".to_string(), "literal".to_string());
    let compiled = WebhookTarget::compile(&cfg).unwrap();
    // The Debug output names header NAMES only — a resolved secret must
    // never render.
    let debug = format!("{compiled:?}");
    assert!(debug.contains("X-Hook-Token"), "{debug}");
    assert!(
        !debug.contains("sekrit-token"),
        "secret leaked in Debug: {debug}"
    );

    // An unresolvable reference fails closed naming the reference.
    let mut broken = target("http://127.0.0.1:9/hook", &["breaker_opened"]);
    broken.headers.insert(
        "X-Hook-Token".to_string(),
        "${file:/nonexistent/token}".to_string(),
    );
    let error = WebhookTarget::compile(&broken).unwrap_err();
    assert!(error.contains("/nonexistent/token"), "{error}");
    assert!(!error.contains("sekrit"), "{error}");
}

// --- delivery ---------------------------------------------------------------

#[tokio::test]
async fn a_transient_503_is_retried_within_the_budget_until_accepted() {
    let (port, conns) = scripted_sink(&[SERVICE_UNAVAILABLE, OK]).await;
    let obs = Arc::new(Observability::new());
    let target = WebhookTarget::compile(&target(
        &format!("http://127.0.0.1:{port}/hook"),
        &["breaker_opened"],
    ))
    .unwrap();
    deliver(
        target,
        Bytes::from_static(b"{}"),
        EventKind::BreakerOpened,
        Arc::clone(&obs),
    )
    .await;
    assert_eq!(conns.load(Ordering::SeqCst), 2, "exactly one retry");
    assert_eq!(outcome_count(&obs, "breaker_opened", "delivered"), 1);
    assert_eq!(outcome_count(&obs, "breaker_opened", "failed"), 0);
}

#[tokio::test]
async fn a_non_transient_404_is_not_retried() {
    let (port, conns) = scripted_sink(&[NOT_FOUND, OK]).await;
    let obs = Arc::new(Observability::new());
    let target = WebhookTarget::compile(&target(
        &format!("http://127.0.0.1:{port}/hook"),
        &["breaker_opened"],
    ))
    .unwrap();
    deliver(
        target,
        Bytes::from_static(b"{}"),
        EventKind::BreakerOpened,
        Arc::clone(&obs),
    )
    .await;
    assert_eq!(conns.load(Ordering::SeqCst), 1, "no retry for a 4xx");
    assert_eq!(outcome_count(&obs, "breaker_opened", "failed"), 1);
    assert_eq!(outcome_count(&obs, "breaker_opened", "delivered"), 0);
}

#[tokio::test]
async fn a_dead_target_exhausts_bounded_attempts_and_fails_fast() {
    // A reserved-then-dropped port: every connect is refused instantly,
    // so 3 attempts with 100ms + 200ms backoff finish far inside a
    // second (the pin is the BOUND, not the refusal).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let obs = Arc::new(Observability::new());
    let target = WebhookTarget::compile(&target(
        &format!("http://127.0.0.1:{port}/hook"),
        &["config_rejected"],
    ))
    .unwrap();
    let started = Instant::now();
    deliver(
        target,
        Bytes::from_static(b"{}"),
        EventKind::ConfigRejected,
        Arc::clone(&obs),
    )
    .await;
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "attempts are bounded: {:?}",
        started.elapsed()
    );
    assert_eq!(outcome_count(&obs, "config_rejected", "failed"), 1);
}

#[tokio::test]
async fn retry_after_seconds_gate_the_retry() {
    // The target demands a 1s pause; the computed backoff for the first
    // retry would be 100ms. Elapsed must land near the DEMANDED wait.
    let too_many_with_wait: &[u8] =
        b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\nContent-Length: 0\r\n\r\n";
    let (port, _conns) = scripted_sink(&[too_many_with_wait, OK]).await;
    let obs = Arc::new(Observability::new());
    let target = WebhookTarget::compile(&target(
        &format!("http://127.0.0.1:{port}/hook"),
        &["breaker_opened"],
    ))
    .unwrap();
    let started = Instant::now();
    deliver(
        target,
        Bytes::from_static(b"{}"),
        EventKind::BreakerOpened,
        Arc::clone(&obs),
    )
    .await;
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(900),
        "Retry-After: 1 must gate the retry, not the 100ms backoff: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "the honored wait stays bounded: {elapsed:?}"
    );
    assert_eq!(outcome_count(&obs, "breaker_opened", "delivered"), 1);
}

#[tokio::test]
async fn a_hung_target_is_cut_off_by_the_total_budget() {
    // Accepts the request and never answers; the delivery must end at
    // its timeout_ms, not hang.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        // Hold the connection open, silent, for far longer than the
        // delivery budget; the client must give up on its own.
        tokio::time::sleep(Duration::from_secs(10)).await;
        drop(stream);
    });
    let obs = Arc::new(Observability::new());
    let mut cfg = target(
        &format!("http://127.0.0.1:{port}/hook"),
        &["breaker_opened"],
    );
    cfg.timeout_ms = 300;
    let target = WebhookTarget::compile(&cfg).unwrap();
    let started = Instant::now();
    deliver(
        target,
        Bytes::from_static(b"{}"),
        EventKind::BreakerOpened,
        Arc::clone(&obs),
    )
    .await;
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(250) && elapsed < Duration::from_secs(2),
        "the total budget bounds a hung target: {elapsed:?}"
    );
    assert_eq!(outcome_count(&obs, "breaker_opened", "failed"), 1);
    assert_eq!(outcome_count(&obs, "breaker_opened", "delivered"), 0);
}

// --- validation ------------------------------------------------------------

fn validate_webhook_yaml(yaml: &str) -> Vec<String> {
    let gateway = dwara_core::config::parse_gateway(yaml).unwrap();
    dwara_core::snapshot::validate(&gateway)
        .into_iter()
        .map(|i| format!("{i}"))
        .collect()
}

fn webhook_yaml(webhooks: &str) -> String {
    format!(
        "{webhooks}routes:\n\
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
    )
}

#[test]
fn a_well_formed_webhook_validates() {
    let issues = validate_webhook_yaml(&webhook_yaml(
        "webhooks:\n\
         - url: https://hooks.example.com/alerts\n\
         \x20 events: [breaker_opened, endpoint_ejected]\n\
         \x20 headers:\n\
         \x20   X-Token: literal\n",
    ));
    assert!(issues.is_empty(), "{issues:?}");
}

#[test]
fn webhook_validation_names_every_authoring_mistake() {
    let issues = validate_webhook_yaml(&webhook_yaml(
        "webhooks:\n\
         - url: not-a-url\n\
         \x20 events: []\n\
         - url: https://hooks.example.com/a\n\
         \x20 events: [nope]\n\
         - url: https://hooks.example.com/a\n\
         \x20 events: [breaker_opened]\n\
         \x20 timeout_ms: 0\n\
         \x20 max_attempts: 0\n\
         \x20 backoff_base_ms: 100\n\
         \x20 backoff_cap_ms: 1\n",
    ));
    let joined = issues.join("\n");
    for expected in [
        "must be an absolute http(s) URL",
        "events is empty",
        "unknown event kind 'nope'",
        "duplicate webhook url 'https://hooks.example.com/a'",
        "timeout_ms must be in 1..=60000",
        "max_attempts must be in 1..=10",
        "backoff_cap_ms must be >= backoff_base_ms",
    ] {
        assert!(
            joined.contains(expected),
            "missing issue {expected:?} in {joined}"
        );
    }
}

#[test]
fn webhook_secret_references_resolve_fail_closed_at_validation() {
    let issues = validate_webhook_yaml(&webhook_yaml(
        "webhooks:\n\
         - url: https://hooks.example.com/alerts\n\
         \x20 events: [breaker_opened]\n\
         \x20 headers:\n\
         \x20   X-Token: ${file:/nonexistent/token}\n",
    ));
    let joined = issues.join("\n");
    assert!(joined.contains("/nonexistent/token"), "{joined}");
    // A resolved value must be a legal header value; the issue names the
    // header, never the value.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    std::fs::write(&path, "bad\nvalue").unwrap();
    let issues = validate_webhook_yaml(&webhook_yaml(&format!(
        "webhooks:\n\
         - url: https://hooks.example.com/alerts\n\
         \x20 events: [breaker_opened]\n\
         \x20 headers:\n\
         \x20   X-Token: ${{file:{}}}\n",
        path.display()
    )));
    let joined = issues.join("\n");
    assert!(joined.contains("X-Token"), "{joined}");
    assert!(
        joined.contains("cannot appear in an HTTP header value"),
        "{joined}"
    );
    assert!(!joined.contains("bad"), "the value leaked: {joined}");
    assert!(!joined.contains("value\n"), "the value leaked: {joined}");
}

#[test]
fn inline_webhook_header_values_are_redacted_in_config_echoes() {
    let gateway = dwara_core::config::parse_gateway(&webhook_yaml(
        "webhooks:\n\
         - url: https://hooks.example.com/alerts\n\
         \x20 events: [breaker_opened]\n\
         \x20 headers:\n\
         \x20   X-Token: inline-secret\n",
    ))
    .unwrap();
    let redacted = gateway.redacted();
    let yaml = dwara_core::config::gateway_to_yaml(&redacted).unwrap();
    assert!(!yaml.contains("inline-secret"), "{yaml}");
    assert!(yaml.contains("${redacted:sha256:"), "{yaml}");
}
