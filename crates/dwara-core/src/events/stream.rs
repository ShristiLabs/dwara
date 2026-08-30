//! Real-time access-record stream (DW-121, feature analysis section 5
//! "Platform"): the record plumbing that mirrors the notice plumbing of
//! DW-044. Where the event bus carries a handful of discrete
//! operational events per minute (breaker transitions, ejections,
//! config publishes), this pipeline carries ONE record per completed
//! request — the raw firehose an operator points at their own
//! warehouse or SIEM when the embedded analytics store (DW-043) is not
//! the system of record. It complements, never replaces: the two are
//! configured independently (a deployment can run either, both, or
//! neither) and share nothing at runtime — different channels, different
//! tasks, different failure domains.
//!
//! # Placement
//!
//! The stream lives in the events domain beside the webhook deliverer
//! because it IS an outbound delivery pipeline: the sink reuses the
//! DW-044 delivery engine (`webhook::deliver_with_retry` — one total
//! timeout per delivery, exponential backoff, the transient status
//! set) and consumes the access record type from `observability`, both
//! of which the events domain may import. The analytics domain cannot
//! (its dependency set is config/observability/extensions), and the
//! firehose needs nothing from the SQLite store — moving it there
//! would force a dependency-graph change to share an engine that
//! already lives one module over.
//!
//! # Wire format (stable shape)
//!
//! One NDJSON body per flushed batch — one JSON object per line, one
//! line per record, `application/x-ndjson`:
//!
//! ```json
//! {"id":"rec-18f3c2a1b9d0-00000a","gateway":"dwara-8213-18f3c2910b07",
//!  "timestamp":"2026-08-30T09:00:00.123Z","request_id":"req-...",
//!  "listener":"edge","route":"billing","consumer":"acme",
//!  "upstream":"billing-v1","endpoint":"10.0.0.4:8443","method":"GET",
//!  "path":"/v1/invoices","status":200,"duration_ms":4.2,"attempts":1,
//!  "rate_limited":false,"broken":false,"shed":false,
//!  "dimensions":{"plan":"gold"}}
//! ```
//!
//! The field list is the access record's redacted-by-construction set:
//! `path` never carries a query string, there are no headers, no
//! credentials, and `dimensions` carries only config-declared
//! header-sourced tags (DW-043's grammar, capped at 16 x 128 bytes).
//! `id` is process-unique and monotonic (`rec-<hex unix ms>-<hex seq>`)
//! and `gateway` is the process instance label — together they give a
//! receiver per-instance ordering even across restarts. A record whose
//! serialized line exceeds [`MAX_RECORD_BYTES`] (only possible via
//! absurd path/dimension lengths — the same bound class as a webhook
//! envelope) is dropped and counted, never truncated: a receiver
//! should never see a malformed line.
//!
//! # Batching: one delivery per flushed batch
//!
//! The flusher accumulates records and flushes on the first of:
//! `batch_max` records queued, the batch byte cap [`MAX_BATCH_BYTES`]
//! reached, or `flush_ms` elapsed since the batch's first record (all
//! three read live from the current generation). ONE delivery — with
//! its whole retry cycle — is made per batch, not per record: a
//! warehouse ingest endpoint wants throughput-shaped traffic, and
//! per-record delivery would multiply the sink's load by the batch
//! factor for zero information gain. Deliveries are made STRICTLY IN
//! ORDER, inline in the flusher task: a record firehose's arrival
//! order is a real receiver expectation (unlike alert events, which
//! the deliverer dispatches as independent tasks). The cost of that
//! ordering is deliberate and bounded: one slow batch holds the queue
//! back by at most its `timeout_ms` budget, after which it fails and
//! the queue moves on — and a queue that outgrows its `buffer` bound
//! drops at OFFER time (counted), never blocks the request path.
//!
//! # Emission contract: never backpressure the dataplane
//!
//! [`AccessRecordStream::offer`] is an enabled-flag check plus a
//! bounded-channel `try_send`. When the queue is full (or the flusher
//! is stalled behind a slow batch) the record is DROPPED and the drop
//! counted ([`AccessRecordStream::dropped`], surfaced as the
//! `dwara_access_records_dropped_total` gauge at scrape time). There
//! is no blocking wait and no unbounded buffer: a dead sink degrades
//! the stream's completeness counters, never the gateway's latency.
//! When the current generation has no compiled sink the flag is off
//! and `offer` returns before allocating anything — an unconfigured
//! stream costs one relaxed atomic load per request.
//!
//! # The sink seam
//!
//! [`RecordSink`] is deliberately small: one method, one batch, one
//! boolean answer. `webhook` is the one shipped implementation; a
//! Kafka producer is the documented second slot, deferred by the
//! lean-deps rule (the same decision that keeps Parquet out of DW-156
//! backlog territory: a sink that drags a client library must earn its
//! dependency weight). Sinks are compiled per config generation (a
//! `kafka` variant would compile its client the same way) and pushed
//! to the flusher over a watch channel — a reload retargets the stream
//! with no restart, mid-batch boundaries aside.
//!
//! # Lifecycle
//!
//! The channel and its capacity are constructed once per process (the
//! capacity is a boot-time property; dwara-bin always constructs the
//! stream so a live reload can arm it) and the flusher is one
//! background task stopped by the shutdown watch, which drains what is
//! already queued into one final flush attempt before returning. The
//! gateway is not a durable queue: a record offered but not yet
//! delivered at process death is lost with only its counters as the
//! witness.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::sync::{mpsc, watch};

use crate::config::{AnalyticsStreamConfig, AnalyticsStreamSink, AnalyticsStreamWebhook};
use crate::observability::{AccessRecord, Observability};

use super::webhook::{self, WebhookTarget};

/// Hard cap on one serialized record line (bytes). The field list is
/// bounded (path length and 16x128-byte dimensions are the only
/// growth axes), so this only binds absurd shapes; an over-cap line is
/// dropped and counted, never sent truncated.
pub const MAX_RECORD_BYTES: usize = 16 * 1024;
/// Hard cap on one flushed batch (bytes), the byte half of the flush
/// trigger (with `batch_max` records, whichever comes first). Batches
/// are delivered inline and in order, so this is also the flusher's
/// per-delivery memory bound.
pub const MAX_BATCH_BYTES: usize = 2 * 1024 * 1024;
/// `User-Agent` stamped on every batch delivery.
const USER_AGENT: &str = "dwara-record-stream";

/// One completed request as it crosses the stream channel: the access
/// record's owned copy plus the identity the flusher stamps into the
/// envelope. Constructed on the request-completion path (the same
/// allocation class as the analytics store's raw-record copy).
#[derive(Debug)]
pub struct StreamRecord {
    /// Process-unique, monotonically assigned at offer time:
    /// `rec-<hex unix ms>-<hex seq>` (the event-id shape).
    pub id: String,
    /// Instance label (`dwara-<pid>-<boot ms>`; every envelope of this
    /// process carries the same one).
    pub gateway: Arc<str>,
    /// Completion time, Unix epoch milliseconds.
    pub timestamp_ms: u64,
    request_id: String,
    listener: String,
    route: String,
    consumer: String,
    upstream: String,
    endpoint: String,
    method: String,
    path: String,
    status: u16,
    duration_ms: f64,
    attempts: u32,
    rate_limited: bool,
    broken: bool,
    shed: bool,
    dimensions: Vec<(String, String)>,
}

impl StreamRecord {
    /// The owned completion-time copy of one access record (identity
    /// assigned here so the flusher stays serialization-only).
    pub fn from_access(
        rec: &AccessRecord,
        id: String,
        gateway: Arc<str>,
        timestamp_ms: u64,
    ) -> Self {
        StreamRecord {
            id,
            gateway,
            timestamp_ms,
            request_id: rec.request_id.clone(),
            listener: rec.listener.clone(),
            route: rec.route.clone(),
            consumer: rec.consumer.clone(),
            upstream: rec.upstream.clone().unwrap_or_default(),
            endpoint: rec.endpoint.clone().unwrap_or_default(),
            method: rec.method.clone(),
            path: rec.path.clone(),
            status: rec.status,
            duration_ms: rec.duration_ms,
            attempts: rec.attempts,
            rate_limited: rec.rate_limited,
            broken: rec.broken,
            shed: rec.shed,
            dimensions: rec.custom.clone(),
        }
    }

    /// The NDJSON line for this record: one JSON object, trailing
    /// newline, no truncation (the flusher enforces the byte cap).
    pub fn line(&self) -> String {
        let mut dims = serde_json::Map::new();
        for (k, v) in &self.dimensions {
            dims.insert(k.clone(), serde_json::Value::String(v.clone()));
        }
        let envelope = RecordEnvelope {
            id: &self.id,
            gateway: &self.gateway,
            timestamp: webhook::rfc3339_ms(self.timestamp_ms),
            request_id: &self.request_id,
            listener: &self.listener,
            route: &self.route,
            consumer: &self.consumer,
            upstream: &self.upstream,
            endpoint: &self.endpoint,
            method: &self.method,
            path: &self.path,
            status: self.status,
            duration_ms: self.duration_ms,
            attempts: self.attempts,
            rate_limited: self.rate_limited,
            broken: self.broken,
            shed: self.shed,
            dimensions: dims,
        };
        let mut line = serde_json::to_string(&envelope)
            .expect("envelope fields are strings, numbers, and booleans");
        line.push('\n');
        line
    }
}

/// The stable wire envelope (see the module docs for the shape and the
/// redaction contract).
#[derive(serde::Serialize)]
struct RecordEnvelope<'a> {
    id: &'a str,
    gateway: &'a str,
    timestamp: String,
    request_id: &'a str,
    listener: &'a str,
    route: &'a str,
    consumer: &'a str,
    upstream: &'a str,
    endpoint: &'a str,
    method: &'a str,
    path: &'a str,
    status: u16,
    duration_ms: f64,
    attempts: u32,
    rate_limited: bool,
    broken: bool,
    shed: bool,
    dimensions: serde_json::Map<String, serde_json::Value>,
}

/// One flushed batch's delivery destination (DW-121). Deliberately
/// small — one method, one batch, one answer — because the pipeline's
/// guarantees (ordering, bounded memory, drop-and-count) live in the
/// FLUSHER, not in the sink: an implementation only decides where a
/// batch goes and whether the receiver took it.
///
/// `webhook` is the one shipped implementation
/// ([`WebhookRecordSink`]); a Kafka producer is the documented second
/// slot (see the module docs and the config enum's), deferred by the
/// lean-deps rule. Implementations must enforce their OWN delivery
/// budget: the flusher calls `deliver_batch` inline and in order, so a
/// sink without a timeout is a stuck queue.
#[async_trait::async_trait]
pub trait RecordSink: Send + Sync {
    /// Deliver one flushed NDJSON batch of `records` lines. Returns
    /// whether the batch was accepted (2xx on some attempt for the
    /// webhook sink) — the flusher only logs; outcome counting is the
    /// implementation's, in the metric family it owns.
    async fn deliver_batch(&self, batch: Bytes, records: usize) -> bool;
}

/// The webhook batch sink (DW-121, `analytics_stream.sink.webhook`):
/// one POST per flushed batch, body the NDJSON lines, media type
/// `application/x-ndjson`, delivered through the shared DW-044 engine
/// (one total timeout per batch, exponential backoff, the transient
/// status set — see `events::webhook` for the contract).
pub struct WebhookRecordSink {
    target: WebhookTarget,
    obs: Arc<Observability>,
}

impl WebhookRecordSink {
    /// Compile the sink from its config block: URL decomposition and
    /// secret-reference header resolution through the same
    /// `WebhookTarget` bottom the alert deliverer uses, so the two
    /// pipelines cannot drift on URL, header, or retry semantics.
    /// Fails with a log-safe message (the caller skips the sink
    /// loudly, fail closed — the same compile-time backstop as alert
    /// webhook targets).
    pub fn compile(cfg: &AnalyticsStreamWebhook, obs: Arc<Observability>) -> Result<Self, String> {
        let target = WebhookTarget::compile_endpoint(
            &cfg.url,
            &cfg.headers,
            cfg.timeout_ms,
            cfg.max_attempts,
            cfg.backoff_base_ms,
            cfg.backoff_cap_ms,
        )?;
        Ok(WebhookRecordSink { target, obs })
    }

    /// The configured URL (operator config, safe to log).
    pub fn url(&self) -> &str {
        self.target.url()
    }
}

impl std::fmt::Debug for WebhookRecordSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookRecordSink")
            .field("url", &self.url())
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl RecordSink for WebhookRecordSink {
    async fn deliver_batch(&self, batch: Bytes, records: usize) -> bool {
        match webhook::deliver_with_retry(&self.target, batch, "application/x-ndjson", USER_AGENT)
            .await
        {
            webhook::DeliveryEnd::Delivered { attempts } => {
                tracing::debug!(
                    code = "record_stream_batch_delivered",
                    url = %self.url(),
                    records,
                    attempt = attempts,
                    "record batch delivered"
                );
                self.obs.record_access_stream("delivered", records as u64);
                true
            }
            webhook::DeliveryEnd::Failed { attempts, error } => {
                tracing::warn!(
                    code = "record_stream_batch_failed",
                    url = %self.url(),
                    records,
                    attempt = attempts,
                    "record batch delivery failed: {error}"
                );
                self.obs.record_access_stream("failed", records as u64);
                false
            }
        }
    }
}

/// The per-generation compiled stream state (DW-121): pushed to the
/// flusher over a watch channel by the dataplane's refresh. An empty
/// `sinks` list is the disabled state — the offer path checks a flag
/// the refresh derives from exactly this, so an unconfigured stream
/// never queues a record.
#[derive(Clone)]
pub struct StreamTargets {
    /// The compiled sinks, in delivery order (one today; the set is
    /// the seam a `kafka` slot would extend).
    pub sinks: Vec<Arc<dyn RecordSink>>,
    /// Maximum batch latency (ms), read live per flush cycle.
    pub flush_ms: u64,
    /// Maximum records per batch, read live per flush cycle.
    pub batch_max: usize,
}

impl StreamTargets {
    /// The disabled state (no block configured).
    pub fn empty() -> Self {
        StreamTargets {
            sinks: Vec::new(),
            flush_ms: crate::config::DEFAULT_STREAM_FLUSH_MS,
            batch_max: crate::config::DEFAULT_STREAM_BATCH_MAX as usize,
        }
    }
}

/// Compile one generation's stream state from the config block. A sink
/// whose compilation fails is skipped with a LOUD error (fail closed —
/// never delivered with placeholder bytes, never fatal to the
/// generation); if that leaves no sinks, the stream is disabled and
/// records drop at offer time with the counters as the witness.
pub fn compile_stream_targets(
    cfg: Option<&AnalyticsStreamConfig>,
    obs: &Arc<Observability>,
) -> StreamTargets {
    let Some(cfg) = cfg else {
        return StreamTargets::empty();
    };
    let mut sinks = Vec::new();
    match &cfg.sink {
        AnalyticsStreamSink::Webhook(wh) => match WebhookRecordSink::compile(wh, Arc::clone(obs)) {
            Ok(sink) => sinks.push(Arc::new(sink) as Arc<dyn RecordSink>),
            Err(error) => tracing::error!(
                code = "record_stream_sink_unusable",
                "analytics_stream sink skipped for this generation (fail closed): {error}"
            ),
        },
    }
    StreamTargets {
        flush_ms: cfg
            .flush_ms
            .unwrap_or(crate::config::DEFAULT_STREAM_FLUSH_MS),
        batch_max: cfg
            .batch_max
            .unwrap_or(crate::config::DEFAULT_STREAM_BATCH_MAX) as usize,
        sinks,
    }
}

/// The bounded record queue plus its counters and enabled flag. Share
/// via `Arc`; the dataplane holds it behind an `ArcSwapOption` set
/// once at boot.
pub struct AccessRecordStream {
    tx: mpsc::Sender<StreamRecord>,
    rx: Mutex<Option<mpsc::Receiver<StreamRecord>>>,
    /// Whether the current generation compiled at least one sink.
    /// Written only by the config refresh; read on every offer.
    enabled: AtomicBool,
    instance: Arc<str>,
    next_seq: AtomicU64,
    offered: AtomicU64,
    dropped: AtomicU64,
}

impl AccessRecordStream {
    /// New stream with an explicit channel capacity (the boot-time
    /// property; see the module docs).
    pub fn with_capacity(capacity: usize) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        Arc::new(AccessRecordStream {
            tx,
            rx: Mutex::new(Some(rx)),
            enabled: AtomicBool::new(false),
            instance: Arc::from(super::generate_instance_id()),
            next_seq: AtomicU64::new(0),
            offered: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        })
    }

    /// Take the single-consumer receiver (the flusher's end; the first
    /// caller wins).
    pub fn take_receiver(&self) -> Option<mpsc::Receiver<StreamRecord>> {
        self.rx
            .lock()
            .expect("record stream receiver lock poisoned")
            .take()
    }

    /// The instance label stamped on every envelope.
    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// Arm or disarm the offer path (the dataplane's refresh calls
    /// this with `!targets.sinks.is_empty()` every generation).
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Release);
    }

    /// Whether offers currently queue (read by tests and diagnostics).
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    /// Records offered (and queued) since process start.
    pub fn offered(&self) -> u64 {
        self.offered.load(Ordering::Relaxed)
    }

    /// Records dropped at offer time (queue full, or the flusher
    /// stalled behind a slow batch). The never-block posture's honest
    /// loss counter, surfaced as `dwara_access_records_dropped_total`.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// The request-completion hot path (DW-121): one enabled-flag
    /// check, one `try_send`. NEVER blocks; a full queue drops and
    /// counts (throttled log, the analytics writer's cadence). A
    /// disabled stream returns before allocating: unconfigured means
    /// one relaxed atomic load per request.
    pub fn offer(&self, rec: &AccessRecord) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let now = super::now_unix_ms();
        let record = StreamRecord::from_access(
            rec,
            format!("rec-{:x}-{:06x}", now, seq & 0xff_ffff),
            Arc::clone(&self.instance),
            now,
        );
        match self.tx.try_send(record) {
            Ok(()) => {
                self.offered.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                let n = self.dropped.fetch_add(1, Ordering::Relaxed);
                if n.is_multiple_of(4096) {
                    tracing::warn!(
                        code = "record_stream_channel_full",
                        total_dropped = n + 1,
                        "record stream channel full; dropping records \
                         (never blocking the dataplane)"
                    );
                }
            }
        }
    }
}

/// Refresh the stream's observation gauges at scrape time (the event
/// bus's model: the offer path bumps plain atomics, and only the
/// scrape couples them to the registry).
pub fn refresh_stream_gauges(stream: &AccessRecordStream, obs: &Observability) {
    obs.set_access_records_offered(stream.offered() as i64);
    obs.set_access_records_dropped(stream.dropped() as i64);
}

/// In-order batch assembly: appends serialized lines and answers
/// whether a flush trigger has been reached. One instance is the
/// flusher's whole in-flight state (bounded by `MAX_BATCH_BYTES`).
struct Batcher {
    lines: Vec<u8>,
    records: usize,
}

impl Batcher {
    fn new() -> Self {
        Batcher {
            lines: Vec::with_capacity(8 * 1024),
            records: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.records == 0
    }

    /// Append one serialized line.
    fn push(&mut self, line: &str) {
        self.lines.extend_from_slice(line.as_bytes());
        self.records += 1;
    }

    /// Whether a flush trigger has been reached (record count or byte
    /// cap).
    fn should_flush(&self, batch_max: usize) -> bool {
        self.records >= batch_max || self.lines.len() >= MAX_BATCH_BYTES
    }

    /// Take the assembled batch (body, record count); `None` when
    /// empty.
    fn take(&mut self) -> Option<(Bytes, usize)> {
        if self.records == 0 {
            return None;
        }
        let records = self.records;
        self.records = 0;
        Some((Bytes::from(std::mem::take(&mut self.lines)), records))
    }
}

/// The flusher loop (DW-121): drain the stream channel, assemble
/// ordered batches, and deliver each batch — inline, in order, one
/// retry cycle per batch — to the current generation's sinks. Stops on
/// shutdown after draining what is already queued into one final flush
/// attempt (the gateway is not a durable queue; an offer undelivered
/// at process death is lost with its counters as the witness).
///
/// Spawned by the dataplane
/// (`DataPlane::spawn_record_stream_flusher`) so the binary and tests
/// share one wiring path.
pub async fn run_stream_flusher(
    mut rx: mpsc::Receiver<StreamRecord>,
    targets: watch::Receiver<StreamTargets>,
    obs: Arc<Observability>,
    mut shutdown: watch::Receiver<()>,
) {
    let mut batch = Batcher::new();
    let mut tick = flush_tick(targets.borrow().flush_ms);
    loop {
        // Apply the current generation's cadence: a live reload that
        // changes flush_ms reschedules the ticker from now (missed
        // ticks delay, never burst).
        let flush_ms = targets.borrow().flush_ms;
        let batch_max = targets.borrow().batch_max.max(1);
        let record = tokio::select! {
            _ = shutdown.changed() => {
                // Drain what is already queued, flush it once, stop.
                while let Ok(r) = rx.try_recv() {
                    push_record(&mut batch, &r, &obs);
                }
                flush(&mut batch, &targets, &obs).await;
                return;
            }
            r = rx.recv() => match r {
                Some(r) => r,
                None => {
                    flush(&mut batch, &targets, &obs).await;
                    return;
                }
            },
            _ = tick.tick() => {
                if !batch.is_empty() {
                    flush(&mut batch, &targets, &obs).await;
                }
                reschedule(&mut tick, targets.borrow().flush_ms, flush_ms);
                continue;
            }
        };
        push_record(&mut batch, &record, &obs);
        if batch.should_flush(batch_max) {
            flush(&mut batch, &targets, &obs).await;
        }
        reschedule(&mut tick, targets.borrow().flush_ms, flush_ms);
    }
}

/// Serialize one record into the batch, enforcing the per-record byte
/// cap (drop-and-count, never truncate).
fn push_record(batch: &mut Batcher, record: &StreamRecord, obs: &Observability) {
    let line = record.line();
    if line.len() > MAX_RECORD_BYTES {
        tracing::warn!(
            code = "record_stream_record_dropped",
            size = line.len(),
            "record line exceeds the {} byte cap; dropped",
            MAX_RECORD_BYTES
        );
        obs.record_access_stream("dropped", 1);
        return;
    }
    batch.push(&line);
}

/// One flush: deliver the assembled batch to every sink, in order,
/// inline. An empty batch is a no-op.
async fn flush(batch: &mut Batcher, targets: &watch::Receiver<StreamTargets>, obs: &Observability) {
    let Some((body, records)) = batch.take() else {
        return;
    };
    let current = targets.borrow().clone();
    if current.sinks.is_empty() {
        // The generation disabled the stream with records still
        // queued: the tail is counted as dropped so the accounting
        // identity (offered == delivered + failed + dropped) holds —
        // an honest loss counter for a deliberate stop.
        tracing::debug!(
            code = "record_stream_tail_dropped",
            records,
            "record stream disabled with a queued tail; counted as dropped"
        );
        obs.record_access_stream("dropped", records as u64);
        return;
    }
    for sink in &current.sinks {
        // Sequential on purpose: order is the contract (see the module
        // docs). A failed batch does not stop the sinks after it.
        sink.deliver_batch(body.clone(), records).await;
    }
}

/// A flush-interval ticker (missed ticks delay — a backlog must not
/// burst).
fn flush_tick(flush_ms: u64) -> tokio::time::Interval {
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(flush_ms.max(1)));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick
}

/// Rebuild the ticker when the live cadence changed.
fn reschedule(tick: &mut tokio::time::Interval, current_ms: u64, was_ms: u64) {
    if current_ms != was_ms {
        *tick = flush_tick(current_ms);
    }
}
