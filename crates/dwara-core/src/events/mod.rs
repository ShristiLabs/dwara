//! In-process event bus (DW-044, feature analysis section 5 "Platform"):
//! the notice plumbing behind alert & event webhooks.
//!
//! # What it is
//!
//! A bounded `tokio::sync::mpsc` channel plus cheap clone-able
//! [`Emitter`] handles. Subsystems that own a state machine worth
//! alerting on (the circuit breaker, passive/active health, the config
//! publish pipeline) emit a small [`Event`] at every transition; the
//! webhook deliverer ([`webhook`]) drains the channel in a background
//! task and POSTs each event to the configured targets. std + tokio
//! only — no dependency beyond `config` (the schema types and their
//! bounds) and `observability` (delivery-outcome metrics).
//!
//! # Emission contract: never backpressure the dataplane
//!
//! [`Emitter::emit`] is a `try_send` onto the bounded channel. When the
//! queue is full (or nobody is draining it) the event is DROPPED and the
//! drop is counted ([`EventBus::dropped_total`], surfaced as the
//! `dwara_events_dropped_total` gauge at scrape time). There is no
//! blocking wait, no unbounded buffer growth, and no failure mode that
//! can stall the caller — emission sites sit on request paths (the
//! breaker `check`/`report` wire) and on the reload path, and a
//! misbehaving webhook target must never show up as gateway latency.
//! The drop policy is drop-NEWEST at emit time (the oldest queued
//! events keep their place in line): a slow drain sheds the burst, not
//! the history.
//!
//! # Event kinds and payloads
//!
//! Kinds are a closed set ([`EventKind::ALL`]) — a webhook's `events`
//! list is validated against it, so a config cannot subscribe to an
//! event the gateway will never emit. The payload is a flat struct of
//! bounded config labels and numbers ([`EventPayload`]); there is no
//! free-form field, so the serialized envelope is small by construction
//! (the deliverer still enforces a hard byte cap). No request-derived
//! data (paths, headers) enters a payload — identifiers are
//! CONFIG-DECLARED labels only (`upstream`, and `consumer` for quota
//! budgets, whose consumers are config records by construction in this
//! edition) — an envelope is safe to POST to a third party by
//! construction.
//!
//! Emission sites:
//!
//! - breaker state transitions (DW-015): opened (with the rule that
//!   tripped), half-open, closed (`resilience::breaker`);
//! - outlier ejection and recovery (DW-012 passive + DW-013 active —
//!   both report through the same tracker, so both emit):
//!   `endpoint_ejected`, `endpoint_recovered`
//!   (`resilience::health`);
//! - config published (generation + content hash + route count) and
//!   config rejected (validation issue count) (`snapshot`);
//! - a consumer's request budget crossing the near-limit threshold
//!   (DW-033): `quota_near_limit`, edge-triggered once per (consumer,
//!   budget, window) from the dataplane's quota phase
//!   (`dataplane::proxy` — the emit lives there because the state
//!   domain must not import events).
//!
//! Deliberately NOT emitted (documented hook points, not gaps):
//!
//! - rate-limiter eviction (#132): already observable as
//!   `dwara_rate_limiter_evictions_total`; an event per eviction would
//!   be high-frequency noise, not an alert.
//!
//! # Failure isolation
//!
//! The deliverer (see `webhook`) runs as its own task, dispatches each
//! delivery as a further task, bounds concurrent deliveries with a
//! semaphore (over-cap deliveries are dropped and counted, never
//! queued), and gives every delivery ONE total timeout shared by all
//! its retry attempts. A slow, hung, or dead target can therefore
//! consume at most `timeout_ms` of one semaphore slot — never the
//! queue, never the emit path, never the dataplane.
//!
//! # Bus identity and lifecycle
//!
//! One bus per gateway process, owned by the `DataPlane` and attached
//! to the `ConfigState` it was built from (so config publish events and
//! dataplane events share one queue and one deliverer). The
//! `gateway` field of every envelope identifies the instance:
//! `dwara-<pid>-<boot unix ms>` — unique per process start, no
//! hostname dependency, stable for the process lifetime.

pub mod stream;
pub mod webhook;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::observability::Observability;

/// Capacity of the event channel (DW-044). Bound chosen for alert-rate
/// shapes: transition events are rare per upstream (a breaker flapping
/// once per `open_ms`, ejections once per `eject_ms`), so 256 queued
/// events is already a gateway in serious trouble — beyond it, drops
/// (counted, gauge-exported) are the right answer, not buffering.
pub const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Every event kind the gateway emits (DW-044). Closed set: webhook
/// `events` lists are validated against [`EventKind::from_config`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A per-upstream circuit breaker moved closed -> open. Payload:
    /// upstream, detail (the rule that tripped).
    BreakerOpened,
    /// An open breaker's cooling-off elapsed: the next request becomes
    /// a half-open probe. Payload: upstream.
    BreakerHalfOpen,
    /// A half-open probe succeeded: the breaker closed again. Payload:
    /// upstream.
    BreakerClosed,
    /// Passive or active health ejected an endpoint from rotation.
    /// Payload: upstream, endpoint.
    EndpointEjected,
    /// An ejected endpoint recovered (successful probe or fail-open
    /// success) and is back in rotation. Payload: upstream, endpoint.
    EndpointRecovered,
    /// A config generation was validated, compiled, and published.
    /// Payload: generation, content_hash, route_count.
    ConfigPublished,
    /// A config candidate was rejected (validation or compile failure);
    /// the previously published generation keeps serving. Payload:
    /// issue_count, generation (the one still running).
    ConfigRejected,
    /// A consumer's request budget crossed the near-limit threshold
    /// (80% of the window's cap; DW-033). Payload: consumer, detail
    /// (the budget: "daily" or "monthly"), used, limit. Edge-triggered
    /// once per (consumer, budget, window): the SECOND crossing inside
    /// one window is not re-emitted, and the counter resets with the
    /// window itself.
    QuotaNearLimit,
}

impl EventKind {
    /// The closed set, in display order. The source of webhook `events`
    /// validation and of every doc list — keep the two in lockstep.
    pub const ALL: &'static [EventKind] = &[
        EventKind::BreakerOpened,
        EventKind::BreakerHalfOpen,
        EventKind::BreakerClosed,
        EventKind::EndpointEjected,
        EventKind::EndpointRecovered,
        EventKind::ConfigPublished,
        EventKind::ConfigRejected,
        EventKind::QuotaNearLimit,
    ];

    /// Stable wire/config spelling (serde's snake_case form, spelled out
    /// so it can be used in labels and validation messages without
    /// serializing).
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::BreakerOpened => "breaker_opened",
            EventKind::BreakerHalfOpen => "breaker_half_open",
            EventKind::BreakerClosed => "breaker_closed",
            EventKind::EndpointEjected => "endpoint_ejected",
            EventKind::EndpointRecovered => "endpoint_recovered",
            EventKind::ConfigPublished => "config_published",
            EventKind::ConfigRejected => "config_rejected",
            EventKind::QuotaNearLimit => "quota_near_limit",
        }
    }

    /// Parse one `gateway.webhooks[].events[]` entry. Unknown spellings
    /// are `None` (validation turns them into an issue naming the
    /// accepted set).
    pub fn from_config(value: &str) -> Option<EventKind> {
        EventKind::ALL.iter().copied().find(|k| k.as_str() == value)
    }
}

/// The payload of one event: a flat set of bounded labels and numbers.
/// Every field is optional (each event kind sets the fields it owns);
/// unset fields are omitted from the serialized envelope, and there is
/// deliberately NO free-form/detail-string-from-input field — an
/// envelope must stay small and safe to hand to a third party.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct EventPayload {
    /// Upstream name (breaker and ejection events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    /// Endpoint `address:port` (ejection events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// The rule that tripped a breaker ("consecutive_failures" or
    /// "error_ratio") or the probe outcome that closed it — a static
    /// string, never operator- or request-derived text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<&'static str>,
    /// Published generation number (config events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    /// Per-process change-detection token of the published config
    /// (config_published; same caveats as the snapshot content hash).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<u64>,
    /// Routes in the published generation (config_published).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_count: Option<usize>,
    /// Validation issues counted on a rejected config (config_rejected).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue_count: Option<usize>,
    /// Config-declared consumer name (quota_near_limit, DW-033). Budgets
    /// attach to CONFIG consumer records only in this edition, so this
    /// is a config label, never a request-derived or admin-entered
    /// string (see the module docs' payload-safety contract).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer: Option<String>,
    /// Requests counted in the budget's current window
    /// (quota_near_limit).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used: Option<u64>,
    /// The budget's configured cap (quota_near_limit).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
}

impl EventPayload {
    /// Payload for a breaker transition of `upstream` (DW-044).
    pub fn breaker(upstream: &str, detail: Option<&'static str>) -> Self {
        EventPayload {
            upstream: Some(upstream.to_string()),
            detail,
            ..EventPayload::default()
        }
    }

    /// Payload for an endpoint ejection/recovery event (DW-044).
    pub fn endpoint(upstream: &str, endpoint: &str) -> Self {
        EventPayload {
            upstream: Some(upstream.to_string()),
            endpoint: Some(endpoint.to_string()),
            ..EventPayload::default()
        }
    }

    /// Payload for a quota near-limit crossing (DW-033): `budget` is the
    /// static budget name carried in `detail` ("daily"/"monthly").
    pub fn quota(consumer: &str, budget: &'static str, used: u64, limit: u64) -> Self {
        EventPayload {
            consumer: Some(consumer.to_string()),
            detail: Some(budget),
            used: Some(used),
            limit: Some(limit),
            ..EventPayload::default()
        }
    }
}

/// One emitted event. `id` and `timestamp_ms` are assigned by the bus at
/// emit time (single place), `gateway` identifies the process.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Event {
    /// Process-unique, monotonically assigned: `evt-<hex unix ms>-<hex
    /// counter>` (the request-id shape; a correlation handle, not a
    /// secret).
    pub id: String,
    pub kind: EventKind,
    /// Emission time, Unix epoch milliseconds.
    pub timestamp_ms: u64,
    /// Instance label (`dwara-<pid>-<boot ms>`; see the module docs).
    pub gateway: String,
    pub payload: EventPayload,
}

/// Wall-clock Unix milliseconds (the same clock reading the resilience
/// domain uses; a monotonic clock cannot be serialized into an envelope).
pub(crate) fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Process-unique instance label: `dwara-<pid>-<boot unix ms hex>`.
/// Two gateway processes on one host never share it; it carries no
/// hostname (a third-party envelope reader needs process identity, not
/// topology).
pub fn generate_instance_id() -> String {
    format!("dwara-{}-{:x}", std::process::id(), now_unix_ms())
}

/// The bounded event queue plus its identity and counters. Share via
/// `Arc`; emitters hold an [`Emitter`] (a cheap clone of that Arc).
///
/// Construction: [`EventBus::with_receiver`] hands the single-consumer
/// receiver to the deliverer; [`EventBus::new`] creates a bus nobody
/// drains yet (the `DataPlane` does this before spawning its deliverer,
/// so startup publishes are queued, not lost — and if no deliverer is
/// ever spawned, every emit is a counted drop, never a block).
pub struct EventBus {
    tx: mpsc::Sender<Event>,
    rx: std::sync::Mutex<Option<mpsc::Receiver<Event>>>,
    instance: Arc<str>,
    next_id: AtomicU64,
    emitted_total: AtomicU64,
    dropped_total: AtomicU64,
}

impl EventBus {
    /// New bus with [`EVENT_CHANNEL_CAPACITY`] and no receiver taken.
    pub fn new() -> Arc<Self> {
        Self::with_capacity(EVENT_CHANNEL_CAPACITY)
    }

    /// New bus with an explicit capacity (tests).
    pub fn with_capacity(capacity: usize) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        Arc::new(EventBus {
            tx,
            rx: std::sync::Mutex::new(Some(rx)),
            instance: Arc::from(generate_instance_id()),
            next_id: AtomicU64::new(0),
            emitted_total: AtomicU64::new(0),
            dropped_total: AtomicU64::new(0),
        })
    }

    /// New bus, returning the receiver alongside (the deliverer's end).
    pub fn with_receiver(capacity: usize) -> (Arc<Self>, mpsc::Receiver<Event>) {
        let bus = Self::with_capacity(capacity);
        let rx = bus
            .rx
            .lock()
            .expect("event receiver lock poisoned")
            .take()
            .expect("a fresh bus holds its receiver");
        (bus, rx)
    }

    /// Take the single-consumer receiver (the first caller wins; later
    /// callers get `None` — one deliverer per bus, by design).
    pub fn take_receiver(&self) -> Option<mpsc::Receiver<Event>> {
        self.rx.lock().expect("event receiver lock poisoned").take()
    }

    /// The instance label stamped on every envelope.
    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// Events handed to the channel since process start.
    pub fn emitted_total(&self) -> u64 {
        self.emitted_total.load(Ordering::Relaxed)
    }

    /// Events dropped at emit time (queue full, or no deliverer
    /// draining). Surfaced as `dwara_events_dropped_total`.
    pub fn dropped_total(&self) -> u64 {
        self.dropped_total.load(Ordering::Relaxed)
    }

    /// A cheap emitter handle (clone of the bus Arc). A fresh `Arc`
    /// bump per call site is fine: emitters are taken once at build
    /// time, not per event.
    pub fn emitter(self: &Arc<Self>) -> Emitter {
        Emitter {
            bus: Arc::clone(self),
        }
    }

    /// Assign identity and enqueue, or count the drop. The ONE emit
    /// path: never blocks, never allocates beyond the event itself.
    fn dispatch(&self, kind: EventKind, payload: EventPayload) {
        let n = self.next_id.fetch_add(1, Ordering::Relaxed);
        let event = Event {
            id: format!("evt-{:x}-{:06x}", now_unix_ms(), n & 0xff_ffff),
            kind,
            timestamp_ms: now_unix_ms(),
            gateway: self.instance.to_string(),
            payload,
        };
        match self.tx.try_send(event) {
            Ok(()) => {
                self.emitted_total.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped_total.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    code = "event_dropped_queue_full",
                    kind = kind.as_str(),
                    "event queue full; dropped (and counted) rather than blocking the caller"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.dropped_total.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// A clone-able emission handle (an `Arc<EventBus>`). `Option<Emitter>`
/// at every emission site: `None` (tests, unwired constructions) is a
/// documented no-op, so the subsystems never need a bus to exist.
#[derive(Clone)]
pub struct Emitter {
    bus: Arc<EventBus>,
}

impl Emitter {
    /// Emit one event; drop-and-count on a full/undrained queue.
    pub fn emit(&self, kind: EventKind, payload: EventPayload) {
        self.bus.dispatch(kind, payload);
    }

    /// An emitter pre-bound to one upstream's label (breaker transitions
    /// and endpoint events): keeps `upstream` consistent across every
    /// event that upstream's state machines emit.
    pub fn for_upstream(&self, upstream: &str) -> UpstreamEmitter {
        UpstreamEmitter {
            emitter: self.clone(),
            upstream: Arc::from(upstream),
        }
    }
}

impl std::fmt::Debug for Emitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Emitter")
            .field("gateway", &self.bus.instance.as_ref())
            .finish_non_exhaustive()
    }
}

/// [`Emitter`] pre-bound to an upstream label (DW-044): held by the
/// per-upstream circuit breaker and balancer.
#[derive(Clone, Debug)]
pub struct UpstreamEmitter {
    emitter: Emitter,
    upstream: Arc<str>,
}

impl UpstreamEmitter {
    /// Emit a breaker state transition of the bound upstream. `detail`
    /// is a static string naming the rule/outcome.
    pub fn breaker_transition(&self, kind: EventKind, detail: Option<&'static str>) {
        self.emitter
            .emit(kind, EventPayload::breaker(&self.upstream, detail));
    }

    /// Emit an endpoint ejection/recovery event of the bound upstream.
    pub fn endpoint_event(&self, kind: EventKind, endpoint: &str) {
        self.emitter
            .emit(kind, EventPayload::endpoint(&self.upstream, endpoint));
    }

    /// Bind one endpoint label: the handle the per-endpoint health
    /// tracker holds, so every ejection/recovery of that endpoint is
    /// labeled consistently.
    pub fn for_endpoint(&self, endpoint: &str) -> EndpointEvents {
        EndpointEvents {
            upstream: self.clone(),
            endpoint: Arc::from(endpoint),
        }
    }
}

/// [`UpstreamEmitter`] further bound to one endpoint label (DW-044):
/// held by the per-endpoint passive health tracker
/// (`resilience::health::EndpointHealth`), which knows its state
/// machine but not its own `address:port` (the balancer does).
#[derive(Clone, Debug)]
pub struct EndpointEvents {
    upstream: UpstreamEmitter,
    endpoint: Arc<str>,
}

impl EndpointEvents {
    /// Emit one endpoint event (`EndpointEjected` or
    /// `EndpointRecovered`) with both labels filled from the bindings.
    pub fn emit(&self, kind: EventKind) {
        self.upstream.emitter.emit(
            kind,
            EventPayload::endpoint(&self.upstream.upstream, &self.endpoint),
        );
    }
}

/// Refresh the event-bus observation gauge at scrape time (the
/// `dwara_rate_limiter_evictions_total` model: the emit path bumps a
/// plain atomic, and only the scrape couples it to the registry — a
/// gauge rather than a counter so the hot path stays registry-free).
pub fn refresh_event_gauges(bus: &EventBus, obs: &Observability) {
    obs.set_events_dropped(bus.dropped_total() as i64);
    obs.set_events_emitted(bus.emitted_total() as i64);
}
