//! Analytics sink extension point.
//!
//! # Contract: [`AnalyticsSink`]
//!
//! **Purpose:** accept request/flow events emitted by the dataplane. The
//! sink is fire-and-forget from the caller's perspective.
//!
//! **Semantics:** `record` appends one event and must not block the caller
//! beyond a bounded enqueue. Implementations bound themselves (ring buffer,
//! batch, drop-oldest) — an analytics overload must never stall the
//! dataplane. Ordering is best-effort; events may be coalesced or dropped
//! under pressure, and `record` returning `Ok` means "accepted", not
//! "durably persisted". Events must not contain secret material.
//!
//! **Failure model:** only enqueue failures (closed channel, full local
//! buffer) produce [`ExtensionsError::Backend`]; call sites should log and
//! continue, never fail the request. No retries.
//!
//! **Editions:** OSS ships [`InMemoryAnalyticsSink`] (bounded ring buffer)
//! and the DW-043 embedded store (`analytics::EmbeddedAnalytics`, SQLite
//! rollups), which implements this contract on top of the richer
//! per-request fields below. Ent planned: federated sink + warehouse
//! export (DW-095). The raw-record firehose (DW-121) deliberately does
//! NOT implement this contract: it streams the access record itself
//! (with `request_id` and the redacted path this event shape omits)
//! through its own sink seam — see `events::stream`.

use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;

use super::ExtensionsError;

/// A single analytics event.
///
/// Deliberately minimal and extensible: new fields are additive. `kind`
/// selects the event type (e.g. `request`); optional route/consumer
/// identifiers carry the common correlation keys, and `attributes` holds
/// everything else as string pairs to avoid a schema lock-in at M1. The
/// DW-043 request-completion fields (listener, method, duration,
/// outcomes) were added additively so the embedded store consumes this
/// type directly; `attributes` carries custom analytics dimensions.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Event {
    /// Event type discriminator, e.g. `request`.
    pub kind: String,
    /// Unix epoch milliseconds.
    pub timestamp_ms: u64,
    /// Route name, when the event is tied to a matched route.
    pub route: Option<String>,
    /// Consumer name, when authenticated.
    pub consumer: Option<String>,
    /// Upstream endpoint the request was forwarded to, if any.
    pub endpoint: Option<String>,
    /// Upstream response status code, if a response was produced.
    pub status: Option<u16>,
    /// Listener that accepted the request (DW-043).
    pub listener: Option<String>,
    /// HTTP method (DW-043).
    pub method: Option<String>,
    /// End-to-end request duration in milliseconds (DW-043).
    pub duration_ms: Option<f64>,
    /// Upstream attempts made (DW-043).
    pub attempts: Option<u32>,
    /// The request was rejected by a rate limit (DW-043).
    pub rate_limited: bool,
    /// The request failed through an open breaker (DW-043).
    pub broken: bool,
    /// The request was shed by admission control (DW-043).
    pub shed: bool,
    /// Additional string key/value data (custom dimensions ride here).
    pub attributes: Vec<(String, String)>,
}

impl Event {
    /// Build a `request` event stamped with the current time.
    pub fn request_now() -> Self {
        Self {
            kind: "request".to_owned(),
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            route: None,
            consumer: None,
            endpoint: None,
            status: None,
            listener: None,
            method: None,
            duration_ms: None,
            attempts: None,
            rate_limited: false,
            broken: false,
            shed: false,
            attributes: Vec::new(),
        }
    }
}

/// Swappable analytics event sink.
#[async_trait]
pub trait AnalyticsSink: Send + Sync {
    /// Accept one event for eventual processing.
    async fn record(&self, event: Event) -> Result<(), ExtensionsError>;
}

/// Bounded in-memory ring-buffer sink (OSS skeleton).
///
/// Keeps the most recent `capacity` events; `record` on a full buffer drops
/// the oldest entry. DW-021 replaces the consumer side, not this contract.
#[derive(Debug)]
pub struct InMemoryAnalyticsSink {
    events: Mutex<VecDeque<Event>>,
    capacity: usize,
}

impl InMemoryAnalyticsSink {
    /// New sink retaining the most recent `capacity` events.
    pub fn new(capacity: usize) -> Self {
        Self {
            events: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    /// Snapshot the currently retained events, oldest first.
    pub fn events(&self) -> Vec<Event> {
        self.events
            .lock()
            .expect("analytics state poisoned")
            .clone()
            .into()
    }
}

#[async_trait]
impl AnalyticsSink for InMemoryAnalyticsSink {
    async fn record(&self, event: Event) -> Result<(), ExtensionsError> {
        let mut events = self.events.lock().expect("analytics state poisoned");
        if events.len() == self.capacity {
            events.pop_front();
        }
        events.push_back(event);
        Ok(())
    }
}
