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
//! **Editions:** OSS ships [`InMemoryAnalyticsSink`] (bounded ring buffer;
//! DW-021 builds the embedded rollup pipeline behind this trait). Ent
//! planned: federated sink + warehouse export.

use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;

use super::ExtensionsError;

/// A single analytics event.
///
/// Deliberately minimal and extensible: new fields are additive. `kind`
/// selects the event type (e.g. `request`); optional route/consumer
/// identifiers carry the common correlation keys, and `attributes` holds
/// everything else as string pairs to avoid a schema lock-in at M1.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Additional string key/value data.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn records_events_in_order() {
        let sink = InMemoryAnalyticsSink::new(8);
        let mut first = Event::request_now();
        first.route = Some("r1".into());
        sink.record(first.clone()).await.unwrap();
        sink.record(Event::request_now()).await.unwrap();
        let events = sink.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], first);
    }

    #[tokio::test]
    async fn full_ring_drops_oldest_and_keeps_capacity() {
        let sink = InMemoryAnalyticsSink::new(2);
        let oldest = tagged("oldest");
        sink.record(oldest.clone()).await.unwrap();
        sink.record(tagged("mid")).await.unwrap();
        sink.record(tagged("newest")).await.unwrap();
        let events = sink.events();
        assert_eq!(events.len(), 2, "size must stay at capacity");
        assert!(
            !events.contains(&oldest),
            "oldest event must be dropped, not the newest"
        );
        assert_eq!(events[0].attributes[0].0, "tag");
        assert_eq!(events[0].attributes[0].1, "mid");
        assert_eq!(events[1].attributes[0].1, "newest");
    }

    #[tokio::test]
    async fn snapshot_reflects_latest_recorded_event() {
        let sink = InMemoryAnalyticsSink::new(8);
        assert!(sink.events().is_empty());
        let latest = tagged("latest");
        sink.record(latest.clone()).await.unwrap();
        assert_eq!(sink.events(), vec![latest]);
    }

    #[test]
    fn request_now_builds_request_event_with_recent_timestamp() {
        let before = now_ms();
        let event = Event::request_now();
        let after = now_ms();
        assert_eq!(event.kind, "request");
        assert!(event.timestamp_ms >= before && event.timestamp_ms <= after);
        assert_eq!(event.route, None);
        assert!(event.attributes.is_empty());
    }

    fn tagged(tag: &str) -> Event {
        let mut event = Event::request_now();
        event.attributes = vec![("tag".to_owned(), tag.to_owned())];
        event
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
}
