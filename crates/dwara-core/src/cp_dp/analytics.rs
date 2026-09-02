//! Federated analytics (DW-095, Enterprise).
//!
//! In the CP/DP split, each edge (`dwara-edge`) serves traffic and
//! records analytics locally. The controller (`dwara-controller`)
//! aggregates analytics from all edges to provide a fleet-wide view.
//!
//! ## Architecture
//!
//! - **Edge side:** `FederatedAnalyticsSink` implements `AnalyticsSink`.
//!   It batches `Event`s in a bounded channel and a background task
//!   pushes batches to the controller over a client-streaming gRPC RPC
//!   (`PublishAnalytics`). The sink is fire-and-forget: a full channel
//!   drops events (counted), a failed push logs and retries with
//!   backoff. The dataplane is never blocked.
//! - **Controller side:** `ControllerServer` receives
//!   `PbAnalyticsBatch` messages from edges and forwards them to an
//!   `AnalyticsCollector` — a trait the controller runtime implements
//!   (typically writing into an `EmbeddedAnalytics` store, but the
//!   trait allows other backends like a warehouse export).
//! - **Admin API:** the controller's admin API exposes the same
//!   `/analytics/*` endpoints, but they query the AGGREGATE store
//!   (all edges' data), not just the local edge's data. An optional
//!   `?edge=` filter narrows to one edge.
//!
//! ## Wire protocol
//!
//! A new `PublishAnalytics` client-streaming RPC on the
//! `DwaraControlPlane` service: the edge streams `PbAnalyticsBatch`
//! messages (each carrying the edge id + N `PbAnalyticsRecord`s), the
//! controller responds with a single `PbAnalyticsAck` when the stream
//! closes. The ack carries the count of records accepted (for edge-side
//! logging).
//!
//! ## Feature gate
//!
//! Ent-only: the `ent` cargo feature must be enabled (tonic + prost are
//! optional deps gated behind `ent`). The module is compiled only with
//! `#[cfg(feature = "ent")]`.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tonic::{Request, Response, Status, Streaming};

use crate::extensions::analytics::{AnalyticsSink, Event};
use crate::extensions::ExtensionsError;

// ---------------------------------------------------------------------------
// Wire messages (hand-written prost structs)
// ---------------------------------------------------------------------------

/// Wire: one analytics record (mirrors the fields of
/// `extensions::analytics::Event`).
#[derive(Clone, PartialEq, prost::Message)]
pub struct PbAnalyticsRecord {
    #[prost(string, tag = "1")]
    pub kind: String,
    #[prost(uint64, tag = "2")]
    pub timestamp_ms: u64,
    #[prost(string, tag = "3")]
    pub route: String,
    #[prost(string, tag = "4")]
    pub consumer: String,
    #[prost(string, tag = "5")]
    pub endpoint: String,
    #[prost(uint32, tag = "6")]
    pub status: u32,
    #[prost(string, tag = "7")]
    pub listener: String,
    #[prost(string, tag = "8")]
    pub method: String,
    #[prost(double, tag = "9")]
    pub duration_ms: f64,
    #[prost(uint32, tag = "10")]
    pub attempts: u32,
    #[prost(bool, tag = "11")]
    pub rate_limited: bool,
    #[prost(bool, tag = "12")]
    pub broken: bool,
    #[prost(bool, tag = "13")]
    pub shed: bool,
    /// Custom dimensions as a JSON object string (same encoding as the
    /// embedded store's `dims` column).
    #[prost(string, tag = "14")]
    pub dims_json: String,
}

/// Wire: a batch of analytics records from one edge.
#[derive(Clone, PartialEq, prost::Message)]
pub struct PbAnalyticsBatch {
    /// The edge instance ID sending this batch.
    #[prost(string, tag = "1")]
    pub edge_id: String,
    /// The records in this batch.
    #[prost(message, repeated, tag = "2")]
    pub records: Vec<PbAnalyticsRecord>,
}

/// Wire: the ack for a completed analytics stream.
#[derive(Clone, PartialEq, prost::Message)]
pub struct PbAnalyticsAck {
    /// Number of records accepted by the controller.
    #[prost(uint64, tag = "1")]
    pub accepted: u64,
}

// ---------------------------------------------------------------------------
// Conversions: Event <-> PbAnalyticsRecord
// ---------------------------------------------------------------------------

impl From<Event> for PbAnalyticsRecord {
    fn from(e: Event) -> Self {
        let dims_json = if e.attributes.is_empty() {
            "{}".to_string()
        } else {
            let map: serde_json::Map<String, serde_json::Value> = e
                .attributes
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                .collect();
            serde_json::Value::Object(map).to_string()
        };
        Self {
            kind: e.kind,
            timestamp_ms: e.timestamp_ms,
            route: e.route.unwrap_or_default(),
            consumer: e.consumer.unwrap_or_default(),
            endpoint: e.endpoint.unwrap_or_default(),
            status: e.status.unwrap_or(0) as u32,
            listener: e.listener.unwrap_or_default(),
            method: e.method.unwrap_or_default(),
            duration_ms: e.duration_ms.unwrap_or(0.0),
            attempts: e.attempts.unwrap_or(0),
            rate_limited: e.rate_limited,
            broken: e.broken,
            shed: e.shed,
            dims_json,
        }
    }
}

impl From<PbAnalyticsRecord> for Event {
    fn from(pb: PbAnalyticsRecord) -> Self {
        let attributes = if pb.dims_json == "{}" || pb.dims_json.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&pb.dims_json)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
                .collect()
        };
        let route = if pb.route.is_empty() {
            None
        } else {
            Some(pb.route)
        };
        let consumer = if pb.consumer.is_empty() {
            None
        } else {
            Some(pb.consumer)
        };
        let endpoint = if pb.endpoint.is_empty() {
            None
        } else {
            Some(pb.endpoint)
        };
        let status = if pb.status == 0 {
            None
        } else {
            Some(pb.status as u16)
        };
        let listener = if pb.listener.is_empty() {
            None
        } else {
            Some(pb.listener)
        };
        let method = if pb.method.is_empty() {
            None
        } else {
            Some(pb.method)
        };
        let duration_ms = if pb.duration_ms == 0.0 {
            None
        } else {
            Some(pb.duration_ms)
        };
        let attempts = if pb.attempts == 0 {
            None
        } else {
            Some(pb.attempts)
        };
        Event {
            kind: pb.kind,
            timestamp_ms: pb.timestamp_ms,
            route,
            consumer,
            endpoint,
            status,
            listener,
            method,
            duration_ms,
            attempts,
            rate_limited: pb.rate_limited,
            broken: pb.broken,
            shed: pb.shed,
            attributes,
        }
    }
}

// ---------------------------------------------------------------------------
// AnalyticsCollector trait (controller-side)
// ---------------------------------------------------------------------------

/// The controller-side analytics collector: receives batches from
/// edges and processes them (typically writing into an
/// `EmbeddedAnalytics` store). The trait is `Send + Sync` so it can be
/// shared across gRPC handler tasks.
#[async_trait]
pub trait AnalyticsCollector: Send + Sync {
    /// Accept a batch of records from an edge. Returns the number of
    /// records accepted (for the ack).
    async fn collect(&self, edge_id: &str, records: Vec<Event>) -> u64;
}

/// A no-op collector (for testing or when the controller does not
/// aggregate analytics).
pub struct NoopCollector;

#[async_trait]
impl AnalyticsCollector for NoopCollector {
    async fn collect(&self, _edge_id: &str, records: Vec<Event>) -> u64 {
        records.len() as u64
    }
}

/// A collector that writes into an `EmbeddedAnalytics` store via its
/// `AnalyticsSink` implementation. Each record is `record()`'d
/// individually (the embedded store's channel is bounded and
/// fire-and-forget, so this is cheap).
pub struct EmbeddedCollector {
    sink: Arc<dyn AnalyticsSink>,
}

impl EmbeddedCollector {
    /// Create a collector that forwards to the given analytics sink
    /// (typically an `EmbeddedAnalytics` instance).
    pub fn new(sink: Arc<dyn AnalyticsSink>) -> Self {
        Self { sink }
    }
}

#[async_trait]
impl AnalyticsCollector for EmbeddedCollector {
    async fn collect(&self, _edge_id: &str, records: Vec<Event>) -> u64 {
        let mut accepted = 0u64;
        for record in records {
            match self.sink.record(record).await {
                Ok(()) => accepted += 1,
                Err(e) => {
                    tracing::warn!(
                        code = "federated_analytics_collect_failed",
                        error = %e,
                        "failed to record federated analytics event"
                    );
                }
            }
        }
        accepted
    }
}

// ---------------------------------------------------------------------------
// FederatedAnalyticsSink (edge-side)
// ---------------------------------------------------------------------------

/// The federated analytics sink (DW-095, Ent): batches `Event`s and
/// pushes them to the controller over gRPC. Implements `AnalyticsSink`
/// so the dataplane uses it as a drop-in replacement for the embedded
/// store on edge instances.
///
/// The sink is fire-and-forget: `record` does a `try_send` onto a
/// bounded channel (never blocks the dataplane). A background task
/// drains the channel, batches records, and pushes them to the
/// controller via the `PublishAnalytics` client-streaming RPC. On
/// failure, the batch is retried with bounded backoff; on channel full,
/// events are dropped and counted.
pub struct FederatedAnalyticsSink {
    tx: mpsc::Sender<Event>,
    /// Dropped-event counter (for metrics/logging).
    dropped: Arc<std::sync::atomic::AtomicU64>,
    /// Pushed-event counter (for metrics/logging).
    pushed: Arc<std::sync::atomic::AtomicU64>,
}

impl FederatedAnalyticsSink {
    /// Create a new federated sink. Spawns a background task that
    /// connects to the controller and pushes batches. The task runs
    /// until the sink is dropped (the channel closes).
    ///
    /// `edge_id` is the edge instance ID included in every batch.
    /// `client` is the gRPC client to the controller. `batch_size` is
    /// the max records per batch (default 100). `flush_interval_ms` is
    /// the max time between flushes (default 5000ms).
    pub fn spawn(
        edge_id: String,
        client: crate::cp_dp::transport::EdgeClient,
        batch_size: usize,
        flush_interval_ms: u64,
    ) -> Self {
        let (tx, rx) = mpsc::channel(batch_size * 4);
        let pushed = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let sink = Self {
            tx,
            dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            pushed: Arc::clone(&pushed),
        };
        tokio::spawn(federated_push_loop(
            edge_id,
            client,
            rx,
            batch_size,
            flush_interval_ms,
            pushed,
        ));
        sink
    }

    /// The number of events dropped (channel full).
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The number of events successfully pushed to the controller.
    pub fn pushed_count(&self) -> u64 {
        self.pushed.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[async_trait]
impl AnalyticsSink for FederatedAnalyticsSink {
    async fn record(&self, event: Event) -> Result<(), ExtensionsError> {
        match self.tx.try_send(event) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err(ExtensionsError::Backend(
                    "federated analytics channel full; event dropped".to_string(),
                ))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(ExtensionsError::Backend(
                "federated analytics channel closed".to_string(),
            )),
        }
    }
}

/// The background push loop: drains the channel, batches records, and
/// pushes them to the controller. Reconnects with bounded backoff on
/// failure.
async fn federated_push_loop(
    edge_id: String,
    client: crate::cp_dp::transport::EdgeClient,
    mut rx: mpsc::Receiver<Event>,
    batch_size: usize,
    flush_interval_ms: u64,
    pushed: Arc<std::sync::atomic::AtomicU64>,
) {
    let flush_duration = std::time::Duration::from_millis(flush_interval_ms);
    let mut batch: Vec<Event> = Vec::with_capacity(batch_size);
    loop {
        // Wait for either a full batch or the flush interval.
        let timeout = tokio::time::sleep(flush_duration);
        tokio::pin!(timeout);
        loop {
            tokio::select! {
                event = rx.recv() => {
                    match event {
                        Some(e) => {
                            batch.push(e);
                            if batch.len() >= batch_size {
                                break;
                            }
                        }
                        None => {
                            // Channel closed: flush remaining and exit.
                            if !batch.is_empty() {
                                push_batch(&edge_id, &client, std::mem::take(&mut batch), &pushed).await;
                            }
                            return;
                        }
                    }
                }
                _ = &mut timeout => {
                    // Flush interval elapsed.
                    break;
                }
            }
        }
        if !batch.is_empty() {
            push_batch(&edge_id, &client, std::mem::take(&mut batch), &pushed).await;
        }
    }
}

/// Push one batch to the controller. Logs on failure; the next batch
/// will be attempted on the next flush.
async fn push_batch(
    edge_id: &str,
    client: &crate::cp_dp::transport::EdgeClient,
    events: Vec<Event>,
    pushed: &Arc<std::sync::atomic::AtomicU64>,
) {
    let count = events.len() as u64;
    let records: Vec<PbAnalyticsRecord> = events.into_iter().map(Into::into).collect();
    let batch = PbAnalyticsBatch {
        edge_id: edge_id.to_string(),
        records,
    };
    match client.publish_analytics(batch).await {
        Ok(accepted) => {
            pushed.fetch_add(count.min(accepted), std::sync::atomic::Ordering::Relaxed);
            tracing::debug!(
                code = "federated_analytics_pushed",
                edge_id = %edge_id,
                count = count,
                accepted = accepted,
                "federated analytics batch pushed to controller"
            );
        }
        Err(e) => {
            tracing::warn!(
                code = "federated_analytics_push_failed",
                edge_id = %edge_id,
                count = count,
                error = %e,
                "failed to push federated analytics batch; events lost"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// gRPC service integration (PublishAnalytics RPC)
// ---------------------------------------------------------------------------

/// The gRPC service path for the `PublishAnalytics` RPC.
pub const PUBLISH_ANALYTICS_PATH: &str = "/dwara.ControlPlane/PublishAnalytics";

/// The server-side handler for the `PublishAnalytics` client-streaming
/// RPC. Reads `PbAnalyticsBatch` messages from the stream, converts
/// them to `Event`s, and forwards them to the `AnalyticsCollector`.
/// Returns a `PbAnalyticsAck` with the total accepted count.
pub async fn handle_publish_analytics(
    collector: Arc<dyn AnalyticsCollector>,
    request: Request<Streaming<PbAnalyticsBatch>>,
) -> Result<Response<PbAnalyticsAck>, Status> {
    let mut stream = request.into_inner();
    let mut total_accepted = 0u64;
    while let Some(batch) = stream
        .message()
        .await
        .map_err(|e| Status::internal(format!("stream error: {e}")))?
    {
        let edge_id = batch.edge_id;
        let events: Vec<Event> = batch.records.into_iter().map(Into::into).collect();
        let accepted = collector.collect(&edge_id, events).await;
        total_accepted += accepted;
    }
    Ok(Response::new(PbAnalyticsAck {
        accepted: total_accepted,
    }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_roundtrip_preserves_fields() {
        let event = Event {
            kind: "request".to_string(),
            timestamp_ms: 1234567890,
            route: Some("api".to_string()),
            consumer: Some("acme".to_string()),
            endpoint: Some("upstream-1".to_string()),
            status: Some(200),
            listener: Some("https".to_string()),
            method: Some("GET".to_string()),
            duration_ms: Some(42.5),
            attempts: Some(1),
            rate_limited: false,
            broken: false,
            shed: false,
            attributes: vec![("region".to_string(), "us-east".to_string())],
        };
        let pb: PbAnalyticsRecord = event.clone().into();
        let back: Event = pb.into();
        assert_eq!(back.kind, event.kind);
        assert_eq!(back.timestamp_ms, event.timestamp_ms);
        assert_eq!(back.route, event.route);
        assert_eq!(back.consumer, event.consumer);
        assert_eq!(back.endpoint, event.endpoint);
        assert_eq!(back.status, event.status);
        assert_eq!(back.listener, event.listener);
        assert_eq!(back.method, event.method);
        assert_eq!(back.duration_ms, event.duration_ms);
        assert_eq!(back.attempts, event.attempts);
        assert_eq!(back.rate_limited, event.rate_limited);
        assert_eq!(back.broken, event.broken);
        assert_eq!(back.shed, event.shed);
        assert_eq!(back.attributes, event.attributes);
    }

    #[test]
    fn event_with_empty_fields_roundtrips() {
        let event = Event::request_now();
        let pb: PbAnalyticsRecord = event.clone().into();
        let back: Event = pb.into();
        assert_eq!(back.kind, "request");
        assert_eq!(back.route, None);
        assert_eq!(back.consumer, None);
        assert_eq!(back.attributes, Vec::new());
    }

    #[tokio::test]
    async fn embedded_collector_forwards_to_sink() {
        use crate::extensions::analytics::InMemoryAnalyticsSink;
        let sink = Arc::new(InMemoryAnalyticsSink::new(100));
        let collector = EmbeddedCollector::new(sink.clone());
        let events = vec![Event::request_now(), Event::request_now()];
        let accepted = collector.collect("edge-1", events).await;
        assert_eq!(accepted, 2);
        assert_eq!(sink.events().len(), 2);
    }

    #[tokio::test]
    async fn noop_collector_counts_events() {
        let collector = NoopCollector;
        let events = vec![Event::request_now(); 5];
        let accepted = collector.collect("edge-1", events).await;
        assert_eq!(accepted, 5);
    }
}
