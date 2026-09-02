//! gRPC transport for the CP/DP split (DW-066, Enterprise).
//!
//! Hand-written prost wire messages + a custom tonic `Codec` (no
//! protoc/build-script dependency). The message shapes mirror the
//! existing domain types (`ConfigGeneration`, `ConfigUpdate`,
//! `ConfigAck`, `EdgeRegistration`); conversions happen in this
//! transport layer -- the domain types in [`super`] are unchanged.
//!
//! ## Architecture
//!
//! - [`ControllerServer`] implements the `DwaraControlPlane` service:
//!   edges register via `stream_config_updates` (server-streaming) and
//!   receive config updates; edges ack applied generations via `ack`
//!   (unary). Each connected edge gets a dedicated stream from a
//!   broadcast channel; `publish_update` fans out to all.
//! - [`EdgeClient`] connects to the controller, registers, receives
//!   updates (feeding them into [`super::EdgeState`]), and sends acks.
//!   Reconnects with bounded backoff on disconnect.
//!
//! ## Feature gate
//!
//! The `ent` cargo feature must be enabled (tonic + prost are optional
//! deps gated behind `ent`).

use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Buf;
use http_body_util::BodyExt;
use prost::Message as ProstMessage;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
use tonic::body::BoxBody;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::server::{NamedService, UnaryService};
use tonic::transport::Channel;
use tonic::{Request, Response, Status, Streaming};
use tower_service::Service as TowerService;

use super::analytics::{PbAnalyticsAck, PbAnalyticsBatch};
use super::{ConfigAck, ConfigGeneration, ConfigUpdate, ControllerState, EdgeRegistration};

// ---------------------------------------------------------------------------
// Wire messages (hand-written prost structs)
// ---------------------------------------------------------------------------

/// Wire: a config generation (mirrors [`ConfigGeneration`]).
#[derive(Clone, PartialEq, prost::Message)]
pub struct PbConfigGeneration {
    #[prost(uint64, tag = "1")]
    pub generation: u64,
    #[prost(string, tag = "2")]
    pub config: String,
    #[prost(string, tag = "3")]
    pub config_hash: String,
    #[prost(uint64, tag = "4")]
    pub timestamp_ms: u64,
}

/// Wire: a config update (mirrors [`ConfigUpdate`]).
#[derive(Clone, PartialEq, prost::Message)]
pub struct PbConfigUpdate {
    #[prost(message, tag = "1")]
    pub generation: Option<PbConfigGeneration>,
    #[prost(string, repeated, tag = "2")]
    pub target_edges: Vec<String>,
}

/// Wire: a config ack (mirrors [`ConfigAck`]).
#[derive(Clone, PartialEq, prost::Message)]
pub struct PbConfigAck {
    #[prost(string, tag = "1")]
    pub edge_id: String,
    #[prost(uint64, tag = "2")]
    pub generation: u64,
    #[prost(bool, tag = "3")]
    pub applied: bool,
    #[prost(string, tag = "4")]
    pub error: String,
    #[prost(uint64, tag = "5")]
    pub timestamp_ms: u64,
}

/// Wire: an edge registration (mirrors [`EdgeRegistration`]).
#[derive(Clone, PartialEq, prost::Message)]
pub struct PbEdgeRegistration {
    #[prost(string, tag = "1")]
    pub edge_id: String,
    #[prost(uint64, tag = "2")]
    pub current_generation: u64,
    #[prost(string, tag = "3")]
    pub version: String,
    #[prost(map = "string, string", tag = "4")]
    pub labels: HashMap<String, String>,
}

/// Wire: the ack response (empty body, status carried by gRPC Status).
#[derive(Clone, PartialEq, prost::Message)]
pub struct PbAckResponse {}

// ---------------------------------------------------------------------------
// Domain <-> wire conversions
// ---------------------------------------------------------------------------

impl From<ConfigGeneration> for PbConfigGeneration {
    fn from(g: ConfigGeneration) -> Self {
        Self {
            generation: g.generation,
            config: g.config,
            config_hash: g.config_hash,
            timestamp_ms: g.timestamp_ms,
        }
    }
}

impl From<PbConfigGeneration> for ConfigGeneration {
    fn from(g: PbConfigGeneration) -> Self {
        Self {
            generation: g.generation,
            config: g.config,
            config_hash: g.config_hash,
            timestamp_ms: g.timestamp_ms,
        }
    }
}

impl From<ConfigUpdate> for PbConfigUpdate {
    fn from(u: ConfigUpdate) -> Self {
        Self {
            generation: Some(u.generation.into()),
            target_edges: u.target_edges,
        }
    }
}

impl TryFrom<PbConfigUpdate> for ConfigUpdate {
    type Error = String;

    fn try_from(u: PbConfigUpdate) -> Result<Self, Self::Error> {
        let generation = u
            .generation
            .ok_or_else(|| "missing generation field".to_string())?;
        Ok(Self {
            generation: generation.into(),
            target_edges: u.target_edges,
        })
    }
}

impl From<ConfigAck> for PbConfigAck {
    fn from(a: ConfigAck) -> Self {
        Self {
            edge_id: a.edge_id,
            generation: a.generation,
            applied: a.applied,
            error: a.error.unwrap_or_default(),
            timestamp_ms: a.timestamp_ms,
        }
    }
}

impl From<PbConfigAck> for ConfigAck {
    fn from(a: PbConfigAck) -> Self {
        Self {
            edge_id: a.edge_id,
            generation: a.generation,
            applied: a.applied,
            error: if a.error.is_empty() {
                None
            } else {
                Some(a.error)
            },
            timestamp_ms: a.timestamp_ms,
        }
    }
}

impl From<EdgeRegistration> for PbEdgeRegistration {
    fn from(r: EdgeRegistration) -> Self {
        Self {
            edge_id: r.edge_id,
            current_generation: r.current_generation,
            version: r.version,
            labels: r.labels,
        }
    }
}

impl From<PbEdgeRegistration> for EdgeRegistration {
    fn from(r: PbEdgeRegistration) -> Self {
        Self {
            edge_id: r.edge_id,
            current_generation: r.current_generation,
            version: r.version,
            labels: r.labels,
        }
    }
}

// ---------------------------------------------------------------------------
// Custom prost Codec (uses workspace prost 0.14, not tonic's prost 0.13)
// ---------------------------------------------------------------------------

/// A gRPC codec that encodes/decodes prost messages using the workspace
/// prost 0.14 (tonic's built-in `ProstCodec` is gated behind the `prost`
/// feature which pulls in prost 0.13 -- we avoid the duplicate version by
/// hand-writing this thin codec).
#[derive(Debug, Clone, Default)]
pub struct ProstCodec<T, U> {
    _pd: PhantomData<(T, U)>,
}

impl<T, U> ProstCodec<T, U> {
    pub fn new() -> Self {
        Self { _pd: PhantomData }
    }
}

impl<T, U> Codec for ProstCodec<T, U>
where
    T: ProstMessage + Send + 'static,
    U: ProstMessage + Default + Send + 'static,
{
    type Encode = T;
    type Decode = U;
    type Encoder = ProstEncoder<T>;
    type Decoder = ProstDecoder<U>;

    fn encoder(&mut self) -> Self::Encoder {
        ProstEncoder { _pd: PhantomData }
    }

    fn decoder(&mut self) -> Self::Decoder {
        ProstDecoder { _pd: PhantomData }
    }
}

/// Encoder for the custom prost codec.
#[derive(Debug, Clone, Default)]
pub struct ProstEncoder<T> {
    _pd: PhantomData<T>,
}

impl<T: ProstMessage> Encoder for ProstEncoder<T> {
    type Item = T;
    type Error = Status;

    fn encode(&mut self, item: Self::Item, dst: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
        item.encode(dst)
            .expect("Message only errors if not enough space");
        Ok(())
    }
}

/// Decoder for the custom prost codec.
#[derive(Debug, Clone, Default)]
pub struct ProstDecoder<U> {
    _pd: PhantomData<U>,
}

impl<U: ProstMessage + Default> Decoder for ProstDecoder<U> {
    type Item = U;
    type Error = Status;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        if !src.has_remaining() {
            return Ok(None);
        }
        let item =
            U::decode(src).map_err(|e| Status::internal(format!("prost decode error: {e}")))?;
        Ok(Some(item))
    }
}

// ---------------------------------------------------------------------------
// Service trait (hand-written, mirrors tonic-build output)
// ---------------------------------------------------------------------------

/// The gRPC service trait for the dwara control plane.
///
/// `stream_config_updates`: server-streaming -- an edge registers and
/// the controller streams config updates to it.
/// `ack`: unary -- an edge acknowledges an applied generation.
#[tonic::async_trait]
pub trait DwaraControlPlane: Send + Sync + 'static {
    /// The stream type for server-streaming config updates.
    type StreamConfigUpdatesStream: Stream<Item = Result<PbConfigUpdate, Status>> + Send + 'static;

    /// Register an edge and stream config updates to it.
    async fn stream_config_updates(
        &self,
        request: Request<PbEdgeRegistration>,
    ) -> Result<Response<Self::StreamConfigUpdatesStream>, Status>;

    /// Acknowledge an applied config generation.
    async fn ack(&self, request: Request<PbConfigAck>) -> Result<Response<PbAckResponse>, Status>;
}

// ---------------------------------------------------------------------------
// ControllerServer
// ---------------------------------------------------------------------------

/// The broadcast channel for fanning out config updates to all edges.
struct UpdateBroadcaster {
    tx: broadcast::Sender<ConfigUpdate>,
}

impl UpdateBroadcaster {
    fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    fn subscribe(&self) -> broadcast::Receiver<ConfigUpdate> {
        self.tx.subscribe()
    }

    fn broadcast(&self, update: ConfigUpdate) {
        // send fails only when there are no active receivers; that is
        // fine -- no edges are connected to receive this update.
        let _ = self.tx.send(update);
    }

    fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

/// The controller gRPC server: holds the [`ControllerState`] and a
/// broadcast channel for fanning out config updates to connected edges.
///
/// On [`ControllerServer::publish_update`], the update is broadcast to
/// all connected edge streams. Each edge's stream filters out updates
/// not targeted at it (empty `target_edges` = all edges).
///
/// DW-095: the server also holds an optional [`AnalyticsCollector`] for
/// federated analytics. When set, the `PublishAnalytics` RPC forwards
/// edge batches to the collector.
#[derive(Clone)]
pub struct ControllerServer {
    state: Arc<ControllerState>,
    broadcaster: Arc<UpdateBroadcaster>,
    analytics_collector: Option<Arc<dyn super::analytics::AnalyticsCollector>>,
}

impl ControllerServer {
    /// Create a new controller server wrapping the given state.
    pub fn new(state: Arc<ControllerState>) -> Self {
        Self {
            state,
            broadcaster: Arc::new(UpdateBroadcaster::new(256)),
            analytics_collector: None,
        }
    }

    /// Attach an analytics collector (DW-095). When set, the
    /// `PublishAnalytics` RPC forwards edge batches to this collector.
    pub fn with_analytics_collector(
        mut self,
        collector: Arc<dyn super::analytics::AnalyticsCollector>,
    ) -> Self {
        self.analytics_collector = Some(collector);
        self
    }

    /// The controller state.
    pub fn state(&self) -> &Arc<ControllerState> {
        &self.state
    }

    /// Publish a config update to all connected edges. The update is
    /// broadcast via the internal broadcast channel; each edge's stream
    /// filters by `target_edges`.
    pub fn publish_update(&self, update: ConfigUpdate) {
        self.broadcaster.broadcast(update);
    }

    /// The number of connected edge streams.
    pub fn connected_edge_count(&self) -> usize {
        self.broadcaster.receiver_count()
    }
}

#[tonic::async_trait]
impl DwaraControlPlane for ControllerServer {
    type StreamConfigUpdatesStream = ReceiverStream<Result<PbConfigUpdate, Status>>;

    async fn stream_config_updates(
        &self,
        request: Request<PbEdgeRegistration>,
    ) -> Result<Response<Self::StreamConfigUpdatesStream>, Status> {
        let registration: EdgeRegistration = request.into_inner().into();
        let edge_id = registration.edge_id.clone();

        tracing::info!(
            code = "cp_edge_registered",
            edge_id = %edge_id,
            current_generation = registration.current_generation,
            "edge registered for config updates"
        );

        self.state.register_edge(registration);

        let (tx, rx) = mpsc::channel(64);
        let mut broadcast_rx = self.broadcaster.subscribe();

        // Spawn a forwarder task: broadcast -> mpsc, filtering by
        // target_edges. The mpsc channel backs the gRPC stream.
        tokio::spawn(async move {
            loop {
                match broadcast_rx.recv().await {
                    Ok(update) => {
                        // Filter: empty target_edges = all edges;
                        // otherwise only deliver to targeted edges.
                        if !update.target_edges.is_empty()
                            && !update.target_edges.contains(&edge_id)
                        {
                            continue;
                        }
                        let pb: PbConfigUpdate = update.into();
                        if tx.send(Ok(pb)).await.is_err() {
                            // Edge disconnected; stop forwarding.
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(
                            code = "cp_edge_lagged",
                            edge_id = %edge_id,
                            skipped = n,
                            "edge stream lagged behind broadcast"
                        );
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn ack(&self, request: Request<PbConfigAck>) -> Result<Response<PbAckResponse>, Status> {
        let pb_ack = request.into_inner();
        let ack: ConfigAck = pb_ack.into();

        tracing::info!(
            code = "cp_edge_acked",
            edge_id = %ack.edge_id,
            generation = ack.generation,
            applied = ack.applied,
            "edge acknowledged config generation"
        );

        self.state.record_ack(ack);

        Ok(Response::new(PbAckResponse {}))
    }
}

// ---------------------------------------------------------------------------
// Tower Service routing (hand-written, mirrors tonic-build output)
// ---------------------------------------------------------------------------

/// The gRPC service name (for routing).
pub const SERVICE_NAME: &str = "dwara.ControlPlane";
pub const STREAM_CONFIG_UPDATES_PATH: &str = "/dwara.ControlPlane/StreamConfigUpdates";
pub const ACK_PATH: &str = "/dwara.ControlPlane/Ack";
pub const PUBLISH_ANALYTICS_PATH: &str = "/dwara.ControlPlane/PublishAnalytics";

impl NamedService for ControllerServer {
    const NAME: &'static str = SERVICE_NAME;
}

/// A boxed future returned by the tower Service.
type BoxFuture =
    Pin<Box<dyn Future<Output = Result<http::Response<BoxBody>, Infallible>> + Send + 'static>>;

impl TowerService<http::Request<BoxBody>> for ControllerServer {
    type Response = http::Response<BoxBody>;
    type Error = Infallible;
    type Future = BoxFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<BoxBody>) -> Self::Future {
        let server = self.clone();
        Box::pin(async move {
            let path = req.uri().path().to_string();
            match path.as_str() {
                STREAM_CONFIG_UPDATES_PATH => {
                    let mut grpc = tonic::server::Grpc::new(ProstCodec::<
                        PbConfigUpdate,
                        PbEdgeRegistration,
                    >::new());
                    let service = StreamConfigUpdatesSvc {
                        server: server.clone(),
                    };
                    let resp = grpc.server_streaming(service, req).await;
                    Ok(resp)
                }
                ACK_PATH => {
                    let mut grpc =
                        tonic::server::Grpc::new(ProstCodec::<PbAckResponse, PbConfigAck>::new());
                    let service = AckSvc {
                        server: server.clone(),
                    };
                    let resp = grpc.unary(service, req).await;
                    Ok(resp)
                }
                PUBLISH_ANALYTICS_PATH => {
                    // DW-095: client-streaming analytics RPC. The
                    // edge streams PbAnalyticsBatch messages; the
                    // controller forwards them to the AnalyticsCollector.
                    if let Some(collector) = &server.analytics_collector {
                        let mut grpc = tonic::server::Grpc::new(ProstCodec::<
                            PbAnalyticsAck,
                            PbAnalyticsBatch,
                        >::new());
                        let service = PublishAnalyticsSvc {
                            collector: Arc::clone(collector),
                        };
                        let resp = grpc.client_streaming(service, req).await;
                        Ok(resp)
                    } else {
                        // No collector attached: return UNIMPLEMENTED.
                        let resp = http::Response::builder()
                            .status(http::StatusCode::NOT_IMPLEMENTED)
                            .body(BoxBody::new(
                                http_body_util::Empty::<bytes::Bytes>::new()
                                    .map_err(|e| -> tonic::Status { match e {} }),
                            ))
                            .expect("static response builds");
                        Ok(resp)
                    }
                }
                _ => {
                    let resp = http::Response::builder()
                        .status(http::StatusCode::NOT_FOUND)
                        .body(BoxBody::new(
                            http_body_util::Empty::<bytes::Bytes>::new()
                                .map_err(|e| -> tonic::Status { match e {} }),
                        ))
                        .expect("static response builds");
                    Ok(resp)
                }
            }
        })
    }
}

/// A boxed future for server-streaming responses.
type ServerStreamingFuture = Pin<
    Box<
        dyn Future<
                Output = Result<Response<ReceiverStream<Result<PbConfigUpdate, Status>>>, Status>,
            > + Send
            + 'static,
    >,
>;

/// A boxed future for unary responses.
type UnaryFuture =
    Pin<Box<dyn Future<Output = Result<Response<PbAckResponse>, Status>> + Send + 'static>>;

/// Wrapper that adapts `DwaraControlPlane::stream_config_updates` to
/// `ServerStreamingService<PbEdgeRegistration>`.
struct StreamConfigUpdatesSvc {
    server: ControllerServer,
}

impl tonic::server::ServerStreamingService<PbEdgeRegistration> for StreamConfigUpdatesSvc {
    type Response = PbConfigUpdate;
    type ResponseStream = ReceiverStream<Result<PbConfigUpdate, Status>>;
    type Future = ServerStreamingFuture;

    fn call(&mut self, request: Request<PbEdgeRegistration>) -> Self::Future {
        let server = self.server.clone();
        Box::pin(async move { server.stream_config_updates(request).await })
    }
}

/// Wrapper that adapts `DwaraControlPlane::ack` to
/// `UnaryService<PbConfigAck>`.
struct AckSvc {
    server: ControllerServer,
}

impl UnaryService<PbConfigAck> for AckSvc {
    type Response = PbAckResponse;
    type Future = UnaryFuture;

    fn call(&mut self, request: Request<PbConfigAck>) -> Self::Future {
        let server = self.server.clone();
        Box::pin(async move { server.ack(request).await })
    }
}

/// A boxed future for client-streaming responses (DW-095).
type ClientStreamingFuture =
    Pin<Box<dyn Future<Output = Result<Response<PbAnalyticsAck>, Status>> + Send + 'static>>;

/// Wrapper that adapts the analytics collector to
/// `ClientStreamingService<PbAnalyticsBatch>` (DW-095).
struct PublishAnalyticsSvc {
    collector: Arc<dyn super::analytics::AnalyticsCollector>,
}

impl tonic::server::ClientStreamingService<PbAnalyticsBatch> for PublishAnalyticsSvc {
    type Response = PbAnalyticsAck;
    type Future = ClientStreamingFuture;

    fn call(&mut self, request: Request<Streaming<PbAnalyticsBatch>>) -> Self::Future {
        let collector = Arc::clone(&self.collector);
        Box::pin(
            async move { super::analytics::handle_publish_analytics(collector, request).await },
        )
    }
}

// ---------------------------------------------------------------------------
// EdgeClient
// ---------------------------------------------------------------------------

/// An error from the edge client (connection, stream, or protocol).
#[derive(Debug)]
pub enum EdgeClientError {
    /// Transport-level error (connection refused, etc.).
    Transport(String),
    /// gRPC status error from the controller.
    Status(Status),
    /// Protocol error (missing fields, decode failure).
    Protocol(String),
}

impl fmt::Display for EdgeClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EdgeClientError::Transport(msg) => write!(f, "transport error: {msg}"),
            EdgeClientError::Status(s) => write!(f, "gRPC status: {s}"),
            EdgeClientError::Protocol(msg) => write!(f, "protocol error: {msg}"),
        }
    }
}

impl StdError for EdgeClientError {}

impl From<Status> for EdgeClientError {
    fn from(s: Status) -> Self {
        EdgeClientError::Status(s)
    }
}

/// The edge gRPC client: connects to the controller, registers, and
/// provides methods to receive config updates and send acks.
#[derive(Clone)]
pub struct EdgeClient {
    channel: Channel,
}

impl EdgeClient {
    /// Connect to the controller at the given endpoint (plaintext gRPC;
    /// mTLS is a documented follow-up).
    pub async fn connect(endpoint: &str) -> Result<Self, EdgeClientError> {
        let channel = Channel::from_shared(endpoint.to_string())
            .map_err(|e| EdgeClientError::Transport(e.to_string()))?
            .connect()
            .await
            .map_err(|e| EdgeClientError::Transport(e.to_string()))?;
        Ok(Self { channel })
    }

    /// Connect from a shared `Channel` (for testing or connection reuse).
    pub fn from_channel(channel: Channel) -> Self {
        Self { channel }
    }

    /// Register the edge and return a stream of config updates.
    ///
    /// The stream yields `PbConfigUpdate` wire types (convert to the
    /// domain `ConfigUpdate` via `TryFrom`).
    pub async fn stream_config_updates(
        &self,
        registration: EdgeRegistration,
    ) -> Result<Streaming<PbConfigUpdate>, EdgeClientError> {
        let codec = ProstCodec::<PbEdgeRegistration, PbConfigUpdate>::new();
        let mut grpc = tonic::client::Grpc::new(self.channel.clone());

        // tonic requires poll_ready before each call (tower buffer).
        grpc.ready()
            .await
            .map_err(|e| EdgeClientError::Transport(e.to_string()))?;

        let pb_reg: PbEdgeRegistration = registration.into();
        let request = Request::new(pb_reg);

        let path = http::uri::PathAndQuery::from_static(STREAM_CONFIG_UPDATES_PATH);

        let response = grpc
            .server_streaming(request, path, codec)
            .await
            .map_err(EdgeClientError::from)?;

        Ok(response.into_inner())
    }

    /// Send an ack for an applied config generation.
    pub async fn ack(&self, ack: ConfigAck) -> Result<(), EdgeClientError> {
        let codec = ProstCodec::<PbConfigAck, PbAckResponse>::new();
        let mut grpc = tonic::client::Grpc::new(self.channel.clone());

        // tonic requires poll_ready before each call (tower buffer).
        grpc.ready()
            .await
            .map_err(|e| EdgeClientError::Transport(e.to_string()))?;

        let pb_ack: PbConfigAck = ack.into();
        let request = Request::new(pb_ack);

        let path = http::uri::PathAndQuery::from_static(ACK_PATH);

        let _ = grpc
            .unary(request, path, codec)
            .await
            .map_err(EdgeClientError::from)?;

        Ok(())
    }

    /// DW-095: publish a batch of analytics records to the controller.
    /// Returns the number of records accepted by the controller.
    pub async fn publish_analytics(
        &self,
        batch: super::analytics::PbAnalyticsBatch,
    ) -> Result<u64, EdgeClientError> {
        let codec = ProstCodec::<PbAnalyticsBatch, PbAnalyticsAck>::new();
        let mut grpc = tonic::client::Grpc::new(self.channel.clone());

        grpc.ready()
            .await
            .map_err(|e| EdgeClientError::Transport(e.to_string()))?;

        let request = Request::new(batch);
        let path = http::uri::PathAndQuery::from_static(PUBLISH_ANALYTICS_PATH);

        let response = grpc
            .unary(request, path, codec)
            .await
            .map_err(EdgeClientError::from)?;

        Ok(response.into_inner().accepted)
    }
}

// ---------------------------------------------------------------------------
// Server builder helper
// ---------------------------------------------------------------------------

/// Start the controller gRPC server on the given address. Returns a
/// future that runs until the server is shut down.
pub async fn serve_controller(
    server: ControllerServer,
    addr: SocketAddr,
) -> Result<(), tonic::transport::Error> {
    tonic::transport::Server::builder()
        .add_service(server)
        .serve(addr)
        .await
}

/// Start the controller gRPC server with a provided incoming stream
/// (for testing: bind a `TcpListener` to port 0, wrap in
/// `TcpListenerStream`, and pass here). Returns a future that runs
/// until the incoming stream is exhausted.
pub async fn serve_controller_with_incoming<I, IO, IE>(
    server: ControllerServer,
    incoming: I,
) -> Result<(), tonic::transport::Error>
where
    I: Stream<Item = Result<IO, IE>> + Send + 'static,
    IO: tokio::io::AsyncRead
        + tokio::io::AsyncWrite
        + tonic::transport::server::Connected
        + Unpin
        + Send
        + 'static,
    IO::ConnectInfo: Clone + Send + Sync + 'static,
    IE: Into<Box<dyn StdError + Send + Sync>> + Send,
{
    tonic::transport::Server::builder()
        .add_service(server)
        .serve_with_incoming(incoming)
        .await
}

/// Default reconnect backoff schedule (exponential with a cap).
pub fn default_backoff() -> Vec<Duration> {
    vec![
        Duration::from_millis(100),
        Duration::from_millis(200),
        Duration::from_millis(500),
        Duration::from_millis(1000),
        Duration::from_millis(2000),
        Duration::from_millis(5000),
    ]
}

// ---------------------------------------------------------------------------
// Tests (white-box: wire round-trip + domain conversions)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_roundtrip_config_generation() {
        let gen = PbConfigGeneration {
            generation: 42,
            config: "routes: []".to_string(),
            config_hash: "abc123".to_string(),
            timestamp_ms: 1700000000,
        };
        let buf = gen.encode_to_vec();
        let decoded = PbConfigGeneration::decode(&buf[..]).unwrap();
        assert_eq!(gen, decoded);
    }

    #[test]
    fn wire_roundtrip_config_update() {
        let update = PbConfigUpdate {
            generation: Some(PbConfigGeneration {
                generation: 1,
                config: "config".to_string(),
                config_hash: "hash".to_string(),
                timestamp_ms: 100,
            }),
            target_edges: vec!["edge-1".to_string()],
        };
        let buf = update.encode_to_vec();
        let decoded = PbConfigUpdate::decode(&buf[..]).unwrap();
        assert_eq!(update, decoded);
    }

    #[test]
    fn wire_roundtrip_config_ack() {
        let ack = PbConfigAck {
            edge_id: "edge-1".to_string(),
            generation: 5,
            applied: true,
            error: String::new(),
            timestamp_ms: 200,
        };
        let buf = ack.encode_to_vec();
        let decoded = PbConfigAck::decode(&buf[..]).unwrap();
        assert_eq!(ack, decoded);
    }

    #[test]
    fn wire_roundtrip_edge_registration() {
        let mut labels = HashMap::new();
        labels.insert("zone".to_string(), "us-east".to_string());
        let reg = PbEdgeRegistration {
            edge_id: "edge-1".to_string(),
            current_generation: 3,
            version: "0.1.0".to_string(),
            labels,
        };
        let buf = reg.encode_to_vec();
        let decoded = PbEdgeRegistration::decode(&buf[..]).unwrap();
        assert_eq!(reg, decoded);
    }

    #[test]
    fn domain_to_wire_and_back() {
        let domain = ConfigGeneration {
            generation: 7,
            config: "test".to_string(),
            config_hash: "h".to_string(),
            timestamp_ms: 999,
        };
        let wire: PbConfigGeneration = domain.clone().into();
        let back: ConfigGeneration = wire.into();
        assert_eq!(domain, back);
    }

    #[test]
    fn ack_error_field_roundtrip() {
        let ack = ConfigAck {
            edge_id: "e1".to_string(),
            generation: 1,
            applied: false,
            error: Some("bad config".to_string()),
            timestamp_ms: 0,
        };
        let wire: PbConfigAck = ack.clone().into();
        let back: ConfigAck = wire.into();
        assert_eq!(ack, back);
    }

    #[test]
    fn ack_no_error_roundtrip() {
        let ack = ConfigAck {
            edge_id: "e1".to_string(),
            generation: 1,
            applied: true,
            error: None,
            timestamp_ms: 0,
        };
        let wire: PbConfigAck = ack.clone().into();
        let back: ConfigAck = wire.into();
        assert_eq!(ack, back);
    }

    #[test]
    fn config_update_conversion() {
        let update = ConfigUpdate {
            generation: ConfigGeneration {
                generation: 3,
                config: "cfg".to_string(),
                config_hash: "h".to_string(),
                timestamp_ms: 42,
            },
            target_edges: vec!["edge-2".to_string()],
        };
        let wire: PbConfigUpdate = update.clone().into();
        let back: ConfigUpdate = wire.try_into().unwrap();
        assert_eq!(update, back);
    }

    #[test]
    fn config_update_missing_generation_fails() {
        let wire = PbConfigUpdate {
            generation: None,
            target_edges: vec![],
        };
        let result: Result<ConfigUpdate, _> = wire.try_into();
        assert!(result.is_err());
    }
}
