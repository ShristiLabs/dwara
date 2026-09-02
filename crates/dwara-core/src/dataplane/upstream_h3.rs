//! HTTP/3 (QUIC) upstream transport (DW-108).
//!
//! The mirror of the DW-088 H3 *ingress* listener: an H3 *egress*
//! connector that dials upstream endpoints over QUIC and speaks
//! HTTP/3 on bidirectional QUIC streams. A route whose upstream is
//! configured `protocol: h3` dispatches through here instead of the
//! TCP/TLS pooled client in [`super::upstream`].
//!
//! ## Transport model
//!
//! QUIC multiplexes many streams over one connection, so the pool
//! shape is inverted relative to HTTP/1.1: a QUIC *connection* is the
//! pooled resource, and each request opens a fresh bidirectional stream
//! *within* it. [`QuicStreamPool`] keeps a bounded set of QUIC
//! connections per endpoint address, hands out a cheaply cloneable
//! [`h3::client::SendRequest`] handle per request (one stream per
//! `send_request` call), and reaps connections idle past
//! [`QuicStreamPool::idle_timeout`].
//!
//! ## TLS
//!
//! QUIC mandates TLS 1.3, so every H3 upstream negotiates TLS with
//! ALPN `h3`. The trust roots are the SAME ones the pooled https
//! connector uses (#121): the Mozilla webpki public set by default, or
//! the upstream's `trusted_ca_file` bundle when configured. The shared
//! rustls client-config shape lives in [`crate::security::tls`]
//! ([`https_h3_client_config`]) so the connector and the QUIC active
//! health probe can never disagree about trust.
//!
//! ## 0-RTT
//!
//! Deliberately NOT used for upstream dialing: 0-RTT early data is
//! replayable, and a replayed non-idempotent upstream request is a
//! footgun the gateway must not expose by default. The rustls client
//! config disables early data ([`https_h3_client_config`]).
//!
//! ## Response buffering (documented v1 limitation)
//!
//! Unlike the TCP/TLS path (which streams the upstream body through
//! [`super::upstream::UpstreamBody`]), the H3 path buffers the full
//! response body before returning. h3's `recv_data` is an async method
//! on the stream handle, not a hyper `Body`, and bridging it into the
//! streaming `UpstreamBody` wrapper without a per-stream driver task is
//! a follow-up. The request body is likewise buffered (the proxy
//! already buffers request bodies for retries; for H3 the body is sent
//! as one `DATA` frame). Streaming H3 bodies are tracked as a future
//! improvement, not a regression: an H3 upstream is a new transport.
//!
//! Everything in this module is behind `#[cfg(feature = "h3")]`; when
//! the feature is off, `protocol: h3` upstreams are accepted at
//! validation but inert (every dispatch fails closed with
//! [`super::upstream::UpstreamError::H3Unavailable`]).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use h3::client::{self, SendRequest};
use h3_quinn::OpenStreams;
use http::{HeaderMap, Response, StatusCode};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::dataplane::upstream::{UpstreamError, UpstreamStats};
use crate::security::tls::https_h3_client_config;

/// Default maximum QUIC connections per endpoint address when the
/// upstream's `connection_cap` is absent. Lower than the TCP/TLS default
/// (64): one QUIC connection carries many streams, so a handful of
/// connections saturates concurrency without the per-stream head-of-line
/// blocking that makes TCP pools need many connections.
pub const DEFAULT_H3_CONNECTION_CAP: u32 = 8;

/// Default idle timeout for a pooled QUIC connection (no streams opened
/// through it for this long => close and reap). QUIC's own keep-alive is
/// not configured here; the sweep is the reaper.
pub const DEFAULT_H3_IDLE_TIMEOUT_MS: u64 = 30_000;

/// Errors specific to the H3/QUIC upstream transport. Mapped onto the
/// shared [`UpstreamError`] by [`H3UpstreamHandle::send`] so the proxy,
/// breaker, and health layers stay transport-agnostic.
#[derive(Debug)]
pub enum H3Error {
    /// QUIC connection attempt failed (handshake, transport, timeout).
    Connect(quinn::ConnectionError),
    /// Building the h3 client over the QUIC connection failed.
    H3(h3::error::ConnectionError),
    /// An HTTP/3 stream-level error (framing, QPACK, ...).
    Stream(h3::error::StreamError),
    /// The QUIC endpoint could not be bound (configuration error; only
    /// reachable from a misconfigured pool build).
    Endpoint(std::io::Error),
    /// The rustls client config could not be turned into a QUIC client
    /// config.
    Crypto(String),
}

impl std::fmt::Display for H3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            H3Error::Connect(e) => write!(f, "h3 upstream QUIC connect failed: {e}"),
            H3Error::H3(e) => write!(f, "h3 upstream connection setup failed: {e}"),
            H3Error::Stream(e) => write!(f, "h3 upstream stream error: {e}"),
            H3Error::Endpoint(e) => write!(f, "h3 upstream endpoint bind failed: {e}"),
            H3Error::Crypto(e) => write!(f, "h3 upstream QUIC crypto config failed: {e}"),
        }
    }
}

impl std::error::Error for H3Error {}

impl From<H3Error> for UpstreamError {
    fn from(e: H3Error) -> Self {
        match e {
            // A connect-time failure maps to the same transport-failure
            // classification the TCP/TLS connector uses; the proxy and
            // breaker treat it as a retryable transport error.
            H3Error::Connect(quinn::ConnectionError::TimedOut) => UpstreamError::ConnectTimeout {
                after: Duration::ZERO,
            },
            H3Error::Connect(e) => UpstreamError::Io(std::io::Error::other(e.to_string())),
            H3Error::H3(e) => UpstreamError::Io(std::io::Error::other(e.to_string())),
            H3Error::Stream(e) => UpstreamError::Io(std::io::Error::other(e.to_string())),
            H3Error::Endpoint(e) => UpstreamError::Io(e),
            H3Error::Crypto(e) => UpstreamError::Io(std::io::Error::other(e)),
        }
    }
}

impl From<UpstreamError> for H3Error {
    fn from(e: UpstreamError) -> Self {
        match e {
            UpstreamError::Io(io) => H3Error::Endpoint(io),
            other => H3Error::Endpoint(std::io::Error::other(other.to_string())),
        }
    }
}

/// Resolve `address:port` to one `SocketAddr` via `getaddrinfo` on the
/// blocking pool (IP literals short-circuit, the same path
/// `tokio::net::lookup_host` takes). The FIRST resolved address dials;
/// happy-eyeballs racing across QUIC addresses is a follow-up (QUIC
/// connection migration makes it less pressing than for TCP). Mirrors
/// the legacy connector's resolve step so an H3 upstream with a
/// hostname endpoint behaves like its TCP/TLS counterpart.
async fn resolve_one(address: &str, port: u16) -> Result<SocketAddr, UpstreamError> {
    tokio::net::lookup_host((address, port))
        .await
        .map_err(UpstreamError::Io)?
        .next()
        .ok_or_else(|| {
            UpstreamError::Io(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("'{address}:{port}' resolved to no addresses"),
            ))
        })
}

/// One pooled QUIC connection to an endpoint: a cloneable h3 request
/// sender (one stream per `send_request` call), the last-used clock for
/// the idle sweep, and the driver task that pumps h3 control frames until
/// the connection closes (the `SendRequest` clones keep the QUIC
/// connection alive; when the last one drops the connection drains and
/// the driver resolves).
struct ConnEntry {
    send_request: SendRequest<OpenStreams, Bytes>,
    last_used: Instant,
    /// Drives `h3::client::Connection::wait_idle`; its completion signals
    /// the connection is closed. `is_finished()` is the liveness probe
    /// used by [`QuicStreamPool::acquire`] to skip dead entries without
    /// dialing through them.
    driver: JoinHandle<()>,
}

impl ConnEntry {
    fn is_live(&self) -> bool {
        !self.driver.is_finished()
    }
}

/// QUIC stream-aware connection pool: a bounded set of QUIC connections
/// per endpoint address, each carrying many H3 streams. One
/// [`QuicStreamPool`] serves one upstream (the per-upstream connection
/// cap and trust roots are fixed at build time); endpoint addresses are
/// the inner key so a multi-endpoint upstream shares one pool.
///
/// The pool binds ONE quinn client endpoint (an ephemeral `0.0.0.0:0`
/// UDP socket) for all dials; quinn multiplexes connections over it.
pub struct QuicStreamPool {
    endpoint: Endpoint,
    tls: Arc<rustls::ClientConfig>,
    connect_timeout: Duration,
    max_conns_per_endpoint: usize,
    idle_timeout: Duration,
    conns: Mutex<HashMap<SocketAddr, Vec<ConnEntry>>>,
    stats: Arc<UpstreamStats>,
}

impl QuicStreamPool {
    /// Build a pool for one upstream's trust roots and connection cap.
    /// `roots` is the trust store the QUIC handshake verifies the
    /// upstream's server certificate against (webpki by default, the
    /// upstream's `trusted_ca_file` bundle when configured). Binds the
    /// quinn client endpoint to an ephemeral port.
    pub fn new(
        roots: rustls::RootCertStore,
        connect_timeout: Duration,
        max_conns_per_endpoint: usize,
        idle_timeout: Duration,
        stats: Arc<UpstreamStats>,
    ) -> Result<Self, H3Error> {
        let tls = Arc::new(https_h3_client_config(roots));
        let quic_client_config = QuicClientConfig::try_from(Arc::clone(&tls))
            .map_err(|e| H3Error::Crypto(e.to_string()))?;
        let mut client_config = ClientConfig::new(Arc::new(quic_client_config));
        // Keep the client config's transport defaults; quinn's defaults
        // are sane for short-lived request streams. A follow-up can wire
        // max_concurrent_bidi_streams from the connection cap.
        let _ = &mut client_config;
        let mut endpoint = Endpoint::client(
            "0.0.0.0:0"
                .parse()
                .expect("0.0.0.0:0 is a valid socket addr"),
        )
        .map_err(H3Error::Endpoint)?;
        endpoint.set_default_client_config(client_config);
        Ok(QuicStreamPool {
            endpoint,
            tls,
            connect_timeout,
            max_conns_per_endpoint: max_conns_per_endpoint.max(1),
            idle_timeout,
            conns: Mutex::new(HashMap::new()),
            stats,
        })
    }

    /// The rustls client config this pool verifies against (shared with
    /// the QUIC active health probe so a probe and a proxied request can
    /// never disagree about who to trust).
    pub fn tls_config(&self) -> &Arc<rustls::ClientConfig> {
        &self.tls
    }

    /// Dial one QUIC connection to `addr` and wrap it in h3. The driver
    /// task pumps h3 control frames; the returned entry keeps a
    /// cloneable `SendRequest` for opening streams.
    async fn dial(&self, addr: SocketAddr, server_name: &str) -> Result<ConnEntry, H3Error> {
        let quinn_conn = match timeout(self.connect_timeout, async {
            self.endpoint
                .connect(addr, server_name)
                .map_err(|e| H3Error::Endpoint(std::io::Error::other(e.to_string())))?
                .await
                .map_err(H3Error::Connect)
        })
        .await
        {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => return Err(e),
            Err(_elapsed) => {
                return Err(H3Error::Connect(quinn::ConnectionError::TimedOut));
            }
        };
        self.stats
            .connections_opened
            .fetch_add(1, Ordering::Relaxed);
        let (h3_conn, send_request) = client::new(h3_quinn::Connection::new(quinn_conn))
            .await
            .map_err(H3Error::H3)?;
        // Drive the h3 connection (control frames, GOAWAY, settings) until
        // it closes. The SendRequest clones handed out keep the connection
        // alive; when the last one drops the connection drains and this
        // task resolves, which `is_live()` observes.
        let driver = tokio::spawn(async move {
            let mut h3_conn = h3_conn;
            let _ = h3_conn.wait_idle().await;
        });
        Ok(ConnEntry {
            send_request,
            last_used: Instant::now(),
            driver,
        })
    }

    /// Acquire a cloneable request sender for `addr`: reuse a live pooled
    /// connection if one exists, otherwise dial a new one (bounded by
    /// `max_conns_per_endpoint`). Dead entries (driver finished) are
    /// reaped opportunistically here and in [`Self::sweep`].
    pub async fn acquire(
        &self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<SendRequest<OpenStreams, Bytes>, H3Error> {
        // Fast path: a live connection is available under the lock. Take
        // a clone of its SendRequest (cheap; h3 counts clones and keeps
        // the QUIC connection alive until the last clone drops) and bump
        // its last-used clock.
        if let Some(sr) = self.try_take_live(addr) {
            return Ok(sr);
        }
        // No live connection: dial a new one. The dial happens outside
        // the lock (it is async and may block up to connect_timeout).
        let entry = self.dial(addr, server_name).await?;
        let sr = entry.send_request.clone();
        // Insert, respecting the per-endpoint cap. If the cap is reached
        // (all slots occupied by live connections raced in), hand back
        // the fresh sender without pooling it (the connection stays open
        // via the sender clone; it will be reaped when the caller drops
        // it) rather than evicting a live connection.
        let mut conns = self.conns.lock().expect("pool lock poisoned");
        let bucket = conns.entry(addr).or_default();
        bucket.retain(|e| e.is_live());
        if bucket.len() < self.max_conns_per_endpoint {
            bucket.push(entry);
        }
        Ok(sr)
    }

    /// Try to grab a clone of a live connection's SendRequest for `addr`
    /// without dialing. Returns None if there is no live pooled
    /// connection. Stale (driver-finished) entries are reaped as a side
    /// effect.
    fn try_take_live(&self, addr: SocketAddr) -> Option<SendRequest<OpenStreams, Bytes>> {
        let mut conns = self.conns.lock().expect("pool lock poisoned");
        let bucket = conns.get_mut(&addr)?;
        // Reap dead entries first so the cap counts only live conns.
        bucket.retain(|e| e.is_live());
        // Pick the least-recently-used live connection (spread streams
        // across connections; approximates round-robin without an index).
        let now = Instant::now();
        let picked = bucket.iter_mut().min_by_key(|e| e.last_used)?;
        picked.last_used = now;
        Some(picked.send_request.clone())
    }

    /// Reap connections idle past `idle_timeout` (no stream opened through
    /// them since `last_used`). Called periodically by the handle's
    /// sweep task and by tests. Dropping the reaped `ConnEntry` drops its
    /// `SendRequest` clone; the connection's last sender (in the driver
    /// task's owned `Connection`) keeps it alive until `wait_idle`
    /// resolves, so reaping is graceful.
    pub fn sweep(&self) {
        let now = Instant::now();
        let mut conns = self.conns.lock().expect("pool lock poisoned");
        for bucket in conns.values_mut() {
            bucket.retain(|e| e.is_live() && now.duration_since(e.last_used) < self.idle_timeout);
        }
        conns.retain(|_, v| !v.is_empty());
    }

    /// Number of live pooled connections for `addr` (observability/tests).
    pub fn live_count(&self, addr: SocketAddr) -> usize {
        let mut conns = self.conns.lock().expect("pool lock poisoned");
        conns
            .get_mut(&addr)
            .map(|b| {
                b.retain(|e| e.is_live());
                b.len()
            })
            .unwrap_or(0)
    }
}

/// Send an HTTP/3 request over a QUIC stream (one `send_request` call =
/// one bidirectional stream) and read the full response. The request body
/// is sent as a single `DATA` frame (the H3 path buffers the request
/// body; see the module docs); the response body is collected into one
/// [`Bytes`] (streaming H3 response bodies are a follow-up).
///
/// `send_request` is taken by mutable reference because h3's
/// `send_request` requires `&mut self`; the caller clones it from the
/// pool so the pooled connection itself is not borrowed.
pub async fn h3_request(
    send_request: &mut SendRequest<OpenStreams, Bytes>,
    req: http::Request<Bytes>,
) -> Result<Response<Bytes>, H3Error> {
    let (parts, body) = req.into_parts();
    let head = http::Request::from_parts(parts, ());
    let mut stream = send_request
        .send_request(head)
        .await
        .map_err(H3Error::Stream)?;
    if !body.is_empty() {
        stream.send_data(body).await.map_err(H3Error::Stream)?;
    }
    stream.finish().await.map_err(H3Error::Stream)?;
    let resp_head = stream.recv_response().await.map_err(H3Error::Stream)?;
    let status: StatusCode = resp_head.status();
    let headers: HeaderMap = resp_head.headers().clone();
    let mut buf = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.map_err(H3Error::Stream)? {
        // `recv_data` yields `impl Buf`; copy it out. The chunk
        // is already decrypted QUIC stream data, so a copy is the
        // cost of buffering (documented v1 limitation).
        let bytes = chunk.copy_to_bytes(chunk.remaining());
        buf.extend_from_slice(&bytes);
    }
    // Trailers are discarded (the proxy does not forward upstream
    // trailers today); drain to cleanly close the stream.
    let _ = stream.recv_trailers().await;
    let mut resp = Response::new(Bytes::from(buf));
    *resp.status_mut() = status;
    *resp.headers_mut() = headers;
    Ok(resp)
}

/// Per-upstream H3 transport handle: a [`QuicStreamPool`] plus the
/// per-upstream timeouts and shared stats. Stored on
/// [`super::upstream::UpstreamHandle`] behind `#[cfg(feature = "h3")]`;
/// the LB, breaker, retry, and health layers are shared with the TCP/TLS
/// path (they operate on endpoint addresses, not the transport).
pub struct H3UpstreamHandle {
    name: String,
    pool: Arc<QuicStreamPool>,
    connect_timeout: Duration,
    read_timeout: Option<Duration>,
    stats: Arc<UpstreamStats>,
    sweep: Mutex<Option<JoinHandle<()>>>,
}

impl H3UpstreamHandle {
    /// Build an H3 handle for one upstream. `roots` is the trust store
    /// (webpki default or the upstream's `trusted_ca_file` bundle);
    /// `connection_cap` bounds QUIC connections per endpoint; the sweep
    /// task reaps idle connections every `idle_timeout / 2`.
    pub fn new(
        name: String,
        roots: rustls::RootCertStore,
        connect_timeout: Duration,
        connection_cap: u32,
        read_timeout: Option<Duration>,
        stats: Arc<UpstreamStats>,
    ) -> Result<Self, H3Error> {
        let idle_timeout = Duration::from_millis(DEFAULT_H3_IDLE_TIMEOUT_MS);
        let pool = Arc::new(QuicStreamPool::new(
            roots,
            connect_timeout,
            connection_cap.max(1) as usize,
            idle_timeout,
            Arc::clone(&stats),
        )?);
        // Background idle sweep: reaps connections not used for
        // `idle_timeout`. Runs at half the idle window so a connection
        // is reaped within ~1.5x idle_timeout of its last stream.
        let sweep_pool = Arc::clone(&pool);
        let sweep = tokio::spawn(async move {
            let interval = idle_timeout / 2;
            loop {
                tokio::time::sleep(interval).await;
                sweep_pool.sweep();
            }
        });
        Ok(H3UpstreamHandle {
            name,
            pool,
            connect_timeout,
            read_timeout,
            stats,
            sweep: Mutex::new(Some(sweep)),
        })
    }

    /// Upstream name (observability).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The shared rustls client config (trust roots + h3 ALPN); the QUIC
    /// active health probe reuses it so a probe and a proxied request
    /// trust the same roots.
    pub fn tls_config(&self) -> &Arc<rustls::ClientConfig> {
        self.pool.tls_config()
    }

    /// Live pooled QUIC connection count for `addr` (observability/tests).
    pub fn live_count(&self, addr: SocketAddr) -> usize {
        self.pool.live_count(addr)
    }

    /// Send an H3 request to the picked endpoint (`address:port`),
    /// verifying the upstream's server certificate against `server_name`
    /// (the endpoint address by default; works for hostname endpoints and
    /// IP endpoints with IP-SAN certificates). `address` is resolved to a
    /// `SocketAddr` via `getaddrinfo` on the blocking pool (IP literals
    /// short-circuit); the first resolved address dials — happy-eyeballs
    /// racing across QUIC addresses is a follow-up. The per-attempt
    /// `read_timeout` bounds the whole exchange (resolve + QUIC dial +
    /// request write + response headers + body), mirroring the TCP/TLS
    /// path's per-attempt deadline. The shared stats count the request;
    /// the pool counts new connections.
    pub async fn send(
        &self,
        address: &str,
        port: u16,
        server_name: &str,
        req: http::Request<Bytes>,
    ) -> Result<Response<Bytes>, UpstreamError> {
        let _ = self.connect_timeout; // dial timeout lives in the pool
        self.stats.requests_sent.fetch_add(1, Ordering::Relaxed);
        let attempt = async {
            let addr = resolve_one(address, port).await?;
            let mut sr = self.pool.acquire(addr, server_name).await?;
            h3_request(&mut sr, req).await
        };
        let result = match self.read_timeout {
            Some(after) => match timeout(after, attempt).await {
                Ok(r) => r,
                Err(_elapsed) => return Err(UpstreamError::ReadTimeout { after }),
            },
            None => attempt.await,
        };
        result.map_err(UpstreamError::from)
    }

    /// Abort the idle-sweep task (graceful shutdown). The pool itself is
    /// dropped with the handle; in-flight senders keep their QUIC
    /// connections alive until they complete.
    pub fn shutdown(&self) {
        if let Some(handle) = self.sweep.lock().expect("sweep lock poisoned").take() {
            handle.abort();
        }
    }
}

impl Drop for H3UpstreamHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl std::fmt::Debug for H3UpstreamHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3UpstreamHandle")
            .field("name", &self.name)
            .field("connect_timeout", &self.connect_timeout)
            .field("read_timeout", &self.read_timeout)
            .finish_non_exhaustive()
    }
}
