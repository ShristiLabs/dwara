//! Pooled upstream clients (DW-008, feature analysis 4.1).
//!
//! One hyper-util legacy client (a connection pool) per configured
//! upstream, keyed by upstream name inside an [`UpstreamRegistry`]. Each
//! pool's connector is tuned per upstream:
//!
//! - **Connect timeout**: `timeouts.connect_ms` (default 5 s) wraps the
//!   whole dial: TCP connect plus, for TLS upstreams, the TLS handshake.
//! - **Connection cap**: `connection_cap` (default 64) bounds concurrent
//!   outbound connections to the upstream — active AND pooled-idle — via a
//!   semaphore permit acquired before dialing and stored inside the
//!   connection's IO wrapper, so it is released exactly when the
//!   connection closes (permit drop). Excess connection attempts queue on
//!   the semaphore; they are never failed, only delayed. Because the
//!   permit wait has no deadline of its own, requests can queue
//!   indefinitely while the cap is saturated; request-level timeouts
//!   (DW-014) will bound that wait. The effective cap is clamped to a
//!   minimum of 1: validated configs always pass a cap >= 1, but direct
//!   construction with cap == 0 would build a zero-permit semaphore whose
//!   dials hang silently — misuse degrades to serial connects instead.
//!   Documented choice:
//!   the cap counts connections, not in-flight requests — HTTP/1.1
//!   multiplexes several requests over one connection only sequentially,
//!   and h2 pools share one connection per origin anyway.
//! - **TLS**: `https` upstreams negotiate TLS with ALPN `http/1.1`;
//!   `http2` upstreams negotiate TLS with ALPN `h2` and lock the client to
//!   HTTP/2; `http1` upstreams dial plaintext. Server certificates are
//!   verified against the Mozilla webpki root set by default (chosen over
//!   system roots for determinism in tests; system roots are a follow-up).
//!   Private-CA upstreams work via [`UpstreamRegistry::with_root_certificates`].
//!
//! Documented v1 limitation (same family as TLS-passthrough routing):
//! requests are sent to the FIRST endpoint of the upstream; load balancing
//! across endpoints is DW-011. Config lifecycle: build a registry from a
//! published snapshot; DW-009 rebuilds it on snapshot swap, mirroring how
//! `TlsTermination` is reloaded.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use hyper::{Request, Response, Uri};
use hyper_util::client::legacy::connect::{
    Connected, Connection as HyperConnection, HttpConnector,
};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower_service::Service;

use crate::config::{Timeouts, Upstream, UpstreamProtocol};
use crate::snapshot::Snapshot;

/// Default connection cap when `connection_cap` is absent.
pub const DEFAULT_CONNECTION_CAP: u32 = 64;
/// Default connect timeout when `timeouts.connect_ms` is absent.
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 5_000;

/// Error sending a request to an upstream.
#[derive(Debug)]
pub enum UpstreamError {
    /// `send` was called on an upstream with no endpoints. Only reachable
    /// via unvalidated direct construction; config validation rejects
    /// empty endpoint lists.
    NoEndpoints,
    /// A root certificate supplied to
    /// [`UpstreamRegistry::with_root_certificates`] could not be parsed
    /// or was otherwise unusable as a trust anchor.
    InvalidRootCertificate(String),
    /// The endpoint address is not usable as a TLS server name.
    InvalidHost(String),
    /// Dialing (TCP or TLS handshake) exceeded the connect timeout.
    ConnectTimeout { after: Duration },
    /// Transport-level I/O failure while connecting.
    Io(std::io::Error),
    /// The hyper client failed to complete the request (broken pool
    /// connection, framing error, ...).
    Client(hyper_util::client::legacy::Error),
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpstreamError::NoEndpoints => write!(f, "upstream has no endpoints"),
            UpstreamError::InvalidRootCertificate(e) => {
                write!(f, "unusable root certificate: {e}")
            }
            UpstreamError::InvalidHost(h) => {
                write!(f, "endpoint address '{h}' is not a valid TLS server name")
            }
            UpstreamError::ConnectTimeout { after } => {
                write!(f, "upstream connect timed out after {after:?}")
            }
            UpstreamError::Io(e) => write!(f, "upstream connect failed: {e}"),
            UpstreamError::Client(e) => write!(f, "upstream request failed: {e}"),
        }
    }
}

impl std::error::Error for UpstreamError {}

impl From<std::io::Error> for UpstreamError {
    fn from(e: std::io::Error) -> Self {
        UpstreamError::Io(e)
    }
}

impl From<hyper_util::client::legacy::Error> for UpstreamError {
    fn from(e: hyper_util::client::legacy::Error) -> Self {
        // The legacy client wraps connector errors (ours included) in its
        // Connect variant; lift our typed errors back out so callers can
        // match e.g. ConnectTimeout without digging through sources.
        let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(&e);
        while let Some(s) = src {
            if let Some(u) = s.downcast_ref::<UpstreamError>() {
                match u {
                    UpstreamError::ConnectTimeout { after } => {
                        return UpstreamError::ConnectTimeout { after: *after }
                    }
                    UpstreamError::InvalidHost(h) => return UpstreamError::InvalidHost(h.clone()),
                    _ => {}
                }
            }
            src = std::error::Error::source(s);
        }
        UpstreamError::Client(e)
    }
}

/// Live connection counters for one upstream; observability for pooling
/// behavior (used by tests and later by the admin surface).
#[derive(Debug, Default)]
pub struct UpstreamStats {
    /// Total TCP/TLS connections established to this upstream since the
    /// handle was built. Stays flat when the pool reuses connections.
    pub connections_opened: AtomicU64,
    /// Total requests handed to the pool.
    pub requests_sent: AtomicU64,
}

/// The transport under a pooled connection: plaintext TCP or TLS, wrapped
/// in `TokioIo` to bridge tokio traits to hyper's runtime traits.
enum Transport {
    Plain(TokioIo<TcpStream>),
    Tls(Box<TokioIo<tokio_rustls::client::TlsStream<TcpStream>>>),
}

impl hyper::rt::Read for Transport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Transport::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Transport::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl hyper::rt::Write for Transport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Transport::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Transport::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Transport::Plain(s) => Pin::new(s).poll_flush(cx),
            Transport::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Transport::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Transport::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Pooled connection IO: the transport plus the connection-cap permit.
/// The permit lives exactly as long as the connection: when the pool drops
/// a closed/evicted connection, the permit is released and the next queued
/// dial may proceed.
struct CappedStream {
    transport: Transport,
    _permit: OwnedSemaphorePermit,
}

impl hyper::rt::Read for CappedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.transport).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for CappedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.transport).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.transport).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.transport).poll_shutdown(cx)
    }
}

impl HyperConnection for CappedStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

/// Per-upstream connector: happy-eyeballs TCP dial (via `HttpConnector`
/// for DNS + address resolution), optional rustls TLS with baked-in ALPN,
/// the connect timeout, and the connection-cap semaphore.
#[derive(Clone)]
struct UpstreamConnector {
    http: HttpConnector,
    /// TLS client config (ALPN already set) for https/http2 upstreams.
    tls: Option<Arc<rustls::ClientConfig>>,
    cap: Arc<Semaphore>,
    connect_timeout: Duration,
    stats: Arc<UpstreamStats>,
}

impl Service<Uri> for UpstreamConnector {
    type Response = CappedStream;
    type Error = UpstreamError;
    type Future =
        Pin<Box<dyn Future<Output = Result<CappedStream, UpstreamError>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http
            .poll_ready(cx)
            .map_err(|e| UpstreamError::Io(std::io::Error::other(e.to_string())))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let mut http = self.http.clone();
        let tls = self.tls.clone();
        let cap = Arc::clone(&self.cap);
        let connect_timeout = self.connect_timeout;
        let stats = Arc::clone(&self.stats);
        Box::pin(async move {
            // Acquire a cap slot BEFORE dialing. The semaphore is never
            // closed, so acquire cannot fail; waiting here is the cap's
            // documented backpressure (queue, never fail).
            let permit = cap
                .acquire_owned()
                .await
                .expect("connection-cap semaphore is never closed");
            let host = uri.host().unwrap_or_default().to_string();
            let dial = async {
                // HttpConnector (hyper-util 0.1.20) resolves + dials and
                // hands back a TokioIo<TcpStream>.
                let tcp = http
                    .call(uri.clone())
                    .await
                    .map_err(|e| UpstreamError::Io(std::io::Error::other(e.to_string())))?;
                let transport = match tls {
                    Some(config) => {
                        let name = ServerName::try_from(host.clone())
                            .map_err(|_| UpstreamError::InvalidHost(host.clone()))?;
                        let connector = tokio_rustls::TlsConnector::from(config);
                        let tls_stream = connector
                            .connect(name, tcp.into_inner())
                            .await
                            .map_err(|e| std::io::Error::other(e.to_string()))?;
                        Transport::Tls(Box::new(TokioIo::new(tls_stream)))
                    }
                    None => Transport::Plain(tcp),
                };
                Ok::<Transport, UpstreamError>(transport)
            };
            let transport = tokio::time::timeout(connect_timeout, dial)
                .await
                .map_err(|_| UpstreamError::ConnectTimeout {
                    after: connect_timeout,
                })??;
            stats.connections_opened.fetch_add(1, Ordering::Relaxed);
            Ok(CappedStream {
                transport,
                _permit: permit,
            })
        })
    }
}

/// A send-capable handle to one configured upstream: a dedicated pooled
/// hyper client plus observability. Cheap to share via `Arc` from the
/// [`UpstreamRegistry`].
pub struct UpstreamHandle {
    name: String,
    cap: u32,
    connect_timeout: Duration,
    stats: Arc<UpstreamStats>,
    client: Client<
        UpstreamConnector,
        http_body_util::combinators::UnsyncBoxBody<
            bytes::Bytes,
            Box<dyn std::error::Error + Send + Sync>,
        >,
    >,
    endpoint: Option<crate::config::Endpoint>,
    scheme: &'static str,
}

impl UpstreamHandle {
    /// Upstream name this handle serves.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Effective connection cap (explicit or default, minimum 1).
    pub fn cap(&self) -> u32 {
        self.cap
    }

    /// Effective connect timeout (explicit or default).
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Total connections established since the handle was built.
    pub fn connections_opened(&self) -> u64 {
        self.stats.connections_opened.load(Ordering::Relaxed)
    }

    /// Total requests sent through the pool.
    pub fn requests_sent(&self) -> u64 {
        self.stats.requests_sent.load(Ordering::Relaxed)
    }

    /// Effective scheme this upstream dials ("http" or "https").
    pub fn scheme(&self) -> &str {
        self.scheme
    }

    /// Send a request through this upstream's pool. The request's URI is
    /// rewritten to `scheme://<first-endpoint><path-and-query>`; headers
    /// and body pass through untouched. The response body streams
    /// (`Incoming`), so proxying (DW-009) can forward it without
    /// buffering.
    pub async fn send<B>(&self, mut req: Request<B>) -> Result<Response<Incoming>, UpstreamError>
    where
        B: hyper::body::Body<Data = bytes::Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let path = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        // Guard rather than dialing a fabricated address: empty endpoint
        // lists are only possible via unvalidated construction.
        let endpoint = self.endpoint.as_ref().ok_or(UpstreamError::NoEndpoints)?;
        let uri: Uri = format!(
            "{}://{}:{}{}",
            self.scheme, endpoint.address, endpoint.port, path
        )
        .parse::<Uri>()
        .map_err(|e| UpstreamError::Io(std::io::Error::other(e.to_string())))?;
        *req.uri_mut() = uri;
        self.stats.requests_sent.fetch_add(1, Ordering::Relaxed);
        let req =
            req.map(|b| http_body_util::combinators::UnsyncBoxBody::new(b.map_err(Into::into)));
        Ok(self.client.request(req).await?)
    }
}

impl std::fmt::Debug for UpstreamHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamHandle")
            .field("name", &self.name)
            .field("cap", &self.cap)
            .field("connect_timeout", &self.connect_timeout)
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

fn effective_cap(u: &Upstream) -> u32 {
    // Validated configs always carry cap >= 1, but a directly constructed
    // (unvalidated) Gateway can bypass that; a zero-permit semaphore would
    // hang every dial forever. Clamp so misuse degrades to serial.
    u.connection_cap.unwrap_or(DEFAULT_CONNECTION_CAP).max(1)
}

fn effective_connect_timeout(u: &Upstream) -> Duration {
    Duration::from_millis(
        u.timeouts
            .as_ref()
            .and_then(|t: &Timeouts| t.connect_ms)
            .unwrap_or(DEFAULT_CONNECT_TIMEOUT_MS),
    )
}

fn build_handle(u: &Upstream, root_store: rustls::RootCertStore) -> Arc<UpstreamHandle> {
    let cap = effective_cap(u);
    let connect_timeout = effective_connect_timeout(u);
    let stats = Arc::new(UpstreamStats::default());

    let mut http = HttpConnector::new();
    http.set_connect_timeout(None); // our timeout wraps dial + TLS handshake
                                    // The connector itself handles the https scheme (TLS dial); without
                                    // this HttpConnector rejects non-http URIs before we ever see them.
    http.enforce_http(false);

    let (scheme, tls, http2_only): (&'static str, Option<_>, bool) = match u.protocol {
        UpstreamProtocol::Http1 => ("http", None, false),
        UpstreamProtocol::Https => {
            let mut cfg = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            ("https", Some(Arc::new(cfg)), false)
        }
        UpstreamProtocol::Http2 => {
            let mut cfg = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            cfg.alpn_protocols = vec![b"h2".to_vec()];
            ("https", Some(Arc::new(cfg)), true)
        }
    };

    let connector = UpstreamConnector {
        http,
        tls,
        cap: Arc::new(Semaphore::new(cap as usize)),
        connect_timeout,
        stats: Arc::clone(&stats),
    };

    let mut builder = Client::builder(TokioExecutor::new());
    if http2_only {
        builder.http2_only(true);
    }
    builder.pool_timer(TokioTimer::new());

    Arc::new(UpstreamHandle {
        name: u.name.clone(),
        cap,
        connect_timeout,
        stats,
        client: builder.build(connector),
        endpoint: u.endpoints.first().cloned(),
        scheme,
    })
}

fn webpki_root_store() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// Registry of per-upstream pooled clients, built from one published
/// snapshot. Rebuild (and drop the old registry) on snapshot swap; in-flight
/// requests keep their old pools until their handles are dropped.
#[derive(Debug, Default)]
pub struct UpstreamRegistry {
    handles: BTreeMap<String, Arc<UpstreamHandle>>,
}

impl UpstreamRegistry {
    /// Build from a snapshot, verifying upstream TLS certificates against
    /// the Mozilla webpki root set.
    pub fn from_snapshot(snapshot: &Snapshot) -> Self {
        // No extra roots are supplied, so the build cannot fail.
        Self::with_root_certificates(snapshot, &[])
            .expect("registry build without extra roots cannot fail")
    }

    /// Build from a snapshot with EXTRA trusted root certificates (e.g. a
    /// private CA signing upstream certificates), added on top of the
    /// webpki roots. Fails if any extra root is malformed, so operators
    /// see the bad certificate at registry build time rather than as a
    /// mysterious handshake failure later.
    pub fn with_root_certificates(
        snapshot: &Snapshot,
        extra_roots: &[CertificateDer<'_>],
    ) -> Result<Self, UpstreamError> {
        let mut roots = webpki_root_store();
        for c in extra_roots {
            roots
                .add(c.clone())
                .map_err(|e| UpstreamError::InvalidRootCertificate(e.to_string()))?;
        }
        Ok(UpstreamRegistry {
            handles: snapshot
                .gateway()
                .upstreams
                .iter()
                .map(|u| (u.name.clone(), build_handle(u, roots.clone())))
                .collect(),
        })
    }

    /// Handle for the named upstream, or None if the snapshot has no such
    /// upstream.
    pub fn get(&self, name: &str) -> Option<Arc<UpstreamHandle>> {
        self.handles.get(name).cloned()
    }

    /// Names of all upstreams in this registry.
    pub fn names(&self) -> Vec<&str> {
        self.handles.keys().map(String::as_str).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Endpoint, Gateway, LoadBalancer, Upstream as ConfigUpstream};
    use crate::snapshot::ConfigState;
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper::{Method, StatusCode};
    use hyper_util::rt::TokioIo;
    use hyper_util::server::conn::auto::Builder as AutoBuilder;
    use std::sync::atomic::AtomicU64;
    use tokio::net::TcpListener;

    fn snapshot_with(up: ConfigUpstream) -> std::sync::Arc<crate::snapshot::Snapshot> {
        crate::tls::install_aws_lc_rs_provider();
        let gw = Gateway {
            listeners: vec![],
            routes: vec![],
            services: vec![],
            upstreams: vec![up],
            consumers: vec![],
            policies: vec![],
        };
        let state = ConfigState::new();
        state.compile_and_publish(&gw).expect("publish");
        state.snapshot()
    }

    fn test_upstream(
        address: String,
        port: u16,
        protocol: UpstreamProtocol,
        cap: Option<u32>,
        connect_ms: Option<u64>,
    ) -> ConfigUpstream {
        ConfigUpstream {
            name: "backend".into(),
            load_balancer: LoadBalancer::RoundRobin,
            protocol,
            endpoints: vec![Endpoint {
                address,
                port,
                weight: 1,
            }],
            connection_cap: cap,
            timeouts: connect_ms.map(|connect_ms| Timeouts {
                connect_ms: Some(connect_ms),
                read_ms: None,
                write_ms: None,
            }),
        }
    }

    fn get_request(path: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .method(Method::GET)
            .uri(path)
            .body(Full::new(Bytes::new()))
            .expect("request")
    }

    /// Serve HTTP (auto h1/h2) on the listener; record accepted
    /// connections and, per request, the concurrency high-water mark
    /// (tracked in `high_water` via fetch_max BEFORE the end-of-request
    /// decrement, so the recorded peak survives after all requests
    /// finish). Each request response is delayed by `delay` so
    /// concurrency can be observed.
    async fn serve(
        listener: TcpListener,
        accepted: Arc<AtomicU64>,
        current: Arc<AtomicU64>,
        high_water: Arc<AtomicU64>,
        delay: Duration,
    ) {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => continue,
            };
            accepted.fetch_add(1, Ordering::SeqCst);
            let current = Arc::clone(&current);
            let high_water = Arc::clone(&high_water);
            let service = service_fn(move |_req: Request<Incoming>| {
                let current = Arc::clone(&current);
                let high_water = Arc::clone(&high_water);
                let delay = delay;
                async move {
                    let active = current.fetch_add(1, Ordering::SeqCst) + 1;
                    high_water.fetch_max(active, Ordering::SeqCst);
                    tokio::time::sleep(delay).await;
                    current.fetch_sub(1, Ordering::SeqCst);
                    Ok::<Response<Full<Bytes>>, std::convert::Infallible>(Response::new(Full::new(
                        Bytes::new(),
                    )))
                }
            });
            tokio::spawn(async move {
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(TokioIo::new(stream), service)
                    .await;
            });
        }
    }

    #[tokio::test]
    async fn sequential_requests_reuse_one_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicU64::new(0));
        let current = Arc::new(AtomicU64::new(0));
        let high_water = Arc::new(AtomicU64::new(0));
        tokio::spawn(serve(
            listener,
            Arc::clone(&accepted),
            Arc::clone(&current),
            Arc::clone(&high_water),
            Duration::ZERO,
        ));

        let snap = snapshot_with(test_upstream(
            "127.0.0.1".into(),
            port,
            UpstreamProtocol::Http1,
            None,
            None,
        ));
        let registry = UpstreamRegistry::from_snapshot(&snap);
        let handle = registry.get("backend").expect("handle");

        assert_eq!(handle.cap(), DEFAULT_CONNECTION_CAP);
        assert_eq!(
            handle.connect_timeout(),
            Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS)
        );

        for _ in 0..4 {
            let resp = handle.send(get_request("/v1/users")).await.expect("sent");
            assert_eq!(resp.status(), StatusCode::OK);
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "connection reused");
        assert_eq!(handle.connections_opened(), 1);
        assert_eq!(handle.requests_sent(), 4);
    }

    #[tokio::test]
    async fn connection_cap_limits_concurrent_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicU64::new(0));
        let current = Arc::new(AtomicU64::new(0));
        let high_water = Arc::new(AtomicU64::new(0));
        tokio::spawn(serve(
            listener,
            Arc::clone(&accepted),
            Arc::clone(&current),
            Arc::clone(&high_water),
            Duration::from_millis(150),
        ));

        let snap = snapshot_with(test_upstream(
            "127.0.0.1".into(),
            port,
            UpstreamProtocol::Http1,
            Some(2),
            None,
        ));
        let registry = UpstreamRegistry::from_snapshot(&snap);
        let handle = registry.get("backend").expect("handle");
        assert_eq!(handle.cap(), 2);

        let mut tasks = Vec::new();
        for _ in 0..4 {
            let h = Arc::clone(&handle);
            tasks.push(tokio::spawn(async move {
                let resp = h.send(get_request("/slow")).await.expect("sent");
                assert_eq!(resp.status(), StatusCode::OK);
            }));
        }
        for t in tasks {
            t.await.expect("task");
        }
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            2,
            "exactly cap-many connections established"
        );
        assert_eq!(
            high_water.load(Ordering::SeqCst),
            2,
            "server saw exactly cap-many concurrent requests at peak"
        );
    }

    #[tokio::test]
    async fn connect_timeout_fails_within_bound() {
        // 10.255.255.1 is a non-routable address: the TCP SYN gets no
        // answer, so the connect hangs until our timeout fires.
        let snap = snapshot_with(test_upstream(
            "10.255.255.1".into(),
            81,
            UpstreamProtocol::Http1,
            None,
            Some(250),
        ));
        let registry = UpstreamRegistry::from_snapshot(&snap);
        let handle = registry.get("backend").expect("handle");
        assert_eq!(handle.connect_timeout(), Duration::from_millis(250));

        let started = std::time::Instant::now();
        let err = handle.send(get_request("/x")).await.expect_err("times out");
        match err {
            UpstreamError::ConnectTimeout { after } => {
                assert_eq!(after, Duration::from_millis(250))
            }
            other => panic!("expected ConnectTimeout, got {other:?}"),
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "failed within the bound, took {:?}",
            started.elapsed()
        );
    }

    /// TLS server answering h1 or h2 depending on the client's ALPN.
    async fn serve_tls(listener: TcpListener, cert: rcgen::CertifiedKey, accepted: Arc<AtomicU64>) {
        let mut server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
                ),
            )
            .expect("server cert");
        server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => continue,
            };
            accepted.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(|_req: Request<Incoming>| async {
                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::new())))
                });
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(TokioIo::new(tls), service)
                    .await;
            });
        }
    }

    fn tls_snapshot(
        port: u16,
        protocol: UpstreamProtocol,
    ) -> std::sync::Arc<crate::snapshot::Snapshot> {
        snapshot_with(test_upstream(
            "localhost".into(),
            port,
            protocol,
            None,
            None,
        ))
    }

    #[tokio::test]
    async fn https_upstream_negotiates_tls_h1_and_reuses() {
        crate::tls::install_aws_lc_rs_provider();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicU64::new(0));
        let root = cert.cert.der().clone();
        tokio::spawn(serve_tls(listener, cert, Arc::clone(&accepted)));

        let snap = tls_snapshot(port, UpstreamProtocol::Https);
        let registry =
            UpstreamRegistry::with_root_certificates(&snap, &[root]).expect("roots accepted");
        let handle = registry.get("backend").expect("handle");
        assert_eq!(handle.scheme(), "https");

        for _ in 0..3 {
            let resp = handle.send(get_request("/secure")).await.expect("sent");
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            assert!(body.is_empty());
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "TLS connection reused");
    }

    #[tokio::test]
    async fn http2_upstream_negotiates_alpn_h2_and_reuses() {
        crate::tls::install_aws_lc_rs_provider();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicU64::new(0));
        let root = cert.cert.der().clone();
        tokio::spawn(serve_tls(listener, cert, Arc::clone(&accepted)));

        let snap = tls_snapshot(port, UpstreamProtocol::Http2);
        let registry =
            UpstreamRegistry::with_root_certificates(&snap, &[root]).expect("roots accepted");
        let handle = registry.get("backend").expect("handle");
        assert_eq!(handle.scheme(), "https");

        // h2 multiplexes: even concurrent requests share one connection.
        let mut tasks = Vec::new();
        for _ in 0..4 {
            let h = Arc::clone(&handle);
            tasks.push(tokio::spawn(async move {
                let resp = h.send(get_request("/h2")).await.expect("sent");
                assert_eq!(resp.status(), StatusCode::OK);
            }));
        }
        for t in tasks {
            t.await.expect("task");
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "h2 connection reused");
    }

    #[tokio::test]
    async fn https_upstream_rejects_untrusted_server_cert() {
        crate::tls::install_aws_lc_rs_provider();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(serve_tls(listener, cert, Arc::new(AtomicU64::new(0))));

        // No extra roots: the self-signed server cert is untrusted.
        let snap = tls_snapshot(port, UpstreamProtocol::Https);
        let registry = UpstreamRegistry::from_snapshot(&snap);
        let handle = registry.get("backend").expect("handle");
        let result = handle.send(get_request("/secure")).await;
        assert!(result.is_err(), "untrusted certificate must be rejected");
    }

    // --- validation of the new schema fields (pure checks) ---------------

    #[test]
    fn validate_rejects_zero_connection_cap_and_zero_timeouts() {
        let issues = crate::snapshot::validate(&Gateway {
            listeners: vec![],
            routes: vec![],
            services: vec![],
            upstreams: vec![ConfigUpstream {
                name: "u".into(),
                load_balancer: LoadBalancer::RoundRobin,
                protocol: UpstreamProtocol::Http1,
                endpoints: vec![Endpoint {
                    address: "127.0.0.1".into(),
                    port: 9001,
                    weight: 1,
                }],
                connection_cap: Some(0),
                timeouts: Some(Timeouts {
                    connect_ms: Some(0),
                    read_ms: Some(0),
                    write_ms: None,
                }),
            }],
            consumers: vec![],
            policies: vec![],
        });
        let fields: Vec<&str> = issues.iter().map(|i| i.field.as_str()).collect();
        assert!(fields.contains(&"connection_cap"));
        assert!(fields.contains(&"timeouts.connect_ms"));
        assert!(fields.contains(&"timeouts.read_ms"));
        assert!(!fields.contains(&"timeouts.write_ms"));
    }

    #[test]
    fn effective_cap_clamps_zero_to_one() {
        // Only reachable via unvalidated direct construction (validation
        // rejects cap == 0); must degrade to serial, never a hang.
        let up = test_upstream(
            "127.0.0.1".into(),
            80,
            UpstreamProtocol::Http1,
            Some(0),
            None,
        );
        assert_eq!(effective_cap(&up), 1);
    }

    #[tokio::test]
    async fn send_without_endpoints_returns_no_endpoints() {
        // Only reachable via unvalidated direct construction; send() is
        // the guard, so the handle dials no fabricated address.
        let up = ConfigUpstream {
            name: "bare".into(),
            load_balancer: LoadBalancer::RoundRobin,
            protocol: UpstreamProtocol::Http1,
            endpoints: vec![],
            connection_cap: None,
            timeouts: None,
        };
        let handle = build_handle(&up, webpki_root_store());
        assert!(matches!(
            handle.send(get_request("/x")).await,
            Err(UpstreamError::NoEndpoints)
        ));
    }

    #[test]
    fn with_root_certificates_rejects_malformed_root() {
        crate::tls::install_aws_lc_rs_provider();
        let state = ConfigState::new();
        state
            .compile_and_publish(&Gateway {
                listeners: vec![],
                routes: vec![],
                services: vec![],
                upstreams: vec![],
                consumers: vec![],
                policies: vec![],
            })
            .expect("publish");
        let bad = CertificateDer::from(vec![0u8; 8]); // not a DER certificate
        assert!(matches!(
            UpstreamRegistry::with_root_certificates(&state.snapshot(), &[bad]),
            Err(UpstreamError::InvalidRootCertificate(_))
        ));
    }

    // Compile-time covers of unused-import surface kept honest.
    #[test]
    fn empty_registry_has_no_handles() {
        let state = ConfigState::new();
        let registry = UpstreamRegistry::from_snapshot(&state.snapshot());
        assert!(registry.get("nope").is_none());
        assert!(registry.names().is_empty());
    }
}
