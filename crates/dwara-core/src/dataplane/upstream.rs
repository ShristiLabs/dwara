//! Pooled upstream clients (DW-008, feature analysis 4.1).
//!
//! One hyper-util legacy client (a connection pool) per configured
//! upstream, keyed by upstream name inside an [`UpstreamRegistry`]. Each
//! pool's connector is tuned per upstream:
//!
//! - **Connect timeout**: `timeouts.connect_ms` (default 5 s) wraps the
//!   whole dial: resolution plus TCP connect plus, for TLS upstreams,
//!   the TLS handshake.
//! - **Happy-eyeballs dial** (DW-030, RFC 8305): an endpoint address
//!   that resolves to multiple addresses — the dual-stack hostname
//!   case — is dialed with interleaved address-family attempts
//!   (`timeouts.happy_eyeballs_ms`, default 250 ms, `0` disables):
//!   the resolver's first address defines the preferred family
//!   (RFC 8305 leaves the preference to the resolver's order — the
//!   system's RFC 6724 sort), the first attempt starts immediately,
//!   each subsequent attempt starts one delay after the previous
//!   START (or immediately when an attempt fails with nothing else in
//!   flight), and the first success wins, cancelling the losers.
//!   Exactly ONE outcome — the overall dial's — reaches the breaker
//!   and passive-health accounting: the losing arms of one dial are
//!   dial-internal retries, never endpoint failures. The dial (and
//!   the [`happy_race`] primitive beneath it) is ours, not
//!   hyper-util's implicit default: the RFC 8305 shape is now
//!   documented, configurable, and observable in tests. DNS
//!   resolution is `getaddrinfo` on the blocking pool
//!   (`tokio::net::lookup_host`), the same resolver hyper-util's
//!   `HttpConnector` used here before DW-030.
//! - **Read timeout (per-attempt)**: `timeouts.read_ms` wraps each pooled
//!   request/response-header exchange (DW-014) — from the moment the
//!   request is handed to the pool (including any connection-cap queue
//!   wait and the dial) until the response HEADERS resolve. It is
//!   therefore also the per-attempt total bound: pool wait + connect +
//!   write request + read headers, all inside one `read_ms` deadline.
//!   A request whose headers do not arrive in time fails with
//!   [`UpstreamError::ReadTimeout`] (classified 504 by the proxy, and a
//!   retryable transport-class failure when retries are enabled). The
//!   response BODY is not covered by `read_ms`.
//! - **Write timeout (body idle)**: `timeouts.write_ms` bounds the
//!   response body stream as an INACTIVITY timeout (DW-014): the body
//!   wrapper [`UpstreamBody`] errors with [`UpstreamBodyError::WriteTimeout`]
//!   when the gap between two body frames exceeds `write_ms`. It is not a
//!   total streaming budget — a body that keeps trickling frames never
//!   trips it. The wrapper also reports a mid-stream abort (transport
//!   error or idle timeout after headers resolved) as a passive-health
//!   FAILURE for the picked endpoint, closing the DW-012 gap where
//!   mid-body deaths were invisible to ejection. Requires a body wrapper:
//!   the handle's response type is `Response<UpstreamBody>`, not
//!   `Response<Incoming>` (documented; the wrapper is a thin frame
//!   passthrough when both knobs are unset).
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
//! - **Pending cap** (DW-015): `max_pending` (default: absent = unbounded)
//!   bounds how many requests may WAIT for a connection-cap slot. Over
//!   that, the connector fails fast with [`UpstreamError::Saturated`]
//!   (classified 503 "upstream saturated" by the proxy) instead of
//!   queueing; a pending slot is held from the dial attempt until the
//!   connection-cap permit is acquired, then released (the request is
//!   connecting, no longer pending).
//! - **TLS**: `https` upstreams negotiate TLS with ALPN `http/1.1`;
//!   `http2` upstreams negotiate TLS with ALPN `h2` and lock the client to
//!   HTTP/2; `http1` upstreams dial plaintext. Server certificates are
//!   verified against the Mozilla webpki root set by default (chosen over
//!   system roots for determinism in tests; system roots are a follow-up).
//!   Private-CA upstreams are configured per upstream via
//!   `trusted_ca_file` (#121): the PEM bundle REPLACES the public roots
//!   for that upstream, and its active https health probes verify against
//!   the same roots (see the handle's [`UpstreamHandle::tls_roots`]).
//!   Programmatic callers can still add extra roots on top of the public
//!   set via [`UpstreamRegistry::with_root_certificates`].
//!
//! Load balancing (DW-011): every dispatch picks its endpoint through the
//! upstream's [`crate::dataplane::balance::UpstreamLb`] (smooth weighted round-robin,
//! least-connections, random-2, or ketama ip-hash; slow-start ramps; hot
//! endpoint-set swaps that carry per-address state). Config lifecycle:
//! build a registry from a published snapshot; reloads rebuild it from the
//! new snapshot while carrying balancer state (see
//! [`UpstreamRegistry::from_snapshot_with_previous`]), mirroring how
//! `TlsTermination` is reloaded.
//!
//! Retries (DW-014) are driven from the proxy (which owns the request
//! body replay decision); the handle exposes the resolved
//! [`crate::resilience::retries::RetryParams`] and the per-upstream
//! [`crate::resilience::retries::RetryBudget`] for that loop, and every `send` call is
//! one ATTEMPT (fresh load-balancer pick, fresh per-attempt deadlines).

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http_body_util::BodyExt as _;
use hyper::body::{Bytes, Frame, Incoming};
use hyper::{Request, Response, Uri, Version};
use hyper_util::client::legacy::connect::{Connected, Connection as HyperConnection};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tower_service::Service;

use crate::config::limits::MAX_SLOW_START_MS;
use crate::config::{Timeouts, Upstream, UpstreamProtocol};
use crate::observability::Observability;
use crate::resilience::breaker::{Breaker, BreakerParams, BreakerState};
use crate::resilience::health::HealthDispatch;
use crate::resilience::retries::{HedgeParams, RetryBudget, RetryParams};
use crate::snapshot::Snapshot;

/// Default connection cap when `connection_cap` is absent.
pub const DEFAULT_CONNECTION_CAP: u32 = 64;
/// Default connect timeout when `timeouts.connect_ms` is absent.
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 5_000;

/// System millisecond clock for a freshly built breaker (the breaker's
/// own `system_now_ms` is private to its module).
fn system_now_ms_for_breaker() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

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
    /// The per-attempt deadline (`timeouts.read_ms`) expired before the
    /// response headers resolved. Covers pool-queue wait + connect +
    /// request write + header read; see the module docs (DW-014).
    ReadTimeout { after: Duration },
    /// The per-upstream pending cap (`max_pending`, DW-015) is full: the
    /// request would have to WAIT for an outbound connection slot and the
    /// config chose immediate rejection over queueing. Classified 503
    /// ("upstream saturated") by the proxy; NOT retryable (the upstream is
    /// saturated by definition — a retry adds load).
    Saturated,
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
            UpstreamError::Saturated => {
                write!(f, "upstream pending queue is saturated")
            }
            UpstreamError::InvalidRootCertificate(e) => {
                write!(f, "unusable root certificate: {e}")
            }
            UpstreamError::InvalidHost(h) => {
                write!(f, "endpoint address '{h}' is not a valid TLS server name")
            }
            UpstreamError::ConnectTimeout { after } => {
                write!(f, "upstream connect timed out after {after:?}")
            }
            UpstreamError::ReadTimeout { after } => {
                write!(f, "upstream response headers timed out after {after:?}")
            }
            UpstreamError::Io(e) => write!(f, "upstream connect failed: {e}"),
            UpstreamError::Client(e) => write!(f, "upstream request failed: {e}"),
        }
    }
}

impl std::error::Error for UpstreamError {}

/// Whether a send-path error reflects a genuine transport/exchange
/// failure of the picked endpoint (and therefore feeds passive health).
/// Client-side admission rejections (Saturated — the request never
/// contacted the endpoint) and configuration-class errors (NoEndpoints,
/// InvalidRootCertificate, InvalidHost) would eject the endpoint for
/// reasons unrelated to its health, so they are not reported.
fn health_reportable(err: &UpstreamError) -> bool {
    !matches!(
        err,
        UpstreamError::Saturated
            | UpstreamError::NoEndpoints
            | UpstreamError::InvalidRootCertificate(_)
            | UpstreamError::InvalidHost(_)
    )
}

/// [`health_reportable`] over a legacy client error: our typed connector
/// errors (Saturated, InvalidHost, ...) ride in its source chain, so walk
/// it; anything else is a genuine transport failure of the exchange.
fn health_reportable_legacy(err: &hyper_util::client::legacy::Error) -> bool {
    let mut src: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(s) = src {
        if let Some(u) = s.downcast_ref::<UpstreamError>() {
            return health_reportable(u);
        }
        src = s.source();
    }
    true
}

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
                    UpstreamError::Saturated => return UpstreamError::Saturated,
                    _ => {}
                }
            }
            src = std::error::Error::source(s);
        }
        UpstreamError::Client(e)
    }
}

/// Error surfaced by a streamed upstream response body
/// ([`UpstreamBody`], DW-014).
#[derive(Debug)]
pub enum UpstreamBodyError {
    /// The underlying transport errored mid-stream (connection reset,
    /// framing error, ...).
    Upstream(hyper::Error),
    /// The gap between two body frames exceeded `timeouts.write_ms`
    /// (inactivity timeout; see the module docs).
    WriteTimeout { after: Duration },
    /// The response body crossed its ABSOLUTE deadline (DW-039: a
    /// gRPC request's `grpc-timeout` covers the whole RPC, so the
    /// deadline armed at dispatch keeps ticking through the body).
    DeadlineExceeded,
}

impl std::fmt::Display for UpstreamBodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpstreamBodyError::Upstream(e) => write!(f, "upstream body failed: {e}"),
            UpstreamBodyError::WriteTimeout { after } => {
                write!(f, "upstream body stalled for more than {after:?}")
            }
            UpstreamBodyError::DeadlineExceeded => {
                write!(f, "response crossed its request deadline (grpc-timeout)")
            }
        }
    }
}

impl std::error::Error for UpstreamBodyError {}

/// Streaming upstream response body: the pooled `Incoming` wrapped with the
/// DW-014 response-side knobs. A thin frame passthrough when both knobs
/// are unset; otherwise:
///
/// - `idle` (from `timeouts.write_ms`): an inactivity timeout — if the gap
///   between two consecutive body frames exceeds the duration, the body
///   errors with [`UpstreamBodyError::WriteTimeout`]. Implemented by
///   arming a `tokio::time::Sleep` on every `Pending` poll and clearing it
///   on every frame; the timer is only alive while the stream is idle, so
///   an actively-trickling body never trips it (documented: it bounds
///   stalls, not total streaming time).
/// - `health`: when the dispatch carried passive health, a mid-stream
///   failure (transport error or idle timeout — either way the endpoint
///   died AFTER headers resolved) is reported as a health FAILURE to the
///   picked endpoint's tracker, closing the DW-012 gap where mid-body
///   aborts were invisible to ejection. A clean end-of-stream reports
///   nothing: the header-resolution report already classified the
///   exchange, and doubling successes would dilute failure ratios.
///
/// The error is terminal for the stream: frames already forwarded to the
/// client end abruptly (HTTP/1.1 truncation semantics); it is never
/// retried (an attempt is final once its headers resolved).
pub struct UpstreamBody {
    inner: Incoming,
    idle: Option<Duration>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    health: Option<(Arc<crate::dataplane::balance::UpstreamLb>, HealthDispatch)>,
    /// Gateway concurrency-cap permit (DW-015), attached by the proxy to
    /// STREAMING responses so the global slot is held until the body
    /// completes (or the response is dropped — client disconnect included).
    /// Dropped with the body; no polling logic needed.
    release: Option<OwnedSemaphorePermit>,
    /// ABSOLUTE deadline for the body (DW-039): a gRPC request's
    /// `grpc-timeout` covers the whole RPC, so the same deadline that
    /// bounded the forward keeps ticking here. Checked at the top of
    /// every poll; unlike `idle`, no timer is armed — the deadline is
    /// compared against the clock each poll the frame path runs, and
    /// the body's own activity drives polling (a body mid-flight
    /// polls constantly; a stalled one is bounded by the idle timer
    /// first). `None` = no deadline.
    deadline: Option<std::time::Instant>,
}

impl hyper::body::Body for UpstreamBody {
    type Data = Bytes;
    type Error = UpstreamBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, UpstreamBodyError>>> {
        let this = self.get_mut();
        loop {
            // Absolute deadline (DW-039): fires whether or not the inner
            // stream is active — the RPC is over when it is over.
            if let Some(deadline) = this.deadline {
                if std::time::Instant::now() >= deadline {
                    this.report_health_failure();
                    return Poll::Ready(Some(Err(UpstreamBodyError::DeadlineExceeded)));
                }
            }
            // Idle deadline armed: check it before (and after) polling the
            // inner stream so an elapsed stall errors even when the inner
            // stream is still Pending.
            if let Some(sleep) = &mut this.sleep {
                if sleep.as_mut().poll(cx).is_ready() {
                    this.report_health_failure();
                    return Poll::Ready(Some(Err(UpstreamBodyError::WriteTimeout {
                        after: this.idle.unwrap_or_default(),
                    })));
                }
            }
            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    // Activity: clear any armed deadline.
                    this.sleep = None;
                    return Poll::Ready(Some(Ok(frame)));
                }
                Poll::Ready(Some(Err(e))) => {
                    this.report_health_failure();
                    return Poll::Ready(Some(Err(UpstreamBodyError::Upstream(e))));
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => {
                    if this.idle.is_some() && this.sleep.is_none() {
                        this.sleep =
                            Some(Box::pin(tokio::time::sleep(this.idle.unwrap_or_default())));
                        // Loop once more so the fresh timer registers its
                        // waker with the executor before we return Pending.
                        continue;
                    }
                    return Poll::Pending;
                }
            }
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}

impl std::fmt::Debug for UpstreamBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamBody")
            .field("idle_timeout", &self.idle)
            .field("health_reporting", &self.health.is_some())
            .finish_non_exhaustive()
    }
}

impl UpstreamBody {
    /// Report a mid-stream failure to the dispatch's health tracker, if any.
    fn report_health_failure(&mut self) {
        if let Some((lb, hd)) = &self.health.take() {
            hd.report(lb.now_ms(), true);
        }
    }

    /// Attach the gateway concurrency-cap permit (DW-015): it releases
    /// when this body completes or is dropped, which is exactly the
    /// "release at body completion" contract of the global cap.
    pub fn set_release_permit(&mut self, permit: OwnedSemaphorePermit) {
        self.release = Some(permit);
    }

    /// Arm the ABSOLUTE body deadline (DW-039): set by the proxy from a
    /// gRPC request's `grpc-timeout` (the deadline that bounded the
    /// forward, continuing through the body — the RPC's total budget).
    pub fn set_deadline(&mut self, deadline: std::time::Instant) {
        self.deadline = Some(deadline);
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

/// Default happy-eyeballs inter-connection delay when
/// `timeouts.happy_eyeballs_ms` is absent (the RFC 8305 recommended
/// value; DW-030).
pub const DEFAULT_HAPPY_EYEBALLS_MS: u64 = 250;

/// `timeouts.happy_eyeballs_ms`, resolved to the effective racing delay:
/// absent -> the RFC 8305 default; `0` -> None (racing disabled, strict
/// resolver order); otherwise the configured value (clamped to the
/// ceiling in `config::limits`; validation has already rejected
/// over-cap values).
fn effective_happy_eyeballs(u: &Upstream) -> Option<Duration> {
    match u.timeouts.as_ref().and_then(|t| t.happy_eyeballs_ms) {
        None => Some(Duration::from_millis(DEFAULT_HAPPY_EYEBALLS_MS)),
        Some(0) => None,
        Some(ms) => Some(Duration::from_millis(
            ms.min(crate::config::limits::MAX_HAPPY_EYEBALLS_MS),
        )),
    }
}

/// RFC 8305 address ordering (DW-030): the resolver's FIRST address keeps
/// its place and defines the preferred family; the remainder follow with
/// the OTHER family second, alternating onward — so the gateway reaches
/// the second family after one inter-connection delay no matter how long
/// the preferred family's list is.
///
/// `#[doc(hidden)]` public for the unit tests in `tests/unit/upstream.rs`
/// (pure ordering function; exercising it through real dials would need
/// controllable DNS, which the test environment cannot provide).
#[doc(hidden)]
pub fn interleave_order(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    if addrs.len() < 2 {
        return addrs.to_vec();
    }
    let preferred_v6 = addrs[0].is_ipv6();
    let mut preferred: VecDeque<SocketAddr> = VecDeque::new();
    let mut other: VecDeque<SocketAddr> = VecDeque::new();
    for a in addrs {
        if a.is_ipv6() == preferred_v6 {
            preferred.push_back(*a);
        } else {
            other.push_back(*a);
        }
    }
    let mut out = Vec::with_capacity(addrs.len());
    while let (Some(a), maybe_b) = (preferred.pop_front(), other.front()) {
        out.push(a);
        if let Some(b) = maybe_b {
            out.push(*b);
            other.pop_front();
        }
    }
    out
}

/// Race connection attempts across addresses, RFC 8305 shape (DW-030).
///
/// Starts an attempt on `seq`'s first address immediately; each further
/// attempt starts `delay` after the previous START — or immediately when
/// an attempt FAILS and nothing else is in flight (RFC 8305 5.2's
/// failure fast-forward). The first success wins and cancelling the
/// losers is dropping the [`JoinSet`]; an all-failed race surfaces the
/// LAST error. Generic over the dial so the unit tests can drive it with
/// controllable futures (real dials cannot make "the first address hangs"
/// deterministic on loopback); `#[doc(hidden)]` for that test seam.
#[doc(hidden)]
pub async fn happy_race<F, Fut, T>(
    seq: Vec<SocketAddr>,
    delay: Option<Duration>,
    dial: F,
) -> std::io::Result<T>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = std::io::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    // Racing disabled (or a single address): strict order, one at a
    // time — the pre-DW-030 dial semantics.
    let Some(delay) = delay.filter(|d| !d.is_zero()) else {
        let mut last = None;
        for a in seq {
            match dial(a).await {
                Ok(t) => return Ok(t),
                Err(e) => last = Some(e),
            }
        }
        return Err(last.unwrap_or_else(no_addresses));
    };
    let mut set: JoinSet<std::io::Result<T>> = JoinSet::new();
    let mut it = seq.into_iter().peekable();
    let mut last_err: Option<std::io::Error> = None;
    let Some(first) = it.next() else {
        return Err(no_addresses());
    };
    set.spawn(dial(first));
    let next_start = tokio::time::sleep(delay);
    tokio::pin!(next_start);
    loop {
        tokio::select! {
            joined = set.join_next() => {
                match joined.expect("join_next polled on a non-empty JoinSet") {
                    // First success wins; returning drops `set`, which
                    // cancels every losing arm mid-connect.
                    Ok(Ok(t)) => return Ok(t),
                    Ok(Err(e)) => last_err = Some(e),
                    // A panicking dial task is a bug, not an address
                    // being unreachable — surface it loudly.
                    Err(join_err) => {
                        return Err(std::io::Error::other(format!("dial task failed: {join_err}")))
                    }
                }
            }
            _ = &mut next_start, if it.peek().is_some() => {
                let a = it.next().expect("peek guaranteed an address");
                set.spawn(dial(a));
                next_start.as_mut().reset(tokio::time::Instant::now() + delay);
            }
        }
        // RFC 8305 failure fast-forward: with nothing in flight, the
        // next attempt starts NOW instead of waiting out the delay (the
        // peer already refused; a delay would only add latency).
        if set.is_empty() {
            match it.next() {
                Some(a) => {
                    set.spawn(dial(a));
                    next_start
                        .as_mut()
                        .reset(tokio::time::Instant::now() + delay);
                }
                None => {
                    return Err(last_err.take().unwrap_or_else(no_addresses));
                }
            }
        }
    }
}

/// The empty-address-list error (both racing modes share it).
fn no_addresses() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, "no addresses to dial")
}

/// Resolve one endpoint authority and dial it with the RFC 8305 racing
/// (DW-030). IP-literal authorities skip DNS entirely (the resolver's
/// short-circuit, the same path `getaddrinfo` takes); a multi-address
/// resolution races per `delay`. One dial, one outcome: the caller's
/// health/breaker accounting sees exactly this Result, never the losing
/// arms' failures. Shared by the pooled connector and the active health
/// probes (one dialing discipline per upstream).
pub async fn happy_dial(
    host: &str,
    port: u16,
    delay: Option<Duration>,
) -> std::io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("'{host}:{port}' resolved to no addresses"),
        ));
    }
    let seq = interleave_order(&addrs);
    happy_race(seq, delay, |addr| async move {
        let stream = TcpStream::connect(addr).await?;
        // Preserve the pre-DW-030 hyper-util connector behavior: NODELAY
        // on the proxy hop (latency over throughput on stream request/
        // response exchanges).
        let _ = stream.set_nodelay(true);
        Ok(stream)
    })
    .await
}

/// Per-upstream connector: RFC 8305 resolve + dial (DW-030), optional
/// rustls TLS with baked-in ALPN, the connect timeout, and the
/// connection-cap semaphore.
#[derive(Clone)]
struct UpstreamConnector {
    /// Happy-eyeballs inter-connection delay; None = racing disabled
    /// (`timeouts.happy_eyeballs_ms: 0`, strict resolver order).
    happy_eyeballs: Option<Duration>,
    /// TLS client config (ALPN already set) for https/http2 upstreams.
    tls: Option<Arc<rustls::ClientConfig>>,
    cap: Arc<Semaphore>,
    /// Pending-request cap (`max_pending`, DW-015). None = unbounded
    /// queueing (the DW-008 behavior). Some = at most this many requests
    /// may WAIT for a connection-cap slot; further dials fail fast with
    /// [`UpstreamError::Saturated`].
    pending_cap: Option<Arc<Semaphore>>,
    connect_timeout: Duration,
    stats: Arc<UpstreamStats>,
}

impl Service<Uri> for UpstreamConnector {
    type Response = CappedStream;
    type Error = UpstreamError;
    type Future =
        Pin<Box<dyn Future<Output = Result<CappedStream, UpstreamError>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Resolution happens inside `call` (tokio's blocking-pool
        // getaddrinfo needs no readiness gating).
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let happy_eyeballs = self.happy_eyeballs;
        let tls = self.tls.clone();
        let cap = Arc::clone(&self.cap);
        let pending_cap = self.pending_cap.clone();
        let connect_timeout = self.connect_timeout;
        let stats = Arc::clone(&self.stats);
        // Pending admission (DW-015) happens OUTSIDE the async block so a
        // saturated upstream rejects immediately: a request that would
        // have to queue behind more than `max_pending` waiters never even
        // arms its dial. The pending permit is held only while the request
        // is WAITING for a connection-cap slot and is dropped the moment
        // the cap permit is acquired (the request is then connecting, no
        // longer pending).
        let _pending = match pending_cap {
            Some(pc) => match pc.try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    return Box::pin(async { Err(UpstreamError::Saturated) });
                }
            },
            None => None,
        };
        Box::pin(async move {
            // Acquire a cap slot BEFORE dialing. The semaphore is never
            // closed, so acquire cannot fail; waiting here is the cap's
            // documented backpressure (queue, never fail).
            let permit = cap
                .acquire_owned()
                .await
                .expect("connection-cap semaphore is never closed");
            // Connection slot acquired: no longer pending. Dropping the
            // permit here (before the dial) frees the pending slot for
            // the next request.
            drop(_pending);
            // `Uri::host()` keeps IPv6 brackets ("[::1]"); the resolver
            // and rustls `ServerName` want the bare address ("::1").
            // hyper-util's GaiResolver stripped these internally — the
            // DW-030 dial is ours, so the strip is ours too.
            let uri_host = uri.host().unwrap_or_default();
            let host = uri_host
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .unwrap_or(uri_host)
                .to_string();
            // The authority always carries the configured endpoint port
            // (endpoint_authority); the defaults are the inert fallback
            // for a hand-built URI.
            let port = uri
                .port_u16()
                .unwrap_or(if tls.is_some() { 443 } else { 80 });
            let dial = async {
                let tcp = happy_dial(&host, port, happy_eyeballs)
                    .await
                    .map_err(UpstreamError::Io)?;
                let transport = match tls {
                    Some(config) => {
                        let name = ServerName::try_from(host.clone())
                            .map_err(|_| UpstreamError::InvalidHost(host.clone()))?;
                        let connector = tokio_rustls::TlsConnector::from(config);
                        let tls_stream = connector
                            .connect(name, tcp)
                            .await
                            .map_err(|e| std::io::Error::other(e.to_string()))?;
                        Transport::Tls(Box::new(TokioIo::new(tls_stream)))
                    }
                    None => Transport::Plain(TokioIo::new(tcp)),
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
    /// Per-attempt deadline over pool wait + connect + request write +
    /// response headers (`timeouts.read_ms`; DW-014). None = unbounded.
    read_timeout: Option<Duration>,
    /// Response-body inactivity timeout (`timeouts.write_ms`; DW-014).
    /// None = unbounded.
    write_timeout: Option<Duration>,
    /// Resolved retry parameters (`upstreams[].retries`; DW-014).
    /// `attempts == 0` means retries off.
    retries: RetryParams,
    /// Resolved hedge parameters (DW-063); extracted from `retries.hedge`
    /// for convenience. `hedge_after == ZERO` means hedging is disabled.
    hedge: HedgeParams,
    /// Rolling-window retry budget, carried across reloads like the
    /// balancer.
    retry_budget: Arc<RetryBudget>,
    /// Effective pending cap (`max_pending`, DW-015); 0 = unbounded.
    max_pending: u32,
    /// Per-upstream circuit breaker state (DW-015), carried across reloads
    /// like the retry budget. Always present (state-only object); whether
    /// the breaker is ENABLED is `breaker_params`.
    breaker: Arc<Breaker>,
    /// Resolved breaker parameters; None disables the breaker (the proxy
    /// then never consults it — behavior identical to pre-DW-015).
    breaker_params: Option<BreakerParams>,
    /// Resolved happy-eyeballs delay (DW-030); None = racing disabled.
    /// Kept on the handle so the active health probes dial with the same
    /// discipline as the pooled connector.
    happy_eyeballs: Option<Duration>,
    stats: Arc<UpstreamStats>,
    client: Client<
        UpstreamConnector,
        http_body_util::combinators::UnsyncBoxBody<
            bytes::Bytes,
            Box<dyn std::error::Error + Send + Sync>,
        >,
    >,
    /// Load balancer over this upstream's endpoint set (DW-011); picks
    /// the endpoint per dispatch and tracks in-flight counts.
    lb: Arc<crate::dataplane::balance::UpstreamLb>,
    scheme: &'static str,
    http2_only: bool,
    /// The trust roots this upstream's TLS connections verify against
    /// (#121): None for plaintext `http1` upstreams, the configured
    /// `trusted_ca_file` bundle when set, else the webpki public set.
    /// Kept on the handle so the active https health probes use the
    /// SAME trust as the pooled connector.
    tls_roots: Option<rustls::RootCertStore>,
}

/// `address:port` with IPv6 literals bracketed. `::1:8080` is not a
/// parseable URI authority; `[::1]:8080` is.
fn endpoint_authority(address: &str, port: u16) -> String {
    let host = if address.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{address}]")
    } else {
        address.to_string()
    };
    format!("{host}:{port}")
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

    /// Effective happy-eyeballs delay (DW-030); None = racing disabled.
    pub fn happy_eyeballs(&self) -> Option<Duration> {
        self.happy_eyeballs
    }

    /// Per-attempt read timeout (`timeouts.read_ms`), if configured.
    pub fn read_timeout(&self) -> Option<Duration> {
        self.read_timeout
    }

    /// Response-body inactivity timeout (`timeouts.write_ms`), if
    /// configured.
    pub fn write_timeout(&self) -> Option<Duration> {
        self.write_timeout
    }

    /// Resolved retry parameters (DW-014). `attempts == 0` = retries off.
    pub fn retry_params(&self) -> &RetryParams {
        &self.retries
    }

    /// Resolved hedge parameters (DW-063).
    pub fn hedge_params(&self) -> &HedgeParams {
        &self.hedge
    }

    /// This upstream's rolling-window retry budget (DW-014).
    pub fn retry_budget(&self) -> &Arc<RetryBudget> {
        &self.retry_budget
    }

    /// Effective pending cap (DW-015); 0 = unbounded queueing.
    pub fn max_pending(&self) -> u32 {
        self.max_pending
    }

    /// This upstream's circuit breaker state (DW-015). Always present;
    /// consult [`UpstreamHandle::breaker_params`] first — a None there
    /// means the breaker is disabled and the state object is dormant.
    pub fn breaker(&self) -> &Arc<Breaker> {
        &self.breaker
    }

    /// Resolved breaker parameters (DW-015); None = breaker disabled.
    pub fn breaker_params(&self) -> Option<&BreakerParams> {
        self.breaker_params.as_ref()
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

    /// This upstream's load balancer (endpoint set, algorithm, in-flight
    /// counters). Exposed for the TLS-passthrough path (which picks an
    /// endpoint the same way) and for tests.
    pub fn lb(&self) -> &Arc<crate::dataplane::balance::UpstreamLb> {
        &self.lb
    }

    /// The trust roots this upstream's TLS connections verify against
    /// (#121): None for plaintext `http1` upstreams, the configured
    /// `trusted_ca_file` bundle when set, else the webpki public set.
    /// Active https health probes clone this so a probe and a proxied
    /// request can never disagree about who to trust.
    pub fn tls_roots(&self) -> Option<&rustls::RootCertStore> {
        self.tls_roots.as_ref()
    }

    /// Send a request through this upstream's pool without a hash key
    /// (algorithms other than `ip_hash` ignore the key anyway).
    pub async fn send<B>(&self, req: Request<B>) -> Result<Response<UpstreamBody>, UpstreamError>
    where
        B: hyper::body::Body<Data = bytes::Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        self.send_with_hash_key(req, None).await
    }

    /// Send a request through this upstream's pool, dispatching via the
    /// upstream's load balancer (DW-011). `hash_key` is the client IP as a
    /// string (used by `ip_hash`; ignored by the other algorithms). The
    /// picked endpoint's `address:port` becomes both the dialed URI's
    /// authority and the outbound `Host` header (replacing whatever the
    /// caller set); the path and query are preserved verbatim. The picked
    /// endpoint's in-flight counter is held for the request/response-header
    /// exchange (documented approximation: released when headers resolve,
    /// not when the streaming body completes). The response body streams
    /// (wrapped in [`UpstreamBody`] for the DW-014 write-timeout /
    /// mid-body health reporting knobs; the wrapper is a frame-for-frame
    /// passthrough when both are unset), so proxying (DW-009) can forward
    /// it without buffering.
    pub async fn send_with_hash_key<B>(
        &self,
        req: Request<B>,
        hash_key: Option<&str>,
    ) -> Result<Response<UpstreamBody>, UpstreamError>
    where
        B: hyper::body::Body<Data = bytes::Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let mut picked = None;
        self.send_inner(req, hash_key, &mut picked)
            .await
            .map(|(resp, ())| resp)
    }

    /// [`UpstreamHandle::send_with_hash_key`] with observability
    /// (DW-021): the load-balancer pick runs under an `upstream_pick`
    /// span (child of the caller's `upstream_attempt` span) and the
    /// picked endpoint's `address:port` is written to `picked` when a
    /// dispatch resolved (left None on the NoEndpoints guard), so the
    /// proxy can attribute the attempt in its access log and the
    /// `upstream_attempts_total` metric.
    pub async fn send_with_hash_key_observed<B>(
        &self,
        req: Request<B>,
        hash_key: Option<&str>,
        picked: &mut Option<String>,
    ) -> Result<Response<UpstreamBody>, UpstreamError>
    where
        B: hyper::body::Body<Data = bytes::Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        self.send_inner(req, hash_key, picked)
            .await
            .map(|(resp, ())| resp)
    }

    async fn send_inner<B>(
        &self,
        mut req: Request<B>,
        hash_key: Option<&str>,
        picked: &mut Option<String>,
    ) -> Result<(Response<UpstreamBody>, ()), UpstreamError>
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
        // lists are only possible via unvalidated construction. The pick,
        // endpoint resolution, and in-flight acquisition all run against
        // ONE state snapshot (pick_for_dispatch), so a concurrent reload
        // cannot detach the guard from the picked endpoint.
        let (dispatch, authority) = {
            // DW-021: the pick phase is its own span so a full trace
            // shows pick separately from the attempt that contains it.
            let span = tracing::info_span!(
                "upstream_pick",
                upstream = self.name,
                endpoint = tracing::field::Empty
            );
            let _guard = span.enter();
            let dispatch = self
                .lb
                .pick_for_dispatch(hash_key)
                .ok_or(UpstreamError::NoEndpoints)?;
            let authority = endpoint_authority(&dispatch.address, dispatch.port);
            span.record("endpoint", authority.as_str());
            *picked = Some(authority.clone());
            (dispatch, authority)
        };
        // Held (inside `dispatch`) until the response (headers) resolves;
        // see the doc comment.
        let uri: Uri = format!("{}://{}{}", self.scheme, authority, path)
            .parse::<Uri>()
            .map_err(|e| UpstreamError::Io(std::io::Error::other(e.to_string())))?;
        *req.uri_mut() = uri;
        // The gateway, not the client, names the origin it dials: the
        // picked endpoint's authority replaces any Host the caller set.
        if let Ok(v) = hyper::header::HeaderValue::from_str(&authority) {
            req.headers_mut().insert(hyper::header::HOST, v);
        }
        // Normalize the HTTP version for the pool's protocol: an inbound h2
        // request proxied to an h1 upstream must be downgraded to 1.1 (and
        // vice versa); the pooled client speaks exactly one dialect.
        *req.version_mut() = if self.http2_only {
            Version::HTTP_2
        } else {
            Version::HTTP_11
        };
        self.stats.requests_sent.fetch_add(1, Ordering::Relaxed);
        let req =
            req.map(|b| http_body_util::combinators::UnsyncBoxBody::new(b.map_err(Into::into)));
        // Observation wire (DW-012): the outcome is reported to the picked
        // endpoint's health tracker when the response headers resolve —
        // the same point the in-flight guard releases. Classification:
        // transport errors (the Err arm: connect timeout, refusal, reset,
        // framing, and the DW-014 read timeout) and statuses >= 500 are
        // failures; 1xx-4xx (including 429/408; documented choice) are
        // successes. Mid-BODY aborts are reported later, by `UpstreamBody`.
        let request = self.client.request(req);
        // Captured before release(): the body wrapper reports mid-stream
        // failures into the same tracker (DW-014 closing the DW-012 gap).
        let body_health = dispatch.health.clone().map(|hd| (Arc::clone(&self.lb), hd));
        let outcome = match self.read_timeout {
            // Per-attempt deadline (DW-014): pool-queue wait + connect +
            // request write + response headers, one bound. Dropping the
            // request future cancels the attempt (the pooled connection,
            // if one was involved, is discarded by the pool).
            Some(after) => match tokio::time::timeout(after, request).await {
                Ok(outcome) => outcome,
                Err(_elapsed) => {
                    if let Some(health) = &dispatch.health {
                        health.report(self.lb.now_ms(), true);
                    }
                    dispatch.release();
                    return Err(UpstreamError::ReadTimeout { after });
                }
            },
            None => request.await,
        };
        // Client-side admission rejections (Saturated) and configuration-
        // class errors say nothing about the PICKED endpoint's health and
        // must not eject it; only genuine transport/exchange outcomes
        // report (same classification as the breaker wire in the proxy).
        let report = match &outcome {
            Ok(resp) => Some(resp.status().as_u16() >= 500),
            Err(err) if health_reportable_legacy(err) => Some(true),
            Err(_) => None,
        };
        if let (Some(health), Some(is_failure)) = (&dispatch.health, report) {
            health.report(self.lb.now_ms(), is_failure);
        }
        dispatch.release();
        outcome.map_err(Into::into).map(|resp| {
            (
                resp.map(|inner| UpstreamBody {
                    inner,
                    idle: self.write_timeout,
                    sleep: None,
                    health: body_health,
                    release: None,
                    deadline: None,
                }),
                (),
            )
        })
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

/// Public for testing the connection-cap clamping contract.
pub fn effective_cap(u: &Upstream) -> u32 {
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

/// `timeouts.read_ms`, resolved to a Duration. None leaves the
/// request/headers exchange unbounded (DW-014 enforcement is opt-in by
/// configuring the knob).
fn effective_read_timeout(u: &Upstream) -> Option<Duration> {
    u.timeouts
        .as_ref()
        .and_then(|t| t.read_ms)
        .map(Duration::from_millis)
}

/// `timeouts.write_ms`, resolved to a Duration (response-body inactivity
/// bound; DW-014).
fn effective_write_timeout(u: &Upstream) -> Option<Duration> {
    u.timeouts
        .as_ref()
        .and_then(|t| t.write_ms)
        .map(Duration::from_millis)
}

fn effective_slow_start(u: &Upstream) -> Duration {
    Duration::from_millis(u.slow_start_ms.unwrap_or(0).min(MAX_SLOW_START_MS))
}

fn build_handle(
    u: &Upstream,
    root_store: rustls::RootCertStore,
    previous: Option<&Arc<UpstreamHandle>>,
    events: Option<&crate::events::Emitter>,
) -> Arc<UpstreamHandle> {
    let cap = effective_cap(u);
    let connect_timeout = effective_connect_timeout(u);
    let stats = Arc::new(UpstreamStats::default());
    // DW-044: one upstream-labeled emitter for this handle's state
    // machines — the breaker's transitions and (via the balancer) the
    // endpoint trackers' ejection/recovery events.
    let upstream_events = events.map(|em| em.for_upstream(&u.name));

    // DW-030: the connector resolves + dials itself (RFC 8305 happy
    // eyeballs, `timeouts.happy_eyeballs_ms`); there is no hyper-util
    // HttpConnector to configure anymore.

    // `root_store` is the trust for THIS upstream (#121): the configured
    // trusted_ca_file bundle when set, else webpki (+ any programmatic
    // extras). Kept on the handle so probes share it (tls_roots).
    let (scheme, tls, http2_only, tls_roots): (&'static str, Option<_>, bool, Option<_>) =
        match u.protocol {
            UpstreamProtocol::Http1 => ("http", None, false, None),
            UpstreamProtocol::Https => (
                "https",
                Some(Arc::new(crate::security::tls::https_h1_client_config(
                    root_store.clone(),
                ))),
                false,
                Some(root_store),
            ),
            UpstreamProtocol::Http2 => {
                // Same roots as https, but ALPN h2 and a client locked to
                // HTTP/2 (see module docs).
                let mut cfg = rustls::ClientConfig::builder()
                    .with_root_certificates(root_store.clone())
                    .with_no_client_auth();
                cfg.alpn_protocols = vec![b"h2".to_vec()];
                ("https", Some(Arc::new(cfg)), true, Some(root_store))
            }
        };

    let connector = UpstreamConnector {
        happy_eyeballs: effective_happy_eyeballs(u),
        tls,
        cap: Arc::new(Semaphore::new(cap as usize)),
        pending_cap: u
            .max_pending
            .filter(|p| *p > 0)
            .map(|p| Arc::new(Semaphore::new(p as usize))),
        connect_timeout,
        stats: Arc::clone(&stats),
    };

    let mut builder = Client::builder(TokioExecutor::new());
    if http2_only {
        builder.http2_only(true);
    }
    builder.pool_timer(TokioTimer::new());

    // Hot-swap: an existing balancer for this upstream name keeps its
    // live state (in-flight counters, WRR phase, slow-start clocks,
    // passive-health trackers) for unchanged endpoint addresses; a fresh
    // one starts clean. The retry budget is carried the same way (the
    // rolling window survives a reload), while the retry PARAMETERS apply
    // from the new config.
    let previous_lb = previous.map(|h| h.lb());
    let lb = match previous_lb {
        Some(prev) => {
            prev.rebuild_with_health_and_events(
                &u.endpoints,
                u.load_balancer,
                effective_slow_start(u),
                u.health.as_ref(),
                upstream_events.as_ref(),
            );
            Arc::clone(prev)
        }
        None => crate::dataplane::balance::UpstreamLb::new_with_health_and_events(
            &u.endpoints,
            u.load_balancer,
            effective_slow_start(u),
            u.health.as_ref(),
            upstream_events.as_ref(),
        ),
    };
    let retry_budget = previous
        .map(|h| Arc::clone(h.retry_budget()))
        .unwrap_or_else(|| Arc::new(RetryBudget::new()));
    // Breaker state carries across reloads; PARAMETERS apply from the new
    // config (the RetryBudget/RetryParams split, verbatim). A carried
    // breaker keeps its emitter binding (state-only object; the emitter
    // is per-dataplane and stable); a fresh one binds it here (DW-044).
    let breaker =
        previous
            .map(|h| Arc::clone(h.breaker()))
            .unwrap_or_else(|| match &upstream_events {
                Some(events) => Arc::new(Breaker::with_clock_and_events(
                    system_now_ms_for_breaker,
                    Some(events.clone()),
                )),
                None => Arc::new(Breaker::new()),
            });

    Arc::new(UpstreamHandle {
        name: u.name.clone(),
        cap,
        connect_timeout,
        read_timeout: effective_read_timeout(u),
        write_timeout: effective_write_timeout(u),
        retries: RetryParams::from_config(u.retries.as_ref()),
        hedge: HedgeParams::from_config(u.retries.as_ref().and_then(|r| r.hedge.as_ref())),
        retry_budget,
        max_pending: u.max_pending.unwrap_or(0),
        breaker,
        breaker_params: u.breaker.as_ref().map(BreakerParams::from_config),
        happy_eyeballs: effective_happy_eyeballs(u),
        stats,
        client: builder.build(connector),
        lb,
        scheme,
        http2_only,
        tls_roots,
    })
}

/// Registry of per-upstream pooled clients, built from one published
/// snapshot. Rebuild (and drop the old registry) on snapshot swap; in-flight
/// requests keep their old pools until their handles are dropped.
#[derive(Default)]
pub struct UpstreamRegistry {
    handles: BTreeMap<String, Arc<UpstreamHandle>>,
    /// Compiled service splits (DW-040), keyed by service name. Empty
    /// unless a service carries a `split` block; single-target
    /// services resolve through `handles` as ever.
    splits: BTreeMap<String, Arc<crate::dataplane::split::ServiceSplit>>,
}

impl UpstreamRegistry {
    /// Build from a snapshot, verifying upstream TLS certificates against
    /// the Mozilla webpki root set — except upstreams that configure
    /// `trusted_ca_file`, which verify against their own bundle (#121).
    pub fn from_snapshot(snapshot: &Snapshot) -> Self {
        Self::with_root_certificates(snapshot, &[])
            .expect("registry build without extra roots cannot fail")
    }

    /// Build from a snapshot, carrying over per-upstream load-balancer
    /// state from `previous` (in-flight counters, WRR phase, slow-start
    /// clocks for unchanged endpoint addresses). This is the reload path:
    /// weight and endpoint changes take effect without a restart, and
    /// in-flight requests holding old handles are unaffected.
    pub fn from_snapshot_with_previous(snapshot: &Snapshot, previous: &UpstreamRegistry) -> Self {
        Self::with_root_certificates_and_previous(snapshot, &[], Some(previous))
            .expect("registry build without extra roots cannot fail")
    }

    /// `from_snapshot` with the dataplane's event emitter attached
    /// (DW-044): breaker transitions and endpoint ejection/recovery in
    /// this registry's state machines emit onto the bus. Distinct
    /// constructors rather than a changed signature so the many
    /// event-agnostic call sites (tests, tooling) stay untouched.
    pub fn from_snapshot_with_events(
        snapshot: &Snapshot,
        events: Option<&crate::events::Emitter>,
    ) -> Self {
        Self::with_root_certificates_previous_and_events(snapshot, &[], None, events)
            .expect("registry build without extra roots cannot fail")
    }

    /// `from_snapshot_with_previous` with the dataplane's event emitter
    /// attached (DW-044); the dataplane's reload path.
    pub fn from_snapshot_with_previous_and_events(
        snapshot: &Snapshot,
        previous: &UpstreamRegistry,
        events: Option<&crate::events::Emitter>,
    ) -> Self {
        Self::with_root_certificates_previous_and_events(snapshot, &[], Some(previous), events)
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
        Self::with_root_certificates_and_previous(snapshot, extra_roots, None)
    }

    /// `with_root_certificates` with optional balancer-state carry-over
    /// from a previous registry build (see
    /// [`UpstreamRegistry::from_snapshot_with_previous`]).
    ///
    /// Per-upstream `trusted_ca_file` (#121): when set, that upstream's
    /// connector trusts the file's bundle INSTEAD of the webpki+extras
    /// store — a private-CA upstream must not implicitly keep public-root
    /// trust. Config-driven bundles that fail to load at build time do
    /// NOT fail the build (the config was file-validated at publish, so
    /// this is a torn state — the bundle was replaced/unlinked
    /// underneath the gateway); the upstream FAILS CLOSED with an empty
    /// root store and a loud error log, so no traffic is ever sent under
    /// trust the operator did not configure. Programmatic `extra_roots`
    /// keep the immediate-Err contract above.
    pub fn with_root_certificates_and_previous(
        snapshot: &Snapshot,
        extra_roots: &[CertificateDer<'_>],
        previous: Option<&UpstreamRegistry>,
    ) -> Result<Self, UpstreamError> {
        Self::with_root_certificates_previous_and_events(snapshot, extra_roots, previous, None)
    }

    /// `with_root_certificates_and_previous` with the dataplane's event
    /// emitter (DW-044); the single build path behind every constructor.
    pub fn with_root_certificates_previous_and_events(
        snapshot: &Snapshot,
        extra_roots: &[CertificateDer<'_>],
        previous: Option<&UpstreamRegistry>,
        events: Option<&crate::events::Emitter>,
    ) -> Result<Self, UpstreamError> {
        let mut default_roots = crate::security::tls::webpki_root_store();
        for c in extra_roots {
            default_roots
                .add(c.clone())
                .map_err(|e| UpstreamError::InvalidRootCertificate(e.to_string()))?;
        }
        let handles: BTreeMap<String, Arc<UpstreamHandle>> = snapshot
            .gateway()
            .upstreams
            .iter()
            .map(|u| {
                let roots = match &u.trusted_ca_file {
                    Some(path) => match crate::security::tls::root_store_from_pem_file(path) {
                        Ok(roots) => roots,
                        Err(err) => {
                            // See the method docs: fail closed, never
                            // fall back to the public roots (that would
                            // silently change who this upstream trusts).
                            tracing::error!(
                                code = "upstream_ca_unloadable",
                                upstream = %u.name,
                                path = %path,
                                "trusted_ca_file unusable; failing closed (every TLS dial to \
                                 this upstream will be refused): {err}"
                            );
                            rustls::RootCertStore::empty()
                        }
                    },
                    None => default_roots.clone(),
                };
                let prev = previous.and_then(|p| p.handles.get(&u.name));
                (u.name.clone(), build_handle(u, roots, prev, events))
            })
            .collect();
        // DW-040: compile each split service's weighted targets.
        // Validation guarantees every named upstream exists and the
        // total weight is positive; a handle miss here (impossible
        // through validation) skips the split loudly — the service
        // answers 502 unknown_upstream rather than dispatching by a
        // half-built split.
        let mut splits = BTreeMap::new();
        for service in &snapshot.gateway().services {
            let Some(split_cfg) = &service.split else {
                continue;
            };
            let mut targets = Vec::with_capacity(split_cfg.targets.len());
            let mut ok = true;
            for t in &split_cfg.targets {
                match handles.get(&t.upstream) {
                    Some(handle) => targets.push((Arc::clone(handle), u64::from(t.weight))),
                    None => {
                        tracing::error!(
                            code = "service_split_target_missing",
                            service = %service.name,
                            upstream = %t.upstream,
                            "split target has no compiled upstream; split skipped (fail closed)"
                        );
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                splits.insert(
                    service.name.clone(),
                    Arc::new(crate::dataplane::split::ServiceSplit::new(&targets)),
                );
            }
        }
        Ok(UpstreamRegistry { handles, splits })
    }

    /// The compiled split for a service (DW-040), when it has one.
    pub fn split_for(&self, service: &str) -> Option<Arc<crate::dataplane::split::ServiceSplit>> {
        self.splits.get(service).cloned()
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

/// Refresh the state-derived observation gauges (breaker state, endpoint
/// health, fail-open picks) from `registry` into `obs` (DW-021).
///
/// Called at scrape time: `/metrics` reflects a point-in-time snapshot,
/// and the hot paths (pick, report) stay pure atomics with zero metrics
/// coupling. The walk lives here — next to the registry state it reads —
/// and the observability side only exposes plain setters, so metrics
/// depend on nothing. Series for endpoints/upstreams removed by a reload
/// linger until process restart (documented Prometheus caveat).
pub fn refresh_observation_gauges(registry: &UpstreamRegistry, obs: &Observability) {
    for name in registry.names() {
        let Some(handle) = registry.get(name) else {
            continue;
        };
        let state = match handle.breaker().state() {
            BreakerState::Closed { .. } => 0,
            BreakerState::Open { .. } => 1,
            BreakerState::HalfOpen { .. } => 2,
        };
        obs.set_breaker_state(name, state);
        obs.set_fail_open_picks(name, handle.lb().fail_open_picks() as i64);
        let lb_now = handle.lb().now_ms();
        for (address, port, health) in handle.lb().health_targets() {
            let label = format!("{address}:{port}");
            let up = health.map(|h| h.is_available(lb_now)).unwrap_or(true);
            obs.set_endpoint_health(name, &label, up);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LoadBalancer, Upstream as ConfigUpstream};
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::Method;

    fn get_request(path: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .method(Method::GET)
            .uri(path)
            .body(Full::new(Bytes::new()))
            .expect("request")
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
            slow_start_ms: None,
            health: None,
            active_health: None,
            retries: None,
            timeouts: None,
            breaker: None,
            max_pending: None,
            trusted_ca_file: None,
            oauth2_client_credentials: None,
            dns_discovery: None,
        };
        let handle = build_handle(&up, crate::security::tls::webpki_root_store(), None, None);
        assert!(matches!(
            handle.send(get_request("/x")).await,
            Err(UpstreamError::NoEndpoints)
        ));
    }
}
