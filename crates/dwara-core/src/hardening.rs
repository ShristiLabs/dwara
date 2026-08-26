//! Protocol hardening knobs (DW-023, feature analysis 4.20).
//!
//! Two families of defenses, applied identically to EVERY serving surface
//! (data-plane listeners and the admin listener):
//!
//! 1. **Parser/amplification bounds** on hyper's connection builders, so a
//!    single hostile connection cannot pin unbounded memory or parse cost:
//!
//!    | Knob (env) | Default | Attack it bounds |
//!    |---|---|---|
//!    | `DWARA_HTTP1_MAX_HEADERS` | 100 | header-count bombs (N header lines per request) |
//!    | `DWARA_HTTP1_MAX_BUF_KIB` | 64 KiB | single-header/line size bombs (hyper's read buffer cap; a header line that does not fit is a 431-class parse failure) |
//!    | `DWARA_HTTP1_HEADER_TIMEOUT_MS` | 10 000 | SLOWLORIS: a connection that sends headers slower than this is closed before ever reaching a route |
//!    | `DWARA_H2_MAX_CONCURRENT_STREAMS` | 128 | stream floods over one h2 connection (also advertised to the peer in SETTINGS) |
//!    | `DWARA_H2_STREAM_WINDOW_KIB` | 1024 (1 MiB) | per-stream receive buffering a malicious h2 peer can force |
//!    | `DWARA_H2_CONNECTION_WINDOW_KIB` | 4096 (4 MiB) | connection-wide h2 receive buffering |
//!    | `DWARA_H2_MAX_SEND_BUF_KIB` | 1024 (1 MiB) | outbound h2 send buffer per connection (write-amplification / memory pinning by a non-reading peer) |
//!
//! Left deliberately at hyper's defaults: `max_frame_size` (16 KiB, the
//! minimum legal value — hyper already refuses larger frames) and HTTP/2
//! `max_headers` (hyper-util's h2 builder has no such knob; the h2 header
//! list is bounded by the flow-control windows pinned above).
//!
//! A timer is installed on the HTTP/1 builder (`TokioTimer`) because
//! hyper disables `header_read_timeout` when no timer is configured.
//!
//! 2. **Request-body inactivity gap** (`DWARA_REQUEST_BODY_TIMEOUT_MS`,
//!    default 30 000, `0` disables): the INBOUND request body handed to the
//!    dataplane is wrapped in [`InboundBody`], which errors when the gap
//!    between two body frames exceeds the configured duration. Semantics
//!    deliberately mirror the DW-014 response-side `write_ms` wrapper
//!    ([`crate::upstream::UpstreamBody`]): it is a GAP timeout, not a total
//!    budget — a legitimate slow upload (large file over a slow link) that
//!    keeps making progress never trips it; a client that sends headers and
//!    then trickles body bytes forever to hold a concurrency slot and an
//!    upstream connection is cut off after the gap. When the wrapper fires
//!    the in-flight upstream attempt fails as a transport-class error (the
//!    proxy answers 502 and closes), and the request's global concurrency
//!    slot is released with the response.
//!
//! CL+TE request smuggling is NOT configured here because it needs no
//! configuration: hyper 1.x's HTTP/1 parser rejects requests carrying both
//! `Content-Length` and `Transfer-Encoding` (400/close) outright, and the
//! gateway never passes raw bytes to an upstream — every forwarded request
//! is rebuilt from hyper-parsed parts, so a smuggled "second request" would
//! require hyper itself to mis-parse the first one. Both properties are
//! pinned by the smuggling-corpus integration tests in dwara-bin.
//!
//! The pre-parse sniff's timeout is PER-READ, not a total head budget: a
//! client that trickles one byte at a time, each inside the
//! `DWARA_HTTP1_HEADER_TIMEOUT_MS` bound, keeps every individual sniff
//! read successful, and the guard deliberately hands such connections to
//! hyper instead of duplicating a head deadline (preferring handoff over
//! racing hyper for the same bytes). The fallback defense for slow
//! trickles is therefore hyper's PER-HEAD `header_read_timeout` — the
//! same knob value, installed on the connection builder together with a
//! `TokioTimer` — which bounds the total time one request head may take
//! and closes the connection when it elapses. The two compose as: the
//! sniff owns each individual read, hyper owns the head as a whole, so
//! neither a stalled connection nor a slow trickle can hold a listener
//! slot indefinitely.
//!
//! All knobs are read once from the environment at startup (invalid values
//! fall back to the documented default) and are process-wide, not
//! per-listener: hardening is a property of the parser, not of the route.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::body::{Body, Bytes, Frame};
use tokio::io::AsyncWriteExt as _;

/// Default HTTP/1 max header COUNT (hyper's own default, made explicit).
pub const DEFAULT_HTTP1_MAX_HEADERS: usize = 100;
/// Default HTTP/1 read-buffer cap, in KiB (hyper's is ~8 KiB growable;
/// pinned to 64 KiB explicitly so the bound is a documented constant).
pub const DEFAULT_HTTP1_MAX_BUF_KIB: usize = 64;
/// Default slowloris header-read timeout.
pub const DEFAULT_HTTP1_HEADER_TIMEOUT_MS: u64 = 10_000;
/// Default HTTP/2 concurrent-stream cap (also advertised in SETTINGS).
pub const DEFAULT_H2_MAX_CONCURRENT_STREAMS: u32 = 128;
/// Default HTTP/2 initial per-stream window, in KiB (1 MiB).
pub const DEFAULT_H2_STREAM_WINDOW_KIB: u32 = 1024;
/// Default HTTP/2 initial connection window, in KiB (4 MiB).
pub const DEFAULT_H2_CONNECTION_WINDOW_KIB: u32 = 4096;
/// Default HTTP/2 per-connection send-buffer cap, in KiB (1 MiB).
pub const DEFAULT_H2_MAX_SEND_BUF_KIB: usize = 1024;
/// Default inbound request-body inactivity gap.
pub const DEFAULT_REQUEST_BODY_TIMEOUT_MS: u64 = 30_000;

fn env_parse<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Resolved hardening configuration (see the module docs for the knob
/// table, defaults, and the attack each bound addresses).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHardening {
    /// HTTP/1 max header count per request/section.
    pub http1_max_headers: usize,
    /// HTTP/1 read-buffer cap, in BYTES.
    pub http1_max_buf_size: usize,
    /// HTTP/1 header-read (slowloris) timeout.
    pub http1_header_read_timeout: Duration,
    /// HTTP/2 max concurrent streams (enforced and advertised).
    pub h2_max_concurrent_streams: u32,
    /// HTTP/2 initial per-stream flow-control window, in BYTES.
    pub h2_initial_stream_window: u32,
    /// HTTP/2 initial connection flow-control window, in BYTES.
    pub h2_initial_connection_window: u32,
    /// HTTP/2 per-connection send-buffer cap, in BYTES.
    pub h2_max_send_buf_size: usize,
    /// Inbound request-body inactivity gap; None disables the wrapper
    /// (the body then streams through untouched).
    pub request_body_gap: Option<Duration>,
}

impl Default for HttpHardening {
    fn default() -> Self {
        Self {
            http1_max_headers: DEFAULT_HTTP1_MAX_HEADERS,
            http1_max_buf_size: DEFAULT_HTTP1_MAX_BUF_KIB * 1024,
            http1_header_read_timeout: Duration::from_millis(DEFAULT_HTTP1_HEADER_TIMEOUT_MS),
            h2_max_concurrent_streams: DEFAULT_H2_MAX_CONCURRENT_STREAMS,
            h2_initial_stream_window: DEFAULT_H2_STREAM_WINDOW_KIB * 1024,
            h2_initial_connection_window: DEFAULT_H2_CONNECTION_WINDOW_KIB * 1024,
            h2_max_send_buf_size: DEFAULT_H2_MAX_SEND_BUF_KIB * 1024,
            request_body_gap: Some(Duration::from_millis(DEFAULT_REQUEST_BODY_TIMEOUT_MS)),
        }
    }
}

impl HttpHardening {
    /// Read the knob set from the environment; invalid or absent values
    /// fall back to the documented defaults.
    pub fn from_env() -> Self {
        let mut h = Self::default();
        h.http1_max_headers = env_parse("DWARA_HTTP1_MAX_HEADERS", h.http1_max_headers);
        h.http1_max_buf_size =
            env_parse("DWARA_HTTP1_MAX_BUF_KIB", DEFAULT_HTTP1_MAX_BUF_KIB) * 1024;
        h.http1_header_read_timeout = Duration::from_millis(env_parse(
            "DWARA_HTTP1_HEADER_TIMEOUT_MS",
            DEFAULT_HTTP1_HEADER_TIMEOUT_MS,
        ));
        h.h2_max_concurrent_streams = env_parse(
            "DWARA_H2_MAX_CONCURRENT_STREAMS",
            h.h2_max_concurrent_streams,
        );
        h.h2_initial_stream_window =
            env_parse("DWARA_H2_STREAM_WINDOW_KIB", DEFAULT_H2_STREAM_WINDOW_KIB) * 1024;
        h.h2_initial_connection_window = env_parse(
            "DWARA_H2_CONNECTION_WINDOW_KIB",
            DEFAULT_H2_CONNECTION_WINDOW_KIB,
        ) * 1024;
        h.h2_max_send_buf_size =
            env_parse("DWARA_H2_MAX_SEND_BUF_KIB", DEFAULT_H2_MAX_SEND_BUF_KIB) * 1024;
        h.request_body_gap = match env_parse(
            "DWARA_REQUEST_BODY_TIMEOUT_MS",
            DEFAULT_REQUEST_BODY_TIMEOUT_MS,
        ) {
            0 => None,
            ms => Some(Duration::from_millis(ms)),
        };
        h
    }

    /// Apply the connection-level bounds to a hyper-util auto builder
    /// (h1 + h2). Used by every serving surface: data-plane listeners and
    /// the admin listener share one hardening posture.
    pub fn apply<E>(&self, builder: &mut hyper_util::server::conn::auto::Builder<E>) {
        builder
            .http1()
            .max_headers(self.http1_max_headers)
            .max_buf_size(self.http1_max_buf_size)
            .header_read_timeout(self.http1_header_read_timeout)
            // header_read_timeout is inert without a timer; hyper's default
            // is a never-firing no-op.
            .timer(hyper_util::rt::TokioTimer::new());
        builder
            .http2()
            .max_concurrent_streams(self.h2_max_concurrent_streams)
            .initial_stream_window_size(self.h2_initial_stream_window)
            .initial_connection_window_size(self.h2_initial_connection_window)
            .max_send_buf_size(self.h2_max_send_buf_size);
    }

    /// Wrap an inbound request body with the inactivity-gap timeout. A thin
    /// passthrough when the knob is disabled.
    pub fn wrap_request_body<B>(&self, body: B) -> InboundBody<B>
    where
        B: Body<Data = Bytes>,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        InboundBody {
            inner: Box::pin(body),
            gap: self.request_body_gap,
            sleep: None,
        }
    }

    /// Pre-parse smuggling guard for one connection (DW-023). Reads ahead
    /// just enough of the first request head to apply the CL+TE rejection
    /// policy BEFORE hyper normalizes the head away (hyper's HTTP/1 parser
    /// gives Transfer-Encoding precedence and DROPS the Content-Length
    /// header, which is desync-safe behind this gateway but erases the
    /// evidence an explicit rejection needs). Returns the stream to hand
    /// to the connection builder (with the sniffed bytes replayed in
    /// front), or None when the connection was rejected and answered.
    ///
    /// Behavior:
    /// - Bytes beginning with `PRI` (the h2c preface) pass through
    ///   untouched the moment the first bytes identify it — h2 has its own
    ///   framing rules (Transfer-Encoding is forbidden there; hyper
    ///   rejects it) and needs no h1 head sniff.
    /// - A first HTTP/1 head carrying BOTH a Content-Length and a
    ///   Transfer-Encoding header (any order) is answered with a bare
    ///   `400 Bad Request` + close and never reaches the dataplane.
    /// - A head containing an obs-fold (RFC 7230 3.2.4 obsolete line
    ///   folding: any header line starting with SP/HTAB) is likewise
    ///   answered `400` + close. Folding can split a header NAME across
    ///   lines (`Transfer-\r\n Encoding: chunked`), which the
    ///   name-anchored CL+TE scan below cannot see — and obs-fold is
    ///   illegal in HTTP/1.1 requests, which hyper also rejects, so
    ///   refusing it at the sniff is strictly aligned with the parser,
    ///   one layer earlier.
    /// - The head terminator is the FIRST blank line under either
    ///   line-ending convention hyper tolerates (`\r\n\r\n` for RFC-strict
    ///   clients, `\n\n` and the mixed forms for bare-LF clients): a
    ///   legal LF-only client's body must not be over-buffered into the
    ///   sniff (spurious 431).
    /// - A head exceeding the HTTP/1 read-buffer cap is likewise refused.
    /// - The sniff's read bound is per-read (`http1_header_read_timeout`
    ///   applied to each individual read, see the module docs): a slow
    ///   starter simply falls through to hyper, whose per-head slowloris
    ///   timeout governs from there.
    /// - Documented limitation: only the FIRST request head on a
    ///   connection is inspected; later keep-alive requests rely on
    ///   hyper's framing itself, which cannot desync behind this gateway
    ///   (every forwarded request is rebuilt from parsed parts — there is
    ///   no raw-passthrough path).
    pub async fn guard_connection<S>(&self, mut stream: S) -> Option<PrefixedStream<S>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncReadExt as _;

        let mut sniffed: Vec<u8> = Vec::with_capacity(1024);
        let mut chunk = [0u8; 4096];
        loop {
            if sniffed.len() >= 3 && &sniffed[..3] == b"PRI" {
                // h2c prior-knowledge connection: not an HTTP/1 head.
                return Some(PrefixedStream {
                    inner: stream,
                    prefix: sniffed,
                    pos: 0,
                });
            }
            if head_end(&sniffed).is_some() {
                if head_has_obs_fold(&sniffed) {
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                        )
                        .await;
                    tracing::warn!(
                        code = "request_head_obs_fold",
                        "first request head uses obsolete line folding; connection rejected"
                    );
                    return None;
                }
                if head_is_ambiguous(&sniffed) {
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                        )
                        .await;
                    tracing::warn!(
                        code = "request_framing_ambiguous",
                        "first request head carries both Content-Length and Transfer-Encoding; connection rejected"
                    );
                    return None;
                }
                return Some(PrefixedStream {
                    inner: stream,
                    prefix: sniffed,
                    pos: 0,
                });
            }
            if sniffed.len() > self.http1_max_buf_size {
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 431 Request Header Fields Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                    )
                    .await;
                return None;
            }
            let read = stream.read(&mut chunk);
            let read = match tokio::time::timeout(self.http1_header_read_timeout, read).await {
                Ok(r) => r,
                Err(_elapsed) => {
                    // Slow starter: hand what we have to hyper; its own
                    // header timeout governs from here.
                    return Some(PrefixedStream {
                        inner: stream,
                        prefix: sniffed,
                        pos: 0,
                    });
                }
            };
            match read {
                Ok(0) | Err(_) => {
                    // EOF or error: nothing to guard; hyper reports it.
                    return Some(PrefixedStream {
                        inner: stream,
                        prefix: sniffed,
                        pos: 0,
                    });
                }
                Ok(n) => sniffed.extend_from_slice(&chunk[..n]),
            }
        }
    }
}

/// Length of the request head INCLUDING its terminating blank line, or
/// None while the head is still incomplete. The terminator is the FIRST
/// blank line under either line-ending convention hyper's tolerant h1
/// parsing accepts: RFC-strict CRLF heads end with `\r\n\r\n`, bare-LF
/// heads with `\n\n`, and mixed heads with `\r\n\n` or `\n\r\n` (a line
/// break followed by a blank line — equivalently: the first `\n` that is
/// itself followed by `\n` or `\r\n`; in any legal head such a byte can
/// only be the last line break before the blank line, since a header
/// name can never begin with CR or LF). Detecting the first of these
/// matters twice: the sniff loop must STOP there, so a bare-LF client's
/// body is never over-buffered into the sniff (spurious 431), and the
/// CL+TE scan below must not look PAST it, since body bytes are not
/// headers.
fn head_end(head: &[u8]) -> Option<usize> {
    for (i, b) in head.iter().enumerate() {
        if *b != b'\n' {
            continue;
        }
        match (head.get(i + 1), head.get(i + 2)) {
            (Some(b'\n'), _) => return Some(i + 2),
            (Some(b'\r'), Some(b'\n')) => return Some(i + 3),
            _ => {}
        }
    }
    None
}

/// Does this (sniffed) HTTP/1 request head carry BOTH a Content-Length and
/// a Transfer-Encoding header? Names compare case-insensitively; the head
/// ends at the first blank line ([`head_end`], either line-ending
/// convention) — bytes AFTER it are BODY (a payload that legitimately
/// contains the strings "Content-Length"/"Transfer-Encoding" must not
/// trip the guard) and are not inspected.
fn head_is_ambiguous(head: &[u8]) -> bool {
    let head = match head_end(head) {
        Some(end) => &head[..end],
        None => head,
    };
    let mut has_cl = false;
    let mut has_te = false;
    for line in head.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            continue;
        };
        let name = &line[..colon];
        if name.eq_ignore_ascii_case(b"content-length") {
            has_cl = true;
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            has_te = true;
        }
    }
    has_cl && has_te
}

/// Does the (sniffed) HTTP/1 request head contain an obs-fold
/// continuation line — any line AFTER the request line starting with SP
/// or HTAB (RFC 7230 3.2.4 obsolete line folding)? A folded head can
/// split a header NAME across lines (`Transfer-\r\n Encoding: chunked`),
/// slipping the CL+TE pair past [`head_is_ambiguous`]'s name-anchored
/// scan. Obs-fold is illegal in HTTP/1.1 requests and hyper rejects it
/// too, so the sniff rejects it early with a 400 — strictly aligned with
/// the parser, one layer earlier. The request line itself is skipped:
/// leading whitespace there is a parse error hyper already owns.
fn head_has_obs_fold(head: &[u8]) -> bool {
    let end = head_end(head).unwrap_or(head.len());
    head[..end]
        .split(|b| *b == b'\n')
        .skip(1)
        .any(|line| matches!(line.first(), Some(b' ') | Some(b'\t')))
}

/// A stream that replays `prefix` (bytes already sniffed off the wire)
/// before forwarding to the inner stream. IO traits only delegate.
pub struct PrefixedStream<S> {
    inner: S,
    prefix: Vec<u8>,
    pos: usize,
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let remaining = &this.prefix[this.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Error of the inbound request-body wrapper.
#[derive(Debug)]
pub enum InboundBodyError {
    /// The gap between two body frames exceeded the configured duration
    /// (slow-body defense; see the module docs).
    Timeout { after: Duration },
    /// The underlying body stream errored.
    Inner(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for InboundBodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InboundBodyError::Timeout { after } => {
                write!(f, "request body stalled for more than {after:?}")
            }
            InboundBodyError::Inner(e) => write!(f, "request body failed: {e}"),
        }
    }
}

impl std::error::Error for InboundBodyError {}

/// Inbound request body with an inactivity-gap timeout (the request-side
/// mirror of [`crate::upstream::UpstreamBody`]). A `tokio::time::Sleep` is
/// armed whenever the stream is idle-Pending and cleared on every frame,
/// so the timeout bounds GAPS, not total streaming time. When it fires the
/// error propagates through the dataplane's attempt machinery: the in-flight
/// upstream send fails as a transport-class error, the client receives a
/// classified 5xx, and the request's concurrency slot is released.
pub struct InboundBody<B> {
    inner: Pin<Box<B>>,
    gap: Option<Duration>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<B> Body for InboundBody<B>
where
    B: Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = Bytes;
    type Error = InboundBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, InboundBodyError>>> {
        let this = self.get_mut();
        loop {
            if let Some(sleep) = &mut this.sleep {
                if sleep.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Some(Err(InboundBodyError::Timeout {
                        after: this.gap.unwrap_or_default(),
                    })));
                }
            }
            match this.inner.as_mut().poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    this.sleep = None;
                    return Poll::Ready(Some(Ok(frame)));
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Some(Err(InboundBodyError::Inner(e.into()))))
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => {
                    if this.gap.is_some() && this.sleep.is_none() {
                        this.sleep =
                            Some(Box::pin(tokio::time::sleep(this.gap.unwrap_or_default())));
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

impl<B> std::fmt::Debug for InboundBody<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundBody")
            .field("gap_timeout", &self.gap)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt as _;
    use http_body_util::Full;
    use hyper::body::Frame as BodyFrame;

    /// Minimal channel-driven body: `next_frame` pulls from a shared queue
    /// the test fills on its own schedule (the stream stays Pending until a
    /// frame is pushed), which is exactly what a slow client looks like.
    struct SlowBody {
        frames: tokio::sync::mpsc::UnboundedReceiver<Bytes>,
    }

    impl Body for SlowBody {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<BodyFrame<Bytes>, std::convert::Infallible>>> {
            self.get_mut()
                .frames
                .poll_recv(cx)
                .map(|maybe: Option<Bytes>| {
                    maybe.map(|b| {
                        Ok::<_, std::convert::Infallible>(BodyFrame::data(Bytes::from(b.to_vec())))
                    })
                })
        }
    }

    #[test]
    fn defaults_match_documented_table() {
        let h = HttpHardening::default();
        assert_eq!(h.http1_max_headers, 100);
        assert_eq!(h.http1_max_buf_size, 64 * 1024);
        assert_eq!(h.http1_header_read_timeout, Duration::from_secs(10));
        assert_eq!(h.h2_max_concurrent_streams, 128);
        assert_eq!(h.h2_initial_stream_window, 1024 * 1024);
        assert_eq!(h.h2_initial_connection_window, 4 * 1024 * 1024);
        assert_eq!(h.h2_max_send_buf_size, 1024 * 1024);
        assert_eq!(h.request_body_gap, Some(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn body_gap_timeout_fires_between_frames() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
        let hardening = HttpHardening {
            request_body_gap: Some(Duration::from_millis(100)),
            ..HttpHardening::default()
        };
        let body = hardening.wrap_request_body(SlowBody { frames: rx });
        tx.send(Bytes::from(&b"first"[..])).unwrap();
        let mut body = std::pin::pin!(body);
        let first = body
            .frame()
            .await
            .expect("first frame arrives")
            .expect("first frame is ok");
        assert_eq!(&first.data_ref().unwrap()[..], b"first");
        // No second frame: the gap timeout must fire.
        let started = std::time::Instant::now();
        let err = body
            .frame()
            .await
            .expect("stream ends")
            .expect_err("times out");
        match err {
            InboundBodyError::Timeout { after } => {
                assert_eq!(after, Duration::from_millis(100))
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "fired within the bound, took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn steadily_trickling_body_never_times_out() {
        // A body that keeps producing frames every 30 ms must survive a
        // 200 ms GAP timeout: the knob bounds stalls, not totals.
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
        let filler = std::thread::spawn(move || {
            for _ in 0..10 {
                std::thread::sleep(Duration::from_millis(30));
                if tx.send(Bytes::new()).is_err() {
                    return;
                }
            }
        });
        let hardening = HttpHardening {
            request_body_gap: Some(Duration::from_millis(200)),
            ..HttpHardening::default()
        };
        let body = hardening.wrap_request_body(SlowBody { frames: rx });
        let collected = body.collect().await;
        assert!(
            collected.is_ok(),
            "trickling body must not trip the gap timeout"
        );
        filler.join().expect("filler thread");
    }

    #[tokio::test]
    async fn disabled_gap_is_a_passthrough() {
        let hardening = HttpHardening {
            request_body_gap: None,
            ..HttpHardening::default()
        };
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
        let body = hardening.wrap_request_body(SlowBody { frames: rx });
        drop(tx); // sender gone: stream ENDS (no timeout error to invent)
        let mut body = std::pin::pin!(body);
        assert!(body.frame().await.is_none(), "clean end of stream");
    }

    #[tokio::test]
    async fn wrapped_body_passes_frames_and_size_hint_through() {
        let hardening = HttpHardening::default();
        let body = hardening.wrap_request_body(Full::new(Bytes::from_static(b"hello")));
        let bytes = body.collect().await.expect("collects").to_bytes();
        assert_eq!(&bytes[..], b"hello");
    }
}
