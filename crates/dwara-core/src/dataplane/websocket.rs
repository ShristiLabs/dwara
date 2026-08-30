//! WebSocket policy (DW-039, feature analysis section 4.13): the two
//! knobs that turn the generic 101 tunnel into a managed one for
//! browser-style WebSocket traffic — origin allowlisting at the
//! handshake and post-upgrade frame-rate policing on the tunnel.
//!
//! # Zero new dependencies, by construction
//!
//! The module hand-rolls exactly as much of RFC 6455 as policing
//! needs and not one byte more. The frame scanner reads HEADERS only
//! (2..=14 bytes: opcode + mask bit + 7/16/64-bit lengths) — it never
//! unmasks, never validates opcodes beyond the data/control split,
//! and never inspects payload bytes. The origin check is a string
//! comparison against config values. The close frame the policer
//! sends (opcode 8, status 1008) is four fixed bytes. Everything
//! else — the handshake itself, the upgraded byte pipe — stays the
//! generic tunnel's job (`proxy::tunnel`); a non-WebSocket upgrade
//! (any other `Upgrade` token) never enters this module.
//!
//! # The origin gate
//!
//! Applied in the proxy action when the request offers a `websocket`
//! upgrade: a non-empty `routes[].websocket.origins` list admits ONLY
//! exact (case-sensitive) matches. A MISSING `Origin` header is
//! denied — browsers always send one on a WebSocket handshake, so an
//! originless handshake is a non-browser client the operator did not
//! name; fail closed. The check denies BEFORE any upstream contact
//! (no dial, no breaker observation) with the gateway's standard
//! envelope, code `websocket_origin_denied`.
//!
//! # The frame-rate policer
//!
//! [`WsPoliceIo`] wraps the UPGRADED CLIENT side of the tunnel. Every
//! byte the client sends passes through transparently while a scanner
//! tracks frame boundaries and counts DATA frames (text `0x1`,
//! binary `0x2`, continuation `0x0`; ping/pong/close are free — they
//! are the protocol's own housekeeping, and a ping flood is bounded
//! by the connection itself). The allowance is a token bucket:
//! `rate` tokens per second, capacity `rate` (a one-second burst). A
//! data frame with no token left trips the policer: a close frame
//! with status 1008 (policy violation) is queued for the CLIENT
//! direction (written ahead of any other pending bytes), the client
//! read side returns EOF (the tunnel propagates shutdown), and the
//! connection ends. Policing is one-directional by design: it
//! protects UPSTREAMS from abusive clients.
//!
//! Fragmented messages count per frame — a client fragmenting every
//! message gets policed harder, not softer; the conservative
//! direction is the safe one. Extended (16/64-bit) lengths are data
//! frames by construction: RFC 6455 caps CONTROL frames at 125
//! payload bytes, so only data frames ever carry them.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper::HeaderMap;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::config::RouteWebsocket;

/// Close frame for status 1008 (policy violation): FIN + opcode 8,
/// unmasked (server-to-client frames are never masked), 2-byte
/// status, empty reason. Four fixed bytes, sent as-is.
const CLOSE_POLICY_VIOLATION: [u8; 4] = [0x88, 0x02, 0x03, 0xe8];

/// Whether a request offering upgrades asks for WebSocket (the
/// `Upgrade` header is a comma list; the token is case-insensitive
/// per RFC 7230).
pub fn offers_websocket(headers: &HeaderMap) -> bool {
    headers
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("websocket"))
        })
}

/// The origin gate: `true` when the handshake may proceed. A
/// non-empty allowlist admits only exact matches; a missing `Origin`
/// is denied under a non-empty allowlist (fail closed).
pub fn origin_allowed(headers: &HeaderMap, ws: &RouteWebsocket) -> bool {
    if ws.origins.is_empty() {
        return true;
    }
    headers
        .get(hyper::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|origin| ws.origins.iter().any(|allowed| allowed == origin))
}

/// The handshake gate's outcome for one upgrade request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handshake {
    /// Proceed with the transparent upgrade path.
    Allowed,
    /// A non-empty allowlist did not name this origin (or the request
    /// carried none): deny with 403 before any upstream contact.
    OriginDenied,
}

/// One policy decision at the handshake (DW-039): the proxy calls
/// this before forwarding an upgrade request.
pub fn handshake_verdict(headers: &HeaderMap, ws: &RouteWebsocket) -> Handshake {
    if !ws.origins.is_empty() && !origin_allowed(headers, ws) {
        return Handshake::OriginDenied;
    }
    Handshake::Allowed
}

/// What part of the current frame the passed bytes belong to.
#[derive(Debug)]
enum Scan {
    /// Reading the fixed 2-byte frame header.
    Head { buf: [u8; 2], have: usize },
    /// Reading an extended length field (2 or 8 bytes; always a data
    /// frame — control frames cannot exceed 125 payload bytes). The
    /// mask length rides along: a masked frame's 4 mask bytes belong
    /// to the payload span, so the skip stays in sync.
    Extended {
        buf: [u8; 8],
        need: usize,
        have: usize,
        mask_len: u64,
    },
    /// Inside a payload with `remaining` bytes left (mask bytes
    /// included: 4 when the frame is masked, which client frames
    /// always are — the mask length is folded in here so the scanner
    /// never has to remember it).
    Payload { remaining: u64, data_frame: bool },
}

/// The frame-boundary scanner: fed the exact byte stream the tunnel
/// forwards client-to-upstream, counts data frames. Bytes are
/// ANALYZED, never modified — the tunnel stays byte-exact.
#[derive(Debug)]
pub struct FrameCounter {
    scan: Scan,
    frames: u64,
}

impl FrameCounter {
    pub fn new() -> Self {
        FrameCounter {
            scan: Scan::Head {
                buf: [0, 0],
                have: 0,
            },
            frames: 0,
        }
    }

    pub fn data_frames(&self) -> u64 {
        self.frames
    }

    /// Feed the next chunk of the client-to-upstream byte stream
    /// (chunk boundaries are irrelevant — the scanner spans them).
    /// Public so the DW-039 unit tests can pin the spanning contract
    /// directly; not part of the stable surface.
    pub fn feed(&mut self, bytes: &[u8]) {
        let mut rest = bytes;
        while !rest.is_empty() {
            match &mut self.scan {
                Scan::Head { buf, have } => {
                    let take = (2 - *have).min(rest.len());
                    buf[*have..*have + take].copy_from_slice(&rest[..take]);
                    *have += take;
                    rest = &rest[take..];
                    if *have < 2 {
                        continue;
                    }
                    let [b0, b1] = *buf;
                    let opcode = b0 & 0x0f;
                    let data_frame = matches!(opcode, 0x0..=0x2);
                    let masked = b1 & 0x80 != 0;
                    let len7 = (b1 & 0x7f) as u64;
                    let mask_len: u64 = if masked { 4 } else { 0 };
                    match len7 {
                        0..=125 => {
                            let total = len7 + mask_len;
                            if total == 0 {
                                if data_frame {
                                    self.frames += 1;
                                }
                                self.scan = Scan::Head {
                                    buf: [0, 0],
                                    have: 0,
                                };
                            } else {
                                self.scan = Scan::Payload {
                                    remaining: total,
                                    data_frame,
                                };
                            }
                        }
                        126 => {
                            self.scan = Scan::Extended {
                                buf: [0; 8],
                                need: 2,
                                have: 0,
                                mask_len,
                            };
                        }
                        _ => {
                            self.scan = Scan::Extended {
                                buf: [0; 8],
                                need: 8,
                                have: 0,
                                mask_len,
                            };
                        }
                    }
                }
                Scan::Extended {
                    buf,
                    need,
                    have,
                    mask_len,
                } => {
                    let take = (*need - *have).min(rest.len());
                    buf[*have..*have + take].copy_from_slice(&rest[..take]);
                    *have += take;
                    rest = &rest[take..];
                    if *have < *need {
                        continue;
                    }
                    let len = if *need == 2 {
                        u16::from_be_bytes([buf[0], buf[1]]) as u64
                    } else {
                        u64::from_be_bytes([
                            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                        ])
                    };
                    // Extended lengths are data frames by construction
                    // (control frames are capped at 125 bytes).
                    self.scan = Scan::Payload {
                        remaining: len + *mask_len,
                        data_frame: true,
                    };
                }
                Scan::Payload {
                    remaining,
                    data_frame,
                } => {
                    let consumed = (*remaining).min(rest.len() as u64);
                    *remaining -= consumed;
                    rest = &rest[consumed as usize..];
                    if *remaining == 0 {
                        if *data_frame {
                            self.frames += 1;
                        }
                        self.scan = Scan::Head {
                            buf: [0, 0],
                            have: 0,
                        };
                    }
                }
            }
        }
    }
}

impl Default for FrameCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Data frames counted for a byte stream fed in one chunk (tests and
/// diagnostics).
pub fn count_data_frames(bytes: &[u8]) -> u64 {
    let mut c = FrameCounter::new();
    c.feed(bytes);
    c.data_frames()
}

/// A token bucket: `rate` tokens per second, capacity `rate` (a
/// one-second burst). Refilled on access — used from exactly one
/// task (the tunnel), so no locking.
#[derive(Debug)]
struct Bucket {
    rate: f64,
    tokens: f64,
    last: std::time::Instant,
}

impl Bucket {
    fn new(rate: u64) -> Self {
        Bucket {
            rate: rate as f64,
            tokens: rate as f64,
            last: std::time::Instant::now(),
        }
    }

    /// Refill to the current instant and try to take one token.
    fn take(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.rate);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// The policing wrapper around the UPGRADED CLIENT side of the tunnel
/// (DW-039). Reads pass through byte-exact while the frame scanner
/// counts; on the first unfunded data frame a 1008 close frame is
/// queued for the write path (ahead of any other bytes) and the read
/// side returns EOF — the tunnel then shuts both directions down.
/// Bytes are never modified in either direction.
pub struct WsPoliceIo<S> {
    inner: S,
    counter: FrameCounter,
    bucket: Bucket,
    /// Data frames already charged against the bucket.
    charged: u64,
    /// Set once the allowance is exhausted.
    closing: bool,
    close_out: Vec<u8>,
    /// Shared with the tunnel spawner so the metric survives the
    /// tunnel consuming the wrapper by value.
    violated: Arc<AtomicU64>,
}

impl<S> WsPoliceIo<S> {
    /// Wrap the upgraded client IO with a `max_frames_per_sec`
    /// allowance (data frames, sustained, one-second burst). The
    /// violation flag is shared with the caller (it reads 1 after the
    /// policer trips — the metric's witness).
    pub fn with_flag(inner: S, max_frames_per_sec: u64, violated: Arc<AtomicU64>) -> Self {
        WsPoliceIo {
            inner,
            counter: FrameCounter::new(),
            bucket: Bucket::new(max_frames_per_sec.max(1)),
            charged: 0,
            closing: false,
            close_out: Vec::new(),
            violated,
        }
    }

    /// Whether policing has tripped.
    pub fn violated(&self) -> bool {
        self.violated.load(Ordering::Relaxed) == 1
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsPoliceIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.closing {
            // The verdict is in: no more client bytes are forwarded
            // (an empty ReadBuf IS the EOF signal).
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                this.counter.feed(buf.filled());
                // Charge one token per NEWLY counted data frame; the
                // first frame without funding trips the policer. The
                // bytes of THIS poll still pass (they were read before
                // the verdict); the next read is EOF.
                while this.charged < this.counter.data_frames() {
                    this.charged += 1;
                    if !this.bucket.take() {
                        this.closing = true;
                        this.close_out.extend_from_slice(&CLOSE_POLICY_VIOLATION);
                        this.violated.store(1, Ordering::Relaxed);
                        break;
                    }
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WsPoliceIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        // The close frame goes first — the client must see the policy
        // verdict even mid-burst of upstream bytes.
        while !this.close_out.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.close_out) {
                Poll::Ready(Ok(n)) => {
                    this.close_out.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
