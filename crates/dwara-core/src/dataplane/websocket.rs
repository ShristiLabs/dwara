//! WebSocket policy (DW-039 + DP-05 #253): the knobs that turn the
//! generic 101 tunnel into a managed one for browser-style WebSocket
//! traffic — origin allowlisting at the handshake, post-upgrade
//! frame-rate policing, per-frame size limits, idle-timeout reaping,
//! and RFC 6455 protocol-error enforcement on the tunnel.
//!
//! # Zero new dependencies, by construction
//!
//! The module hand-rolls exactly as much of RFC 6455 as policing
//! needs and not one byte more. The frame scanner reads HEADERS only
//! (2..=14 bytes: opcode + mask bit + 7/16/64-bit lengths) — it never
//! unmasks, never inspects payload bytes. The origin check is a string
//! comparison against config values. The close frames the policer
//! sends (opcode 8, status 1008/1009/1002) are four fixed bytes each.
//! Everything else — the handshake itself, the upgraded byte pipe —
//! stays the generic tunnel's job (`proxy::tunnel` / `proxy::idle_tunnel`);
//! a non-WebSocket upgrade (any other `Upgrade` token) never enters
//! this module.
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
//!
//! # DP-05 (#253): frame size, protocol errors, and idle timeout
//!
//! The frame scanner was extended to enforce three additional
//! policies, all closing the connection with the appropriate code:
//!
//! - **`max_frame_size_bytes`**: a DATA frame whose payload length
//!   exceeds the configured cap is closed with status 1009 (message
//!   too big). The check runs at the header scan — both the 7-bit
//!   short length and the 16/64-bit extended length — before the
//!   payload is consumed.
//! - **Reserved opcodes**: RFC 6455 reserves 0x3-0x7 (data) and
//!   0xB-0xF (control). A frame using a reserved opcode is closed
//!   with status 1002 (protocol error).
//! - **Control-frame length**: control frames with extended lengths
//!   (len7 >= 126) violate RFC 6455 §5.5 (control payloads must be
//!   <= 125 bytes) and are closed with status 1002.
//!
//! The idle timeout (`idle_timeout_s`) is enforced at the tunnel
//! level by `proxy::idle_tunnel`, which wraps the bidirectional copy
//! in a resettable `tokio::time::sleep`. Each successful read or
//! write in either direction resets the timer; if it fires, both
//! sides are shut down.

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

/// Close frame for status 1009 (message too big): FIN + opcode 8,
/// unmasked, 2-byte status 0x03F1, empty reason.
const CLOSE_MESSAGE_TOO_BIG: [u8; 4] = [0x88, 0x02, 0x03, 0xf1];

/// Close frame for status 1002 (protocol error): FIN + opcode 8,
/// unmasked, 2-byte status 0x03EA, empty reason. Used for reserved
/// opcodes and malformed control-frame lengths (DP-05, #253).
const CLOSE_PROTOCOL_ERROR: [u8; 4] = [0x88, 0x02, 0x03, 0xea];

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

/// The kind of protocol violation the frame scanner detected (DP-05,
/// #253). Stored in the shared violation flag so the tunnel spawner
/// records the right metric and close code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FrameViolation {
    #[default]
    None,
    /// Data frame exceeded `max_frame_size_bytes` — close 1009.
    SizeExceeded,
    /// Reserved opcode (0x3-0x7 data, 0xB-0xF control) or a control
    /// frame with an extended length (RFC 6455 caps control payloads
    /// at 125 bytes) — close 1002.
    ProtocolError,
}

/// Shared-flag discriminants stored in the `AtomicU64` witness.
/// Distinct from the `FrameViolation` enum so rate-closed (which is
/// not a frame-scanner violation) gets its own code without colliding.
const FLAG_NONE: u64 = 0;
const FLAG_RATE_CLOSED: u64 = 1;
const FLAG_SIZE_CLOSED: u64 = 2;
const FLAG_PROTOCOL_CLOSED: u64 = 3;

/// Decode the shared violation flag into the metric label the tunnel
/// spawner records (DP-05, #253). Returns an empty string when no
/// violation occurred.
pub fn flag_to_metric(flag: u64) -> &'static str {
    match flag {
        FLAG_RATE_CLOSED => "rate_closed",
        FLAG_SIZE_CLOSED => "size_closed",
        FLAG_PROTOCOL_CLOSED => "protocol_closed",
        _ => "",
    }
}

impl FrameViolation {
    /// The close frame to send for this violation kind.
    fn close_frame(self) -> &'static [u8] {
        match self {
            FrameViolation::SizeExceeded => &CLOSE_MESSAGE_TOO_BIG,
            FrameViolation::ProtocolError => &CLOSE_PROTOCOL_ERROR,
            FrameViolation::None => &[],
        }
    }

    /// The shared-flag discriminant for the tunnel spawner's witness.
    fn flag(self) -> u64 {
        match self {
            FrameViolation::None => FLAG_NONE,
            FrameViolation::SizeExceeded => FLAG_SIZE_CLOSED,
            FrameViolation::ProtocolError => FLAG_PROTOCOL_CLOSED,
        }
    }
}

/// The frame-boundary scanner: fed the exact byte stream the tunnel
/// forwards client-to-upstream, counts data frames. Bytes are
/// ANALYZED, never modified — the tunnel stays byte-exact.
#[derive(Debug)]
pub struct FrameCounter {
    scan: Scan,
    frames: u64,
    /// Optional per-frame payload-size cap (DP-05, #253). A frame
    /// whose payload length exceeds this trips `violation`.
    max_frame_size: Option<u64>,
    /// The first violation detected during scanning (size or protocol).
    /// Once set, the scanner stops updating — the policer will close.
    violation: FrameViolation,
}

impl FrameCounter {
    pub fn new() -> Self {
        FrameCounter {
            scan: Scan::Head {
                buf: [0, 0],
                have: 0,
            },
            frames: 0,
            max_frame_size: None,
            violation: FrameViolation::None,
        }
    }

    /// Configure a maximum payload size per data frame (DP-05, #253).
    pub fn with_max_frame_size(mut self, max: u64) -> Self {
        self.max_frame_size = Some(max);
        self
    }

    pub fn data_frames(&self) -> u64 {
        self.frames
    }

    /// The first violation detected, or `None` if the stream is clean.
    pub fn violation(&self) -> FrameViolation {
        self.violation
    }

    /// Feed the next chunk of the client-to-upstream byte stream
    /// (chunk boundaries are irrelevant — the scanner spans them).
    /// Public so the DW-039 unit tests can pin the spanning contract
    /// directly; not part of the stable surface.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.violation != FrameViolation::None {
            return;
        }
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
                    // DP-05 (#253): reject reserved opcodes. RFC 6455
                    // reserves 0x3-0x7 (data) and 0xB-0xF (control).
                    // Valid: 0x0 continuation, 0x1 text, 0x2 binary,
                    // 0x8 close, 0x9 ping, 0xA pong.
                    if matches!(opcode, 0x3..=0x7 | 0xB..=0xF) {
                        self.violation = FrameViolation::ProtocolError;
                        return;
                    }
                    let data_frame = matches!(opcode, 0x0..=0x2);
                    let control = matches!(opcode, 0x8..=0xA);
                    let masked = b1 & 0x80 != 0;
                    let len7 = (b1 & 0x7f) as u64;
                    let mask_len: u64 = if masked { 4 } else { 0 };
                    // DP-05 (#253): control frames with extended
                    // lengths are a protocol error (RFC 6455 §5.5
                    // caps control payloads at 125 bytes).
                    if control && len7 >= 126 {
                        self.violation = FrameViolation::ProtocolError;
                        return;
                    }
                    // DP-05 (#253): check per-frame size cap.
                    if let Some(max) = self.max_frame_size {
                        if len7 <= 125 && len7 > max {
                            self.violation = FrameViolation::SizeExceeded;
                            return;
                        }
                    }
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
                    // DP-05 (#253): check per-frame size cap on the
                    // extended length (already known to be a data frame
                    // — control frames with extended lengths were
                    // rejected at the Head scan).
                    if let Some(max) = self.max_frame_size {
                        if len > max {
                            self.violation = FrameViolation::SizeExceeded;
                            return;
                        }
                    }
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
/// (DW-039, DP-05 #253). Reads pass through byte-exact while the frame
/// scanner counts; on the first unfunded data frame a 1008 close frame
/// is queued for the write path (ahead of any other bytes) and the read
/// side returns EOF — the tunnel then shuts both directions down.
/// Bytes are never modified in either direction.
///
/// DP-05 (#253) extends policing beyond rate to per-frame size limits
/// (close 1009) and reserved-opcode / malformed-control-length
/// enforcement (close 1002). The shared `violated` flag carries the
/// violation kind so the tunnel spawner records the right metric.
pub struct WsPoliceIo<S> {
    inner: S,
    counter: FrameCounter,
    bucket: Option<Bucket>,
    /// Data frames already charged against the bucket.
    charged: u64,
    /// Set once a violation has been detected and the close frame
    /// queued.
    closing: bool,
    close_out: Vec<u8>,
    /// Shared with the tunnel spawner so the metric survives the
    /// tunnel consuming the wrapper by value. Stores a `FrameViolation`
    /// discriminant as a `u64` (0 = no violation).
    violated: Arc<AtomicU64>,
}

impl<S> WsPoliceIo<S> {
    /// Wrap the upgraded client IO with post-upgrade WebSocket
    /// policies (DW-039 + DP-05 #253). `max_frames_per_sec` enables
    /// rate policing (data frames, sustained, one-second burst);
    /// `max_frame_size_bytes` enables per-frame size policing. Either
    /// may be `None` to skip that policy. The violation flag is shared
    /// with the caller so it can record the right metric after the
    /// tunnel ends.
    pub fn with_flag(
        inner: S,
        max_frames_per_sec: Option<u64>,
        max_frame_size_bytes: Option<u64>,
        violated: Arc<AtomicU64>,
    ) -> Self {
        let counter = match max_frame_size_bytes {
            Some(max) => FrameCounter::new().with_max_frame_size(max),
            None => FrameCounter::new(),
        };
        WsPoliceIo {
            inner,
            counter,
            bucket: max_frames_per_sec.map(|r| Bucket::new(r.max(1))),
            charged: 0,
            closing: false,
            close_out: Vec::new(),
            violated,
        }
    }

    /// Whether policing has tripped.
    pub fn violated(&self) -> bool {
        self.violated.load(Ordering::Relaxed) != 0
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
                // DP-05 (#253): check for frame-level violations
                // (size, reserved opcode, malformed control) first —
                // these are hard protocol errors, not rate limits.
                let v = this.counter.violation();
                if v != FrameViolation::None {
                    this.closing = true;
                    this.close_out.extend_from_slice(v.close_frame());
                    this.violated.store(v.flag(), Ordering::Relaxed);
                    return Poll::Ready(Ok(()));
                }
                // Charge one token per NEWLY counted data frame; the
                // first frame without funding trips the policer. The
                // bytes of THIS poll still pass (they were read before
                // the verdict); the next read is EOF.
                if let Some(bucket) = this.bucket.as_mut() {
                    while this.charged < this.counter.data_frames() {
                        this.charged += 1;
                        if !bucket.take() {
                            this.closing = true;
                            this.close_out.extend_from_slice(&CLOSE_POLICY_VIOLATION);
                            this.violated.store(FLAG_RATE_CLOSED, Ordering::Relaxed);
                            break;
                        }
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
