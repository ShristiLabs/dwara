//! PROXY protocol acceptance, v1 and v2 (DW-030, feature analysis 4.20).
//!
//! A listener configured with `proxy_protocol: true` expects a PROXY
//! protocol header (HAProxy specification; v1 text or v2 binary) as the
//! FIRST bytes of every connection — BEFORE the TLS handshake when the
//! listener terminates TLS, because the L4 load balancer in front wraps
//! the whole stream. The header's source address then REPLACES the
//! accepted socket peer for everything downstream that consumes the
//! peer address: the authz IP ACL's effective-client-IP base,
//! rate-limit keying, and the `X-Forwarded-For` / `X-Real-IP` values
//! stamped on the forwarded request (the one `peer` argument of
//! [`crate::dataplane::proxy::handle`]).
//!
//! Security posture (frozen):
//!
//! - **Opt-in per listener.** A listener without the flag never
//!   interprets first bytes as a PROXY line; there is no sniffing. The
//!   spoofing boundary is exactly the config: an address claim is
//!   honored only on listeners explicitly declared to sit behind a
//!   PROXY-protocol-speaking LB (the same trust model as
//!   `gateway.trusted_proxies` for XFF).
//! - **Fail closed.** A malformed header (bad signature, bad lengths,
//!   Unix address family, datagram protocol on this stream listener,
//!   trailing garbage) is answered with a `400` JSON error envelope and
//!   the connection is closed — the bytes are NEVER handed to HTTP
//!   parsing (a desynced half-header must not become half a request
//!   line). A connection that stalls mid-header or drops is closed
//!   without a response (nothing parseable to answer, same as a TLS
//!   handshake timeout).
//! - **Bounded.** The whole header must arrive within the caller's
//!   deadline (the DW-023 slowloris header timeout — the same attack,
//!   one layer earlier) and within the protocol's own size ceiling
//!   (107 bytes for v1, 16 + 65535 for v2). A trickle that never
//!   completes is cut by the deadline, not buffered forever.
//! - **Spec fallbacks honored.** A v2 `LOCAL` command (the LB's own
//!   health check, not a proxied client) and a v1 `UNKNOWN` line keep
//!   the REAL peer address — the specification's fallback for
//!   connections whose origin the LB declines to assert.
//!
//! Parsing is delegated to the `ppp` crate (v2 TLV/bounds safety);
//! this module owns the async framing read, the deadline, the caps,
//! and the fail-closed policy. Passthrough listeners cannot combine
//! with PROXY acceptance (validation rejects it): a passthrough
//! listener splices raw bytes and never runs the HTTP pipeline that
//! would consume the address.

use std::net::SocketAddr;
use std::time::Duration;

use ppp::{HeaderResult, PartialResult};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Hard ceiling on a v1 header line (the specification's 107-byte worst
/// case: long IPv6 literals at both ends).
const V1_MAX: usize = 107;
/// Hard ceiling on a v2 header: 16 fixed bytes + the u16 length field's
/// payload maximum (TLVs included). A length field claiming more than
/// this is malformed on its face (it cannot exist in a u16).
const V2_MAX: usize = 16 + u16::MAX as usize;

/// Why a connection was not admitted with a PROXY-protocol-derived
/// address. `Malformed` is answerable (the gateway was given bytes that
/// claimed to be a header and were not); the IO variants are silent
/// closes.
#[derive(Debug)]
pub enum ProxyProtoError {
    /// The header bytes were parseable as NEITHER a complete v1 nor v2
    /// header (bad signature/lengths/families), carried a Unix address
    /// family or a datagram protocol (this is a TCP stream listener), or
    /// exceeded the protocol's size ceiling. Fail closed with 400.
    Malformed(&'static str),
    /// The whole header did not arrive within the deadline (a
    /// slowloris-style trickle against the PROXY line). Close silently.
    Incomplete,
    /// The peer closed the stream or the read errored mid-header.
    /// Close silently (nothing parseable to answer).
    Io(std::io::Error),
}

impl std::fmt::Display for ProxyProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyProtoError::Malformed(why) => write!(f, "malformed PROXY header: {why}"),
            ProxyProtoError::Incomplete => {
                write!(f, "PROXY header did not complete within the deadline")
            }
            ProxyProtoError::Io(e) => write!(f, "PROXY header read failed: {e}"),
        }
    }
}

impl std::error::Error for ProxyProtoError {}

/// Read one PROXY protocol header (v1 or v2) from the stream and decide
/// the connection's EFFECTIVE client address.
///
/// Returns the address the gateway must use as the peer: the header's
/// source address for a `PROXY` command with a TCP family, or `real`
/// for the specification's own fallback shapes (v2 `LOCAL`, v1
/// `UNKNOWN`). `deadline` bounds the WHOLE header (not per-read: a
/// partial PROXY line can never be handed to the HTTP parser, so
/// unlike the DW-023 request-head sniff there is no fall-through).
///
/// Reads incrementally: ppp's `PartialResult` says whether more bytes
/// could complete the header, so at most the header itself is buffered
/// (never the request that follows it on well-behaved senders that
/// coalesce; a sender that pipelines request bytes into the first read
/// has them replayed by the caller's sniff/prefix stream — see
/// [`ProxyHeader::consumed`]).
pub async fn read_client_addr<S>(
    stream: &mut S,
    real: SocketAddr,
    deadline: Duration,
) -> Result<ProxyHeader, ProxyProtoError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Buffer with headroom for one v2 header exactly; grow past V1_MAX
    // only for v2-shaped input (the 12-byte binary signature).
    let mut buf: Vec<u8> = Vec::with_capacity(V2_MAX);
    let mut chunk = [0u8; 1024];
    let read = async {
        loop {
            let parsed = HeaderResult::parse(&buf);
            if !parsed.is_incomplete() {
                let (client, consumed) = classify(parsed, real)?;
                return Ok(ProxyHeader {
                    client,
                    consumed,
                    prefix: buf[consumed..].to_vec(),
                });
            }
            // Incomplete so far: the bytes read so far must still be
            // CONSISTENT with one of the two version signatures (a
            // prefix of "PROXY ", or a prefix of the 12-byte v2 binary
            // signature followed by anything). Growth is then bounded
            // by that version's own ceiling; anything else is malformed
            // NOW — never fall through to HTTP parsing.
            let v2_sig = ppp::v2::PROTOCOL_PREFIX;
            let n2 = buf.len().min(v2_sig.len());
            let v1_prefix: &[u8] = b"PROXY ";
            let n1 = buf.len().min(v1_prefix.len());
            let cap = if buf[..n2] == v2_sig[..n2] {
                V2_MAX
            } else if buf[..n1] == v1_prefix[..n1] {
                V1_MAX
            } else {
                return Err(ProxyProtoError::Malformed(
                    "first bytes are neither a v1 line nor a v2 signature",
                ));
            };
            if buf.len() > cap {
                return Err(ProxyProtoError::Malformed(
                    "header exceeds the protocol ceiling",
                ));
            }
            let n = match stream.read(&mut chunk).await {
                Ok(0) => {
                    return Err(ProxyProtoError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "peer closed mid-header",
                    )))
                }
                Ok(n) => n,
                Err(e) => return Err(ProxyProtoError::Io(e)),
            };
            buf.extend_from_slice(&chunk[..n]);
        }
    };
    match tokio::time::timeout(deadline, read).await {
        Ok(result) => result,
        Err(_) => Err(ProxyProtoError::Incomplete),
    }
}

/// What the listener learned from one accepted connection's header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyHeader {
    /// The address the gateway must treat as the connection's client
    /// (header source, or the real peer for the spec's fallback shapes).
    pub client: SocketAddr,
    /// Bytes of the PROXY header itself.
    pub consumed: usize,
    /// Bytes read BEYOND the header (a sender pipelining the TLS
    /// records or the HTTP head behind the PROXY line): replay them in
    /// front of the stream handed onward
    /// ([`crate::dataplane::hardening::PrefixedStream`]).
    pub prefix: Vec<u8>,
}

/// Turn a complete `HeaderResult` into the effective address policy:
/// the client address and how many bytes the header occupied.
fn classify(
    parsed: HeaderResult<'_>,
    real: SocketAddr,
) -> Result<(SocketAddr, usize), ProxyProtoError> {
    match parsed {
        HeaderResult::V2(Ok(h)) => {
            let consumed = h.header.len();
            use ppp::v2::{Addresses, Command, Protocol};
            // A datagram protocol claim is misuse on a TCP stream
            // listener — but only under the PROXY command: a LOCAL
            // header's other fields are noise by specification (the
            // connection is the LB's own), so LOCAL falls through to
            // the real peer whatever they say.
            if h.command == Command::Proxy && h.protocol == Protocol::Datagram {
                return Err(ProxyProtoError::Malformed(
                    "v2 header claims a datagram protocol on a stream listener",
                ));
            }
            match (h.command, h.addresses) {
                // The LB's own connection (health checks): keep the real
                // peer, exactly as the specification prescribes.
                (Command::Local, _) => Ok((real, consumed)),
                // AF_UNSPEC with the PROXY command: the spec's explicit
                // "use the local connection's addresses" fallback.
                (Command::Proxy, Addresses::Unspecified) => Ok((real, consumed)),
                (Command::Proxy, Addresses::IPv4(a)) => Ok((
                    SocketAddr::from((a.source_address, a.source_port)),
                    consumed,
                )),
                (Command::Proxy, Addresses::IPv6(a)) => Ok((
                    SocketAddr::from((a.source_address, a.source_port)),
                    consumed,
                )),
                // AF_UNIX addresses cannot feed the IP-keyed policies.
                (Command::Proxy, Addresses::Unix(_)) => Err(ProxyProtoError::Malformed(
                    "v2 header carries a Unix address family on a TCP listener",
                )),
            }
        }
        HeaderResult::V1(Ok(h)) => {
            let consumed = h.header.len();
            match h.addresses {
                ppp::v1::Addresses::Unknown => Ok((real, consumed)),
                ppp::v1::Addresses::Tcp4(a) => Ok((
                    SocketAddr::from((a.source_address, a.source_port)),
                    consumed,
                )),
                ppp::v1::Addresses::Tcp6(a) => Ok((
                    SocketAddr::from((a.source_address, a.source_port)),
                    consumed,
                )),
            }
        }
        // A terminal error from both parsers: garbage that claimed to be
        // neither version. Fail closed.
        HeaderResult::V2(Err(_)) | HeaderResult::V1(Err(_)) => Err(ProxyProtoError::Malformed(
            "bytes are neither a valid v1 nor v2 header",
        )),
    }
}

/// Answer a malformed-header connection with the `400` error envelope
/// and close it (the fail-closed half of the policy: never fall through
/// to HTTP parsing). The envelope is the gateway's uniform error shape,
/// with a freshly generated correlation ID (no request exists yet to
/// inherit one from).
pub async fn reject_malformed<S>(stream: &mut S) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let rid = crate::observability::generate_request_id();
    let body = crate::observability::envelope_body(
        "proxy_protocol_malformed",
        "connection opened with a malformed PROXY protocol header",
        &rid,
    );
    let head = format!(
        "HTTP/1.1 400 Bad Request\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\nx-request-id: {}\r\n\r\n",
        body.len(),
        rid
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await
}
