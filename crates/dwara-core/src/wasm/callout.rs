//! Plugin HTTP callout transport (DW-167, issue #285).
//!
//! [`perform_callout`] executes ONE `proxy_http_call` dispatch: the
//! minimal synchronous HTTP/1.1 client the wasm domain already owns
//! for registry fetches (`super::source`) extended with the `http://`
//! scheme (callouts usually target internal services) and arbitrary
//! methods. The wasm runner stays synchronous — the ASYNC boundary is
//! `dataplane::plugin_dispatch`, which wraps this function in
//! `spawn_blocking`, delivers the response to the instance, and
//! re-collects the phase outcome (the pause/resume model; see the
//! adapter and plugin_dispatch docs).
//!
//! ## Guardrails (hard caps, no config surface)
//!
//! - **Timeout**: the plugin's requested timeout (milliseconds, the
//!   unit the Rust SDK's `dispatch_http_call` sends) clamped to
//!   `[CALLOUT_TIMEOUT_MIN_MS, CALLOUT_TIMEOUT_MAX_MS]` = [1ms, 5s].
//!   It is a whole-exchange wall clock: the connect budget and every
//!   read are clamped to the remaining time, so a target dripping one
//!   byte per read cannot outlive it by resetting a per-read timer.
//! - **Body cap**: [`CALLOUT_BODY_CAP_BYTES`] (4 MiB) on the response
//!   body (Content-Length and received bytes alike). Over-cap is a
//!   callout error, not truncation — the plugin must not act on a
//!   silently shortened decision payload.
//! - **Head cap**: [`CALLOUT_HEAD_CAP_BYTES`] (16 KiB), the same bound
//!   the registry fetcher uses.
//! - **Redirects are NOT followed**: a 3xx is delivered to the plugin
//!   as data (the plugin decides), the same posture as webhook
//!   deliveries and registry fetches.
//! - **SSRF**: the gateway `ssrf_filter` is applied at connect time
//!   against every RESOLVED IP (DNS rebinding mitigation), exactly as
//!   `source::https_get` does for registry fetches.
//! - **Schemes**: `http://` and `https://` only; anything else fails
//!   validation at the hostcall (BadArgument) before any network work.
//! - **Request-head integrity**: the request head is built by
//!   interpolating the plugin-supplied method, header names, values,
//!   and `:path` — every one of them is validated at the hostcall
//!   (BadArgument, fail-closed, no connection attempted): the method
//!   and header names must be RFC 7230 tokens, and names, values, and
//!   the map `:path` must carry no CR, LF, or NUL. A plugin reflecting
//!   client data into a callout therefore cannot smuggle a second
//!   request into the gateway-initiated connection (request
//!   splitting). [`perform_callout`] re-checks the same grammar as
//!   defense in depth (it is `pub` and callable with a hand-built
//!   [`CalloutRequest`]).
//!
//! ## Failure semantics (deliberate deviation from Envoy)
//!
//! Envoy invokes `proxy_on_http_call_response` with zeroed counts on a
//! callout failure (timeout, refused, reset), letting the plugin
//! branch on the empty maps. dwara instead FAILS THE ROUTE CLOSED: a
//! callout error is a plugin failure (500 `plugin_failed`, metric
//! reason `callout_failed`; the outcome itself is observable as
//! `dwara_plugin_callouts_total{name,outcome=timeout|error}`). The
//! plugin cannot make a fail-open decision without receiving a
//! response, and dwara's plugin posture is fail-closed end to end
//! (DW-157) — a plugin whose decision input never arrived must not
//! resume as if it had. Recipes wanting fail-open behavior scope it
//! explicitly (short timeouts, a fallback verdict implemented without
//! a callout, or an extension trait instead of a plugin).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::ssrf::SsrfFilter;

/// Minimum callout timeout (the plugin's request is clamped UP to
/// this): a zero/near-zero timeout would make every callout fail on
/// scheduling jitter alone.
pub const CALLOUT_TIMEOUT_MIN_MS: u32 = 1;
/// Maximum callout timeout (the plugin's request is clamped DOWN to
/// this): a per-request edge plugin must never hold a route for long.
pub const CALLOUT_TIMEOUT_MAX_MS: u32 = 5_000;
/// Cap on one callout response body (bytes).
pub const CALLOUT_BODY_CAP_BYTES: usize = 4 * 1024 * 1024;
/// Cap on the callout response head while locating the blank line
/// (bytes; the same bound the registry fetcher uses).
pub const CALLOUT_HEAD_CAP_BYTES: usize = 16 * 1024;
/// Maximum callout rounds per phase per request (the loop guard,
/// enforced by `dataplane::plugin_dispatch`; declared here so the
/// callout vocabulary lives in one module).
pub const MAX_CALLOUT_ROUNDS: u32 = 8;
/// TCP connect timeout per address (clamped to the remaining
/// callout-deadline budget in flight).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// `User-Agent` stamped on plugin callouts.
const USER_AGENT: &str = "dwara-plugin-callout";

/// One registered `proxy_http_call` dispatch, parsed and validated at
/// the hostcall and performed by [`perform_callout`].
#[derive(Clone, Debug)]
pub struct CalloutRequest {
    /// The config-declared plugin name (attribution + metrics).
    pub plugin: String,
    /// The token the host handed the plugin (delivered back with the
    /// response so the SDK dispatcher can route it).
    pub token: u32,
    /// The full `http(s)://host[:port]/path?query` URI string.
    pub uri: String,
    /// The request method (`:method` from the dispatch header map).
    pub method: String,
    /// Ordinary request headers (pseudo-headers stripped at the
    /// hostcall; framing headers are owned by the transport).
    pub headers: Vec<(String, String)>,
    /// The request body (may be empty).
    pub body: Vec<u8>,
    /// The plugin-requested timeout in milliseconds (clamped to
    /// `[CALLOUT_TIMEOUT_MIN_MS, CALLOUT_TIMEOUT_MAX_MS]` at perform
    /// time).
    pub timeout_ms: u32,
}

/// A completed callout response, ready to deliver to the instance.
/// ANY completed status is delivered — non-2xx is data (the plugin
/// decides what a 403 from its decision service means); only transport
/// failures (timeout/refused/reset/caps/SSRF) are errors.
#[derive(Clone, Debug)]
pub struct CalloutResponse {
    /// The response status code.
    pub status: u16,
    /// Response headers with hop-by-hop names stripped; `:status` is
    /// prepended by the host when the map is exposed to the plugin.
    pub headers: Vec<(String, String)>,
    /// The response body (bounded by [`CALLOUT_BODY_CAP_BYTES`]).
    pub body: Vec<u8>,
}

/// Why a callout could not be completed. `Timeout` gets its own metric
/// outcome; every other failure is `Error`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CalloutError {
    /// The clamped whole-exchange deadline expired (mid-connect,
    /// mid-read, or before the exchange started).
    Timeout,
    /// Every other failure: DNS, refused, TLS, reset, framing, caps,
    /// SSRF rejection. The string is operator-facing detail (logs
    /// only; it never reaches the client).
    Failed(String),
}

impl CalloutError {
    /// The `dwara_plugin_callouts_total` outcome label for this error.
    pub fn outcome(&self) -> &'static str {
        match self {
            CalloutError::Timeout => "timeout",
            CalloutError::Failed(_) => "error",
        }
    }
}

impl std::fmt::Display for CalloutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CalloutError::Timeout => write!(
                f,
                "callout timeout: the clamped whole-exchange deadline \
                 (max {} ms) expired before the response completed",
                CALLOUT_TIMEOUT_MAX_MS
            ),
            CalloutError::Failed(detail) => write!(f, "callout failed: {detail}"),
        }
    }
}

impl std::error::Error for CalloutError {}

/// Clamp the plugin-requested timeout into the documented window.
pub fn clamp_timeout_ms(requested_ms: u32) -> u32 {
    requested_ms.clamp(CALLOUT_TIMEOUT_MIN_MS, CALLOUT_TIMEOUT_MAX_MS)
}

/// Whether `s` is an RFC 7230 `token` (the `tchar` grammar): the
/// method and every header NAME must match it. A non-token would
/// smuggle framing bytes (spaces, CR/LF, control characters) into the
/// interpolated request head — the request-splitting recipe.
pub fn is_rfc7230_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Whether `s` is free of the bytes that terminate or split the
/// HTTP/1.1 request head: CR, LF, and NUL. Header values and the map
/// `:path` ride the head verbatim, so any of these bytes is rejected
/// (a value may legally carry obs-text, which this check leaves alone).
pub fn is_head_safe(s: &str) -> bool {
    !s.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

/// Validate the request-head grammar of one callout request (method
/// token, header-name tokens, delimiter-free values). Shared by the
/// hostcall (BadArgument before any registration) and
/// [`perform_callout`] (defense in depth before any network work).
fn validate_request_head(method: &str, headers: &[(String, String)]) -> Result<(), CalloutError> {
    if !is_rfc7230_token(method) {
        return Err(CalloutError::Failed(
            "callout method is not a valid HTTP token".to_string(),
        ));
    }
    for (name, value) in headers {
        // A token name is delimiter-free by construction; the value
        // check is the request-splitting guard.
        if !is_rfc7230_token(name) {
            return Err(CalloutError::Failed(format!(
                "callout header name '{name}' is not a valid HTTP token"
            )));
        }
        if !is_head_safe(value) {
            return Err(CalloutError::Failed(
                "callout header value contains CR, LF, or NUL".to_string(),
            ));
        }
    }
    Ok(())
}

/// Perform one callout exchange. Synchronous by design (the async
/// boundary is plugin_dispatch's `spawn_blocking`); reuses the
/// registry fetcher's transport posture (SSRF at connect, per-read
/// timeouts clamped to the deadline, `Connection: close`, read to
/// EOF) with the `http://` scheme and arbitrary methods added.
pub fn perform_callout(
    req: &CalloutRequest,
    ssrf: &SsrfFilter,
) -> Result<CalloutResponse, CalloutError> {
    let timeout = Duration::from_millis(clamp_timeout_ms(req.timeout_ms) as u64);
    let deadline = Instant::now() + timeout;
    // Defense in depth: the hostcall already rejected a non-token
    // method, non-token names, and delimiter-carrying values with
    // BadArgument (register_callout); this re-check keeps the
    // transport itself request-splitting-safe for any caller that
    // builds a CalloutRequest by hand.
    validate_request_head(&req.method, &req.headers)?;
    let uri: http::Uri = req
        .uri
        .parse()
        .map_err(|e| CalloutError::Failed(format!("callout URI does not parse: {e}")))?;
    let https = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => false,
        _ => {
            return Err(CalloutError::Failed(
                "callout URI must use the http:// or https:// scheme".to_string(),
            ))
        }
    };
    let host = uri
        .host()
        .ok_or_else(|| CalloutError::Failed("callout URI has no host".to_string()))?;
    let default_port = if https { 443 } else { 80 };
    let port = uri.port_u16().unwrap_or(default_port);
    let path_and_query = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    // ServerName wants the bare host (IPv6 brackets stripped for
    // dialing/TLS, un-bracketed for the Host header logic below).
    let dial_host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .to_string();

    // Resolve + SSRF-check every resolved IP at connect time, then
    // dial the first address that accepts (DNS rebinding mitigation:
    // the check runs against what we actually connect to).
    let addrs: Vec<std::net::SocketAddr> =
        std::net::ToSocketAddrs::to_socket_addrs(&(dial_host.as_str(), port))
            .map_err(|e| CalloutError::Failed(format!("DNS resolution failed: {e}")))?
            .collect();
    if ssrf.is_enabled() {
        for addr in &addrs {
            if let Err(reason) = ssrf.check(addr.ip()) {
                return Err(CalloutError::Failed(format!(
                    "SSRF egress filter rejected target: {reason}"
                )));
            }
        }
    }
    let mut last_err = String::from("no addresses resolved");
    let mut stream: Option<TcpStream> = None;
    for addr in &addrs {
        let connect_budget =
            CONNECT_TIMEOUT.min(deadline.saturating_duration_since(Instant::now()));
        if connect_budget.is_zero() {
            return Err(CalloutError::Timeout);
        }
        match TcpStream::connect_timeout(addr, connect_budget) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    let tcp = stream.ok_or_else(|| CalloutError::Failed(format!("connect failed: {last_err}")))?;
    tcp.set_nodelay(true).ok();
    // Per-write timeout clamped to the wall-clock remainder, like the
    // read path: a stalled target cannot outlive the callout deadline
    // one write at a time. A zero remainder means the deadline already
    // expired mid-connect — the exchange is a timeout, not an error.
    let write_budget = timeout.min(deadline.saturating_duration_since(Instant::now()));
    if write_budget.is_zero() {
        return Err(CalloutError::Timeout);
    }
    tcp.set_write_timeout(Some(write_budget)).ok();

    // Build the request head: the plugin's ordinary headers minus the
    // framing/hop-by-hop names the transport owns.
    let host_header = if port == default_port {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let mut head = format!("{} {} HTTP/1.1\r\n", req.method, path_and_query);
    head.push_str(&format!("host: {host_header}\r\n"));
    head.push_str(&format!("user-agent: {USER_AGENT}\r\n"));
    for (name, value) in &req.headers {
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "host"
                | "connection"
                | "keep-alive"
                | "transfer-encoding"
                | "upgrade"
                | "te"
                | "proxy-connection"
                | "content-length"
        ) {
            continue;
        }
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if !req.body.is_empty() {
        head.push_str(&format!("content-length: {}\r\n", req.body.len()));
    }
    head.push_str("connection: close\r\n\r\n");

    // The exchange: for https the same bytes ride a rustls stream over
    // the TcpStream (the registry fetcher's shape); for http the raw
    // TcpStream. One enum transport keeps the two paths identical
    // below the TLS wrapper (including the per-read timeout reset).
    let mut io = if https {
        let name = rustls::pki_types::ServerName::try_from(dial_host.clone()).map_err(|_| {
            CalloutError::Failed(format!(
                "host '{dial_host}' is not a usable TLS server name"
            ))
        })?;
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(super::source::webpki_root_store())
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let conn = rustls::ClientConnection::new(Arc::new(config), name)
            .map_err(|e| CalloutError::Failed(format!("TLS setup failed: {e}")))?;
        CalloutIo::Tls(rustls::StreamOwned::new(conn, tcp))
    } else {
        CalloutIo::Plain(tcp)
    };
    exchange(&mut io, &head, &req.body, deadline)
}

/// The established callout transport: plain TCP or rustls over TCP.
/// Implements Read/Write plus the per-read timeout reset the deadline
/// loop needs (rustls's `StreamOwned` does not forward setsockopt, but
/// its `sock` field is reachable). Boxed: the TLS variant is ~1 KiB
/// and the enum lives on the callout's (spawn_blocking) stack — the
/// indirection keeps the plain path from paying that footprint.
#[allow(clippy::large_enum_variant)]
enum CalloutIo {
    Plain(TcpStream),
    Tls(rustls::StreamOwned<rustls::ClientConnection, TcpStream>),
}

impl CalloutIo {
    fn set_read_timeout(&mut self, d: Duration) {
        match self {
            CalloutIo::Plain(s) => {
                s.set_read_timeout(Some(d)).ok();
            }
            CalloutIo::Tls(t) => {
                t.sock.set_read_timeout(Some(d)).ok();
            }
        }
    }
}

impl Read for CalloutIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            CalloutIo::Plain(s) => s.read(buf),
            CalloutIo::Tls(t) => t.read(buf),
        }
    }
}

impl Write for CalloutIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            CalloutIo::Plain(s) => s.write(buf),
            CalloutIo::Tls(t) => t.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            CalloutIo::Plain(s) => s.flush(),
            CalloutIo::Tls(t) => t.flush(),
        }
    }
}

/// Run one `Connection: close` exchange on an established transport:
/// write the head + body, read to EOF under the deadline, parse the
/// response. Reading to EOF keeps the framing simple (CL, chunked, or
/// close-delimited all complete); a peer that drops without a TLS
/// close_notify surfaces as UnexpectedEof/reset AFTER bytes arrived
/// and is treated as end-of-stream — the framing parse decides
/// whether the body is complete.
fn exchange(
    io: &mut CalloutIo,
    head: &str,
    body: &[u8],
    deadline: Instant,
) -> Result<CalloutResponse, CalloutError> {
    io.write_all(head.as_bytes())
        .map_err(|e| CalloutError::Failed(format!("callout request write failed: {e}")))?;
    if !body.is_empty() {
        io.write_all(body)
            .map_err(|e| CalloutError::Failed(format!("callout request write failed: {e}")))?;
    }
    io.flush()
        .map_err(|e| CalloutError::Failed(format!("callout request flush failed: {e}")))?;

    let mut raw = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if raw.len() > CALLOUT_HEAD_CAP_BYTES + CALLOUT_BODY_CAP_BYTES {
            return Err(CalloutError::Failed(format!(
                "callout response exceeds the {} MiB body cap",
                CALLOUT_BODY_CAP_BYTES / (1024 * 1024)
            )));
        }
        let remaining = deadline.checked_duration_since(Instant::now());
        let Some(remaining) = remaining else {
            return Err(CalloutError::Timeout);
        };
        // Per-read timeout clamped to the deadline remainder: a target
        // dripping one byte per read cannot outlive the callout.
        io.set_read_timeout(remaining);
        match io.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ) && !raw.is_empty() =>
            {
                break;
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Err(CalloutError::Timeout)
            }
            Err(e) => return Err(CalloutError::Failed(format!("callout read failed: {e}"))),
        }
    }
    parse_callout_response(&raw)
}

/// Parse a raw HTTP/1.1 callout response: status line, headers, body
/// framing (Content-Length, chunked, or read-to-EOF). ANY status is
/// returned (non-2xx is data); redirects are deliberately not
/// followed. Public for the integration tests, which pin the framing
/// edge cases as pure functions (the same posture as
/// `source::parse_response`).
pub fn parse_callout_response(raw: &[u8]) -> Result<CalloutResponse, CalloutError> {
    let Some(pos) = find_subslice(raw, b"\r\n\r\n") else {
        return Err(CalloutError::Failed(
            "callout response head was not terminated (no blank line)".to_string(),
        ));
    };
    if pos > CALLOUT_HEAD_CAP_BYTES {
        return Err(CalloutError::Failed(format!(
            "callout response head exceeded the {CALLOUT_HEAD_CAP_BYTES} byte cap"
        )));
    }
    let head = std::str::from_utf8(&raw[..pos]).map_err(|_| {
        CalloutError::Failed("callout response head is not valid UTF-8".to_string())
    })?;
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| CalloutError::Failed("unparseable callout status line".to_string()))?;
    let body = &raw[pos + 4..];
    let mut chunked = false;
    let mut content_length: Option<usize> = None;
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        } else if name == "content-length" {
            content_length = value.parse::<usize>().ok();
        }
        // Hop-by-hop and framing names never reach the plugin's map.
        if matches!(
            name.as_str(),
            "connection"
                | "keep-alive"
                | "transfer-encoding"
                | "upgrade"
                | "te"
                | "proxy-connection"
        ) {
            continue;
        }
        headers.push((name, value.to_string()));
    }
    let body = if chunked {
        decode_chunked(body, CALLOUT_BODY_CAP_BYTES).map_err(CalloutError::Failed)?
    } else if let Some(len) = content_length {
        // Cap before truncation so a short body with a hostile
        // over-cap Content-Length reports the cap, not a truncation.
        if len > CALLOUT_BODY_CAP_BYTES {
            return Err(CalloutError::Failed(format!(
                "Content-Length {len} exceeds the {} MiB callout body cap",
                CALLOUT_BODY_CAP_BYTES / (1024 * 1024)
            )));
        }
        if body.len() < len {
            return Err(CalloutError::Failed(format!(
                "truncated callout body: Content-Length says {len}, got {} bytes",
                body.len()
            )));
        }
        body[..len].to_vec()
    } else {
        // No framing header: Connection: close read-to-EOF is the body.
        body.to_vec()
    };
    if body.len() > CALLOUT_BODY_CAP_BYTES {
        return Err(CalloutError::Failed(format!(
            "callout body exceeds the {} MiB cap",
            CALLOUT_BODY_CAP_BYTES / (1024 * 1024)
        )));
    }
    Ok(CalloutResponse {
        status,
        headers,
        body,
    })
}

/// Minimal chunked transfer decoding with a caller-supplied cap (the
/// same hardened shape as `source::decode_chunked`: 1-16 ASCII hex
/// digits, checked arithmetic, per-chunk and aggregate caps).
pub fn decode_chunked(mut body: &[u8], cap: usize) -> Result<Vec<u8>, String> {
    let cap_err = || format!("chunked body exceeds the {cap} byte cap");
    let mut out = Vec::new();
    loop {
        let Some(line_end) = find_subslice(body, b"\r\n") else {
            return Err("chunked body: missing chunk size line".to_string());
        };
        let line = std::str::from_utf8(&body[..line_end])
            .map_err(|_| "chunked body: size line is not valid UTF-8".to_string())?;
        let size_str = line.split(';').next().unwrap_or("").trim();
        if size_str.is_empty()
            || size_str.len() > 16
            || !size_str.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(format!("chunked body: bad chunk size '{size_str}'"));
        }
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| format!("chunked body: bad chunk size '{size_str}'"))?;
        body = &body[line_end + 2..];
        if size == 0 {
            break; // trailers (if any) follow; ignored
        }
        if size > cap {
            return Err(cap_err());
        }
        let next_len = out.len().checked_add(size).ok_or_else(cap_err)?;
        if next_len > cap {
            return Err(cap_err());
        }
        let need = size
            .checked_add(2)
            .ok_or_else(|| "chunked body: truncated chunk".to_string())?;
        if body.len() < need {
            return Err("chunked body: truncated chunk".to_string());
        }
        out.extend_from_slice(&body[..size]);
        body = &body[need..];
    }
    Ok(out)
}

/// Find `needle` in `haystack` (the tiny helper `source` uses too).
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
