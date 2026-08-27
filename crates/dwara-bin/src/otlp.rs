//! OTLP trace export (#126): ships the DW-021 span tree (root `request`
//! span + `authn`/`authz`/`ratelimit`/`admission`/`upstream_pick`/
//! `upstream_attempt` phase spans) to an OTLP collector over http/protobuf.
//!
//! Compiled ONLY behind the default-off `otlp` cargo feature: the
//! opentelemetry stack is real megabytes on the musl release binary
//! against the DW-026 25MB budget, so the default build keeps
//! `DWARA_OTLP_ENDPOINT` reserved-but-inert (dwara-core::observability
//! documents the original decision; this module is the deferred half).
//!
//! Wiring shape (installed by `main` at startup, BEFORE the subscriber):
//!
//! 1. [`Otlp::from_env`] resolves `DWARA_OTLP_ENDPOINT`. Unset or empty =
//!    no-op (the tracing layer is `None`; one INFO line after init).
//! 2. The endpoint is a BASE url (OTLP convention, e.g.
//!    `http://collector:4318`); `traces_endpoint` appends `/v1/traces`
//!    (a programmatic endpoint is used verbatim by opentelemetry-otlp).
//! 3. [`Otlp::layer`] bridges the existing `tracing` spans into the
//!    provider via `tracing-opentelemetry` (the era-appropriate bridge —
//!    `opentelemetry-appender-tracing` is logs-only since 0.28). The
//!    spans themselves are unchanged: the same `tracing` callsites
//!    dwara-core already emits; the layer only observes them.
//! 4. A batch span processor (its own dedicated thread) exports finished
//!    spans; on SIGTERM/SIGINT `main` calls [`Otlp::shutdown`] inside
//!    the existing graceful-drain budget, bounded.
//!
//! ## The exporter HTTP client
//!
//! [`StdHttpClient`] is a std-only blocking HTTP/1.1 client implementing
//! `opentelemetry-http`'s `HttpClient` trait, handed to the exporter via
//! `with_http_client`. Neither of upstream's bundled clients fits this
//! binary: the reqwest clients add a second HTTP/TLS stack (hundreds of
//! KB against the size budget this feature exists to respect), and the
//! hyper client requires a tokio context that the SDK batch thread (a
//! plain OS thread driving the async exporter with
//! `futures_executor::block_on`) does not have — polling it there panics
//! on `tokio::time`. A blocking client is exactly right on that thread.
//! Plain `http://` endpoints only (the deployment shape is a
//! loopback/sidecar collector); upstream's own hyper default connector
//! ships no TLS either. An `https://` endpoint fails fast at startup.
//!
//! v1 scope, deliberately deferred: the client does NOT retry
//! retryable collector answers (429/503), and nothing behind it saves
//! the batch either — opentelemetry_sdk 0.32's batch span processors
//! (both variants) log a failed batch and DROP it, so a retryable
//! answer means those spans are lost. v1 accepts that loss knowingly:
//! traces are auxiliary and the collector is operator-configured (a
//! healthy sidecar does not answer 429/503 to its own gateway).
//! Retry-on-429/503 remains future work. Also deferred: non-UTF-8
//! exporter header values serialize as empty rather than erroring.

use std::io::{Read as _, Write as _};
use std::net::{TcpStream, ToSocketAddrs as _};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, Request, Response};
use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_http::{HttpClient, HttpError};
use opentelemetry_otlp::{Protocol, SpanExporter, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::trace::{SdkTracer, SdkTracerProvider};
use opentelemetry_sdk::Resource;
use tracing_opentelemetry::OpenTelemetryLayer;

/// Env var holding the OTLP collector base endpoint (see module docs).
pub(crate) const ENDPOINT_ENV: &str = "DWARA_OTLP_ENDPOINT";
/// Instrumentation-scope name stamped on every exported span.
const TRACER_NAME: &str = "dwara";
/// `service.name` resource attribute identifying the gateway to the
/// collector.
const SERVICE_NAME: &str = "dwara";
/// TOTAL budget for ONE export POST (the otel spec treats the exporter
/// timeout as one aggregate budget, not per-op): every connect attempt
/// and all socket I/O shrink against the remaining time. DNS
/// resolution is the one unbounded step (std `to_socket_addrs` takes
/// no timeout); the deadline bounds everything after it. Matches
/// opentelemetry-otlp's own 10s default. Batch-thread only; never
/// request-path.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(10);
/// Response-header read bound while locating the blank line (bytes).
const MAX_RESPONSE_HEAD_BYTES: usize = 64 * 1024;
/// Response-body read bound (collectors answer with a tiny or empty
/// protobuf body; anything larger is not going to be parsed usefully).
const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;

/// Startup wiring handle: the provider (when live) plus the deferred
/// status line. `main` builds this BEFORE the subscriber (the layer must
/// exist at init) and logs the status AFTER (so the line lands in the
/// JSON pipeline like every other startup log).
pub(crate) struct Otlp {
    provider: Option<SdkTracerProvider>,
    status: Status,
}

enum Status {
    /// Feature enabled, env var unset/empty: no-op, by design.
    NotConfigured,
    /// Feature enabled, provider live.
    Exporting { endpoint: String },
    /// Endpoint set but the pipeline could not be built: the gateway
    /// still runs (traces are auxiliary), with one ERROR naming why.
    InitFailed { endpoint: String, error: String },
}

impl Otlp {
    /// Resolve `DWARA_OTLP_ENDPOINT` and build the provider. Performs no
    /// network I/O (the client connects per export), so it is safe at the
    /// very top of `main`.
    pub(crate) fn from_env() -> Self {
        let endpoint = std::env::var(ENDPOINT_ENV).ok().filter(|v| !v.is_empty());
        match endpoint {
            Some(endpoint) => match build_provider(&endpoint) {
                Ok(provider) => Otlp {
                    provider: Some(provider),
                    status: Status::Exporting { endpoint },
                },
                Err(error) => Otlp {
                    provider: None,
                    status: Status::InitFailed {
                        endpoint,
                        error: error.to_string(),
                    },
                },
            },
            None => Otlp {
                provider: None,
                status: Status::NotConfigured,
            },
        }
    }

    /// The tracing bridge for the subscriber: `Some(layer)` when the
    /// provider is live, else `None` (an `Option<Layer>` composes as a
    /// no-op, so the unset-endpoint case needs no separate code path).
    pub(crate) fn layer<S>(&self) -> Option<OpenTelemetryLayer<S, SdkTracer>>
    where
        S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
    {
        self.provider
            .as_ref()
            .map(|p| tracing_opentelemetry::layer().with_tracer(p.tracer(TRACER_NAME)))
    }

    /// Emit the startup status line (called after subscriber init so it
    /// flows through the JSON pipeline). The endpoint value is an
    /// operator-supplied URL, not a secret.
    pub(crate) fn log_status(&self) {
        match &self.status {
            Status::NotConfigured => tracing::info!(
                code = "otlp_not_configured",
                "{ENDPOINT_ENV} is not set; OTLP trace export is off \
                 (the otlp cargo feature is enabled)"
            ),
            Status::Exporting { endpoint } => tracing::info!(
                code = "otlp_export_enabled",
                endpoint = %endpoint,
                protocol = "http/protobuf",
                "exporting traces over OTLP (base endpoint; /v1/traces appended)"
            ),
            Status::InitFailed { endpoint, error } => tracing::error!(
                code = "otlp_init_failed",
                endpoint = %endpoint,
                "OTLP trace export could not start ({error}); running without it"
            ),
        }
    }

    /// Flush + shut the exporter down, bounded: the SDK's own shutdown
    /// deadline is 5s; `bound` (the leftover graceful-drain budget)
    /// further caps the wait so a stuck collector cannot hold the exit.
    /// Runs off the async runtime (`spawn_blocking`): the flush blocks.
    pub(crate) async fn shutdown(&self, bound: Duration) {
        let Some(provider) = self.provider.as_ref() else {
            return;
        };
        tracing::info!(
            code = "otlp_shutdown",
            "flushing OTLP exporter before exit (bounded {}s)",
            bound.as_secs()
        );
        let provider = provider.clone();
        let flush = tokio::task::spawn_blocking(move || provider.shutdown());
        match tokio::time::timeout(bound, flush).await {
            Ok(Ok(Ok(()))) => {
                tracing::info!(code = "otlp_shutdown_flushed", "OTLP exporter drained");
            }
            Ok(Ok(Err(err))) => {
                tracing::warn!(code = "otlp_shutdown_error", "OTLP flush failed: {err}");
            }
            Ok(Err(err)) => {
                tracing::warn!(code = "otlp_shutdown_join_failed", "OTLP flush task: {err}");
            }
            Err(_) => {
                tracing::warn!(
                    code = "otlp_shutdown_timeout",
                    "OTLP flush exceeded the shutdown budget; exiting without it"
                );
            }
        }
    }
}

/// The OTLP signal path for traces (spec: exporter.md#endpoint-urls-for-
/// otlphttp).
const TRACE_PATH: &str = "/v1/traces";

/// Resolve the operator-supplied BASE endpoint into the full trace URL.
/// A programmatically-set endpoint is used VERBATIM by opentelemetry-otlp
/// (only `OTEL_EXPORTER_OTLP_*` env vars get the signal path appended),
/// so the path is appended here; an endpoint that already ends with it
/// (a full trace URL) is respected as-is.
fn traces_endpoint(base: &str) -> String {
    if base.ends_with(TRACE_PATH) {
        base.to_string()
    } else if base.ends_with('/') {
        format!("{base}v1/traces")
    } else {
        format!("{base}{TRACE_PATH}")
    }
}

/// Build the exporter + provider for one endpoint. Also installs the
/// global provider (context propagation callers read the global; our own
/// export path uses the typed handle directly).
fn build_provider(
    endpoint: &str,
) -> Result<SdkTracerProvider, Box<dyn std::error::Error + Send + Sync>> {
    // Fail fast on endpoints the built-in client cannot serve (http
    // only) instead of erroring on every export later.
    let uri: http::Uri = endpoint.parse()?;
    match uri.scheme_str() {
        Some("http") => {}
        Some("https") => {
            return Err(format!(
                "https OTLP endpoints are not supported by the built-in exporter \
                 client; use an http:// endpoint (e.g. a loopback/sidecar collector): \
                 {endpoint}"
            )
            .into());
        }
        other => {
            return Err(format!("OTLP endpoint must be http://, got {other:?}: {endpoint}").into());
        }
    }
    if uri.host().is_none() {
        return Err(format!("OTLP endpoint has no host: {endpoint}").into());
    }
    let exporter = SpanExporter::builder()
        .with_http()
        .with_http_client(StdHttpClient::new(EXPORT_TIMEOUT))
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(traces_endpoint(endpoint))
        .build()?;
    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(Resource::builder().with_service_name(SERVICE_NAME).build())
        .build();
    global::set_tracer_provider(provider.clone());
    Ok(provider)
}

/// A std-only blocking HTTP/1.1 client for the OTLP exporter (#126).
///
/// One `POST` per export on the SDK batch thread (blocking there is the
/// design — that thread exists to keep exports off the request path).
/// Bounded everywhere std allows: one TOTAL exchange deadline (each
/// connect attempt and all socket I/O shrink against the remaining
/// budget), header and body caps. Name resolution is the exception —
/// std resolution takes no timeout, so the deadline starts bounding at
/// connect. Plain `http://` only (see module docs); `https://` fails
/// with a pointed error rather than silently degrading.
#[derive(Debug)]
struct StdHttpClient {
    timeout: Duration,
}

/// Time left against the total export deadline; `Err` once the budget
/// is spent. Every timed op in [`StdHttpClient::post`] checks this
/// before running so no exchange can outlive `timeout` in aggregate
/// (name resolution is the untimed exception; std takes no timeout
/// there).
fn remaining(deadline: Instant) -> Result<Duration, HttpError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err("OTLP export exceeded its total timeout budget".into());
    }
    Ok(left)
}

/// Host string for std name resolution: `http::Uri::host()` keeps IPv6
/// literal brackets (`[::1]`), which `ToSocketAddrs` rejects — strip
/// them for RESOLUTION only (the Host header below keeps the bracketed
/// uri form verbatim, as the HTTP grammar requires).
fn resolve_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

impl StdHttpClient {
    fn new(timeout: Duration) -> Self {
        StdHttpClient { timeout }
    }

    /// Perform one exchange. Fully synchronous on purpose: it is called
    /// on the exporter's dedicated batch thread.
    fn post(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        // One anchor for the WHOLE exchange (otel's exporter timeout is
        // a total budget): every timed step below shrinks against the
        // time left here; name resolution is the untimed exception (std
        // takes no timeout there).
        let deadline = Instant::now() + self.timeout;
        let uri = request.uri().clone();
        let (parts, body) = request.into_parts();
        match uri.scheme_str() {
            Some("http") => {}
            Some("https") => {
                return Err(format!(
                    "https OTLP endpoints are not supported by the built-in exporter \
                     client; use an http:// endpoint (e.g. a loopback/sidecar collector): \
                     {uri}"
                )
                .into());
            }
            other => {
                return Err(format!("OTLP endpoint must be http://, got {other:?}: {uri}").into());
            }
        }
        let host = uri
            .host()
            .ok_or_else(|| format!("OTLP endpoint has no host: {uri}"))?;
        let port = uri.port_u16().unwrap_or(80);
        let authority = if port == 80 {
            host.to_string()
        } else {
            format!("{host}:{port}")
        };
        let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");

        // Resolve (the one unbounded step — std name resolution takes
        // no timeout; the budget bounds everything after it), then
        // connect; try every resolved address once (first successful
        // connect wins). Each attempt is capped by the remaining
        // budget, so a tail of unreachable addresses cannot stretch the
        // export past the deadline.
        let addrs: Vec<_> = (resolve_host(host), port)
            .to_socket_addrs()
            .map_err(|e| format!("OTLP endpoint {authority} does not resolve: {e}"))?
            .collect();
        let mut last_err = None;
        let mut connected = None;
        for addr in &addrs {
            let budget = remaining(deadline)?;
            match TcpStream::connect_timeout(addr, budget) {
                Ok(stream) => {
                    connected = Some(stream);
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        let mut stream = connected.ok_or_else(|| {
            match last_err {
                Some(e) => format!(
                    "OTLP collector {authority} connect failed across {} resolved \
                     address(es): {e}",
                    addrs.len()
                ),
                // Resolution succeeded but yielded nothing.
                None => format!("OTLP endpoint {authority} resolved to no address"),
            }
        })?;

        // Serialize the request: rebuild the head (Host, Content-Length,
        // Connection: close are ours; exporter headers pass through).
        // Write timeouts shrink against the deadline (std applies them
        // per send, so they are re-armed before each write).
        let mut head = format!("{} {} HTTP/1.1\r\n", parts.method, path);
        head.push_str(&format!("host: {authority}\r\n"));
        for (name, value) in parts.headers.iter() {
            if name == http::header::HOST || name == http::header::CONTENT_LENGTH {
                continue;
            }
            head.push_str(&format!("{name}: {}\r\n", value.to_str().unwrap_or("")));
        }
        head.push_str(&format!("content-length: {}\r\n", body.len()));
        head.push_str("connection: close\r\n\r\n");
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|e| format!("OTLP socket write timeout: {e}"))?;
        stream.write_all(head.as_bytes())?;
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|e| format!("OTLP socket write timeout: {e}"))?;
        stream.write_all(&body)?;
        stream.flush()?;

        let (status, headers, body) = read_response(&mut stream, deadline)?;
        let mut response = Response::builder().status(status);
        if let Some(h) = response.headers_mut() {
            *h = headers;
        }
        let response = response.body(body)?;
        if response.status().as_u16() >= 400 {
            return Err(format!(
                "OTLP collector answered {} for {} {}",
                response.status(),
                parts.method,
                path
            )
            .into());
        }
        Ok(response)
    }
}

/// Read once off `stream`, bounded by the remaining export budget: std
/// applies a socket read timeout per read call, so re-arming it here
/// keeps the TOTAL bounded — a slow-drip collector cannot stretch one
/// export past the deadline.
fn read_bounded(
    stream: &mut TcpStream,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<usize, HttpError> {
    stream
        .set_read_timeout(Some(remaining(deadline)?))
        .map_err(|e| format!("OTLP socket read timeout: {e}"))?;
    Ok(stream.read(buf)?)
}

/// Read one HTTP/1.1 response off `stream`: status line, headers, then
/// the body per Content-Length / chunked / close-delimited framing.
/// Every read is bounded against the export `deadline`.
fn read_response(
    stream: &mut TcpStream,
    deadline: Instant,
) -> Result<(http::StatusCode, HeaderMap, Bytes), HttpError> {
    // Head: read until CRLFCRLF, bounded.
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).into_owned();
            let body_start = buf.split_off(pos + 4);
            return read_body(stream, &head, body_start, deadline)
                .map(|(status, headers, body)| (status, headers, Bytes::from(body)));
        }
        if buf.len() > MAX_RESPONSE_HEAD_BYTES {
            return Err("OTLP response head exceeded 64 KiB".into());
        }
        let n = read_bounded(stream, &mut chunk, deadline)?;
        if n == 0 {
            return Err("OTLP connection closed before response head".into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Parse the head and read the body (already-buffered prefix carried in).
fn read_body(
    stream: &mut TcpStream,
    head: &str,
    mut body: Vec<u8>,
    deadline: Instant,
) -> Result<(http::StatusCode, HeaderMap, Vec<u8>), HttpError> {
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or("empty OTLP response")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("unparseable OTLP status line: {status_line:?}"))?;
    let mut headers = HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.trim().as_bytes()),
                value.trim().parse(),
            ) {
                headers.append(name, value);
            }
        }
    }
    let content_length = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    let chunked = headers
        .get(http::header::TRANSFER_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));

    if let Some(len) = content_length {
        if len > MAX_RESPONSE_BODY_BYTES {
            return Err(format!("OTLP response body of {len} bytes exceeds the cap").into());
        }
        while body.len() < len {
            let take = (len - body.len()).min(8192);
            let mut chunk = vec![0u8; take];
            let n = read_bounded(stream, &mut chunk, deadline)?;
            if n == 0 {
                return Err("OTLP connection closed mid-body".into());
            }
            body.extend_from_slice(&chunk[..n]);
        }
        body.truncate(len);
    } else if chunked {
        // Minimal chunked decode (collectors rarely chunk; the body only
        // feeds partial-success diagnostics).
        let mut decoded = Vec::new();
        let mut cursor = 0usize;
        loop {
            // Ensure a size line is buffered.
            loop {
                if body[cursor..].windows(2).any(|w| w == b"\r\n") {
                    break;
                }
                if body.len() > MAX_RESPONSE_BODY_BYTES {
                    return Err("OTLP chunked response exceeds the cap".into());
                }
                let mut chunk = [0u8; 1024];
                let n = read_bounded(stream, &mut chunk, deadline)?;
                if n == 0 {
                    return Err("OTLP connection closed mid-chunk".into());
                }
                body.extend_from_slice(&chunk[..n]);
            }
            let line_end = cursor
                + body[cursor..]
                    .windows(2)
                    .position(|w| w == b"\r\n")
                    .expect("checked above");
            let size_str = String::from_utf8_lossy(&body[cursor..line_end]);
            let size = usize::from_str_radix(size_str.trim().split(';').next().unwrap_or(""), 16)
                .map_err(|_| format!("bad chunk size {size_str:?}"))?;
            cursor = line_end + 2;
            if size == 0 {
                break; // terminal chunk; trailers ignored
            }
            // The size is collector-controlled: cap the DECLARATION
            // itself against the body budget before any use. An absurd
            // hex size near usize::MAX parses fine, and the old
            // unchecked sums (`decoded.len() + size`, `cursor + size +
            // 2`) could WRAP past the cap check and panic on the slice
            // below (start > end) — on the SDK batch thread, silently
            // stopping every later export. Oversized or wrap-shaped
            // declarations are a malformed response, an export error.
            if size > MAX_RESPONSE_BODY_BYTES {
                return Err(format!(
                    "OTLP chunked response declares a {size}-byte chunk, over the cap"
                )
                .into());
            }
            if decoded
                .len()
                .checked_add(size)
                .is_none_or(|total| total > MAX_RESPONSE_BODY_BYTES)
            {
                return Err("OTLP chunked response exceeds the cap".into());
            }
            let chunk_end = cursor
                .checked_add(size)
                .ok_or("OTLP chunked response size overflows")?;
            let framed_end = chunk_end
                .checked_add(2)
                .ok_or("OTLP chunked response size overflows")?;
            while body.len() < framed_end {
                let mut chunk = [0u8; 4096];
                let n = read_bounded(stream, &mut chunk, deadline)?;
                if n == 0 {
                    return Err("OTLP connection closed mid-chunk".into());
                }
                body.extend_from_slice(&chunk[..n]);
            }
            decoded.extend_from_slice(&body[cursor..chunk_end]);
            cursor = framed_end; // skip data + CRLF
        }
        body = decoded;
    } else {
        // Close-delimited: read to EOF, bounded.
        loop {
            if body.len() > MAX_RESPONSE_BODY_BYTES {
                return Err("OTLP response body exceeds the cap".into());
            }
            let mut chunk = [0u8; 4096];
            let n = read_bounded(stream, &mut chunk, deadline)?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
    }
    let status =
        http::StatusCode::from_u16(status).map_err(|e| format!("bad OTLP status {status}: {e}"))?;
    Ok((status, headers, body))
}

#[async_trait]
impl HttpClient for StdHttpClient {
    async fn send_bytes(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        // No await by design: the SDK polls this future on its dedicated
        // batch thread, where blocking is the intended behavior.
        self.post(request)
    }
}

#[cfg(test)]
mod tests {
    //! White-box in src (the AGENTS.md residual rule): `resolve_host` is
    //! a private helper of this module, unreachable from `tests/`. It is
    //! the FALLBACK coverage for IPv6-literal endpoints on hosts without
    //! IPv6 loopback, where the integration pin
    //! (`otlp_export.rs::ipv6_literal_endpoint_exports_to_loopback_sink`)
    //! skips itself.

    use super::resolve_host;

    #[test]
    fn ipv6_literals_lose_their_brackets_for_resolution_only() {
        assert_eq!(resolve_host("[::1]"), "::1");
        assert_eq!(resolve_host("[2001:db8::1]"), "2001:db8::1");
        // Anything that is not a bracketed literal passes through
        // verbatim (names, and hosts with at most one bracket).
        assert_eq!(resolve_host("collector"), "collector");
        assert_eq!(resolve_host("[::1"), "[::1");
        assert_eq!(resolve_host("::1]"), "::1]");
    }
}
