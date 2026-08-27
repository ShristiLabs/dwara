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
//! v1 scope, deliberately deferred: nothing behind the client saves a
//! batch the collector never accepted — opentelemetry_sdk 0.32's batch
//! span processors (both variants) log a failed batch and DROP it.
//! Since #133 the client itself retries retryable outcomes INSIDE one
//! export call: the transient status set (429/502/503/504) and
//! transport failures are retried up to [`MAX_EXPORT_ATTEMPTS`] total
//! attempts with exponential backoff, honoring a seconds-form
//! `Retry-After` when the collector sends one (the HTTP-date form is
//! deliberately uninterpreted and falls back to the computed backoff);
//! every attempt shares the ONE total export deadline, so retries
//! cannot stretch a batch past [`EXPORT_TIMEOUT`] any more than a slow
//! collector could. Consequence, accepted: a transport failure AFTER
//! the request was fully written may re-send a batch the collector
//! already ingested — at-least-once delivery with possible duplicate
//! spans, the standard telemetry-export trade (the alternative drops
//! committed batches on a response-read hiccup). Still deferred:
//! non-UTF-8 exporter header values serialize as empty rather than
//! erroring.

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
/// Total attempts for one export exchange when the collector answers
/// transiently (429/502/503/504) or the transport fails: the initial
/// attempt plus two retries. Bounded so a down collector cannot occupy
/// the batch thread indefinitely; every attempt shares the one total
/// export deadline (#133).
const MAX_EXPORT_ATTEMPTS: u32 = 3;
/// First backoff between export attempts, doubling per retry up to
/// [`RETRY_BACKOFF_CAP`]; a seconds-form `Retry-After` replaces the
/// computed value for that wait (still bounded by the total deadline).
const RETRY_BACKOFF_BASE: Duration = Duration::from_millis(100);
const RETRY_BACKOFF_CAP: Duration = Duration::from_secs(1);
/// Write granularity for request serialization (#133): the total
/// deadline is re-checked between chunks, so a peer making steady
/// minimal TCP-window progress inside one send — which would never
/// trip a single armed write timeout — still cannot stretch the write
/// past the export budget.
const WRITE_CHUNK: usize = 64 * 1024;
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
/// Bounded everywhere std allows: one TOTAL deadline shared by every
/// attempt of the export (#133 — transient 429/502/503/504 answers and
/// transport failures are retried up to [`MAX_EXPORT_ATTEMPTS`] times
/// with backoff honoring seconds-form `Retry-After`, each connect
/// attempt and all socket I/O shrinking against the remaining budget),
/// header and body caps, and deadline-re-checked chunked writes. Name
/// resolution is the exception — std resolution takes no timeout, so
/// the deadline starts bounding at connect. Plain `http://` only (see
/// module docs); `https://` fails with a pointed error rather than
/// silently degrading.
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
    /// Perform ONE exchange attempt against the shared `deadline`
    /// (otel's exporter timeout is a total budget covering every retry
    /// attempt of one export, #133). Fully synchronous on purpose: it
    /// is called on the exporter's dedicated batch thread. The
    /// [`Attempt`] classification decides whether the caller retries.
    fn post(
        &self,
        request: &Request<Bytes>,
        deadline: Instant,
    ) -> Result<Response<Bytes>, Attempt> {
        let uri = request.uri().clone();
        match uri.scheme_str() {
            Some("http") => {}
            Some("https") => {
                return Err(Attempt::Fatal(
                    format!(
                        "https OTLP endpoints are not supported by the built-in exporter \
                     client; use an http:// endpoint (e.g. a loopback/sidecar collector): \
                     {uri}"
                    )
                    .into(),
                ));
            }
            other => {
                return Err(Attempt::Fatal(
                    format!("OTLP endpoint must be http://, got {other:?}: {uri}").into(),
                ));
            }
        }
        let host = uri
            .host()
            .ok_or_else(|| Attempt::Fatal(format!("OTLP endpoint has no host: {uri}").into()))?;
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
            .map_err(|e| {
                Attempt::transport(format!("OTLP endpoint {authority} does not resolve: {e}"))
            })?
            .collect();
        let mut last_err = None;
        let mut connected = None;
        for addr in &addrs {
            let budget = match remaining(deadline) {
                Ok(b) => b,
                Err(e) => return Err(Attempt::Fatal(e)),
            };
            match TcpStream::connect_timeout(addr, budget) {
                Ok(stream) => {
                    connected = Some(stream);
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        let mut stream = connected.ok_or_else(|| {
            let error = match last_err {
                Some(e) => format!(
                    "OTLP collector {authority} connect failed across {} resolved \
                     address(es): {e}",
                    addrs.len()
                ),
                // Resolution succeeded but yielded nothing.
                None => format!("OTLP endpoint {authority} resolved to no address"),
            };
            Attempt::transport(error)
        })?;

        // Serialize the request: rebuild the head (Host, Content-Length,
        // Connection: close are ours; exporter headers pass through).
        // Writes go through the chunked deadline-checked loop (#133):
        // std applies a write timeout per send, and a dribbling peer
        // making steady minimal window progress would never trip one
        // armed timeout — the LOOP is what bounds the total.
        let body = request.body();
        let mut head = format!("{} {} HTTP/1.1\r\n", request.method(), path);
        head.push_str(&format!("host: {authority}\r\n"));
        for (name, value) in request.headers().iter() {
            if name == http::header::HOST || name == http::header::CONTENT_LENGTH {
                continue;
            }
            head.push_str(&format!("{name}: {}\r\n", value.to_str().unwrap_or("")));
        }
        head.push_str(&format!("content-length: {}\r\n", body.len()));
        head.push_str("connection: close\r\n\r\n");
        if let Err(e) = write_all_bounded(&mut stream, head.as_bytes(), deadline) {
            return Err(Attempt::from_transport(e, deadline));
        }
        if let Err(e) = write_all_bounded(&mut stream, body, deadline) {
            return Err(Attempt::from_transport(e, deadline));
        }
        stream
            .flush()
            .map_err(|e| Attempt::transport(format!("OTLP socket flush: {e}")))?;

        let (status, headers, body) = read_response(&mut stream, deadline)
            .map_err(|e| Attempt::from_transport(e, deadline))?;
        let mut response = Response::builder().status(status);
        if let Some(h) = response.headers_mut() {
            *h = headers;
        }
        let response = response
            .body(body)
            .map_err(|e| Attempt::Fatal(format!("OTLP response build: {e}").into()))?;
        if response.status().as_u16() >= 400 {
            let error: HttpError = format!(
                "OTLP collector answered {} for {} {}",
                response.status(),
                request.method(),
                path
            )
            .into();
            // The transient set (#133): the collector is out of quota
            // (429) or briefly unavailable (502/503/504) — the batch
            // was not accepted, and the SDK drops it on a plain error,
            // so the client retries. Every other 4xx/5xx (auth, size,
            // malformed) is fatal for this batch: retrying cannot fix
            // it.
            if is_retryable_status(response.status().as_u16()) {
                return Err(Attempt::Retry {
                    error,
                    retry_after: retry_after_seconds(response.headers()),
                });
            }
            return Err(Attempt::Fatal(error));
        }
        Ok(response)
    }

    /// Drive one export through bounded retries (#133). All attempts
    /// share the ONE total deadline (a flapping collector cannot
    /// stretch a batch past `EXPORT_TIMEOUT` any more than a slow one
    /// could); backoff is exponential from [`RETRY_BACKOFF_BASE`],
    /// replaced by a seconds-form `Retry-After` when the collector
    /// sent one, and any wait that would exhaust the remaining budget
    /// gives up immediately instead.
    fn send_with_retry(
        &self,
        request: &Request<Bytes>,
        deadline: Instant,
    ) -> Result<Response<Bytes>, HttpError> {
        let mut backoff = RETRY_BACKOFF_BASE;
        for attempt in 1..=MAX_EXPORT_ATTEMPTS {
            match self.post(request, deadline) {
                Ok(response) => return Ok(response),
                Err(Attempt::Fatal(error)) => return Err(error),
                Err(Attempt::Retry { error, retry_after }) => {
                    if attempt == MAX_EXPORT_ATTEMPTS {
                        tracing::warn!(
                            code = "otlp_export_retry_exhausted",
                            attempts = attempt,
                            "OTLP export still not accepted after {attempt} attempts; \
                             dropping this batch: {error}"
                        );
                        return Err(error);
                    }
                    let wait = match retry_after {
                        // Retry-After: 0 asks to re-send immediately;
                        // treat it as the computed backoff so a hostile
                        // zero cannot busy-loop the batch thread.
                        Some(ra) if !ra.is_zero() => ra,
                        _ => backoff,
                    };
                    backoff = backoff.saturating_mul(2).min(RETRY_BACKOFF_CAP);
                    let left = match remaining(deadline) {
                        Ok(left) => left,
                        Err(_) => {
                            tracing::warn!(
                                code = "otlp_export_retry_budget",
                                attempt,
                                "OTLP export budget spent before retry {attempt}: {error}"
                            );
                            return Err(error);
                        }
                    };
                    if wait >= left {
                        tracing::warn!(
                            code = "otlp_export_retry_budget",
                            attempt,
                            wait_ms = wait.as_millis() as u64,
                            "OTLP retry wait {wait:?} would exhaust the export budget; \
                             dropping this batch: {error}"
                        );
                        return Err(error);
                    }
                    tracing::warn!(
                        code = "otlp_export_retry",
                        attempt,
                        backoff_ms = wait.as_millis() as u64,
                        "OTLP export not accepted ({error}); retrying in {wait:?}"
                    );
                    std::thread::sleep(wait);
                }
            }
        }
        unreachable!("the final attempt returns inside the loop")
    }
}

/// One exchange attempt's outcome classification (#133).
enum Attempt {
    /// Retrying cannot help: unsupported endpoint, non-transient
    /// status, or the shared total budget is already spent.
    Fatal(HttpError),
    /// The batch was not accepted but might be next time: transient
    /// status (429/502/503/504) or transport failure, carrying the
    /// collector's seconds-form `Retry-After` when present.
    Retry {
        error: HttpError,
        retry_after: Option<Duration>,
    },
}

impl Attempt {
    /// Classify a transport-level failure: if the total deadline has
    /// passed, the failure IS the budget exhaustion (fatal — retrying
    /// would immediately fail the same way); otherwise it is a
    /// transport hiccup worth one bounded retry.
    fn from_transport(error: HttpError, deadline: Instant) -> Self {
        if Instant::now() >= deadline {
            Attempt::Fatal(error)
        } else {
            Attempt::Retry {
                error,
                retry_after: None,
            }
        }
    }

    fn transport(message: String) -> Self {
        Attempt::Retry {
            error: message.into(),
            retry_after: None,
        }
    }
}

/// The transient status set the client retries (#133): out of quota
/// (429, where Retry-After is defined) and briefly unavailable
/// (502/503/504). Deliberately narrow: 500 is a collector BUG a retry
/// cannot fix, and 4xx family answers are this batch's fault.
fn is_retryable_status(status: u16) -> bool {
    matches!(status, 429 | 502 | 503 | 504)
}

/// Seconds-form `Retry-After` only (#133): decimal seconds. The
/// HTTP-date form is deliberately uninterpreted (a sidecar collector
/// answers in seconds; parsing IMF-fixdate would buy nothing here) —
/// absent or unparseable falls back to the computed backoff.
fn retry_after_seconds(headers: &HeaderMap) -> Option<Duration> {
    let raw = headers.get(http::header::RETRY_AFTER)?.to_str().ok()?;
    let seconds: u64 = raw.trim().parse().ok()?;
    Some(Duration::from_secs(seconds))
}

/// Write the whole buffer in [`WRITE_CHUNK`]-bounded sends, re-arming
/// the write timeout and re-checking the total deadline between sends
/// (#133): a peer dribbling steady minimal TCP-window progress inside
/// one send would never trip a single armed timeout, so the loop is
/// what bounds the write against the export deadline.
fn write_all_bounded(
    stream: &mut TcpStream,
    mut buf: &[u8],
    deadline: Instant,
) -> Result<(), HttpError> {
    while !buf.is_empty() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|e| format!("OTLP socket write timeout: {e}"))?;
        let n = stream.write(&buf[..buf.len().min(WRITE_CHUNK)])?;
        if n == 0 {
            return Err("OTLP socket write made no progress".into());
        }
        buf = &buf[n..];
    }
    Ok(())
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
        // One TOTAL deadline spans every attempt of this export (#133):
        // otel's exporter timeout is an aggregate budget, and retries
        // sharing it means a flapping collector cannot stretch a batch
        // past EXPORT_TIMEOUT any more than a slow one could. No await
        // by design: the SDK polls this future on its dedicated batch
        // thread, where blocking is the intended behavior.
        let deadline = Instant::now() + self.timeout;
        self.send_with_retry(&request, deadline)
    }
}

#[cfg(test)]
mod tests {
    //! White-box in src (the AGENTS.md residual rule): the retry and
    //! write-bound machinery (`StdHttpClient::send_with_retry`,
    //! `write_all_bounded`, `Attempt`, the Retry-After parser) is
    //! private to this module and unreachable from `tests/`. The
    //! integration pin for the same behaviors through the REAL binary
    //! lives in `otlp_export.rs`; `resolve_host` here is the FALLBACK
    //! coverage for IPv6-literal endpoints on hosts without IPv6
    //! loopback, where that integration pin skips itself.

    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::{
        is_retryable_status, remaining, resolve_host, retry_after_seconds, StdHttpClient,
        MAX_EXPORT_ATTEMPTS,
    };

    fn post_request(port: u16, body: &[u8]) -> http::Request<bytes::Bytes> {
        http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("http://127.0.0.1:{port}/v1/traces"))
            .header("content-type", "application/x-protobuf")
            .body(bytes::Bytes::copy_from_slice(body))
            .unwrap()
    }

    /// A std-only scripted sink: connection N (0-based) is read as one
    /// full HTTP request (head + Content-Length body), then answered
    /// with `responses[N]` (later connections repeat the last script
    /// entry). Returns the port and a connection counter.
    fn scripted_sink(responses: &[&[u8]]) -> (u16, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("sink bind");
        let port = listener.local_addr().expect("sink addr").port();
        let conns = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&conns);
        let responses: Vec<Vec<u8>> = responses.iter().map(|r| r.to_vec()).collect();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let n = seen.fetch_add(1, Ordering::SeqCst);
                let Some(response) = responses.get(n).or_else(|| responses.last()).cloned() else {
                    continue;
                };
                std::thread::spawn(move || {
                    // Read exactly one request (head to CRLFCRLF, then
                    // the Content-Length body), bounded; the client
                    // waits for our answer, so draining to EOF would
                    // deadlock.
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .expect("sink read timeout");
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let head = String::from_utf8_lossy(&buf).into_owned();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.split_once(':'))
                        .filter(|(n, _)| n.trim().eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, v)| v.trim().parse().ok())
                        .unwrap_or(0);
                    let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
                    let mut have = buf.len() - head_end - 4;
                    while have < len {
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => have += n,
                        }
                    }
                    let _ = stream.write_all(&response);
                    let _ = stream.flush();
                });
            }
        });
        (port, conns)
    }

    const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    const SERVICE_UNAVAILABLE: &[u8] =
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
    const TOO_MANY_REQUESTS: &[u8] =
        b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\nContent-Length: 0\r\n\r\n";
    const NOT_FOUND: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

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

    #[test]
    fn the_transient_status_set_is_exactly_quota_and_brief_unavailability() {
        for status in [429u16, 502, 503, 504] {
            assert!(is_retryable_status(status), "{status} must be retryable");
        }
        // 500 is a collector bug; 4xx family answers are this batch's
        // fault; 3xx/2xx never reach the check.
        for status in [400u16, 401, 404, 413, 500, 501, 505] {
            assert!(
                !is_retryable_status(status),
                "{status} must not be retryable"
            );
        }
    }

    #[test]
    fn retry_after_parses_only_the_seconds_form() {
        let mut headers = http::HeaderMap::new();
        headers.insert("retry-after", "5".parse().unwrap());
        assert_eq!(retry_after_seconds(&headers), Some(Duration::from_secs(5)));
        headers.insert("retry-after", "0".parse().unwrap());
        assert_eq!(retry_after_seconds(&headers), Some(Duration::ZERO));
        // The HTTP-date form is deliberately uninterpreted.
        headers.insert(
            "retry-after",
            "Sun, 06 Nov 1994 08:49:37 GMT".parse().unwrap(),
        );
        assert_eq!(retry_after_seconds(&headers), None);
        headers.remove("retry-after");
        assert_eq!(retry_after_seconds(&headers), None);
    }

    #[test]
    fn transient_503_is_retried_within_one_export_until_accepted() {
        let (port, conns) = scripted_sink(&[SERVICE_UNAVAILABLE, OK]);
        let client = StdHttpClient::new(Duration::from_secs(2));
        let request = post_request(port, b"batch");
        client
            .send_with_retry(&request, Instant::now() + Duration::from_secs(2))
            .expect("the second attempt is accepted");
        assert_eq!(conns.load(Ordering::SeqCst), 2, "exactly one retry");
    }

    #[test]
    fn persistent_429_exhausts_the_bounded_attempts_and_errors() {
        let (port, conns) = scripted_sink(&[TOO_MANY_REQUESTS]);
        let client = StdHttpClient::new(Duration::from_secs(2));
        let request = post_request(port, b"batch");
        let error = client
            .send_with_retry(&request, Instant::now() + Duration::from_secs(2))
            .expect_err("persistent 429 must fail the export");
        assert!(
            error.to_string().contains("429"),
            "the error names the collector answer: {error}"
        );
        assert_eq!(
            conns.load(Ordering::SeqCst),
            MAX_EXPORT_ATTEMPTS as usize,
            "attempts are bounded"
        );
    }

    #[test]
    fn non_transient_4xx_is_not_retried() {
        let (port, conns) = scripted_sink(&[NOT_FOUND, OK]);
        let client = StdHttpClient::new(Duration::from_secs(2));
        let request = post_request(port, b"batch");
        let error = client
            .send_with_retry(&request, Instant::now() + Duration::from_secs(2))
            .expect_err("a 404 must fail the export");
        assert!(
            error.to_string().contains("404"),
            "the error names the collector answer: {error}"
        );
        assert_eq!(conns.load(Ordering::SeqCst), 1, "no retry for 4xx");
    }

    #[test]
    fn transport_failure_is_retried_and_stays_bounded() {
        // A reserved-then-dropped port: every connect is refused
        // instantly, so MAX attempts with 100ms + 200ms backoff must
        // complete far inside a second (the pin is the bound, not the
        // refusal itself).
        let listener = TcpListener::bind("127.0.0.1:0").expect("reserve port");
        let port = listener.local_addr().expect("port").port();
        drop(listener);
        let client = StdHttpClient::new(Duration::from_secs(2));
        let request = post_request(port, b"batch");
        let started = Instant::now();
        let error = client
            .send_with_retry(&request, Instant::now() + Duration::from_secs(2))
            .expect_err("refused connects must fail the export");
        assert!(
            error.to_string().contains("connect failed"),
            "the error names the transport failure: {error}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "bounded attempts: {}s",
            started.elapsed().as_secs_f32()
        );
    }

    /// The dribble pin (#133): a peer that accepts the head, then
    /// drains the body one byte every 100ms with a strangled receive
    /// window makes steady minimal write progress — exactly the shape
    /// that never trips a single armed write timeout. The chunked
    /// deadline-rechecking write loop must bound the exchange by the
    /// TOTAL deadline (~400ms here), not by the minutes a full
    /// 256 KiB dribble would take.
    #[test]
    fn write_dribble_is_bounded_by_the_total_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("dribble bind");
        let port = listener.local_addr().expect("port").port();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("dribble accept");
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            // Read the head fully, then dribble the body.
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut one = [0u8; 1];
            while Instant::now() < deadline {
                match stream.read(&mut one) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => std::thread::sleep(Duration::from_millis(100)),
                }
            }
            // Never answer: the client must have given up on its own.
        });

        let client = StdHttpClient::new(Duration::from_millis(400));
        // 4 MiB dwarfs any default loopback buffering, so once the
        // dribble begins the client's sends stall awaiting window
        // openings — steady minimal progress that a single armed write
        // timeout would ride forever.
        let body = vec![0u8; 4 * 1024 * 1024];
        let request = post_request(port, &body);
        let started = Instant::now();
        let result = client.send_with_retry(&request, Instant::now() + Duration::from_millis(400));
        let elapsed = started.elapsed();
        assert!(result.is_err(), "the dribble must end in an export error");
        assert!(
            elapsed >= Duration::from_millis(350),
            "the client used its budget: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "the write loop bounded the dribble by the deadline, not the \
             byte cadence: {elapsed:?}"
        );
        // The shared deadline helper itself must now be spent.
        assert!(remaining(Instant::now()).is_err());
    }

    #[test]
    fn retry_after_seconds_are_honored_not_just_parsed() {
        // The collector demands a 1s pause; the computed backoff for
        // the first retry would be 100ms. Elapsed must land near the
        // DEMANDED wait (well above any computed-backoff path), bounded
        // generously for CI scheduling noise.
        let too_many_with_wait: &[u8] =
            b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\nContent-Length: 0\r\n\r\n";
        let (port, _conns) = scripted_sink(&[too_many_with_wait, OK]);
        let client = StdHttpClient::new(Duration::from_secs(5));
        let request = post_request(port, b"batch");
        let started = Instant::now();
        client
            .send_with_retry(&request, Instant::now() + Duration::from_secs(5))
            .expect("the second attempt is accepted");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(900),
            "Retry-After: 1 must gate the retry, not the 100ms computed \
             backoff: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "the honored wait stays bounded: {elapsed:?}"
        );
    }

    #[test]
    fn a_retry_that_would_exhaust_the_budget_gives_up_after_one_attempt() {
        // The collector burns ~380ms of a 400ms budget before answering
        // 503; whatever budget remains is smaller than any wait, so the
        // client must drop the batch WITHOUT a second connection. The
        // connection count is the timing-robust discriminator: a client
        // that tried to retry would open one.
        let listener = TcpListener::bind("127.0.0.1:0").expect("slow sink bind");
        let port = listener.local_addr().expect("port").port();
        let conns = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&conns);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                seen.fetch_add(1, Ordering::SeqCst);
                std::thread::spawn(move || {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .expect("slow sink read timeout");
                    // Read one full request (head + body), slowly.
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let head = String::from_utf8_lossy(&buf).into_owned();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.split_once(':'))
                        .filter(|(n, _)| n.trim().eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, v)| v.trim().parse().ok())
                        .unwrap_or(0);
                    let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
                    let mut have = buf.len() - head_end - 4;
                    while have < len {
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => have += n,
                        }
                    }
                    // Burn most of the client's budget, then refuse.
                    std::thread::sleep(Duration::from_millis(380));
                    let _ = stream.write_all(SERVICE_UNAVAILABLE);
                    let _ = stream.flush();
                });
            }
        });

        let client = StdHttpClient::new(Duration::from_millis(400));
        let request = post_request(port, b"batch");
        let error = client
            .send_with_retry(&request, Instant::now() + Duration::from_millis(400))
            .expect_err("a budget-exhausting 503 must fail the export");
        assert!(
            error.to_string().contains("503"),
            "the error names the collector answer: {error}"
        );
        assert_eq!(
            conns.load(Ordering::SeqCst),
            1,
            "no retry may be attempted when the wait would exceed the budget"
        );
    }
}
