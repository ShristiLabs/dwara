//! Webhook delivery (DW-044, feature analysis section 5 "Platform"):
//! drains the event bus and POSTs each event to the configured targets.
//!
//! # Envelope (stable shape)
//!
//! One JSON object per delivery, serialized once per event and shared by
//! every matching target:
//!
//! ```json
//! {
//!   "id": "evt-18f3c2a1b9d0-00000a",
//!   "kind": "breaker_opened",
//!   "timestamp": "2026-08-27T09:00:00.123Z",
//!   "gateway": "dwara-8213-18f3c2910b07",
//!   "payload": { "upstream": "billing", "detail": "error_ratio" }
//! }
//! ```
//!
//! `id` is process-unique and monotonic (event correlation, not
//! ordering across processes), `kind` is the closed
//! [`EventKind`] spelling, `timestamp` is RFC 3339 UTC
//! with millisecond precision, `gateway` identifies the emitting
//! process, and `payload` carries only the bounded labels and numbers
//! of [`EventPayload`] — no request-derived data,
//! no secrets. The envelope is byte-capped at [`MAX_ENVELOPE_BYTES`]
//! (an over-cap envelope — only possible via absurd config label
//! lengths — is dropped and counted, never truncated: a receiver should
//! never see a malformed event).
//!
//! # Delivery contract
//!
//! One delivery = one target + one event. Every attempt of a delivery
//! (the first POST plus its retries) shares ONE total budget of
//! `timeout_ms`, the OTLP exporter's model (#133): a flapping or hung
//! target cannot stretch a delivery past the budget any more than a
//! slow one could, which is the whole failure-isolation guarantee. The
//! retry shape is equally borrowed from that client:
//!
//! - retryable outcomes: transport failures and the transient status
//!   set 429/502/503/504. A seconds-form `Retry-After` replaces the
//!   computed backoff for that wait (the HTTP-date form is deliberately
//!   uninterpreted); `Retry-After: 0` falls back to the computed
//!   backoff so a hostile zero cannot busy-loop.
//! - every other non-2xx answer (4xx, 500, 3xx — redirects are NOT
//!   followed) fails the delivery immediately: retrying cannot fix an
//!   answer that is this delivery's fault.
//! - backoff is exponential from `backoff_base_ms`, doubling up to
//!   `backoff_cap_ms`; a wait that would exhaust the remaining budget
//!   gives up instead of sleeping past it.
//!
//! Outcomes are counted in `dwara_webhook_events_total{kind,outcome}`:
//! `delivered` (2xx on some attempt), `failed` (retries exhausted,
//! non-transient answer, or budget spent — the target was tried and did
//! not take it), and `dropped` (never tried: envelope over the byte
//! cap, or the delivery-concurrency semaphore saturated). Queue drops
//! at EMIT time are the separate `dwara_events_dropped_total` gauge
//! (see the parent module). Cardinality is bounded: `kind` is the
//! closed event set, `outcome` is these three spellings.
//!
//! # Isolation from the dataplane
//!
//! [`run_deliverer`] is one background task; each delivery is a further
//! task, and at most [`MAX_CONCURRENT_DELIVERIES`] run at once
//! (a saturated semaphore drops-and-counts rather than queueing — an
//! unbounded delivery queue would just move the unbounded buffer from
//! the bus to the deliverer). The emit path (`try_send` + atomics) is
//! unaffected by everything here: a dead target costs its semaphore
//! slot for at most `timeout_ms`, a hung one exactly the same.
//!
//! # Egress posture
//!
//! Webhook URLs are OPERATOR configuration, exactly like upstream
//! endpoints and JWKS URLs: the gateway dials what its config names, so
//! there is no SSRF boundary to enforce against the config author.
//! There is deliberately no private-address egress filter in v1 (an
//! internal alerting listener on 127.0.0.1 or 10/8 is a normal shape);
//! `https://` targets verify against the public webpki root set with no
//! `trusted_ca_file` override (v1 scope — the alerting fan-out is
//! public SaaS), and HTTP/1.1 only. Header values may carry secrets
//! via `${...}` references (DW-045): they are resolved at compile time,
//! held only by the compiled target, and NEVER logged (delivery logs
//! name the URL and the outcome, never the headers).
//!
//! # Target lifecycle
//!
//! Targets are compiled per config generation (secret references
//! re-resolved on every publish) and pushed to the deliverer over a
//! `tokio::sync::watch` channel by the dataplane's refresh — a config
//! change applies to the NEXT event, with no deliverer restart.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};

use crate::config::credentials::resolve_configured_secret;
use crate::config::Webhook;
use crate::observability::Observability;

use super::{Event, EventKind, EventPayload};

/// Hard cap on one serialized envelope (bytes). Payload fields are
/// bounded config labels, so this only binds absurd label lengths; an
/// over-cap envelope is dropped and counted, never sent truncated.
pub const MAX_ENVELOPE_BYTES: usize = 16 * 1024;
/// At most this many deliveries in flight across every target (per
/// gateway process). Over it: drop and count — a stuck fleet of
/// targets must not accumulate an unbounded task pile.
pub const MAX_CONCURRENT_DELIVERIES: usize = 32;
/// Response-head read bound while locating the blank line (bytes); the
/// body is never read (only the status line and `Retry-After` matter).
const MAX_RESPONSE_HEAD_BYTES: usize = 8 * 1024;
/// `User-Agent` stamped on every delivery.
const USER_AGENT: &str = "dwara-webhook";

/// One compiled `gateway.webhooks[]` entry (DW-044): the URL decomposed
/// for dialing, the event-kind filter, and the RESOLVED header set.
/// Built per config generation by [`WebhookTarget::compile`]; held by
/// the deliverer via the watch channel. Header values may be secret
/// material (a `${...}` reference): they are never logged and never
/// appear in `Debug` (the impl prints names only).
#[derive(Clone)]
pub struct WebhookTarget {
    url: String,
    /// Host as it appears in an HTTP `Host` header (IPv6 literals stay
    /// bracketed, as the URI grammar requires).
    host_header: String,
    /// Host for dialing/SNI (IPv6 brackets stripped).
    dial_host: String,
    port: u16,
    tls: bool,
    path_and_query: String,
    events: Vec<EventKind>,
    headers: Vec<(String, String)>,
    timeout: Duration,
    attempts: u32,
    backoff_base: Duration,
    backoff_cap: Duration,
}

impl std::fmt::Debug for WebhookTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Header VALUES may be secrets; names only.
        f.debug_struct("WebhookTarget")
            .field("url", &self.url)
            .field(
                "events",
                &self.events.iter().map(|k| k.as_str()).collect::<Vec<_>>(),
            )
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(n, _)| n.as_str())
                    .collect::<Vec<_>>(),
            )
            .field("timeout_ms", &(self.timeout.as_millis() as u64))
            .field("attempts", &self.attempts)
            .finish_non_exhaustive()
    }
}

impl WebhookTarget {
    /// Compile one config entry: decompose the URL, resolve every
    /// header value (literals pass through; `${...}` references resolve
    /// NOW — the DW-045 compile-time contract), and resolve the retry
    /// knobs to their defaults. Fails with a message safe for logs
    /// (names the URL or the reference, never a resolved value).
    /// Validation (`snapshot::validate`) has already checked the shape;
    /// this is the compile-time re-resolution whose failure skips the
    /// target loudly (the microsecond-race backstop, same as the
    /// authenticator's credential resolution).
    pub fn compile(cfg: &Webhook) -> Result<Self, String> {
        let mut target = Self::compile_endpoint(
            &cfg.url,
            &cfg.headers,
            cfg.timeout_ms,
            cfg.max_attempts,
            cfg.backoff_base_ms,
            cfg.backoff_cap_ms,
        )?;
        let mut events = Vec::with_capacity(cfg.events.len());
        for e in &cfg.events {
            let Some(kind) = EventKind::from_config(e) else {
                return Err(format!(
                    "webhook url '{}' lists unknown event kind '{e}'",
                    cfg.url
                ));
            };
            events.push(kind);
        }
        target.events = events;
        Ok(target)
    }

    /// Compile the endpoint half of a target — URL decomposition,
    /// secret-reference header resolution (with the header-value
    /// legality re-check), and the retry knobs — without any event-kind
    /// filter. The shared bottom of [`WebhookTarget::compile`] and the
    /// DW-121 record-stream sink's compilation
    /// (`events::stream::WebhookRecordSink`), which delivers to an
    /// endpoint with no kind filter at all. Same failure contract:
    /// log-safe messages, fail closed, never a resolved value in the
    /// error.
    pub(super) fn compile_endpoint(
        url: &str,
        headers: &std::collections::BTreeMap<String, String>,
        timeout_ms: u64,
        max_attempts: u32,
        backoff_base_ms: u64,
        backoff_cap_ms: u64,
    ) -> Result<Self, String> {
        let uri: hyper::Uri = url
            .parse()
            .map_err(|e| format!("webhook url '{url}' does not parse: {e}"))?;
        let tls = match uri.scheme_str() {
            Some("http") => false,
            Some("https") => true,
            other => {
                return Err(format!(
                    "webhook url '{url}' must be http:// or https://, got {other:?}"
                ))
            }
        };
        let host = uri
            .host()
            .ok_or_else(|| format!("webhook url '{url}' has no host"))?
            .to_string();
        let default_port = if tls { 443 } else { 80 };
        let port = uri.port_u16().unwrap_or(default_port);
        let host_header = if port == default_port {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        let dial_host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(&host)
            .to_string();
        let path_and_query = uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let mut compiled_headers = Vec::with_capacity(headers.len());
        for (name, value) in headers {
            let resolved = resolve_configured_secret(value)
                .map_err(|e| format!("webhook url '{url}' header '{name}': {e}"))?;
            // The request head is serialized by hand, so the resolved
            // bytes must be a legal single header value. Validation
            // checked this against the compile-time resolution; a secret
            // file that changed in between could otherwise smuggle CR/LF
            // into the head (request splitting). Fail closed, skip the
            // target — the error names the header, never the value.
            if hyper::header::HeaderValue::from_str(&resolved).is_err() {
                return Err(format!(
                    "webhook url '{url}' header '{name}': the resolved value contains \
                     characters that cannot appear in an HTTP header value",
                ));
            }
            compiled_headers.push((name.clone(), resolved));
        }
        Ok(WebhookTarget {
            url: url.to_string(),
            host_header,
            dial_host,
            port,
            tls,
            path_and_query,
            events: Vec::new(),
            headers: compiled_headers,
            timeout: Duration::from_millis(timeout_ms),
            attempts: max_attempts,
            backoff_base: Duration::from_millis(backoff_base_ms),
            backoff_cap: Duration::from_millis(backoff_cap_ms),
        })
    }

    /// The configured URL (operator config, safe to log).
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Whether this target receives `kind`.
    pub fn wants(&self, kind: EventKind) -> bool {
        self.events.contains(&kind)
    }
}

/// The stable wire envelope (see the module docs for the shape).
#[derive(serde::Serialize)]
struct Envelope<'a> {
    id: &'a str,
    kind: &'a str,
    timestamp: String,
    gateway: &'a str,
    payload: &'a EventPayload,
}

/// Serialize one event into its envelope JSON.
pub fn envelope_json(event: &Event) -> String {
    let envelope = Envelope {
        id: &event.id,
        kind: event.kind.as_str(),
        timestamp: rfc3339_ms(event.timestamp_ms),
        gateway: &event.gateway,
        payload: &event.payload,
    };
    serde_json::to_string(&envelope).expect("envelope fields serialize (strings and numbers)")
}

/// RFC 3339 UTC with millisecond precision from Unix milliseconds
/// (`civil_from_days`, the standard fully-specified conversion — no
/// datetime dependency, stable across toolchains like the FNV ring
/// hash). UTC by definition of the `Z` suffix.
pub fn rfc3339_ms(unix_ms: u64) -> String {
    let secs = (unix_ms / 1000) as i64;
    let millis = unix_ms % 1000;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        sod / 3_600,
        (sod % 3_600) / 60,
        sod % 60
    )
}

/// Days since 1970-01-01 to (year, month, day) — Howard Hinnant's
/// `civil_from_days`, arithmetic on `i64` so pre-1970 inputs (never
/// produced by the wall clock, but reachable in tests) stay correct.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// One exchange attempt's outcome classification (the OTLP client's
/// triage, #133, verbatim in shape).
enum Attempt {
    /// 2xx: accepted.
    Accepted,
    /// Not accepted, but a bounded retry may help: transient status or
    /// transport failure, carrying the target's seconds-form
    /// `Retry-After` when it sent one.
    Retry {
        retry_after: Option<Duration>,
        error: String,
    },
    /// Retrying cannot help (unsupported endpoint, non-transient
    /// status, budget spent).
    Fatal(String),
}

/// Whether a status is in the transient retry set (429 quota, 502/503/
/// 504 brief unavailability). Deliberately narrow, like the OTLP set:
/// 500 is a receiver bug, other 4xx are this delivery's fault.
fn is_retryable_status(status: u16) -> bool {
    matches!(status, 429 | 502 | 503 | 504)
}

/// Seconds-form `Retry-After` only (the HTTP-date form is deliberately
/// uninterpreted; absent or unparseable falls back to the computed
/// backoff).
fn retry_after_seconds(head: &str) -> Option<Duration> {
    let value = head.lines().find_map(|l| {
        let (name, value) = l.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("retry-after")
            .then(|| value.trim().to_string())
    })?;
    let seconds: u64 = value.parse().ok()?;
    Some(Duration::from_secs(seconds))
}

/// Object-safe alias over the two transports a delivery can run on
/// (`Box<dyn AsyncRead + AsyncWrite>` is not a legal trait object; an
/// alias trait with a blanket impl is the standard shape).
trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T> Io for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// Time left against the delivery deadline; `None` once spent.
fn remaining(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
}

/// Perform ONE exchange attempt against the shared `deadline`: dial
/// (DNS + TCP + optional TLS), write the request, read the response
/// head. The whole attempt runs inside one `tokio::time::timeout` of
/// the remaining budget, so no phase of it — resolution included — can
/// outlive the delivery's total. `content_type` and `user_agent` name
/// the body the caller is POSTing (the alert envelope and the DW-121
/// record batch use different media types and agents; the transport
/// shape is shared).
async fn post_once(
    target: &WebhookTarget,
    body: &[u8],
    deadline: Instant,
    content_type: &str,
    user_agent: &str,
) -> Attempt {
    let Some(budget) = remaining(deadline) else {
        return Attempt::Fatal("delivery budget spent before the attempt".to_string());
    };
    let attempt =
        async {
            let stream = tokio::net::TcpStream::connect((target.dial_host.as_str(), target.port))
                .await
                .map_err(|e| format!("webhook {} connect failed: {e}", target.host_header))?;
            let mut io: Box<dyn Io> = if target.tls {
                let name = rustls::pki_types::ServerName::try_from(target.dial_host.clone())
                    .map_err(|_| {
                        format!(
                            "webhook host '{}' is not a usable TLS server name",
                            target.dial_host
                        )
                    })?;
                let connector = tokio_rustls::TlsConnector::from(webhook_tls_config());
                let tls = connector.connect(name, stream).await.map_err(|e| {
                    format!("webhook {} TLS handshake failed: {e}", target.host_header)
                })?;
                Box::new(tls)
            } else {
                Box::new(stream)
            };
            // Serialize the request head. Ours: request line, Host,
            // Content-Length, Connection: close, User-Agent, Content-Type —
            // the configured headers ride along and may override
            // Content-Type/User-Agent by appearing later.
            let mut head = format!(
                "POST {} HTTP/1.1\r\nhost: {}\r\ncontent-length: {}\r\n\
             connection: close\r\nuser-agent: {user_agent}\r\n\
             content-type: {content_type}\r\n",
                target.path_and_query,
                target.host_header,
                body.len()
            );
            for (name, value) in &target.headers {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
            head.push_str("\r\n");
            io.write_all(head.as_bytes())
                .await
                .map_err(|e| format!("webhook {} write failed: {e}", target.host_header))?;
            io.write_all(body)
                .await
                .map_err(|e| format!("webhook {} write failed: {e}", target.host_header))?;
            io.flush()
                .await
                .map_err(|e| format!("webhook {} flush failed: {e}", target.host_header))?;
            // Read the head only: status line + headers up to the blank
            // line, bounded. The body is never read (the receiver closes).
            let mut buf = Vec::with_capacity(512);
            let mut chunk = [0u8; 1024];
            loop {
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..pos]).into_owned();
                    let status = head
                        .split_whitespace()
                        .nth(1)
                        .and_then(|s| s.parse::<u16>().ok());
                    let status = match status {
                        Some(s) => s,
                        None => {
                            return Err(format!(
                                "webhook {} answered an unparseable status line",
                                target.host_header
                            ))
                        }
                    };
                    return Ok((status, head));
                }
                if buf.len() > MAX_RESPONSE_HEAD_BYTES {
                    return Err(format!(
                        "webhook {} response head exceeded the {} byte cap",
                        target.host_header, MAX_RESPONSE_HEAD_BYTES
                    ));
                }
                let n = io.read(&mut chunk).await.map_err(|e| {
                    format!("webhook {} response read failed: {e}", target.host_header)
                })?;
                if n == 0 {
                    return Err(format!(
                        "webhook {} closed the connection before answering",
                        target.host_header
                    ));
                }
                buf.extend_from_slice(&chunk[..n]);
            }
        };
    match tokio::time::timeout(budget, attempt).await {
        // Map the inner Result<(status, head), String> into an Attempt.
        Ok(Ok((status, head))) => {
            if (200..300).contains(&status) {
                Attempt::Accepted
            } else if is_retryable_status(status) {
                Attempt::Retry {
                    retry_after: retry_after_seconds(&head),
                    error: format!("webhook {} answered {status}", target.host_header),
                }
            } else {
                Attempt::Fatal(format!(
                    "webhook {} answered {status} (not retryable)",
                    target.host_header
                ))
            }
        }
        Ok(Err(error)) => Attempt::Retry {
            retry_after: None,
            error,
        },
        Err(_) => Attempt::Fatal(format!(
            "webhook {} delivery exceeded its timeout budget",
            target.host_header
        )),
    }
}

/// The TLS client config for `https://` webhook targets: public webpki
/// roots, no client certificate, HTTP/1.1 ALPN. Built once per attempt
/// (a rustls `ClientConfig` is cheap to build and the alerting rate is
/// trivial; see the module docs for the no-`trusted_ca_file` scope).
fn webhook_tls_config() -> Arc<rustls::ClientConfig> {
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(webpki_root_store())
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

/// Public webpki root store for webhook TLS verification. Local
/// re-statement of `security::tls::webpki_root_store` (the events
/// domain must not import the security domain; the roots are the same
/// public set the pooled connector defaults to).
fn webpki_root_store() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// Terminal outcome of one body's retry cycle through the shared
/// delivery engine. The engine itself counts nothing and logs only
/// debug-level retry traces — each CALLER owns the outcome logging and
/// the metric family it reports into (alert events:
/// `dwara_webhook_events_total`; DW-121 record batches: the stream
/// families).
pub(super) enum DeliveryEnd {
    /// A 2xx answer arrived on the `attempts`-th attempt.
    Delivered { attempts: u32 },
    /// Retries exhausted, a non-transient answer, or the budget spent.
    Failed { attempts: u32, error: String },
}

/// The shared delivery engine (DW-044's retry/budget shape): one body,
/// one target, ONE total timeout shared by every attempt, exponential
/// backoff doubling to the target's cap, seconds-form `Retry-After`
/// honored in place of the computed wait. This is the whole
/// failure-isolation guarantee — a slow, hung, or flapping receiver
/// costs at most `timeout` — and it is deliberately extractor-shared by
/// the two POST-based pipelines in this domain: the alert-event
/// deliverer and the DW-121 access-record batch sink. The caller
/// decides how the outcome is counted.
pub(super) async fn deliver_with_retry(
    target: &WebhookTarget,
    body: Bytes,
    content_type: &str,
    user_agent: &str,
) -> DeliveryEnd {
    let deadline = Instant::now() + target.timeout;
    let mut backoff = target.backoff_base;
    let mut attempt = 1;
    loop {
        match post_once(target, &body, deadline, content_type, user_agent).await {
            Attempt::Accepted => {
                return DeliveryEnd::Delivered { attempts: attempt };
            }
            Attempt::Fatal(error) => {
                return DeliveryEnd::Failed {
                    attempts: attempt,
                    error,
                };
            }
            Attempt::Retry { retry_after, error } => {
                if attempt >= target.attempts {
                    return DeliveryEnd::Failed {
                        attempts: attempt,
                        error: format!("still not accepted after {attempt} attempts: {error}"),
                    };
                }
                // Retry-After replaces the computed backoff for this
                // wait; a demanded zero falls back to the computed value
                // so a hostile zero cannot busy-loop.
                let wait = match retry_after {
                    Some(ra) if !ra.is_zero() => ra,
                    _ => backoff,
                };
                backoff = backoff.saturating_mul(2).min(target.backoff_cap);
                let Some(left) = remaining(deadline) else {
                    return DeliveryEnd::Failed {
                        attempts: attempt,
                        error: format!("delivery budget spent before retry: {error}"),
                    };
                };
                if wait >= left {
                    return DeliveryEnd::Failed {
                        attempts: attempt,
                        error: format!(
                            "retry wait {wait:?} would exhaust the delivery budget: {error}"
                        ),
                    };
                }
                tracing::debug!(
                    code = "webhook_retry",
                    url = %target.url,
                    attempt,
                    backoff_ms = wait.as_millis() as u64,
                    "webhook not accepted ({error}); retrying in {wait:?}"
                );
                tokio::time::sleep(wait).await;
                attempt += 1;
            }
        }
    }
}

/// Deliver one alert-event envelope to one target, with the documented
/// retry shape, counting exactly one outcome (`delivered` or `failed`)
/// in `dwara_webhook_events_total{kind,outcome}`. Public for the
/// delivery contract's unit tests; the deliverer calls it per delivery.
pub async fn deliver(target: WebhookTarget, body: Bytes, kind: EventKind, obs: Arc<Observability>) {
    let url = target.url().to_string();
    match deliver_with_retry(&target, body, "application/json", USER_AGENT).await {
        DeliveryEnd::Delivered { attempts } => {
            tracing::debug!(
                code = "webhook_delivered",
                url = %url,
                kind = kind.as_str(),
                attempt = attempts,
                "webhook delivered"
            );
            obs.record_webhook_event(kind.as_str(), "delivered");
        }
        DeliveryEnd::Failed { attempts, error } => {
            tracing::warn!(
                code = "webhook_failed",
                url = %url,
                kind = kind.as_str(),
                attempt = attempts,
                "webhook delivery failed: {error}"
            );
            obs.record_webhook_event(kind.as_str(), "failed");
        }
    }
}

/// The deliverer loop (DW-044): drain the bus, filter by kind, dispatch
/// one bounded-concurrency delivery task per (event, target). Returns
/// on shutdown (pending queue abandoned — documented: the gateway is
/// not a durable queue) or when the bus closes.
///
/// Spawned by the `DataPlane`
/// (`DataPlane::spawn_webhook_deliverer`) so the binary and tests share
/// one wiring path.
pub async fn run_deliverer(
    mut rx: tokio::sync::mpsc::Receiver<Event>,
    targets: watch::Receiver<Arc<Vec<WebhookTarget>>>,
    obs: Arc<Observability>,
    mut shutdown: watch::Receiver<()>,
) {
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES));
    loop {
        let event = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() {
                    return;
                }
                tracing::debug!(
                    code = "webhook_deliverer_stopped",
                    "shutdown signaled; webhook deliverer stopping (pending queue abandoned)"
                );
                return;
            }
            event = rx.recv() => match event {
                Some(event) => event,
                None => return,
            },
        };
        let body = envelope_json(&event);
        if body.len() > MAX_ENVELOPE_BYTES {
            tracing::warn!(
                code = "webhook_event_dropped",
                kind = event.kind.as_str(),
                size = body.len(),
                "event envelope exceeds the {} byte cap; dropped",
                MAX_ENVELOPE_BYTES
            );
            obs.record_webhook_event(event.kind.as_str(), "dropped");
            continue;
        }
        let current = targets.borrow().clone();
        for target in current.iter().filter(|t| t.wants(event.kind)) {
            let Some(permit) = permits.clone().try_acquire_owned().ok() else {
                tracing::warn!(
                    code = "webhook_event_dropped",
                    kind = event.kind.as_str(),
                    url = %target.url(),
                    "webhook delivery concurrency saturated ({} in flight); dropped",
                    MAX_CONCURRENT_DELIVERIES
                );
                obs.record_webhook_event(event.kind.as_str(), "dropped");
                continue;
            };
            tokio::spawn(delivery_task(
                target.clone(),
                Bytes::from(body.clone()),
                event.kind,
                Arc::clone(&obs),
                permit,
            ));
        }
    }
}

/// `deliver` with the semaphore permit moved in (released when the
/// delivery finishes, bounding concurrency).
async fn delivery_task(
    target: WebhookTarget,
    body: Bytes,
    kind: EventKind,
    obs: Arc<Observability>,
    _permit: OwnedSemaphorePermit,
) {
    deliver(target, body, kind, obs).await;
}
