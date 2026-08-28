//! Observability substrate (DW-021, feature analysis sections 4.17 and
//! 4.19): tracing spans per request phase, structured JSON access logs,
//! Prometheus metrics, request IDs, and the unified error envelope.
//!
//! ## Tracing and spans
//!
//! `tracing` (MIT) is the substrate. Every request opens a root span
//! named `request` carrying `request_id`, `method`, `path` (WITHOUT the
//! query string — redaction: query strings carry tokens), `consumer`,
//! `route`, and `listener` fields, plus child spans at each phase:
//! `authn`, `authz`, `ratelimit`, `admission`, `upstream_pick` (emitted
//! inside the upstream handle where the pick actually happens), and one
//! `upstream_attempt` span per send. The binary installs a
//! `tracing-subscriber` JSON formatter over STDOUT filtered by
//! `DWARA_LOG` (RUST_LOG syntax, default `dwara=info`).
//!
//! ## OTLP decision
//!
//! The OTLP exporter (`opentelemetry` + `opentelemetry-otlp`) was
//! evaluated and NOT added in v1: the crates are heavy (their own HTTP
//! transport, tonic/protonic codegen) against a musl <25MB binary-size
//! budget (DW-026) and a compute-conscious CI. The span STRUCTURE ships
//! now and is proven by an in-process span-capture test (one trace shows
//! all phases). Since #126 the exporter exists behind the default-off
//! `otlp` cargo FEATURE on dwara-bin (the env var `DWARA_OTLP_ENDPOINT`
//! is a binary-level knob and the tracing subscriber the exporter must
//! hook lives in the bin; this module stays dependency-light by design).
//! Default build: `DWARA_OTLP_ENDPOINT` remains RESERVED but inert;
//! feature build: the spans defined here export over http/protobuf.
//!
//! ## Access logs
//!
//! One event at target `dwara::access` per completed request (rendered
//! as one JSON line by the binary's subscriber): `ts` (subscriber
//! timestamp), `request_id`, `method`, `path` (sanitized: no query),
//! `status`, `duration_ms`, `route`, `consumer`, `upstream`,
//! `endpoint`, `attempts`, and the `rate_limited` / `broken` / `shed`
//! flags. `bytes_in`/`bytes_out` are deliberately omitted: the proxy
//! path is zero-buffering by design (DW-009) and body sizes are not
//! cheaply available for streamed bodies — recorded here as an honest
//! omission rather than a wrong number. Sampling: `DWARA_ACCESS_LOG_
//! SAMPLE` (0.0-1.0, default 1.0); responses with status >= 500 are
//! ALWAYS logged regardless of sampling (documented rule).
//!
//! ## Metrics
//!
//! Prometheus text format on `/metrics`, reserved on every HTTP(S)
//! listener exactly like `/healthz` (a configured route matching it is
//! shadowed — same accepted v1 behavior). The `prometheus` crate (MIT,
//! default features off: text format only, no protobuf exporter) backs
//! the registry. Metric families:
//!
//! - `requests_total{route,listener,status_class}` counter
//! - `request_duration_seconds{route}` histogram
//! - `upstream_attempts_total{upstream,endpoint,status_class}` counter
//! - `retries_total{upstream}` counter
//! - `rate_limited_total{route}` counter
//! - `shed_total{priority}` counter
//! - `dwara_policy_dry_run_total{phase,route}` counter (DW-041) —
//!   requests a dry-run (monitor) policy would have rejected, by phase
//!   (`route_limits`, `authz`, `rate_limit`, `load_shed`) and route
//!   (`unrouted` for pre-404 listener/global policies); the request was
//!   ALLOWED. Together with the `dwara::policy` warn events (phase,
//!   would-be status, reason, route, consumer, request id) this family
//!   IS the dry-run report — no separate endpoint.
//! - `breaker_state{upstream}` gauge (0 closed, 1 open, 2 half-open)
//! - `endpoint_health{upstream,endpoint}` gauge (1 available, 0 ejected)
//! - `upstream_fail_open_picks{upstream}` gauge (scrape-time snapshot of
//!   the balancer's monotonic fail-open counter; a gauge rather than a
//!   counter so the hot pick path stays free of registry coupling)
//! - `active_requests` gauge
//! - `config_generation` gauge
//! - `jwks_refresh_total{provider}` counter
//! - `dwara_rate_limiter_evictions_total` gauge (scrape-time snapshot
//!   of the rate-limit engine's monotonic eviction counter, aggregated
//!   over every compiled rule; resets when a reload rebuilds the
//!   engine; a gauge rather than a counter so the hot check path stays
//!   free of registry coupling)
//! - `dwara_rate_limiter_live_keys` gauge (live per-key cells across
//!   every compiled rule, approximate, bounded by the sharded store
//!   cap; aggregate and unlabeled — cardinality is never per key)
//! - `dwara_webhook_events_total{kind,outcome}` counter (DW-044):
//!   webhook deliveries by event kind and outcome — `delivered` (2xx
//!   on some attempt), `failed` (retries exhausted / non-transient
//!   answer / budget spent), `dropped` (never tried: envelope over the
//!   byte cap, or delivery concurrency saturated). Both labels are
//!   closed sets, so cardinality is bounded by construction.
//! - `dwara_events_dropped_total` / `dwara_events_emitted_total`
//!   gauges (DW-044, scrape-time snapshots of the event bus's
//!   monotonic counters — gauges rather than counters so the emit path
//!   stays a plain atomic with zero registry coupling, the same model
//!   as the rate-limiter eviction gauge): events dropped at EMIT time
//!   (full queue / no deliverer) and events handed to the queue.
//!
//! ## Error envelope (section 4.19)
//!
//! Every gateway-generated non-success body — including the reserved
//! `/healthz`/`/readyz` responses, which are aligned to the same shape —
//! is `{"error":{"code","message","request_id"}}`. Messages never leak
//! upstream internals: classification strings only ("upstream
//! unavailable", not hyper error text).
//!
//! ## Request IDs
//!
//! An inbound `X-Request-Id` is respected when it is printable ASCII of
//! at most 128 bytes (anything else is replaced — a hostile ID must not
//! smuggle control bytes into logs); otherwise a process-unique ID is
//! generated (wall-clock nanoseconds + per-process counter — cheaper
//! than a UUID, no extra dependency). The ID is echoed on the response
//! as `X-Request-Id` and available to every span and log line.
//!
//! ## Redaction rules (hard requirements)
//!
//! - Paths are logged WITHOUT query strings.
//! - No Authorization / Proxy-Authorization / Cookie / Set-Cookie /
//!   X-API-Key VALUES are ever emitted by this module or the tracing
//!   calls it fronts; field lists below are exhaustive.
//! - JWKS bodies, credentials, and keys are never logged.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry, TextEncoder,
};

/// Request header carrying the correlation ID (inbound respected,
/// outbound always set by the gateway).
pub const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Extension inserted by the listener frontend (dwara-bin) naming the
/// listener that accepted the request; absent when `proxy::handle` is
/// driven directly (tests), in which case the label is "unknown".
#[derive(Clone, Debug)]
pub struct ListenerLabel(pub std::sync::Arc<str>);

/// Histogram buckets for `request_duration_seconds`: sub-millisecond
/// precision is noise at gateway scale; 10s covers every classified
/// timeout (default connect timeout is 5s).
const DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Prometheus status-class label ("2xx", "5xx", ...).
pub fn status_class(status: u16) -> String {
    format!("{}xx", status / 100)
}

/// The accumulated access-log record for one request. The proxy fills
/// fields as the request progresses; `finish` stamps status/duration.
#[derive(Debug)]
pub struct AccessRecord {
    pub request_id: String,
    pub method: String,
    /// Request path WITHOUT the query string (redaction).
    pub path: String,
    pub listener: String,
    /// Matched route name, or "unrouted" for 404s.
    pub route: String,
    /// Authenticated consumer, or "anonymous".
    pub consumer: String,
    pub upstream: Option<String>,
    pub endpoint: Option<String>,
    pub attempts: u32,
    pub rate_limited: bool,
    pub broken: bool,
    pub shed: bool,
    pub status: u16,
    pub duration_ms: f64,
}

impl AccessRecord {
    pub fn new(request_id: String, method: String, path: String, listener: String) -> Self {
        AccessRecord {
            request_id,
            method,
            path,
            listener,
            route: "unrouted".to_string(),
            consumer: "anonymous".to_string(),
            upstream: None,
            endpoint: None,
            attempts: 0,
            rate_limited: false,
            broken: false,
            shed: false,
            status: 0,
            duration_ms: 0.0,
        }
    }
}

/// Emit one access-log event (one JSON line under the binary's
/// subscriber). The field list is exhaustive and redacted by
/// construction: no headers, no query string, no credentials.
pub fn emit_access(rec: &AccessRecord) {
    tracing::info!(
        target: "dwara::access",
        request_id = %rec.request_id,
        method = %rec.method,
        path = %rec.path,
        status = rec.status,
        duration_ms = rec.duration_ms,
        route = %rec.route,
        consumer = %rec.consumer,
        upstream = rec.upstream.as_deref().unwrap_or(""),
        endpoint = rec.endpoint.as_deref().unwrap_or(""),
        attempts = rec.attempts,
        rate_limited = rec.rate_limited,
        broken = rec.broken,
        shed = rec.shed,
        "access"
    );
}

/// The unified error body (section 4.19): a JSON object an operator can
/// grep and a client can correlate. `code` is a stable machine token,
/// `message` a human string with no upstream internals, `request_id`
/// ties the response to the trace/access log.
pub fn envelope_body(code: &str, message: &str, request_id: &str) -> bytes::Bytes {
    let obj = serde_json::json!({
        "error": {
            "code": code,
            "message": message,
            "request_id": request_id,
        }
    });
    bytes::Bytes::from(obj.to_string())
}

/// Validate an inbound `X-Request-Id` value: printable ASCII (0x20-0x7E),
/// at most 128 bytes. Anything else (control bytes, UTF-8 multibyte,
/// overlong) is rejected so hostile IDs cannot smuggle control
/// characters into logs.
pub fn valid_inbound_request_id(v: &[u8]) -> bool {
    !v.is_empty() && v.len() <= 128 && v.iter().all(|b| (0x20..=0x7e).contains(b))
}

/// Resolve the request's correlation ID: a valid inbound `X-Request-Id`
/// verbatim, else a generated one (`req-` + hex wall-clock nanoseconds +
/// hex process counter; unique per process, no dependency pulled in for
/// randomness — request IDs are correlation handles, not secrets).
pub fn resolve_request_id(headers: &HeaderMap) -> String {
    if let Some(v) = headers.get(&X_REQUEST_ID) {
        if valid_inbound_request_id(v.as_bytes()) {
            if let Ok(s) = v.to_str() {
                return s.to_string();
            }
        }
    }
    generate_request_id()
}

/// Per-process request-ID counter (the low bits of the wall clock are
/// already unique per nanosecond; the counter disambiguates coarse
/// clocks and multi-ID calls within one nanosecond).
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Public for testing the request-id generation contract.
pub fn generate_request_id() -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let c = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("req-{:016x}-{:06x}", n, c & 0xff_ffff)
}

/// Cheap sampling PRNG: a Weyl-sequence over one atomic (add a large
/// odd constant, use the high bits of the product). Not cryptographic —
/// it only decides whether an access-log line is emitted.
struct SampleRng {
    state: AtomicU64,
}

impl SampleRng {
    fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9e37_79b9_7f4a_7c15);
        SampleRng {
            state: AtomicU64::new(seed | 1),
        }
    }

    fn next_f64(&self) -> f64 {
        let x = self
            .state
            .fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
        // Multiply-shift normalization into [0, 1).
        ((x.wrapping_mul(0x9e37_79b9_7f4a_7c15)) >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Per-dataplane observability state: the metric families plus the
/// access-log sampling knob. One instance per `DataPlane`, so parallel
/// tests never share a registry (duplicate-metric registration errors).
pub struct Observability {
    registry: Registry,
    requests_total: IntCounterVec,
    request_duration: HistogramVec,
    upstream_attempts_total: IntCounterVec,
    retries_total: IntCounterVec,
    rate_limited_total: IntCounterVec,
    shed_total: IntCounterVec,
    policy_dry_run_total: IntCounterVec,
    breaker_state: IntGaugeVec,
    endpoint_health: IntGaugeVec,
    fail_open_picks: IntGaugeVec,
    jwks_refresh_total: IntCounterVec,
    active_requests: IntGauge,
    config_generation: IntGauge,
    /// #132: rate-limiter eviction/live-key snapshot gauges — aggregate,
    /// unlabeled (config-bounded cardinality: never per key).
    rate_limiter_evictions: IntGauge,
    rate_limiter_live_keys: IntGauge,
    /// DW-044: webhook delivery outcomes by (kind, outcome) — both
    /// labels closed sets (the event kinds and the three outcomes), so
    /// cardinality is bounded by construction.
    webhook_events_total: IntCounterVec,
    /// DW-044: event-bus emit/drop snapshot gauges (see the module
    /// docs for the gauge-not-counter rationale).
    events_dropped: IntGauge,
    events_emitted: IntGauge,
    /// DW-037: response-cache lookup outcomes — a CLOSED label set
    /// (`hit`, `stale`, `miss`, `bypass`), one increment per request on
    /// a cache-configured route, decided at lookup.
    cache_lookups_total: IntCounterVec,
    /// DW-037: response-cache store outcomes — CLOSED set (`stored`,
    /// `vetoed`, `over_cap`, `error`), one increment per cacheable
    /// fetch that reached the store stage.
    cache_stores_total: IntCounterVec,
    /// DW-037: responses served from a stored body after the upstream
    /// answered a conditional revalidation with 304 (the "unchanged"
    /// path; plain counter — no label space to close).
    cache_revalidated_total: IntCounter,
    /// DW-037: purge operations — CLOSED set (`route`, `all`).
    cache_purges_total: IntCounterVec,
    /// DW-037: approximate live cache entries (scrape-time snapshot
    /// walk of the store's `entry_count`, the same gauge model as the
    /// rate-limiter live-keys gauge).
    cache_entries: IntGauge,
    /// DW-038: cache misses that became the coalescing LEADER (their
    /// own upstream fetch ran while followers could attach). Plain
    /// counter — no label space to close.
    coalescing_leaders_total: IntCounter,
    /// DW-038: coalescing follower resolutions — a CLOSED label set
    /// (`served`, `fell_back_timeout`, `fell_back_unshared`,
    /// `fell_back_epoch`), so the family's cardinality is four series
    /// total. `served` = the leader's stored outcome replayed;
    /// `fell_back_timeout` = the wait bound expired; `fell_back_unshared`
    /// = the leader finished without a storable outcome (vetoed,
    /// non-200, error — the follower fetched on its own);
    /// `fell_back_epoch` = a purge/config change invalidated the
    /// generation mid-flight (checked first; the follower fetched on
    /// its own).
    coalescing_followers_total: IntCounterVec,
    /// DW-038: upstream calls avoided by coalescing (one per `served`
    /// follower — the direct answer to "is coalescing paying for
    /// itself").
    coalescing_saved_upstream_calls_total: IntCounter,
    /// DW-038: requests currently parked as coalescing followers.
    coalescing_waiters: IntGauge,
    /// Access-log sample rate [0.0, 1.0] as raw bits (f64 does not fit
    /// an atomic portably); read via [`Self::access_sample`].
    access_sample_bits: AtomicU64,
    rng: SampleRng,
}

impl Default for Observability {
    fn default() -> Self {
        Self::from_env()
    }
}

impl Observability {
    /// Build with `DWARA_ACCESS_LOG_SAMPLE` applied (default 1.0; values
    /// outside [0.0, 1.0] fall back to 1.0 — a malformed knob must never
    /// silence logs).
    pub fn from_env() -> Self {
        let sample = std::env::var("DWARA_ACCESS_LOG_SAMPLE")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|f| (0.0..=1.0).contains(f))
            .unwrap_or(1.0);
        let obs = Self::new();
        obs.set_access_sample(sample);
        obs
    }

    pub fn new() -> Self {
        let registry = Registry::new();
        let requests_total = IntCounterVec::new(
            Opts::new(
                "requests_total",
                "Requests handled by the gateway, by route/listener/status class.",
            ),
            &["route", "listener", "status_class"],
        )
        .expect("valid metric definition");
        let request_duration = HistogramVec::new(
            HistogramOpts::new(
                "request_duration_seconds",
                "Gateway request latency (route resolution to response headers).",
            )
            .buckets(DURATION_BUCKETS.to_vec()),
            &["route"],
        )
        .expect("valid metric definition");
        let upstream_attempts_total = IntCounterVec::new(
            Opts::new(
                "upstream_attempts_total",
                "Upstream send attempts, by upstream/endpoint/status class.",
            ),
            &["upstream", "endpoint", "status_class"],
        )
        .expect("valid metric definition");
        let retries_total = IntCounterVec::new(
            Opts::new("retries_total", "Retried upstream attempts, by upstream."),
            &["upstream"],
        )
        .expect("valid metric definition");
        let rate_limited_total = IntCounterVec::new(
            Opts::new(
                "rate_limited_total",
                "Requests denied by rate limiting, by route.",
            ),
            &["route"],
        )
        .expect("valid metric definition");
        let shed_total = IntCounterVec::new(
            Opts::new(
                "shed_total",
                "Requests shed by the gateway concurrency cap, by priority class.",
            ),
            &["priority"],
        )
        .expect("valid metric definition");
        let policy_dry_run_total = IntCounterVec::new(
            Opts::new(
                "dwara_policy_dry_run_total",
                "Requests a dry-run (monitor) policy would have rejected, by phase and \
                 route; the request was allowed (DW-041). Phases: route_limits, authz, \
                 rate_limit, load_shed.",
            ),
            &["phase", "route"],
        )
        .expect("valid metric definition");
        let breaker_state = IntGaugeVec::new(
            Opts::new(
                "breaker_state",
                "Upstream circuit breaker state: 0 closed, 1 open, 2 half-open.",
            ),
            &["upstream"],
        )
        .expect("valid metric definition");
        let endpoint_health = IntGaugeVec::new(
            Opts::new(
                "endpoint_health",
                "Endpoint availability under passive/active health: 1 available, 0 ejected.",
            ),
            &["upstream", "endpoint"],
        )
        .expect("valid metric definition");
        let fail_open_picks = IntGaugeVec::new(
            Opts::new(
                "upstream_fail_open_picks",
                "Balancer picks that fail-opened over an all-ejected pool (scrape-time snapshot).",
            ),
            &["upstream"],
        )
        .expect("valid metric definition");
        let jwks_refresh_total = IntCounterVec::new(
            Opts::new(
                "jwks_refresh_total",
                "JWKS fetch attempts (stale and rotation-triggered), by provider.",
            ),
            &["provider"],
        )
        .expect("valid metric definition");
        let active_requests = IntGauge::new(
            "active_requests",
            "Requests currently between handle() entry and response-header completion.",
        )
        .expect("valid metric definition");
        let config_generation = IntGauge::new(
            "config_generation",
            "Currently published configuration generation number.",
        )
        .expect("valid metric definition");
        let rate_limiter_evictions = IntGauge::new(
            "dwara_rate_limiter_evictions_total",
            "Rate-limiter per-key cells dropped by eviction sweeps, aggregated over \
             every compiled rule (scrape-time snapshot of the engine's monotonic \
             counter; resets when a reload rebuilds the engine).",
        )
        .expect("valid metric definition");
        let rate_limiter_live_keys = IntGauge::new(
            "dwara_rate_limiter_live_keys",
            "Live per-key rate-limiter cells across every compiled rule \
             (approximate under concurrent checks; bounded by the sharded \
             store cap per window).",
        )
        .expect("valid metric definition");
        let webhook_events_total = IntCounterVec::new(
            Opts::new(
                "dwara_webhook_events_total",
                "Webhook deliveries by event kind and outcome (DW-044). \
                 outcome: delivered (2xx on some attempt), failed (retries \
                 exhausted, non-transient answer, or budget spent), dropped \
                 (never tried: envelope over the byte cap or delivery \
                 concurrency saturated).",
            ),
            &["kind", "outcome"],
        )
        .expect("valid metric definition");
        let events_dropped = IntGauge::new(
            "dwara_events_dropped_total",
            "Events dropped at EMIT time (event queue full or no deliverer \
             draining); scrape-time snapshot of the event bus's monotonic \
             counter (DW-044).",
        )
        .expect("valid metric definition");
        let events_emitted = IntGauge::new(
            "dwara_events_emitted_total",
            "Events handed to the event queue since process start; \
             scrape-time snapshot of the event bus's monotonic counter \
             (DW-044).",
        )
        .expect("valid metric definition");
        let cache_lookups_total = IntCounterVec::new(
            Opts::new(
                "dwara_cache_lookups_total",
                "Response-cache lookups by outcome (DW-037), one per request on a \
                 cache-configured route. outcome: hit (fresh entry served), stale \
                 (expired entry served inside the stale-while-revalidate window), \
                 miss (no usable entry; the request went upstream), bypass (the \
                 request shape is not cacheable).",
            ),
            &["outcome"],
        )
        .expect("valid metric definition");
        let cache_stores_total = IntCounterVec::new(
            Opts::new(
                "dwara_cache_stores_total",
                "Response-cache store attempts by outcome (DW-037). outcome: \
                 stored, vetoed (a response-side rule forbade storage), over_cap \
                 (body larger than the route's max_body_bytes; passed through \
                 unbuffered), error (the backing store failed).",
            ),
            &["outcome"],
        )
        .expect("valid metric definition");
        let cache_revalidated_total = IntCounter::new(
            "dwara_cache_revalidated_total",
            "Responses served from the stored body after the upstream confirmed \
             the validator with 304 (DW-037).",
        )
        .expect("valid metric definition");
        let cache_purges_total = IntCounterVec::new(
            Opts::new(
                "dwara_cache_purges_total",
                "Cache purge operations by scope (DW-037): route (one named \
                 route) or all.",
            ),
            &["scope"],
        )
        .expect("valid metric definition");
        let cache_entries = IntGauge::new(
            "dwara_cache_entries",
            "Approximate live response-cache entries (DW-037); scrape-time \
             snapshot of the backing store's entry count.",
        )
        .expect("valid metric definition");
        let coalescing_leaders_total = IntCounter::new(
            "dwara_coalescing_leaders_total",
            "Cache misses that became the request-coalescing leader (DW-038): \
             their upstream fetch ran while later identical misses waited.",
        )
        .expect("valid metric definition");
        let coalescing_followers_total = IntCounterVec::new(
            Opts::new(
                "dwara_coalescing_followers_total",
                "Request-coalescing follower resolutions by outcome (DW-038). \
                 outcome: served (the leader's stored outcome replayed, one \
                 upstream call saved), fell_back_timeout (the wait bound \
                 expired), fell_back_unshared (the leader finished without a \
                 storable outcome; the follower fetched on its own), \
                 fell_back_epoch (a purge/config change invalidated the \
                 generation mid-flight; the follower fetched on its own).",
            ),
            &["outcome"],
        )
        .expect("valid metric definition");
        let coalescing_saved_upstream_calls_total = IntCounter::new(
            "dwara_coalescing_saved_upstream_calls_total",
            "Upstream calls avoided by request coalescing (DW-038); one per \
             served follower.",
        )
        .expect("valid metric definition");
        let coalescing_waiters = IntGauge::new(
            "dwara_coalescing_waiters",
            "Requests currently parked as request-coalescing followers \
             (DW-038).",
        )
        .expect("valid metric definition");
        // Clones share state (every prometheus family is a shared handle),
        // so registering clones keeps the originals usable for recording.
        for m in [
            Box::new(requests_total.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(request_duration.clone()),
            Box::new(upstream_attempts_total.clone()),
            Box::new(retries_total.clone()),
            Box::new(rate_limited_total.clone()),
            Box::new(shed_total.clone()),
            Box::new(policy_dry_run_total.clone()),
            Box::new(breaker_state.clone()),
            Box::new(endpoint_health.clone()),
            Box::new(fail_open_picks.clone()),
            Box::new(jwks_refresh_total.clone()),
            Box::new(active_requests.clone()),
            Box::new(config_generation.clone()),
            Box::new(rate_limiter_evictions.clone()),
            Box::new(rate_limiter_live_keys.clone()),
            Box::new(webhook_events_total.clone()),
            Box::new(events_dropped.clone()),
            Box::new(events_emitted.clone()),
            Box::new(cache_lookups_total.clone()),
            Box::new(cache_stores_total.clone()),
            Box::new(cache_revalidated_total.clone()),
            Box::new(cache_purges_total.clone()),
            Box::new(cache_entries.clone()),
            Box::new(coalescing_leaders_total.clone()),
            Box::new(coalescing_followers_total.clone()),
            Box::new(coalescing_saved_upstream_calls_total.clone()),
            Box::new(coalescing_waiters.clone()),
        ] {
            registry
                .register(m)
                .expect("fresh registry accepts every family exactly once");
        }
        Observability {
            registry,
            requests_total,
            request_duration,
            upstream_attempts_total,
            retries_total,
            rate_limited_total,
            shed_total,
            policy_dry_run_total,
            breaker_state,
            endpoint_health,
            fail_open_picks,
            jwks_refresh_total,
            active_requests,
            config_generation,
            rate_limiter_evictions,
            rate_limiter_live_keys,
            webhook_events_total,
            events_dropped,
            events_emitted,
            cache_lookups_total,
            cache_stores_total,
            cache_revalidated_total,
            cache_purges_total,
            cache_entries,
            coalescing_leaders_total,
            coalescing_followers_total,
            coalescing_saved_upstream_calls_total,
            coalescing_waiters,
            access_sample_bits: AtomicU64::new(1.0f64.to_bits()),
            rng: SampleRng::new(),
        }
    }

    /// Access-log sample rate in [0.0, 1.0]. Env-driven at construction
    /// (`DWARA_ACCESS_LOG_SAMPLE`); settable directly for tests.
    pub fn set_access_sample(&self, rate: f64) {
        let rate = rate.clamp(0.0, 1.0);
        self.access_sample_bits
            .store(rate.to_bits(), Ordering::Relaxed);
    }

    pub fn access_sample(&self) -> f64 {
        f64::from_bits(self.access_sample_bits.load(Ordering::Relaxed))
    }

    /// Whether this request's access log line is emitted. Errors
    /// (status >= 500) are ALWAYS logged; everything else follows the
    /// configured sample rate.
    pub fn should_log_access(&self, status: u16) -> bool {
        if status >= 500 {
            return true;
        }
        let rate = self.access_sample();
        rate >= 1.0 || self.rng.next_f64() < rate
    }

    /// Count and observe one completed request.
    pub fn record_request(&self, route: &str, listener: &str, status: u16, elapsed: Duration) {
        self.requests_total
            .with_label_values(&[route, listener, &status_class(status)])
            .inc();
        self.request_duration
            .with_label_values(&[route])
            .observe(elapsed.as_secs_f64());
    }

    /// Count one upstream send attempt (endpoint = "unpicked" when the
    /// dispatch never resolved an endpoint).
    pub fn record_upstream_attempt(&self, upstream: &str, endpoint: &str, status: u16) {
        self.upstream_attempts_total
            .with_label_values(&[upstream, endpoint, &status_class(status)])
            .inc();
    }

    /// Count one retry (a send attempt after the first).
    pub fn record_retry(&self, upstream: &str) {
        self.retries_total.with_label_values(&[upstream]).inc();
    }

    /// Count one rate-limit denial (429).
    pub fn record_rate_limited(&self, route: &str) {
        self.rate_limited_total.with_label_values(&[route]).inc();
    }

    /// Count one gateway-cap shed (503), by priority class.
    pub fn record_shed(&self, priority: u8) {
        self.shed_total
            .with_label_values(&[&priority.to_string()])
            .inc();
    }

    /// Count one dry-run (monitor) would-have-rejected observation
    /// (DW-041): a policy phase evaluated a DENY (or shed, or limit
    /// violation) and the request was allowed anyway. `phase` is one of
    /// `route_limits`, `authz`, `rate_limit`, `load_shed`; `route` is
    /// the matched route name (`unrouted` for the pre-404 listener/
    /// global policy pass) — both config-bounded label spaces.
    pub fn record_policy_dry_run(&self, phase: &str, route: &str) {
        self.policy_dry_run_total
            .with_label_values(&[phase, route])
            .inc();
    }

    /// The dry-run report's log side (DW-041): one structured warn
    /// event at target `dwara::policy` per would-have-rejected request,
    /// carrying the phase, the status the phase WOULD have answered, the
    /// route and consumer (when known), and the phase's own reason —
    /// the request-id correlation key ties it to the trace and access
    /// line of the request that was allowed. Field list is exhaustive
    /// and redacted by construction (no headers, no query string).
    pub fn emit_policy_dry_run(
        &self,
        phase: &str,
        would_be_status: u16,
        route: &str,
        consumer: Option<&str>,
        request_id: &str,
        detail: &str,
    ) {
        tracing::warn!(
            target: "dwara::policy",
            code = "policy_dry_run",
            phase = phase,
            would_be_status = would_be_status,
            route = route,
            consumer = consumer.unwrap_or("anonymous"),
            request_id = request_id,
            detail = detail,
            "policy would have rejected this request (dry-run); \
             enforcement of this phase skipped"
        );
    }

    /// The JWKS refresh counter child for one provider (handed to the
    /// authenticator; incremented on every JWKS fetch attempt).
    pub fn jwks_refresh_counter(&self, provider: &str) -> IntCounter {
        self.jwks_refresh_total.with_label_values(&[provider])
    }

    /// Count one response-cache lookup outcome (DW-037). `outcome` is
    /// one of the closed set `hit` / `stale` / `miss` / `bypass` (see
    /// `dataplane::response_cache` for the decision table).
    pub fn record_cache_lookup(&self, outcome: &str) {
        self.cache_lookups_total.with_label_values(&[outcome]).inc();
    }

    /// Count one response-cache store outcome (DW-037). `outcome` is
    /// one of the closed set `stored` / `vetoed` / `over_cap` /
    /// `error`.
    pub fn record_cache_store(&self, outcome: &str) {
        self.cache_stores_total.with_label_values(&[outcome]).inc();
    }

    /// Count one 304-confirmed revalidation served from the stored body
    /// (DW-037).
    pub fn record_cache_revalidated(&self) {
        self.cache_revalidated_total.inc();
    }

    /// Count one cache purge (DW-037). `scope` is `route` or `all`.
    pub fn record_cache_purge(&self, scope: &str) {
        self.cache_purges_total.with_label_values(&[scope]).inc();
    }

    /// Set the approximate live-entries gauge (DW-037) — a scrape-time
    /// snapshot walk of the backing store (the same gauge model as the
    /// rate-limiter live-keys gauge: state lives outside observability,
    /// the dataplane walks it at scrape time).
    pub fn set_cache_entries(&self, entries: i64) {
        self.cache_entries.set(entries);
    }

    /// DW-038: this cache miss became the coalescing leader.
    pub fn record_coalescing_leader(&self) {
        self.coalescing_leaders_total.inc();
    }

    /// DW-038: a coalescing follower resolved — `outcome` is one of the
    /// closed set `served` / `fell_back_timeout` / `fell_back_unshared`
    /// / `fell_back_epoch` (see the field docs; callers pass literals).
    pub fn record_coalescing_follower(&self, outcome: &str) {
        self.coalescing_followers_total
            .with_label_values(&[outcome])
            .inc();
    }

    /// DW-038: one upstream call avoided (a follower was served).
    pub fn record_coalescing_saved(&self) {
        self.coalescing_saved_upstream_calls_total.inc();
    }

    /// DW-038: follower waiters gauge, +/- on park/resolve.
    pub fn coalescing_waiter(&self, parked: bool) {
        if parked {
            self.coalescing_waiters.inc();
        } else {
            self.coalescing_waiters.dec();
        }
    }

    pub fn active_requests(&self) -> &IntGauge {
        &self.active_requests
    }

    /// Publish the current config generation number.
    pub fn set_config_generation(&self, generation: u64) {
        self.config_generation.set(generation as i64);
    }

    /// Set the `breaker_state` gauge for one upstream (0 closed, 1 open,
    /// 2 half-open). Scrape-time snapshot setter: the walk that computes
    /// the values from live upstream state lives on the dataplane (see
    /// `refresh_observation_gauges` in `dataplane::upstream`), keeping
    /// this module free of runtime-state dependencies — it only records
    /// what it is handed.
    pub fn set_breaker_state(&self, upstream: &str, state: i64) {
        self.breaker_state.with_label_values(&[upstream]).set(state);
    }

    /// Set the `upstream_fail_open_picks` gauge for one upstream
    /// (scrape-time snapshot of the balancer's monotonic fail-open
    /// counter; a gauge rather than a counter so the hot pick path stays
    /// free of metrics coupling).
    pub fn set_fail_open_picks(&self, upstream: &str, picks: i64) {
        self.fail_open_picks
            .with_label_values(&[upstream])
            .set(picks);
    }

    /// Set the `dwara_rate_limiter_evictions_total` gauge: aggregate
    /// cells dropped by eviction sweeps across every compiled rule
    /// (#132). Scrape-time snapshot of the engine's monotonic counter —
    /// a gauge rather than a counter so the hot check path stays free
    /// of metrics coupling; the value resets when a reload rebuilds the
    /// engine. See [`Self::set_breaker_state`] for the refresh model.
    pub fn set_rate_limiter_evictions(&self, evictions: i64) {
        self.rate_limiter_evictions.set(evictions);
    }

    /// Set the `dwara_rate_limiter_live_keys` gauge: live per-key cells
    /// across every compiled rule, approximate under concurrent checks
    /// and bounded by the sharded store cap (#132). Aggregate and
    /// unlabeled by design — cardinality is never per key. Scrape-time
    /// snapshot setter; see [`Self::set_breaker_state`].
    pub fn set_rate_limiter_live_keys(&self, keys: i64) {
        self.rate_limiter_live_keys.set(keys);
    }

    /// Count one webhook delivery outcome (DW-044) in
    /// `dwara_webhook_events_total{kind,outcome}`. `kind` is the
    /// event-kind spelling, `outcome` one of `delivered`, `failed`,
    /// `dropped` (the deliverer is the only caller, so both label
    /// spaces stay the closed sets documented on the family).
    pub fn record_webhook_event(&self, kind: &str, outcome: &str) {
        self.webhook_events_total
            .with_label_values(&[kind, outcome])
            .inc();
    }

    /// Set the `dwara_events_dropped_total` gauge (DW-044): events
    /// dropped at EMIT time. Scrape-time snapshot of the event bus's
    /// monotonic counter; see [`Self::set_rate_limiter_evictions`] for
    /// the gauge-not-counter model.
    pub fn set_events_dropped(&self, dropped: i64) {
        self.events_dropped.set(dropped);
    }

    /// Set the `dwara_events_emitted_total` gauge (DW-044): events
    /// handed to the event queue since process start. Scrape-time
    /// snapshot setter; see [`Self::set_events_dropped`].
    pub fn set_events_emitted(&self, emitted: i64) {
        self.events_emitted.set(emitted);
    }

    /// Set the `endpoint_health` gauge for one endpoint (1 available,
    /// 0 ejected). Scrape-time snapshot setter; see
    /// [`Self::set_breaker_state`] for the refresh model.
    pub fn set_endpoint_health(&self, upstream: &str, endpoint: &str, up: bool) {
        self.endpoint_health
            .with_label_values(&[upstream, endpoint])
            .set(up as i64);
    }

    /// Render every family in Prometheus text format.
    pub fn render(&self) -> String {
        let mut buf = Vec::new();
        let encoder = TextEncoder::new();
        let families = self.registry.gather();
        encoder
            .encode(&families, &mut buf)
            .expect("text encoding of gathered families cannot fail");
        String::from_utf8(buf).expect("prometheus text format is ASCII")
    }
}

/// Echo a request ID onto a response (insert, never append: exactly one
/// `X-Request-Id`, the gateway's resolved one).
pub fn stamp_request_id(headers: &mut HeaderMap, request_id: &str) {
    if let Ok(v) = HeaderValue::from_str(request_id) {
        headers.insert(&X_REQUEST_ID, v);
    }
}
