//! Reverse-proxy dataplane (DW-009, feature analysis sections 4.1 and 9.2).
//!
//! Per request: snapshot lookup, route resolution (path via the compiled
//! `RouteTable`, then the route's non-path criteria: host, methods,
//! headers, query, cookies), and the route action:
//!
//! - `proxy`: strip hop-by-hop headers, rebuild `Host` to the upstream
//!   authority (upstream `address:port`, NOT the inbound host — v1 choice:
//!   the gateway, not the client, names the origin it dials), inject
//!   `X-Forwarded-For` / `X-Real-IP`, and stream the request body through
//!   the pooled upstream client frame-by-frame. The upstream response
//!   (`Incoming`) is forwarded untouched after hop-by-hop stripping.
//!   ZERO default buffering: no code on this path collects a body.
//!   Backpressure is hyper's natural frame-based flow — the gateway never
//!   spawns unbounded buffering tasks.
//! - `redirect`: 3xx with a `Location` built from the configured
//!   scheme/host/path; when no `path` is configured the inbound path AND
//!   query are preserved verbatim (v1 semantics).
//! - `respond`: fixed status/body straight from config.
//! - no route / criteria miss: 404 via the unified error envelope (v1
//!   does not model 405; a method or host mismatch reads as "no route
//!   for this request").
//!
//! Forwarded-header semantics (chosen and frozen here):
//! - `X-Forwarded-For`: if the direct connection peer is inside
//!   `gateway.trusted_proxies`, the inbound XFF value is preserved and the
//!   peer appended (`"<inbound>, <peer>"`). Otherwise (including the empty
//!   default list — trust nobody) the inbound XFF is DISCARDED and replaced
//!   with exactly the peer. A spoofed chain from an untrusted peer never
//!   reaches the upstream.
//! - `X-Real-IP`: always the direct peer. When the peer is a trusted proxy
//!   this equals "the last trusted hop"; when it is the client itself it
//!   equals the client. One rule, no configuration.
//!
//! Protocol upgrades (generic 101 tunneling, not WebSocket-specific): a
//! request carrying an `Upgrade` header on HTTP/1.1 is forwarded with its
//! `Upgrade`/`Connection` headers intact; a `101` upstream response is
//! relayed to the client and both connections are upgraded
//! (`hyper::upgrade::on` both sides) and spliced with
//! `tokio::io::copy_bidirectional` until EOF. HTTP/2 clients cannot tunnel
//! upgrades the HTTP/1.1 way: an `Upgrade` request received over h2/h2c is
//! answered `501 Not Implemented` with a clear message (extended CONNECT is
//! out of scope for v1).
//!
//! Upstream error classification (details are logged server-side, never
//! leaked to the client): connect timeout / per-attempt read timeout ->
//! 504; endpoint refused / pool failure / no endpoints -> 502; invalid TLS
//! host -> 500. A mid-body upstream abort (connection torn down partway
//! through a response body, or the DW-014 body-idle timeout firing) is NOT
//! retryable — the attempt was final once its headers resolved — and any
//! frames already forwarded to the client end abruptly (HTTP/1.1
//! truncation semantics, no synthesized tail). The abort IS reported as a
//! passive-health failure for the picked endpoint (DW-014 closing the
//! DW-012 gap), so chronically dying streams eject the endpoint.
//!
//! Retries, timeouts, budgets (DW-014): per-upstream `retries` config
//! drives a bounded retry loop around the send — per attempt the balancer
//! re-picks the endpoint (health ejection applies naturally), the
//! per-attempt `read_ms` deadline is enforced by the upstream handle, and
//! backoff is exponential with full jitter. Idempotency:
//! GET/HEAD/OPTIONS/TRACE/PUT are retry-eligible by method; POST is
//! retried ONLY when the upstream sets `retries.retry_post` (the opt-in
//! governs POST exclusively — DELETE, PATCH, and every other
//! non-idempotent method are never retried). A request
//! body is replayed only when it was buffered within
//! `retries.buffer_max_bytes` (opt-in; the default proxy path never
//! buffers — zero-copy streaming is preserved byte-for-byte when retries
//! are off). Every retry is charged against the upstream's rolling-window
//! retry budget; exhaustion fails requests through to the client.
//!
//! Authorization (DW-020): immediately after authN (and before rate
//! limiting), the request runs through the `authz` module's precedence
//! chain — consumer > route > service > listener > global
//! (`authz::AuthzChain`; every link has a config attachment:
//! `consumers[].authorization`, `routes[].authorization`,
//! `services[].authorization`, `listeners[].authorization`, and the
//! gateway-level `authorization`) — consumer/group/scope/claim rules
//! against the authenticated identity, IP ACLs against the EFFECTIVE
//! client IP (XFF-resolved behind a trusted proxy, see DW-009). A deny
//! at ANY level wins; otherwise the most specific level with rules
//! governs. Denials answer 403 (generic body, reason logged server-side
//! only); identity rules imply authentication, so an anonymous caller
//! gets 401. An `ip_acl`-only block is the one authorization shape that
//! can admit anonymous traffic.
//!
//! Local rate limiting (DW-017): after route resolution (and its
//! criteria checks) but BEFORE cap admission, the request runs through
//! the rate-limit engine (`RateLimitEngine`, built from the generation's
//! policies). Ordering rationale: rejecting early with a 429 is the
//! cheapest thing the gateway can do with a request, so it precedes the
//! more expensive admission layers; a 429 is emitted before any permit is
//! acquired, so rate-limited requests never hold a cap slot (though the
//! connection itself is held for the length of the response — accepted).
//! A denied request answers 429 with `Retry-After` (whole seconds,
//! rounded up, minimum 1) and `X-RateLimit-Limit` / `-Remaining` /
//! `-Reset` headers from the BINDING constraint (the window that denied;
//! see the rate_limiter module docs for stacked-window semantics).
//! Admitted requests whose policies matched carry the same three
//! `X-RateLimit-*` headers on their final response (only when a policy
//! actually applied — a no-match request carries no rate headers).
//! `X-RateLimit-Reset` is Unix epoch seconds of the binding window's
//! estimated full replenishment. Policy resolution follows the frozen
//! precedence chain consumer > route > service > listener > global:
//! every level with an attachment applies and the applicable rules
//! AND together; the resolution order binds the 429 headers (the first
//! denying rule wins them — see the rate_limiter module docs). UNROUTED
//! traffic (no route / criteria miss) is NOT exempt: the listener and
//! global links apply to it before the 404 is answered (rate limiting
//! at minimum; the consumer/route/service links are unknowable before
//! routing, and authentication sits after route resolution in the
//! documented order), so 404 floods cannot bypass the limiter. The
//! reserved paths (`/healthz`, `/readyz`, `/metrics`) stay exempt. When
//! several rules deny, Retry-After is the maximum wait across denying
//! rules while the Limit/Remaining headers come from the first binding
//! one (see the rate_limiter module docs for multi-rule denial
//! semantics). When rate headers are applied the GATEWAY is the source
//! of truth for `X-RateLimit-*`: any upstream values are silently
//! replaced.
//!
//! Observability (DW-021): every request opens a root `request` span
//! (request id, method, path WITHOUT the query string, consumer, route,
//! listener) with child spans per phase — authn, authz, ratelimit,
//! admission, and one `upstream_attempt` per send (the balancer's pick
//! runs inside it as `upstream_pick`). On completion the wrapper
//! records `requests_total`/`request_duration_seconds`, echoes
//! `X-Request-Id` (a valid inbound value respected, printable ASCII up
//! to 128 bytes; anything else replaced), and emits the sampled
//! `dwara::access` log line. `/metrics` is reserved on every HTTP(S)
//! listener like `/healthz` (it shadows configured routes). All
//! gateway-generated error bodies — including the reserved health
//! endpoints — are the JSON envelope `{"error":{code,message,
//! request_id}}` with classification-only messages (upstream internals
//! never leak). See the `observability` module for the full surface.
//! Load shedding by priority (DW-016): the gateway concurrency cap admits
//! requests ROUTE-AWARE — route resolution happens BEFORE cap admission
//! (so the request's priority class is known; 404s therefore never consume
//! cap slots, a deliberate change from DW-015's admit-at-entry ordering).
//! Priority classes are 0 (lowest) to 10 (highest); 5 is the default. The
//! design is a RESERVED BUCKET, not preemption — HTTP requests already in
//! flight cannot be displaced, so under saturation the gateway sheds
//! lower-priority ADMISSIONS first: requests at `high_priority` (>= 8) may
//! draw from a reserved sub-allowance of the cap (10% of the cap, minimum
//! one permit) that lower-priority traffic cannot use. Normal traffic is
//! shed (503 "gateway saturated") as soon as the general allowance fills;
//! high-priority traffic survives until the reserved bucket fills too.
//! The bucket is carved only when a high-priority ROUTE is configured
//! (priority >= 8; consumer priorities are inert until authN — DW-019 —
//! and never trigger carving), so priority-free configs behave
//! byte-identically to DW-015 (full cap for everyone, same shed
//! response). Sheds are 503, not 429 — 429 is reserved for rate limiting
//! (DW-017); no `Retry-After` is set (immediate re-dispatch under a
//! saturated gateway is not advised) and no shed marker header is added
//! (the response stays a plain 503 status + the error envelope). Every admission and shed
//! is counted per priority class in atomics on the dataplane
//! (`DataPlane::priority_counters`; metrics exposure is DW-021).
//!
//! Circuit breaking and caps (DW-015): three independent admission
//! layers wrap the send path. (1) The per-upstream BREAKER
//! (`upstreams[].breaker`, see `breaker`) is checked BEFORE the endpoint
//! pick and before every (re)attempt — an open upstream answers 503
//! "upstream circuit open" with a `Retry-After` of the seconds until
//! half-open; in-flight requests complete normally, and the breaker is a
//! layer ABOVE endpoint ejection (a fail-open pick still flows through
//! it; a breaker-open period ejects nothing, since health sees no
//! traffic). (2) The per-upstream PENDING cap (`upstreams[].max_pending`)
//! rejects requests that would have to WAIT for an outbound connection
//! slot: 503 "upstream saturated", immediately, no queueing (the default
//! is the DW-008 queue-forever behavior). (3) The GATEWAY concurrency cap
//! (`gateway.max_concurrent_requests`) admits requests at `handle()`
//! entry — after the reserved `/healthz`/`/readyz` paths, so probes
//! answer under saturation — rejecting over-cap requests with 503
//! "gateway saturated" immediately; a slot is released when the response
//! body completes (or the client connection drops).
//!
//! Upgrade forwarding on non-tunnel requests: an `Upgrade` header arriving
//! on an ordinary proxied request (no `101` ever comes back) is forwarded
//! upstream, together with its `Connection` tokens, rather than stripped.
//! This is deliberate: the upstream, not the gateway, decides protocol
//! switches — stripping `Upgrade` would break legitimate upgrades (h2c,
//! WebSocket handshakes that begin as a normal request) the moment the
//! upstream wanted to accept one. RFC-strict proxies that strip
//! connection-oriented headers wholesale would reject this; we chose
//! upgrade transparency, and the behavior is pinned by the coverage suite.
//!
//! Maintenance mode (DW-041): a route carrying a `maintenance` block is
//! answered by the GATEWAY, never the route action — a 503 carrying
//! `Retry-After` and the JSON envelope (`maintenance` code,
//! operator-optional message).
//! The check runs IMMEDIATELY after route resolution, BEFORE the route's
//! request limits: maintenance is a statement about the route's
//! availability, not about any request's shape, so every matched request
//! gets the same answer (an over-limit request is told "we're down", not
//! "your headers are too big" — fixing the headers would still leave it
//! refused) and the gateway skips evaluating limits for a request it will
//! refuse anyway. Preflights are the one exemption: a CORS preflight on
//! a CORS-configured route still answers 204 (the preflight is a Fetch
//! handshake about the gateway's own cross-origin policy, sent without
//! credentials; failing it surfaces in the browser as an opaque CORS
//! error and hides the 503 the operator wants clients to see on the
//! actual request — which DOES get 503, carrying the policy's
//! actual-response CORS headers so browser clients can read the
//! envelope). Reserved paths answer before route resolution and are
//! unaffected: probes and scrapes keep working through maintenance.
//! Toggled per generation by config reload; unrouted traffic is
//! unaffected (404 stays 404).
//!
//! Policy dry run (DW-041, monitor mode): every policy phase that can
//! reject supports a per-attachment `dry_run` flag — route limits
//! (`routes[].limits.dry_run`, 413/431), authorization
//! (`authorization.dry_run` at any of the five levels, 401/403), rate
//! limiting (`policies[].dry_run`, 429), and load shedding
//! (`gateway.load_shed_dry_run`, 503). A dry phase still EVALUATES, but
//! on a would-reject it logs one structured `dwara::policy` warn event
//! (phase, would-be status, reason, route, consumer, request id),
//! increments `dwara_policy_dry_run_total{phase,route}`, and lets the
//! request PROCEED. The invariant throughout: dry run never makes
//! enforcement more permissive — a LIVE deny always enforces (the authz
//! resolver walks past a dry deny and stops only at a live one; live
//! rate-limit bundles 429 regardless of dry bundles on the same
//! request). Dry rate-limit rules contribute no `X-RateLimit-*` headers;
//! a dry route-limits block leaves the streaming body guard unarmed
//! (only the cheap up-front checks are observable). Authentication
//! (401 on invalid/missing credentials, `auth_required`) is identity
//! verification, not a policy phase, and has no dry-run flag. The
//! metric + log events ARE the dry-run report (§9.3): no endpoint, no
//! buffer — scrape the counter and grep `dwara::policy`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use arc_swap::ArcSwap;
use http_body_util::Full;
use hyper::body::Body as _;
use hyper::body::Bytes;
use hyper::header::{
    HeaderMap, HeaderName, HeaderValue, ACCEPT_ENCODING, CONNECTION, COOKIE, HOST, LOCATION,
    ORIGIN, UPGRADE,
};
use hyper::{Request, Response, StatusCode, Version};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::Instrument as _;
use zeroize::Zeroizing;

use crate::config::net::peer_is_trusted;
use crate::config::{
    Consumer, Gateway, NameValueMatch, PathRewrite, Route, RouteAction, RouteMatch,
};
use crate::dataplane::upstream::{
    refresh_observation_gauges, UpstreamBody, UpstreamError, UpstreamRegistry,
};
use crate::extensions::rate_limiter::{RateLimitEngine, RateLimitOutcome};
use crate::observability::{self, AccessRecord, ListenerLabel, Observability};
use crate::resilience::retries::RetryParams;
use crate::security::authn::{
    AuthError, Authenticator, CompositeAuthenticator, Identity, JwksCacheEntry,
};
use crate::snapshot::RouteTable;
use crate::snapshot::{ConfigState, Snapshot};
use crate::state::store::StateStore;

/// Body type of every proxied/gateway-generated response: a small
/// fully-buffered gateway message (`Full`), the untouched streaming
/// upstream body ([`UpstreamBody`]: the pooled stream wrapped with the
/// DW-014 write-timeout / mid-body health-report knobs), or a route-
/// compressed stream ([`crate::dataplane::compression::CompressedBody`], DW-027 — the codec wrapper
/// around either of the other two).
pub enum ProxyBody {
    /// Small fully-buffered gateway message (envelope, respond action,
    /// metrics/health payloads).
    Full(Full<Bytes>),
    /// Untouched streaming upstream body.
    Upstream(UpstreamBody),
    /// Route-compressed response body (DW-027).
    Compressed(Box<crate::dataplane::compression::CompressedBody>),
}

/// Error of a [`ProxyBody`]: upstream stream failure or a compression
/// codec failure (DW-027). The `Full` variant is infallible.
#[derive(Debug)]
pub enum ProxyBodyError {
    /// The upstream stream died (DW-014 knobs report health on their
    /// way out; see [`UpstreamBody`]).
    Upstream(crate::dataplane::upstream::UpstreamBodyError),
    /// The compression codec failed mid-stream (DW-027). The stream
    /// ends like an upstream abort: already-forwarded frames stand,
    /// no synthesized tail.
    Io(std::io::Error),
}

impl std::fmt::Display for ProxyBodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyBodyError::Upstream(e) => write!(f, "{e}"),
            ProxyBodyError::Io(e) => write!(f, "compression failed: {e}"),
        }
    }
}

impl std::error::Error for ProxyBodyError {}

impl hyper::body::Body for ProxyBody {
    type Data = Bytes;
    type Error = ProxyBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, ProxyBodyError>>> {
        match self.get_mut() {
            ProxyBody::Full(b) => Pin::new(b).poll_frame(cx).map_err(|e| match e {}),
            ProxyBody::Upstream(b) => Pin::new(b).poll_frame(cx).map_err(ProxyBodyError::Upstream),
            ProxyBody::Compressed(b) => Pin::new(b.as_mut()).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            ProxyBody::Full(b) => b.is_end_stream(),
            ProxyBody::Upstream(b) => b.is_end_stream(),
            ProxyBody::Compressed(b) => b.is_end_stream(),
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        match self {
            ProxyBody::Full(b) => b.size_hint(),
            ProxyBody::Upstream(b) => b.size_hint(),
            ProxyBody::Compressed(b) => b.size_hint(),
        }
    }
}

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");
const X_RATELIMIT_LIMIT: HeaderName = HeaderName::from_static("x-ratelimit-limit");
const X_RATELIMIT_REMAINING: HeaderName = HeaderName::from_static("x-ratelimit-remaining");
const X_RATELIMIT_RESET: HeaderName = HeaderName::from_static("x-ratelimit-reset");
const WWW_AUTHENTICATE: HeaderName = HeaderName::from_static("www-authenticate");
const X_CONSUMER_NAME: HeaderName = HeaderName::from_static("x-consumer-name");

/// The default priority class (DW-016): requests on routes without an
/// explicit `priority` shed and are shed as class 5.
pub const DEFAULT_PRIORITY: u8 = 5;

/// The priority class at or above which a request may draw from the
/// gateway cap's reserved sub-allowance (DW-016).
pub const HIGH_PRIORITY: u8 = 8;

/// Per-priority-class admission/shed counters (DW-016). Plain atomics on
/// the dataplane — they survive config reloads (unlike the cap semaphores)
/// and are never reset. Exposure through the admin/metrics surface is
/// DW-021; tests read them directly.
#[derive(Debug, Default)]
pub struct PriorityCounters {
    admitted: [AtomicU64; 11],
    shed: [AtomicU64; 11],
}

impl PriorityCounters {
    fn record_admitted(&self, priority: u8) {
        self.admitted[priority as usize].fetch_add(1, Ordering::Relaxed);
    }

    fn record_shed(&self, priority: u8) {
        self.shed[priority as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Requests admitted (against the global cap, or with no cap
    /// configured) at the given priority class so far. Note for future
    /// metrics consumers (DW-021): the admitted counters CONFLATE
    /// capped and uncapped generations — a reload that toggles the cap
    /// changes which admissions are counted here mid-stream, and the
    /// counters are never reset to separate the eras.
    pub fn admitted_at(&self, priority: u8) -> u64 {
        self.admitted[priority as usize].load(Ordering::Relaxed)
    }

    /// Requests shed (rejected with 503 by the global cap) at the given
    /// priority class so far.
    pub fn shed_at(&self, priority: u8) -> u64 {
        self.shed[priority as usize].load(Ordering::Relaxed)
    }
}

/// Resolve a request's load-shedding priority class (DW-016). This is the
/// documented PRIORITY-RESOLVER seam: consumer (once known) overrides the
/// route, the route overrides the default. Today authentication is not
/// wired (DW-019/DW-020), so the caller passes `None` and priority is
/// purely route-level; once authN identifies the consumer, pass
/// `Some(consumer)` here and its `priority` wins over the route's — no
/// other change to the shedding path is needed.
pub fn resolve_priority(consumer: Option<&Consumer>, route: &Route) -> u8 {
    let p = consumer
        .and_then(|c| c.priority)
        .or(route.priority)
        .unwrap_or(DEFAULT_PRIORITY);
    // Validation rejects out-of-range values at compile time; this clamp
    // keeps the per-priority counters (11 slots) index-safe even for a
    // hand-built Route that never went through validation.
    p.min(10)
}

/// One configuration generation coupled with the upstream pools built from
/// it. Requests resolve routes AND upstreams from the same pair, so a
/// reload can never mix a new route table with old pools.
struct Generation {
    snapshot: Arc<Snapshot>,
    registry: Arc<UpstreamRegistry>,
}

/// The proxy dataplane: reads config generations from [`ConfigState`] and
/// keeps an [`UpstreamRegistry`] coupled to each generation.
///
/// Lifecycle: after every successful `compile_and_publish`, the operator
/// (dwara-bin's reload path) calls [`DataPlane::refresh`], which builds a
/// new generation pair and swaps it in atomically. In-flight requests hold
/// an `Arc` to the old pair, so old pools stay alive until the last request
/// using them completes — reloads drop nothing.
pub struct DataPlane {
    state: Arc<ConfigState>,
    current: ArcSwap<Generation>,
    /// Gateway concurrency cap (DW-015): `gateway.max_concurrent_requests`
    /// as a semaphore, rebuilt on every generation swap. None = unlimited
    /// (the default). In-flight permits hold an `Arc` to the semaphore they
    /// were drawn from, so a reload that changes (or removes) the cap never
    /// invalidates live admissions — new requests are admitted against the
    /// new cap.
    global_cap: ArcSwap<GlobalCap>,
    /// Per-priority admission/shed counters (DW-016). Lives on the
    /// dataplane (not the generation) so reloads never reset them.
    priority_counters: PriorityCounters,
    /// Rate-limit engine (DW-017), rebuilt on every generation swap.
    /// Governor's GCRA state lives inside it, so a reload resets all
    /// rate-limit buckets — accepted and documented: reloads are rare,
    /// and coupling buckets to the (rule-shaped) generation avoids
    /// lifetime questions when rules change or disappear.
    rate_limits: ArcSwap<RateLimitEngine>,
    /// Authenticator (DW-019), rebuilt on every generation swap from the
    /// new config (and the optional state store, set once at startup via
    /// [`DataPlane::set_state_store`], and the credential pepper set via
    /// [`DataPlane::set_credential_pepper`], #124).
    authn: ArcSwap<CompositeAuthenticator>,
    /// The DWARA_STATE_DB store when deployed; None = config-only
    /// credentials. Set once before serving; the authenticator rebuild
    /// reads it.
    state_store: std::sync::RwLock<Option<Arc<StateStore>>>,
    /// The per-deployment credential pepper (#124): raw bytes resolved
    /// ABOVE dwara-core's security domain — dwara-bin resolves the secret
    /// through the `SecretSource` extension seam and hands the bytes
    /// down, because `security` must not import `extensions`
    /// (`check_deps.py`). Arc-held so the authenticator rebuild shares
    /// the SAME Zeroizing buffer (no plain copy; the bytes zeroize when
    /// the last holder drops). SECRET: never logged, never in Debug.
    /// None = legacy-only mode (peppered stored hashes fail closed).
    credential_pepper: std::sync::RwLock<Option<Arc<Zeroizing<Vec<u8>>>>>,
    /// JWKS caches keyed by provider URL, carried ACROSS generation swaps
    /// so key rotation state survives reloads (DW-019).
    jwks_caches: std::sync::Mutex<HashMap<String, Arc<JwksCacheEntry>>>,
    /// HMAC replay-nonce store (DW-036), carried ACROSS generation swaps
    /// exactly like `jwks_caches`: a reload must never wipe remembered
    /// nonces (that would re-open the replay window mid-flight). Built
    /// once per dataplane (per-instance in M2 — see the authn module's
    /// replay boundary note); the authenticator rebuild shares the Arc.
    nonce_cache: Arc<crate::security::authn::NonceCache>,
    /// Observability state (DW-021): metrics families plus the access-log
    /// sampling knob. Per-dataplane (not global) so parallel tests never
    /// share a registry.
    obs: Arc<Observability>,
}

/// The gateway-level concurrency admission for one generation (DW-015 +
/// DW-016). `general: None` means unlimited (`max_concurrent_requests`
/// absent or 0). When set, `general` holds the permits available to ALL
/// traffic; `reserved` (when carved) holds a small sub-allowance of the
/// same cap usable ONLY by high-priority requests (>= [`HIGH_PRIORITY`])
/// once the general allowance is full.
#[derive(Clone, Default)]
struct GlobalCap {
    general: Option<Arc<Semaphore>>,
    reserved: Option<Arc<Semaphore>>,
}

/// Whether any ROUTE is high-priority (priority at or above
/// [`HIGH_PRIORITY`]). The reserved bucket is carved only when this holds,
/// so priority-free configs keep the full cap for everyone — behavior
/// identical to DW-015.
///
/// Consumer priorities deliberately contribute NOTHING to the carve
/// decision: consumer priority is inert until authN (DW-019/DW-020)
/// identifies the consumer on a request, so a config whose only
/// high-priority entry is a consumer would otherwise carve the general
/// allowance down (to the point of blackholing everything at a cap of 1)
/// while no traffic could ever draw from the reserved bucket.
/// DW-019 SEAM: when authN wires `Some(consumer)` into
/// [`resolve_priority`], extend this check with consumers as well.
fn has_high_priority(gateway: &Gateway) -> bool {
    gateway
        .routes
        .iter()
        .any(|r| r.priority.is_some_and(|p| p >= HIGH_PRIORITY))
}

/// The gateway-level concurrency admission for a snapshot's config: None
/// when `max_concurrent_requests` is absent or 0 (unlimited). With
/// high-priority traffic configured, 10% of the cap (minimum 1, capped at
/// the cap itself) is reserved: the general allowance shrinks to
/// `cap - bucket` and high-priority requests may draw from either.
fn global_cap_of(gateway: &Gateway) -> GlobalCap {
    let Some(cap) = gateway.max_concurrent_requests.filter(|c| *c > 0) else {
        return GlobalCap::default();
    };
    let cap = cap as usize;
    let bucket = if has_high_priority(gateway) {
        (cap / 10).max(1).min(cap)
    } else {
        0
    };
    GlobalCap {
        general: Some(Arc::new(Semaphore::new(cap - bucket))),
        reserved: if bucket > 0 {
            Some(Arc::new(Semaphore::new(bucket)))
        } else {
            None
        },
    }
}

impl DataPlane {
    /// Build from the state's currently published snapshot.
    pub fn new(state: Arc<ConfigState>) -> Arc<Self> {
        let snapshot = state.snapshot();
        let generation = snapshot.generation();
        let registry = Arc::new(UpstreamRegistry::from_snapshot(&snapshot));
        let global_cap = global_cap_of(snapshot.gateway());
        let rate_limits = RateLimitEngine::compile(snapshot.gateway());
        let dp = DataPlane {
            current: ArcSwap::from_pointee(Generation { snapshot, registry }),
            global_cap: ArcSwap::from_pointee(global_cap),
            priority_counters: PriorityCounters::default(),
            rate_limits: ArcSwap::from_pointee(rate_limits),
            authn: ArcSwap::from_pointee(CompositeAuthenticator::disabled()),
            state_store: std::sync::RwLock::new(None),
            credential_pepper: std::sync::RwLock::new(None),
            jwks_caches: std::sync::Mutex::new(HashMap::new()),
            nonce_cache: Arc::new(crate::security::authn::NonceCache::new()),
            obs: Arc::new(Observability::from_env()),
            state,
        };
        dp.obs.set_config_generation(generation);
        dp.rebuild_authn();
        Arc::new(dp)
    }

    /// Attach the DWARA_STATE_DB store (DWARA_STATE_DB deployments):
    /// credentials then come from the store's hot-cached records instead
    /// of in-memory config hashes. Call once, before serving traffic;
    /// rebuilds the authenticator against it immediately.
    pub fn set_state_store(&self, store: Arc<StateStore>) {
        *self.state_store.write().expect("state store lock poisoned") = Some(store);
        self.rebuild_authn();
    }

    /// The DWARA_STATE_DB store when one is attached (None = pure-config
    /// credentials). Admin surface seam (DW-022): `/stats` reports the
    /// store's schema version when present.
    pub fn state_store(&self) -> Option<Arc<StateStore>> {
        self.state_store
            .read()
            .expect("state store lock poisoned")
            .clone()
    }

    /// Attach the per-deployment credential pepper (#124). The bytes are
    /// resolved by the CALLER (dwara-bin, through the SecretSource
    /// extension seam — the security domain never touches extensions)
    /// and threaded down here; an empty slice is treated as "no pepper"
    /// (legacy-only mode). Call once, before serving traffic; rebuilds
    /// the authenticator against it immediately.
    pub fn set_credential_pepper(&self, pepper: Option<Vec<u8>>) {
        let pepper = pepper
            .filter(|p| !p.is_empty())
            .map(|p| Arc::new(Zeroizing::new(p)));
        *self
            .credential_pepper
            .write()
            .expect("credential pepper lock poisoned") = pepper;
        self.rebuild_authn();
    }

    /// The credential pepper for the authenticator rebuild: a clone of
    /// the Arc-held Zeroizing buffer (an Arc bump, NO byte copy; the
    /// authenticator keeps it alive until its next rebuild and the bytes
    /// zeroize when the last holder drops). Never logged.
    fn pepper_bytes(&self) -> Option<Arc<Zeroizing<Vec<u8>>>> {
        self.credential_pepper
            .read()
            .expect("credential pepper lock poisoned")
            .clone()
    }

    /// Rebuild the authenticator from the CURRENT snapshot and the
    /// attached state store (if any), reusing JWKS caches by URL.
    fn rebuild_authn(&self) {
        let store = self
            .state_store
            .read()
            .expect("state store lock poisoned")
            .clone();
        let pepper = self.pepper_bytes();
        let snapshot = self.state.snapshot();
        let mut caches = self.jwks_caches.lock().expect("jwks cache lock poisoned");
        let authn = CompositeAuthenticator::build(
            snapshot.gateway(),
            store,
            &mut caches,
            Some(&self.obs),
            pepper.as_ref(),
            Arc::clone(&self.nonce_cache),
        );
        self.authn.store(authn);
    }

    /// Rebuild the (snapshot, registry) pair from the state's current
    /// snapshot and swap it in. Call after every successful publish.
    /// Balancer state (in-flight counters, WRR phase, slow-start clocks
    /// for unchanged endpoint addresses) carries over from the previous
    /// generation, so weight/endpoint changes take effect without a
    /// restart and without resetting live counters (DW-011).
    ///
    /// Contract (#46): the authenticator rebuild re-resolves `${...}`
    /// secret references from the CURRENT snapshot's config, so a
    /// refresh is only meaningful after the publish that validated
    /// them. A bare refresh against a snapshot whose secret sources
    /// have since broken loud-skips the affected credentials BY DESIGN
    /// (the key stops authenticating; never stale plaintext). Both
    /// call sites — the binary's reload path and the admin publish
    /// path — invoke it only on the success side of a publish.
    pub fn refresh(&self) {
        let snapshot = self.state.snapshot();
        let generation = snapshot.generation();
        let registry = Arc::new(UpstreamRegistry::from_snapshot_with_previous(
            &snapshot,
            &self.current().registry,
        ));
        self.global_cap
            .store(Arc::new(global_cap_of(snapshot.gateway())));
        self.rate_limits
            .store(Arc::new(RateLimitEngine::compile(snapshot.gateway())));
        self.current
            .store(Arc::new(Generation { snapshot, registry }));
        self.obs.set_config_generation(generation);
        self.rebuild_authn();
    }

    fn current(&self) -> Arc<Generation> {
        self.current.load_full()
    }

    /// The per-priority admission/shed counters (DW-016). Metrics
    /// exposure (DW-021) reads these; tests read them directly.
    pub fn priority_counters(&self) -> &PriorityCounters {
        &self.priority_counters
    }

    /// This dataplane's observability state (DW-021): metric recording,
    /// /metrics rendering, and the access-log sampling knob.
    pub fn observability(&self) -> &Observability {
        &self.obs
    }

    /// The current generation's upstream registry. Used by the
    /// TLS-passthrough path (which picks endpoints through the same
    /// balancers) and by tests.
    pub fn registry(&self) -> Arc<UpstreamRegistry> {
        Arc::clone(&self.current().registry)
    }

    /// Whether the gateway is READY to serve: at least one config
    /// generation has been published successfully (generation >= 1). This
    /// is the `/readyz` definition (DW-013). Upstream health deliberately
    /// does NOT participate: a fully-ejected pool fail-opens rather than
    /// blackholing (DW-012), so readiness tracks the gateway's own state,
    /// not its backends'.
    pub fn ready(&self) -> bool {
        self.state.snapshot().generation() >= 1
    }
}

/// Reserved gateway paths (DW-013), served on EVERY listener BEFORE any
/// route resolution: `/healthz` answers 200 whenever the process is up
/// (liveness; a container orchestrator should restart it otherwise-false
/// cases, which only process death can produce), and `/readyz` answers 200
/// exactly when [`DataPlane::ready`] holds, 503 otherwise. Precedence:
/// these paths are NOT routable — a configured route matching `/healthz`
/// or `/readyz` (exact, regex, or prefix) is permanently shadowed, which
/// is accepted v1 behavior (documented; no conflict rejection). Applies
/// regardless of listener protocol, so a TLS-terminated listener serves
/// them too; TLS-passthrough listeners do not (they never speak HTTP).
fn reserved_path(dp: &DataPlane, path: &str, rid: &str) -> Option<Response<ProxyBody>> {
    match path {
        "/healthz" => Some(simple(StatusCode::OK, "ok", "ok", rid)),
        "/readyz" => {
            if dp.ready() {
                Some(simple(StatusCode::OK, "ready", "ready", rid))
            } else {
                Some(simple(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "not_ready",
                    "not ready",
                    rid,
                ))
            }
        }
        // Prometheus scrape endpoint (DW-021): reserved exactly like
        // /healthz (shadows any configured route; served on every HTTP(S)
        // listener; TLS-passthrough listeners never speak HTTP). The
        // state-derived gauges (breaker/endpoint health/fail-open) are
        // refreshed from the CURRENT generation at scrape time.
        "/metrics" => {
            let obs = &dp.obs;
            refresh_observation_gauges(&dp.current().registry, obs);
            let rate_limits = dp.rate_limits.load_full();
            refresh_rate_limiter_gauges(&rate_limits, obs);
            Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "text/plain; version=0.0.4")
                .body(ProxyBody::Full(Full::new(Bytes::from(obs.render()))))
                .ok()
        }
        _ => None,
    }
}

/// Refresh the rate-limiter observation gauges from the CURRENT
/// engine at scrape time (#132) — the same snapshot model as
/// [`refresh_observation_gauges`]: the walk lives on the dataplane
/// (the extensions-side engine must stay free of observability
/// imports), the hot check path stays pure atomics with zero metrics
/// coupling, and the observability side only records what it is
/// handed. Both gauges are aggregate and unlabeled — cardinality is
/// never per key. The eviction figure resets when a reload rebuilds
/// the engine (documented family caveat).
pub fn refresh_rate_limiter_gauges(engine: &RateLimitEngine, obs: &Observability) {
    obs.set_rate_limiter_evictions(engine.evictions() as i64);
    obs.set_rate_limiter_live_keys(engine.live_keys() as i64);
}

/// The response for UNROUTED traffic (#123): a request whose path
/// resolved to no route (no path match, a dangling route index, or a
/// non-path criteria miss) is still subject to the LISTENER- and
/// GLOBAL-attached policies before its 404 is answered — the documented
/// gap that unrouted 404 floods bypassed rate limiting entirely. Only
/// those two links apply: the consumer, route, and service links are
/// unknowable before routing, and the documented request-path order
/// places authentication (and therefore identity) after route
/// resolution. A denied request answers 429 exactly like routed traffic
/// (`Retry-After` + the binding rule's `X-RateLimit-*` headers); an
/// admitted-but-unrouted request carries the rate headers on its 404
/// (the same "only when a policy actually matched" rule as routed
/// responses). The reserved paths never reach here. The `route` key
/// component of the rate context is the empty string (see
/// `RateLimitKeyContext::route`).
fn unrouted_response(
    dp: &DataPlane,
    gateway: &Gateway,
    listener_cfg: Option<&crate::config::Listener>,
    peer: IpAddr,
    rid: &str,
    rec: &mut AccessRecord,
) -> Response<ProxyBody> {
    let listener_policies: &[String] = listener_cfg.map(|l| l.policies.as_slice()).unwrap_or(&[]);
    let global_policies: &[String] = &gateway.global_policies;
    if listener_policies.is_empty() && global_policies.is_empty() {
        return simple(StatusCode::NOT_FOUND, "no_route", "no route", rid);
    }
    let engine = dp.rate_limits.load_full();
    if engine.is_empty() {
        return simple(StatusCode::NOT_FOUND, "no_route", "no route", rid);
    }
    let ctx = crate::extensions::rate_limiter::RateLimitKeyContext {
        peer,
        consumer: None,
        route: "",
    };
    // Dry-run bundles (DW-041) observe here exactly as on routed traffic
    // (route label "unrouted"); live bundles alone decide the 429.
    let evaluation = engine.evaluate(&ctx, &[], &[], &[], listener_policies, global_policies);
    if let Some(crate::extensions::rate_limiter::RateLimitOutcome::Denied {
        retry_after_s, ..
    }) = evaluation.dry_denied
    {
        dp.obs.record_policy_dry_run("rate_limit", "unrouted");
        dp.obs.emit_policy_dry_run(
            "rate_limit",
            429,
            "unrouted",
            None,
            rid,
            &format!("rate limit would deny (retry after {retry_after_s}s)"),
        );
    }
    match evaluation.outcome {
        crate::extensions::rate_limiter::RateLimitOutcome::Denied {
            limit,
            remaining,
            reset_epoch_s,
            retry_after_s,
        } => {
            rec.rate_limited = true;
            dp.obs.record_rate_limited("unrouted");
            rate_limited(limit, remaining, reset_epoch_s, retry_after_s, rid)
        }
        crate::extensions::rate_limiter::RateLimitOutcome::Allowed {
            limit,
            remaining,
            reset_epoch_s,
        } => {
            let mut resp = simple(StatusCode::NOT_FOUND, "no_route", "no route", rid);
            apply_rate_headers(resp.headers_mut(), limit, remaining, reset_epoch_s);
            resp
        }
        crate::extensions::rate_limiter::RateLimitOutcome::NotLimited => {
            simple(StatusCode::NOT_FOUND, "no_route", "no route", rid)
        }
    }
}

/// Handle one request against the current generation. Never panics; every
/// failure path is a classified response. Generic over the request body so
/// tests and alternative frontends can drive it with any streaming body.
///
/// Observability wrapper (DW-021): resolves the request ID (valid inbound
/// `X-Request-Id` respected, else generated), opens the root `request`
/// span, tracks the active-requests gauge, and — on completion — records
/// the request counter/latency histogram, echoes `X-Request-Id`, and
/// emits the (sampled) access-log line. Reserved paths (`/healthz`,
/// `/readyz`, `/metrics`) count under the "unrouted" route label like
/// 404s (they are not routes).
pub async fn handle<B>(dp: &DataPlane, peer: IpAddr, req: Request<B>) -> Response<ProxyBody>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let started = std::time::Instant::now();
    let obs = &dp.obs;
    // Path WITHOUT the query string everywhere it is recorded
    // (redaction: query strings carry tokens).
    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();
    let listener = req
        .extensions()
        .get::<ListenerLabel>()
        .map(|l| l.0.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let request_id = observability::resolve_request_id(req.headers());
    let root = tracing::info_span!(
        "request",
        request_id = %request_id,
        method = %method,
        path = %path,
        listener = %listener,
        consumer = tracing::field::Empty,
        route = tracing::field::Empty
    );
    let mut rec = AccessRecord::new(request_id.clone(), method, path, listener);
    obs.active_requests().inc();
    let mut resp = handle_inner(dp, peer, req, &request_id, &mut rec, &root)
        .instrument(root.clone())
        .await;
    obs.active_requests().dec();
    let status = resp.status().as_u16();
    rec.status = status;
    rec.duration_ms = started.elapsed().as_secs_f64() * 1000.0;
    obs.record_request(&rec.route, &rec.listener, status, started.elapsed());
    observability::stamp_request_id(resp.headers_mut(), &request_id);
    if obs.should_log_access(status) {
        observability::emit_access(&rec);
    }
    resp
}

async fn handle_inner<B>(
    dp: &DataPlane,
    peer: IpAddr,
    mut req: Request<B>,
    rid: &str,
    rec: &mut AccessRecord,
    root: &tracing::Span,
) -> Response<ProxyBody>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let gen = dp.current();
    let gateway = gen.snapshot.gateway();
    let path = req.uri().path().to_string();

    // Framing ambiguity rejection (DW-023): hyper's HTTP/1 parser gives
    // Transfer-Encoding precedence over Content-Length (RFC 7230 3.3.3
    // "careful" framing), which is desync-SAFE behind this gateway because
    // every forwarded request is rebuilt from parsed parts — but the
    // AMBIGUOUS header pair is itself the smuggling primitive, so the
    // documented policy is outright rejection: a request carrying both
    // headers never reaches a route or an upstream. (Response-side and
    // h2 paths are unaffected; hyper never synthesizes the pair.)
    //
    // UNREACHABLE BY DESIGN — belt-and-suspenders insurance: the
    // pre-parse sniff (hardening::guard_connection) rejects the pair on
    // the first head of every connection, hyper's parser refuses it on
    // any later keep-alive head, and even a surviving pair would lose
    // its Content-Length to hyper's TE-preference normalization before
    // this handler runs. The check stays so a future parser change that
    // alters any of those layers (e.g. TE-preference no longer stripping
    // the redundant Content-Length) fails CLOSED here instead of quietly
    // re-admitting the smuggling primitive to the route layer.
    if req.headers().contains_key(hyper::header::CONTENT_LENGTH)
        && req.headers().contains_key(hyper::header::TRANSFER_ENCODING)
    {
        tracing::warn!(
            code = "request_framing_ambiguous",
            request_id = %rid,
            "request carries both Content-Length and Transfer-Encoding; rejecting"
        );
        return simple(
            StatusCode::BAD_REQUEST,
            "ambiguous_framing",
            "request declares both Content-Length and Transfer-Encoding",
            rid,
        );
    }

    // Reserved gateway paths first: they shadow any configured route.
    if let Some(resp) = reserved_path(dp, &path, rid) {
        return resp;
    }

    // The listener that accepted this request (#123): its policies and
    // authorization apply to every request it accepts. The label rides
    // the request extensions from the listener frontend (dwara-bin);
    // absent when `handle` is driven directly (tests) — no listener
    // config matches, so listener-level rules are transparent, exactly
    // like the "unknown" metrics label.
    let listener_cfg = req.extensions().get::<ListenerLabel>().and_then(|l| {
        gateway
            .listeners
            .iter()
            .find(|li| li.name.as_str() == &*l.0)
    });

    // Route resolution BEFORE cap admission (DW-016): the request's
    // priority class comes from the matched route, so the cap can shed
    // route-aware. Two consequences: 404s (no route / criteria miss) never
    // consume a cap slot — a deliberate change from DW-015's
    // admit-at-entry ordering — and unknown paths cost nothing under
    // saturation.
    let Some((idx, params)) = gen.snapshot.route_table().find_full(&path) else {
        return unrouted_response(dp, gateway, listener_cfg, peer, rid, rec);
    };
    let Some(route) = gateway.routes.get(idx) else {
        return unrouted_response(dp, gateway, listener_cfg, peer, rid, rec);
    };

    if !route_applies(
        &route.r#match,
        gen.snapshot.route_table().accept_media_type(idx),
        &req,
    ) {
        return unrouted_response(dp, gateway, listener_cfg, peer, rid, rec);
    }
    rec.route = route.name.clone();
    root.record("route", route.name.as_str());

    // Maintenance mode (DW-041): the earliest post-resolution
    // short-circuit — see the module docs for why it precedes the route
    // limits and why CORS preflights are the one exemption (they keep
    // their 204 so browser clients can read the 503 envelope on the
    // actual request, which carries the policy's CORS headers).
    if let Some(maintenance) = &route.maintenance {
        let preflight_exempt = route.cors.is_some()
            && crate::dataplane::cors::is_preflight(req.method(), req.headers());
        if !preflight_exempt {
            tracing::warn!(
                code = "maintenance",
                request_id = %rid,
                route = %route.name,
                retry_after_secs = maintenance.retry_after(),
                "route is in maintenance; request refused with 503"
            );
            let origin = req.headers().get(&ORIGIN).cloned();
            return maintenance_response(route, idx, &gen, origin.as_ref(), maintenance, rid);
        }
    }

    // Route-scoped request limits (DW-027): header caps and a declared
    // (`Content-Length`) body cap are enforced immediately after route
    // resolution — before CORS preflight handling, authentication, and
    // any upstream contact. 431 for headers, 413 for the body, both in
    // the JSON error envelope. Monitor mode (DW-041, `limits.dry_run`):
    // the violation is logged and counted instead, and the request
    // proceeds (the streaming body guard is left unarmed below).
    if let Some(limits) = &route.limits {
        if let Some(violation) = crate::dataplane::hardening::check_route_limits(
            limits,
            req.headers(),
            req.body().size_hint().exact(),
        ) {
            let (status, code, msg) = match violation {
                crate::dataplane::hardening::RouteLimitViolation::HeaderCount { count, max } => (
                    StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                    "request_headers_too_large",
                    format!("request carries {count} header fields; the route allows {max}"),
                ),
                crate::dataplane::hardening::RouteLimitViolation::HeaderBytes { bytes, max } => (
                    StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                    "request_headers_too_large",
                    format!("request headers total {bytes} bytes; the route allows {max}"),
                ),
                crate::dataplane::hardening::RouteLimitViolation::BodyBytes { declared, max } => (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request_body_too_large",
                    format!("request body declares {declared} bytes; the route allows {max}"),
                ),
            };
            // Dry-run note: this phase runs before authn, so the log's
            // consumer field is always "anonymous" here — it reflects
            // evaluation order, not that the traffic was unauthenticated.
            if limits.dry_run {
                dp.obs.record_policy_dry_run("route_limits", &route.name);
                dp.obs.emit_policy_dry_run(
                    "route_limits",
                    status.as_u16(),
                    &route.name,
                    None,
                    rid,
                    &msg,
                );
            } else {
                tracing::warn!(
                    code = code,
                    request_id = %rid,
                    route = %route.name,
                    "request rejected by route limits"
                );
                return simple(status, code, &msg, rid);
            }
        }
    }

    // CORS preflight short-circuit (DW-027): an OPTIONS request with the
    // preflight markers is answered by the gateway on CORS-configured
    // routes — never forwarded upstream, never subject to authn/authz/
    // rate limiting/cap admission (browsers send preflights without
    // credentials; gating them on authn would break every credentialed
    // route). Routes without a cors block proxy preflights normally.
    if let Some(cors) = &route.cors {
        if crate::dataplane::cors::is_preflight(req.method(), req.headers()) {
            // The origin set is compiled in lockstep with `Route::cors`
            // (RouteTable::cors_origins); a None here is unreachable for
            // a published snapshot and falls through to a normal proxy.
            if let Some(origins) = gen.snapshot.route_table().cors_origins(idx) {
                return crate::dataplane::cors::preflight_response(cors, origins, req.headers())
                    .map(ProxyBody::Full);
            }
        }
    }

    // Authentication (DW-019): after route resolution, before rate
    // limiting and cap admission (the rate-limit `credential` selector
    // and the shedding priority class both consume the identity). An
    // INVALID presented credential is always rejected (401 +
    // WWW-Authenticate), even on a route that allows anonymous traffic;
    // an anonymous request is rejected only when the route sets
    // `auth_required`. Gateway-side failures (JWKS endpoint down) answer
    // 500 — the gateway cannot vouch for the caller either way.
    let authn = dp.authn.load_full();
    // The ambient mTLS family (#124): the accepting TLS listener (when
    // it carries a client_ca_file) inserts the VERIFIED client
    // certificate into the request extensions; absent on cleartext
    // listeners and connections that presented none.
    let client_cert = req
        .extensions()
        .get::<Arc<crate::security::authn::ClientCertificate>>()
        .cloned();
    // The authn phase span (DW-021): instrumented onto the authenticate
    // future so the span covers exactly the phase (no guard is held
    // across a poll boundary). The request target (method/path/query)
    // rides along for the HMAC family (DW-036), which signs it; the
    // body deliberately does not (authn never buffers — the HMAC body
    // digest is enforced on the forward path below).
    let authn_req = crate::security::authn::AuthnRequest {
        method: req.method(),
        uri: req.uri(),
        headers: req.headers(),
        client_cert: client_cert.as_deref(),
    };
    let identity = match authn
        .authenticate(&authn_req)
        .instrument(tracing::info_span!("authn"))
        .await
    {
        Ok(id) => id,
        Err(AuthError::Invalid(_)) => return unauthorized(&authn.challenge(), rid),
        Err(AuthError::Unavailable(msg)) => {
            tracing::error!(
                code = "authentication_unavailable",
                request_id = %rid,
                "authentication backend unavailable: {msg}"
            );
            return simple(
                StatusCode::INTERNAL_SERVER_ERROR,
                "authentication_unavailable",
                "authentication unavailable",
                rid,
            );
        }
    };
    if route.auth_required && identity.is_none() {
        return unauthorized(&authn.challenge(), rid);
    }
    if let Some(id) = &identity {
        rec.consumer = id.consumer_name.clone();
        root.record("consumer", id.consumer_name.as_str());
    }
    // Spoof prevention: any client-supplied X-Consumer-* header is
    // stripped here; the trusted identity header is injected on the
    // proxied request below.
    strip_consumer_headers(req.headers_mut());
    let consumer_cfg = identity.as_ref().and_then(|id| {
        gateway
            .consumers
            .iter()
            .find(|c| c.name == id.consumer_name)
    });
    // The route's service: resolved here (before authorization and rate
    // limiting) because both consume its attachments (#123 — service
    // authorization and service policies). Validation guarantees the
    // reference resolves; a miss is a generation tear and simply means
    // no service-level rules apply (the proxy send below answers 500 on
    // the same tear).
    let service = gateway.services.iter().find(|s| s.name == route.service);

    // Authorization (DW-020): after authN, before rate limiting. The
    // precedence chain is consumer > route > service > listener >
    // global; every link has a config attachment (#123):
    // `consumers[].authorization`, `routes[].authorization`,
    // `services[].authorization`, `listeners[].authorization`, and the
    // gateway-level `authorization`. A deny at ANY level wins;
    // otherwise the most specific level with rules governs. Denials of
    // authenticated (or IP-gated anonymous) requests are 403; identity
    // rules imply authentication (anonymous -> 401 with the challenge).
    // The IP ACL is evaluated against the EFFECTIVE client IP: the
    // X-Forwarded-For-resolved client when the peer is a trusted proxy
    // (DW-009 chain), else the peer. No reason detail reaches the
    // client (generic 403 body).
    let consumer_authz = consumer_cfg.and_then(|c| c.authorization.as_ref());
    let service_authz = service.and_then(|s| s.authorization.as_ref());
    let listener_authz = listener_cfg.and_then(|l| l.authorization.as_ref());
    let global_authz = gateway.authorization.as_ref();
    // The authz phase span (DW-021) opens unconditionally — the phase
    // runs on every routed request (a chain with no rules allows), and
    // the trace contract pins its presence. Resolution is level-aware
    // (DW-041): a `dry_run` attachment's deny is reported
    // (`Resolved::would_deny`) instead of enforced, and the walk inside
    // the resolver guarantees a LIVE deny at any level still wins.
    let authz_resolved = {
        let _authz_phase = tracing::info_span!("authz").entered();
        if consumer_authz.is_some()
            || route.authorization.is_some()
            || service_authz.is_some()
            || listener_authz.is_some()
            || global_authz.is_some()
        {
            let inbound_xff = req
                .headers()
                .get(&X_FORWARDED_FOR)
                .and_then(|v| v.to_str().ok());
            let effective_ip = crate::security::authz::effective_client_ip(
                &gateway.trusted_proxies,
                peer,
                inbound_xff,
            );
            let authz_ctx = crate::security::authz::AuthzContext {
                identity: identity.as_ref(),
                // Groups ride the identity (#124): config consumers from
                // the config record, store-managed consumers from the
                // store — one source for both, so group rules apply
                // uniformly.
                consumer_groups: identity
                    .as_ref()
                    .map(|id| id.groups.as_slice())
                    .unwrap_or(&[]),
                peer_ip: peer,
                effective_ip,
            };
            let chain = crate::security::authz::AuthzChain {
                consumer: consumer_authz,
                route: route.authorization.as_ref(),
                service: service_authz,
                listener: listener_authz,
                global: global_authz,
            };
            crate::security::authz::resolve(&chain, &authz_ctx)
        } else {
            crate::security::authz::Resolved {
                decision: crate::security::authz::Decision::Allow,
                would_deny: None,
            }
        }
    };
    if let Some((level, decision)) = &authz_resolved.would_deny {
        let crate::security::authz::Decision::Deny {
            unauthenticated,
            reason,
        } = decision
        else {
            unreachable!("would_deny only carries Deny decisions")
        };
        dp.obs.record_policy_dry_run("authz", &route.name);
        dp.obs.emit_policy_dry_run(
            "authz",
            if *unauthenticated { 401 } else { 403 },
            &route.name,
            identity.as_ref().map(|id| id.consumer_name.as_str()),
            rid,
            &format!(
                "authorization deny at {} level (dry-run): {reason}",
                level.as_str()
            ),
        );
    }
    match authz_resolved.decision {
        crate::security::authz::Decision::Allow => {}
        crate::security::authz::Decision::Deny {
            unauthenticated: true,
            ..
        } => return unauthorized(&authn.challenge(), rid),
        crate::security::authz::Decision::Deny { reason, .. } => {
            // Reason is server-side only: which list matched, which claim
            // was absent — none of it is the client's business.
            tracing::warn!(
                code = "authorization_denied",
                request_id = %rid,
                route = %route.name,
                consumer = %identity
                    .as_ref()
                    .map(|id| id.consumer_name.as_str())
                    .unwrap_or("<anonymous>"),
                "authorization denied: {reason}"
            );
            return forbidden(rid);
        }
    }

    // Local rate limiting (DW-017): BEFORE cap admission — a 429 is the
    // cheapest rejection the gateway can emit, so it precedes the permit
    // acquisition below (rate-limited requests never hold a cap slot).
    // Policy resolution: consumer (DW-019) > route > service > listener
    // > global; all applicable rules AND together, and the resolution
    // order binds the 429 headers. The `credential` selector falls back
    // to the peer IP until authN identifies consumers.
    let service_policies: &[String] = service.map(|s| s.policies.as_slice()).unwrap_or(&[]);
    let consumer_policies: &[String] = consumer_cfg.map(|c| c.policies.as_slice()).unwrap_or(&[]);
    let listener_policies: &[String] = listener_cfg.map(|l| l.policies.as_slice()).unwrap_or(&[]);
    // The ratelimit phase span (DW-021); sync bookkeeping, so a plain
    // entered guard is correct (nothing is awaited under it). Dry-run
    // bundles (DW-041) report their would-be denial through the same
    // evaluation; live bundles alone decide the 429 and the headers.
    let rate_headers = {
        let _ratelimit_phase = tracing::info_span!("ratelimit").entered();
        let engine = dp.rate_limits.load_full();
        if engine.is_empty() {
            None
        } else {
            let ctx = crate::extensions::rate_limiter::RateLimitKeyContext {
                peer,
                consumer: identity.as_ref().map(|id| id.consumer_name.as_str()),
                route: &route.name,
            };
            let evaluation = engine.evaluate(
                &ctx,
                consumer_policies,
                &route.policies,
                service_policies,
                listener_policies,
                &gateway.global_policies,
            );
            if let Some(RateLimitOutcome::Denied { retry_after_s, .. }) = evaluation.dry_denied {
                dp.obs.record_policy_dry_run("rate_limit", &route.name);
                dp.obs.emit_policy_dry_run(
                    "rate_limit",
                    429,
                    &route.name,
                    identity.as_ref().map(|id| id.consumer_name.as_str()),
                    rid,
                    &format!("rate limit would deny (retry after {retry_after_s}s)"),
                );
            }
            match evaluation.outcome {
                RateLimitOutcome::Denied {
                    limit,
                    remaining,
                    reset_epoch_s,
                    retry_after_s,
                } => {
                    rec.rate_limited = true;
                    dp.obs.record_rate_limited(&route.name);
                    return rate_limited(limit, remaining, reset_epoch_s, retry_after_s, rid);
                }
                RateLimitOutcome::Allowed {
                    limit,
                    remaining,
                    reset_epoch_s,
                } => Some((limit, remaining, reset_epoch_s)),
                RateLimitOutcome::NotLimited => None,
            }
        }
    };

    // Gateway concurrency cap with priority-aware load shedding
    // (DW-015 + DW-016). Admission is two-tier: every request tries the
    // general allowance; a request at or above HIGH_PRIORITY may then try
    // the reserved bucket (when one is carved). No permits anywhere ->
    // 503 "gateway saturated" immediately (no queueing, no Retry-After —
    // see the module docs for the 503-vs-429 and header choices). The
    // permit lives until the response body completes: the proxy path
    // attaches it to the streaming body, and complete bodies (errors,
    // redirects, respond actions) release it when this scope ends.
    //
    // AuthN (DW-019) supplies the consumer here: its priority overrides
    // the route's when the authenticated consumer declares one.
    let priority = resolve_priority(consumer_cfg, route);
    let cap = dp.global_cap.load_full();
    // The admission phase span (DW-021); sync permit bookkeeping.
    let mut global_permit = {
        let _admission_phase = tracing::info_span!("admission").entered();
        match &cap.general {
            None => {
                // Unlimited: no admission decision, but still counted per
                // priority class (the counters describe traffic mix, not only
                // capped traffic).
                dp.priority_counters.record_admitted(priority);
                None
            }
            Some(general) => {
                let admitted = Arc::clone(general).try_acquire_owned().ok().or_else(|| {
                    // General allowance full: high-priority traffic may
                    // draw from the reserved bucket; everything else is
                    // shed. This is reserved-capacity admission, NOT
                    // preemption — in-flight normal requests keep their
                    // slots until they complete.
                    if priority >= HIGH_PRIORITY {
                        cap.reserved
                            .as_ref()
                            .and_then(|bucket| Arc::clone(bucket).try_acquire_owned().ok())
                    } else {
                        None
                    }
                });
                match admitted {
                    Some(permit) => {
                        dp.priority_counters.record_admitted(priority);
                        Some(permit)
                    }
                    None => {
                        // Monitor mode (DW-041): the would-shed is logged
                        // and counted, and the request is admitted OVER
                        // the cap (no permit) — the point is observing
                        // what a cap would shed before enforcing it, so
                        // over-admission is the documented trade, not an
                        // accident.
                        if gateway.load_shed_dry_run {
                            dp.priority_counters.record_admitted(priority);
                            dp.obs.record_policy_dry_run("load_shed", &route.name);
                            dp.obs.emit_policy_dry_run(
                                "load_shed",
                                503,
                                &route.name,
                                identity.as_ref().map(|id| id.consumer_name.as_str()),
                                rid,
                                &format!(
                                    "gateway concurrency cap saturated at priority {priority}; \
                                     request would have been shed (dry-run) and is admitted \
                                     over the cap"
                                ),
                            );
                            None
                        } else {
                            dp.priority_counters.record_shed(priority);
                            rec.shed = true;
                            dp.obs.record_shed(priority);
                            tracing::warn!(
                                code = "gateway_saturated",
                                request_id = %rid,
                                priority = priority,
                                "gateway concurrency cap saturated; request shed"
                            );
                            return simple(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "gateway_saturated",
                                "gateway saturated",
                                rid,
                            );
                        }
                    }
                }
            }
        }
    };

    // Response edge policies (DW-027) consume request header values the
    // actions below take ownership of — capture them first.
    let req_origin = req.headers().get(&ORIGIN).cloned();
    let req_accept_encoding = req
        .headers()
        .get(&ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let mut resp = match &route.action {
        RouteAction::Proxy { .. } => {
            // Streaming body limit (DW-027): the counting wrapper (a
            // thin passthrough when the route sets no cap; the
            // declared-length half was rejected above) guards requests
            // of unknown length for the whole proxy path.
            //
            // Signed-body digest enforcement (DW-036): an
            // HMAC-authenticated request carries the digest its
            // signature bound — the digesting wrapper folds every
            // streamed frame into a SHA-256 (nothing buffered) and
            // aborts the upstream send when the final hash disagrees.
            // It sits INSIDE the route's limit wrapper, so an over-cap
            // body is still rejected 413 first; every other request
            // (no signed digest) streams through unchanged.
            let signed_digest = identity.as_ref().and_then(|id| id.body_digest);
            // Eager verdict for a signed body declaring EXACTLY zero
            // bytes: hyper's h1 encoder never polls it (see
            // DigestingBody's docs), so a digest mismatch there has
            // no mid-stream abort to surface through — refuse with
            // the family's 401 before the request is forwarded at
            // all. A correct empty digest forwards normally; unsigned
            // requests are unaffected.
            let (parts, body) = req.into_parts();
            let digesting = crate::dataplane::hardening::DigestingBody::new(body, signed_digest);
            if digesting.eager_digest_mismatch() {
                tracing::warn!(
                    code = "signature_body_mismatch",
                    request_id = %rid,
                    "signed empty request body did not match its digest; refused before forward"
                );
                unauthorized(crate::security::authn::HMAC_CHALLENGE, rid)
            } else {
                let req = Request::from_parts(
                    parts,
                    crate::dataplane::hardening::LimitedBody::new(
                        digesting,
                        // A dry-run limits block (DW-041) leaves the
                        // streaming guard unarmed: the cap is monitor
                        // mode, so a body that would have been aborted
                        // mid-stream flows through.
                        route
                            .limits
                            .as_ref()
                            .filter(|l| !l.dry_run)
                            .and_then(|l| l.max_body_bytes),
                    ),
                );
                proxy_request(
                    &gen,
                    peer,
                    req,
                    route,
                    idx,
                    &params,
                    &mut global_permit,
                    identity.as_ref(),
                    rid,
                    rec,
                    &dp.obs,
                )
                .await
            }
        }
        RouteAction::Redirect {
            scheme,
            host,
            path: redirect_path,
            status,
        } => redirect(
            &req,
            scheme.as_deref(),
            host.as_deref(),
            redirect_path.as_deref(),
            *status,
            rid,
        ),
        RouteAction::Respond {
            status,
            body,
            headers,
        } => respond(*status, body.as_deref(), headers),
    };

    // Response compression (DW-027): route-scoped, negotiated against
    // the captured Accept-Encoding, applied after the action so every
    // action reports identically. The content-type filter is compiled
    // in lockstep with `Route::compression` (RouteTable::
    // compression_types; None is unreachable and reads as "skip",
    // landing in the Vary-only branch below). The body's exact size
    // hint gates `min_size` for header-less gateway bodies (respond,
    // redirect); unknown-length streams are always candidates.
    // Already-encoded responses are left entirely untouched; every
    // other response on the route carries at least `Vary:
    // Accept-Encoding` (a candidate response must not be cached under
    // another client's coding).
    if let Some(policy) = &route.compression {
        let already_encoded = resp.headers().contains_key(hyper::header::CONTENT_ENCODING);
        if !already_encoded {
            let decision = gen
                .snapshot
                .route_table()
                .compression_types(idx)
                .and_then(|types| {
                    crate::dataplane::compression::decide(
                        policy,
                        types,
                        resp.status(),
                        resp.headers(),
                        resp.body().size_hint().exact(),
                        req_accept_encoding.as_deref(),
                    )
                });
            match decision {
                Some(plan) => {
                    resp = crate::dataplane::compression::wrap_response(resp, &plan);
                }
                None => {
                    crate::dataplane::hardening::merge_vary(resp.headers_mut(), "Accept-Encoding")
                }
            }
        }
    }

    // API versioning aids (DW-048), both applied after the action (and
    // after compression wrapping — the codec rewrites only
    // Content-Length/Content-Encoding/Vary, so headers stamped here
    // survive verbatim; Vary merges compose):
    // - a route selected by `match.accept` varies with the request's
    //   Accept, so shared caches must key on it (`Vary: Accept`, merged
    //   with any CORS/compression Vary the response already carries);
    // - the route's deprecation policy stamps Deprecation (RFC 9745),
    //   Sunset (RFC 8594), and the Link;rel=deprecation companion on
    //   every action response (not on gateway short-circuits —
    //   maintenance 503s, 413/431 limits, preflights, 401/403/429,
    //   sheds — those describe the request or the route's
    //   availability, not the route's lifecycle).
    if route.r#match.accept.is_some() {
        crate::dataplane::hardening::merge_vary(resp.headers_mut(), "Accept");
    }
    if let Some(dep) = gen.snapshot.route_table().deprecation(idx) {
        crate::dataplane::versioning::decorate(resp.headers_mut(), dep);
    }

    // CORS actual-response decoration (DW-027): policy headers on every
    // response of a CORS route whose request origin is allowed.
    if let Some(cors) = &route.cors {
        if let Some(origins) = gen.snapshot.route_table().cors_origins(idx) {
            crate::dataplane::cors::decorate_actual(
                cors,
                origins,
                req_origin.as_ref(),
                resp.headers_mut(),
            );
        }
    }
    // Admitted requests carry the binding constraint's rate headers (only
    // when a policy actually matched — see DW-017 module docs). Applied
    // after the action so every action (including streaming proxy bodies
    // and 101 upgrades) reports identically.
    if let Some((limit, remaining, reset_epoch_s)) = rate_headers {
        apply_rate_headers(resp.headers_mut(), limit, remaining, reset_epoch_s);
    }
    resp
}

/// The 503 maintenance response (DW-041): `Retry-After` in whole seconds
/// plus the uniform JSON envelope with the `maintenance` code and the
/// operator-optional message. On a CORS-configured route whose request
/// origin is allowed, the policy's actual-response CORS headers are
/// applied so a browser client can READ the envelope cross-origin (the
/// companion of the preflight exemption — see the module docs).
fn maintenance_response(
    route: &Route,
    idx: usize,
    gen: &Generation,
    origin: Option<&HeaderValue>,
    maintenance: &crate::config::Maintenance,
    rid: &str,
) -> Response<ProxyBody> {
    let mut resp = Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(
            hyper::header::RETRY_AFTER,
            maintenance.retry_after().to_string(),
        )
        .body(ProxyBody::Full(Full::new(observability::envelope_body(
            "maintenance",
            maintenance.message(),
            rid,
        ))))
        .expect("static 503 response is valid");
    if let (Some(cors), Some(origins)) = (
        route.cors.as_ref(),
        gen.snapshot.route_table().cors_origins(idx),
    ) {
        crate::dataplane::cors::decorate_actual(cors, origins, origin, resp.headers_mut());
    }
    resp
}

/// The 403 response for a denied authorization (DW-020): deliberately a
/// generic body — which list matched, which claim was absent, none of
/// it is the client's business (the reason is logged server-side only).
fn forbidden(rid: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(ProxyBody::Full(Full::new(observability::envelope_body(
            "forbidden",
            "forbidden",
            rid,
        ))))
        .expect("static 403 response is valid")
}

/// The 401 response for an unauthenticated/invalid request (DW-019):
/// error-envelope body plus a `WWW-Authenticate` challenge built from the schemes
/// the current authenticator interprets.
fn unauthorized(challenge: &str, rid: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(&WWW_AUTHENTICATE, challenge)
        .body(ProxyBody::Full(Full::new(observability::envelope_body(
            "unauthorized",
            "unauthorized",
            rid,
        ))))
        .expect("static 401 response is valid")
}

/// Remove every client-supplied `X-Consumer-*` header (spoof prevention,
/// DW-019): consumer identity is established by the gateway's
/// authenticator and injected as a trusted header on the proxied request;
/// a client claiming `X-Consumer-*` must never reach the upstream with it.
fn strip_consumer_headers(headers: &mut HeaderMap) {
    let names: Vec<HeaderName> = headers
        .keys()
        .filter(|n| n.as_str().starts_with("x-consumer-"))
        .cloned()
        .collect();
    for name in names {
        headers.remove(&name);
    }
}

/// The 429 response for a denied rate limit (DW-017): `Retry-After` in
/// whole seconds (already rounded up, minimum 1) plus the binding
/// window's `X-RateLimit-*` headers.
fn rate_limited(
    limit: u32,
    remaining: u32,
    reset_epoch_s: u64,
    retry_after_s: u32,
    rid: &str,
) -> Response<ProxyBody> {
    let mut builder = Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(hyper::header::RETRY_AFTER, retry_after_s.max(1).to_string());
    builder = builder
        .header(X_RATELIMIT_LIMIT, limit.to_string())
        .header(X_RATELIMIT_REMAINING, remaining.to_string())
        .header(X_RATELIMIT_RESET, reset_epoch_s.to_string());
    builder
        .body(ProxyBody::Full(Full::new(observability::envelope_body(
            "rate_limit_exceeded",
            "rate limit exceeded",
            rid,
        ))))
        .expect("static 429 response is valid")
}

/// Stamp the gateway's rate headers onto a response. Uses `insert`, so
/// any upstream-sent `X-RateLimit-*` values are silently REPLACED: the
/// gateway is the source of truth for rate accounting its clients see.
fn apply_rate_headers(headers: &mut HeaderMap, limit: u32, remaining: u32, reset_epoch_s: u64) {
    headers.insert(
        X_RATELIMIT_LIMIT,
        HeaderValue::from_str(&limit.to_string()).expect("u32 header"),
    );
    headers.insert(
        X_RATELIMIT_REMAINING,
        HeaderValue::from_str(&remaining.to_string()).expect("u32 header"),
    );
    headers.insert(
        X_RATELIMIT_RESET,
        HeaderValue::from_str(&reset_epoch_s.to_string()).expect("u64 header"),
    );
}

/// Apply the route's non-path criteria. All criteria are AND-ed. Empty
/// method list = all methods; host matches the `Host` header
/// (case-insensitive, with or without a port); headers must all be present
/// with exact values; query and cookie entries match on presence, or on
/// exact value when one is configured. `accept` is the route's COMPILED
/// `match.accept` media type (`RouteTable::accept_media_type`), never the
/// raw config string — padding and case are normalized once at snapshot
/// compile, so a padded spelling matches exactly like its trimmed form.
/// Public so router golden-file tests (tests/router_golden.rs) can
/// exercise the full resolution pipeline without a live upstream.
pub fn route_applies<B>(m: &RouteMatch, accept: Option<&str>, req: &Request<B>) -> bool {
    if let Some(want) = &m.host {
        let Some(got) = req.headers().get(HOST).and_then(|v| v.to_str().ok()) else {
            return false;
        };
        let got_host = got.rsplit_once(':').map(|(h, _)| h).unwrap_or(got);
        if !got.eq_ignore_ascii_case(want) && !got_host.eq_ignore_ascii_case(want) {
            return false;
        }
    }
    if !m.methods.is_empty()
        && !m
            .methods
            .iter()
            .any(|want| req.method().as_str().eq_ignore_ascii_case(want.trim()))
    {
        return false;
    }
    for (name, value) in &m.headers {
        match req.headers().get(name) {
            Some(got) => {
                if got.as_bytes() != value.as_bytes() {
                    return false;
                }
            }
            None => return false,
        }
    }
    // Media-type version selection (DW-048): applied like every other
    // criterion (AND-ed, after path resolution, no fallthrough) — see
    // the versioning module docs for the shape and its limits. The
    // comparison key is the compiled normalized form, not `m.accept`:
    // the raw config string never reaches the hot path.
    if let Some(want) = accept {
        if !crate::dataplane::versioning::accept_matches(req.headers(), want) {
            return false;
        }
    }
    let query = req.uri().query();
    for want in &m.query {
        if !query_param_matches(query, want) {
            return false;
        }
    }
    for want in &m.cookies {
        let present = req.headers().get_all(COOKIE).iter().any(|header| {
            header
                .to_str()
                .map(|raw| {
                    parse_cookies(raw)
                        .iter()
                        .any(|(n, v)| name_value_hits(n, v, want))
                })
                .unwrap_or(false)
        });
        if !present {
            return false;
        }
    }
    true
}

/// One `key=value` (or bare `key`) pair of a query string. No
/// percent-decoding in v1: matching is over the raw bytes the client sent.
#[doc(hidden)]
pub fn query_param_matches(query: Option<&str>, want: &NameValueMatch) -> bool {
    let Some(raw) = query else { return false };
    raw.split('&').any(|pair| {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        name_value_hits(name, value, want)
    })
}

/// Parse a `Cookie` request header into (name, value) pairs. Simple
/// RFC-6265-shaped parsing: split on `;`, trim spaces, split each pair on
/// the FIRST `=`. No quoting/encoding handling in v1 — values are matched
/// exactly as sent. Public for the router golden-file tests.
pub fn parse_cookies(header: &str) -> Vec<(&str, &str)> {
    header
        .split(';')
        .filter_map(|pair| {
            let pair = pair.trim();
            if pair.is_empty() {
                return None;
            }
            Some(pair.split_once('=').unwrap_or((pair, "")))
        })
        .collect()
}

fn name_value_hits(name: &str, value: &str, want: &NameValueMatch) -> bool {
    if name != want.name {
        return false;
    }
    match &want.value {
        Some(v) => value == v,
        None => true,
    }
}

/// Apply a proxy action's path rewrite (DW-010). `params` are the
/// `{param}` captures of the exact-template match for this request (empty
/// for regex/prefix routes); they are available to `regex` substitutions
/// as `$name` references that miss the pattern's own capture groups.
/// Returns the rewritten path; a rewrite that does not apply (e.g.
/// `strip_prefix` on a path that does not start with the prefix) leaves
/// the path unchanged. The query string is NOT touched here — the caller
/// re-attaches it. Public for the router golden-file tests.
pub fn apply_path_rewrite(
    route: &Route,
    table: &RouteTable,
    idx: usize,
    path: &str,
    params: &[(String, String)],
) -> String {
    let rewrite = match &route.action {
        RouteAction::Proxy { rewrite: Some(rw) } => rw,
        _ => return path.to_string(),
    };
    match rewrite {
        PathRewrite::StripPrefix {} => {
            let prefix = route.r#match.path.value.trim_end_matches('/');
            match path.strip_prefix(prefix) {
                Some("") => "/".to_string(),
                Some(rest) if rest.starts_with('/') => rest.to_string(),
                Some(rest) => format!("/{rest}"),
                None => path.to_string(),
            }
        }
        PathRewrite::ReplacePrefix {
            prefix,
            replacement,
        } => match path.strip_prefix(prefix) {
            Some(rest) => format!("{replacement}{rest}"),
            None => path.to_string(),
        },
        PathRewrite::Regex { substitution, .. } => match table.rewrite_regex(idx) {
            Some(re) => re
                .replace(path, |caps: &regex::Captures<'_>| {
                    expand_substitution(substitution, caps, params)
                })
                .into_owned(),
            None => path.to_string(),
        },
    }
}

/// Expand `$1` / `${name}` references against a regex match. Lookup order
/// for a name: numeric -> pattern capture group by index; otherwise ->
/// pattern named group, then the route's `{param}` path capture; unknown
/// references expand to the empty string. A lone `$` (end of string, or
/// followed by a non-identifier character) is kept literally.
pub fn expand_substitution(
    substitution: &str,
    caps: &regex::Captures<'_>,
    params: &[(String, String)],
) -> String {
    let mut out = String::with_capacity(substitution.len());
    let mut rest = substitution;
    while let Some(dollar) = rest.find('$') {
        out.push_str(&rest[..dollar]);
        let after = &rest[dollar + 1..];
        if after.is_empty() {
            out.push('$');
            rest = after;
            break;
        }
        if let Some(braced) = after.strip_prefix('{') {
            match braced.find('}') {
                Some(end) => {
                    out.push_str(resolve_ref(&braced[..end], caps, params));
                    rest = &braced[end + 1..];
                }
                None => {
                    out.push('$');
                    rest = after;
                }
            }
        } else {
            let end = after
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(after.len());
            if end == 0 {
                out.push('$');
                rest = after;
            } else {
                out.push_str(resolve_ref(&after[..end], caps, params));
                rest = &after[end..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn resolve_ref<'a>(
    name: &str,
    caps: &'a regex::Captures<'_>,
    params: &'a [(String, String)],
) -> &'a str {
    if let Ok(i) = name.parse::<usize>() {
        return caps.get(i).map(|m| m.as_str()).unwrap_or("");
    }
    caps.name(name)
        .map(|m| m.as_str())
        .or_else(|| {
            params
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        })
        .unwrap_or("")
}

// Eleven parameters is the price of keeping every input explicit on the
// per-request proxy path (no per-request allocation of a context struct);
// DW-021's request id, access record, and metrics are the newest.
#[allow(clippy::too_many_arguments)]
async fn proxy_request<B>(
    gen: &Generation,
    peer: IpAddr,
    mut req: Request<B>,
    route: &Route,
    route_idx: usize,
    params: &[(String, String)],
    global_permit: &mut Option<OwnedSemaphorePermit>,
    identity: Option<&Identity>,
    rid: &str,
    rec: &mut AccessRecord,
    obs: &Observability,
) -> Response<ProxyBody>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let gateway = gen.snapshot.gateway();
    let Some(service) = gateway.services.iter().find(|s| s.name == route.service) else {
        // Validation rejects dangling references, so this is a generation
        // tear; keep it classified rather than panicking.
        return simple(
            StatusCode::INTERNAL_SERVER_ERROR,
            "unknown_service",
            "route targets unknown service",
            rid,
        );
    };
    let Some(handle) = gen.registry.get(&service.upstream) else {
        return simple(
            StatusCode::INTERNAL_SERVER_ERROR,
            "unknown_upstream",
            "unknown upstream",
            rid,
        );
    };
    rec.upstream = Some(handle.name().to_string());

    let wants_upgrade = req.headers().contains_key(UPGRADE);
    if wants_upgrade && req.version() == Version::HTTP_2 {
        return simple(
            StatusCode::NOT_IMPLEMENTED,
            "upgrade_not_supported",
            "protocol upgrade is not supported over HTTP/2",
            rid,
        );
    }

    // Path rewrite (DW-010): applied to the path component only, before
    // anything is sent upstream; the inbound query string is re-attached
    // verbatim. Validation rejects relative substitutions, so a parse
    // failure here should be unreachable for a freshly compiled config —
    // the no-op fallback below stays as defense-in-depth (e.g. a snapshot
    // compiled before this rule): keep the original path, never a 500,
    // never a panic.
    let inbound = req.uri().clone();
    let new_path = apply_path_rewrite(
        route,
        gen.snapshot.route_table(),
        route_idx,
        inbound.path(),
        params,
    );
    if new_path != inbound.path() {
        let pq = match inbound.query() {
            Some(q) => format!("{new_path}?{q}"),
            None => new_path,
        };
        if let Ok(uri) = pq.parse() {
            *req.uri_mut() = uri;
        }
    }

    // The inbound upgrade handle, if the listener enabled upgrades: pulled
    // out of the request extensions so the request itself can be rebuilt.
    let on_client_upgrade = req.extensions_mut().remove::<hyper::upgrade::OnUpgrade>();

    // Forwarded headers: rebuild XFF/X-Real-IP from the direct peer under
    // the trusted-proxies rule; Host becomes the upstream authority.
    let trusted = peer_is_trusted(&gateway.trusted_proxies, peer);
    let inbound_xff = req
        .headers()
        .get(&X_FORWARDED_FOR)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let xff = match (trusted, inbound_xff) {
        (true, Some(existing)) => format!("{existing}, {peer}"),
        (_, _) => peer.to_string(),
    };

    // Tunneling rebuilds a `Connection: Upgrade` header on the forwarded
    // request: stripping it would leave conformant backends (which require
    // the Connection token to offer a 101) declining every upgrade.
    let (mut parts, body) = req.into_parts();
    let conn_tokens = strip_hop_by_hop(&mut parts.headers, wants_upgrade);
    if wants_upgrade {
        let mut tokens = conn_tokens;
        if !tokens.iter().any(|t| t.eq_ignore_ascii_case("upgrade")) {
            tokens.push("Upgrade".to_string());
        }
        if let Ok(v) = HeaderValue::from_str(&tokens.join(", ")) {
            parts.headers.insert(CONNECTION, v);
        }
    }
    // Host is rebuilt by the upstream handle from the load-balancer pick
    // (the gateway, not the client, names the origin it dials); see
    // UpstreamHandle::send_with_hash_key.
    if let Ok(v) = HeaderValue::from_str(&xff) {
        parts.headers.insert(&X_FORWARDED_FOR, v);
    }
    if let Ok(v) = HeaderValue::from_str(&peer.to_string()) {
        parts.headers.insert(&X_REAL_IP, v);
    }
    // Trusted consumer identity upstream (DW-019): injected by the gateway
    // AFTER inbound X-Consumer-* headers were stripped in `handle`, so the
    // upstream can trust `X-Consumer-Name` as the authenticated consumer
    // (absent for anonymous traffic). Strip + inject, never pass-through.
    if let Some(identity) = identity {
        if let Ok(v) = HeaderValue::from_str(&identity.consumer_name) {
            parts.headers.insert(&X_CONSUMER_NAME, v);
        }
    }

    let out_req_parts = parts;
    // The peer IP is the ip_hash key (X-Real-IP peer; other algorithms
    // ignore it); every attempt re-picks the endpoint through the
    // balancer (so health ejection and weights apply per attempt).
    //
    // ---- DW-014: retry wiring ------------------------------------------
    // Idempotency: GET/HEAD/OPTIONS/TRACE/PUT are retry-eligible by
    // method; POST only when the upstream opts in via `retries.retry_post`.
    // A request whose body was not fully buffered within
    // `buffer_max_bytes` is never retried (its body is partially consumed
    // and cannot be replayed). Upgrade requests are never retried.
    let rp: RetryParams = handle.retry_params().clone();
    let idempotent = matches!(
        out_req_parts.method,
        hyper::Method::GET
            | hyper::Method::HEAD
            | hyper::Method::OPTIONS
            | hyper::Method::TRACE
            | hyper::Method::PUT
    );
    let retries_enabled = rp.attempts > 0
        && !wants_upgrade
        && (idempotent || (rp.retry_post && out_req_parts.method == hyper::Method::POST));

    let budget = handle.retry_budget();
    // Per-upstream circuit breaker (DW-015): evaluated BEFORE the endpoint
    // pick and before every (re)attempt — an open breaker means NO attempts
    // at all. The breaker gates the whole upstream; endpoint ejection
    // (DW-012) gates endpoints within it, and even a fail-open pick (all
    // endpoints ejected) still flows through this check. Requests already
    // in flight when the breaker opened complete normally.
    let breaker = handle.breaker();
    let breaker_params = handle.breaker_params().copied();
    // One budget denominator per proxied request (not per attempt),
    // regardless of retry eligibility or upgrade status: the budget window
    // counts ALL proxied traffic to the upstream, so a POST-heavy upstream
    // still accumulates denominator headroom for its idempotent share.
    budget.record_request();
    let mut replay: Option<Bytes> = None;
    let first_body: AttemptBody<B> = if retries_enabled {
        match buffer_request_body(body, rp.buffer_max_bytes).await {
            Ok(bytes) => {
                replay = Some(bytes.clone());
                AttemptBody::Replay(bytes)
            }
            Err((prefix, rest)) => {
                // Over-cap (or errored) body: stream the buffered prefix
                // plus the remainder, single attempt. Documented choice:
                // over-cap bodies are NOT retried (fail through) rather
                // than erroring the request.
                AttemptBody::OneShot {
                    prefix: Some(prefix),
                    rest,
                }
            }
        }
    } else {
        // Retries off (the default): the original streaming body is
        // forwarded untouched — zero-copy, no buffering, byte-identical
        // to the pre-DW-014 path.
        AttemptBody::OneShot {
            prefix: None,
            rest: Box::pin(body),
        }
    };

    let mut first_body = Some(first_body);
    let mut done_tries: u32 = 0;
    loop {
        // Breaker admission (DW-015) precedes every attempt: endpoint
        // pick, dial, and any remaining retries. Checked per iteration so
        // a breaker that trips mid-request (an earlier attempt's failure
        // crossed the threshold) still short-circuits the retries.
        if let Some(bp) = breaker_params {
            if let crate::resilience::breaker::BreakerDecision::Reject { retry_after_ms } =
                breaker.check(&bp)
            {
                tracing::warn!(
                    code = "upstream_circuit_open",
                    request_id = %rid,
                    upstream = handle.name(),
                    "upstream circuit open; failing fast"
                );
                rec.broken = true;
                return breaker_open(retry_after_ms, rid);
            }
        }
        let body = match first_body.take() {
            Some(body) => body,
            None => {
                // Unreachable: the only `continue` into this branch requires
                // `may_retry`, which requires `replay.is_some()`.
                debug_assert!(replay.is_some(), "retry requires a replayable body");
                AttemptBody::Replay(replay.clone().expect("retry requires a replayable body"))
            }
        };
        let out_req = Request::from_parts(out_req_parts.clone(), body);
        // One span per upstream attempt (DW-021); the balancer's pick
        // runs inside it under its own `upstream_pick` span (see the
        // upstream handle). Instrumented onto the send future — no span
        // guard is held across a poll boundary.
        let attempt_span = tracing::info_span!(
            "upstream_attempt",
            attempt = done_tries + 1,
            upstream = handle.name()
        );
        let mut picked: Option<String> = None;
        let result = handle
            .send_with_hash_key_observed(out_req, Some(&peer.to_string()), &mut picked)
            .instrument(attempt_span)
            .await;
        rec.attempts = done_tries + 1;
        if let Some(ep) = &picked {
            rec.endpoint = Some(ep.clone());
        }
        // Attempt metric (DW-021): endpoint = "unpicked" when the dispatch
        // never resolved one; error outcomes classify to 5xx (every
        // upstream error maps to a 502/503/504/500 — see
        // classify_upstream_error), so the class reflects the response
        // the client ultimately receives for that attempt.
        let attempt_status = match &result {
            Ok(resp) => resp.status().as_u16(),
            Err(_) => 500,
        };
        obs.record_upstream_attempt(
            handle.name(),
            picked.as_deref().unwrap_or("unpicked"),
            attempt_status,
        );
        done_tries += 1;
        // An attempt is retryable only while attempts remain and the body
        // is replayable; the budget reservation is charged atomically
        // BEFORE a retry runs (and only when one actually will — a charged
        // but unused reservation would undercount future headroom).
        let may_retry = done_tries <= rp.attempts && replay.is_some();
        match result {
            Ok(resp) => {
                // Breaker observation (DW-015): the same point passive
                // health sees — headers resolved; status >= 500 is a
                // failure, everything else a success. Each attempt (a
                // retried one included) reports.
                if let Some(bp) = breaker_params {
                    breaker.report(&bp, resp.status().as_u16() >= 500);
                }
                // Retry when the upstream answered with a retryable status
                // (headers resolved — the attempt is otherwise final).
                if may_retry
                    && rp.retries_status(resp.status().as_u16())
                    && budget.try_reserve_retry(rp.budget_percent)
                {
                    obs.record_retry(handle.name());
                    tracing::warn!(
                        code = "upstream_retry",
                        request_id = %rid,
                        upstream = handle.name(),
                        attempt = done_tries,
                        status = resp.status().as_u16(),
                        "retryable upstream status; retrying"
                    );
                    tokio::time::sleep(crate::resilience::retries::jitter_delay(
                        rp.backoff_base_ms,
                        rp.backoff_cap_ms,
                        done_tries,
                    ))
                    .await;
                    continue;
                }
                return finish_proxy_response(
                    resp,
                    wants_upgrade,
                    on_client_upgrade,
                    global_permit.take(),
                    rid,
                );
            }
            Err(err) => {
                // Signed-body digest mismatch (DW-036): the CLIENT's
                // request body did not match the digest its signature
                // bound. Checked BEFORE the retry branch (a mismatch is
                // deterministic — a retry re-sends the same tampered
                // bytes and re-fails) and before breaker observation:
                // the upstream never saw a complete request, so this
                // says nothing about upstream health either. 401, the
                // family's failure shape.
                if signature_body_mismatch(&err) {
                    tracing::warn!(
                        code = "signature_body_mismatch",
                        request_id = %rid,
                        upstream = handle.name(),
                        "signed request body did not match its digest; aborted mid-stream"
                    );
                    return unauthorized(crate::security::authn::HMAC_CHALLENGE, rid);
                }
                // Breaker observation: transport-class failures count.
                // Client-side admission rejections (Saturated — no upstream
                // contact) and configuration-class errors say nothing about
                // upstream health and must not drive the breaker.
                if let Some(bp) = breaker_params {
                    if breaker_reportable(&err) {
                        breaker.report(&bp, true);
                    }
                }
                // Retry on transport-class failures (connect/read timeout,
                // refusal, reset, framing) when `retry_transport` is on.
                if may_retry
                    && rp.retry_transport
                    && transport_retryable(&err)
                    && budget.try_reserve_retry(rp.budget_percent)
                {
                    obs.record_retry(handle.name());
                    tracing::warn!(
                        code = "upstream_retry",
                        request_id = %rid,
                        upstream = handle.name(),
                        attempt = done_tries,
                        "upstream attempt failed: {err}; retrying"
                    );
                    tokio::time::sleep(crate::resilience::retries::jitter_delay(
                        rp.backoff_base_ms,
                        rp.backoff_cap_ms,
                        done_tries,
                    ))
                    .await;
                    continue;
                }
                // Server-side detail stays in the log (classification only
                // reaches the client — no hyper error text leaks).
                tracing::error!(
                    code = "upstream_failed",
                    request_id = %rid,
                    upstream = handle.name(),
                    "upstream request failed: {err}"
                );
                // Streaming body limit (DW-027): a request body that
                // crossed the route cap mid-upload surfaces here (the
                // client's failure, not the upstream's) — answer 413
                // rather than a 5xx classification.
                if request_limit_exceeded(&err) {
                    return simple(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "request_body_too_large",
                        "request body exceeded the route limit mid-stream",
                        rid,
                    );
                }
                let (status, code, msg) = classify_upstream_error(&err);
                return simple(status, code, msg, rid);
            }
        }
    }
}

/// The fail-fast response for an open circuit (DW-015): 503 with the
/// error-envelope body and a `Retry-After` header carrying the
/// whole seconds until a half-open probe may be admitted (rounded up,
/// minimum 1 — a client honoring it retries neither too early nor
/// needlessly late). While half-open probes are in flight the hint is 1
/// second (the exact half-open time is unknowable until a probe resolves).
fn breaker_open(retry_after_ms: u64, rid: &str) -> Response<ProxyBody> {
    let seconds = retry_after_ms.div_ceil(1000);
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(hyper::header::RETRY_AFTER, seconds.max(1).to_string())
        .body(ProxyBody::Full(Full::new(observability::envelope_body(
            "upstream_circuit_open",
            "upstream circuit open",
            rid,
        ))))
        .expect("static breaker response is valid")
}

/// Finalize a proxied response: upgrade tunneling for 101s, hop-by-hop
/// stripping, and the streaming body passthrough. The gateway
/// concurrency-cap permit (DW-015), when present, is attached to the
/// streaming body so the global slot is held until the body completes or
/// the response is dropped (client disconnect included); a tunneled 101
/// releases it when the (empty) 101 response is dropped.
fn finish_proxy_response(
    mut resp: Response<UpstreamBody>,
    wants_upgrade: bool,
    on_client_upgrade: Option<hyper::upgrade::OnUpgrade>,
    global_permit: Option<OwnedSemaphorePermit>,
    rid: &str,
) -> Response<ProxyBody> {
    if resp.status() == StatusCode::SWITCHING_PROTOCOLS && wants_upgrade {
        let on_upstream = hyper::upgrade::on(&mut resp);
        if let Some(client) = on_client_upgrade {
            tokio::spawn(async move {
                match tokio::try_join!(client, on_upstream) {
                    Ok((client_io, upstream_io)) => {
                        tunnel(TokioIo::new(client_io), TokioIo::new(upstream_io)).await
                    }
                    Err(err) => {
                        tracing::warn!("upgrade handshake failed: {err}");
                    }
                }
            });
        } else {
            return simple(
                StatusCode::INTERNAL_SERVER_ERROR,
                "upgrades_unsupported",
                "listener does not support upgrades",
                rid,
            );
        }
        // Keep the 101 headers (Connection/Upgrade must reach the
        // client to complete its handshake); body is empty.
        if let Some(permit) = global_permit {
            resp.body_mut().set_release_permit(permit);
        }
        return resp.map(ProxyBody::Upstream);
    }
    let _ = strip_hop_by_hop(resp.headers_mut(), false);
    if let Some(permit) = global_permit {
        resp.body_mut().set_release_permit(permit);
    }
    resp.map(ProxyBody::Upstream)
}

/// Whether an upstream send failed because the REQUEST body crossed the
/// route's streaming limit (DW-027). The counting wrapper's error rides
/// the hyper client error's source chain; walk it. Never confusable
/// with an upstream failure: the marker type is only produced by the
/// gateway's own request-body wrapper.
fn request_limit_exceeded(err: &UpstreamError) -> bool {
    let UpstreamError::Client(e) = err else {
        return false;
    };
    let mut src: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(s) = src {
        if s.downcast_ref::<crate::dataplane::hardening::LimitedBodyError>()
            .is_some_and(|l| {
                matches!(
                    l,
                    crate::dataplane::hardening::LimitedBodyError::OverLimit { .. }
                )
            })
        {
            return true;
        }
        src = s.source();
    }
    false
}

/// Whether an upstream send failed because the REQUEST body did not
/// match the digest its HMAC signature bound (DW-036). The digesting
/// wrapper (`hardening::DigestingBody`) sits INSIDE the route's limit
/// wrapper, so the marker may hide under a `LimitedBodyError::Inner`
/// box whose own `source()` chain is not wired — walk the generic
/// source chain AND descend into that box explicitly. Like
/// [`request_limit_exceeded`], the marker type is only ever produced
/// by the gateway's own request-body wrapper, so it can never be
/// confused with an upstream failure.
fn signature_body_mismatch(err: &UpstreamError) -> bool {
    use crate::dataplane::hardening::{LimitedBodyError, SignatureBodyError};
    let UpstreamError::Client(e) = err else {
        return false;
    };
    let is_mismatch = |e: &(dyn std::error::Error + 'static)| {
        matches!(
            e.downcast_ref::<SignatureBodyError>(),
            Some(SignatureBodyError::DigestMismatch)
        )
    };
    let mut src: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(s) = src {
        if is_mismatch(s) {
            return true;
        }
        // Descend into the limit wrapper's Inner box (it does not
        // expose the inner error through `source()`).
        if let Some(LimitedBodyError::Inner(inner)) = s.downcast_ref::<LimitedBodyError>() {
            let mut inner_src: Option<&(dyn std::error::Error + 'static)> = Some(inner.as_ref());
            while let Some(i) = inner_src {
                if is_mismatch(i) {
                    return true;
                }
                inner_src = i.source();
            }
        }
        src = s.source();
    }
    false
}

/// Whether an upstream error reflects a genuine transport/exchange
/// outcome and therefore feeds the breaker. Client-side admission
/// rejections (Saturated — the request never contacted the upstream) and
/// configuration-class errors (NoEndpoints, InvalidRootCertificate,
/// InvalidHost) would trip the breaker for reasons unrelated to upstream
/// health, so they are not reported.
fn breaker_reportable(err: &UpstreamError) -> bool {
    !matches!(
        err,
        UpstreamError::Saturated
            | UpstreamError::NoEndpoints
            | UpstreamError::InvalidRootCertificate(_)
            | UpstreamError::InvalidHost(_)
    )
}

/// Whether an upstream transport error is safe to retry: genuine
/// transport-class failures only. Configuration errors (no endpoints,
/// invalid TLS host, invalid root certificate) are not transient and
/// would fail identically on every attempt.
fn transport_retryable(err: &UpstreamError) -> bool {
    matches!(
        err,
        UpstreamError::Io(_)
            | UpstreamError::Client(_)
            | UpstreamError::ConnectTimeout { .. }
            | UpstreamError::ReadTimeout { .. }
    )
}

/// The request body of one attempt (DW-014). `OneShot` streams an optional
/// buffered prefix followed by the original remainder (used for the first
/// and only attempt of a non-replayable body — retries off, over-cap
/// bodies, or unbuffered defaults). `Replay` is a fully buffered body
/// cloned per attempt, byte-exact.
enum AttemptBody<B> {
    OneShot {
        prefix: Option<Bytes>,
        rest: Pin<Box<B>>,
    },
    Replay(Bytes),
}

impl<B> hyper::body::Body for AttemptBody<B>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        match this {
            AttemptBody::Replay(bytes) => {
                if bytes.is_empty() {
                    return std::task::Poll::Ready(None);
                }
                let frame = Ok(hyper::body::Frame::data(std::mem::take(bytes)));
                std::task::Poll::Ready(Some(frame))
            }
            AttemptBody::OneShot { prefix, rest } => {
                if let Some(prefix) = prefix.take() {
                    if !prefix.is_empty() {
                        return std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(prefix))));
                    }
                }
                rest.as_mut()
                    .poll_frame(cx)
                    .map(|opt| opt.map(|res| res.map_err(Into::into)))
            }
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        match self {
            AttemptBody::Replay(bytes) => {
                let mut hint = hyper::body::SizeHint::default();
                hint.set_exact(bytes.len() as u64);
                hint
            }
            // Delegate to the wrapped body (preserving its exact/unknown
            // hint so the retry-off path forwards the same framing, e.g.
            // content-length). With a buffered prefix the remainder's own
            // hint no longer describes the stream (bytes were consumed),
            // so the composition reports unknown — the bytes still arrive
            // in order via prefix + remainder frames.
            AttemptBody::OneShot { prefix, rest } => match prefix {
                Some(p) if !p.is_empty() => hyper::body::SizeHint::default(),
                _ => rest.size_hint(),
            },
        }
    }
}

/// Buffer a request body up to `cap` bytes (DW-014 opt-in). `Ok` = the
/// whole body fit (possibly empty — an empty body is trivially
/// replayable) and may be replayed on retries. `Err((prefix, body))` =
/// the body exceeded the cap (prefix = the bytes already consumed; the
/// caller streams prefix + remainder without retrying). Request TRAILER
/// frames are dropped: the hop-by-hop `Trailer`/`TE` headers are already
/// stripped from the forwarded request, so v1 forwards no trailers
/// anywhere (documented; consistent with the no-trailer stance).
async fn buffer_request_body<B>(body: B, cap: u64) -> Result<Bytes, (Bytes, Pin<Box<B>>)>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    use http_body_util::BodyExt as _;
    let mut body = Box::pin(body);
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                let Ok(data) = frame.into_data() else {
                    continue; // trailer frame: dropped (see doc comment)
                };
                if buf.len() as u64 + data.len() as u64 > cap {
                    // Over cap: the frame that broke the camel's back is
                    // already consumed, so it must ride in the streamed
                    // prefix (the caller streams prefix + remainder — the
                    // full body still reaches the upstream byte-exact).
                    buf.extend_from_slice(&data);
                    return Err((Bytes::from(buf), body));
                }
                buf.extend_from_slice(&data);
            }
            Some(Err(_)) => return Err((Bytes::from(buf), body)),
            None => return Ok(Bytes::from(buf)),
        }
    }
}

/// (status, envelope code, envelope message) for an upstream error. The
/// message is a classification string — never the underlying error text
/// (no hyper/io internals leak to the client; the full error is logged
/// server-side at the call site).
fn classify_upstream_error(err: &UpstreamError) -> (StatusCode, &'static str, &'static str) {
    match err {
        UpstreamError::Saturated => (
            StatusCode::SERVICE_UNAVAILABLE,
            "upstream_saturated",
            "upstream saturated",
        ),
        UpstreamError::ConnectTimeout { .. } => (
            StatusCode::GATEWAY_TIMEOUT,
            "upstream_connect_timeout",
            "upstream connect timed out",
        ),
        UpstreamError::ReadTimeout { .. } => (
            StatusCode::GATEWAY_TIMEOUT,
            "upstream_response_timeout",
            "upstream response timed out",
        ),
        UpstreamError::InvalidHost(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_upstream_host",
            "invalid upstream host",
        ),
        UpstreamError::NoEndpoints | UpstreamError::Io(_) | UpstreamError::Client(_) => (
            StatusCode::BAD_GATEWAY,
            "upstream_unavailable",
            "upstream unavailable",
        ),
        UpstreamError::InvalidRootCertificate(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_upstream_configuration",
            "invalid upstream configuration",
        ),
    }
}

/// Generic 101 tunnel: splice the upgraded client and upstream connections
/// byte-for-byte until either side closes.
async fn tunnel<S1, S2>(mut client: S1, mut upstream: S2)
where
    S1: AsyncRead + AsyncWrite + Unpin,
    S2: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        Ok(_) => {}
        Err(err) => tracing::warn!("upgrade tunnel ended with error: {err}"),
    }
}

fn redirect<B>(
    req: &Request<B>,
    scheme: Option<&str>,
    host: Option<&str>,
    path: Option<&str>,
    status: u16,
    rid: &str,
) -> Response<ProxyBody> {
    // Default preserves the inbound path AND query verbatim.
    let path_part = path.map(str::to_string).unwrap_or_else(|| {
        req.uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string())
    });
    let location = match (scheme, host) {
        (Some(s), Some(h)) => {
            let p = path_part.strip_prefix('/').unwrap_or(&path_part);
            format!("{s}://{h}/{p}")
        }
        (None, Some(h)) => {
            let p = path_part.strip_prefix('/').unwrap_or(&path_part);
            format!("//{h}/{p}")
        }
        // A scheme without a host cannot form an absolute URI; treat the
        // path as a relative redirect target.
        (_, None) => path_part,
    };
    // Validation keeps Location header-safe, but handle()'s never-panics
    // contract needs a belt behind the suspenders: if the value still fails
    // HeaderValue construction, answer 500 rather than panicking the task.
    let location = match HeaderValue::from_str(&location) {
        Ok(v) => v,
        Err(_) => {
            return simple(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid_redirect_target",
                "invalid redirect target",
                rid,
            )
        }
    };
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::FOUND))
        .header(LOCATION, location)
        .body(ProxyBody::Full(Full::new(Bytes::new())))
        .expect("static redirect response is valid")
}

fn respond(
    status: u16,
    body: Option<&str>,
    headers: &std::collections::BTreeMap<String, String>,
) -> Response<ProxyBody> {
    let body = body.unwrap_or("");
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK))
        .header(hyper::header::CONTENT_TYPE, "text/plain");
    for (name, value) in headers {
        // Validation rejects unbuildable name/value pairs; skip rather
        // than panic if a generation tear slipped one through.
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            builder = builder.header(n, v);
        }
    }
    builder
        .body(ProxyBody::Full(Full::new(Bytes::from(body.to_string()))))
        .expect("static respond body is valid")
}

fn simple(status: StatusCode, code: &str, msg: &str, rid: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(ProxyBody::Full(Full::new(observability::envelope_body(
            code, msg, rid,
        ))))
        .expect("static error body is valid")
}

/// Header names always treated as hop-by-hop per RFC 7230 section 6.1
/// (plus the de-facto `Proxy-Connection`), and any name listed in ANY
/// `Connection` header (RFC 7230 allows multiple; only `get_all` sees them
/// all). `TE` is always dropped: trailers are not supported in v1, so there
/// is nothing a `TE: trailers` could license. `Upgrade` (and its
/// `Connection` token) survives only when the request is being tunneled.
///
/// Returns the `Connection` token list collected before stripping (original
/// case, deduplicated, order preserved) so the tunneling caller can rebuild
/// a `Connection` header with the surviving tokens.
///
/// (Public so the DW-024 micro-benchmark can exercise it directly; it is
/// not part of the stable public surface.)
pub fn strip_hop_by_hop(headers: &mut HeaderMap, keep_upgrade: bool) -> Vec<String> {
    let tokens = connection_tokens(headers);
    let listed: Vec<String> = tokens.iter().map(|t| t.to_ascii_lowercase()).collect();
    let drop: Vec<HeaderName> = headers
        .keys()
        .filter(|name| {
            let n = name.as_str();
            if listed.iter().any(|l| l == n) {
                return !(keep_upgrade && n == "upgrade");
            }
            matches!(
                n,
                "connection"
                    | "keep-alive"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "proxy-connection"
                    | "te"
                    | "trailer"
                    | "transfer-encoding"
            ) || (n == "upgrade" && !keep_upgrade)
        })
        .cloned()
        .collect();
    for name in drop {
        headers.remove(&name);
    }
    tokens
}

/// Deduplicated tokens across ALL `Connection` header lines (an HTTP/1
/// message may carry several; `get` alone only consults the first).
fn connection_tokens(headers: &HeaderMap) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    for value in headers.get_all(CONNECTION) {
        let Ok(v) = value.to_str() else { continue };
        for t in v.split(',') {
            let t = t.trim();
            if !t.is_empty() && !tokens.iter().any(|e| e.eq_ignore_ascii_case(t)) {
                tokens.push(t.to_string());
            }
        }
    }
    tokens
}

// --- trusted proxies: the IP/CIDR grammar lives in `config::net` (shared
// --- with validation and the authorization ACLs); the dataplane consumes
// --- it for the forwarded-header trust rule above. -------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// DW-021 review fix: the invalid-redirect-target 500 envelope must
    /// carry the request's correlation id, not an empty string, so a
    /// misconfigured redirect route stays correlatable against the
    /// `x-request-id` response header and access logs. Config validation
    /// (snapshot.rs) already rejects header-hostile redirect targets, so
    /// this defensive branch is pinned at the unit level: the DEL byte in
    /// the host is exactly the kind of validation gap the branch guards.
    #[tokio::test]
    async fn invalid_redirect_target_envelope_carries_request_id() {
        let req = Request::builder()
            .uri("/v1/old?x=1")
            .body(())
            .expect("test request builds");
        let rid = "req-0000000000000000-000001";
        let resp = redirect(&req, Some("https"), Some("bad\u{7f}host"), None, 302, rid);
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .expect("static error body collects")
            .to_bytes();
        let envelope: serde_json::Value =
            serde_json::from_slice(&body).expect("error body is the JSON envelope");
        assert_eq!(
            envelope["error"]["code"].as_str().unwrap(),
            "invalid_redirect_target"
        );
        let got = envelope["error"]["request_id"].as_str().unwrap();
        assert!(!got.is_empty(), "request_id must not be empty");
        assert_eq!(got, rid, "envelope request_id must match the request");
    }
}
