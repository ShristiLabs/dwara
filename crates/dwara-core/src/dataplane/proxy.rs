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
//! Consumer request budgets (DW-033): a quota-configured consumer's
//! requests additionally run a budget check AFTER rate limiting and
//! BEFORE cap admission — an in-memory GCRA 429 is cheaper than a
//! store-backed one, and a refused request never holds a concurrency
//! slot. A budget 429 reuses the same builder (Retry-After +
//! `X-RateLimit-*` from the binding budget; reset is the UTC window
//! boundary), but budget headers appear on DENIALS only: admitted
//! responses' `X-RateLimit-*` family belongs to the rate limiter when
//! it applies (two mechanisms racing to write the same header names on
//! every success would be noise, not information). Budgets apply to
//! authenticated CONFIG consumers exclusively (anonymous traffic and
//! store-managed consumers have none); counters live in the state
//! store, so quota config without `DWARA_STATE_DB` is inert (warned
//! once). Usage is metered through `dwara_quota_*` metrics, the
//! admin `GET /quotas/usage` endpoint, the analytics store's
//! per-consumer axis, and the `quota_near_limit` event (edge-triggered
//! once per budget per window at 80%). See `state::quotas` for the
//! window and evaluation semantics.
//!
//! Observability (DW-021): every request opens a root `request` span
//! (request id, method, path WITHOUT the query string, consumer, route,
//! listener) with child spans per phase — authn, authz, ratelimit,
//! quota, admission, and one `upstream_attempt` per send (the balancer's pick
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
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use arc_swap::ArcSwap;
use http_body_util::{Full, LengthLimitError, Limited};
use hyper::body::Body as _;
use hyper::body::Bytes;
use hyper::header::{
    HeaderMap, HeaderName, HeaderValue, ACCEPT_ENCODING, CONNECTION, COOKIE, HOST, IF_NONE_MATCH,
    LOCATION, ORIGIN, UPGRADE,
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
use crate::dataplane::split::{mint_affinity_id, read_cookie};
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
/// DW-014 write-timeout / mid-body health-report knobs), a route-
/// compressed stream ([`crate::dataplane::compression::CompressedBody`], DW-027 — the codec wrapper
/// around either of the other two), or an over-cap cache passthrough
/// ([`crate::dataplane::response_cache::PassthroughBody`], DW-037 —
/// the buffered prefix followed by the untouched remainder).
pub enum ProxyBody {
    /// Small fully-buffered gateway message (envelope, respond action,
    /// metrics/health payloads).
    Full(Full<Bytes>),
    /// Untouched streaming upstream body.
    Upstream(UpstreamBody),
    /// Route-compressed response body (DW-027).
    Compressed(Box<crate::dataplane::compression::CompressedBody>),
    /// Cache over-cap passthrough (DW-037): a body that began
    /// buffering for the response cache, crossed the route's
    /// `max_body_bytes` cap mid-stream, and continues streaming the
    /// original bytes exactly as if no cache existed.
    Passthrough(crate::dataplane::response_cache::PassthroughBody),
    /// AI streaming body (DW-077): the provider's SSE stream
    /// translated frame-by-frame into OpenAI-shaped chunks — zero
    /// buffering, gateway-owned terminator, infallible by
    /// construction (provider aborts become terminal error frames).
    Ai(Box<crate::dataplane::ai_proxy::AiStreamBody>),
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
            ProxyBody::Passthrough(b) => Pin::new(b).poll_frame(cx),
            ProxyBody::Ai(b) => Pin::new(b.as_mut()).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            ProxyBody::Full(b) => b.is_end_stream(),
            ProxyBody::Upstream(b) => b.is_end_stream(),
            ProxyBody::Compressed(b) => b.is_end_stream(),
            ProxyBody::Passthrough(b) => b.is_end_stream(),
            ProxyBody::Ai(b) => b.is_end_stream(),
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        match self {
            ProxyBody::Full(b) => b.size_hint(),
            ProxyBody::Upstream(b) => b.size_hint(),
            ProxyBody::Compressed(b) => b.size_hint(),
            ProxyBody::Passthrough(b) => b.size_hint(),
            ProxyBody::Ai(b) => b.size_hint(),
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
pub(super) struct Generation {
    pub(super) snapshot: Arc<Snapshot>,
    registry: Arc<UpstreamRegistry>,
    /// OAuth2 clients (DW-035): per-upstream, built from each
    /// upstream's `oauth2_client_credentials` config. Keyed by upstream
    /// name. Empty when no upstream configures OAuth2. Rebuilt every
    /// generation (the TLS config / client cert may change); the token
    /// CACHE lives on the dataplane and persists across reloads.
    oauth2_clients: HashMap<String, Arc<crate::security::oauth2::OAuth2Client>>,
    /// The compiled AI provider/model table (DW-075), built from the
    /// `ai:` block with auth references resolved. None when the config
    /// has no `ai:` block. Rebuilt every generation (a reload picks up
    /// rotated secrets and model-table changes).
    ai: Option<Arc<crate::ai::AiRuntime>>,
}

impl Generation {
    /// The OAuth2 client for `upstream_name`, if that upstream has an
    /// `oauth2_client_credentials` block (DW-035).
    fn oauth2_client(
        &self,
        upstream_name: &str,
    ) -> Option<&Arc<crate::security::oauth2::OAuth2Client>> {
        self.oauth2_clients.get(upstream_name)
    }

    /// The upstream registry coupled to this generation (DW-075: the
    /// AI proxy action resolves provider transports through the SAME
    /// generation the route table came from).
    pub(super) fn registry(&self) -> &Arc<UpstreamRegistry> {
        &self.registry
    }

    /// The compiled AI table (DW-075); None when no `ai:` block.
    pub(super) fn ai(&self) -> Option<&Arc<crate::ai::AiRuntime>> {
        self.ai.as_ref()
    }
}

/// Build the per-upstream OAuth2 client map (DW-035) from the gateway
/// config. Each upstream with an `oauth2_client_credentials` block gets
/// an [`OAuth2Client`] built here (loading the optional mTLS cert/key
/// at build time so a broken bundle disables that upstream's OAuth2 at
/// build instead of failing every request). A build failure for one
/// upstream logs and skips — the upstream still proxies, just without
/// the OAuth2 Bearer token (the request reaches the upstream with
/// whatever `Authorization` the client sent, subject to the authn
/// family's pass-through rules).
fn build_oauth2_clients(
    gateway: &crate::config::Gateway,
) -> HashMap<String, Arc<crate::security::oauth2::OAuth2Client>> {
    let mut clients = HashMap::new();
    for upstream in &gateway.upstreams {
        if let Some(cfg) = &upstream.oauth2_client_credentials {
            match crate::security::oauth2::OAuth2Client::build(cfg.clone()) {
                Ok(client) => {
                    clients.insert(upstream.name.clone(), client);
                }
                Err(e) => {
                    tracing::error!(
                        code = "oauth2_client_disabled",
                        upstream = %upstream.name,
                        "oauth2 client-credentials disabled for upstream: {e}"
                    );
                }
            }
        }
    }
    clients
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
    /// OAuth2 token cache (DW-035), carried ACROSS generation swaps
    /// like `jwks_caches` and `nonce_cache`: a reload must never discard
    /// a still-valid access token (that would re-fetch from the token
    /// endpoint on every request after every reload). Per-upstream,
    /// keyed by the token endpoint URL. The OAuth2 CLIENTS (with their
    /// TLS config) are per-generation; the token CACHE is per-dataplane.
    oauth2_token_cache: Arc<crate::security::oauth2::OAuth2TokenCache>,
    /// OIDC introspection cache (DW-034), carried ACROSS generation
    /// swaps like `jwks_caches` and `oauth2_token_cache`: a reload
    /// must never discard a cached `active: true` introspection (that
    /// would re-introspect every Bearer token on every request after
    /// every reload). Per-provider, keyed by
    /// `{provider_name}:{sha256_hex(token)}`. The OIDC CLIENTS (with
    /// their TLS config) are per-generation; the introspection CACHE
    /// is per-dataplane.
    oidc_introspection_cache: Arc<crate::security::oidc::OidcIntrospectionCache>,
    /// AI token budgets (DW-078): per-generation rules over a
    /// reload-surviving spend ledger (empty engine when no policy
    /// declares a budget — the pre-check skips entirely).
    ai_budgets: ArcSwap<crate::ai::budget::AiBudgetEngine>,
    /// AI pricing table (DW-079): per-provider-model token rates,
    /// compiled from the `ai.pricing` config map. Swapped on every
    /// reload so a pricing change takes effect on the next request
    /// with no restart. Empty (every model unknown -> cost 0) when no
    /// pricing is configured — fail-open, never a crash.
    ai_pricing: ArcSwap<crate::ai::cost::PricingTable>,
    /// AI model governance (DW-084): per-team model allowlists plus
    /// the shadow-audit switch, compiled from the `ai.governance`
    /// config block. Swapped on every reload so an allowlist change
    /// takes effect on the next request with no restart. Empty (no
    /// allowlists -> every consumer unrestricted) when governance is
    /// not configured — fail-open.
    ai_governance: ArcSwap<crate::ai::governance::GovernanceEngine>,
    /// AI prompt/response logging (DW-081): the compiled logging
    /// engine (enabled flag, sampling rate, retention, redactor),
    /// compiled from the `ai.logging` config block. Swapped on every
    /// reload so a logging change takes effect on the next request
    /// with no restart. None (an empty engine) when logging is not
    /// configured — capture is off (privacy-first).
    ai_logging: arc_swap::ArcSwapOption<crate::ai::logging::AiLoggingEngine>,
    /// AI guardrails (DW-082): the compiled guardrail engine
    /// (prompt-injection, PII, banned-content, output schema
    /// enforcement), compiled from the `ai.guardrails` config block.
    /// Swapped on every reload so a guardrail change takes effect on
    /// the next request with no restart. Empty (no rules -> every
    /// prompt and response passes through) when guardrails are not
    /// configured — fail-open.
    ai_guardrails: ArcSwap<crate::ai::guardrails::GuardrailEngine>,
    /// AI semantic cache (DW-083): embedding-similarity cache for AI
    /// prompts. None when semantic caching is not configured or
    /// disabled. PERSISTS across reloads (the HNSW index and cached
    /// entries survive config refreshes); config is updated in place
    /// via `update_config` so a threshold/TTL change applies to the
    /// next lookup with no cache reset.
    ai_semantic_cache: arc_swap::ArcSwapOption<crate::ai::semantic_cache::SemanticCacheEngine>,
    /// Observability state (DW-021): metrics families plus the access-log
    /// sampling knob. Per-dataplane (not global) so parallel tests never
    /// share a registry.
    obs: Arc<Observability>,
    /// The event bus (DW-044): adopted from the state's bus when one is
    /// attached, else created here AND attached back to the state, so a
    /// live gateway always has exactly one bus shared by the config
    /// publish pipeline and the dataplane's state machines. Breaker
    /// transitions, endpoint ejection/recovery, and config
    /// published/rejected emit onto it; the webhook deliverer drains it.
    events: Arc<crate::events::EventBus>,
    /// The compiled webhook targets of the CURRENT generation (DW-044),
    /// pushed to the deliverer task over this watch channel by every
    /// `refresh` (config changes apply to the next event, no deliverer
    /// restart).
    webhook_targets: tokio::sync::watch::Sender<Arc<Vec<crate::events::webhook::WebhookTarget>>>,
    /// The construction-time receiver of `webhook_targets`, held for the
    /// dataplane's lifetime so the watch channel is never CLOSED between
    /// construction and the deliverer's spawn (a closed watch silently
    /// drops every `refresh` send; the deliverer subscribes later).
    #[allow(dead_code)]
    webhook_targets_anchor:
        tokio::sync::watch::Receiver<Arc<Vec<crate::events::webhook::WebhookTarget>>>,
    /// The compiled access-record stream state of the CURRENT
    /// generation (DW-121): sinks, flush cadence, and batch bound,
    /// pushed to the flusher task over this watch channel by every
    /// `refresh` — a reload retargets the stream with no restart.
    stream_targets: tokio::sync::watch::Sender<crate::events::stream::StreamTargets>,
    /// The construction-time receiver of `stream_targets` (the
    /// `webhook_targets_anchor` shape: keeps the watch channel open
    /// between construction and the flusher's spawn).
    #[allow(dead_code)]
    stream_targets_anchor: tokio::sync::watch::Receiver<crate::events::stream::StreamTargets>,
    /// The access-record stream (DW-121): constructed once at startup
    /// by dwara-bin (ALWAYS — an unconfigured stream is disabled by
    /// its enabled flag, so a live reload can arm it) and drained by
    /// the flusher task. ArcSwap for the same reason as `analytics`:
    /// the completion path reads it on EVERY request, and the offer
    /// itself is fire-and-forget (`try_send` onto a bounded channel —
    /// full drops and counts, never blocks).
    record_stream: arc_swap::ArcSwapOption<crate::events::stream::AccessRecordStream>,
    /// The local response cache (DW-037): the store backend, route
    /// epochs, and the revalidation guard. RUNTIME STATE on the
    /// dataplane (like the priority counters), deliberately NOT part of
    /// a generation — it survives reloads; config changes reach it
    /// through epoch bumps computed at `refresh` (see
    /// `response_cache::ResponseCache::note_generation`).
    response_cache: Arc<crate::dataplane::response_cache::ResponseCache>,
    /// The embedded analytics store (DW-043): set once at startup by
    /// dwara-bin when the config carries an `analytics` block; None =
    /// analytics off, `record_analytics` is a no-op. ArcSwap (not a
    /// RwLock) because the completion path reads it on EVERY request.
    /// The sink call itself is fire-and-forget (`try_send` onto a
    /// bounded channel — a full channel drops and counts, never
    /// blocks); queries (admin endpoints) take the connection's mutex
    /// briefly behind the background writer's batched transactions.
    analytics: arc_swap::ArcSwapOption<crate::analytics::EmbeddedAnalytics>,
    /// The GeoIP database (DW-050): opened at startup when
    /// `gateway.geoip` is configured, hot-swapped by the dwara-bin
    /// watcher when the file changes. ArcSwap: the authz path loads it
    /// per request (an Arc bump), and in-flight lookups keep the
    /// reader they loaded across a swap. None = geo-UNKNOWN.
    geoip: arc_swap::ArcSwapOption<crate::security::geoip::GeoipDb>,
    /// DW-031: the Redis connection for the distributed rate limiter
    /// (ent feature only). Set once at startup by dwara-bin when the
    /// config carries a `redis_rate_limiter` block AND the license
    /// grants the `redis_rate_limiter` feature claim. When set, the
    /// rate-limit engine compiles with Redis-backed limiters instead
    /// of local ones; when None, the local GCRA limiter is used. The
    /// connection persists across reloads (a reload re-clones it for
    /// the new engine, it does not re-establish).
    #[cfg(feature = "ent")]
    redis_conn: std::sync::RwLock<Option<redis::aio::ConnectionManager>>,
    /// DW-054: the config convergence coordinator (ent feature only).
    /// Set once at startup by dwara-bin when the config carries a
    /// `config_convergence` block AND the license grants the
    /// `config_convergence` feature claim. When set, the reload path
    /// calls `publish_convergence_local` after every successful local
    /// reload so the backend carries the new generation. The
    /// coordinator's background poll task is spawned by dwara-bin
    /// (not here) against the shutdown watch.
    #[cfg(feature = "ent")]
    convergence:
        std::sync::RwLock<Option<Arc<crate::dataplane::convergence::ConvergenceCoordinator>>>,
    /// Quota near-limit edge-trigger bookkeeping (DW-033): the
    /// (consumer, budget, window_start) triples already reported, so
    /// `quota_near_limit` fires ONCE per budget per window instead of
    /// per request above 80%. Bounded by quota-configured consumers x
    /// budgets; stale windows are pruned on each insert (see
    /// `note_quota_near_limit`). Runtime state, deliberately not part
    /// of a generation — reloads never re-notify a window already
    /// reported.
    quota_near_limit_seen: std::sync::Mutex<std::collections::HashSet<(String, &'static str, i64)>>,
}

/// The gateway-level concurrency admission for one generation (DW-015 +
/// DW-016). `general: None` means unlimited (`max_concurrent_requests`
/// absent or 0). When set, `general` holds the permits available to ALL
/// traffic; `reserved` (when carved) holds a small sub-allowance of the
/// same cap usable ONLY by high-priority requests (>= [`HIGH_PRIORITY`])
/// once the general allowance is full.
///
/// DW-053: when `admission_queue` is `Some`, over-cap requests WAIT for
/// a permit up to `queue_timeout` instead of being immediately shed.
/// `queue_depth` tracks the current number of waiting requests (an
/// atomic on the dataplane, shared across generations so a reload never
/// loses an in-flight waiter). `low_queue_limit` is the maximum queue
/// depth low-priority requests may occupy (the high-priority reserve is
/// `max_queue_size - low_queue_limit`); high-priority may queue up to
/// `max_queue_size`.
#[derive(Clone, Default)]
struct GlobalCap {
    general: Option<Arc<Semaphore>>,
    reserved: Option<Arc<Semaphore>>,
    /// DW-053: the admission queue config. `None` = queueing disabled
    /// (immediate shed, the DW-016 behavior).
    admission_queue: Option<AdmissionQueueState>,
}

/// DW-053: the runtime admission queue state carried on the GlobalCap.
/// The queue depth atomic lives HERE (not on the dataplane) so it is
/// rebuilt per generation — but a reload that changes the queue config
/// simply swaps in a new state; in-flight waiters on the old semaphore
/// complete normally (the permit they are waiting for is on the old
/// `Arc<Semaphore>`, which stays alive until the last holder drops).
#[derive(Clone)]
struct AdmissionQueueState {
    /// The queue timeout (from `admission_queue.queue_timeout_ms`).
    queue_timeout: Duration,
    /// The maximum total queue depth (from `admission_queue.max_queue_size`).
    max_queue_size: u32,
    /// The maximum queue depth low-priority requests may occupy. High-
    /// priority requests may use the full `max_queue_size`; the reserve
    /// (`max_queue_size - low_queue_limit`) is high-priority-only. When
    /// `per_priority` is false, this equals `max_queue_size` (no reserve).
    low_queue_limit: u32,
    /// Current number of requests waiting in the queue. Incremented
    /// before the timed acquire, decremented after (whether admitted or
    /// timed out).
    queue_depth: Arc<AtomicU32>,
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
///
/// DW-053: when `admission_queue` is present and enabled, the cap carries
/// the queue state (timeout, depth bounds, the depth atomic). The queue
/// waits for a permit from the SAME semaphores — it is a timed acquire,
/// not a separate data structure.
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
    let admission_queue = gateway.admission_queue.as_ref().and_then(|aq| {
        if !aq.enabled {
            return None;
        }
        let max_queue_size = aq.max_queue_size;
        // Per-priority split: reserve half the queue for high-priority
        // (minimum 1 high-priority slot when the queue is non-empty and
        // per_priority is true). Low-priority may occupy up to
        // `low_queue_limit`; high-priority may occupy the full
        // `max_queue_size`.
        let low_queue_limit = if aq.per_priority {
            max_queue_size / 2
        } else {
            max_queue_size
        };
        Some(AdmissionQueueState {
            queue_timeout: Duration::from_millis(aq.queue_timeout_ms),
            max_queue_size,
            low_queue_limit,
            queue_depth: Arc::new(AtomicU32::new(0)),
        })
    });
    GlobalCap {
        general: Some(Arc::new(Semaphore::new(cap - bucket))),
        reserved: if bucket > 0 {
            Some(Arc::new(Semaphore::new(bucket)))
        } else {
            None
        },
        admission_queue,
    }
}

impl DataPlane {
    /// Build from the state's currently published snapshot.
    pub fn new(state: Arc<ConfigState>) -> Arc<Self> {
        let snapshot = state.snapshot();
        let generation = snapshot.generation();
        // DW-044: exactly one bus per (state, dataplane) pair — adopt the
        // state's, or create one and attach it back so config events are
        // never silently missing in a live gateway.
        let events = match state.event_bus() {
            Some(bus) => bus,
            None => {
                let bus = crate::events::EventBus::new();
                state.attach_event_bus(Arc::clone(&bus));
                bus
            }
        };
        let registry = Arc::new(UpstreamRegistry::from_snapshot_with_events(
            &snapshot,
            Some(&events.emitter()),
        ));
        let slos = compile_route_slos(&snapshot);
        let global_cap = global_cap_of(snapshot.gateway());
        let rate_limits = RateLimitEngine::compile(snapshot.gateway());
        let webhook_targets = Arc::new(compile_webhook_targets(&snapshot));
        let (target_tx, target_anchor) = tokio::sync::watch::channel(webhook_targets);
        let obs = Arc::new(Observability::from_env());
        // DW-121: the first generation's record-stream state, compiled
        // through the same path every later `refresh` uses. The sinks
        // hold THIS dataplane's observability handle (their outcome
        // counters must land in the registered registry).
        let stream_targets = crate::events::stream::compile_stream_targets(
            snapshot.gateway().analytics_stream.as_ref(),
            &obs,
        );
        let (stream_tx, stream_anchor) = tokio::sync::watch::channel(stream_targets);
        let oauth2_token_cache = Arc::new(crate::security::oauth2::OAuth2TokenCache::new());
        let oidc_introspection_cache =
            Arc::new(crate::security::oidc::OidcIntrospectionCache::new());
        let oauth2_clients = build_oauth2_clients(snapshot.gateway());
        let ai = crate::ai::AiRuntime::compile(snapshot.gateway().ai.as_ref(), snapshot.gateway())
            .map(Arc::new);
        let ai_budgets = ArcSwap::from_pointee(crate::ai::budget::AiBudgetEngine::compile(
            snapshot.gateway(),
        ));
        let ai_pricing = ArcSwap::from_pointee(crate::ai::cost::PricingTable::compile(
            snapshot.gateway().ai.as_ref(),
        ));
        let ai_governance = ArcSwap::from_pointee(
            crate::ai::governance::GovernanceEngine::compile(snapshot.gateway().ai.as_ref()),
        );
        let ai_logging =
            crate::ai::logging::AiLoggingEngine::compile(snapshot.gateway().ai.as_ref())
                .map(Arc::new);
        let ai_guardrails = ArcSwap::from_pointee(crate::ai::guardrails::GuardrailEngine::compile(
            snapshot.gateway().ai.as_ref(),
        ));
        let ai_semantic_cache =
            crate::ai::semantic_cache::SemanticCacheEngine::compile(snapshot.gateway().ai.as_ref())
                .map(Arc::new);
        let dp = DataPlane {
            ai_budgets,
            ai_pricing,
            ai_governance,
            ai_logging: arc_swap::ArcSwapOption::new(ai_logging),
            ai_guardrails,
            ai_semantic_cache: arc_swap::ArcSwapOption::new(ai_semantic_cache),
            current: ArcSwap::from_pointee(Generation {
                snapshot,
                registry,
                oauth2_clients,
                ai,
            }),
            global_cap: ArcSwap::from_pointee(global_cap),
            priority_counters: PriorityCounters::default(),
            rate_limits: ArcSwap::from_pointee(rate_limits),
            authn: ArcSwap::from_pointee(CompositeAuthenticator::disabled()),
            state_store: std::sync::RwLock::new(None),
            credential_pepper: std::sync::RwLock::new(None),
            jwks_caches: std::sync::Mutex::new(HashMap::new()),
            nonce_cache: Arc::new(crate::security::authn::NonceCache::new()),
            oauth2_token_cache,
            oidc_introspection_cache,
            obs: Arc::clone(&obs),
            events,
            webhook_targets: target_tx,
            webhook_targets_anchor: target_anchor,
            stream_targets: stream_tx,
            stream_targets_anchor: stream_anchor,
            record_stream: arc_swap::ArcSwapOption::empty(),
            response_cache: Arc::new(crate::dataplane::response_cache::ResponseCache::default()),
            analytics: arc_swap::ArcSwapOption::empty(),
            geoip: arc_swap::ArcSwapOption::empty(),
            #[cfg(feature = "ent")]
            redis_conn: std::sync::RwLock::new(None),
            #[cfg(feature = "ent")]
            convergence: std::sync::RwLock::new(None),
            quota_near_limit_seen: std::sync::Mutex::new(std::collections::HashSet::new()),
            state,
        };
        dp.obs.set_config_generation(generation);
        // DW-052: the startup generation's SLO set (refresh() handles
        // every subsequent generation; construction builds the FIRST
        // one inline, so both paths must seed the collector).
        dp.obs.set_route_slos(slos);
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

    /// Publish the license status gauge (DW-032): 0 = no license (OSS),
    /// 1 = valid, 2 = expired within grace, 3 = expired past grace.
    /// Set once at startup and on every reload.
    pub fn set_license_status(&self, status: i64) {
        self.obs.set_license_status(status);
    }

    /// Attach the Redis connection for the distributed rate limiter
    /// (DW-031, ent feature only). Set once at startup by dwara-bin
    /// when the config carries a `redis_rate_limiter` block AND the
    /// license grants the `redis_rate_limiter` feature claim. After
    /// storing the connection, the rate-limit engine is IMMEDIATELY
    /// rebuilt with Redis-backed limiters (so the first generation
    /// served uses Redis, not the local limiter the constructor built).
    /// Subsequent `refresh` calls also use the Redis connection.
    #[cfg(feature = "ent")]
    pub fn set_redis_conn(&self, conn: redis::aio::ConnectionManager) {
        *self.redis_conn.write().expect("redis conn lock poisoned") = Some(conn.clone());
        // Rebuild the rate-limit engine with Redis-backed limiters.
        let snapshot = self.state.snapshot();
        if let Some(config) = snapshot.gateway().redis_rate_limiter.as_ref() {
            self.rate_limits
                .store(Arc::new(RateLimitEngine::compile_with_redis(
                    snapshot.gateway(),
                    conn,
                    config,
                )));
        }
    }

    /// Whether a Redis connection is attached for the distributed rate
    /// limiter (DW-031, ent feature only). Used by `refresh` to decide
    /// whether to compile with Redis-backed limiters.
    #[cfg(feature = "ent")]
    fn redis_conn_for_compile(&self) -> Option<redis::aio::ConnectionManager> {
        self.redis_conn
            .read()
            .expect("redis conn lock poisoned")
            .clone()
    }

    /// Attach the config convergence coordinator (DW-054, ent feature
    /// only). Set once at startup by dwara-bin when the config carries
    /// a `config_convergence` block AND the license grants the
    /// `config_convergence` feature claim. The coordinator's
    /// background poll task is spawned separately by dwara-bin; this
    /// only stores the handle so the reload path can publish the new
    /// generation after every successful local reload.
    #[cfg(feature = "ent")]
    pub fn set_convergence_coordinator(
        &self,
        coordinator: Arc<crate::dataplane::convergence::ConvergenceCoordinator>,
    ) {
        *self.convergence.write().expect("convergence lock poisoned") = Some(coordinator);
    }

    /// Publish the current local generation to the convergence backend
    /// (DW-054, ent feature only). Called by the reload path after
    /// every successful local reload. A no-op when no coordinator is
    /// attached (convergence not configured or not licensed).
    #[cfg(feature = "ent")]
    pub async fn publish_convergence_local(&self) {
        let Some(coordinator) = self
            .convergence
            .read()
            .expect("convergence lock poisoned")
            .clone()
        else {
            return;
        };
        coordinator.publish_local().await;
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

    /// Quota near-limit edge trigger (DW-033): `true` exactly when this
    /// (consumer, budget, window) has not been reported yet — the caller
    /// emits `quota_near_limit` and warns on `true`, stays silent on
    /// `false` (the second and later crossings inside one window are
    /// not noise). Stale windows are pruned under the same lock on the
    /// insert path only (at most two inserts per window per consumer),
    /// each budget against its OWN current window start, so the set
    /// holds at most one live entry per (consumer, budget) — bounded by
    /// quota-configured consumers x 2.
    fn note_quota_near_limit(
        &self,
        consumer: &str,
        budget: crate::state::quotas::Budget,
        window_start: i64,
    ) -> bool {
        let now_epoch_s = unix_now_secs();
        let (day_start, _) = crate::state::quotas::day_window(now_epoch_s);
        let (month_start, _) = crate::state::quotas::month_window(now_epoch_s);
        let mut seen = self
            .quota_near_limit_seen
            .lock()
            .expect("quota near-limit set poisoned");
        seen.retain(|(_, budget_key, window)| match *budget_key {
            crate::state::quotas::DAILY_KEY => *window >= day_start,
            crate::state::quotas::MONTHLY_KEY => *window >= month_start,
            _ => true,
        });
        seen.insert((consumer.to_string(), budget.key(), window_start))
    }

    /// Attach the embedded analytics store (DW-043): dwara-bin opens
    /// the configured database, spawns the writer/rollup workers, and
    /// hands the store here ONCE, before serving traffic. There is no
    /// detach: analytics lifetime is the process lifetime (the
    /// database file outlives restarts; the runtime handle does not).
    pub fn set_analytics(&self, store: Arc<crate::analytics::EmbeddedAnalytics>) {
        self.analytics.store(Some(store));
    }

    /// The embedded analytics store when one is attached (DW-043;
    /// None = the analytics endpoints 404 and recording is a no-op).
    /// Admin surface seam.
    pub fn analytics(&self) -> Option<Arc<crate::analytics::EmbeddedAnalytics>> {
        self.analytics.load_full()
    }

    /// Attach the access-record stream (DW-121): dwara-bin constructs
    /// it ALWAYS (capacity from the config when the block is present
    /// at boot, the default otherwise) and hands it here once, before
    /// serving traffic; the flusher is spawned separately
    /// ([`DataPlane::spawn_record_stream_flusher`]). Arming is the
    /// generation's business: this immediately applies the CURRENT
    /// compiled sink set's enabled flag, so a stream attached after
    /// construction with sinks configured does not wait for a reload
    /// to start queuing.
    pub fn set_record_stream(&self, stream: Arc<crate::events::stream::AccessRecordStream>) {
        let enabled = !self.stream_targets.borrow().sinks.is_empty();
        stream.set_enabled(enabled);
        self.record_stream.store(Some(stream));
    }

    /// The access-record stream when one is attached (DW-121; None =
    /// offers are no-ops — the direct-drive tests' shape). Scrape and
    /// diagnostics seam.
    pub fn record_stream(&self) -> Option<Arc<crate::events::stream::AccessRecordStream>> {
        self.record_stream.load_full()
    }

    /// A fresh receiver of the CURRENT record-stream target state
    /// (DW-121); updates on every `refresh`. Tests driving the flusher
    /// directly use this.
    pub fn stream_targets(
        &self,
    ) -> tokio::sync::watch::Receiver<crate::events::stream::StreamTargets> {
        self.stream_targets.subscribe()
    }

    /// Spawn the record-stream flusher (DW-121): one background task
    /// draining the stream's bounded channel into ordered batches and
    /// delivering each batch (one retry cycle per batch) to the
    /// current generation's sinks. Exactly one flusher per dataplane
    /// (the channel's single-consumer receiver is gone after the
    /// first); a duplicate spawn logs and returns a finished handle.
    /// The task stops on `shutdown` after one final drain-and-flush.
    pub fn spawn_record_stream_flusher(
        self: &Arc<Self>,
        shutdown: tokio::sync::watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        let Some(stream) = self.record_stream() else {
            tracing::error!(
                code = "record_stream_flusher_no_stream",
                "record stream flusher spawned without a stream attached; ignoring"
            );
            return tokio::spawn(async {});
        };
        let Some(rx) = stream.take_receiver() else {
            tracing::error!(
                code = "record_stream_flusher_already_running",
                "record stream flusher already spawned for this dataplane; ignoring \
                 the duplicate spawn"
            );
            return tokio::spawn(async {});
        };
        tokio::spawn(crate::events::stream::run_stream_flusher(
            rx,
            self.stream_targets(),
            Arc::clone(&self.obs),
            shutdown,
        ))
    }

    /// The request-completion record-stream hook (DW-121):
    /// fire-and-forget offer of one finished request's record to the
    /// external sink pipeline. No-op (one ArcSwap load) when no stream
    /// is attached or the current generation compiled no sink; never
    /// blocks (a bounded-channel `try_send` that drops and counts on
    /// full).
    fn record_stream_offer(&self, rec: &observability::AccessRecord) {
        let guard = self.record_stream.load();
        if let Some(stream) = &*guard {
            stream.offer(rec);
        }
    }

    /// Attach/replace the GeoIP database (DW-050). dwara-bin opens it
    /// at startup and the hot-reload watcher swaps it; the swap is
    /// atomic and in-flight requests keep their loaded reader.
    pub fn set_geoip(&self, db: std::sync::Arc<crate::security::geoip::GeoipDb>) {
        self.geoip.store(Some(db));
    }

    /// The current GeoIP database, if one is loaded (DW-050).
    pub fn geoip(&self) -> Option<std::sync::Arc<crate::security::geoip::GeoipDb>> {
        self.geoip.load_full()
    }

    /// The request-completion analytics hook (DW-043): fire-and-forget
    /// record of one finished request. No-op (one ArcSwap load) when
    /// analytics is not configured; never blocks (the sink is a
    /// bounded-channel `try_send` that drops and counts on full).
    fn record_analytics(&self, rec: &observability::AccessRecord) {
        let guard = self.analytics.load();
        if let Some(store) = &*guard {
            store.record(rec);
        }
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

    /// Hash a NEW api-key secret exactly as the config seed path does
    /// (DW-046, the admin credential-issue endpoint's helper):
    /// `hmac-sha256:<hex>` when a pepper is configured (#124),
    /// legacy `sha256:<hex>` otherwise — the authenticator verifies
    /// either shape with the SAME pepper state, so an issued key
    /// authenticates immediately. The secret never leaves this call's
    /// stack in the clear (hashing is one-shot; no storage of raw
    /// bytes anywhere).
    pub fn hash_new_credential(&self, secret: &str) -> String {
        match self.pepper_bytes() {
            Some(pepper) => crate::config::credentials::hmac_stored_hash(&pepper, secret),
            None => crate::config::credentials::sha256_stored_hash(secret),
        }
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
            Arc::clone(&self.oidc_introspection_cache),
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
        let previous = self.current();
        let slos = compile_route_slos(&snapshot);
        let registry = Arc::new(UpstreamRegistry::from_snapshot_with_previous_and_events(
            &snapshot,
            &previous.registry,
            Some(&self.events.emitter()),
        ));
        self.global_cap
            .store(Arc::new(global_cap_of(snapshot.gateway())));
        // DW-031: compile with Redis-backed limiters when a Redis
        // connection is attached (ent feature) and the config carries
        // a redis_rate_limiter block; otherwise the local GCRA limiter.
        #[cfg(feature = "ent")]
        {
            if let Some(conn) = self.redis_conn_for_compile() {
                if let Some(config) = snapshot.gateway().redis_rate_limiter.as_ref() {
                    self.rate_limits
                        .store(Arc::new(RateLimitEngine::compile_with_redis(
                            snapshot.gateway(),
                            conn,
                            config,
                        )));
                } else {
                    self.rate_limits
                        .store(Arc::new(RateLimitEngine::compile(snapshot.gateway())));
                }
            } else {
                self.rate_limits
                    .store(Arc::new(RateLimitEngine::compile(snapshot.gateway())));
            }
        }
        #[cfg(not(feature = "ent"))]
        {
            self.rate_limits
                .store(Arc::new(RateLimitEngine::compile(snapshot.gateway())));
        }
        // DW-037: cache epochs advance for every route whose definition
        // changed between generations (stored bytes were shaped by the
        // old masking/transform/policy); unchanged routes stay warm.
        self.response_cache
            .note_generation(Some(previous.snapshot.as_ref()), &snapshot);
        let oauth2_clients = build_oauth2_clients(snapshot.gateway());
        let ai = crate::ai::AiRuntime::compile(snapshot.gateway().ai.as_ref(), snapshot.gateway())
            .map(Arc::new);
        // DW-078: budget RULES swap with the generation; the LEDGER
        // (spent windows) carries over — a reload never resets a
        // live budget window.
        self.ai_budgets.store(Arc::new(
            crate::ai::budget::AiBudgetEngine::compile_with_ledger(
                snapshot.gateway(),
                self.ai_budgets.load_full().ledger(),
            ),
        ));
        // DW-079: the pricing table swaps with the generation — a
        // pricing change takes effect on the next request with no
        // restart.
        self.ai_pricing
            .store(Arc::new(crate::ai::cost::PricingTable::compile(
                snapshot.gateway().ai.as_ref(),
            )));
        // DW-084: the governance engine swaps with the generation —
        // an allowlist change takes effect on the next request with no
        // restart.
        self.ai_governance
            .store(Arc::new(crate::ai::governance::GovernanceEngine::compile(
                snapshot.gateway().ai.as_ref(),
            )));
        // DW-081: the logging engine swaps with the generation — a
        // logging config change takes effect on the next request with
        // no restart. Also update the analytics store's prompt log
        // retention so the maintenance tick ages records out per the
        // new window.
        let logging_engine =
            crate::ai::logging::AiLoggingEngine::compile(snapshot.gateway().ai.as_ref())
                .map(Arc::new);
        if let Some(engine) = &logging_engine {
            if let Some(analytics) = self.analytics() {
                let retention_ms = (engine.retention_secs() as i64) * 1000;
                analytics.set_prompt_log_retention_ms(retention_ms);
            }
        }
        self.ai_logging.store(logging_engine);
        // DW-082: the guardrail engine swaps with the generation —
        // a guardrail change takes effect on the next request with no
        // restart.
        self.ai_guardrails
            .store(Arc::new(crate::ai::guardrails::GuardrailEngine::compile(
                snapshot.gateway().ai.as_ref(),
            )));
        // DW-083: the semantic cache config updates IN PLACE (the
        // HNSW index and cached entries persist across reloads). A
        // config that newly enables the cache constructs a fresh
        // engine; a config that removes the block clears it.
        let sem_cache_cfg = crate::ai::semantic_cache::SemanticCacheEngine::config_of(
            snapshot.gateway().ai.as_ref(),
        );
        match (sem_cache_cfg, self.ai_semantic_cache.load_full()) {
            (Some(new_cfg), Some(existing)) => {
                existing.update_config(new_cfg);
            }
            (Some(new_cfg), None) => {
                self.ai_semantic_cache.store(Some(Arc::new(
                    crate::ai::semantic_cache::SemanticCacheEngine::new(new_cfg),
                )));
            }
            (None, _) => {
                self.ai_semantic_cache.store(None);
            }
        }
        self.current.store(Arc::new(Generation {
            snapshot,
            registry,
            oauth2_clients,
            ai,
        }));
        self.obs.set_config_generation(generation);
        // DW-052: the new generation's SLO set (plain targets, converted
        // here — observability takes primitives, not config types).
        // Routes whose `slo` block vanished stop exporting series.
        self.obs.set_route_slos(slos);
        // DW-044: the new generation's webhook targets (secret references
        // re-resolved at compile) apply from the next event on.
        let compiled = Arc::new(compile_webhook_targets(&self.state.snapshot()));
        if self.webhook_targets.send(compiled).is_err() {
            tracing::error!(
                code = "webhook_targets_watch_closed",
                "webhook target watch channel closed; deliveries will keep using the last set"
            );
        }
        // DW-121: the new generation's record-stream state — sinks
        // (re-resolved per compile), flush cadence, batch bound —
        // applies to the next batch, and the offer path's enabled flag
        // follows the compiled sink count (an unconfigured or
        // fail-closed stream never queues a record). ORDER: the watch
        // is pushed BEFORE the flag flips, so a reload ARMING the
        // stream never queues a record the flusher has no sink for
        // yet (the symmetric disarm window — offers stopping a moment
        // before the flusher's sink set empties — drains the tail to
        // the still-compiled sink, which is the operator's intent).
        let stream_state = crate::events::stream::compile_stream_targets(
            self.state.snapshot().gateway().analytics_stream.as_ref(),
            &self.obs,
        );
        if self.stream_targets.send(stream_state).is_err() {
            tracing::error!(
                code = "record_stream_targets_watch_closed",
                "record stream target watch channel closed; the flusher will keep \
                 using the last set"
            );
        }
        let armed = !self.stream_targets.borrow().sinks.is_empty();
        if let Some(stream) = self.record_stream() {
            stream.set_enabled(armed);
        }
        self.rebuild_authn();
    }

    /// The current (snapshot, registry) generation pair. pub(super):
    /// the response cache's background revalidation (DW-037) resolves
    /// routes through the same generation the dataplane serves.
    pub(super) fn current(&self) -> Arc<Generation> {
        self.current.load_full()
    }

    /// The OAuth2 token cache (DW-035): per-dataplane, carried across
    /// generation swaps so a reload never discards a still-valid token.
    /// pub(super): the response cache's background revalidation (DW-037)
    /// drives the same forward path and needs the token cache too.
    pub(super) fn oauth2_token_cache(&self) -> &Arc<crate::security::oauth2::OAuth2TokenCache> {
        &self.oauth2_token_cache
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

    /// The shared handle behind [`Self::observability`] (DW-039: the
    /// WebSocket tunnel task outlives the request and needs an owned
    /// handle to record its policy outcome).
    pub fn observability_arc(&self) -> Arc<Observability> {
        Arc::clone(&self.obs)
    }

    /// This dataplane's event bus (DW-044): breaker/ejection/config
    /// events emit onto it; `spawn_webhook_deliverer` drains it.
    pub fn events(&self) -> &Arc<crate::events::EventBus> {
        &self.events
    }

    /// The local response cache (DW-037): lookup/store stages run from
    /// `handle`, the admin purge endpoint and the metrics gauge walk
    /// read from here. Shared as an `Arc` because stale-while-revalidate
    /// spawns background revalidations that outlive the request.
    pub fn response_cache(&self) -> &Arc<crate::dataplane::response_cache::ResponseCache> {
        &self.response_cache
    }

    /// A fresh receiver of the CURRENT webhook target set (DW-044);
    /// updates on every `refresh`. Tests driving the deliverer directly
    /// (without [`DataPlane::spawn_webhook_deliverer`]) use this.
    pub fn webhook_targets(
        &self,
    ) -> tokio::sync::watch::Receiver<Arc<Vec<crate::events::webhook::WebhookTarget>>> {
        self.webhook_targets.subscribe()
    }

    /// Spawn the webhook deliverer (DW-044) against this dataplane's bus,
    /// target set, and metrics: one background task that drains the event
    /// queue and POSTs matching events to the configured targets (see
    /// `events::webhook` for the delivery contract). Exactly one
    /// deliverer per dataplane: a second call logs and returns an
    /// already-finished handle (the bus's single-consumer receiver is
    /// gone). The task stops on `shutdown` (or when the dataplane is
    /// dropped and the bus closes).
    pub fn spawn_webhook_deliverer(
        self: &Arc<Self>,
        shutdown: tokio::sync::watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        match self.events.take_receiver() {
            Some(rx) => tokio::spawn(crate::events::webhook::run_deliverer(
                rx,
                self.webhook_targets(),
                Arc::clone(&self.obs),
                shutdown,
            )),
            None => {
                tracing::error!(
                    code = "webhook_deliverer_already_running",
                    "webhook deliverer already spawned for this dataplane; \
                     ignoring the duplicate spawn"
                );
                tokio::spawn(async {})
            }
        }
    }

    /// Per-consumer quota figures for one export window (DW-120): the
    /// read side of the statement's quota columns, assembled from the
    /// CURRENT config generation's quota blocks and the state store's
    /// `quota_counters`. A budget's figures appear only when its UTC
    /// quota window FULLY CONTAINS `[period_start_s, period_end_s)`
    /// (see `analytics::exports`' alignment rule): a daily export
    /// carries the same-day daily counter and the month-to-date
    /// monthly counter; a monthly export carries only the monthly
    /// counter. Consumers without a quotas block, without a store, or
    /// not yet synced into the store carry no figures — never
    /// fabricated zeros.
    pub fn quota_figures_at(
        &self,
        period_start_s: i64,
        period_end_s: i64,
    ) -> std::collections::HashMap<String, crate::analytics::exports::QuotaFigures> {
        let mut out = std::collections::HashMap::new();
        let Some(store) = self.state_store() else {
            return out;
        };
        for consumer in &self.current().snapshot.gateway().consumers {
            let Some(quotas) = &consumer.quotas else {
                continue;
            };
            let figures = match store.lookup_consumer(&consumer.name) {
                Ok(Some(record)) => {
                    let usage = crate::state::quotas::current_usage(
                        &store,
                        record.id,
                        quotas,
                        period_start_s,
                    );
                    let mut f = crate::analytics::exports::QuotaFigures::default();
                    for u in &usage {
                        let contains = u.window_start_epoch_s as i64 <= period_start_s
                            && period_end_s <= u.reset_epoch_s as i64;
                        if !contains {
                            continue;
                        }
                        let b = crate::analytics::exports::QuotaBudget {
                            used: u.used,
                            limit: u.limit,
                            window_start_epoch_s: u.window_start_epoch_s as i64,
                            reset_epoch_s: u.reset_epoch_s as i64,
                        };
                        match u.budget {
                            crate::state::quotas::Budget::Daily => f.daily = Some(b),
                            crate::state::quotas::Budget::Monthly => f.monthly = Some(b),
                        }
                    }
                    f
                }
                _ => crate::analytics::exports::QuotaFigures::default(),
            };
            out.insert(consumer.name.clone(), figures);
        }
        out
    }

    /// Spawn the usage-report export worker (DW-120): one background
    /// task on the same interval-plus-shutdown-watch machinery as the
    /// analytics rollup cascade, reading the CURRENT config generation
    /// each tick (a reload can add, change, or remove `analytics.
    /// exports` without a restart) and exporting every closed window
    /// of the configured kind that has no successful run record —
    /// oldest first, so a restart backfills missed windows. No-ops
    /// without an analytics store or an exports block. Safe to abort:
    /// each export is an atomic file write plus an idempotent record.
    pub fn spawn_export_worker(
        self: &Arc<Self>,
        shutdown: tokio::sync::watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        let dp = Arc::clone(self);
        let mut shutdown = shutdown;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(
                crate::analytics::exports::EXPORT_TICK_MS,
            ));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        let Some(exports_cfg) = dp
                            .state
                            .snapshot()
                            .gateway()
                            .analytics
                            .as_ref()
                            .and_then(|a| a.exports.as_ref())
                            .cloned()
                        else {
                            continue;
                        };
                        let Some(store) = dp.analytics() else {
                            continue;
                        };
                        crate::analytics::exports::run_due(
                            &store,
                            &exports_cfg,
                            &|ps, pe| dp.quota_figures_at(ps, pe),
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_millis() as i64)
                                .unwrap_or(0),
                        );
                    }
                    _ = shutdown.changed() => return,
                }
            }
        })
    }

    /// The AI budget engine (DW-078): current rules over the shared
    /// reload-surviving ledger.
    pub fn ai_budgets(&self) -> Arc<crate::ai::budget::AiBudgetEngine> {
        self.ai_budgets.load_full()
    }

    /// The AI pricing table (DW-079): current per-model token rates.
    pub fn ai_pricing(&self) -> Arc<crate::ai::cost::PricingTable> {
        self.ai_pricing.load_full()
    }

    /// The AI governance engine (DW-084): current per-team model
    /// allowlists and the audit switch.
    pub fn ai_governance(&self) -> Arc<crate::ai::governance::GovernanceEngine> {
        self.ai_governance.load_full()
    }

    /// The AI prompt/response logging engine (DW-081): current logging
    /// config (enabled, sampling, retention) and compiled redactor.
    /// None when logging is not configured (capture off, privacy-first).
    pub fn ai_logging(&self) -> Option<Arc<crate::ai::logging::AiLoggingEngine>> {
        self.ai_logging.load_full()
    }

    /// The AI guardrail engine (DW-082): current compiled guardrail
    /// rules (prompt-injection, PII, banned-content, output schema
    /// enforcement). Empty when guardrails are not configured (every
    /// prompt and response passes through — fail-open).
    pub fn ai_guardrails(&self) -> Arc<crate::ai::guardrails::GuardrailEngine> {
        self.ai_guardrails.load_full()
    }

    /// The AI semantic cache engine (DW-083): the embedding-similarity
    /// cache. None when semantic caching is not configured or disabled.
    /// Persists across reloads (the HNSW index and cached entries
    /// survive config refreshes).
    pub fn ai_semantic_cache(&self) -> Option<Arc<crate::ai::semantic_cache::SemanticCacheEngine>> {
        self.ai_semantic_cache.load_full()
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
            // DW-033: quota usage/limit gauges are a scrape-time
            // snapshot of the state store's counters (the same walk
            // model as the rate-limiter gauges above).
            refresh_quota_gauges(dp, obs);
            crate::events::refresh_event_gauges(&dp.events, obs);
            // DW-121: the stream's offered/dropped gauges are a
            // scrape-time snapshot of the stream's monotonic counters
            // (the same walk model).
            if let Some(stream) = dp.record_stream() {
                crate::events::stream::refresh_stream_gauges(&stream, obs);
            }
            // DW-037: the cache entries gauge is a scrape-time snapshot
            // of the backing store's approximate count (the same walk
            // model as the rate-limiter gauges above).
            obs.set_cache_entries(dp.response_cache().live_entries());
            Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "text/plain; version=0.0.4")
                .body(ProxyBody::Full(Full::new(Bytes::from(obs.render()))))
                .ok()
        }
        _ => None,
    }
}

/// The MCP session-id header name (DW-087).
const MCP_SESSION_ID_HDR: hyper::header::HeaderName =
    hyper::header::HeaderName::from_static("mcp-session-id");

/// Maximum MCP request body size (1 MiB — JSON-RPC requests are small;
/// anything larger is a misbehaving or hostile client).
const MCP_BODY_CAP: u64 = 1024 * 1024;

/// Handle one MCP JSON-RPC request (DW-087): authenticate, collect
/// the body, parse JSON-RPC, dispatch to the compiled MCP gateway,
/// manage the session (state store), record analytics, and return the
/// JSON-RPC response. The MCP path shadows any configured route (it
/// is checked before route resolution in [`handle_inner`]).
async fn mcp_handle<B>(
    dp: &Arc<DataPlane>,
    peer: IpAddr,
    req: Request<B>,
    mcp: &Arc<crate::ai::mcp::CompiledMcp>,
    rid: &str,
    rec: &mut AccessRecord,
) -> Response<ProxyBody>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    use http_body_util::BodyExt as _;

    // --- AuthN (same as the proxy path) ---
    let authn = dp.authn.load_full();
    let client_cert = req
        .extensions()
        .get::<Arc<crate::security::authn::ClientCertificate>>()
        .cloned();
    let authn_req = crate::security::authn::AuthnRequest {
        method: req.method(),
        uri: req.uri(),
        headers: req.headers(),
        client_cert: client_cert.as_deref(),
    };
    let identity = match authn
        .authenticate(&authn_req)
        .instrument(tracing::info_span!("mcp_authn"))
        .await
    {
        Ok(id) => id,
        Err(AuthError::Invalid(_)) => {
            return unauthorized(&authn.challenge(), rid);
        }
        Err(AuthError::Unavailable(msg)) => {
            tracing::error!(
                code = "mcp_authn_unavailable",
                request_id = %rid,
                error = %msg,
                "authn unavailable for MCP request"
            );
            return simple(
                StatusCode::INTERNAL_SERVER_ERROR,
                "authn_unavailable",
                "authentication unavailable",
                rid,
            );
        }
    };
    let consumer = identity
        .as_ref()
        .map(|i| i.consumer_name.clone())
        .unwrap_or_else(|| "anonymous".to_string());
    rec.consumer = consumer.clone();

    // --- Collect the request body ---
    // Split the request first so we can still read headers after
    // consuming the body.
    let (parts, body) = req.into_parts();
    let limited = Limited::new(body, MCP_BODY_CAP as usize);
    let body_bytes = match limited.collect().await {
        Ok(c) => c.to_bytes(),
        Err(err) => {
            if err.downcast_ref::<LengthLimitError>().is_some() {
                return simple(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "mcp_body_too_large",
                    &format!("mcp request body exceeds {} bytes", MCP_BODY_CAP),
                    rid,
                );
            }
            return simple(
                StatusCode::BAD_REQUEST,
                "mcp_body_read_failed",
                &err.to_string(),
                rid,
            );
        }
    };

    // --- Parse JSON-RPC ---
    let body_json: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => {
            let resp = crate::ai::mcp::parse_error_response();
            return mcp_json_response(StatusCode::BAD_REQUEST, &resp, None);
        }
    };
    let rpc_req = match crate::ai::mcp::JsonRpcRequest::parse(&body_json) {
        Ok(r) => r,
        Err(err_resp) => {
            return mcp_json_response(StatusCode::BAD_REQUEST, &err_resp, None);
        }
    };

    // --- Session management ---
    let session_id_hdr = parts
        .headers
        .get(&MCP_SESSION_ID_HDR)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let state_store = dp.state_store();

    // For non-initialize requests, validate the session if a state
    // store is attached. Without a state store, sessions are
    // stateless (the session id is still returned but not persisted).
    if let Some(sid) = &session_id_hdr {
        if rpc_req.method != "initialize" {
            if let Some(store) = &state_store {
                if let Ok(false) = store.touch_mcp_session(sid) {
                    return mcp_json_response(
                        StatusCode::NOT_FOUND,
                        &crate::ai::mcp::json_rpc_error_pub(
                            None,
                            -32000,
                            "session not found or expired",
                        ),
                        None,
                    );
                }
            }
        }
    }

    // --- AuthZ for tools/call (DW-087) ---
    // The `ai` domain may not import `security` (dependency direction),
    // so authz is evaluated here in the dataplane. A tool with an
    // authz attachment is only callable by consumers satisfying the
    // rules; a tool without one is open to any authenticated consumer.
    let mcp_tool_started = if rpc_req.method == "tools/call" {
        Some(std::time::Instant::now())
    } else {
        None
    };
    if rpc_req.method == "tools/call" {
        let tool_name = rpc_req
            .params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if let Some(authz) = mcp.tool_authz(tool_name) {
            let authz_chain = crate::security::authz::AuthzChain {
                consumer: None,
                route: None,
                service: None,
                listener: None,
                global: Some(authz),
            };
            let authz_ctx = crate::security::authz::AuthzContext {
                identity: identity.as_ref(),
                consumer_groups: identity
                    .as_ref()
                    .map(|i| i.groups.as_slice())
                    .unwrap_or(&[]),
                peer_ip: peer,
                effective_ip: peer,
                geoip: None,
            };
            if crate::security::authz::authorize(&authz_chain, &authz_ctx)
                != crate::security::authz::Decision::Allow
            {
                let duration_ms = mcp_tool_started
                    .map(|s| s.elapsed().as_secs_f64() * 1000.0)
                    .unwrap_or(0.0);
                let outcome = crate::ai::mcp::McpToolCallOutcome {
                    tool_name: tool_name.to_string(),
                    allowed: false,
                    duration_ms,
                    error_code: Some("unauthorized".to_string()),
                    status: "denied".to_string(),
                };
                // Record metrics for the denied call (DW-087).
                dp.obs.record_mcp_tool_call(tool_name, "denied");
                dp.obs
                    .record_mcp_tool_duration(tool_name, duration_ms / 1000.0);
                // Record analytics for the denied call.
                if let Some(analytics) = dp.analytics() {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as i64)
                        .unwrap_or(0);
                    analytics.offer_mcp_tool_call(crate::analytics::McpToolCallRecord {
                        ts_ms: now_ms,
                        request_id: rid.to_string(),
                        session_id: session_id_hdr.clone().unwrap_or_default(),
                        consumer: consumer.clone(),
                        tool_name: outcome.tool_name.clone(),
                        allowed: outcome.allowed,
                        duration_ms: outcome.duration_ms,
                        error_code: outcome.error_code.clone(),
                        status: outcome.status.clone(),
                    });
                }
                let result_json = serde_json::json!({
                    "content": [{"type": "text", "text": "unauthorized: this tool requires authorization"}],
                    "isError": true,
                });
                let resp = if rpc_req.id.is_none() {
                    serde_json::json!({})
                } else {
                    crate::ai::mcp::json_rpc_result_pub(rpc_req.id.clone(), result_json)
                };
                let status = if rpc_req.id.is_none() {
                    StatusCode::ACCEPTED
                } else {
                    StatusCode::OK
                };
                return mcp_json_response(status, &resp, session_id_hdr.as_deref());
            }
        }
    }

    // --- Dispatch to the compiled MCP gateway ---
    let result = mcp
        .handle_request(&rpc_req, session_id_hdr.as_deref(), &consumer)
        .await;

    // --- AuthZ filtering for tools/list (DW-087) ---
    // Filter the tools list to only show tools the caller is allowed
    // to invoke. The filtering happens here (dataplane) because the
    // `ai` domain may not import `security`.
    if rpc_req.method == "tools/list" {
        if let Some(resp) = &result.response {
            if let Some(tools) = resp.get("result").and_then(|r| r.get("tools")) {
                if let Some(tools_arr) = tools.as_array() {
                    let mut filtered = Vec::new();
                    for tool in tools_arr {
                        let name = tool.get("name").and_then(|n| n.as_str()).unwrap_or("");
                        let allowed = match mcp.tool_authz(name) {
                            None => true,
                            Some(authz) => {
                                let chain = crate::security::authz::AuthzChain {
                                    consumer: None,
                                    route: None,
                                    service: None,
                                    listener: None,
                                    global: Some(authz),
                                };
                                let ctx = crate::security::authz::AuthzContext {
                                    identity: identity.as_ref(),
                                    consumer_groups: identity
                                        .as_ref()
                                        .map(|i| i.groups.as_slice())
                                        .unwrap_or(&[]),
                                    peer_ip: peer,
                                    effective_ip: peer,
                                    geoip: None,
                                };
                                crate::security::authz::authorize(&chain, &ctx)
                                    == crate::security::authz::Decision::Allow
                            }
                        };
                        if allowed {
                            filtered.push(tool.clone());
                        }
                    }
                    // Rebuild the response with filtered tools.
                    // We need to return a modified result — but since
                    // `result` is immutable, we'll handle this by
                    // post-processing the response below.
                    // Store the filtered list for response building.
                    // Actually, let's just rebuild the response here.
                    let filtered_resp = if rpc_req.id.is_none() {
                        serde_json::json!({})
                    } else {
                        crate::ai::mcp::json_rpc_result_pub(
                            rpc_req.id.clone(),
                            serde_json::json!({
                                "tools": filtered,
                                "nextCursor": null,
                            }),
                        )
                    };
                    let session_id_for_hdr = result.session_id.clone();
                    return mcp_json_response(
                        StatusCode::OK,
                        &filtered_resp,
                        session_id_for_hdr.as_deref(),
                    );
                }
            }
        }
    }

    // --- Session lifecycle (state store) ---
    if result.session_initialized {
        if let Some(sid) = &result.session_id {
            if let Some(store) = &state_store {
                // Enforce max concurrent sessions.
                if let Ok(count) = store.count_active_mcp_sessions() {
                    if count >= mcp.sessions_max_concurrent {
                        // Reject: too many sessions.
                        let resp = crate::ai::mcp::json_rpc_error_pub(
                            rpc_req.id.clone(),
                            -32001,
                            "too many concurrent sessions",
                        );
                        return mcp_json_response(StatusCode::SERVICE_UNAVAILABLE, &resp, None);
                    }
                }
                let client_info = rpc_req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("clientInfo"))
                    .map(|v| v.to_string());
                let _ = store.create_mcp_session(
                    sid,
                    &consumer,
                    mcp.sessions_ttl_secs,
                    client_info.as_deref(),
                );
            }
            // Record the session-initialized metric (DW-087). Counted
            // whether or not a state store is attached (the session is
            // created either way; without a store it is stateless).
            dp.obs.record_mcp_session("initialized");
        }
    }
    if result.session_closed {
        if let Some(sid) = &result.session_id {
            if let Some(store) = &state_store {
                let _ = store.delete_mcp_session(sid);
            }
            // Record the session-closed metric (DW-087).
            dp.obs.record_mcp_session("closed");
        }
    }

    // --- Analytics and metrics (tool calls) ---
    if let Some(outcome) = &result.tool_call {
        // Record metrics (DW-087): tool call count by status and
        // duration. The duration from the authz-check start through
        // the upstream response is used; when no timer was started
        // (e.g. a tool-not-found before the dispatch), the outcome's
        // own duration is used.
        let dur_secs = if let Some(started) = mcp_tool_started {
            started.elapsed().as_secs_f64()
        } else {
            outcome.duration_ms / 1000.0
        };
        dp.obs
            .record_mcp_tool_call(&outcome.tool_name, &outcome.status);
        dp.obs
            .record_mcp_tool_duration(&outcome.tool_name, dur_secs);
        if let Some(analytics) = dp.analytics() {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            analytics.offer_mcp_tool_call(crate::analytics::McpToolCallRecord {
                ts_ms: now_ms,
                request_id: rid.to_string(),
                session_id: result.session_id.clone().unwrap_or_default(),
                consumer: consumer.clone(),
                tool_name: outcome.tool_name.clone(),
                allowed: outcome.allowed,
                duration_ms: outcome.duration_ms,
                error_code: outcome.error_code.clone(),
                status: outcome.status.clone(),
            });
        }
    }

    // --- Build the response ---
    let session_id_for_hdr = result.session_id.clone();
    match result.response {
        Some(resp_json) => {
            mcp_json_response(StatusCode::OK, &resp_json, session_id_for_hdr.as_deref())
        }
        None => {
            // Notification: no response body, but still 202 Accepted.
            mcp_json_response(
                StatusCode::ACCEPTED,
                &serde_json::json!({}),
                session_id_for_hdr.as_deref(),
            )
        }
    }
}

/// Build a JSON response for the MCP endpoint (DW-087).
fn mcp_json_response(
    status: StatusCode,
    body: &serde_json::Value,
    session_id: Option<&str>,
) -> Response<ProxyBody> {
    let mut builder = Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json");
    if let Some(sid) = session_id {
        builder = builder.header(&MCP_SESSION_ID_HDR, sid);
    }
    builder
        .body(ProxyBody::Full(Full::new(Bytes::from(body.to_string()))))
        .expect("static response parts")
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

/// Refresh the quota observation gauges at scrape time (DW-033): the
/// current-window usage and the configured cap of every
/// quota-configured consumer's every budget, read from the state
/// store (the same `current_usage` walk the admin `/quotas/usage`
/// endpoint and the near-limit trigger use). Series cardinality is
/// config-bounded (quota consumers x the closed daily/monthly set).
/// A consumer REMOVED from the config by a reload keeps its last
/// series values until restart — the accepted staleness trade of the
/// scrape-time snapshot model (the rate-limiter gauges carry the same
/// caveat); the used/limit ratio of a stale pair stays correct
/// because both series freeze together. No store (quotas inert) or a
/// store error skips the refresh without failing the scrape.
pub fn refresh_quota_gauges(dp: &DataPlane, obs: &Observability) {
    let Some(store) = dp.state_store() else {
        return;
    };
    let current = dp.current();
    let gateway = current.snapshot.gateway();
    let now_epoch_s = unix_now_secs();
    for c in &gateway.consumers {
        let Some(quotas) = &c.quotas else {
            continue;
        };
        let Ok(Some(record)) = store.lookup_consumer(&c.name) else {
            continue;
        };
        for u in crate::state::quotas::current_usage(&store, record.id, quotas, now_epoch_s) {
            obs.set_quota_used(&c.name, u.budget.as_str(), u.used as i64);
            obs.set_quota_limit(&c.name, u.budget.as_str(), u.limit as i64);
        }
    }
}

/// Wall-clock seconds since the Unix epoch (the quota windows' time
/// domain; clamped at 0 for a pre-epoch clock, which simply pins every
/// window to the epoch day).
fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// One-shot latches for the two quota wiring gaps (DW-033): both are
/// deployment mistakes, not per-request events — the first occurrence
/// warns loudly, the rest stay silent so a misconfigured gateway does
/// not log-storm under load.
static QUOTA_STORE_MISSING_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static QUOTA_CONSUMER_UNSYNCED_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn warn_quota_store_missing(consumer: &str) {
    if !QUOTA_STORE_MISSING_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::warn!(
            code = "quota_store_missing",
            consumer = consumer,
            "a consumer declares quotas but no state store is attached (set \
             DWARA_STATE_DB and restart): request budgets are NOT enforced"
        );
    }
}

fn warn_quota_consumer_unsynced(consumer: &str) {
    if !QUOTA_CONSUMER_UNSYNCED_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::warn!(
            code = "quota_consumer_unsynced",
            consumer = consumer,
            "a quota-configured consumer has no state-store row (consumer sync \
             runs at startup): its request budgets are NOT enforced until \
             the store is synced"
        );
    }
}

/// Compile one generation's per-route SLO targets (DW-052): config
/// percentages to the plain fractions observability consumes (that
/// domain takes primitives only — it depends on nothing).
fn compile_route_slos(
    snapshot: &crate::snapshot::Snapshot,
) -> Vec<(String, observability::SloTargets)> {
    snapshot
        .gateway()
        .routes
        .iter()
        .filter_map(|r| {
            r.slo.as_ref().map(|s| {
                (
                    r.name.clone(),
                    observability::SloTargets {
                        availability: s.availability / 100.0,
                        latency_threshold_ms: s.latency_ms,
                        latency_target: s.latency_target.unwrap_or(99.0) / 100.0,
                    },
                )
            })
        })
        .collect()
}

/// Compile one generation's webhook targets (DW-044). Validation
/// already resolved every secret reference at publish; this re-resolves
/// per build (the same validate-then-resolve backstop as the
/// authenticator's credentials): a target whose reference broke between
/// validate and build is skipped with a loud error — never delivered
/// with placeholder bytes, never fatal to the generation.
fn compile_webhook_targets(snapshot: &Snapshot) -> Vec<crate::events::webhook::WebhookTarget> {
    snapshot
        .gateway()
        .webhooks
        .iter()
        .filter_map(
            |cfg| match crate::events::webhook::WebhookTarget::compile(cfg) {
                Ok(target) => Some(target),
                Err(error) => {
                    tracing::error!(
                        code = "webhook_target_unusable",
                        "webhook target skipped for this generation (fail closed): {error}"
                    );
                    None
                }
            },
        )
        .collect()
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
async fn unrouted_response(
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
    let evaluation = engine
        .evaluate(&ctx, &[], &[], &[], listener_policies, global_policies)
        .await;
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
            rate_limited(
                u64::from(limit),
                u64::from(remaining),
                reset_epoch_s,
                retry_after_s,
                rid,
            )
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
/// Takes the dataplane as an `Arc` reference: the response cache's
/// stale-while-revalidate path (DW-037) spawns background revalidations
/// that need the dataplane to outlive the request.
///
/// Observability wrapper (DW-021): resolves the request ID (valid inbound
/// `X-Request-Id` respected, else generated), opens the root `request`
/// span, tracks the active-requests gauge, and — on completion — records
/// the request counter/latency histogram, echoes `X-Request-Id`, and
/// emits the (sampled) access-log line. Reserved paths (`/healthz`,
/// `/readyz`, `/metrics`) count under the "unrouted" route label like
/// 404s (they are not routes).
pub async fn handle<B>(dp: &Arc<DataPlane>, peer: IpAddr, req: Request<B>) -> Response<ProxyBody>
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
    // Custom analytics dimensions (DW-043): header-sourced tags read
    // HERE, while the request head is still in hand (the completion
    // seam has only the record). The dimension list is read from the
    // CURRENT generation, so reloads add/rename dimensions live.
    if let Some(dims) = dp.current().snapshot.gateway().analytics.as_ref() {
        for dim in &dims.dimensions {
            if let Some(v) = req.headers().get(&dim.header) {
                // First value of a repeated header wins; non-UTF-8 and
                // over-128-byte values are skipped (bounded rollup
                // cardinality per value, documented in the config).
                if let Ok(s) = v.to_str() {
                    if !s.is_empty() && s.len() <= 128 {
                        rec.custom.push((dim.name.clone(), s.to_string()));
                    }
                }
            }
        }
    }
    obs.active_requests().inc();
    let mut resp = handle_inner(dp, peer, req, &request_id, &mut rec, &root)
        .instrument(root.clone())
        .await;
    obs.active_requests().dec();
    let status = resp.status().as_u16();
    rec.status = status;
    rec.duration_ms = started.elapsed().as_secs_f64() * 1000.0;
    obs.record_request(&rec.route, &rec.listener, status, started.elapsed());
    obs.record_slo(&rec.route, status, rec.duration_ms);
    dp.record_analytics(&rec);
    dp.record_stream_offer(&rec);
    observability::stamp_request_id(resp.headers_mut(), &request_id);
    if obs.should_log_access(status) {
        observability::emit_access(&rec);
    }
    resp
}

async fn handle_inner<B>(
    dp: &Arc<DataPlane>,
    peer: IpAddr,
    req: Request<B>,
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

    // DW-087: the MCP JSON-RPC endpoint. Like the reserved paths, it
    // shadows any configured route — but unlike them it needs the
    // full request (authn, body, session management), so it is
    // handled as a dedicated path here, before route resolution.
    // Only active when the current generation's `ai.mcp` block
    // compiled a `CompiledMcp`; absent = 404 (fall through to route
    // resolution, which will 404 on the unknown path).
    if let Some(mcp) = gen.ai.as_ref().and_then(|ai| ai.mcp()) {
        if path == mcp.path() {
            return mcp_handle(dp, peer, req, mcp, rid, rec).await;
        }
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
        return unrouted_response(dp, gateway, listener_cfg, peer, rid, rec).await;
    };
    let Some(route) = gateway.routes.get(idx) else {
        return unrouted_response(dp, gateway, listener_cfg, peer, rid, rec).await;
    };

    if !route_applies(
        &route.r#match,
        gen.snapshot.route_table().accept_media_type(idx),
        &req,
    ) {
        return unrouted_response(dp, gateway, listener_cfg, peer, rid, rec).await;
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

    // Per-route METHOD ALLOWLIST (DW-030): a non-empty `methods` list on
    // the matched route answers 405 + Allow for every method not in it.
    // Placement (frozen, mirrors the DW-041 maintenance argument): the
    // allowlist is a statement about the ROUTE, not the request's shape,
    // so it precedes the route limits (an oversized DELETE on a GET-only
    // route is told "DELETE is not allowed" — fixing the body would
    // still leave it refused) and authentication (an unauthenticated
    // wrong-method request is not worth auth work). A CORS PREFLIGHT is
    // exempt exactly like the maintenance 503: the preflight is a
    // Fetch-protocol handshake about the GATEWAY's cross-origin policy,
    // not a resource request, and failing it would surface in the
    // browser as an opaque CORS error instead of the gateway's CORS
    // answer. Matching is case-insensitive (the `match.methods`
    // comparison); HEAD is never implicitly granted by GET.
    if !route.methods.is_empty() {
        let preflight_exempt = route.cors.is_some()
            && crate::dataplane::cors::is_preflight(req.method(), req.headers());
        let allowed = route
            .methods
            .iter()
            .any(|m| req.method().as_str().eq_ignore_ascii_case(m.trim()));
        if !allowed && !preflight_exempt {
            tracing::warn!(
                code = "method_not_allowed",
                request_id = %rid,
                route = route.name,
                method = %req.method(),
                "request method rejected by the route's allowlist"
            );
            let mut resp = method_not_allowed(&route.methods, rid);
            // CORS actual-response decoration on CORS-configured routes
            // (the maintenance-503 precedent): a browser must be able to
            // READ the 405 envelope cross-origin, or the gateway's answer
            // surfaces as an opaque CORS error instead.
            if let (Some(cors), Some(origins)) = (
                route.cors.as_ref(),
                gen.snapshot.route_table().cors_origins(idx),
            ) {
                let origin = req.headers().get(&ORIGIN).cloned();
                crate::dataplane::cors::decorate_actual(
                    cors,
                    origins,
                    origin.as_ref(),
                    resp.headers_mut(),
                );
            }
            stamp_security_headers(&mut resp, route);
            return resp;
        }
    }

    // WAF-lite heuristic filtering (DW-051): inspects the request path,
    // query string, selected headers, and body (when JSON or
    // form-urlencoded) for common SQLi/XSS/path-traversal signatures.
    // Placement: after the route method allowlist, before the route
    // limits — a content filter that rejects malicious requests before
    // any resource is spent on auth or rate limiting. Dry-run mode
    // (DW-041 synergy) evaluates and logs matches without blocking.
    if let Some(waf_cfg) = &route.waf {
        if let Some(waf_gen) = crate::dataplane::waf::WafGeneration::from_config(waf_cfg) {
            // Head inspection (path, query, headers) — synchronous.
            let head_match =
                waf_gen.inspect_head(req.uri().path(), req.uri().query(), req.headers());
            if let Some(m) = &head_match {
                let filter_str = m.filter.as_str();
                if waf_gen.dry_run() {
                    dp.obs.record_waf(&route.name, filter_str, "logged");
                    tracing::warn!(
                        code = "waf_logged",
                        request_id = %rid,
                        route = %route.name,
                        filter = filter_str,
                        target = m.target.as_str(),
                        pattern = %m.pattern,
                        "WAF dry-run match (request allowed)"
                    );
                } else {
                    dp.obs.record_waf(&route.name, filter_str, "blocked");
                    tracing::warn!(
                        code = "waf_blocked",
                        request_id = %rid,
                        route = %route.name,
                        filter = filter_str,
                        target = m.target.as_str(),
                        "request blocked by WAF"
                    );
                    let mut resp = simple(
                        StatusCode::FORBIDDEN,
                        "waf_blocked",
                        "request blocked by security filter",
                        rid,
                    );
                    stamp_security_headers(&mut resp, route);
                    return resp;
                }
            }
            // Body inspection: when the content type is JSON or
            // form-urlencoded and the body cap is > 0, buffer up to
            // max_body_inspect_bytes and inspect. The reconstructed
            // body (buffered prefix + any remaining stream) is forwarded
            // to the rest of the request path via handle_routed.
            if waf_gen.max_body_inspect_bytes() > 0
                && crate::dataplane::waf::should_inspect_body(req.headers())
            {
                let (parts, body) = req.into_parts();
                let result = crate::dataplane::waf::inspect_body(body, &waf_gen).await;
                if let Some(m) = &result.match_found {
                    let filter_str = m.filter.as_str();
                    if waf_gen.dry_run() {
                        dp.obs.record_waf(&route.name, filter_str, "logged");
                        tracing::warn!(
                            code = "waf_logged",
                            request_id = %rid,
                            route = %route.name,
                            filter = filter_str,
                            target = m.target.as_str(),
                            pattern = %m.pattern,
                            "WAF dry-run body match (request allowed)"
                        );
                    } else {
                        dp.obs.record_waf(&route.name, filter_str, "blocked");
                        tracing::warn!(
                            code = "waf_blocked",
                            request_id = %rid,
                            route = %route.name,
                            filter = filter_str,
                            target = m.target.as_str(),
                            "request blocked by WAF (body)"
                        );
                        let mut resp = simple(
                            StatusCode::FORBIDDEN,
                            "waf_blocked",
                            "request blocked by security filter",
                            rid,
                        );
                        stamp_security_headers(&mut resp, route);
                        return resp;
                    }
                }
                if head_match.is_none() && result.match_found.is_none() {
                    dp.obs.record_waf(&route.name, "all", "passed");
                }
                let req = Request::from_parts(parts, result.body);
                return handle_routed(dp, peer, req, rid, rec, root, gen, idx, params).await;
            }
            if head_match.is_none() {
                dp.obs.record_waf(&route.name, "all", "passed");
            }
        }
    }

    handle_routed(dp, peer, req, rid, rec, root, gen, idx, params).await
}

/// The post-WAF request path (DW-051 split point): everything from the
/// route limits onward — route limits, CORS preflight, authn, authz,
/// rate limiting, cap admission, the proxy/redirect/respond action, and
/// the response decoration tail (masking, transforms, compression,
/// versioning, CORS, security headers, rate headers). Generic over the
/// body type so it accepts both the original request body `B` and the
/// WAF-reconstructed [`crate::dataplane::waf::WafBody`] (body inspection
/// may buffer and replay the body — the only dataplane buffering the WAF
/// introduces, bounded by `max_body_inspect_bytes`).
#[allow(clippy::too_many_arguments)]
async fn handle_routed<B>(
    dp: &Arc<DataPlane>,
    peer: IpAddr,
    req: Request<B>,
    rid: &str,
    rec: &mut AccessRecord,
    root: &tracing::Span,
    gen: Arc<Generation>,
    idx: usize,
    params: Vec<(String, String)>,
) -> Response<ProxyBody>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let gateway = gen.snapshot.gateway();
    let listener_cfg = req.extensions().get::<ListenerLabel>().and_then(|l| {
        gateway
            .listeners
            .iter()
            .find(|li| li.name.as_str() == &*l.0)
    });
    let Some(route) = gateway.routes.get(idx) else {
        return unrouted_response(dp, gateway, listener_cfg, peer, rid, rec).await;
    };
    let mut req = req;
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
                let mut resp = simple(status, code, &msg, rid);
                stamp_security_headers(&mut resp, route);
                return resp;
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
                let mut resp =
                    crate::dataplane::cors::preflight_response(cors, origins, req.headers())
                        .map(ProxyBody::Full);
                stamp_security_headers(&mut resp, route);
                return resp;
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
        Err(AuthError::Invalid(_)) => {
            let mut resp = unauthorized(&authn.challenge(), rid);
            stamp_security_headers(&mut resp, route);
            return resp;
        }
        Err(AuthError::Unavailable(msg)) => {
            tracing::error!(
                code = "authentication_unavailable",
                request_id = %rid,
                "authentication backend unavailable: {msg}"
            );
            let mut resp = simple(
                StatusCode::INTERNAL_SERVER_ERROR,
                "authentication_unavailable",
                "authentication unavailable",
                rid,
            );
            stamp_security_headers(&mut resp, route);
            return resp;
        }
    };
    if route.auth_required && identity.is_none() {
        let mut resp = unauthorized(&authn.challenge(), rid);
        stamp_security_headers(&mut resp, route);
        return resp;
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
            // Hold the ArcSwap guard for the whole authz phase: the
            // context borrows the reader, and the guard keeps it alive
            // even across a concurrent hot swap.
            let geoip_guard = dp.geoip.load();
            let authz_ctx = crate::security::authz::AuthzContext {
                geoip: geoip_guard.as_ref().map(std::sync::Arc::as_ref),
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
        } => {
            let mut resp = unauthorized(&authn.challenge(), rid);
            stamp_security_headers(&mut resp, route);
            return resp;
        }
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
            let mut resp = forbidden(rid);
            stamp_security_headers(&mut resp, route);
            return resp;
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
    // The ratelimit phase span (DW-021). The evaluate call is async
    // (DW-031: Redis-backed limiters await a network round-trip), so
    // the span is instrumented onto the future rather than held as an
    // entered guard — an EnteredSpan is !Send and would poison the
    // handler future for hyper's h2 executor. Dry-run bundles (DW-041)
    // report their would-be denial through the same evaluation; live
    // bundles alone decide the 429 and the headers.
    let rate_headers = {
        let ratelimit_span = tracing::info_span!("ratelimit");
        let engine = dp.rate_limits.load_full();
        if engine.is_empty() {
            None
        } else {
            let ctx = crate::extensions::rate_limiter::RateLimitKeyContext {
                peer,
                consumer: identity.as_ref().map(|id| id.consumer_name.as_str()),
                route: &route.name,
            };
            let evaluation = engine
                .evaluate(
                    &ctx,
                    consumer_policies,
                    &route.policies,
                    service_policies,
                    listener_policies,
                    &gateway.global_policies,
                )
                .instrument(ratelimit_span)
                .await;
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
                    let mut resp = rate_limited(
                        u64::from(limit),
                        u64::from(remaining),
                        reset_epoch_s,
                        retry_after_s,
                        rid,
                    );
                    stamp_security_headers(&mut resp, route);
                    return resp;
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

    // Consumer request budgets (DW-033): after rate limiting — an
    // in-memory GCRA 429 is cheaper than a store-backed budget 429, so
    // the cheaper rejection wins the ordering — and before cap
    // admission (a budget wall never holds a concurrency slot, the
    // same rule the rate limiter follows). Budgets are per
    // authenticated CONFIG consumer (`consumers[].quotas`): anonymous
    // traffic has no budget, and store-managed consumers have no
    // config record to carry one. Counters live in the state store
    // (durable across restarts); without a store the block is inert —
    // warned once per process, never a per-request log storm. The
    // quota phase span (DW-021) opens only when a budget actually
    // applies, mirroring the ratelimit span's conditional shape.
    if let Some(quotas) = consumer_cfg.and_then(|c| c.quotas.as_ref()) {
        let consumer_name = identity
            .as_ref()
            .map(|id| id.consumer_name.as_str())
            .expect("consumer_cfg resolves only for an authenticated identity");
        match dp.state_store() {
            None => warn_quota_store_missing(consumer_name),
            Some(store) => match store.lookup_consumer(consumer_name) {
                Err(e) => {
                    tracing::error!(
                        code = "quota_store_unavailable",
                        request_id = %rid,
                        consumer = consumer_name,
                        "quota consumer lookup failed: {e}"
                    );
                    let mut resp = simple(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "quota_store_unavailable",
                        "quota store unavailable",
                        rid,
                    );
                    stamp_security_headers(&mut resp, route);
                    return resp;
                }
                Ok(None) => warn_quota_consumer_unsynced(consumer_name),
                Ok(Some(record)) => {
                    let _quota_phase = tracing::info_span!("quota").entered();
                    let now_epoch_s = unix_now_secs();
                    match crate::state::quotas::check(&store, record.id, quotas, now_epoch_s) {
                        crate::state::quotas::QuotaOutcome::Denied {
                            limit,
                            remaining,
                            reset_epoch_s,
                            retry_after_s,
                            budget,
                        } => {
                            // rec.rate_limited carries the denial into
                            // the analytics pipeline (the per-consumer
                            // usage axis); the rate_limited_total
                            // metric family stays RATE-limit-only —
                            // dwara_quota_denied_total owns budgets.
                            rec.rate_limited = true;
                            dp.obs.record_quota_denied(consumer_name, budget.as_str());
                            tracing::info!(
                                code = "quota_exceeded",
                                request_id = %rid,
                                route = %route.name,
                                consumer = consumer_name,
                                budget = budget.as_str(),
                                limit = limit,
                                retry_after_s = retry_after_s,
                                "consumer request budget exhausted; answering 429"
                            );
                            let mut resp =
                                rate_limited(limit, remaining, reset_epoch_s, retry_after_s, rid);
                            stamp_security_headers(&mut resp, route);
                            return resp;
                        }
                        crate::state::quotas::QuotaOutcome::Unavailable => {
                            tracing::error!(
                                code = "quota_store_unavailable",
                                request_id = %rid,
                                consumer = consumer_name,
                                "quota counter read/write failed; the budget cannot \
                                 be vouched for"
                            );
                            let mut resp = simple(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "quota_store_unavailable",
                                "quota store unavailable",
                                rid,
                            );
                            stamp_security_headers(&mut resp, route);
                            return resp;
                        }
                        // NotQuotaed here means the consumer row was
                        // reported missing mid-check (the engine's
                        // fail-open path) — the warn already fired.
                        crate::state::quotas::QuotaOutcome::NotQuotaed => {}
                        crate::state::quotas::QuotaOutcome::Allowed { .. } => {
                            // Near-limit notice (DW-033): edge-triggered
                            // once per (consumer, budget, window) at
                            // >= 80% of the cap. The read is the same
                            // current-usage query the admin endpoint
                            // and the scrape gauges use.
                            for u in crate::state::quotas::current_usage(
                                &store,
                                record.id,
                                quotas,
                                now_epoch_s,
                            ) {
                                if u.used * 5 >= u.limit * 4
                                    && dp.note_quota_near_limit(
                                        consumer_name,
                                        u.budget,
                                        u.window_start_epoch_s as i64,
                                    )
                                {
                                    dp.events.emitter().emit(
                                        crate::events::EventKind::QuotaNearLimit,
                                        crate::events::EventPayload::quota(
                                            consumer_name,
                                            u.budget.as_str(),
                                            u.used,
                                            u.limit,
                                        ),
                                    );
                                    tracing::warn!(
                                        code = "quota_near_limit",
                                        consumer = consumer_name,
                                        budget = u.budget.as_str(),
                                        used = u.used,
                                        limit = u.limit,
                                        "consumer request budget at or above 80% of \
                                         its window cap"
                                    );
                                }
                            }
                        }
                    }
                }
            },
        }
    }

    // Gateway concurrency cap with priority-aware load shedding
    // (DW-015 + DW-016) and bounded admission queues (DW-053). Admission
    // is two-tier: every request tries the general allowance; a request
    // at or above HIGH_PRIORITY may then try the reserved bucket (when
    // one is carved). No permits anywhere -> either WAIT for a permit
    // up to the queue timeout (DW-053, when admission_queue is enabled)
    // or 503 "gateway saturated" immediately (DW-016, the default). The
    // permit lives until the response body completes: the proxy path
    // attaches it to the streaming body, and complete bodies (errors,
    // redirects, respond actions) release it when this scope ends.
    //
    // AuthN (DW-019) supplies the consumer here: its priority overrides
    // the route's when the authenticated consumer declares one.
    let priority = resolve_priority(consumer_cfg, route);
    let cap = dp.global_cap.load_full();
    // The admission phase span (DW-021); permit bookkeeping. The sync
    // try-acquire runs inside the span; the DW-053 queue path's timed
    // acquire runs OUTSIDE the span guard (EnteredSpan is not Send, so
    // holding it across an .await would make the future non-Send).
    let global_permit = {
        let _admission_phase = tracing::info_span!("admission").entered();
        match &cap.general {
            None => {
                // Unlimited: no admission decision, but still counted per
                // priority class (the counters describe traffic mix, not only
                // capped traffic).
                dp.priority_counters.record_admitted(priority);
                AdmissionResult::Permit(None)
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
                        AdmissionResult::Permit(Some(permit))
                    }
                    None => {
                        // DW-053: admission queue. When enabled, the
                        // request waits for a permit up to the queue
                        // timeout instead of being immediately shed.
                        // The queue depth is bounded: once at capacity
                        // (per-priority-aware), the request is shed
                        // immediately with 503 (queue_full).
                        if let Some(aq) = &cap.admission_queue {
                            // Check queue capacity. High-priority may
                            // queue up to max_queue_size; low-priority
                            // up to low_queue_limit (the high-priority
                            // reserve is max_queue_size - low_queue_limit).
                            let depth = aq.queue_depth.load(Ordering::Relaxed);
                            let limit = if priority >= HIGH_PRIORITY {
                                aq.max_queue_size
                            } else {
                                aq.low_queue_limit
                            };
                            if depth >= limit {
                                // Queue full: shed immediately.
                                dp.obs.record_admission_queued("queue_full");
                                handle_shed(
                                    dp,
                                    priority,
                                    rec,
                                    rid,
                                    route,
                                    Some(aq.queue_timeout),
                                    gateway.load_shed_dry_run,
                                    identity.as_ref().map(|id| id.consumer_name.as_str()),
                                )
                            } else {
                                // Reserve a queue slot. The timed acquire
                                // runs outside the span guard (below).
                                aq.queue_depth.fetch_add(1, Ordering::Relaxed);
                                let depth = aq.queue_depth.load(Ordering::Relaxed);
                                dp.obs.set_admission_queue_depth(depth as i64);
                                AdmissionResult::Queue(
                                    Arc::clone(general),
                                    cap.reserved.clone(),
                                    aq.queue_timeout,
                                    aq.queue_depth.clone(),
                                )
                            }
                        } else {
                            // DW-016: no queue — immediate shed (or
                            // dry-run admit, DW-041).
                            handle_shed(
                                dp,
                                priority,
                                rec,
                                rid,
                                route,
                                None,
                                gateway.load_shed_dry_run,
                                identity.as_ref().map(|id| id.consumer_name.as_str()),
                            )
                        }
                    }
                }
            }
        }
    };
    // Unpack the admission result: a shed response returns immediately;
    // a permit (Some for admitted, None for dry-run-admitted-over-cap)
    // continues the request path; a Queue result needs a timed acquire
    // (DW-053) which runs here, outside the span guard.
    let mut global_permit = match global_permit {
        AdmissionResult::Permit(p) => p,
        AdmissionResult::Shed(resp) => return resp,
        AdmissionResult::Queue(general, reserved, timeout, queue_depth) => {
            let acquired = try_acquire_queued(general, reserved, priority, timeout).await;
            queue_depth.fetch_sub(1, Ordering::Relaxed);
            let depth = queue_depth.load(Ordering::Relaxed);
            dp.obs.set_admission_queue_depth(depth as i64);
            match acquired {
                Some(permit) => {
                    dp.obs.record_admission_queued("admitted");
                    dp.priority_counters.record_admitted(priority);
                    Some(permit)
                }
                None => {
                    // Timed out waiting for a permit.
                    dp.obs.record_admission_queued("timeout");
                    let result = handle_shed(
                        dp,
                        priority,
                        rec,
                        rid,
                        route,
                        Some(timeout),
                        gateway.load_shed_dry_run,
                        identity.as_ref().map(|id| id.consumer_name.as_str()),
                    );
                    match result {
                        AdmissionResult::Permit(p) => p,
                        AdmissionResult::Shed(resp) => return resp,
                        AdmissionResult::Queue(..) => {
                            unreachable!("handle_shed never returns Queue")
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

    // Response cache lookup (DW-037): PROXY-action routes with a cache
    // block only, AFTER authn/authz/rate limiting/admission (a replay
    // is still client traffic — it consumed a token and a slot, and no
    // policy is bypassed by a hit) and BEFORE the breaker/endpoint pick
    // (a hit contacts no upstream). A Serve short-circuits the action,
    // masking, and transforms — the stored bytes ARE the post-mask,
    // post-transform bytes for this exact consumer — and the response
    // re-enters the pipeline at the store-stage/tail below, so the
    // decoration tail (compression onward) still runs on every replay.
    //
    // Request coalescing (DW-038) rides the MISS arm: a coalescing-
    // enabled miss either leads (fetches while holding the key's
    // slot, `coalesce_lead` below), follows (parks bounded and is
    // Served the leader's stored outcome — same guarantees as a hit,
    // since the entry IS a hit by the time it replays), or fetches
    // independently (Solo: every fail-open fallback is just this
    // normal miss path). Everything upstream of this point —
    // maintenance, limits, authn/authz, rate limiting, admission —
    // already ran for the follower too, so a 503 or a 429 is never
    // coalesced and no policy is bypassed by following.
    let mut cache_flow: Option<crate::dataplane::response_cache::CacheFlow> = None;
    let mut coalesce_lead: Option<crate::dataplane::response_cache::CoalesceLead> = None;
    let replayed: Option<Response<ProxyBody>> = if let (RouteAction::Proxy { .. }, Some(policy)) =
        (&route.action, gen.snapshot.route_table().cache(idx))
    {
        use crate::dataplane::response_cache::LookupOutcome;
        match dp
            .response_cache()
            .lookup(
                dp,
                policy,
                route,
                identity.as_ref(),
                peer,
                req.uri().path(),
                req.uri().query(),
                req.headers(),
                req.method(),
                req.body().size_hint().exact(),
                &dp.obs,
            )
            .await
        {
            LookupOutcome::Serve(resp) => Some(*resp),
            LookupOutcome::Bypass => {
                cache_flow = Some(crate::dataplane::response_cache::CacheFlow::Bypass);
                None
            }
            LookupOutcome::Miss(flow) => {
                // Conditional revalidation (DW-037): when the lookup
                // kept an expired entry with a validator and the
                // client sent none of its own, the forwarded fetch
                // carries the stored validator — an upstream 304
                // refreshes the entry without re-sending the body
                // (the store stage converts it back to a 200).
                if flow.injected_inm {
                    if let Some(etag) = flow.stored_etag() {
                        if let Ok(v) = HeaderValue::from_str(&etag) {
                            req.headers_mut().insert(&IF_NONE_MATCH, v);
                        }
                    }
                }
                if flow.coalesce_wait().is_some() {
                    match dp.response_cache().attach(&flow, &dp.obs).await {
                        crate::dataplane::response_cache::CoalesceOutcome::Served(resp) => {
                            Some(*resp)
                        }
                        crate::dataplane::response_cache::CoalesceOutcome::Lead(lead) => {
                            coalesce_lead = Some(lead);
                            cache_flow =
                                Some(crate::dataplane::response_cache::CacheFlow::Miss(flow));
                            None
                        }
                        crate::dataplane::response_cache::CoalesceOutcome::Solo => {
                            cache_flow =
                                Some(crate::dataplane::response_cache::CacheFlow::Miss(flow));
                            None
                        }
                    }
                } else {
                    cache_flow = Some(crate::dataplane::response_cache::CacheFlow::Miss(flow));
                    None
                }
            }
        }
    } else {
        None
    };

    // Request validation (DW-047): when a route carries a
    // `request_validation.body_schema`, the request body is buffered
    // and validated against the minimal JSON-Schema subset BEFORE the
    // action runs. A mismatch answers 400 `validation_failed` with the
    // offending instance paths in the JSON error envelope. This runs
    // after every policy phase (authn, authz, rate limit, admission)
    // and before the action — a malformed body from an authenticated,
    // authorized caller is still rejected, and no upstream is
    // contacted on a mismatch (the whole point for mock mode). The
    // buffered bytes are replayed to the action below (proxy or mock
    // alike). A cache HIT skips validation (the cached response was
    // already validated when it was first fetched).
    let mut resp = if let Some(resp) = replayed {
        resp
    } else {
        // Validate the request body before dispatching the action. On
        // success, the body is replaced with the buffered bytes (a
        // `Full<Bytes>` body) so the action sees the full body. On
        // failure, a 400 is returned immediately.
        if let Some(rv) = &route.request_validation {
            match validate_and_replay_body(req, &rv.body_schema).await {
                Ok(validated_req) => {
                    dispatch_action(
                        validated_req,
                        route,
                        &gen,
                        idx,
                        &params,
                        peer,
                        identity.as_ref(),
                        rid,
                        rec,
                        &mut global_permit,
                        dp,
                        client_cert.as_ref(),
                    )
                    .await
                }
                Err(violation) => {
                    tracing::warn!(
                        code = "validation_failed",
                        request_id = %rid,
                        route = %route.name,
                        path = %violation,
                        "request body failed validation"
                    );
                    let mut resp = simple(
                        StatusCode::BAD_REQUEST,
                        "validation_failed",
                        &format!("request body does not match the expected schema: {violation}"),
                        rid,
                    );
                    stamp_security_headers(&mut resp, route);
                    return resp;
                }
            }
        } else {
            dispatch_action(
                req,
                route,
                &gen,
                idx,
                &params,
                peer,
                identity.as_ref(),
                rid,
                rec,
                &mut global_permit,
                dp,
                client_cert.as_ref(),
            )
            .await
        }
    };

    // Response field masking (DW-029), the decoration tail's FIRST
    // stage and the security floor of the response path: the effective
    // pointer set (route floor + the consumer's groups, the union
    // rule) is replaced with the fixed sentinel BEFORE anything else
    // can read the body — once masked, the original bytes exist
    // nowhere in the gateway, so no later stage (operator transforms,
    // the DW-027 compression codec) can resurrect them; the gateway's
    // own compression runs later and never trips the encoding gate.
    // Every gate here FAILS CLOSED (502): masking guards the UPSTREAM's
    // output, so it applies to PROXY action responses only —
    // gateway-authored bodies (redirect, respond) carry no upstream
    // data, and bodiless statuses carry nothing at all.
    if matches!(&route.action, RouteAction::Proxy { .. }) {
        if let Some(masking) = gen.snapshot.route_table().masking(idx) {
            resp = crate::dataplane::transforms::mask_response_body(
                resp,
                masking,
                identity
                    .as_ref()
                    .map(|id| id.groups.as_slice())
                    .unwrap_or(&[]),
                &route.name,
                identity.as_ref().map(|id| id.consumer_name.as_str()),
                rid,
            )
            .await;
        }
    }

    // Response body transforms (DW-028), the tail's stage after
    // masking: buffers only when the route configured a JSON body
    // transform AND the response declares a JSON body within the cap —
    // every other response (SSE, streamed downloads, other content
    // types, already-encoded) passes untouched, the streaming
    // guarantee. Before compression so the codec encodes the
    // TRANSFORMED bytes and the eligibility check below sees the
    // final Content-Type (header ops may have rewritten it).
    if let Some(compiled) = gen.snapshot.route_table().response_body_ops(idx) {
        resp = crate::dataplane::transforms::transform_response_body(resp, compiled, rid).await;
    }

    // Response header transforms (DW-028): the operator's final shape
    // of the upstream's headers, before the gateway's own policy
    // stamps (compression's Vary/Content-Encoding, versioning, CORS,
    // security headers, rate headers — each owns headers validation
    // keeps the ops out of, so no stage here can be undone by an op).
    if let Some(ops) = route
        .transforms
        .as_ref()
        .and_then(|t| t.response.as_ref())
        .and_then(|resp_t| resp_t.headers.as_ref())
    {
        crate::dataplane::transforms::apply_header_ops(resp.headers_mut(), ops);
    }

    // Cache store stage (DW-037): the tail's LAST hands on the bytes
    // before the gateway's own decoration. Stores happen only on the
    // miss/bypass flows created above; the stage stamps `x-cache`
    // (hit/stale were stamped at replay), applies the 304-reuse and
    // storable-rule arms, and buffers — size-capped, this opted-in
    // path only — the post-masking/post-transform identity bytes into
    // the CacheStore. Compression and everything after re-run below
    // for fresh AND replayed responses alike.
    if let Some(flow) = cache_flow {
        resp = dp
            .response_cache()
            .store_stage(flow, resp, rid, &dp.obs)
            .await;
    }

    // DW-038: publish the coalescing leader's outcome NOW — the store
    // write above has completed, so the parked followers that wake
    // re-read a settled store and either replay the entry or fetch on
    // their own. Dropping here (not at function end) lets followers
    // proceed while this response's decoration tail still runs; a
    // leader that panicked or was cancelled mid-fetch publishes the
    // same way via Drop, failing its followers open.
    drop(coalesce_lead);

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

    // Security headers (DW-028): the LAST policy stamp before the rate
    // headers — the gateway's edge policy has the final word over
    // upstream values AND over operator transforms (an operator who
    // needs per-route exceptions omits the field here and sets it via
    // transforms). REPLACE semantics: the gateway is the source of
    // truth at its edge.
    if let Some(sh) = &route.security_headers {
        crate::dataplane::transforms::apply_security_headers(resp.headers_mut(), sh);
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

/// Stamp the route's security-header policy (DW-028) onto a gateway
/// short-circuit response. Security headers are an EDGE property of
/// every route-matched response — a browser parsing a 401 or a 429
/// deserves the same `nosniff`/HSTS guarantees as one parsing a 200
/// (the deliberate asymmetry with deprecation stamps, which announce
/// API lifecycle and stay off short-circuits; see
/// `config::transforms::SecurityHeaders`).
fn stamp_security_headers(resp: &mut Response<ProxyBody>, route: &Route) {
    if let Some(sh) = &route.security_headers {
        crate::dataplane::transforms::apply_security_headers(resp.headers_mut(), sh);
    }
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
    // Security headers (DW-028): the 503 is a route-matched response —
    // the edge policy stamps it like every other.
    stamp_security_headers(&mut resp, route);
    resp
}

/// The 405 response for a method outside the route's allowlist (DW-030):
/// `Allow` carries the route's configured methods (RFC 9110 10.2.1 — the
/// header's whole job is to name what the resource supports, so the
/// configured order is preserved verbatim) plus the uniform JSON
/// envelope.
fn method_not_allowed(allowed: &[String], rid: &str) -> Response<ProxyBody> {
    let allow = allowed
        .iter()
        .map(|m| m.trim())
        .collect::<Vec<_>>()
        .join(", ");
    let message = format!("method not allowed; the route allows {allow}");
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(hyper::header::ALLOW, allow)
        .body(ProxyBody::Full(Full::new(observability::envelope_body(
            "method_not_allowed",
            &message,
            rid,
        ))))
        .expect("static 405 response is valid")
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

/// DW-035: strip any inbound headers with the configured `X-Client-Cert`
/// prefix (case-insensitive) and inject the gateway's own
/// `X-Client-Cert-{Fingerprint,Subject-CN,Issuer-CN,Not-After}` from
/// the VERIFIED client certificate. Spoofing prevention: a client
/// cannot claim certificate identity upstream — the gateway overwrites
/// any inbound headers with the prefix. `Not-After` is formatted as an
/// RFC 3339 timestamp (the conventional HTTP-date-adjacent format for
/// certificate expiry); absent metadata is simply not injected (the
/// upstream sees fewer headers, never an empty value).
fn inject_client_cert_headers(
    headers: &mut HeaderMap,
    fwd: &crate::config::MtlsForwardHeaders,
    cert: &crate::security::authn::ClientCertificate,
) {
    // Strip inbound headers with the configured prefix (case-insensitive
    // match on the header name, per HTTP semantics).
    let prefix_lower = fwd.prefix.to_ascii_lowercase();
    let names: Vec<HeaderName> = headers
        .keys()
        .filter(|n| n.as_str().starts_with(&prefix_lower))
        .cloned()
        .collect();
    for name in names {
        headers.remove(&name);
    }
    // Inject the gateway-computed metadata. Each header is added only
    // when the value is present and encodable.
    let p = &fwd.prefix;
    // Fingerprint (colon-separated hex, always present).
    if let Ok(name) = HeaderName::from_str(&format!("{p}-Fingerprint")) {
        if let Ok(v) = HeaderValue::from_str(cert.fingerprint_colon()) {
            headers.insert(name, v);
        }
    }
    // Subject CN (present when the certificate carries a decodable CN).
    if let Some(cn) = cert.subject_cn() {
        if let Ok(name) = HeaderName::from_str(&format!("{p}-Subject-CN")) {
            if let Ok(v) = HeaderValue::from_str(cn) {
                headers.insert(name, v);
            }
        }
    }
    // Issuer CN (DW-035).
    if let Some(cn) = cert.issuer_cn() {
        if let Ok(name) = HeaderName::from_str(&format!("{p}-Issuer-CN")) {
            if let Ok(v) = HeaderValue::from_str(cn) {
                headers.insert(name, v);
            }
        }
    }
    // Not-After as RFC 3339 timestamp (DW-035).
    if let Some(secs) = cert.not_after() {
        if let Ok(name) = HeaderName::from_str(&format!("{p}-Not-After")) {
            if let Some(ts) = unix_secs_to_rfc3339(secs) {
                if let Ok(v) = HeaderValue::from_str(&ts) {
                    headers.insert(name, v);
                }
            }
        }
    }
}

/// Format a Unix epoch seconds value as an RFC 3339 timestamp (DW-035):
/// `YYYY-MM-DDTHH:MM:SSZ` (UTC, the `Z` suffix). Returns `None` for
/// values outside the representable range (before 1970 or after
/// 9999-12-31T23:59:59Z). Hand-rolled to avoid pulling a datetime
/// dependency — the calendar math is fixed and well-known.
fn unix_secs_to_rfc3339(secs: i64) -> Option<String> {
    if secs < 0 {
        return None;
    }
    let secs = u64::try_from(secs).ok()?;
    // Days since 1970-01-01 and seconds within the day.
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    // Civil date from days since epoch (Howard Hinnant's algorithm,
    // public domain — works for any non-negative day count).
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    if y > 9999 {
        return None;
    }
    Some(format!(
        "{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

/// The 429 response for a denied rate limit (DW-017) or a denied
/// consumer request budget (DW-033 — same client-facing contract):
/// `Retry-After` in whole seconds (already rounded up, minimum 1) plus
/// the binding window's `X-RateLimit-*` headers. u64 limits: quota
/// budgets are u64 config values (a monthly cap can exceed u32 range);
/// rate-limit callers convert.
fn rate_limited(
    limit: u64,
    remaining: u64,
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
// pub(super): the response cache's background revalidation (DW-037)
// drives the same forward path with a synthetic conditional GET.
#[allow(clippy::too_many_arguments)]
pub(super) async fn proxy_request<B>(
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
    obs_arc: &Arc<Observability>,
    client_cert: Option<&Arc<crate::security::authn::ClientCertificate>>,
    oauth2_token_cache: &Arc<crate::security::oauth2::OAuth2TokenCache>,
) -> Response<ProxyBody>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let obs: &Observability = obs_arc;
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
    // DW-040: resolve the dispatch target. A split service picks a
    // branch upstream by the deterministic weighted hash (the sticky
    // cookie's value when configured and presented, else the request
    // id — see `dataplane::split`); a single-target service resolves
    // its one upstream as ever. The sticky value doubles as the
    // dispatch HASH KEY below, so an `ip_hash` branch upstream pins
    // the session to one endpoint through the same ketama ring that
    // pins client IPs.
    let mut sticky_set_cookie: Option<String> = None;
    let sticky_key: Option<String> = service.sticky.as_ref().map(|sticky| {
        match read_cookie(req.headers(), &sticky.cookie) {
            Some(value) => value,
            None => {
                // First request of the session: mint the affinity
                // handle NOW so the branch picked below is exactly the
                // branch the cookie pins — stickiness holds from the
                // very first response. Opaque, not a secret (see the
                // split module docs); recorded so the response can
                // carry it.
                let value = mint_affinity_id();
                sticky_set_cookie = Some(format!(
                    "{}={}; Path=/; Max-Age={}",
                    sticky.cookie, value, sticky.ttl_s
                ));
                value
            }
        }
    });
    let dispatch_key: String = sticky_key.clone().unwrap_or_else(|| rid.to_string());
    let handle: Arc<crate::dataplane::upstream::UpstreamHandle> =
        if let Some(split) = gen.registry.split_for(&service.name) {
            let picked = Arc::clone(split.pick(&dispatch_key));
            obs.record_split_pick(&service.name, picked.name());
            picked
        } else {
            let Some(name) = &service.upstream else {
                // Validation requires exactly one of upstream/split, and a
                // split service resolved to None only when its compile
                // failed loudly (registry logs it); classified, no panic.
                return simple(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "unknown_upstream",
                    "unknown upstream",
                    rid,
                );
            };
            let Some(handle) = gen.registry.get(name) else {
                return simple(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "unknown_upstream",
                    "unknown upstream",
                    rid,
                );
            };
            handle
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

    // WebSocket policy (DW-039): the origin gate runs at the proxy
    // action — after authn/authz/rate limit (the documented request
    // path: the origin allowlist is a ROUTE policy about the upgrade,
    // not an identity claim) and BEFORE any upstream contact (no dial,
    // no breaker observation, no pick). Applies only to requests
    // offering a WEBSOCKET upgrade; other upgrades are untouched.
    let ws_policy = route.websocket.as_ref();
    let ws_police = if wants_upgrade
        && ws_policy.is_some_and(|_| crate::dataplane::websocket::offers_websocket(req.headers()))
    {
        if let Some(ws) = ws_policy {
            match crate::dataplane::websocket::handshake_verdict(req.headers(), ws) {
                crate::dataplane::websocket::Handshake::OriginDenied => {
                    obs.record_websocket_policy(&route.name, "origin_denied");
                    tracing::warn!(
                        code = "websocket_origin_denied",
                        request_id = %rid,
                        route = %route.name,
                        origin = req
                            .headers()
                            .get(ORIGIN)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("(none)"),
                        "websocket upgrade denied: origin not in the route allowlist"
                    );
                    return simple(
                        StatusCode::FORBIDDEN,
                        "websocket_origin_denied",
                        "websocket origin not allowed",
                        rid,
                    );
                }
                crate::dataplane::websocket::Handshake::Allowed => {}
            }
        }
        ws_policy
            .and_then(|ws| ws.max_frames_per_sec)
            .map(|rate| WsPoliceDecision {
                route: route.name.clone(),
                rate,
            })
    } else {
        None
    };

    // gRPC (DW-039): an h2 request with an `application/grpc` content
    // type. Its `grpc-timeout` header is the RPC's TOTAL budget — arm
    // it as the forward deadline (bounding the attempt below) and let
    // the same instant keep ticking through the response body (the
    // upstream body's absolute deadline). Parse failures are ignored:
    // a malformed timeout is the caller's bug, not the gateway's.
    // Health-report split (deliberate): a BODY-phase deadline crossing
    // reports a passive-health failure (the endpoint accepted the RPC
    // and then starved it), while a FORWARD-phase cut does NOT (the
    // client's own budget expired before the endpoint answered — the
    // gateway cancelling on the caller's clock is not endpoint
    // misbehavior, and the operator's fixed `timeouts.read_ms` already
    // bounds genuinely hung endpoints).
    let grpc = grpc_request(req.headers(), req.version());
    let grpc_deadline = grpc
        .then(|| {
            req.headers()
                .get("grpc-timeout")
                .and_then(|v| v.to_str().ok())
                .and_then(parse_grpc_timeout)
        })
        .flatten()
        .map(|d| std::time::Instant::now() + d);

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

    // Query transforms (DW-028): the one place the forwarded query may
    // change. After the path rewrite (which re-attaches the ORIGINAL
    // query verbatim — DW-010 never saw transforms) and before route
    // matching is a memory: matching, limits, authn, and rate limiting
    // all evaluated the request's ORIGINAL query. Untouched pairs keep
    // their exact bytes; only pairs a named op touches are re-encoded.
    if let Some(ops) = route
        .transforms
        .as_ref()
        .and_then(|t| t.request.as_ref())
        .and_then(|req_t| req_t.query.as_ref())
    {
        if let Some(new_uri) = crate::dataplane::transforms::apply_query_ops(req.uri(), ops) {
            *req.uri_mut() = new_uri;
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
    let conn_tokens = strip_hop_by_hop(&mut parts.headers, wants_upgrade, grpc);
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

    // DW-035: X-Client-Cert-* identity-forwarding headers. When
    // `mtls_forward_headers` is enabled and the connection presented a
    // verified client certificate, the gateway STRIPS any inbound
    // headers with the configured prefix (spoofing prevention) and
    // injects its own `X-Client-Cert-{Fingerprint,Subject-CN,Issuer-CN,
    // Not-After}`. The certificate is already verified at the TLS
    // layer; these headers carry metadata the upstream uses for
    // audit/logging, not for authentication (the gateway's authn
    // already resolved the consumer).
    if let Some(fwd) = gateway.mtls_forward_headers.as_ref().filter(|f| f.enabled) {
        if let Some(cert) = &client_cert {
            inject_client_cert_headers(&mut parts.headers, fwd, cert);
        }
    }

    // DW-035: OAuth2 client-credentials Bearer token. When the resolved
    // upstream has an `oauth2_client_credentials` block, the gateway
    // obtains an access token and REPLACES any client-supplied
    // `Authorization` header with `Bearer <token>` — the upstream sees
    // the GATEWAY's token, not the client's. A token-endpoint failure
    // surfaces as 502 `oauth2_token_unavailable` (never proxying
    // unauthenticated). The token fetch is on the request path (first
    // request / refresh); cached tokens return immediately.
    if let Some(oauth2_client) = gen.oauth2_client(handle.name()) {
        match oauth2_client.token(oauth2_token_cache).await {
            Ok(token) => {
                if let Ok(v) = HeaderValue::from_str(&format!("Bearer {token}")) {
                    parts.headers.insert(hyper::header::AUTHORIZATION, v);
                }
            }
            Err(e) => {
                tracing::error!(
                    code = "oauth2_token_unavailable",
                    request_id = %rid,
                    upstream = %handle.name(),
                    "oauth2 token acquisition failed: {e}"
                );
                let mut resp = simple(
                    StatusCode::BAD_GATEWAY,
                    "oauth2_token_unavailable",
                    "oauth2 token endpoint unavailable",
                    rid,
                );
                stamp_security_headers(&mut resp, route);
                return resp;
            }
        }
    }

    // Request header transforms (DW-028): LAST hands on the forwarded
    // headers, after hop-by-hop stripping and the gateway's trusted
    // injections — ops see (and may shape, including removing the
    // trust headers; the operator owns the upstream's contract) the
    // near-final request. Framing/hop-by-hop names were rejected by
    // validation, so the ops cannot disturb the pipeline's own
    // headers here.
    if let Some(ops) = route
        .transforms
        .as_ref()
        .and_then(|t| t.request.as_ref())
        .and_then(|req_t| req_t.headers.as_ref())
    {
        crate::dataplane::transforms::apply_header_ops(&mut parts.headers, ops);
    }

    // Request body transform (DW-028): BEFORE the retry buffering, so
    // a retried attempt replays the TRANSFORMED bytes, and before any
    // upstream contact. The compiled ops come from the snapshot table
    // (pointers parsed once at compile); a None policy leaves the
    // body streaming untouched. Reading through the wrappers below
    // (limit counting, HMAC digest fold) keeps enforcement on the
    // CLIENT's original bytes — the transform shapes what the upstream
    // receives, never what the gateway verifies.
    let mut transformed_body: Option<Bytes> = None;
    let mut body_rest: Option<B> = Some(body);
    if let Some(compiled) = gen.snapshot.route_table().request_body_ops(route_idx) {
        match crate::dataplane::transforms::transform_request_body(
            body_rest
                .take()
                .expect("body present before the transform step"),
            compiled,
            &parts.headers,
        )
        .await
        {
            // No transform applied (non-JSON, encoded, or empty): the
            // ORIGINAL body streams on — the streaming guarantee of
            // this feature.
            crate::dataplane::transforms::RequestBodyOutcome::Original(b) => body_rest = Some(b),
            crate::dataplane::transforms::RequestBodyOutcome::Replaced(bytes) => {
                // Framing: the forwarded body IS these bytes now —
                // rewrite the declared length to match (a stale length
                // would misframe the hop; the value is always
                // representable).
                parts.headers.insert(
                    hyper::header::CONTENT_LENGTH,
                    HeaderValue::from_str(&bytes.len().to_string())
                        .expect("a length is a valid header value"),
                );
                transformed_body = Some(bytes);
            }
            crate::dataplane::transforms::RequestBodyOutcome::Failed(e) => {
                return request_body_transform_failed(e, rid);
            }
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

    // DW-063: request hedging. A hedge copy is a speculative duplicate
    // sent to a different endpoint after `hedge_after` without a
    // response; the first response wins, the loser is cancelled. Hedging
    // requires a replayable body and idempotent semantics (POST only
    // when `retry_post` is true), and is disabled for upgrade requests.
    // Evaluated here (before body buffering) because hedging requires
    // the body to be buffered — the buffering condition below includes
    // `hedge_eligible`.
    let hedge = handle.hedge_params();
    let hedge_eligible = hedge.enabled()
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
    let first_body: AttemptBody<B> = if let Some(bytes) = transformed_body {
        // DW-028: the transform already buffered (and replaced) the
        // body — it is replayable by construction, and a retry re-sends
        // the TRANSFORMED bytes.
        replay = Some(bytes.clone());
        AttemptBody::Replay(bytes)
    } else if retries_enabled || hedge_eligible {
        // DW-014/DW-063: buffer the request body so it can be replayed
        // on retry or sent as a hedge copy. Hedging requires a
        // replayable body even when retries are off (attempts == 0).
        match buffer_request_body(
            body_rest.take().expect("untransformed body present"),
            rp.buffer_max_bytes,
        )
        .await
        {
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
            rest: Box::pin(body_rest.take().expect("untransformed body present")),
        }
    };

    let mut first_body = Some(first_body);
    let mut done_tries: u32 = 0;
    // DW-063: hedge is enabled if the hedge block is present, the method
    // is idempotent (or POST with retry_post), and the body was buffered
    // (replay is available). Over-cap bodies that couldn't be buffered
    // disable hedging.
    let hedge_enabled = hedge_eligible && replay.is_some();
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
        let peer_key = peer.to_string();
        // DW-040: sticky sessions hash the ENDPOINT pick by the same
        // key that picked the branch (the affinity cookie), so an
        // ip_hash branch pins the session to one endpoint; split
        // services without sticky hash per request id. Everything
        // else keeps the client-IP key (the ip_hash contract).
        let dispatch_hash_key: &str = if sticky_key.is_some() || service.split.is_some() {
            dispatch_key.as_str()
        } else {
            peer_key.as_str()
        };
        // gRPC deadline (DW-039): the RPC's total budget bounds every
        // attempt's forward — the remaining slice, so a retry that
        // cannot fit before the deadline is cut by the timeout, not
        // started in vain. Non-gRPC requests are unwrapped (zero cost).
        let send = handle
            .send_with_hash_key_observed(out_req, Some(dispatch_hash_key), &mut picked)
            .instrument(attempt_span);

        // DW-063: request hedging. On the first attempt, if the hedge
        // timer fires before the primary responds, spawn a speculative
        // duplicate to a different endpoint. Race the primary and all
        // hedge copies; the first response (headers resolved) wins.
        let result = if hedge_enabled && done_tries == 0 {
            hedge_race(
                send,
                hedge,
                &handle,
                &out_req_parts,
                replay.as_ref().expect("hedge requires replay"),
                dispatch_hash_key,
                rid,
                handle.name(),
                obs_arc,
            )
            .await
        } else {
            match grpc_deadline {
                Some(deadline) => match tokio::time::timeout(
                    deadline.saturating_duration_since(std::time::Instant::now()),
                    send,
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        // The deadline expired before headers resolved: for a
                        // gRPC caller the answer carries grpc-status 4
                        // (DEADLINE_EXCEEDED) in the headers — the
                        // trailers-only shape — plus the standard envelope
                        // body for non-gRPC tooling.
                        tracing::warn!(
                            code = "grpc_deadline_exceeded",
                            request_id = %rid,
                            upstream = handle.name(),
                            "grpc-timeout expired before the upstream answered"
                        );
                        if let Some(ep) = &picked {
                            rec.endpoint = Some(ep.clone());
                        }
                        rec.attempts = done_tries + 1;
                        let mut resp = simple(
                            StatusCode::GATEWAY_TIMEOUT,
                            "grpc_deadline_exceeded",
                            "grpc-timeout expired",
                            rid,
                        );
                        let v = HeaderValue::from_static("4");
                        resp.headers_mut().insert("grpc-status", v);
                        return resp;
                    }
                },
                None => send.await,
            }
        };
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
                let mut resp = finish_proxy_response(
                    resp,
                    wants_upgrade,
                    on_client_upgrade,
                    global_permit.take(),
                    ws_police,
                    obs_arc,
                    grpc_deadline,
                    rid,
                );
                // DW-040: the first request of a sticky session carries
                // its affinity handle back (appended, never replacing
                // an upstream's own cookies).
                if let Some(cookie) = sticky_set_cookie.take() {
                    if let Ok(v) = HeaderValue::from_str(&cookie) {
                        resp.headers_mut().append(hyper::header::SET_COOKIE, v);
                    }
                    obs.record_sticky_session();
                }
                return resp;
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

/// DW-063: inline hedge helper. Races the primary send future against a
/// hedge timer; if the timer fires first, spawns up to `hedge_max`
/// speculative copies and races all of them. First Ok wins; losers are
/// aborted. Returns the winning result (or the last error if all fail).
#[allow(clippy::too_many_arguments)]
async fn hedge_race(
    primary_send: impl std::future::Future<
        Output = Result<
            Response<crate::dataplane::upstream::UpstreamBody>,
            crate::dataplane::upstream::UpstreamError,
        >,
    >,
    hedge: &crate::resilience::retries::HedgeParams,
    handle: &Arc<crate::dataplane::upstream::UpstreamHandle>,
    out_req_parts: &http::request::Parts,
    replay: &Bytes,
    dispatch_hash_key: &str,
    rid: &str,
    upstream_name: &str,
    obs: &Arc<Observability>,
) -> Result<
    Response<crate::dataplane::upstream::UpstreamBody>,
    crate::dataplane::upstream::UpstreamError,
> {
    use crate::dataplane::upstream::UpstreamBody;
    use tokio::task::JoinSet;
    use tracing::{info, warn};

    let hedge_after = hedge.hedge_after;
    let hedge_max = hedge.hedge_max;

    // Phase 1: race the primary send against the hedge timer. If the
    // primary resolves first (Ok or Err), no hedge is needed — return it.
    tokio::pin!(primary_send);
    let timer = tokio::time::sleep(hedge_after);
    tokio::pin!(timer);

    tokio::select! {
        biased;
        result = &mut primary_send => {
            return result;
        }
        _ = &mut timer => {
            // Timer fired — enter the hedge phase.
            warn!(
                code = "hedge_timer_fired",
                request_id = %rid,
                upstream = upstream_name,
                "hedge timer fired after {}ms; sending speculative copies",
                hedge_after.as_millis()
            );
        }
    }

    // Phase 2: spawn hedge copies into a JoinSet. The primary is kept
    // as a pinned local future (not spawned) to avoid the 'static bound;
    // we race it alongside the JoinSet using a select loop.
    let mut set: JoinSet<Result<Response<UpstreamBody>, UpstreamError>> = JoinSet::new();

    // Spawn up to hedge_max hedge copies. The `hedge_max` config bounds
    // the amplification factor (at most N speculative copies per request).
    // Hedge copies are NOT charged against the retry budget — the budget
    // prevents retry storms after failures, while hedging is a proactive
    // performance optimization that runs on every slow request.
    let mut hedges_spawned: u32 = 0;
    for _ in 0..hedge_max {
        let body: AttemptBody<Full<Bytes>> = AttemptBody::Replay(replay.clone());
        let hedge_req = Request::from_parts(out_req_parts.clone(), body);
        let handle_clone = Arc::clone(handle);
        let hash_key = dispatch_hash_key.to_string();
        let obs_clone = Arc::clone(obs);
        let upstream_name_clone = upstream_name.to_string();
        set.spawn(async move {
            let mut ep: Option<String> = None;
            let result = handle_clone
                .send_with_hash_key_observed(hedge_req, Some(&hash_key), &mut ep)
                .await;
            if let Ok(ref resp) = result {
                obs_clone.record_upstream_attempt(
                    &upstream_name_clone,
                    ep.as_deref().unwrap_or("unpicked"),
                    resp.status().as_u16(),
                );
            }
            result
        });
        hedges_spawned += 1;
        obs.record_hedge_sent(upstream_name);
    }

    info!(
        code = "hedge_sent",
        request_id = %rid,
        upstream = upstream_name,
        copies = hedges_spawned,
        "sent {} hedge copies",
        hedges_spawned
    );

    // Race the primary (local pinned future) against the hedge JoinSet.
    // First Ok wins; on a hedge Ok the primary is dropped (its connection
    // is abandoned — the upstream response body is not consumed). If the
    // primary resolves first (Ok or Err), hedges are aborted.
    loop {
        tokio::select! {
            biased;
            result = &mut primary_send => {
                set.abort_all();
                return result;
            }
            joined = set.join_next(), if !set.is_empty() => {
                match joined {
                    Some(Ok(Ok(resp))) => {
                        // First hedge success wins. Drop the primary
                        // (its upstream connection is abandoned).
                        set.abort_all();
                        return Ok(resp);
                    }
                    Some(Ok(Err(_))) => {
                        // Hedge errored — continue racing the primary
                        // against remaining hedges.
                    }
                    Some(Err(_)) => {
                        // Hedge task panicked — treat as errored.
                    }
                    None => {
                        // All hedges completed (errored). Fall through
                        // to await the primary directly.
                        break;
                    }
                }
            }
        }
    }

    // All hedges errored — await the primary directly.
    primary_send.await
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

/// Finalize a proxied response: upgrade tunneling for 101s (with the
/// DW-039 WebSocket policer when the route asked for one), hop-by-hop
/// stripping, and the streaming body passthrough. The gateway
/// concurrency-cap permit (DW-015), when present, is attached to the
/// streaming body so the global slot is held until the body completes or
/// the response is dropped (client disconnect included); a tunneled 101
/// releases it when the (empty) 101 response is dropped. A gRPC
/// request's armed deadline (DW-039) keeps ticking through the body as
/// its ABSOLUTE bound.
#[allow(clippy::too_many_arguments)] // the per-request explicit-inputs rule (see proxy_request)
fn finish_proxy_response(
    mut resp: Response<UpstreamBody>,
    wants_upgrade: bool,
    on_client_upgrade: Option<hyper::upgrade::OnUpgrade>,
    global_permit: Option<OwnedSemaphorePermit>,
    ws_police: Option<WsPoliceDecision>,
    obs_arc: &Arc<Observability>,
    grpc_deadline: Option<std::time::Instant>,
    rid: &str,
) -> Response<ProxyBody> {
    if resp.status() == StatusCode::SWITCHING_PROTOCOLS && wants_upgrade {
        // DW-039: policing keys off what the UPSTREAM actually
        // upgraded (its 101 names the protocol), not what the client
        // offered — a mixed-token request (`Upgrade: foo, websocket`)
        // whose upstream upgrades `foo` must not have a non-WebSocket
        // tunnel parsed as WS frames (and a WS close frame injected
        // into it). Read the header BEFORE `upgrade::on` consumes the
        // response.
        let upgraded_websocket = crate::dataplane::websocket::offers_websocket(resp.headers());
        let ws_police = if upgraded_websocket { ws_police } else { None };
        let on_upstream = hyper::upgrade::on(&mut resp);
        if let Some(client) = on_client_upgrade {
            let obs = Arc::clone(obs_arc);
            tokio::spawn(async move {
                match tokio::try_join!(client, on_upstream) {
                    Ok((client_io, upstream_io)) => match ws_police {
                        Some(policy) => {
                            // DW-039: police the client side — count data
                            // frames, close 1008 past the allowance. The
                            // violation flag is shared with the wrapper so
                            // the metric survives the tunnel consuming it.
                            let flag = Arc::new(AtomicU64::new(0));
                            let policed = crate::dataplane::websocket::WsPoliceIo::with_flag(
                                TokioIo::new(client_io),
                                policy.rate,
                                Arc::clone(&flag),
                            );
                            tunnel(policed, TokioIo::new(upstream_io)).await;
                            if flag.load(Ordering::Relaxed) == 1 {
                                obs.record_websocket_policy(&policy.route, "rate_closed");
                                tracing::warn!(
                                    code = "websocket_rate_closed",
                                    route = %policy.route,
                                    "websocket connection closed by frame-rate policy"
                                );
                            }
                        }
                        None => tunnel(TokioIo::new(client_io), TokioIo::new(upstream_io)).await,
                    },
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
    let _ = strip_hop_by_hop(resp.headers_mut(), false, false);
    if let Some(permit) = global_permit {
        resp.body_mut().set_release_permit(permit);
    }
    if let Some(deadline) = grpc_deadline {
        resp.body_mut().set_deadline(deadline);
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

/// Map a failed REQUEST body transform (DW-028) to its client answer.
/// The two marker arms keep the answer of the layer that tripped (the
/// route limit's 413, the HMAC family's 401); the transform's own
/// failures answer in its envelope with generic client-facing text
/// (the offending POINTER is logged server-side only — it names the
/// route's contract, not the client's business).
fn request_body_transform_failed(
    e: crate::dataplane::transforms::RequestBodyTransformError,
    rid: &str,
) -> Response<ProxyBody> {
    use crate::dataplane::transforms::RequestBodyTransformError;
    match e {
        RequestBodyTransformError::RouteLimit => simple(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_body_too_large",
            "request body exceeded the route limit mid-stream",
            rid,
        ),
        RequestBodyTransformError::SignatureMismatch => {
            tracing::warn!(
                code = "signature_body_mismatch",
                request_id = %rid,
                "signed request body did not match its digest while buffering for a transform"
            );
            unauthorized(crate::security::authn::HMAC_CHALLENGE, rid)
        }
        RequestBodyTransformError::TooLarge { cap } => simple(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_body_too_large",
            &format!("request body exceeds the route's transform cap of {cap} bytes"),
            rid,
        ),
        RequestBodyTransformError::InvalidJson => simple(
            StatusCode::BAD_REQUEST,
            "request_body_invalid_json",
            "request body is not valid JSON (a JSON body transform is configured on this route)",
            rid,
        ),
        RequestBodyTransformError::Unresolved { path } => {
            tracing::warn!(
                code = "request_transform_failed",
                request_id = %rid,
                pointer = %path,
                "request body pointer did not resolve against the route's transform policy"
            );
            simple(
                StatusCode::BAD_REQUEST,
                "request_transform_failed",
                "request body did not match the route's transform policy",
                rid,
            )
        }
        RequestBodyTransformError::Body(_) => simple(
            StatusCode::BAD_REQUEST,
            "request_body_invalid",
            "request body could not be read",
            rid,
        ),
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

/// Dispatch the route action (DW-047 extraction point): the proxy/
/// redirect/respond/mock action, generic over the body type so it
/// accepts both the original streaming body `B` and the `Full<Bytes>`
/// body produced by request validation. This is the action half of
/// `handle_routed`; the response decoration tail (masking, transforms,
/// compression, ...) runs in `handle_routed` after this returns.
#[allow(clippy::too_many_arguments)]
async fn dispatch_action<B>(
    req: Request<B>,
    route: &Route,
    gen: &Arc<Generation>,
    idx: usize,
    params: &[(String, String)],
    peer: IpAddr,
    identity: Option<&crate::security::authn::Identity>,
    rid: &str,
    rec: &mut AccessRecord,
    global_permit: &mut Option<OwnedSemaphorePermit>,
    dp: &Arc<DataPlane>,
    client_cert: Option<&Arc<crate::security::authn::ClientCertificate>>,
) -> Response<ProxyBody>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    match &route.action {
        RouteAction::Mock { mock } => {
            serve_mock(mock, gen.snapshot.route_table().mock_body(idx), rid).await
        }
        RouteAction::Ai => {
            let listener_name = rec.listener.clone();
            crate::dataplane::ai_proxy::serve_ai(
                req,
                &route.name,
                gen,
                dp,
                rid,
                rec,
                identity,
                &listener_name,
            )
            .await
        }
        RouteAction::Proxy { .. } => {
            // DW-062: fault injection — abort and delay are evaluated
            // BEFORE any upstream contact. The abort short-circuits with
            // a configured status; the delay injects a fixed latency.
            // Both are sampled by percentage (a random draw per
            // request). This runs before the body limit and digest
            // checks because an aborted request never reaches the
            // upstream and a delayed request waits before the forward
            // path begins.
            if let Some(fi) = &route.fault_injection {
                if let Some(abort) = &fi.abort {
                    if sample_percentage(abort.percentage) {
                        tracing::info!(
                            code = "fault_injection_abort",
                            request_id = %rid,
                            route = %route.name,
                            status = abort.status,
                            "fault injection: aborting request"
                        );
                        return simple(
                            StatusCode::from_u16(abort.status)
                                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                            "fault_injection_abort",
                            "request aborted by fault injection",
                            rid,
                        );
                    }
                }
                if let Some(delay) = &fi.delay {
                    if sample_percentage(delay.percentage) {
                        tracing::info!(
                            code = "fault_injection_delay",
                            request_id = %rid,
                            route = %route.name,
                            delay_ms = delay.fixed_ms,
                            "fault injection: delaying request"
                        );
                        tokio::time::sleep(Duration::from_millis(delay.fixed_ms)).await;
                    }
                }
            }
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
            let signed_digest = identity.and_then(|id| id.body_digest);
            // Eager verdict for a signed body declaring EXACTLY zero
            // bytes: hyper's h1 encoder never polls it (see
            // DigestingBody's docs), so a digest mismatch there has
            // no mid-stream abort to surface through — refuse with
            // the family's 401 before the request is forwarded at
            // all. A correct empty digest forwards normally; unsigned
            // requests are unaffected.
            //
            // DW-062: shadow traffic mirroring. When the route has a
            // mirror config and the percentage sample hits, spawn a
            // fire-and-forget task that sends a copy of the request
            // (same headers and path, empty body) to the mirror
            // upstream. The mirror response is discarded and the task
            // is detached — it never impacts the primary request's
            // latency. The mirror runs AFTER fault injection (an
            // aborted request is never mirrored). For v1 the mirror
            // carries the request shape (method, path, headers) but an
            // empty body — this avoids body buffering entirely and has
            // truly zero latency impact. A future version may buffer
            // the body for full shadow requests.
            let mirror_cfg = route
                .mirror
                .as_ref()
                .filter(|m| m.percentage > 0 && sample_percentage(m.percentage));
            let (parts, body) = req.into_parts();
            // Spawn the mirror task (fire-and-forget) before the
            // primary forward. The mirror gets a cloned request with
            // an empty body.
            if let Some(m) = mirror_cfg {
                if let Some(mirror_handle) = dp.registry().get(&m.upstream) {
                    let mirror_parts = parts.clone();
                    let mirror_upstream_name = m.upstream.clone();
                    let mirror_rid = rid.to_string();
                    dp.observability_arc().record_mirror_sent(&m.upstream);
                    tokio::spawn(async move {
                        let mirror_req = Request::from_parts(mirror_parts, Full::new(Bytes::new()));
                        let result = mirror_handle.send(mirror_req).await;
                        if let Err(e) = result {
                            tracing::debug!(
                                code = "mirror_request_failed",
                                request_id = %mirror_rid,
                                upstream = %mirror_upstream_name,
                                error = %e,
                                "mirror request failed (best-effort, ignored)"
                            );
                        }
                    });
                    tracing::debug!(
                        code = "mirror_sent",
                        request_id = %rid,
                        route = %route.name,
                        upstream = %m.upstream,
                        "sent mirror request to shadow upstream"
                    );
                }
            }
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
                    gen,
                    peer,
                    req,
                    route,
                    idx,
                    params,
                    global_permit,
                    identity,
                    rid,
                    rec,
                    &dp.observability_arc(),
                    client_cert,
                    dp.oauth2_token_cache(),
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
    }
}

/// Serve a mock response (DW-047): no upstream contact, just the
/// canned status/headers/body. `body_file_bytes` is the preloaded file
/// content from the RouteTable (None when the mock uses an inline
/// `body` or an empty body). `delay_ms` simulates latency before the
/// response is sent.
async fn serve_mock(
    mock: &crate::config::MockAction,
    body_file_bytes: Option<&Bytes>,
    _rid: &str,
) -> Response<ProxyBody> {
    if let Some(delay) = mock.delay_ms {
        if delay > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay as u64)).await;
        }
    }
    let body_bytes: Bytes = if let Some(file_bytes) = body_file_bytes {
        file_bytes.clone()
    } else if let Some(body) = &mock.body {
        Bytes::from(body.clone())
    } else {
        Bytes::new()
    };
    let mut builder =
        Response::builder().status(StatusCode::from_u16(mock.status).unwrap_or(StatusCode::OK));
    // Default content-type: application/json if the body parses as
    // JSON, else text/plain — but only when the operator did not set
    // one explicitly (an explicit header always wins).
    let has_content_type = mock
        .headers
        .keys()
        .any(|k| k.eq_ignore_ascii_case("content-type"));
    if !has_content_type {
        let is_json = serde_json::from_slice::<serde_json::Value>(&body_bytes).is_ok();
        builder = builder.header(
            hyper::header::CONTENT_TYPE,
            if is_json {
                "application/json"
            } else {
                "text/plain"
            },
        );
    }
    for (name, value) in &mock.headers {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            builder = builder.header(n, v);
        }
    }
    builder
        .body(ProxyBody::Full(Full::new(body_bytes)))
        .expect("static mock body is valid")
}

/// Validate the request body against a JSON schema (DW-047). Buffers
/// the body fully (the route's body limit was already enforced above),
/// parses it as JSON, and walks the schema. On success, returns the
/// request with the body replaced by the buffered bytes (a `Full<Bytes>`
/// body) so the action below sees the full body. On failure, returns
/// `Err(violation_path)`. A non-JSON body with a schema that expects an
/// object/array is a validation failure; a schema with no `type` is
/// permissive (only `required`/`enum`/bounds are checked).
async fn validate_and_replay_body<B>(
    req: Request<B>,
    schema: &crate::config::BodySchema,
) -> Result<Request<Full<Bytes>>, String>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    use http_body_util::BodyExt as _;
    let (parts, body) = req.into_parts();
    let collected = body
        .collect()
        .await
        .map_err(|_| "request body could not be read".to_string())?;
    let bytes = collected.to_bytes();
    // An empty body: if the schema requires fields, that is a mismatch;
    // otherwise (no required, no type, or type=null) it passes.
    if bytes.is_empty() {
        if !schema.required.is_empty() {
            return Err(format!(
                "missing required field(s): {}",
                schema.required.join(", ")
            ));
        }
        return Ok(Request::from_parts(parts, Full::new(bytes)));
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| "body is not valid JSON".to_string())?;
    if let Some(violation) = validate_json_instance(&value, schema, "") {
        return Err(violation);
    }
    Ok(Request::from_parts(parts, Full::new(bytes)))
}

/// Walk a JSON instance against the minimal schema subset (DW-047).
/// Returns `Some(path)` on the first violation, `None` on success. The
/// `path` is a JSON-pointer-style string (e.g. `/name` or `/items/0`).
fn validate_json_instance(
    value: &serde_json::Value,
    schema: &crate::config::BodySchema,
    path: &str,
) -> Option<String> {
    // type check
    if let Some(t) = &schema.r#type {
        let ok = match t.as_str() {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "number" => value.is_number(),
            "integer" => {
                value.is_i64()
                    || value.is_u64()
                    || (value.is_f64() && value.as_f64().map(|f| f.fract() == 0.0).unwrap_or(false))
            }
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            _ => true, // unknown type: permissive (validation caught it)
        };
        if !ok {
            return Some(format!("{path}: expected type {t}"));
        }
    }
    // enum check
    if !schema.r#enum.is_empty() && !schema.r#enum.iter().any(|e| e == value) {
        return Some(format!("{path}: value not in enum"));
    }
    // string checks
    if let Some(s) = value.as_str() {
        if let Some(min) = schema.min_length {
            if (s.chars().count() as u64) < min {
                return Some(format!("{path}: string shorter than minLength {min}"));
            }
        }
        if let Some(max) = schema.max_length {
            if (s.chars().count() as u64) > max {
                return Some(format!("{path}: string longer than maxLength {max}"));
            }
        }
    }
    // numeric checks
    if let Some(n) = value.as_f64() {
        if let Some(min) = schema.minimum {
            if n < min {
                return Some(format!("{path}: number below minimum {min}"));
            }
        }
        if let Some(max) = schema.maximum {
            if n > max {
                return Some(format!("{path}: number above maximum {max}"));
            }
        }
    }
    // object checks
    if let Some(obj) = value.as_object() {
        for req in &schema.required {
            if !obj.contains_key(req) {
                return Some(format!("{}/{}: missing required field", path, req));
            }
        }
        for (key, child_schema) in &schema.properties {
            if let Some(child) = obj.get(key) {
                if let Some(v) =
                    validate_json_instance(child, child_schema, &format!("{path}/{key}"))
                {
                    return Some(v);
                }
            }
        }
        // additionalProperties
        if let Some(ap) = &schema.additional_properties {
            match ap.as_ref() {
                crate::config::AdditionalProperties::Bool(false) => {
                    for key in obj.keys() {
                        if !schema.properties.contains_key(key) {
                            return Some(format!("{path}/{key}: additional property not allowed"));
                        }
                    }
                }
                crate::config::AdditionalProperties::Schema(s) => {
                    for key in obj.keys() {
                        if !schema.properties.contains_key(key) {
                            if let Some(child) = obj.get(key) {
                                if let Some(v) =
                                    validate_json_instance(child, s, &format!("{path}/{key}"))
                                {
                                    return Some(v);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    // array checks
    if let Some(arr) = value.as_array() {
        if let Some(items_schema) = &schema.items {
            for (i, elem) in arr.iter().enumerate() {
                if let Some(v) = validate_json_instance(elem, items_schema, &format!("{path}/{i}"))
                {
                    return Some(v);
                }
            }
        }
    }
    None
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

/// DW-062: sample a percentage (0..=100). Returns true with probability
/// `percentage / 100`. A percentage of 0 always returns false; 100 always
/// returns true. Uses a fast thread-local PRNG (no crypto strength needed
/// — this is a sampling decision, not a security boundary).
fn sample_percentage(percentage: u8) -> bool {
    if percentage == 0 {
        return false;
    }
    if percentage >= 100 {
        return true;
    }
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u64> = Cell::new({
            // Seed from the system time — no crypto strength needed,
            // just enough entropy to avoid correlated samples across
            // threads. The xorshift step below scrambles it further.
            let seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0x9E3779B97F4A7C15);
            if seed == 0 { 0x9E3779B97F4A7C15 } else { seed }
        });
    }
    STATE.with(|state| {
        let mut s = state.get();
        // xorshift64 — fast, good enough for sampling.
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        state.set(s);
        // Map to 0..=99 and compare.
        (s % 100) < percentage as u64
    })
}

/// The outcome of the gateway cap admission phase (DW-015 + DW-053):
/// either a permit was acquired (Some) or the request was dry-run
/// admitted over the cap (None), the request was shed and the 503
/// response should be returned from `handle`, or the request needs to
/// wait for a permit (DW-053 queue path — the timed acquire runs outside
/// the span guard because `EnteredSpan` is not `Send`).
enum AdmissionResult {
    /// Admission succeeded: the permit is `Some` when a cap slot was
    /// acquired, `None` when dry-run admitted over the cap (DW-041).
    Permit(Option<OwnedSemaphorePermit>),
    /// The request was shed: return this 503 response from `handle`.
    Shed(Response<ProxyBody>),
    /// DW-053: the request reserved a queue slot and needs a timed
    /// acquire. Carries the semaphores, the timeout, and the queue
    /// depth atomic (to decrement after the acquire completes).
    Queue(
        Arc<Semaphore>,
        Option<Arc<Semaphore>>,
        Duration,
        Arc<AtomicU32>,
    ),
}

/// The shed path for the gateway concurrency cap (DW-015 + DW-053).
/// When `dry_run` is true (DW-041), the would-shed is logged and counted
/// and the request is admitted over the cap (no permit) — the point is
/// observing what a cap would shed before enforcing it. When `dry_run`
/// is false, the request is shed with 503 "gateway saturated". When
/// `retry_after` is `Some` (DW-053: the request was shed due to queue
/// timeout or queue full), a `Retry-After` header is added to the 503.
///
/// Returns an [`AdmissionResult`]: `Permit(None)` for dry-run, `Shed`
/// for the 503 response. The caller returns the `Shed` response from
/// `handle` immediately.
#[allow(clippy::too_many_arguments)]
fn handle_shed(
    dp: &Arc<DataPlane>,
    priority: u8,
    rec: &mut AccessRecord,
    rid: &str,
    route: &Route,
    retry_after: Option<Duration>,
    dry_run: bool,
    consumer_name: Option<&str>,
) -> AdmissionResult {
    if dry_run {
        dp.priority_counters.record_admitted(priority);
        dp.obs.record_policy_dry_run("load_shed", &route.name);
        dp.obs.emit_policy_dry_run(
            "load_shed",
            503,
            &route.name,
            consumer_name,
            rid,
            &format!(
                "gateway concurrency cap saturated at priority {priority}; \
                 request would have been shed (dry-run) and is admitted \
                 over the cap"
            ),
        );
        AdmissionResult::Permit(None)
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
        let mut resp = simple(
            StatusCode::SERVICE_UNAVAILABLE,
            "gateway_saturated",
            "gateway saturated",
            rid,
        );
        // DW-053: a Retry-After header on queue-timeout and queue-full
        // sheds (a small fixed value derived from the queue timeout, in
        // whole seconds, minimum 1). The immediate-shed path (DW-016,
        // no queue) carries no Retry-After — immediate re-dispatch
        // under a saturated gateway is not advised.
        if let Some(timeout) = retry_after {
            let secs = timeout.as_secs().max(1);
            if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                resp.headers_mut().insert(hyper::header::RETRY_AFTER, v);
            }
        }
        stamp_security_headers(&mut resp, route);
        AdmissionResult::Shed(resp)
    }
}

/// DW-053: try to acquire a permit from the general semaphore (or the
/// reserved bucket for high-priority) within the queue timeout. Returns
/// `Some(permit)` if acquired, `None` if the timeout expired. This is a
/// timed `acquire_owned` — the request parks on the semaphore's wait
/// queue until a permit is released or the timeout fires.
async fn try_acquire_queued(
    general: Arc<Semaphore>,
    reserved: Option<Arc<Semaphore>>,
    priority: u8,
    timeout: Duration,
) -> Option<OwnedSemaphorePermit> {
    // High-priority tries the general semaphore first, then the
    // reserved bucket (same two-tier order as the immediate path).
    let general_fut = general.acquire_owned();
    let reserved_fut = reserved.map(|r| r.acquire_owned());
    let result = tokio::time::timeout(timeout, async {
        match general_fut.await {
            Ok(permit) => Some(permit),
            Err(_) => {
                // The general semaphore was closed (should not happen
                // in normal operation — the Arc keeps it alive). Try
                // the reserved bucket as a fallback for high-priority.
                if priority >= HIGH_PRIORITY {
                    if let Some(fut) = reserved_fut {
                        fut.await.ok()
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        }
    })
    .await;
    match result {
        Ok(Some(permit)) => Some(permit),
        Ok(None) => None,
        Err(_) => None,
    }
}

/// Header names always treated as hop-by-hop per RFC 7230 section 6.1
/// (plus the de-facto `Proxy-Connection`), and any name listed in ANY
/// `Connection` header (RFC 7230 allows multiple; only `get_all` sees them
/// all). `TE` is dropped — EXCEPT for a gRPC request (DW-039), whose
/// spec-mandated `TE: trailers` rides through so conformant gRPC
/// servers see the client's dialect (h2 carries trailers natively; the
/// header is the courtesy contract). `Upgrade` (and its `Connection`
/// token) survives only when the request is being tunneled.
///
/// Returns the `Connection` token list collected before stripping (original
/// case, deduplicated, order preserved) so the tunneling caller can rebuild
/// a `Connection` header with the surviving tokens.
///
/// (Public so the DW-024 micro-benchmark can exercise it directly; it is
/// not part of the stable public surface.)
pub fn strip_hop_by_hop(
    headers: &mut HeaderMap,
    keep_upgrade: bool,
    preserve_te: bool,
) -> Vec<String> {
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
                    | "trailer"
                    | "transfer-encoding"
            ) || (n == "te" && !preserve_te)
                || (n == "upgrade" && !keep_upgrade)
        })
        .cloned()
        .collect();
    for name in drop {
        headers.remove(&name);
    }
    tokens
}

/// Whether a request is gRPC (DW-039): HTTP/2 with an
/// `application/grpc` content type (the spec's family prefix —
/// `application/grpc+proto`, `+json`, ... all match).
///
/// (Public for the DW-039 unit tests; like `strip_hop_by_hop`, not
/// part of the stable public surface.)
pub fn grpc_request(headers: &HeaderMap, version: Version) -> bool {
    version == Version::HTTP_2
        && headers
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("application/grpc"))
}

/// Parse a `grpc-timeout` value (DW-039): 1..=8 ASCII decimal digits
/// plus a unit — Hours, Minutes, Seconds, milliseconds, microseconds,
/// nanoseconds (RFC `SnH` grammar, case-exact per the spec). Values
/// that overflow the duration space saturate at one day (a longer RPC
/// budget than that is un-enforceable by this gateway anyway); garbage
/// is `None` (the caller treats absence as no deadline).
///
/// (Public for the DW-039 unit tests; like `strip_hop_by_hop`, not
/// part of the stable public surface.)
pub fn parse_grpc_timeout(value: &str) -> Option<std::time::Duration> {
    let (digits, unit) = value.split_at(value.len().checked_sub(1)?);
    if digits.is_empty() || digits.len() > 8 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = digits.parse().ok()?;
    let nanos = match unit {
        "H" => n.saturating_mul(3_600_000_000_000),
        "M" => n.saturating_mul(60_000_000_000),
        "S" => n.saturating_mul(1_000_000_000),
        "m" => n.saturating_mul(1_000_000),
        "u" => n.saturating_mul(1_000),
        "n" => n,
        _ => return None,
    };
    Some(std::time::Duration::from_nanos(
        nanos.min(86_400_000_000_000),
    ))
}

/// The post-upgrade WebSocket policing decision threaded to the
/// tunnel (DW-039): the route label for the metric and the frame
/// allowance.
struct WsPoliceDecision {
    route: String,
    rate: u64,
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

// White-box test staying in src/ per AGENTS.md: exercises private proxy
// internals that are not reachable through the public API.
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
