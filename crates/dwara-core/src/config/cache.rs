//! Route-scoped response caching grammar (DW-037, feature analysis
//! 5-Protocol "Response caching"): the config shape of a route's cache
//! policy and the compiled form the dataplane's response cache consumes.
//!
//! This is config-contract grammar in the same sense as `transforms.rs`
//! (DW-028) and `versioning.rs` (DW-048): validation
//! (`snapshot::validate`) and the runtime (`dataplane::response_cache`)
//! must agree on ONE parsing of these values, so the grammar lives in
//! `config`, the lowest consuming domain.
//!
//! ## Posture: explicit opt-in buffering, bounded
//!
//! The dataplane buffers nothing by default; a cache entry is a
//! buffered response body. Presence of the `cache` block is therefore
//! the opt-in (the same presence-means-enabled rule as `transforms`,
//! `compression`, and `masking`), and the buffering is capped by
//! `max_body_bytes` per entry: a response that would cross the cap is
//! passed through UNSTORED and streams exactly as if no cache existed
//! (see `dataplane::response_cache` for the full cacheability matrix).
//!
//! ## Variance model: configured + policy-derived, not response-driven
//!
//! RFC 9111 lets a response's own `Vary` drive what a shared cache
//! keys on. dwara's cache key must be derivable from the REQUEST alone
//! (the backing `CacheStore` extension trait is an opaque key-value
//! seam — no entry enumeration, so no
//! two-level "hash, then vary" lookup is possible). The variance
//! dimension is therefore DECLARED, not discovered:
//!
//! - the operator lists extra request headers in `vary`;
//! - the snapshot compile folds in the headers the gateway's own
//!   policies already promise to vary by: `Accept` when the route
//!   selects on `match.accept` (DW-048), `Origin` when the route
//!   carries a CORS policy (DW-027), and `Accept-Encoding` never
//!   (cached bodies are identity; compression re-negotiates per
//!   request on replay).
//!
//! A response whose `Vary` names anything OUTSIDE the effective set is
//! not stored (the cache cannot prove it would key correctly), and
//! `Vary: *` never stores. The union of everything the key folds in is
//! stamped on cached responses through the decoration tail's existing
//! `Vary` merges, so replays advertise exactly what they varied by.

use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Default `cache.max_body_bytes` (DW-037): 1 MiB per entry — large
/// enough for typical JSON payloads, small enough that a full store of
/// them stays cheap. Validation bounds the configurable range around it.
pub const DEFAULT_CACHE_MAX_BODY_BYTES: u64 = 1024 * 1024;

/// Upper bound for `cache.max_body_bytes` (DW-037): 16 MiB. A cache
/// entry is a buffered body; the ceiling keeps one route's policy from
/// opting the gateway into buffering near-streaming payloads.
pub const MAX_CACHE_MAX_BODY_BYTES: u64 = 16 * 1024 * 1024;

/// Upper bound for `cache.ttl_secs` (DW-037): 24 hours. Freshness
/// beyond a day is an origin's job (CDN), not a gateway's local cache.
pub const MAX_CACHE_TTL_SECS: u64 = 86400;

/// Upper bound for `cache.stale_while_revalidate_secs` (DW-037): 24
/// hours, symmetric with the TTL bound.
pub const MAX_CACHE_STALE_SECS: u64 = 86400;

/// Maximum number of `vary` entries (DW-037): the vary set multiplies
/// the key space per route; eight extra dimensions is already generous.
pub const MAX_CACHE_VARY_HEADERS: usize = 8;

/// Default `cache.coalescing.wait_ms` (DW-038): 5 s — comfortably above
/// a typical upstream fetch so a follower normally out-waits the leader
/// instead of piling its own call on top (the wait bound exists for the
/// pathological leader, not the common one).
pub const DEFAULT_COALESCE_WAIT_MS: u64 = 5000;

/// Upper bound for `cache.coalescing.wait_ms` (DW-038): 60 s. A follower
/// parked longer than a minute is a stuck request from the client's
/// point of view; the route's own timeouts bound the leader, so a wait
/// beyond them only delays the inevitable fail-open.
pub const MAX_COALESCE_WAIT_MS: u64 = 60_000;

/// Route-scoped response caching policy (DW-037). Absent (the
/// default): the route's responses are never cached, buffered, or
/// stamped with cache headers — bytes flow exactly as before. Presence
/// opts the route's GET traffic into the local response cache behind
/// the `CacheStore` extension seam (extensions domain).
///
/// Semantics (frozen; enforcement lives in `dataplane::response_cache`):
///
/// - Only PROXY-action routes cache. The key folds in the route name,
///   the consumer, the inbound path + query, and the effective vary
///   set's request header values — two consumers (or two vary
///   dimensions) never share an entry.
/// - Freshness is the configured `ttl_secs`, full stop: upstream
///   freshness directives other than the storage vetoes
///   (`no-store`/`private`/`no-cache`) are deliberately ignored — the
///   OPERATOR, not the origin, owns how long the gateway holds an
///   entry. Within `stale_while_revalidate_secs` after expiry the
///   entry is served stale while a single background revalidation
///   refreshes it; past that window the next request revalidates
///   synchronously (conditional on the stored validator).
/// - `ETag` round-trips: a stored entry's ETag backs client
///   `If-None-Match` 304s from the cache and upstream revalidation
///   (`If-None-Match` on the forwarded fetch; a 304 refreshes the
///   entry without re-sending the body).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteCache {
    /// Freshness lifetime, in seconds. Required: a cache entry without
    /// a lifetime is an unbounded staleness bug, so there is no
    /// default. Validation rejects 0 and values above 24 hours.
    pub ttl_secs: u64,
    /// How long past expiry the entry may be served stale while a
    /// background revalidation runs (DW-037
    /// stale-while-revalidate). Absent/0: no stale serving — an expired
    /// entry revalidates synchronously. Validation bounds the value to
    /// 24 hours.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_while_revalidate_secs: Option<u64>,
    /// Per-entry body cap in bytes: responses at or under the cap are
    /// buffered and stored; larger responses pass through unstored and
    /// unbuffered (the zero-buffering principle — the cap is the
    /// buffering opt-in's hard edge). Absent: 1 MiB. Validation bounds
    /// the range [1, 16 MiB].
    #[serde(
        default = "default_cache_max_body_bytes",
        skip_serializing_if = "is_default_max_body_bytes"
    )]
    pub max_body_bytes: u64,
    /// Extra request header names folded into the cache key (the
    /// configured half of the variance model — see the module docs).
    /// The policy-derived halves (`Accept` for `match.accept` routes,
    /// `Origin` for CORS routes) are added at snapshot compile and
    /// need not (but may) be listed. Validation rejects duplicates,
    /// hop-by-hop/framing names, `Authorization`/`Cookie` (requests
    /// carrying them are never cacheable, so varying on them is dead
    /// configuration), and `X-Consumer-*` (consumer identity is already
    /// a key component).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vary: Vec<String>,
    /// Request coalescing (DW-038): collapse concurrent identical
    /// cacheable GETs on this route into ONE upstream call — the first
    /// miss (the leader) fetches while the rest (followers) wait,
    /// bounded, and replay the leader's stored outcome. Absent (the
    /// default): every miss fetches independently, exactly as before.
    /// Presence enables; see [`RouteCacheCoalescing`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coalescing: Option<RouteCacheCoalescing>,
}

/// Request-coalescing knobs (DW-038). Presence of the block on a
/// route's `cache` is the opt-in (the same presence-means-enabled rule
/// as every other block); this struct carries the one bound the
/// behavior needs.
///
/// Scope (deliberate, spec-faithful): coalescing applies ONLY to the
/// cache-miss path of cache-enabled routes — "concurrent identical
/// CACHEABLE GETs". Requests on routes without a `cache` block (or
/// shapes the cache bypasses: non-GET, credentialed, body-bearing,
/// upgrade) are never coalesced; they were never cacheable, so there is
/// no shared outcome to hand a follower.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteCacheCoalescing {
    /// How long a follower waits for the leader's outcome before doing
    /// its own upstream call (fail open — a client is never errored
    /// because coalescing gave up). Absent: 5 s. Validation bounds the
    /// value to (0, 60 s].
    #[serde(
        default = "default_coalesce_wait_ms",
        skip_serializing_if = "is_default_coalesce_wait_ms"
    )]
    pub wait_ms: u64,
}

fn default_coalesce_wait_ms() -> u64 {
    DEFAULT_COALESCE_WAIT_MS
}

fn is_default_coalesce_wait_ms(v: &u64) -> bool {
    *v == DEFAULT_COALESCE_WAIT_MS
}

fn default_cache_max_body_bytes() -> u64 {
    DEFAULT_CACHE_MAX_BODY_BYTES
}

fn is_default_max_body_bytes(v: &u64) -> bool {
    *v == DEFAULT_CACHE_MAX_BODY_BYTES
}

/// Header names that may never appear in `cache.vary`, with the reason
/// validation reports. Checked case-insensitively against the
/// lowercased name. Grammar helper in the house style of `net.rs` /
/// `transforms.rs`: validation (snapshot) and compile agree on this
/// one parsing.
pub fn forbidden_vary_reason(name: &str) -> Option<&'static str> {
    match name {
        "authorization" | "cookie" => {
            Some("requests carrying it are never cacheable, so varying on it is dead configuration")
        }
        "host" => Some("the route's host match already selects the response"),
        "connection"
        | "keep-alive"
        | "proxy-authenticate"
        | "proxy-authorization"
        | "proxy-connection"
        | "te"
        | "trailer"
        | "transfer-encoding"
        | "upgrade" => Some("hop-by-hop headers never reach the cache decision"),
        "content-length" => Some("framing header; not a variance dimension"),
        "cache-control" | "pragma" => {
            Some("request cache directives do not vary the response body")
        }
        _ => {
            if name.starts_with("x-consumer-") {
                Some("consumer identity is already a cache key component")
            } else {
                None
            }
        }
    }
}

/// The compiled per-route cache policy (DW-037): validated values
/// resolved into the exact durations, bounds, and the EFFECTIVE vary
/// set (configured entries plus the policy-derived `Accept`/`Origin`
/// folds), lowercased and in deterministic order. Built once at
/// snapshot compile (`RouteTable`), never per request.
#[derive(Debug, Clone, PartialEq)]
pub struct CompiledRouteCache {
    /// Freshness lifetime.
    pub ttl: Duration,
    /// Stale-while-revalidate window past expiry (0 = disabled).
    pub stale_while_revalidate: Duration,
    /// Per-entry body cap.
    pub max_body_bytes: u64,
    /// The effective vary set: lowercased header names, deduplicated,
    /// in deterministic order (configured order, then the derived
    /// folds). This is exactly the set of request headers the key folds
    /// in, and exactly what a stored response's `Vary` must be a
    /// subset of.
    pub vary: Vec<String>,
    /// Follower wait bound for request coalescing (DW-038). None:
    /// coalescing disabled on this route (the default).
    pub coalesce_wait: Option<Duration>,
}

impl CompiledRouteCache {
    /// Compile the route's cache block, folding in the policy-derived
    /// vary dimensions: `accept` (Some when the route matches on
    /// `match.accept`, DW-048) and `origin` (the route carries a CORS
    /// policy, DW-027). Validation has already run, so the configured
    /// vary list is well-formed; the folds deduplicate against it.
    pub fn compile(cache: &RouteCache, accept: bool, cors: bool) -> Self {
        let mut vary: Vec<String> = cache
            .vary
            .iter()
            .map(|v| v.trim().to_ascii_lowercase())
            .collect();
        if accept && !vary.iter().any(|v| v == "accept") {
            vary.push("accept".to_string());
        }
        if cors && !vary.iter().any(|v| v == "origin") {
            vary.push("origin".to_string());
        }
        CompiledRouteCache {
            ttl: Duration::from_secs(cache.ttl_secs),
            stale_while_revalidate: Duration::from_secs(
                cache.stale_while_revalidate_secs.unwrap_or(0),
            ),
            max_body_bytes: cache.max_body_bytes,
            vary,
            coalesce_wait: cache
                .coalescing
                .as_ref()
                .map(|c| Duration::from_millis(c.wait_ms)),
        }
    }
}
