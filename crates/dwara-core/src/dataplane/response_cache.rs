//! Local response cache engine (DW-037, feature analysis 5-Protocol
//! "Response caching").
//!
//! Sits behind the [`CacheStore`] extension seam
//! (DW-004): the engine owns HTTP semantics — keys,
//! cacheability, freshness, revalidation, purge — while the backend is
//! an opaque byte store (OSS ships the moka-backed [`MokaCache`];
//! DW-068 swaps in Redis behind the same trait). Cache errors degrade
//! to misses, never request failures.
//!
//! ## Where it sits in the pipeline
//!
//! ```text
//! ... authn -> authz -> rate limit -> cap admission
//!   -> CACHE LOOKUP (hit/stale: replay; miss: fall through)
//!   -> proxy action -> masking (DW-029) -> body/header transforms (DW-028)
//!   -> CACHE STORE (post-mask, post-transform bytes; pre-compression)
//!   -> compression (DW-027) -> versioning stamps (DW-048) -> CORS (DW-027)
//!   -> security headers (DW-028) -> rate headers
//! ```
//!
//! The two placements are load-bearing:
//!
//! - LOOKUP runs after authn/authz/rate limiting on purpose: a replay
//!   is still client traffic (it consumed a rate-limit token and an
//!   admission slot, and the consumer's identity is part of the key),
//!   and no policy may be bypassed by a hit. It runs before the
//!   breaker/endpoint pick because a hit contacts no upstream.
//! - STORE writes the POST-masking, POST-transform bytes keyed per
//!   consumer: replayed bytes are exactly what the same consumer would
//!   have received (masking and transforms are route-scoped, so replay
//!   consistency holds — pinned by test: a transform change invalidates
//!   old entries). Stored bodies are IDENTITY (never compressed —
//!   DW-027's compression re-negotiates per request on replay), and
//!   the decoration tail from compression onward re-runs on every
//!   replay: security headers, masking-era bytes, CORS, rate headers
//!   can never be bypassed by a cache hit.
//!
//! ## Cacheability (deterministic, closed rules)
//!
//! A REQUEST is cacheable when: the route has a `cache` block and a
//! PROXY action; the method is GET or HEAD (DP-04: HEAD is cacheable —
//! a HEAD response carries the same headers as GET with no body, and
//! the method folds into the key so the two representations are
//! distinct entries; a fresh GET entry also serves a HEAD via the
//! GET-fallback, RFC 9111 section 4.1); the request carries no body,
//! no `Authorization`, no `Cookie` (credentials make per-consumer
//! keying insufficient — two bearer tokens of one consumer would share
//! an entry), and no `Upgrade`. Everything else is a BYPASS (stamped
//! and counted, never stored).
//!
//! A RESPONSE is storable when: status is exactly 200; it carries no
//! `Set-Cookie`; its `Cache-Control` has none of `no-store` /
//! `private` / `no-cache` (the storage vetoes; DP-04 additionally
//! honors `s-maxage`/`max-age` as the freshness lifetime — taking
//! precedence over the configured `ttl_secs` — and `stale-if-error`
//! as the per-entry stale-on-error window, RFC 5861 section 4); it is
//! not content-encoded (dwara compresses on replay; an upstream-encoded
//! body cannot be re-negotiated); and its `Vary` is `*`-free and a
//! subset of the route's effective vary set (see `config::cache` for
//! the configured + policy-derived variance model — the key must be
//! derivable from the request alone, so an unknown variance dimension
//! forbids storage).
//!
//! ## Keys
//!
//! `sha256("dwara-rc-v1" | route | epoch | method | consumer | path |
//! query | vary-name=value...)` — hex-encoded. The method component
//! (DP-04) separates HEAD and GET representations of one resource.
//! The consumer component means masked (DW-029) and consumer-group
//! variants can never cross consumers. Keys are never logged (paths
//! and query strings carry tokens; the hash is opaque anyway).
//!
//! ## Freshness, stale-while-revalidate, ETag
//!
//! Fresh for the effective freshness lifetime — the upstream
//! `Cache-Control: s-maxage` (then `max-age`) when present (DP-04,
//! RFC 7234 section 5.2.2.9), else the configured `ttl_secs`; within
//! `stale_while_revalidate_secs` after expiry the entry is served stale (`x-cache: stale`) while ONE
//! background revalidation runs per key (a bounded in-flight set
//! deduplicates; DW-038's request coalescing applies the same
//! single-flight discipline to the foreground miss path). Past the
//! window the next request revalidates synchronously: the stored
//! validator rides the forwarded fetch as `If-None-Match` (only when
//! the client sent none of its own — a client conditional always wins
//! the forwarded request), and an upstream 304 refreshes the entry
//! without re-sending the body (`x-cache: revalidated`). A client
//! `If-None-Match` that matches a FRESH entry's validator is answered
//! 304 straight from the cache. Weak comparison (W/ prefixes ignored)
//! per RFC 9110 section 8.8.3.
//!
//! ## Request coalescing (DW-038)
//!
//! A cache MISS on a route whose cache block carries `coalescing`
//! either becomes the LEADER (fetches upstream while holding the key's
//! slot) or a FOLLOWER (parks, bounded by the route's
//! `coalescing.wait_ms`). The coalescing key IS the cache key — route
//! epoch, consumer, path, query, vary — so a follower can only ever be
//! handed an outcome computed for a byte-identical request shape of
//! its OWN consumer and generation; per-consumer isolation is
//! inherited from the key, not reimplemented. The STORE is the share
//! point: the leader's store stage completes before it publishes, and
//! a woken follower re-reads the store and replays the entry exactly
//! like a hit (`x-cache: hit`; the decoration tail re-runs — the same
//! replay guarantees as a normal hit). Scope: the miss path of
//! cache-enabled routes only. A request shape the cache bypasses
//! (non-GET, credentialed, body-bearing, upgrade) never coalesces,
//! and routes without a cache block never coalesce — "concurrent
//! identical cacheable GETs" is the whole claim.
//!
//! Every failure mode fails OPEN (no client is ever errored because
//! coalescing gave up), each rule pinned by test:
//!
//! - Leader finished with nothing storable (vetoed, non-200, upstream
//!   error, over-cap) or died outright (panic, client-cancel abort):
//!   followers fetch on their own, each running the route's FULL
//!   retry policy — a leader's failure is never inherited.
//! - Epoch flipped mid-flight (purge or config change): followers
//!   fetch on their own rather than inherit a dead generation's
//!   answer.
//! - Follower wait bound expired: the follower fetches on its own.
//! - The leader map is saturated ([`MAX_COALESCING_KEYS`] distinct
//!   in-flight keys): the request never joins — it just fetches
//!   (uncounted by coalescing metrics; it was neither leader nor
//!   follower).
//!
//! The map holds LEADER slots only (waiters carry no per-key state);
//! a slot leaves the map at completion by the leader's guard, and the
//! guard's Drop is the publish — so a leader that dies unpublishes
//! into the fail-open path too. Nothing in the coalescing path waits
//! on the SWR revalidation in-flight set or vice versa: the two
//! single-flight mechanisms have disjoint state and no shared locks,
//! so they cannot deadlock or double-subscribe each other.
//!
//! ## Invalidations (why epochs)
//!
//! Entries record the route's CACHE EPOCH at store time; a lookup
//! under a different epoch is a miss (the dead entry is dropped).
//! Epochs bump on: an explicit purge (the admin API — an O(1)
//! generation advance, which is why purge is <100 ms at any store
//! size; the opaque backend is never enumerated), and any snapshot
//! publish that CHANGES a route's definition (a `Route`-equality diff
//! at refresh — stored bytes were shaped by the old masking/transform/
//! cache policy, so any route change invalidates that route's entries;
//! unrelated config edits leave the cache warm). Entries left
//! unreachable by a bump are never re-read; the byte-weighed store
//! reclaims them by eviction.
//!
//! DP-04 adds two targeted purge axes alongside the epoch-based route
//! purge: purge-by-tag (every entry the upstream tagged with a given
//! `Cache-Tags` value) and purge-by-URL (every entry for an exact or
//! prefix-matched request URL). These delete specific keys through the
//! `CacheStore` seam (O(keys-matching), not O(1)) using in-memory
//! tag→keys and URL→keys indexes populated at store time; the indexes
//! are runtime state (lost on restart) and self-clean lazily as purges
//! drop their dead cross-references.
//!
//! ## Reload behavior
//!
//! The engine (store, epochs, in-flight set) lives on the
//! [`DataPlane`], NOT in the snapshot: it is
//! runtime state, like the priority counters, and survives config
//! reloads. A changed `cache` block applies to NEW lookups (freshness
//! windows are read from the CURRENT policy at lookup time); entries
//! stored under a changed route die by the epoch rule above.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Body as _;
use hyper::header::{HeaderName, HeaderValue};
use hyper::header::{ETAG, IF_NONE_MATCH};
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use sha2::{Digest, Sha256};
use tokio::sync::OwnedSemaphorePermit;

use crate::config::cache::CompiledRouteCache;
use crate::config::Route;
use crate::extensions::cache::{CacheStore, MokaCache};
use crate::observability::Observability;
use crate::security::authn::Identity;
use crate::snapshot::Snapshot;

use super::hardening::merge_vary;
use super::proxy::{DataPlane, ProxyBody};
use super::transforms;

/// The gateway's cache-outcome stamp header (DW-037): `hit`, `stale`,
/// `miss`, `bypass`, or `revalidated` — the same closed set as the
/// `dwara_cache_lookups_total` metric (plus `revalidated`, which is a
/// miss resolved by a 304 confirmation).
pub const X_CACHE: HeaderName = HeaderName::from_static("x-cache");

/// Envelope magic + schema version (see [`EntryEnvelope`]).
const ENVELOPE_MAGIC: [u8; 4] = *b"DWRC";
/// Envelope schema version 1 (DW-037): epoch, stored-at, status,
/// headers, body. Decoded for back-compat with entries a long-lived
/// store may still hold across an in-place upgrade.
const ENVELOPE_VERSION_V1: u8 = 1;
/// Envelope schema version 2 (DP-04): adds the per-entry freshness TTL
/// and the `stale-if-error` window (both in milliseconds, 0 = "use the
/// configured policy"). v2 is what [`EntryEnvelope::encode`] writes;
/// v1 entries decode with both fields zeroed (the policy applies).
const ENVELOPE_VERSION: u8 = 2;

/// Upper bound on concurrently in-flight background revalidations
/// (DW-037): the stale-while-revalidate path serves stale immediately
/// and refreshes in the background; beyond this many DISTINCT keys the
/// gateway skips spawning (the next request past the stale window
/// revalidates synchronously) so a cache-wide expiry cannot stampede.
pub const MAX_INFLIGHT_REVALIDATIONS: usize = 32;

/// Upper bound on concurrently held coalescing LEADER slots (DW-038).
/// The map bounds memory (each slot is a key string + a watch channel)
/// and the stampede-collapse itself: beyond this many DISTINCT
/// in-flight cache keys, new misses never join — they fetch
/// independently (fail open, uncounted by coalescing metrics). Slots
/// are not evicted early (an in-flight leader cannot be preempted —
/// its followers are parked on it); the map drains as leaders
/// complete, which IS the eviction policy: hold-while-in-flight,
/// remove-at-completion, refuse-at-capacity. A same-process burst
/// with more than this many distinct keys was never going to collapse
/// anyway — the keys are distinct.
pub const MAX_COALESCING_KEYS: usize = 256;

/// Wall-clock milliseconds since the Unix epoch (the freshness clock
/// domain; a backwards clock step reads as age 0 — never negative).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The local response cache: opaque store + route epochs + the
/// single-flight revalidation guard + the request-coalescing leader
/// map. Owned by the [`DataPlane`]; survives reloads.
pub struct ResponseCache {
    /// The backing `CacheStore` (SCALE-04, #183: swappable at startup
    /// so the OSS moka backend can be replaced with a Redis-backed
    /// shared cache without rebuilding the whole `ResponseCache`).
    store: RwLock<Arc<dyn CacheStore>>,
    /// Route name -> cache epoch (DW-037 invalidations). Grows with
    /// distinct route names ever seen (bounded by operator config
    /// churn; entries for long-gone routes are a few dozen bytes each
    /// and keep re-added names from inheriting stale entries).
    epochs: RwLock<HashMap<String, u64>>,
    /// Keys with a background revalidation in flight (bounded by
    /// [`MAX_INFLIGHT_REVALIDATIONS`]).
    inflight: Arc<Mutex<HashSet<String>>>,
    /// In-flight coalescing LEADERS (DW-038): cache key -> publication
    /// slot. A leader holds its slot from the miss decision until its
    /// store stage completes (or its task dies — the guard drops).
    /// Bounded by [`MAX_COALESCING_KEYS`]. Runtime state like the
    /// revalidation set: survives reloads, and its keys embed the
    /// route epoch, so a generation change strands waiters into the
    /// fail-open path rather than serving them a dead generation.
    coalescing: Arc<Mutex<HashMap<String, Arc<CoalesceSlot>>>>,
    /// Cache-tag -> set of store keys (DP-04 purge-by-tag). Populated
    /// at store time from the upstream `Cache-Tags` response header.
    /// Purge-by-tag deletes every key in the set (and cleans the
    /// entries). In-memory: lost on restart, so a purge-by-tag after a
    /// restart is a no-op until entries are re-stored — the cache is a
    /// local optimization, and the epoch-based route purge remains the
    /// durable invalidation path. Bounded lazily: dead keys (evicted or
    /// epoch-bumped) are removed when a purge touches their tag.
    tag_index: RwLock<HashMap<String, HashSet<String>>>,
    /// Request URL (`path[?query]`) -> set of store keys (DP-04
    /// purge-by-URL). One URL maps to many keys because the cache key
    /// also folds the route epoch, the consumer, and the vary values,
    /// all invisible to a purge caller. Same lifecycle as
    /// [`ResponseCache::tag_index`].
    url_index: RwLock<HashMap<String, HashSet<String>>>,
    /// Purges and epoch bumps performed (for /stats; the metrics
    /// counter lives in observability).
    purges: AtomicU64,
}

impl Default for ResponseCache {
    fn default() -> Self {
        ResponseCache::new(Arc::new(MokaCache::default()))
    }
}

impl ResponseCache {
    /// Build over a specific backend (tests inject the plain
    /// in-memory store; the OSS gateway uses the moka backend).
    pub fn new(store: Arc<dyn CacheStore>) -> Self {
        ResponseCache {
            store: RwLock::new(store),
            epochs: RwLock::new(HashMap::new()),
            inflight: Arc::new(Mutex::new(HashSet::new())),
            coalescing: Arc::new(Mutex::new(HashMap::new())),
            tag_index: RwLock::new(HashMap::new()),
            url_index: RwLock::new(HashMap::new()),
            purges: AtomicU64::new(0),
        }
    }

    /// Swap the backing store (SCALE-04, #183). Called at startup when
    /// a Redis cache config is present and the license grants the
    /// `redis_cache` feature claim. The old store's entries are NOT
    /// migrated (the new store starts cold; a two-tier `CoordinatedCache`
    /// fronts Redis with the local moka cache so hot keys survive).
    pub fn set_store(&self, store: Arc<dyn CacheStore>) {
        *self.store.write().expect("cache store lock poisoned") = store;
    }

    /// Clone of the backing store Arc (admin/metrics introspection seam).
    pub fn store_handle(&self) -> Arc<dyn CacheStore> {
        Arc::clone(&self.store.read().expect("cache store lock poisoned"))
    }

    /// Approximate live entries (the `dwara_cache_entries` gauge walk;
    /// 0 when the backend cannot report).
    pub fn live_entries(&self) -> i64 {
        self.store
            .read()
            .expect("cache store lock poisoned")
            .entry_count()
            .unwrap_or(0) as i64
    }

    /// Purges + epoch bumps performed since process start.
    pub fn purge_count(&self) -> u64 {
        self.purges.load(Ordering::Relaxed)
    }

    /// The route's current cache epoch (0 for never-bumped routes).
    pub fn epoch(&self, route: &str) -> u64 {
        self.epochs
            .read()
            .expect("cache epoch lock poisoned")
            .get(route)
            .copied()
            .unwrap_or(0)
    }

    /// Advance one route's epoch (admin purge, DW-037). Every entry
    /// stored under an earlier epoch is unreachable from the next
    /// lookup — O(1), no store enumeration, which is the whole point.
    pub fn bump_route(&self, route: &str) -> u64 {
        let mut epochs = self.epochs.write().expect("cache epoch lock poisoned");
        let next = epochs.get(route).copied().unwrap_or(0) + 1;
        epochs.insert(route.to_string(), next);
        self.purges.fetch_add(1, Ordering::Relaxed);
        next
    }

    /// Purge every named route at once (admin purge-all): bumps each
    /// CURRENT route's epoch (routes no longer in the config have no
    /// reachable entries). Returns how many routes were invalidated.
    pub fn purge_all(&self, route_names: impl IntoIterator<Item = String>) -> usize {
        let mut epochs = self.epochs.write().expect("cache epoch lock poisoned");
        let mut bumped = 0;
        for name in route_names {
            let next = epochs.get(&name).copied().unwrap_or(0) + 1;
            epochs.insert(name, next);
            bumped += 1;
        }
        self.purges.fetch_add(1, Ordering::Relaxed);
        bumped
    }

    /// Purge every entry tagged with `tag` (DP-04). The tag's keys are
    /// deleted from the store and the tag's index entry is cleared.
    /// Returns the number of keys the tag mapped to (a tag with no
    /// entries, or one the gateway never saw, returns 0). Unlike the
    /// epoch-based route purge this is an O(keys-with-tag) store
    /// deletion — the tag index is the only place the opaque
    /// `CacheStore` seam exposes which keys carry a tag.
    pub async fn purge_by_tag(&self, tag: &str) -> usize {
        let keys = {
            let mut index = self.tag_index.write().expect("cache tag index poisoned");
            index.remove(tag).unwrap_or_default()
        };
        let n = keys.len();
        for key in &keys {
            let _ = {
                let s = self.store_handle();
                s.delete(key).await
            };
        }
        // Drop the purged keys from the URL index too (lazy cleanup of
        // any dead cross-references the purge just made).
        if !keys.is_empty() {
            let mut url_index = self.url_index.write().expect("cache url index poisoned");
            for set in url_index.values_mut() {
                set.retain(|k| !keys.contains(k));
            }
            url_index.retain(|_, set| !set.is_empty());
        }
        if n > 0 {
            self.purges.fetch_add(1, Ordering::Relaxed);
        }
        n
    }

    /// Purge every entry whose request URL matches (DP-04). With
    /// `prefix` false the URL must match exactly (`path[?query]`); with
    /// `prefix` true every URL whose path starts with `prefix` as a path
    /// segment is purged (e.g. `/api/users/` evicts every user entry;
    /// `/api/users` evicts `/api/users`, `/api/users/123`, and
    /// `/api/users?x=1` but NOT `/api/users2`). Returns the number of
    /// keys deleted. The URL index maps one URL to many keys (the cache
    /// key also folds the route epoch, the consumer, and the vary
    /// values), so a single URL purge can delete several entries.
    pub async fn purge_by_url(&self, url: &str, prefix: bool) -> usize {
        let mut keys: HashSet<String> = HashSet::new();
        {
            let mut index = self.url_index.write().expect("cache url index poisoned");
            if prefix {
                let matching: Vec<String> = index
                    .keys()
                    .filter(|u| url_prefix_match(u, url))
                    .cloned()
                    .collect();
                for u in matching {
                    if let Some(set) = index.remove(&u) {
                        keys.extend(set);
                    }
                }
            } else if let Some(set) = index.remove(url) {
                keys.extend(set);
            }
        }
        let n = keys.len();
        for key in &keys {
            let _ = {
                let s = self.store_handle();
                s.delete(key).await
            };
        }
        // Lazy cleanup of the tag index's now-dead cross-references.
        if !keys.is_empty() {
            let mut tag_index = self.tag_index.write().expect("cache tag index poisoned");
            for set in tag_index.values_mut() {
                set.retain(|k| !keys.contains(k));
            }
            tag_index.retain(|_, set| !set.is_empty());
        }
        if n > 0 {
            self.purges.fetch_add(1, Ordering::Relaxed);
        }
        n
    }

    /// Record a freshly stored entry's tags and request URL in the
    /// purge indexes (DP-04). Called from the store stage after a
    /// successful write. Tags come from the upstream `Cache-Tags`
    /// response header (comma-separated, whitespace-trimmed); the URL
    /// is the request's `path[?query]`. A store that overwrites an
    /// existing key with DIFFERENT tags/URL first removes the key from
    /// its old tag/URL sets (reverse cleanup) so a later purge_by_tag
    /// cannot over-evict via stale tag associations.
    fn record_indexes(&self, key: &str, tags: &[String], url: &str) {
        // Reverse cleanup: remove the key from any old tag/URL sets
        // before recording the new associations. This prevents a
        // re-store with different tags from leaving the key reachable
        // by its old tags (which would cause over-eviction on purge).
        let new_tag_set: HashSet<&str> = tags.iter().map(String::as_str).collect();
        {
            let mut tag_index = self.tag_index.write().expect("cache tag index poisoned");
            for (tag, keys) in tag_index.iter_mut() {
                if !new_tag_set.contains(tag.as_str()) {
                    keys.remove(key);
                }
            }
            tag_index.retain(|_, set| !set.is_empty());
        }
        {
            let mut url_index = self.url_index.write().expect("cache url index poisoned");
            for (old_url, keys) in url_index.iter_mut() {
                if old_url != url {
                    keys.remove(key);
                }
            }
            url_index.retain(|_, set| !set.is_empty());
        }
        // Record the new associations.
        if !tags.is_empty() {
            let mut index = self.tag_index.write().expect("cache tag index poisoned");
            for tag in tags {
                index
                    .entry(tag.clone())
                    .or_default()
                    .insert(key.to_string());
            }
        }
        if !url.is_empty() {
            let mut index = self.url_index.write().expect("cache url index poisoned");
            index
                .entry(url.to_string())
                .or_default()
                .insert(key.to_string());
        }
    }

    /// Generation-change invalidation (called from
    /// [`DataPlane::refresh`] before the swap): a route whose
    /// definition CHANGED (Route equality — masking, transforms, the
    /// cache block itself, anything) has its epoch bumped, because its
    /// stored bytes were shaped by the old definition. Unchanged
    /// routes keep their entries warm; removed routes bump once so a
    /// later same-name re-add cannot inherit them.
    pub fn note_generation(&self, old: Option<&Snapshot>, fresh: &Snapshot) {
        let old_routes: HashMap<&str, &Route> = old
            .map(|s| {
                s.gateway()
                    .routes
                    .iter()
                    .map(|r| (r.name.as_str(), r))
                    .collect()
            })
            .unwrap_or_default();
        let new_names: HashSet<&str> = fresh
            .gateway()
            .routes
            .iter()
            .map(|r| r.name.as_str())
            .collect();
        let mut epochs = self.epochs.write().expect("cache epoch lock poisoned");
        let bump = |name: &str, epochs: &mut HashMap<String, u64>| {
            let next = epochs.get(name).copied().unwrap_or(0) + 1;
            epochs.insert(name.to_string(), next);
        };
        for r in &fresh.gateway().routes {
            match old_routes.get(r.name.as_str()) {
                Some(old_route) if **old_route == *r => {}
                _ => bump(&r.name, &mut epochs),
            }
        }
        for name in old_routes.keys() {
            if !new_names.contains(name) {
                bump(name, &mut epochs);
            }
        }
    }

    /// The lookup half of the cache (DW-037), running after authn/
    /// authz/rate limiting/admission and before the proxy action.
    /// See the module docs for the cacheability rules and the key
    /// derivation; this function only classifies and either replays or
    /// hands a [`MissFlow`] to the store stage.
    #[allow(clippy::too_many_arguments)] // the per-request explicit-inputs rule (see proxy_request)
    pub async fn lookup(
        self: &Arc<Self>,
        dp: &Arc<DataPlane>,
        policy: &Arc<CompiledRouteCache>,
        route: &Route,
        identity: Option<&Identity>,
        peer: IpAddr,
        path: &str,
        query: Option<&str>,
        req_headers: &HeaderMap,
        method: &Method,
        declared_body_bytes: Option<u64>,
        obs: &Observability,
    ) -> LookupOutcome {
        // Request-side gates (each miss of a gate is a BYPASS: stamped,
        // counted, never stored — the deterministic closed set).
        let bypass = |obs: &Observability| {
            obs.record_cache_lookup("bypass");
            LookupOutcome::Bypass
        };
        // DP-04: HEAD is cacheable alongside GET. A HEAD response carries
        // the same headers as GET with no body; the method folds into the
        // key so a HEAD representation (no body) and a GET representation
        // (full body) of one resource are distinct entries (RFC 9111
        // section 4.1). Other methods remain a bypass.
        let is_head = *method == Method::HEAD;
        if !is_head && *method != Method::GET {
            return bypass(obs);
        }
        if req_headers.contains_key(hyper::header::AUTHORIZATION)
            || req_headers.contains_key(hyper::header::COOKIE)
            || req_headers.contains_key(hyper::header::UPGRADE)
        {
            return bypass(obs);
        }
        if declared_body_bytes.is_some_and(|n| n > 0) {
            return bypass(obs);
        }

        let epoch = self.epoch(&route.name);
        let vary_values = capture_vary_values(&policy.vary, req_headers);
        let key = derive_key(
            &route.name,
            epoch,
            identity,
            method,
            path,
            query,
            &vary_values,
        );

        let store = self.store_handle();
        let stored = match store.get(&key).await {
            Ok(Some(bytes)) => match EntryEnvelope::decode(&bytes) {
                Some(entry) if entry.epoch == epoch => Some(entry),
                Some(_) => {
                    // Dead generation (config change or purge raced the
                    // lookup): drop it so it costs no one else a read.
                    let _ = {
                        let s = self.store_handle();
                        s.delete(&key).await
                    };
                    None
                }
                None => {
                    // Undecodable envelope (backend corruption or a
                    // foreign writer): drop, degrade to miss.
                    let _ = {
                        let s = self.store_handle();
                        s.delete(&key).await
                    };
                    None
                }
            },
            Ok(None) => None,
            Err(_) => None, // store failure degrades to a miss, by contract
        };

        // DP-04: HEAD GET-fallback (RFC 9111 section 4.1 allows serving a
        // cached GET representation to a HEAD request — same headers, no
        // body). Only a FRESH GET entry is reused this way: a stale one
        // falls through to the normal miss path so the HEAD response is
        // fetched and stored under its own (HEAD) key rather than
        // overwriting the GET entry with an empty body.
        if is_head && stored.is_none() {
            let get_key = derive_key(
                &route.name,
                epoch,
                identity,
                &Method::GET,
                path,
                query,
                &vary_values,
            );
            if let Ok(Some(bytes)) = {
                let s = self.store_handle();
                s.get(&get_key).await
            } {
                if let Some(entry) = EntryEnvelope::decode(&bytes) {
                    if entry.epoch == epoch {
                        let age_ms = now_ms().saturating_sub(entry.stored_at_ms);
                        let ttl_ms = effective_freshness_ttl_ms(&entry, policy);
                        if age_ms < ttl_ms {
                            if let Some(resp) = serve_head_from_entry(policy, &entry, age_ms, "hit")
                            {
                                obs.record_cache_lookup("hit");
                                return LookupOutcome::Serve(Box::new(resp));
                            }
                        }
                    }
                }
            }
        }

        let mut injected_inm = false;
        if let Some(entry) = &stored {
            let age_ms = now_ms().saturating_sub(entry.stored_at_ms);
            let ttl_ms = effective_freshness_ttl_ms(entry, policy);
            let fresh = age_ms < ttl_ms;
            let stale_ok = policy.stale_while_revalidate.as_millis() as u64 > 0
                && age_ms < ttl_ms + policy.stale_while_revalidate.as_millis() as u64;
            if fresh {
                let resp = if is_head {
                    serve_head_from_entry(policy, entry, age_ms, "hit")
                } else {
                    serve_from_entry(
                        policy,
                        entry,
                        age_ms,
                        req_headers.get(&IF_NONE_MATCH),
                        "hit",
                    )
                };
                if let Some(resp) = resp {
                    obs.record_cache_lookup("hit");
                    return LookupOutcome::Serve(Box::new(resp));
                }
                // An entry that cannot be rebuilt (a header that no
                // longer parses) is a miss, not a failure: drop it.
                let _ = {
                    let s = self.store_handle();
                    s.delete(&key).await
                };
            } else if stale_ok && !is_head {
                if let Some(resp) = serve_from_entry(policy, entry, age_ms, None, "stale") {
                    obs.record_cache_lookup("stale");
                    // Serve stale NOW; refresh in the background (one
                    // revalidation per key — the in-flight guard).
                    self.spawn_revalidate(
                        Arc::clone(dp),
                        &route.name,
                        &key,
                        epoch,
                        policy,
                        path,
                        query,
                        identity,
                        &vary_values,
                        peer,
                        entry,
                    );
                    return LookupOutcome::Serve(Box::new(resp));
                }
                let _ = {
                    let s = self.store_handle();
                    s.delete(&key).await
                };
            } else {
                // Expired past the stale window: fall through as a
                // miss, but keep the entry — its validator makes the
                // forwarded fetch a conditional revalidation the store
                // stage can resolve with a 304, and (DP-04) it backs
                // stale-if-error serving when the upstream errors.
                // Only when WE inject it (the client sent none of its
                // own, and the validator is a header-safe value — an
                // uninjectable one simply never marks the flag, so the
                // client can never be answered a 304 the gateway itself
                // caused).
                injected_inm = !req_headers.contains_key(&IF_NONE_MATCH)
                    && entry
                        .header("etag")
                        .and_then(|b| std::str::from_utf8(b).ok())
                        .is_some_and(|e| HeaderValue::from_str(e).is_ok());
            }
        }

        // Miss: fall through to the proxy action. The caller injects
        // `If-None-Match` from the stored entry when `injected_inm` is
        // set (see `MissFlow::stored_etag`).
        obs.record_cache_lookup("miss");
        LookupOutcome::Miss(Box::new(MissFlow {
            key,
            route_name: route.name.clone(),
            epoch,
            policy: Arc::clone(policy),
            path: path.to_string(),
            query: query.map(str::to_string),
            peer,
            identity: identity.cloned(),
            vary_values,
            stored,
            injected_inm,
            is_head,
        }))
    }

    /// Spawn the background revalidation of a stale-served entry
    /// (stale-while-revalidate, DW-037). One per key at a time, at
    /// most [`MAX_INFLIGHT_REVALIDATIONS`] distinct keys — beyond the
    /// bound the entry stays stale until a request past the window
    /// revalidates synchronously (bounding the refresh burst after a
    /// mass expiry is the point of the cap).
    #[allow(clippy::too_many_arguments)] // the per-request explicit-inputs rule (see proxy_request)
    fn spawn_revalidate(
        self: &Arc<Self>,
        dp: Arc<DataPlane>,
        route_name: &str,
        key: &str,
        epoch: u64,
        policy: &Arc<CompiledRouteCache>,
        path: &str,
        query: Option<&str>,
        identity: Option<&Identity>,
        vary_values: &[(String, String)],
        peer: IpAddr,
        stored: &EntryEnvelope,
    ) {
        {
            let mut inflight = self.inflight.lock().expect("revalidation lock poisoned");
            if inflight.len() >= MAX_INFLIGHT_REVALIDATIONS || !inflight.insert(key.to_string()) {
                return;
            }
        }
        let flow = MissFlow {
            key: key.to_string(),
            route_name: route_name.to_string(),
            epoch,
            policy: Arc::clone(policy),
            path: path.to_string(),
            query: query.map(str::to_string),
            peer,
            identity: identity.cloned(),
            vary_values: vary_values.to_vec(),
            stored: Some(stored.clone()),
            // The synthetic refresh always carries the stored validator
            // (there is no client to honor conditionals for).
            injected_inm: true,
            // Revalidation preserves the original method (a HEAD entry
            // revalidates as HEAD; a GET as GET).
            is_head: false,
        };
        let inflight = Arc::clone(&self.inflight);
        let key = key.to_string();
        let cache = Arc::clone(self);
        tokio::spawn(async move {
            let _guard = InflightGuard {
                set: inflight,
                key: key.clone(),
            };
            cache.run_revalidation(dp, flow).await;
        });
    }

    /// The background refresh: a minimal synthetic GET (vary-relevant
    /// headers + the stored validator) through the full proxy path,
    /// then the SAME masking/transform/store stages a foreground miss
    /// runs. Deliberately NOT rate-limited (the request that triggered
    /// it already paid) and always bounded by the in-flight guard.
    /// Body-bearing, upgrade, and credentialed original requests are
    /// never cacheable, so the shapes that could not be reconstructed
    /// are exactly the shapes that never reach this path.
    async fn run_revalidation(self: Arc<Self>, dp: Arc<DataPlane>, flow: MissFlow) {
        let gen = dp.current();
        let gateway = gen.snapshot.gateway();
        let Some((idx, _params)) = gen.snapshot.route_table().find_full(&flow.path) else {
            return;
        };
        let Some(route) = gateway.routes.get(idx) else {
            return;
        };
        // Config moved under us (route redefined or purged): the epoch
        // check in the store stage would drop the write anyway; skip
        // the upstream call too. Guarded against the OWNING route's
        // epoch (review fix) — the path may now resolve to a different
        // route entirely, and that route's epoch says nothing about
        // this entry's validity.
        if self.epoch(&flow.route_name) != flow.epoch || route.cache.is_none() {
            return;
        }
        let etag = flow
            .stored
            .as_ref()
            .and_then(|e| e.header("etag"))
            .map(|b| String::from_utf8_lossy(b).to_string());
        let mut builder = Request::builder().method(Method::GET).uri(&flow.path);
        if let Some(q) = &flow.query {
            builder = builder.uri(format!("{}?{}", flow.path, q));
        }
        for (name, value) in &flow.vary_values {
            builder = builder.header(name.as_str(), value.as_str());
        }
        if let Some(etag) = etag {
            builder = builder.header(&IF_NONE_MATCH, etag);
        }
        let req = match builder.body(http_body_util::Empty::<Bytes>::new()) {
            Ok(r) => r,
            Err(_) => return,
        };
        let rid = format!("cache-revalidate-{:016x}", now_ms());
        let mut rec = crate::observability::AccessRecord::new(
            rid.clone(),
            "GET".to_string(),
            flow.path.clone(),
            "cache".to_string(),
        );
        let mut no_permit: Option<OwnedSemaphorePermit> = None;
        let mut resp = super::proxy::proxy_request(
            &gen,
            flow.peer,
            req,
            route,
            idx,
            &_params,
            &mut no_permit,
            flow.identity.as_ref(),
            &rid,
            &mut rec,
            &dp.observability_arc(),
            None,
            dp.oauth2_token_cache(),
            &[],
        )
        .await;
        // The foreground store stage expects post-masking/
        // post-transform bytes; apply the same stages here.
        if let Some(masking) = gen.snapshot.route_table().masking(idx) {
            resp = transforms::mask_response_body(
                resp,
                masking,
                flow.identity
                    .as_ref()
                    .map(|i| i.groups.as_slice())
                    .unwrap_or(&[]),
                &route.name,
                flow.identity.as_ref().map(|i| i.consumer_name.as_str()),
                &rid,
            )
            .await;
        }
        if let Some(compiled) = gen.snapshot.route_table().response_body_ops(idx) {
            resp = transforms::transform_response_body(resp, compiled, &rid).await;
        }
        if let Some(ops) = route
            .transforms
            .as_ref()
            .and_then(|t| t.response.as_ref())
            .and_then(|r| r.headers.as_ref())
        {
            transforms::apply_header_ops(resp.headers_mut(), ops);
        }
        // The response is discarded: only the store (and its metrics)
        // matter. X-Cache stamping on it is harmless and consistent.
        let _ = self
            .store_stage(
                CacheFlow::Miss(Box::new(flow)),
                resp,
                &rid,
                dp.observability(),
            )
            .await;
    }

    /// The store half of the cache (DW-037), running after masking and
    /// the DW-028 transforms and before compression. Stamps the
    /// `x-cache` outcome on the response in every arm. See the module
    /// docs for the response-side storable rules.
    pub async fn store_stage(
        &self,
        flow: CacheFlow,
        mut resp: Response<ProxyBody>,
        rid: &str,
        obs: &Observability,
    ) -> Response<ProxyBody> {
        match flow {
            CacheFlow::Bypass => {
                stamp(&mut resp, "bypass");
                resp
            }
            CacheFlow::Miss(flow) => self.finish_miss(*flow, resp, rid, obs).await,
        }
    }

    /// Resolve a cache miss against the fetched response: the 304
    /// revalidation arms first (they consume the stored entry), then
    /// the storable-rule vetoes and the size-capped store.
    async fn finish_miss(
        &self,
        flow: MissFlow,
        mut resp: Response<ProxyBody>,
        rid: &str,
        obs: &Observability,
    ) -> Response<ProxyBody> {
        // 304 revalidation arms (an upstream answering a conditional
        // with Not Modified): the stored body is still current.
        if resp.status() == StatusCode::NOT_MODIFIED {
            if let Some(entry) = flow.stored.as_ref() {
                let upstream_etag = resp
                    .headers()
                    .get(&ETAG)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let stored_etag = entry
                    .header("etag")
                    .map(|b| String::from_utf8_lossy(b).to_string());
                if validators_match(upstream_etag.as_deref(), stored_etag.as_deref()) {
                    // Refresh (same bytes, new clock) under the epoch
                    // we fetched with; a purge/config change since then
                    // silently drops the write.
                    let refreshed = EntryEnvelope {
                        stored_at_ms: now_ms(),
                        ..entry.clone()
                    };
                    if self.epoch(&flow.route_name) == flow.epoch {
                        let ttl = flow.policy.ttl + flow.policy.stale_while_revalidate;
                        let store = self.store_handle();
                        let outcome = match store
                            .set_with_ttl(flow.key.clone(), refreshed.encode(), ttl)
                            .await
                        {
                            Ok(()) => "stored",
                            Err(_) => "error",
                        };
                        obs.record_cache_store(outcome);
                    }
                    obs.record_cache_revalidated();
                    if flow.injected_inm {
                        // WE made the request conditional; the client
                        // sent no validator and MUST NOT receive a bare
                        // 304 (RFC 9111 section 4.3.4) — serve the
                        // stored representation as 200.
                        return match response_from_entry(&refreshed, &flow.policy) {
                            Some(mut out) => {
                                stamp_age(&mut out, 0);
                                stamp(&mut out, "revalidated");
                                out
                            }
                            None => resp,
                        };
                    }
                    // The CLIENT made it conditional: the 304 is its
                    // answer; the cache refreshed underneath.
                    stamp(&mut resp, "revalidated");
                    return resp;
                }
                // Validator drift (the 304 names a different ETag than
                // the stored entry): the stored representation is no
                // longer current — drop it and pass the 304 through.
                let _ = {
                    let s = self.store_handle();
                    s.delete(&flow.key).await
                };
            }
            stamp(&mut resp, "miss");
            return resp;
        }

        // DP-04 stale-if-error (RFC 5861 section 4): an upstream 5xx —
        // which includes the 502 the gateway synthesizes on connection
        // failure — is served from a stale entry when one is on hand
        // and within the entry's `stale-if-error` window. The window is
        // per-entry (the upstream advertised it via Cache-Control at
        // store time); an entry without one (0) does not serve stale on
        // error, and `must-revalidate` zeroes the window at store time
        // (the origin forbade serving stale without revalidation). The
        // error response itself is NEVER stored (it would poison the
        // cache); only a fresh 200 stores below.
        if resp.status().is_server_error() {
            if let Some(entry) = flow.stored.as_ref() {
                let age_ms = now_ms().saturating_sub(entry.stored_at_ms);
                let ttl_ms = effective_freshness_ttl_ms(entry, &flow.policy);
                let sie_ms = entry.stale_if_error_ms;
                if sie_ms > 0 && age_ms < ttl_ms + sie_ms {
                    if let Some(mut stale) = response_from_entry(entry, &flow.policy) {
                        stamp_age(&mut stale, age_ms);
                        stamp(&mut stale, "stale");
                        obs.record_cache_lookup("stale");
                        tracing::info!(
                            code = "cache_stale_if_error",
                            route = %flow.route_name,
                            status = %resp.status().as_u16(),
                            "served stale entry on upstream error (stale-if-error)"
                        );
                        return stale;
                    }
                }
            }
            stamp(&mut resp, "miss");
            return resp;
        }

        // Storable rules: exactly 200, no vetoed header, within the cap.
        if resp.status() != StatusCode::OK {
            stamp(&mut resp, "miss");
            return resp;
        }
        if let Some(_reason) = store_veto(resp.headers(), &flow.policy) {
            obs.record_cache_store("vetoed");
            stamp(&mut resp, "miss");
            return resp;
        }
        let cap = flow.policy.max_body_bytes;
        if resp.body().size_hint().exact().is_some_and(|d| d > cap) {
            obs.record_cache_store("over_cap");
            stamp(&mut resp, "miss");
            return resp;
        }

        // Size-capped buffering — the ONLY buffering this feature ever
        // does, and only on this opted-in path. Over-cap bodies stream
        // on exactly as if no cache existed (prefix + remainder).
        let (mut parts, body) = resp.into_parts();
        match collect_capped(body, cap).await {
            Ok(bytes) => {
                // DP-04: honor the upstream Cache-Control freshness
                // lifetime (s-maxage over max-age, RFC 7234 section
                // 5.2.2.9) and the stale-if-error window (RFC 5861
                // section 4). 0 means "use the configured policy" (the
                // v1 behavior). must-revalidate zeroes stale-if-error
                // (the origin forbade serving stale without
                // revalidation). Cache-Tags (comma-separated) feed the
                // purge-by-tag index.
                let cc = CacheControl::parse(&parts.headers);
                let freshness_ttl_ms = cc.effective_max_age().map(|s| s * 1000).unwrap_or(0);
                let stale_if_error_ms = if cc.must_revalidate {
                    0
                } else {
                    cc.stale_if_error.map(|s| s * 1000).unwrap_or(0)
                };
                let tags = parse_cache_tags(&parts.headers);
                let entry = EntryEnvelope {
                    epoch: flow.epoch,
                    stored_at_ms: now_ms(),
                    status: parts.status.as_u16(),
                    freshness_ttl_ms,
                    stale_if_error_ms,
                    headers: sanitize_headers(&parts.headers, flow.is_head),
                    body: bytes.to_vec(),
                };
                if self.epoch(&flow.route_name) == flow.epoch {
                    // The backend TTL hint is the full usable lifetime
                    // (freshness + SWR + stale-if-error) so the backend
                    // reclaims memory only after the entry is truly
                    // unusable; the envelope's read-side expiry is the
                    // source of truth either way.
                    let eff_ttl_ms = if freshness_ttl_ms > 0 {
                        freshness_ttl_ms
                    } else {
                        flow.policy.ttl.as_millis() as u64
                    };
                    let ttl = Duration::from_millis(
                        eff_ttl_ms
                            + flow.policy.stale_while_revalidate.as_millis() as u64
                            + stale_if_error_ms,
                    );
                    let store = self.store_handle();
                    let outcome = match store
                        .set_with_ttl(flow.key.clone(), entry.encode(), ttl)
                        .await
                    {
                        Ok(()) => "stored",
                        Err(_) => "error",
                    };
                    obs.record_cache_store(outcome);
                    if outcome == "stored" {
                        let url = match &flow.query {
                            Some(q) => format!("{}?{}", flow.path, q),
                            None => flow.path.clone(),
                        };
                        // Note: there is a small best-effort window between
                        // store.set_with_ttl and record_indexes where a
                        // concurrent purge_by_tag/purge_by_url could miss
                        // this just-stored entry (it is in the store but
                        // not yet in the index). The entry will be caught
                        // by the next epoch-based route purge or will
                        // expire via the backend TTL. This is accepted as
                        // a best-effort trade-off: inserting into the
                        // index before the store would risk stale indexes
                        // on store failure, which is worse.
                        self.record_indexes(&flow.key, &tags, &url);
                    }
                }
                if let Ok(v) = HeaderValue::from_str(&bytes.len().to_string()) {
                    parts.headers.insert(hyper::header::CONTENT_LENGTH, v);
                }
                // DP-04: strip internal cache directives from the live
                // response before it reaches the client. The gateway is a
                // shared cache; the upstream's Cache-Control/Expires
                // describe the ORIGIN's freshness policy (not the
                // gateway's), and Cache-Tags is an operator-controlled
                // purge axis that must never leak to end users. These
                // are already stripped from the stored entry by
                // sanitize_headers; the live response must match.
                parts.headers.remove("cache-tags");
                parts.headers.remove(hyper::header::CACHE_CONTROL);
                parts.headers.remove(hyper::header::EXPIRES);
                let mut out = Response::from_parts(parts, ProxyBody::Full(Full::new(bytes)));
                stamp(&mut out, "miss");
                out
            }
            Err(CollectError::OverCap { prefix, rest }) => {
                obs.record_cache_store("over_cap");
                let mut out = Response::from_parts(
                    parts,
                    ProxyBody::Passthrough(PassthroughBody { prefix, rest }),
                );
                stamp(&mut out, "miss");
                out
            }
            Err(CollectError::Stream(err)) => {
                // Mid-body upstream death while buffering: headers have
                // not reached the client, so answer a clean 502 (the
                // DW-028 buffering precedent) instead of a torn stream.
                tracing::warn!(
                    code = "cache_store_failed",
                    request_id = %rid,
                    error = %err,
                    "upstream response failed while buffering for the cache"
                );
                let mut out = Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .header(hyper::header::CONTENT_TYPE, "application/json")
                    .body(ProxyBody::Full(Full::new(
                        crate::observability::envelope_body(
                            "cache_store_failed",
                            "upstream response failed",
                            rid,
                        ),
                    )))
                    .expect("static 502 response is valid");
                stamp(&mut out, "miss");
                out
            }
        }
    }

    /// Request coalescing (DW-038): resolve ONE cache miss into the
    /// leader, a served follower, or an independent fetch. The
    /// coalescing key is the cache key itself (route epoch, consumer,
    /// path, query, vary — see [`derive_key`]), so a follower can only
    /// be handed an outcome computed for an identical request shape of
    /// its own consumer and generation. The caller runs its fetch on
    /// `Lead`/`Solo` and drops the guard when its store stage is done.
    ///
    /// Follower resolution, in the pinned order: (1) wait, bounded by
    /// the route's `coalescing.wait_ms`; (2) epoch check FIRST — a
    /// mid-flight purge/config change detours to an independent fetch
    /// even if the leader stored something; (3) store re-read — a live
    /// entry replays exactly like a hit; (4) otherwise an independent
    /// fetch (leader finished unstored, or the wait expired). Every
    /// fallback is the caller's NORMAL miss path: failures are never
    /// inherited, and each fetching follower runs the route's full
    /// retry policy.
    pub async fn attach(&self, flow: &MissFlow, obs: &Observability) -> CoalesceOutcome {
        let Some(wait) = flow.policy.coalesce_wait else {
            return CoalesceOutcome::Solo;
        };
        // Decide under the lock: follower (a leader slot exists),
        // leader (room in the map), or neither (saturated — fail open,
        // uncounted: this request is neither leader nor follower).
        enum Park {
            Lead(CoalesceLead),
            Follow(Arc<CoalesceSlot>),
            Solo,
        }
        let park = {
            let mut map = self.coalescing.lock().expect("coalescing lock poisoned");
            if let Some(slot) = map.get(&flow.key) {
                Park::Follow(Arc::clone(slot))
            } else if map.len() >= MAX_COALESCING_KEYS {
                Park::Solo
            } else {
                let slot = Arc::new(CoalesceSlot::default());
                map.insert(flow.key.clone(), Arc::clone(&slot));
                Park::Lead(CoalesceLead {
                    map: Arc::clone(&self.coalescing),
                    key: flow.key.clone(),
                    slot,
                })
            }
        };
        match park {
            Park::Lead(lead) => {
                obs.record_coalescing_leader();
                CoalesceOutcome::Lead(lead)
            }
            Park::Solo => CoalesceOutcome::Solo,
            Park::Follow(slot) => {
                // Subscribe to the slot's watch: a leader that already
                // published is visible through the CURRENT value (watch
                // receivers start at the sender's version), so there is
                // no register-before-notify race to close.
                let mut done = slot.done.subscribe();
                obs.coalescing_waiter(true);
                let woke = tokio::time::timeout(wait, async {
                    if !*done.borrow() {
                        // Err = the sender dropped without publishing
                        // (leader died mid-unpublish): treat exactly
                        // like a publication — the store re-read below
                        // decides what, if anything, is shareable.
                        let _ = done.changed().await;
                    }
                })
                .await
                .is_ok();
                obs.coalescing_waiter(false);
                // (1) Epoch first, pinned: a dead generation's answer
                // is never served to a stranded follower.
                if self.epoch(&flow.route_name) != flow.epoch {
                    obs.record_coalescing_follower("fell_back_epoch");
                    return CoalesceOutcome::Solo;
                }
                // (2) The store re-read: the leader's store stage
                // completed before it published (guard Drop order), so
                // a present entry is the leader's outcome — replay it
                // exactly like a hit.
                let store = self.store_handle();
                let stored = match store.get(&flow.key).await {
                    Ok(Some(bytes)) => match EntryEnvelope::decode(&bytes) {
                        Some(entry) if entry.epoch == flow.epoch => Some(entry),
                        _ => None,
                    },
                    Ok(None) | Err(_) => None,
                };
                if let Some(entry) = stored {
                    let age_ms = now_ms().saturating_sub(entry.stored_at_ms);
                    if let Some(resp) = serve_from_entry(&flow.policy, &entry, age_ms, None, "hit")
                    {
                        obs.record_coalescing_follower("served");
                        obs.record_coalescing_saved();
                        return CoalesceOutcome::Served(Box::new(resp));
                    }
                }
                // (3) Nothing shareable: independent fetch. The label
                // distinguishes "waited out the bound" from "the leader
                // finished, just not with something storable".
                obs.record_coalescing_follower(if woke {
                    "fell_back_unshared"
                } else {
                    "fell_back_timeout"
                });
                CoalesceOutcome::Solo
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Request coalescing (DW-038): leader map, publication slot, guard
// ---------------------------------------------------------------------------

/// One coalescing leader's publication point: followers subscribe to
/// the watch; the leader's [`CoalesceLead`] Drop sends `true` (or the
/// sender's own drop wakes them with an error, handled identically by
/// the follower's store re-read).
struct CoalesceSlot {
    done: tokio::sync::watch::Sender<bool>,
}

impl Default for CoalesceSlot {
    fn default() -> Self {
        CoalesceSlot {
            done: tokio::sync::watch::channel(false).0,
        }
    }
}

/// What [`ResponseCache::attach`] decided for one cache miss (DW-038).
pub enum CoalesceOutcome {
    /// This request is the leader: run the fetch, then drop the guard
    /// (explicitly after the store stage, or implicitly on
    /// panic/cancel) to publish to followers.
    Lead(CoalesceLead),
    /// A leader's stored outcome replayed for this follower: serve it
    /// exactly like a lookup `Serve` (the decoration tail still runs;
    /// `x-cache: hit`, `Age` stamped).
    Served(Box<Response<ProxyBody>>),
    /// Coalescing made no claim (disabled, map saturated, or the
    /// follower fell back): run an independent fetch — the caller's
    /// normal miss path, retries and all.
    Solo,
}

/// A leader's hold on one coalescing key (DW-038). Dropping IS the
/// publication: the slot leaves the map, then every parked follower
/// wakes and re-reads the store. The guard pattern (not manual
/// cleanup) so a leader that panics or is cancelled mid-fetch still
/// publishes — its followers wake, find nothing shareable, and fetch
/// on their own.
pub struct CoalesceLead {
    map: Arc<Mutex<HashMap<String, Arc<CoalesceSlot>>>>,
    key: String,
    slot: Arc<CoalesceSlot>,
}

impl Drop for CoalesceLead {
    fn drop(&mut self) {
        self.map
            .lock()
            .expect("coalescing lock poisoned")
            .remove(&self.key);
        // Publish after the unlock: the woken follower's first acts
        // (store re-read, epoch check) take no coalescing lock, and
        // the map lock is never held across an await anywhere.
        let _ = self.slot.done.send(true);
    }
}

/// What a lookup decided (DW-037): replay now, carry a miss to the
/// store stage, or stamp a bypass.
pub enum LookupOutcome {
    /// Fresh (or stale-within-window) entry: the replayed response,
    /// X-Cache/Age/Vary already stamped — the caller runs the
    /// decoration tail on it like any action response. Boxed: the
    /// other arms are pointer-sized and this variant carries a whole
    /// response.
    Serve(Box<Response<ProxyBody>>),
    /// No usable entry: carry to the store stage. The caller may need
    /// to inject the stored validator into the forwarded request (see
    /// `MissFlow::injected_inm`).
    Miss(Box<MissFlow>),
    /// Request shape not cacheable: stamp and count only.
    Bypass,
}

/// The per-request cache state carried from lookup to the store stage.
pub enum CacheFlow {
    /// Route caches, this request does not.
    Bypass,
    /// Cacheable request that fetched from upstream.
    Miss(Box<MissFlow>),
}

/// Everything the store stage and the background revalidation need
/// about one cacheable request (DW-037).
pub struct MissFlow {
    /// Store key (never logged — it hashes the path and query).
    key: String,
    /// The name of the route that owns this entry — the epoch guard
    /// compares against THIS route (review fix): a reload can shift
    /// same-path precedence to a different route mid-revalidation, and
    /// guarding on whatever the path now resolves to would let bytes
    /// shaped by route B land under route A's key.
    route_name: String,
    /// Route epoch at lookup (writes under a different epoch are
    /// dropped by the store stage's re-check).
    epoch: u64,
    /// The compiled route policy the lookup ran under.
    policy: Arc<CompiledRouteCache>,
    /// Inbound path (cache-keyed; the revalidation re-runs the path
    /// rewrite against the current snapshot).
    path: String,
    /// Inbound query, verbatim (part of the key).
    query: Option<String>,
    /// Direct peer (the revalidation's forwarded-header identity).
    peer: IpAddr,
    /// The authenticated identity (None = anonymous): consumer and
    /// groups key the entry and shape the revalidation's masking.
    identity: Option<Identity>,
    /// Captured vary-header values of THIS request (the revalidation
    /// reproduces them so the upstream sees the same variance).
    vary_values: Vec<(String, String)>,
    /// The entry found at lookup past its stale window (None on a cold
    /// miss): backs conditional revalidation and the 304-reuse arm.
    stored: Option<EntryEnvelope>,
    /// Whether the CALLER injected the stored validator into the
    /// forwarded request (a 304 answer must then become a 200 for the
    /// client — RFC 9111 section 4.3.4).
    pub injected_inm: bool,
    /// Whether this is a HEAD request (DP-04): HEAD entries preserve the
    /// upstream Content-Length in the stored headers (the body is empty
    /// but the entity length must be replayed correctly per RFC 9110
    /// section 9.3.2).
    pub is_head: bool,
}

impl MissFlow {
    /// The stored entry's ETag, decoded (the caller injects it as
    /// `If-None-Match` when the client sent none).
    pub fn stored_etag(&self) -> Option<String> {
        self.stored
            .as_ref()
            .and_then(|e| e.header("etag"))
            .map(|b| String::from_utf8_lossy(b).to_string())
    }

    /// The route's coalescing follower wait bound, if the route's
    /// cache block enables request coalescing (DW-038). The proxy path
    /// gates on this before consulting the coalescing map.
    pub fn coalesce_wait(&self) -> Option<std::time::Duration> {
        self.policy.coalesce_wait
    }
}

/// Removes the key from the in-flight set when the revalidation task
/// ends (any exit path — the guard pattern, not manual cleanup).
struct InflightGuard {
    set: Arc<Mutex<HashSet<String>>>,
    key: String,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.set
            .lock()
            .expect("revalidation lock poisoned")
            .remove(&self.key);
    }
}

// ---------------------------------------------------------------------------
// Key derivation and vary capture
// ---------------------------------------------------------------------------

/// Capture the vary-set header values of one request: each configured
/// vary name's values (all lines, wire order) joined with ", " — the
/// exact bytes the key folds.
fn capture_vary_values(vary: &[String], headers: &HeaderMap) -> Vec<(String, String)> {
    vary.iter()
        .map(|name| {
            let joined = headers
                .get_all(name.as_str())
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect::<Vec<_>>()
                .join(", ");
            (name.clone(), joined)
        })
        .collect()
}

/// Derive the store key: a SHA-256 over the domain-tagged components
/// (route, epoch, consumer, method, path, query, vary values). Hashing
/// keeps the key length bounded and keeps raw paths/queries out of the
/// store's memory-visible key space (they are never logged either way).
/// The method component (DP-04) separates a HEAD representation (no
/// body) from a GET representation (full body) of the same resource —
/// they are distinct cache entries per RFC 9111 section 4.1.
pub fn derive_key(
    route: &str,
    epoch: u64,
    identity: Option<&Identity>,
    method: &Method,
    path: &str,
    query: Option<&str>,
    vary_values: &[(String, String)],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"dwara-rc-v1\x00");
    hasher.update(route.as_bytes());
    hasher.update([0]);
    hasher.update(epoch.to_le_bytes());
    hasher.update(method.as_str().as_bytes());
    hasher.update([0]);
    if let Some(id) = identity {
        hasher.update(id.consumer_name.as_bytes());
    }
    hasher.update([0]);
    hasher.update(path.as_bytes());
    hasher.update([0]);
    hasher.update(query.unwrap_or("").as_bytes());
    hasher.update([0]);
    for (name, value) in vary_values {
        hasher.update(name.as_bytes());
        hasher.update([1]);
        hasher.update(value.as_bytes());
        hasher.update([0]);
    }
    format!("rc-{:016x}", hasher.finalize())
}

// ---------------------------------------------------------------------------
// Envelope: the stored entry format
// ---------------------------------------------------------------------------

/// One stored response (the value bytes of the [`CacheStore`]). The
/// layout is a tiny length-prefixed binary frame (no new dependency):
/// magic, schema version, epoch, stored-at, status, header pairs, body.
/// Headers are the DENY-LISTED copy of the response's headers — hop-
/// by-hop and framing names are already gone (stripped on the proxy
/// path); additionally excluded at store time: `Content-Length`
/// (recomputed on replay), `Vary` (re-derived from the live policy),
/// `Age` (recomputed), `Cache-Control`/`Expires` (the gateway owns the
/// entry's freshness — replaying origin directives would mislead
/// clients about a gateway-held entry), `Set-Cookie` (personalized;
/// also a storage veto), and the gateway's own stamps (`X-Cache`,
/// `X-Request-Id`, `X-RateLimit-*`). Everything else round-trips
/// verbatim (ETag, Last-Modified, Date, Content-Type, custom headers).
#[derive(Debug, Clone, PartialEq)]
pub struct EntryEnvelope {
    /// Route cache epoch at store time (the invalidation dimension).
    pub epoch: u64,
    /// Wall-clock ms at store time (the freshness clock origin).
    pub stored_at_ms: u64,
    /// Stored status (200 by the storable rules; carried so widening
    /// the status set later does not change the envelope).
    pub status: u16,
    /// Per-entry freshness lifetime in milliseconds (DP-04). 0 means
    /// "use the configured `ttl_secs`" (the v1 behavior and the
    /// fallback when the upstream sent no `s-maxage`/`max-age`).
    /// Non-zero is the upstream `Cache-Control` lifetime the gateway
    /// honors as a shared cache (RFC 7234 section 5.2.2).
    pub freshness_ttl_ms: u64,
    /// Per-entry `stale-if-error` window in milliseconds (DP-04,
    /// RFC 5861 section 4). 0 means "no stale-on-error serving beyond
    /// the configured stale-while-revalidate window".
    pub stale_if_error_ms: u64,
    /// (name, value) raw byte pairs, wire order.
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    /// Identity (never compressed) body bytes.
    pub body: Vec<u8>,
}

impl EntryEnvelope {
    /// First value of `name` (lowercase), if stored.
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
            .map(|(_, v)| v.as_slice())
    }

    /// Encode into the store's value bytes.
    pub fn encode(&self) -> Vec<u8> {
        fn put_u16(out: &mut Vec<u8>, v: u16) {
            out.extend_from_slice(&v.to_le_bytes());
        }
        fn put_u32(out: &mut Vec<u8>, v: u32) {
            out.extend_from_slice(&v.to_le_bytes());
        }
        fn put_u64(out: &mut Vec<u8>, v: u64) {
            out.extend_from_slice(&v.to_le_bytes());
        }
        fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
            put_u32(out, b.len() as u32);
            out.extend_from_slice(b);
        }
        let mut out = Vec::with_capacity(72 + self.body.len());
        out.extend_from_slice(&ENVELOPE_MAGIC);
        out.push(ENVELOPE_VERSION);
        put_u64(&mut out, self.epoch);
        put_u64(&mut out, self.stored_at_ms);
        put_u16(&mut out, self.status);
        put_u64(&mut out, self.freshness_ttl_ms);
        put_u64(&mut out, self.stale_if_error_ms);
        put_u32(&mut out, self.headers.len() as u32);
        for (name, value) in &self.headers {
            put_bytes(&mut out, name);
            put_bytes(&mut out, value);
        }
        put_u32(&mut out, self.body.len() as u32);
        out.extend_from_slice(&self.body);
        out
    }

    /// Decode store bytes; `None` on any framing/schema mismatch (the
    /// caller treats an undecodable entry as a miss and drops it).
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut cur = bytes;
        fn take<'a>(cur: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
            if cur.len() < n {
                return None;
            }
            let (head, rest) = cur.split_at(n);
            *cur = rest;
            Some(head)
        }
        fn take_u16(cur: &mut &[u8]) -> Option<u16> {
            take(cur, 2).map(|b| u16::from_le_bytes(b.try_into().expect("2 bytes")))
        }
        fn take_u32(cur: &mut &[u8]) -> Option<u32> {
            take(cur, 4).map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")))
        }
        fn take_u64(cur: &mut &[u8]) -> Option<u64> {
            take(cur, 8).map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes")))
        }
        fn take_bytes<'a>(cur: &mut &'a [u8]) -> Option<&'a [u8]> {
            let len = take_u32(cur)? as usize;
            take(cur, len)
        }
        if take(&mut cur, ENVELOPE_MAGIC.len())? != &ENVELOPE_MAGIC[..] {
            return None;
        }
        let version = take(&mut cur, 1)?[0];
        let epoch = take_u64(&mut cur)?;
        let stored_at_ms = take_u64(&mut cur)?;
        let status = take_u16(&mut cur)?;
        // DP-04: v2 carries the per-entry freshness TTL and the
        // stale-if-error window after the status; v1 omits them and
        // they read as 0 (the configured policy applies). A version
        // the gateway does not know is a framing mismatch.
        let (freshness_ttl_ms, stale_if_error_ms) = match version {
            ENVELOPE_VERSION => (take_u64(&mut cur)?, take_u64(&mut cur)?),
            ENVELOPE_VERSION_V1 => (0, 0),
            _ => return None,
        };
        let header_count = take_u32(&mut cur)? as usize;
        // A corrupt header count must not arm a monstrous allocation.
        if header_count.saturating_mul(8) > cur.len() {
            return None;
        }
        let mut headers = Vec::with_capacity(header_count);
        for _ in 0..header_count {
            let name = take_bytes(&mut cur)?.to_vec();
            let value = take_bytes(&mut cur)?.to_vec();
            headers.push((name, value));
        }
        let body = take_bytes(&mut cur)?.to_vec();
        if !cur.is_empty() {
            return None; // trailing bytes = framing mismatch
        }
        Some(EntryEnvelope {
            epoch,
            stored_at_ms,
            status,
            freshness_ttl_ms,
            stale_if_error_ms,
            headers,
            body,
        })
    }
}

/// Header names never stored (see [`EntryEnvelope`]'s docs for the
/// why of each group).
fn is_denied_storage_header(name: &str) -> bool {
    matches!(
        name,
        "content-length"
            | "transfer-encoding"
            | "connection"
            | "keep-alive"
            | "te"
            | "trailer"
            | "upgrade"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "age"
            | "vary"
            | "cache-control"
            | "cache-tags"
            | "expires"
            | "set-cookie"
            | "x-cache"
            | "x-request-id"
            | "x-ratelimit-limit"
            | "x-ratelimit-remaining"
            | "x-ratelimit-reset"
    )
}

/// The deny-listed copy of a response's headers (store side). When
/// `preserve_content_length` is true (HEAD entries, DP-04), the upstream
/// `Content-Length` is kept — the HEAD body is empty but the entity
/// length must be replayed correctly per RFC 9110 section 9.3.2.
fn sanitize_headers(headers: &HeaderMap, preserve_content_length: bool) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if is_denied_storage_header(name_str) {
            // DP-04: HEAD entries keep Content-Length (the entity length
            // a GET would return); GET entries re-derive it from the
            // body at replay time.
            if !(preserve_content_length && name_str.eq_ignore_ascii_case("content-length")) {
                continue;
            }
        }
        out.push((name_str.to_string().into_bytes(), value.as_bytes().to_vec()));
    }
    out
}

/// Parse the upstream `Cache-Tags` response header (DP-04): a comma-
/// separated list of opaque tags the operator can purge by. Whitespace
/// around each tag is trimmed and empty tags are dropped. Multiple
/// `Cache-Tags` headers are folded. Tags are never validated beyond
/// being non-empty trimmed tokens — they are an operator-controlled
/// purge axis, not a client-facing value (the header is stripped before
/// replay by [`is_denied_storage_header`]).
fn parse_cache_tags(headers: &HeaderMap) -> Vec<String> {
    let mut tags = Vec::new();
    for value in headers.get_all("cache-tags") {
        let Ok(s) = value.to_str() else { continue };
        for tag in s.split(',') {
            let tag = tag.trim();
            if !tag.is_empty() {
                tags.push(tag.to_string());
            }
        }
    }
    tags
}

/// Rebuild a response from a stored entry. Also re-derives what the
/// replay must advertise: `Content-Length` from the body and one
/// `Vary` merge per effective-vary token (the decoration tail adds the
/// policy-derived folds — Accept/Origin/Accept-Encoding — exactly as
/// for a live response; `merge_vary` dedupes).
fn response_from_entry(
    entry: &EntryEnvelope,
    policy: &CompiledRouteCache,
) -> Option<Response<ProxyBody>> {
    let mut builder = Response::builder().status(StatusCode::from_u16(entry.status).ok()?);
    // DP-04: HEAD entries preserve the upstream Content-Length in the
    // stored headers (the entity length a GET would return). If present,
    // it is already in the header loop below; skip overwriting it with
    // body.len() (which is 0 for HEAD entries). GET entries do not store
    // Content-Length (sanitize_headers strips it), so body.len() is the
    // correct replay value for them.
    let has_stored_cl = entry
        .headers
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case(b"content-length"));
    for (name, value) in &entry.headers {
        builder = builder.header(
            HeaderName::from_bytes(name).ok()?,
            HeaderValue::from_bytes(value).ok()?,
        );
    }
    let body = Bytes::from(entry.body.clone());
    if !has_stored_cl {
        builder = builder.header(
            hyper::header::CONTENT_LENGTH,
            HeaderValue::from_str(&body.len().to_string()).ok()?,
        );
    }
    let mut resp = builder.body(ProxyBody::Full(Full::new(body))).ok()?;
    for token in &policy.vary {
        merge_vary(resp.headers_mut(), token);
    }
    Some(resp)
}

/// The effective freshness lifetime for one entry (DP-04): the
/// upstream `Cache-Control` lifetime stored on the entry when present
/// (s-maxage over max-age, RFC 7234 section 5.2.2.9), else the
/// configured `ttl_secs` (the operator-owned default, the v1
/// behavior). Returned in milliseconds for direct comparison with
/// `age_ms`.
fn effective_freshness_ttl_ms(entry: &EntryEnvelope, policy: &CompiledRouteCache) -> u64 {
    if entry.freshness_ttl_ms > 0 {
        entry.freshness_ttl_ms
    } else {
        policy.ttl.as_millis() as u64
    }
}

/// Serve a HEAD response from a stored entry (DP-04): the entry's
/// headers with the entity's `Content-Length` (the bytes a GET would
/// return) but an EMPTY body — the HEAD framing (RFC 9110 section
/// 9.3.2). Works for a HEAD entry (empty body, Content-Length 0) and
/// for the GET-fallback (a GET entry's headers + Content-Length, no
/// body). Carries `Age` and the `x-cache` outcome like a GET replay.
fn serve_head_from_entry(
    policy: &CompiledRouteCache,
    entry: &EntryEnvelope,
    age_ms: u64,
    outcome: &str,
) -> Option<Response<ProxyBody>> {
    let mut resp = response_from_entry(entry, policy)?;
    // The body is empty; keep the Content-Length response_from_entry
    // stamped (it reflects the entity length, not the body bytes — the
    // HEAD framing a client uses to learn what a GET would return).
    *resp.body_mut() = ProxyBody::Full(Full::new(Bytes::new()));
    for token in &policy.vary {
        merge_vary(resp.headers_mut(), token);
    }
    stamp_age(&mut resp, age_ms);
    stamp(&mut resp, outcome);
    Some(resp)
}

/// Serve a stored entry: a 304 when the client's `If-None-Match`
/// matches the stored validator (fresh entries only — the caller
/// passes no client conditional on the stale path), else the full
/// stored representation. Both carry `Age` and the `x-cache` outcome.
fn serve_from_entry(
    policy: &CompiledRouteCache,
    entry: &EntryEnvelope,
    age_ms: u64,
    client_inm: Option<&HeaderValue>,
    outcome: &str,
) -> Option<Response<ProxyBody>> {
    if let Some(inm) = client_inm.and_then(|v| v.to_str().ok()) {
        let stored_etag = entry
            .header("etag")
            .map(|b| String::from_utf8_lossy(b).to_string());
        if inm_matches(inm, stored_etag.as_deref()) {
            let mut builder = Response::builder().status(StatusCode::NOT_MODIFIED);
            if let Some(etag) = entry.header("etag") {
                builder = builder.header(&ETAG, String::from_utf8_lossy(etag).to_string());
            }
            if let Some(date) = entry.header("date") {
                if let Ok(v) = HeaderValue::from_bytes(date) {
                    builder = builder.header(hyper::header::DATE, v);
                }
            }
            let mut resp = builder
                .body(ProxyBody::Full(Full::new(Bytes::new())))
                .expect("static 304 response is valid");
            for token in &policy.vary {
                merge_vary(resp.headers_mut(), token);
            }
            stamp_age(&mut resp, age_ms);
            stamp(&mut resp, "hit");
            return Some(resp);
        }
    }
    let mut resp = response_from_entry(entry, policy)?;
    stamp_age(&mut resp, age_ms);
    stamp(&mut resp, outcome);
    Some(resp)
}

/// Whether a client `If-None-Match` value matches a stored validator:
/// `*` matches any; otherwise weak comparison (RFC 9110 section 8.8.3
/// — the W/ prefix is ignored on both sides) over the comma-separated
/// list. A stored entry without a validator never matches.
pub fn inm_matches(inm: &str, etag: Option<&str>) -> bool {
    let Some(etag) = etag else { return false };
    let etag = strip_weak(etag);
    inm.split(',').any(|token| {
        let token = token.trim();
        token == "*" || strip_weak(token) == etag
    })
}

/// Strip the weak-validator prefix (RFC 9110 section 8.8.3: weak
/// comparison ignores `W/` on both sides).
pub fn strip_weak(v: &str) -> &str {
    let trimmed = v.trim();
    trimmed.strip_prefix("W/").unwrap_or(trimmed)
}

/// Whether an upstream 304's validator agrees with the stored one
/// (both absent also agrees — an entity with no validator is trivially
/// unchanged). Weak comparison, like `inm_matches`.
pub fn validators_match(upstream: Option<&str>, stored: Option<&str>) -> bool {
    match (upstream, stored) {
        (None, None) => true,
        (Some(u), Some(s)) => strip_weak(u) == strip_weak(s),
        _ => false,
    }
}

/// Parsed upstream `Cache-Control` directives (RFC 7234 + the
/// `stale-if-error` extension, RFC 5861 section 4). Only the directives
/// the gateway's shared cache acts on are captured; unknown directives
/// are ignored (forward-compat). The parser is hand-rolled (no new
/// dependency) and tolerant: a malformed `delta-seconds` argument is
/// treated as absent rather than failing the whole header, and directive
/// names are matched case-insensitively with optional whitespace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheControl {
    /// `no-store`: the response MUST NOT be stored (a hard storage veto).
    pub no_store: bool,
    /// `no-cache`: store, but revalidate before every reuse (a storage
    /// veto in v1 — the gateway does not yet serve-then-revalidate, so
    /// storing an entry that can never be replayed fresh is dead weight).
    pub no_cache: bool,
    /// `private`: a shared cache MUST NOT store the response (the
    /// gateway's cache is shared — consumer keying does not make it
    /// private, because the operator owns the cache, not the client).
    pub private: bool,
    /// `must-revalidate`: a stale response MUST NOT be served without
    /// revalidation. Recorded but not yet enforced beyond blocking the
    /// stale-while-revalidate serve path (see `lookup`).
    pub must_revalidate: bool,
    /// `s-maxage`: the freshness lifetime for SHARED caches. Takes
    /// precedence over `max-age` for the gateway's shared cache (RFC
    /// 7234 section 5.2.2.9). Absent = fall back to `max_age` then the
    /// configured `ttl_secs`.
    pub s_maxage: Option<u64>,
    /// `max-age`: the freshness lifetime for any cache. Used when
    /// `s-maxage` is absent.
    pub max_age: Option<u64>,
    /// `stale-if-error` (RFC 5861 section 4): the number of seconds PAST
    /// expiry a stale entry may be served when the upstream returns an
    /// error (5xx) or is unreachable. Absent/0 = no stale-on-error
    /// serving beyond the configured stale-while-revalidate window.
    pub stale_if_error: Option<u64>,
}

impl CacheControl {
    /// Parse every `Cache-Control` header value (RFC 7234 section 5.2.2).
    /// Multiple values are folded; a directive appearing more than once
    /// uses the last occurrence's argument (matches common cache
    /// behavior). Returns an empty `CacheControl` when the header is
    /// absent or entirely unparseable — the caller then falls back to
    /// the configured policy.
    pub fn parse(headers: &HeaderMap) -> Self {
        let mut cc = CacheControl::default();
        for value in headers.get_all(hyper::header::CACHE_CONTROL) {
            let Ok(s) = value.to_str() else { continue };
            for directive in s.split(',') {
                let directive = directive.trim();
                if directive.is_empty() {
                    continue;
                }
                let (name, arg) = directive
                    .split_once('=')
                    .map(|(n, v)| (n.trim(), Some(v.trim())))
                    .unwrap_or((directive, None));
                match name.to_ascii_lowercase().as_str() {
                    "no-store" => cc.no_store = true,
                    "no-cache" => cc.no_cache = true,
                    "private" => cc.private = true,
                    "must-revalidate" => cc.must_revalidate = true,
                    "s-maxage" => cc.s_maxage = arg.and_then(parse_delta_seconds),
                    "max-age" => cc.max_age = arg.and_then(parse_delta_seconds),
                    "stale-if-error" => cc.stale_if_error = arg.and_then(parse_delta_seconds),
                    _ => {}
                }
            }
        }
        cc
    }

    /// The effective shared-cache freshness lifetime, in seconds:
    /// `s-maxage` wins over `max-age` (RFC 7234 section 5.2.2.9), else
    /// None (the caller applies the configured `ttl_secs`).
    pub fn effective_max_age(&self) -> Option<u64> {
        self.s_maxage.or(self.max_age)
    }
}

/// Parse an RFC 7234 `delta-seconds` argument: a non-negative integer
/// (the spec allows values larger than 2^31-1, which a 32-bit parser
/// would reject; u64 accepts them and they simply read as "very far in
/// the future"). A non-numeric or empty argument yields None (the
/// directive is treated as absent, not as a parse failure for the
/// whole header).
fn parse_delta_seconds(s: &str) -> Option<u64> {
    s.trim().parse::<u64>().ok()
}

/// Path-segment-aware prefix match for URL purge (DP-04). `url` is the
/// stored request URL (`path[?query]`), `prefix` is the purge prefix.
/// Matches when: the stored URL equals the prefix, or the stored URL
/// starts with the prefix AND either the prefix ends with `/` (already
/// a full path segment) or the character after the prefix is a path
/// separator (`/` or `?`) — preventing `/api/users` from matching
/// `/api/users2` while allowing `/api/users/` to match `/api/users/alice`.
fn url_prefix_match(url: &str, prefix: &str) -> bool {
    if url == prefix {
        return true;
    }
    if !url.starts_with(prefix) {
        return false;
    }
    // A prefix ending with `/` is already segment-complete; any
    // continuation matches. Otherwise the next character must be a
    // path/query boundary so `/api/users` does not match `/api/users2`.
    prefix.ends_with('/') || {
        let after = &url[prefix.len()..];
        after.starts_with('/') || after.starts_with('?')
    }
}

/// The response-side storable rules (see the module docs). Returns the
/// veto reason code for logging/telemetry when storage is forbidden.
pub fn store_veto(headers: &HeaderMap, policy: &CompiledRouteCache) -> Option<&'static str> {
    if headers.contains_key(hyper::header::SET_COOKIE) {
        return Some("set_cookie");
    }
    let cc = CacheControl::parse(headers);
    if cc.no_store || cc.private || cc.no_cache {
        return Some("cache_control");
    }
    // DP-04: s-maxage=0 or max-age=0 means "immediately stale" — the
    // origin requires revalidation on every use. This engine does not
    // yet support revalidate-on-every-use, so a zero freshness lifetime
    // is a storage veto (the response would be stored but never served
    // fresh, which is pointless and wastes capacity).
    if cc.effective_max_age() == Some(0) {
        return Some("cache_control");
    }
    if headers.contains_key(hyper::header::CONTENT_ENCODING) {
        return Some("content_encoding");
    }
    for value in headers.get_all(hyper::header::VARY) {
        let Ok(v) = value.to_str() else {
            return Some("vary");
        };
        for token in v.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if token == "*" {
                return Some("vary_star");
            }
            if !policy
                .vary
                .iter()
                .any(|name| name.eq_ignore_ascii_case(token))
            {
                return Some("vary_uncovered");
            }
        }
    }
    None
}

fn stamp(resp: &mut Response<ProxyBody>, outcome: &str) {
    if let Ok(v) = HeaderValue::from_str(outcome) {
        resp.headers_mut().insert(&X_CACHE, v);
    }
}

fn stamp_age(resp: &mut Response<ProxyBody>, age_ms: u64) {
    if let Ok(v) = HeaderValue::from_str(&(age_ms / 1000).to_string()) {
        resp.headers_mut().insert(hyper::header::AGE, v);
    }
}

// ---------------------------------------------------------------------------
// Size-capped response collection (the zero-buffering edge)
// ---------------------------------------------------------------------------

/// Why a capped collection stopped early.
enum CollectError {
    /// The body crossed the cap mid-stream: the buffered prefix plus
    /// the untouched remainder must still reach the client.
    OverCap {
        prefix: Bytes,
        rest: Pin<Box<ProxyBody>>,
    },
    /// The stream errored mid-body (headers not yet sent: the caller
    /// answers a clean 502 envelope).
    Stream(String),
}

/// Buffer a response body up to `cap` bytes — the ONLY buffering of
/// response bodies the cache ever performs, on the opted-in store path
/// only. Trailers are dropped (they described the streamed body; the
/// DW-028 transform collector made the same call for the same reason).
async fn collect_capped(body: ProxyBody, cap: u64) -> Result<Bytes, CollectError> {
    let mut body = Box::pin(body);
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match body.as_mut().frame().await {
            Some(Ok(frame)) => {
                let Ok(data) = frame.into_data() else {
                    continue; // trailer: dropped
                };
                if buf.len() as u64 + data.len() as u64 > cap {
                    buf.extend_from_slice(&data);
                    return Err(CollectError::OverCap {
                        prefix: Bytes::from(buf),
                        rest: body,
                    });
                }
                buf.extend_from_slice(&data);
            }
            Some(Err(err)) => return Err(CollectError::Stream(err.to_string())),
            None => return Ok(Bytes::from(buf)),
        }
    }
}

/// A body that replays a buffered prefix and then continues the
/// original stream byte-for-byte (the over-cap passthrough arm — the
/// response reaches the client exactly as if no cache existed).
pub struct PassthroughBody {
    prefix: Bytes,
    rest: Pin<Box<ProxyBody>>,
}

impl hyper::body::Body for PassthroughBody {
    type Data = Bytes;
    type Error = super::proxy::ProxyBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            return Poll::Ready(Some(Ok(hyper::body::Frame::data(std::mem::take(
                &mut this.prefix,
            )))));
        }
        this.rest.as_mut().poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.prefix.is_empty() && self.rest.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        if self.prefix.is_empty() {
            self.rest.size_hint()
        } else {
            hyper::body::SizeHint::default()
        }
    }
}
