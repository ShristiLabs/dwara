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
//! PROXY action; the method is GET (HEAD is bypassed in v1 — replaying
//! a GET body under HEAD's no-body framing needs separate machinery);
//! the request carries no body, no `Authorization`, no `Cookie`
//! (credentials make per-consumer keying insufficient — two bearer
//! tokens of one consumer would share an entry), and no `Upgrade`.
//! Everything else is a BYPASS (stamped and counted, never stored).
//!
//! A RESPONSE is storable when: status is exactly 200; it carries no
//! `Set-Cookie`; its `Cache-Control` has none of `no-store` /
//! `private` / `no-cache` (the only upstream freshness directives
//! honored — the configured `ttl_secs` is the freshness lifetime, the
//! operator owns it); it is not content-encoded (dwara compresses on
//! replay; an upstream-encoded body cannot be re-negotiated); and its
//! `Vary` is `*`-free and a subset of the route's effective vary set
//! (see `config::cache` for the configured + policy-derived variance
//! model — the key must be derivable from the request alone, so an
//! unknown variance dimension forbids storage).
//!
//! ## Keys
//!
//! `sha256("dwara-rc-v1" | route | epoch | consumer | path | query |
//! vary-name=value...)` — hex-encoded. The consumer component means
//! masked (DW-029) and consumer-group variants can never cross
//! consumers. Keys are never logged (paths and query strings carry
//! tokens; the hash is opaque anyway).
//!
//! ## Freshness, stale-while-revalidate, ETag
//!
//! Fresh for `ttl_secs`; within `stale_while_revalidate_secs` after
//! expiry the entry is served stale (`x-cache: stale`) while ONE
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
const ENVELOPE_VERSION: u8 = 1;

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
    store: Arc<dyn CacheStore>,
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
            store,
            epochs: RwLock::new(HashMap::new()),
            inflight: Arc::new(Mutex::new(HashSet::new())),
            coalescing: Arc::new(Mutex::new(HashMap::new())),
            purges: AtomicU64::new(0),
        }
    }

    /// The backing store (admin/metrics introspection seam).
    pub fn store(&self) -> &Arc<dyn CacheStore> {
        &self.store
    }

    /// Approximate live entries (the `dwara_cache_entries` gauge walk;
    /// 0 when the backend cannot report).
    pub fn live_entries(&self) -> i64 {
        self.store.entry_count().unwrap_or(0) as i64
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
        if method != Method::GET {
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
        let key = derive_key(&route.name, epoch, identity, path, query, &vary_values);

        let stored = match self.store.get(&key).await {
            Ok(Some(bytes)) => match EntryEnvelope::decode(&bytes) {
                Some(entry) if entry.epoch == epoch => Some(entry),
                Some(_) => {
                    // Dead generation (config change or purge raced the
                    // lookup): drop it so it costs no one else a read.
                    let _ = self.store.delete(&key).await;
                    None
                }
                None => {
                    // Undecodable envelope (backend corruption or a
                    // foreign writer): drop, degrade to miss.
                    let _ = self.store.delete(&key).await;
                    None
                }
            },
            Ok(None) => None,
            Err(_) => None, // store failure degrades to a miss, by contract
        };

        let mut injected_inm = false;
        if let Some(entry) = &stored {
            let age_ms = now_ms().saturating_sub(entry.stored_at_ms);
            let fresh = age_ms < policy.ttl.as_millis() as u64;
            let stale_ok = policy.stale_while_revalidate.as_millis() as u64 > 0
                && age_ms < (policy.ttl + policy.stale_while_revalidate).as_millis() as u64;
            if fresh {
                if let Some(resp) = serve_from_entry(
                    policy,
                    entry,
                    age_ms,
                    req_headers.get(&IF_NONE_MATCH),
                    "hit",
                ) {
                    obs.record_cache_lookup("hit");
                    return LookupOutcome::Serve(Box::new(resp));
                }
                // An entry that cannot be rebuilt (a header that no
                // longer parses) is a miss, not a failure: drop it.
                let _ = self.store.delete(&key).await;
            } else if stale_ok {
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
                let _ = self.store.delete(&key).await;
            } else {
                // Expired past the stale window: fall through as a
                // miss, but keep the entry — its validator makes the
                // forwarded fetch a conditional revalidation the store
                // stage can resolve with a 304. Only when WE inject it
                // (the client sent none of its own, and the validator
                // is a header-safe value — an uninjectable one simply
                // never marks the flag, so the client can never be
                // answered a 304 the gateway itself caused).
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
            dp.observability(),
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
                        let outcome = match self
                            .store
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
                let _ = self.store.delete(&flow.key).await;
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
                let entry = EntryEnvelope {
                    epoch: flow.epoch,
                    stored_at_ms: now_ms(),
                    status: parts.status.as_u16(),
                    headers: sanitize_headers(&parts.headers),
                    body: bytes.to_vec(),
                };
                if self.epoch(&flow.route_name) == flow.epoch {
                    let ttl = flow.policy.ttl + flow.policy.stale_while_revalidate;
                    let outcome = match self
                        .store
                        .set_with_ttl(flow.key.clone(), entry.encode(), ttl)
                        .await
                    {
                        Ok(()) => "stored",
                        Err(_) => "error",
                    };
                    obs.record_cache_store(outcome);
                }
                if let Ok(v) = HeaderValue::from_str(&bytes.len().to_string()) {
                    parts.headers.insert(hyper::header::CONTENT_LENGTH, v);
                }
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
                let stored = match self.store.get(&flow.key).await {
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
/// (route, epoch, consumer, path, query, vary values). Hashing keeps
/// the key length bounded and keeps raw paths/queries out of the
/// store's memory-visible key space (they are never logged either way).
pub fn derive_key(
    route: &str,
    epoch: u64,
    identity: Option<&Identity>,
    path: &str,
    query: Option<&str>,
    vary_values: &[(String, String)],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"dwara-rc-v1\x00");
    hasher.update(route.as_bytes());
    hasher.update([0]);
    hasher.update(epoch.to_le_bytes());
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
        let mut out = Vec::with_capacity(64 + self.body.len());
        out.extend_from_slice(&ENVELOPE_MAGIC);
        out.push(ENVELOPE_VERSION);
        put_u64(&mut out, self.epoch);
        put_u64(&mut out, self.stored_at_ms);
        put_u16(&mut out, self.status);
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
        if take(&mut cur, 1)? != [ENVELOPE_VERSION] {
            return None;
        }
        let epoch = take_u64(&mut cur)?;
        let stored_at_ms = take_u64(&mut cur)?;
        let status = take_u16(&mut cur)?;
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
            | "expires"
            | "set-cookie"
            | "x-cache"
            | "x-request-id"
            | "x-ratelimit-limit"
            | "x-ratelimit-remaining"
            | "x-ratelimit-reset"
    )
}

/// The deny-listed copy of a response's headers (store side).
fn sanitize_headers(headers: &HeaderMap) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for (name, value) in headers.iter() {
        if is_denied_storage_header(name.as_str()) {
            continue;
        }
        out.push((
            name.as_str().to_string().into_bytes(),
            value.as_bytes().to_vec(),
        ));
    }
    out
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
    for (name, value) in &entry.headers {
        builder = builder.header(
            HeaderName::from_bytes(name).ok()?,
            HeaderValue::from_bytes(value).ok()?,
        );
    }
    let body = Bytes::from(entry.body.clone());
    builder = builder.header(
        hyper::header::CONTENT_LENGTH,
        HeaderValue::from_str(&body.len().to_string()).ok()?,
    );
    let mut resp = builder.body(ProxyBody::Full(Full::new(body))).ok()?;
    for token in &policy.vary {
        merge_vary(resp.headers_mut(), token);
    }
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

/// The response-side storable rules (see the module docs). Returns the
/// veto reason code for logging/telemetry when storage is forbidden.
pub fn store_veto(headers: &HeaderMap, policy: &CompiledRouteCache) -> Option<&'static str> {
    if headers.contains_key(hyper::header::SET_COOKIE) {
        return Some("set_cookie");
    }
    if let Some(cc) = headers
        .get(hyper::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
    {
        if cc.split(',').any(|d| {
            let d = d
                .trim()
                .split(';')
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            d == "no-store" || d == "private" || d == "no-cache"
        }) {
            return Some("cache_control");
        }
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
