//! Rate limiting extension point.
//!
//! # Contract: [`RateLimiter`]
//!
//! **Purpose:** decide, per caller-supplied key (consumer id, IP, route, or
//! a composite), whether a request costing `cost` units may proceed.
//!
//! **Semantics:** `check` is the hot path — it MUST be non-blocking from the
//! caller's perspective (in-flight for at most the backend round-trip) and
//! MUST be atomic: concurrent `check` calls for the same key are linearized
//! by the implementation. Ordering across distinct keys is unspecified.
//! `check` both decides AND reserves: if it returns `allowed: true` the cost
//! has already been deducted from the key's budget; callers must not call
//! again to "commit". There is no separate refund in M1.
//!
//! **Failure model:** returns [`ExtensionsError`]; a limiter that cannot
//! reach its backend should report [`ExtensionsError::Backend`]. Callers are
//! expected to apply their own fail-open/fail-closed policy — the trait does
//! not prescribe one. No retries are built in.
//!
//! **Editions:** OSS ships [`InMemoryRateLimiter`] (fixed window, kept for
//! reference) and [`GcraRateLimiter`] (DW-017: the real sharded GCRA
//! limiter behind this same trait). Additional distributed limiter
//! backends may be provided separately in future editions.
//!
//! # DW-017: GCRA limiter and policy engine
//!
//! [`GcraRateLimiter`] implements the [`RateLimiter`] trait with the
//! `governor` crate's GCRA cells over a sharded keyed state store
//! (`GcraShardStore`: fixed-count shard-locked maps per window, no
//! global mutex; contrast [`InMemoryRateLimiter`]'s single
//! `Mutex<HashMap>`, which is why it stayed a skeleton). A limiter may
//! STACK several windows (e.g. 10 r/s AND 100 r/hour): each window is
//! an independent GCRA cell per key and the decision is the AND of all
//! windows — denied if ANY window denies, `retry_after` from the
//! denying (binding) window.
//!
//! **Stacking consumption semantics (documented trade-off):** windows are
//! evaluated shortest-first and evaluation STOPS at the first denial, so
//! windows before the binding one have already consumed their cell. A
//! request denied by the hourly window still spends one second-window
//! token. This is fail-fast and slightly STRICTER than a fully-atomic
//! all-windows decision (governor's public API has no non-consuming
//! peek), never more permissive, and the waste is bounded to the
//! short-window bucket (which also replenishes fastest).
//!
//! **Multi-rule denial semantics:** when several RULES apply (route- and
//! service-attached policies), a denial in one rule does not stop
//! evaluation of the others — every applicable rule's state advances and
//! the reported `Retry-After` is the MAXIMUM wait across all denying
//! rules, while the Limit/Remaining headers come from the first (binding)
//! denying rule. Headers thus show the tightest constraint in resolution
//! order; Retry-After is the longest wait, so a compliant client never
//! retries into a second 429 early. This max-wait rule is across RULES;
//! the stricter-not-looser stop-at-first-denial semantics above stay,
//! per limiter, for WINDOWS stacked within one rule.
//!
//! **Dry-run bundles (DW-041):** a policy bundle may set `dry_run` —
//! its rules still evaluate (buckets advance exactly as if enforcing,
//! so denial rates preview enforcement) but its denials are reported to
//! the caller ([`RateLimitEngine::evaluate`]'s `dry_denied`]) instead of
//! enforced, and its allowed outcomes contribute no `X-RateLimit-*`
//! headers. LIVE bundles attached to the same request enforce
//! unaffected: monitor mode observes without ever making enforcement
//! more permissive. Extensions may not import observability, so the
//! log/metric side of the report lives on the dataplane caller.
//!
//! **Per-key eviction (#122):** every window's keyed GCRA state lives in
//! a `GcraShardStore` — [`GCRA_STORE_SHARDS`] independent lock-guarded
//! maps replacing governor's unbounded `DashMapStateStore` (whose key
//! set a reload can only reset wholesale). Each shard holds at most
//! [`crate::config::limits::MAX_RATE_LIMITER_KEYS_PER_SHARD`] keys, so a
//! window's worst case is `GCRA_STORE_SHARDS` times that cap — an
//! `[ip]`-selector limiter under key spray is memory-bounded for the
//! process lifetime. The sweep runs INLINE, on the shard lock a
//! reservation already holds (cascade-on-insert; no background task, no
//! O(cap) work per request): when a shard reaches its cap it first
//! drops IDLE cells — keys untouched for at least the window's
//! full-refill time, whose GCRA state is indistinguishable from a fresh
//! cell, so dropping them cannot change any decision — and if the shard
//! is still crowded (every key fresh — sustained spray) it evicts the
//! idlest half, ordered by `(last_touch_ms, key)`, down to half the cap
//! so the O(cap) sweep amortizes to O(1) per insertion. Idle-first
//! ordering means a key actively under enforcement (denied, hence
//! freshly touched) is evicted only when the shard holds more than a
//! cap-full of keys ALL touched within one full-refill window; losing a
//! cell then merely resets that key's bucket (a fresh bucket can only
//! be MORE permissive for that key, never stricter for anyone) — the
//! documented fail-open trade under spray. `GcraRateLimiter::evictions`
//! exposes the dropped-cell count as a monotonic counter in the
//! balancer's fail-open-picks style; extensions may not import
//! observability, so no metric family is wired here (a future gauge can
//! scrape it from the dataplane).
//!
//! **Legacy field mapping:** a policy's old `rate_limit
//! {requests, window_seconds}` compiles to one rule with selector
//! `[route]` and a single window of `requests` per `window_seconds`
//! (burst = requests). Both fields may be set; both apply.
//!
//! **Burst vs sustained:** a window of `requests_per.s = 10` with
//! `burst: 20` is a GCRA quota replenishing 1 token per 1/10 s with a
//! 20-token bucket: 20 rapid requests pass (burst), sustained traffic
//! above 10 r/s starts drawing 429s once the bucket empties. `burst`
//! defaults to the window's request count; under GCRA the first window
//! can admit up to `burst + replenished` cells (documented, standard
//! GCRA shape).

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::num::NonZeroU32;
use std::time::{Duration, Instant};
// DW-025 (#122): under the `loom` feature the shard mutexes and the
// eviction counter swap for loom's model-checked equivalents so the
// shard reservation path (lock -> read TAT -> decide -> write TAT) can
// be exhaustively explored; builds are bit-identical otherwise.
#[cfg(feature = "loom")]
use loom::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "loom")]
use loom::sync::Mutex;
#[cfg(not(feature = "loom"))]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(not(feature = "loom"))]
use std::sync::{Arc, Mutex};
// Arc stays std even under loom (the health.rs precedent): it is a
// container, not a synchronization primitive.
#[cfg(feature = "loom")]
use std::sync::Arc;

use async_trait::async_trait;
use governor::clock::Clock as _;
use governor::clock::{DefaultClock, QuantaInstant};
use governor::middleware::{NoOpMiddleware, StateInformationMiddleware};
use governor::nanos::Nanos;
use governor::state::keyed::ShrinkableKeyedStateStore;
use governor::state::{RateLimiter as GovernorLimiter, StateStore};
use governor::Quota;

use super::ExtensionsError;

/// Outcome of a [`RateLimiter::check`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateDecision {
    /// Whether the request is allowed (cost already reserved if true).
    pub allowed: bool,
    /// Units remaining for the key after this decision.
    pub remaining: u64,
    /// When allowed is false: milliseconds until the window resets and the
    /// caller may retry. `None` when allowed. This is the window remainder,
    /// not a success promise: a retry may still be denied when the request's
    /// cost exceeds the key's limit.
    pub retry_after_ms: Option<u64>,
}

/// Swappable rate-limit backend.
#[async_trait]
pub trait RateLimiter: Send + Sync {
    /// Atomically decide-and-reserve `cost` units for `key`.
    async fn check(&self, key: &str, cost: u32) -> Result<RateDecision, ExtensionsError>;
}

#[derive(Debug)]
struct WindowState {
    window_start_ms: u128,
    used: u64,
}

/// In-memory fixed-window limiter (OSS skeleton).
///
/// DW-017 superseded this skeleton with [`GcraRateLimiter`] (sharded,
/// stacked-window GCRA behind the same trait); it is kept as the simple
/// fixed-window reference implementation and trait-existence proof.
#[derive(Debug)]
pub struct InMemoryRateLimiter {
    limit: u64,
    window_ms: u128,
    now_ms: fn() -> u128,
    windows: Mutex<HashMap<String, WindowState>>,
}

impl InMemoryRateLimiter {
    /// New limiter allowing `limit` units per `window_ms` per key.
    pub fn new(limit: u64, window_ms: u64) -> Self {
        Self {
            limit,
            window_ms: window_ms as u128,
            now_ms: || {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis())
                    .unwrap_or(0)
            },
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// New limiter using a caller-supplied millisecond clock.
    ///
    /// Intended for tests and other time-controlled setups; production code
    /// should prefer [`InMemoryRateLimiter::new`], which uses the system
    /// clock. `now_ms` must return Unix-epoch milliseconds and must be cheap
    /// to call (it runs on every `check`).
    pub fn with_clock(limit: u64, window_ms: u64, now_ms: fn() -> u128) -> Self {
        Self {
            limit,
            window_ms: window_ms as u128,
            now_ms,
            windows: Mutex::new(HashMap::new()),
        }
    }

    fn now(&self) -> u128 {
        (self.now_ms)()
    }
}

#[async_trait]
impl RateLimiter for InMemoryRateLimiter {
    async fn check(&self, key: &str, cost: u32) -> Result<RateDecision, ExtensionsError> {
        let cost = u64::from(cost);
        let mut windows = self.windows.lock().expect("rate limiter state poisoned");
        let now = self.now();
        let state = match windows.get_mut(key) {
            Some(state) => state,
            None => windows.entry(key.to_owned()).or_insert(WindowState {
                window_start_ms: now,
                used: 0,
            }),
        };
        if now.saturating_sub(state.window_start_ms) >= self.window_ms {
            state.window_start_ms = now;
            state.used = 0;
        }
        if state.used + cost <= self.limit {
            state.used += cost;
            Ok(RateDecision {
                allowed: true,
                remaining: self.limit - state.used,
                retry_after_ms: None,
            })
        } else {
            Ok(RateDecision {
                allowed: false,
                remaining: self.limit - state.used,
                retry_after_ms: Some(
                    u64::try_from(self.window_ms - now.saturating_sub(state.window_start_ms))
                        .unwrap_or(0),
                ),
            })
        }
    }
}

/// Number of independent shard locks in a `GcraShardStore`. Fixed (not
/// CPU-count-derived) so the worst-case key bound per window
/// (`GCRA_STORE_SHARDS * MAX_RATE_LIMITER_KEYS_PER_SHARD`) is the same
/// number on every machine. Public for the eviction tests' bound
/// assertions.
pub const GCRA_STORE_SHARDS: usize = 16;

/// Per-key GCRA cell: governor's theoretical arrival time in nanoseconds
/// since the limiter was created (`0` = fresh/absent, mirroring
/// governor's `NonZeroU64` encoding) plus the last-touch stamp the
/// eviction sweep orders by. The stamp comes from the store's
/// bookkeeping clock, NOT governor's GCRA clock.
#[derive(Debug, Default, Clone, Copy)]
struct GcraCell {
    tat: u64,
    last_touch_ms: u64,
}

/// One shard's keyed cells (a plain map; the shard mutex provides the
/// atomicity governor's `measure_and_replace` contract requires).
#[derive(Debug, Default)]
struct ShardCells {
    cells: HashMap<String, GcraCell>,
}

/// Clock for eviction bookkeeping only — governor keeps its own
/// monotonic clock for the GCRA math (see `GcraRateLimiter::with_clock`).
#[derive(Debug, Clone, Copy)]
enum StoreClock {
    /// Milliseconds elapsed since store creation (production default).
    Monotonic(Instant),
    /// Caller-supplied millisecond source (deterministic tests).
    Injected(fn() -> u64),
}

impl StoreClock {
    fn now_ms(&self) -> u64 {
        match *self {
            StoreClock::Monotonic(start) => start.elapsed().as_millis() as u64,
            StoreClock::Injected(now_ms) => now_ms(),
        }
    }
}

/// Sharded keyed state store for one GCRA window (#122).
///
/// Implements governor's [`StateStore`] so the limiter keeps governor's
/// GCRA decision math (`measure_and_replace` receives the closure and
/// must atomically apply its new state — or leave the old state in place
/// when it returns `Err`, i.e. on a denial). Unlike governor's
/// `DashMapStateStore`, whose key set grows for the process lifetime,
/// each shard is size-capped at
/// [`crate::config::limits::MAX_RATE_LIMITER_KEYS_PER_SHARD`] keys with
/// an inline idle-first eviction sweep (see the module docs for the
/// policy and its fail-open trade).
struct GcraShardStore {
    shards: Vec<Mutex<ShardCells>>,
    hasher: RandomState,
    clock: StoreClock,
    /// A key untouched for at least this long is indistinguishable from
    /// a fresh cell and may be dropped by the sweep's idle pass.
    max_idle_ms: u64,
    /// Dropped-cell count, shared with the owning window (monotonic;
    /// scrape-ready in the fail-open-picks style).
    evictions: Arc<AtomicU64>,
}

impl GcraShardStore {
    fn new(max_idle_ms: u64, clock: StoreClock, evictions: Arc<AtomicU64>) -> Self {
        Self {
            shards: (0..GCRA_STORE_SHARDS)
                .map(|_| Mutex::new(ShardCells::default()))
                .collect(),
            hasher: RandomState::new(),
            clock,
            max_idle_ms,
            evictions,
        }
    }

    fn shard_for(&self, key: &str) -> &Mutex<ShardCells> {
        &self.shards[(self.hasher.hash_one(key) as usize) & (GCRA_STORE_SHARDS - 1)]
    }

    /// Inline cascade-on-insert sweep (see module docs): runs when the
    /// shard REACHES its cap — before the requesting key's own insert,
    /// so a shard never exceeds the cap, even transiently — first
    /// dropping idle cells, then, if every key is fresh, the idlest half
    /// by `(last_touch_ms, key)` order down to half the cap, which
    /// amortizes the O(cap) scan to O(1) per insertion. Deterministic:
    /// the victim order is a total order. Must be called with the shard
    /// already locked, BEFORE the current key's cell is touched, so the
    /// sweep orders by pre-request stamps: a cell dropped by the idle
    /// pass is decision-identical to a fresh cell (its TAT lies in the
    /// past), and the size pass's cap-full-of-fresh-keys trade is the
    /// documented one.
    fn sweep_if_crowded(&self, shard: &mut ShardCells, now_ms: u64) {
        let cap = crate::config::limits::MAX_RATE_LIMITER_KEYS_PER_SHARD;
        if shard.cells.len() < cap {
            return;
        }
        // Idle pass: cells untouched for at least one full refill are
        // fresh-equivalent; dropping them is unobservable through
        // decisions (the millisecond rounding keeps a cell at most ~1ms
        // past its refill before it becomes droppable).
        let before = shard.cells.len();
        shard
            .cells
            .retain(|_, cell| now_ms.saturating_sub(cell.last_touch_ms) < self.max_idle_ms);
        let mut dropped = (before - shard.cells.len()) as u64;
        // Size pass: still at/over the cap — every remaining key is
        // fresh. Evict the idlest half down to the low-water mark.
        if shard.cells.len() >= cap {
            let excess = shard.cells.len() - cap / 2;
            let mut victims: Vec<(u64, String)> = shard
                .cells
                .iter()
                .map(|(key, cell)| (cell.last_touch_ms, key.clone()))
                .collect();
            victims.sort_unstable();
            for (_, key) in victims.into_iter().take(excess) {
                shard.cells.remove(&key);
            }
            dropped += excess as u64;
        }
        if dropped > 0 {
            self.evictions.fetch_add(dropped, Ordering::Relaxed);
        }
    }
}

/// The reservation critical section: one shard lock covers the
/// read-decide-write of the TAT, linearizing concurrent checks for the
/// same key (and any keys sharing its shard).
impl StateStore for GcraShardStore {
    type Key = String;

    fn measure_and_replace<T, F, E>(&self, key: &String, f: F) -> Result<T, E>
    where
        F: Fn(Option<Nanos>) -> Result<(T, Nanos), E>,
    {
        let now_ms = self.clock.now_ms();
        let shard = self.shard_for(key);
        let mut guard = shard.lock().expect("rate limiter shard poisoned");
        self.sweep_if_crowded(&mut guard, now_ms);
        if let Some(cell) = guard.cells.get_mut(key) {
            // Fast path: measure the existing cell. A denial (`Err`)
            // leaves the TAT untouched per governor's contract, but
            // still counts as activity — a throttled key is an ACTIVE
            // key and must not age out of the store ahead of idle ones.
            cell.last_touch_ms = now_ms;
            let prev = if cell.tat == 0 {
                None
            } else {
                Some(Nanos::from(cell.tat))
            };
            match f(prev) {
                Ok((outcome, new_tat)) => {
                    cell.tat = new_tat.as_u64();
                    Ok(outcome)
                }
                Err(e) => Err(e),
            }
        } else {
            // Fresh cell: governor seeds the TAT from `t0` itself, so a
            // first touch is always admitted (when the cost fits the
            // bucket at all). A denial here stores nothing.
            match f(None) {
                Ok((outcome, new_tat)) => {
                    guard.cells.insert(
                        key.clone(),
                        GcraCell {
                            tat: new_tat.as_u64(),
                            last_touch_ms: now_ms,
                        },
                    );
                    Ok(outcome)
                }
                Err(e) => Err(e),
            }
        }
    }
}

/// Housekeeping seam (parity with governor's own stores): exposes the
/// live key count the eviction bound is asserted against, plus
/// TAT-based retention for callers that want a wider-than-idle drop.
impl ShrinkableKeyedStateStore<String> for GcraShardStore {
    fn retain_recent(&self, drop_below: Nanos) {
        for shard in &self.shards {
            let mut guard = shard.lock().expect("rate limiter shard poisoned");
            guard.cells.retain(|_, cell| cell.tat > drop_below.as_u64());
        }
    }

    fn shrink_to_fit(&self) {
        for shard in &self.shards {
            let mut guard = shard.lock().expect("rate limiter shard poisoned");
            guard.cells.shrink_to_fit();
        }
    }

    fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| {
                shard
                    .lock()
                    .expect("rate limiter shard poisoned")
                    .cells
                    .len()
            })
            .sum()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One stacked GCRA window (DW-017): `requests` per `window` with a
/// `burst`-token bucket, backed by its own sharded keyed state.
struct GcraWindow {
    limiter: GovernorLimiter<String, GcraShardStore, DefaultClock, StateInformationMiddleware>,
    /// Dropped-cell counter shared with the window's store (the store is
    /// owned by the governor limiter; this handle keeps it readable).
    evictions: Arc<AtomicU64>,
    /// Bucket size (governor's max_burst) — the `X-RateLimit-Limit` this
    /// window reports when it is the binding constraint.
    burst: NonZeroU32,
    /// Full-bucket refill time (`burst_size_replenished_in`) — used when
    /// a cost can never fit the bucket, and as the store's idle
    /// threshold.
    full_refill_ms: u64,
}

/// Result of one [`GcraRateLimiter::check`] across its stacked windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcraOutcome {
    pub decision: RateDecision,
    /// Bucket size of the binding window (denying window on denial, the
    /// least-remaining window on success) — for `X-RateLimit-Limit`.
    pub limit: u32,
    /// Estimated milliseconds until the binding window is FULLY
    /// replenished (on denial: until the next conforming retry) — the
    /// basis of `X-RateLimit-Reset`.
    pub refill_ms: u64,
}

/// One window specification for [`GcraRateLimiter::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcraWindowSpec {
    /// Sustained rate: `requests` per `window`.
    pub requests: NonZeroU32,
    pub window: Duration,
    /// Bucket size; defaults to `requests` when `None`.
    pub burst: Option<NonZeroU32>,
}

/// Sharded GCRA limiter over one or more stacked windows (DW-017).
///
/// Implements the [`RateLimiter`] trait: `check(key, cost)` reserves
/// `cost` units in every stacked window for `key` (see the module docs
/// for the stop-at-first-denial consumption semantics). Keys are opaque
/// strings; the caller composes them (see [`RateLimitEngine`]).
///
/// **Clocks:** the GCRA math runs on governor's own quanta monotonic
/// clock; there is deliberately no clock injection for it. The EVICTION
/// bookkeeping (per-key last-touch stamps) has a separate, injectable
/// millisecond clock: `new` uses elapsed monotonic time, tests use
/// [`GcraRateLimiter::with_clock`] to advance deterministically. The two
/// clocks only meet in the idle-eviction threshold (one full refill of
/// the window's bucket), where both advance with wall time.
pub struct GcraRateLimiter {
    /// Shortest window first (see module docs: consumption on a stacked
    /// denial falls on the fastest-replenishing buckets).
    windows: Vec<GcraWindow>,
}

impl std::fmt::Debug for GcraRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcraRateLimiter")
            .field("windows", &self.windows.len())
            .finish()
    }
}

impl GcraRateLimiter {
    /// New limiter over the given window specs (any order; internally
    /// sorted shortest window first). Returns `None` for an empty spec
    /// list — a limiter with no windows cannot make decisions.
    pub fn new(specs: Vec<GcraWindowSpec>) -> Option<Self> {
        Self::build(specs, StoreClock::Monotonic(Instant::now()))
    }

    /// New limiter using a caller-supplied millisecond clock for the
    /// per-key eviction bookkeeping (NOT the GCRA decisions — see the
    /// clocks note in the type docs).
    ///
    /// Intended for tests and other time-controlled setups; production
    /// code should prefer [`GcraRateLimiter::new`]. `now_ms` must return
    /// non-decreasing milliseconds and is called once per window per
    /// `check` (cheap).
    pub fn with_clock(specs: Vec<GcraWindowSpec>, now_ms: fn() -> u64) -> Option<Self> {
        Self::build(specs, StoreClock::Injected(now_ms))
    }

    fn build(specs: Vec<GcraWindowSpec>, clock: StoreClock) -> Option<Self> {
        if specs.is_empty() {
            return None;
        }
        let mut specs = specs;
        specs.sort_by_key(|s| s.window);
        let windows = specs
            .into_iter()
            .map(|spec| {
                let burst = spec.burst.unwrap_or(spec.requests);
                // Replenish interval = window / requests; `with_period`
                // returns None only for a zero period, which a non-zero
                // request count over a non-zero window cannot produce
                // (sub-nanosecond periods clamp to 1ns inside governor).
                let quota = Quota::with_period(spec.window / spec.requests.get())
                    .unwrap_or_else(|| Quota::per_second(spec.requests))
                    .allow_burst(burst);
                let full_refill_ms = quota.burst_size_replenished_in().as_millis() as u64;
                let evictions = Arc::new(AtomicU64::new(0));
                let store = GcraShardStore::new(full_refill_ms, clock, Arc::clone(&evictions));
                // `new` leaves the middleware parameter uninferred; the
                // raw limiter is NoOp until the snapshot middleware is
                // layered on (the field's final type).
                let raw: GovernorLimiter<
                    String,
                    GcraShardStore,
                    DefaultClock,
                    NoOpMiddleware<QuantaInstant>,
                > = GovernorLimiter::new(quota, store, DefaultClock::default());
                GcraWindow {
                    limiter: raw.with_middleware::<StateInformationMiddleware>(),
                    evictions,
                    burst,
                    full_refill_ms,
                }
            })
            .collect();
        Some(Self { windows })
    }

    /// Live per-key cell count across all stacked windows (sum of the
    /// shard maps; approximate under concurrent checks). Bounded by
    /// `GCRA_STORE_SHARDS *
    /// crate::config::limits::MAX_RATE_LIMITER_KEYS_PER_SHARD` per
    /// window — the bound the spray tests assert.
    pub fn live_keys(&self) -> usize {
        self.windows.iter().map(|w| w.limiter.len()).sum::<usize>()
    }

    /// Cells dropped by eviction sweeps across all stacked windows
    /// (monotonic for the limiter's lifetime; a reload builds a fresh
    /// limiter, so the counter resets with the generation).
    pub fn evictions(&self) -> u64 {
        self.windows
            .iter()
            .map(|w| w.evictions.load(Ordering::Relaxed))
            .sum()
    }

    /// Check-and-reserve `cost` units for `key` across all stacked
    /// windows (see module docs). `cost` 0 is treated as 1 (a request
    /// always costs at least one unit); a cost larger than any window's
    /// bucket is always denied.
    pub fn check(&self, key: &str, cost: u32) -> GcraOutcome {
        let cost = NonZeroU32::new(cost.max(1)).expect("cost.max(1) is non-zero");
        let mut binding: Option<GcraOutcome> = None;
        let key = key.to_string();
        for w in &self.windows {
            match w.limiter.check_key_n(&key, cost) {
                // Cost can never fit this bucket: deny for a full refill.
                Err(_) => {
                    return denied_outcome(w.burst.get(), w.full_refill_ms);
                }
                Ok(Err(not_until)) => {
                    let wait = not_until.wait_time_from(w.limiter.clock().now());
                    return denied_outcome(w.burst.get(), wait.as_millis() as u64);
                }
                Ok(Ok(snapshot)) => {
                    let remaining = snapshot.remaining_burst_capacity();
                    let refill = snapshot.quota().burst_size_replenished_in().as_millis() as u64;
                    let candidate = GcraOutcome {
                        decision: RateDecision {
                            allowed: true,
                            remaining: u64::from(remaining),
                            retry_after_ms: None,
                        },
                        limit: w.burst.get(),
                        refill_ms: refill,
                    };
                    if binding
                        .as_ref()
                        .is_none_or(|b| candidate.decision.remaining < b.decision.remaining)
                    {
                        binding = Some(candidate);
                    }
                }
            }
        }
        binding.expect("non-empty window list always yields a decision")
    }
}

pub fn denied_outcome(limit: u32, retry_after_ms: u64) -> GcraOutcome {
    GcraOutcome {
        decision: RateDecision {
            allowed: false,
            remaining: 0,
            retry_after_ms: Some(retry_after_ms),
        },
        limit,
        refill_ms: retry_after_ms,
    }
}

#[async_trait]
impl RateLimiter for GcraRateLimiter {
    async fn check(&self, key: &str, cost: u32) -> Result<RateDecision, ExtensionsError> {
        Ok(self.check(key, cost).decision)
    }
}

// --- policy engine (DW-017 wiring) --------------------------------------

/// One compiled rate-limit rule: selector set plus its stacked windows.
/// `dry_run` (DW-041) is the owning policy bundle's monitor flag: the
/// rule still evaluates (its GCRA buckets advance exactly as if
/// enforcing), but its denials are REPORTED to the caller instead of
/// returned as the enforcement outcome.
struct EngineRule {
    selectors: Vec<crate::config::RateLimitSelector>,
    limiter: EngineLimiter,
    dry_run: bool,
}

/// The limiter backend for one compiled rule (DW-031): the local
/// in-memory GCRA limiter (OSS default) or the Redis-backed GCRA
/// limiter (ent feature, when configured and licensed). Both expose
/// the same `check` shape returning a [`GcraOutcome`], so the engine
/// can use either uniformly — the Redis variant is async (one
/// round-trip per window), the local variant is sync (in-memory).
enum EngineLimiter {
    Local(GcraRateLimiter),
    #[cfg(feature = "ent")]
    Redis(Box<crate::extensions::redis_rate_limiter::RedisRateLimiter>),
}

impl EngineLimiter {
    /// Check-and-reserve `cost` units for `key`. Delegates to the
    /// local (sync) or Redis (async) backend. The Redis path is one
    /// round-trip per stacked window; the local path is in-memory.
    async fn check(&self, key: &str, cost: u32) -> GcraOutcome {
        match self {
            EngineLimiter::Local(l) => l.check(key, cost),
            #[cfg(feature = "ent")]
            EngineLimiter::Redis(l) => l.check(key, cost).await,
        }
    }

    /// Live per-key cell count (local only; Redis manages its own keys
    /// and reports 0 here — the gauge is a local-limiter metric).
    fn live_keys(&self) -> usize {
        match self {
            EngineLimiter::Local(l) => l.live_keys(),
            #[cfg(feature = "ent")]
            EngineLimiter::Redis(_) => 0,
        }
    }

    /// Cells dropped by eviction sweeps (local only; Redis manages its
    /// own key expiry and reports 0 here).
    fn evictions(&self) -> u64 {
        match self {
            EngineLimiter::Local(l) => l.evictions(),
            #[cfg(feature = "ent")]
            EngineLimiter::Redis(_) => 0,
        }
    }
}

/// The per-request attributes a rule key can be built from (DW-017).
#[derive(Debug, Clone, Copy)]
pub struct RateLimitKeyContext<'a> {
    /// Direct connection peer (the `ip` selector; same IP as X-Real-IP).
    pub peer: std::net::IpAddr,
    /// Authenticated consumer name; `None` for anonymous traffic — the
    /// `credential` selector then falls back to the peer IP.
    pub consumer: Option<&'a str>,
    /// Name of the matched route (the `route` selector); the empty
    /// string on unrouted traffic (no route resolved — the selector then
    /// keys one bucket shared by all unrouted requests of that policy).
    pub route: &'a str,
}

/// What the engine decided for one request (DW-017).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitOutcome {
    /// No rule applied to the request: no limiting, and responses carry
    /// no rate headers.
    NotLimited,
    /// Admitted; `limit`/`remaining`/`reset_epoch_s` describe the binding
    /// constraint (the window with the least remaining budget).
    Allowed {
        limit: u32,
        remaining: u32,
        reset_epoch_s: u64,
    },
    /// Denied: emit 429 with `Retry-After` = `retry_after_s` (ceil, min 1)
    /// and the binding (first-denying) rule's rate headers. When several
    /// rules deny, `retry_after_s` is the MAX wait across them (see
    /// [`RateLimitEngine::check`]); headers still show the first binding
    /// rule — Limit/Remaining report the tightest constraint in
    /// resolution order, Retry-After the longest wait.
    Denied {
        limit: u32,
        remaining: u32,
        reset_epoch_s: u64,
        retry_after_s: u32,
    },
}

/// Policy-resolution and key-building engine for request rate limiting
/// (DW-017). Compiled once per config generation.
///
/// **Precedence chain** (frozen vocabulary: consumer, then route, then
/// service, then listener, then global): rules from ALL applicable
/// policies apply and are AND-ed; the resolution order is consumer
/// (authenticated requests carry their consumer's policies), then route,
/// then service, then listener (`listeners[].policies`, the listener
/// that accepted the request), then global (`gateway.global_policies`).
/// The order matters for the 429 HEADERS only (the first denying rule
/// binds Limit/Remaining/Reset; see [`RateLimitEngine::check`]); every
/// applicable rule still gates the request. On UNROUTED traffic
/// (no route resolved) only the listener and global links apply —
/// consumer, route, and service links are unknowable before routing,
/// and the documented request-path order places authentication after
/// route resolution.
///
/// Key building per rule: each selector contributes one component
/// (`ip` = peer, `credential` = consumer or peer fallback, `route` =
/// route name; the empty string for unrouted requests); components are
/// joined with `|` into one key. Rules attached to the same policy
/// share a limiter instance, so two rules with identical selectors and
/// windows would double-count — validation does not reject it
/// (harmless), operators just should not write it.
pub struct RateLimitEngine {
    /// (policy name, rule) in config order; resolution scans by name.
    rules: Vec<(String, EngineRule)>,
}

impl std::fmt::Debug for RateLimitEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitEngine")
            .field("rules", &self.rules.len())
            .finish()
    }
}

fn window_specs(rp: &crate::config::RateRequestsPer, burst: Option<u32>) -> Vec<GcraWindowSpec> {
    /// `window` seconds per `requests` (burst defaults to the request
    /// count; see the module docs for the GCRA first-window shape).
    fn spec(requests: u32, window: u64, burst: Option<u32>) -> GcraWindowSpec {
        let requests = NonZeroU32::new(requests).expect("validation rejects 0");
        let burst = burst.and_then(NonZeroU32::new).unwrap_or(requests);
        GcraWindowSpec {
            requests,
            window: Duration::from_secs(window),
            burst: Some(burst),
        }
    }
    let mut specs = Vec::new();
    if let Some(s) = rp.per_second.filter(|v| *v > 0) {
        specs.push(spec(s, 1, burst));
    }
    if let Some(m) = rp.minute.filter(|v| *v > 0) {
        specs.push(spec(m, 60, burst));
    }
    if let Some(h) = rp.hour.filter(|v| *v > 0) {
        specs.push(spec(h, 3600, burst));
    }
    specs
}

impl RateLimitEngine {
    /// Compile every policy's rate rules of a config generation. Policies
    /// without rate rules contribute nothing (their timeouts and future
    /// plugin bundles are other layers' concern).
    pub fn compile(gateway: &crate::config::Gateway) -> Self {
        let mut rules = Vec::new();
        for policy in &gateway.policies {
            // Legacy single-window field: selector [route], one window of
            // `requests` per `window_seconds` (documented mapping; the
            // field stays for schema stability within M1).
            if let Some(rl) = &policy.rate_limit {
                if rl.requests > 0 && rl.window_seconds > 0 {
                    let requests = NonZeroU32::new(u32::try_from(rl.requests).unwrap_or(u32::MAX))
                        .expect("validated > 0");
                    rules.push((
                        policy.name.clone(),
                        EngineRule {
                            selectors: vec![crate::config::RateLimitSelector::Route],
                            limiter: EngineLimiter::Local(
                                GcraRateLimiter::new(vec![GcraWindowSpec {
                                    requests,
                                    window: Duration::from_secs(rl.window_seconds),
                                    burst: Some(requests),
                                }])
                                .expect("one window spec"),
                            ),
                            dry_run: policy.dry_run,
                        },
                    ));
                }
            }
            for rule in &policy.rate_limits {
                let specs = window_specs(&rule.requests_per, rule.burst);
                let Some(limiter) = GcraRateLimiter::new(specs) else {
                    continue; // empty rule shapes are rejected by validation
                };
                rules.push((
                    policy.name.clone(),
                    EngineRule {
                        selectors: rule.selector.clone(),
                        limiter: EngineLimiter::Local(limiter),
                        dry_run: policy.dry_run,
                    },
                ));
            }
        }
        Self { rules }
    }

    /// Compile every policy's rate rules with Redis-backed limiters
    /// (DW-031, ent feature only). Same rule compilation as
    /// [`Self::compile`], but each rule's limiter is a
    /// [`RedisRateLimiter`](crate::extensions::redis_rate_limiter::RedisRateLimiter)
    /// sharing the provided connection (cloned cheaply per rule). The
    /// config supplies the fail-open flag, key prefix, and key TTL.
    /// Used when the `ent` feature is compiled in, the
    /// `redis_rate_limiter` config block is present, and the license
    /// grants the `redis_rate_limiter` feature claim.
    #[cfg(feature = "ent")]
    pub fn compile_with_redis(
        gateway: &crate::config::Gateway,
        conn: redis::aio::ConnectionManager,
        config: &crate::config::RedisRateLimiterConfig,
    ) -> Self {
        use crate::extensions::redis_rate_limiter::RedisRateLimiter;

        let mut rules = Vec::new();
        for policy in &gateway.policies {
            if let Some(rl) = &policy.rate_limit {
                if rl.requests > 0 && rl.window_seconds > 0 {
                    let requests = NonZeroU32::new(u32::try_from(rl.requests).unwrap_or(u32::MAX))
                        .expect("validated > 0");
                    let specs = vec![GcraWindowSpec {
                        requests,
                        window: Duration::from_secs(rl.window_seconds),
                        burst: Some(requests),
                    }];
                    if let Some(limiter) =
                        RedisRateLimiter::from_config(conn.clone(), specs, config)
                    {
                        rules.push((
                            policy.name.clone(),
                            EngineRule {
                                selectors: vec![crate::config::RateLimitSelector::Route],
                                limiter: EngineLimiter::Redis(Box::new(limiter)),
                                dry_run: policy.dry_run,
                            },
                        ));
                    }
                }
            }
            for rule in &policy.rate_limits {
                let specs = window_specs(&rule.requests_per, rule.burst);
                let Some(limiter) = RedisRateLimiter::from_config(conn.clone(), specs, config)
                else {
                    continue;
                };
                rules.push((
                    policy.name.clone(),
                    EngineRule {
                        selectors: rule.selector.clone(),
                        limiter: EngineLimiter::Redis(Box::new(limiter)),
                        dry_run: policy.dry_run,
                    },
                ));
            }
        }
        Self { rules }
    }

    /// Whether any rule is compiled in at all (fast path: configs with no
    /// rate-limit policies skip per-request key building entirely).
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Live per-key cell count across every compiled rule's windows
    /// (approximate under concurrent checks) — the spray-bounded figure
    /// for tests and ops visibility. See [`GcraRateLimiter::live_keys`].
    pub fn live_keys(&self) -> usize {
        self.rules
            .iter()
            .map(|(_, rule)| rule.limiter.live_keys())
            .sum()
    }

    /// Cells dropped by eviction sweeps across every compiled rule
    /// (monotonic per config generation). See [`GcraRateLimiter::evictions`].
    pub fn evictions(&self) -> u64 {
        self.rules
            .iter()
            .map(|(_, rule)| rule.limiter.evictions())
            .sum()
    }

    /// Resolve the applicable rules for one request and check them.
    /// The policy name lists are those attached to the authenticated
    /// consumer (DW-019; empty for anonymous traffic), the matched
    /// route, its service, the accepting listener, and the gateway
    /// (global) — in that resolution order (the frozen precedence
    /// chain). On unrouted traffic the caller passes empty
    /// consumer/route/service lists (`ctx.route` is then the empty
    /// string) and only the listener/global links resolve.
    /// A policy attached at multiple levels (or repeated within one
    /// list) is evaluated ONCE per request; its first — most
    /// specific — chain position is the occurrence that binds the
    /// 429 headers.
    /// All applicable rules apply (AND); on success the reported
    /// constraint is the tightest one (least remaining budget). On denial
    /// the FIRST denying rule binds the Limit/Remaining/Reset headers,
    /// but evaluation continues through the remaining applicable rules so
    /// `retry_after_s` (and the matching Reset) reflect the MAXIMUM wait
    /// any denying rule demands — a client honoring the hint never
    /// retries into a second 429 with an understated Retry-After.
    /// Dry-run bundles (DW-041, `policies[].dry_run`) never contribute
    /// to this outcome — see [`RateLimitEngine::evaluate`], which this
    /// delegates to.
    pub async fn check(
        &self,
        ctx: &RateLimitKeyContext<'_>,
        consumer_policies: &[String],
        route_policies: &[String],
        service_policies: &[String],
        listener_policies: &[String],
        global_policies: &[String],
    ) -> RateLimitOutcome {
        self.evaluate(
            ctx,
            consumer_policies,
            route_policies,
            service_policies,
            listener_policies,
            global_policies,
        )
        .await
        .outcome
    }

    /// [`Self::check`] with the dry-run observation attached (DW-041):
    /// every applicable rule still EVALUATES (dry bundles' GCRA buckets
    /// advance exactly as if enforcing, so their denial rates reflect
    /// what enforcement would do), but the enforcement `outcome` is
    /// computed from LIVE rules only, while `dry_denied` carries the
    /// first (most specific) dry bundle's would-be denial for the caller
    /// to log and count. Dry bundles also contribute no
    /// `X-RateLimit-*` header values: a monitor never touches the
    /// response. A request can therefore be BOTH 429'd by a live rule
    /// and reported as a dry would-deny in the same evaluation.
    pub async fn evaluate(
        &self,
        ctx: &RateLimitKeyContext<'_>,
        consumer_policies: &[String],
        route_policies: &[String],
        service_policies: &[String],
        listener_policies: &[String],
        global_policies: &[String],
    ) -> RateLimitEvaluation {
        // Resolution order (precedence): consumer > route > service >
        // listener > global. One policy is ONE evaluation: a name listed
        // at several levels (or twice in one list) resolves its rules
        // once, at its FIRST chain position, so a shared policy spends
        // its budget once per request and the most specific level's
        // occurrence is the one that binds when it denies. The attached
        // lists are tiny and config-bounded, so the dedup is an
        // allocation-free rescan of the earlier positions — cheaper
        // than any heap set on this per-request path.
        //
        // Header binding: the FIRST denying LIVE rule supplies Limit /
        // Remaining / Reset (the tightest constraint in resolution
        // order); Retry-After is the MAX wait across every denying live
        // rule, so a client honoring it never retries into a second 429
        // with an understated hint. Allowed outcomes are irrelevant
        // once a live rule has denied (the response is a 429
        // regardless). Dry denials (DW-041) run through the same loop
        // into their own accumulator: the first one is the report, the
        // rest only stretch its Retry-After for the log line.
        let attached = [
            consumer_policies,
            route_policies,
            service_policies,
            listener_policies,
            global_policies,
        ];
        let attached_names = || attached.iter().flat_map(|l| l.iter());
        let mut acc: Option<RateLimitOutcome> = None;
        let mut denied: Option<RateLimitOutcome> = None;
        let mut dry_denied: Option<RateLimitOutcome> = None;
        for (pos, name) in attached_names().enumerate() {
            if attached_names().take(pos).any(|prev| prev == name) {
                // Already resolved at a more specific position.
                continue;
            }
            for (policy_name, rule) in &self.rules {
                if policy_name != name {
                    continue;
                }
                let key = build_key(ctx, &rule.selectors);
                match rate_outcome(rule.limiter.check(&key, 1).await) {
                    RateLimitOutcome::Denied {
                        limit,
                        remaining,
                        reset_epoch_s,
                        retry_after_s,
                    } => {
                        // Dry bundles report instead of enforce (DW-041);
                        // the accumulator is the same first-binds /
                        // later-stretches shape as the live one.
                        let sink = if rule.dry_run {
                            &mut dry_denied
                        } else {
                            &mut denied
                        };
                        match sink.as_mut() {
                            // First denial binds the headers (live) or
                            // the report (dry).
                            None => {
                                *sink = Some(RateLimitOutcome::Denied {
                                    limit,
                                    remaining,
                                    reset_epoch_s,
                                    retry_after_s,
                                });
                            }
                            // Later denials only stretch Retry-After (and
                            // the matching Reset) when they wait longer.
                            Some(RateLimitOutcome::Denied {
                                retry_after_s: max_ra,
                                reset_epoch_s: max_rs,
                                ..
                            }) => {
                                if retry_after_s > *max_ra {
                                    *max_ra = retry_after_s;
                                    *max_rs = reset_epoch_s;
                                }
                            }
                            // The sinks only ever hold Denied variants.
                            Some(_) => unreachable!("denial sinks only hold Denied"),
                        }
                    }
                    next @ RateLimitOutcome::Allowed { remaining, .. } => {
                        // Dry bundles never contribute headers: their
                        // allowed outcomes are dropped entirely.
                        if denied.is_some() || rule.dry_run {
                            continue;
                        }
                        // The tightest constraint (least remaining
                        // budget) is the one the headers report.
                        let keep_prev = matches!(
                            acc,
                            Some(RateLimitOutcome::Allowed { remaining: prev, .. })
                                if remaining >= prev
                        );
                        if !keep_prev {
                            acc = Some(next);
                        }
                    }
                    RateLimitOutcome::NotLimited => {}
                }
            }
        }
        RateLimitEvaluation {
            outcome: denied.unwrap_or(acc.unwrap_or(RateLimitOutcome::NotLimited)),
            dry_denied,
        }
    }
}

/// The full rate-limit decision for one request (DW-041): the LIVE
/// enforcement outcome (exactly the pre-dry-run `check` semantics over
/// live bundles) plus the first dry bundle's would-be denial, if any
/// evaluated to one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitEvaluation {
    pub outcome: RateLimitOutcome,
    /// The first (most specific) `dry_run` bundle that would have denied
    /// this request: a [`RateLimitOutcome::Denied`] payload for the log
    /// line and metric — never enforced, never on the response.
    pub dry_denied: Option<RateLimitOutcome>,
}

fn rate_outcome(result: GcraOutcome) -> RateLimitOutcome {
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if !result.decision.allowed {
        let retry_ms = result.decision.retry_after_ms.unwrap_or(0);
        RateLimitOutcome::Denied {
            limit: result.limit,
            remaining: result.decision.remaining as u32,
            reset_epoch_s: now_epoch + retry_ms.div_ceil(1000),
            retry_after_s: u32::try_from(retry_ms.div_ceil(1000)).unwrap_or(1).max(1),
        }
    } else {
        RateLimitOutcome::Allowed {
            limit: result.limit,
            remaining: result.decision.remaining as u32,
            reset_epoch_s: now_epoch + result.refill_ms.div_ceil(1000),
        }
    }
}

fn build_key(
    ctx: &RateLimitKeyContext<'_>,
    selectors: &[crate::config::RateLimitSelector],
) -> String {
    let mut key = String::new();
    for s in selectors {
        if !key.is_empty() {
            key.push('|');
        }
        match s {
            crate::config::RateLimitSelector::Ip => key.push_str(&ctx.peer.to_string()),
            // Falls back to the peer IP until DW-019 identifies consumers:
            // anonymous traffic then limits per client rather than sharing
            // one global "anonymous" bucket (documented choice).
            crate::config::RateLimitSelector::Credential => {
                key.push_str(ctx.consumer.unwrap_or(&ctx.peer.to_string()))
            }
            crate::config::RateLimitSelector::Route => key.push_str(ctx.route),
        }
    }
    key
}
