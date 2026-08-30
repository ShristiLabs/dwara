//! Per-upstream load balancing (DW-011, feature analysis 4.3).
//!
//! One [`UpstreamLb`] per upstream holds the endpoint set behind an
//! [`ArcSwap`] (`LbState`), so [`UpstreamLb::pick`] is lock-free: it loads
//! the current state snapshot and runs the configured algorithm with no
//! mutex on the hot path. Endpoint mutation happens only on config reload
//! via [`UpstreamLb::rebuild`], which swaps in a new state atomically —
//! in-flight requests holding an older state keep working against it.
//!
//! Algorithms (config `load_balancer`):
//!
//! - `round_robin` — smooth weighted round-robin (the nginx algorithm):
//!   each pick adds every endpoint's effective weight to its running
//!   `current_weight`, selects the maximum, and subtracts the total from
//!   the winner. The result interleaves endpoints deterministically in
//!   proportion to their weights (weights {5,1,2} produce the classic
//!   `a a b a c a a` pattern) with period = sum of weights; over any full
//!   period each endpoint is picked exactly its weight many times.
//! - `least_requests` — the endpoint with the fewest in-flight requests
//!   (see the inflight counters below) wins; ties break to the lowest
//!   index. Slow start is NOT applied here (documented choice: least-conn
//!   balances on observed load, not weights; a ramping endpoint naturally
//!   receives traffic only when others are busier, which is the same
//!   conservative effect without inventing a weight model).
//! - `random` — "power of two choices": two distinct endpoints are drawn
//!   uniformly at random and the one with the lower in-flight count wins
//!   (ties to the lower index). With large fan-out this converges to
//!   least-conn at a fraction of the coordination cost.
//! - `ip_hash` — consistent hashing (ketama): each endpoint is hashed onto
//!   a ring with vnode count per unit of weight ([`KETAMA_VNODES`] = 160
//!   per weight unit, so a weight-w endpoint gets 160*w vnodes); a pick
//!   hashes its key (the client IP, plumbed by the proxy) and takes the
//!   first ring entry at or after that hash. Because vnodes are additive
//!   (no max-normalization), adding or removing an endpoint remaps only
//!   ~1/(n+1) of keys for equal weights and keys between unchanged
//!   endpoints stay put. Ring and key hashing use an inline, fully
//!   specified FNV-1a hash with a murmur3-style finalizer — stable
//!   across Rust versions, unlike `DefaultHasher` (SipHash), which
//!   makes no cross-version stability guarantee and would silently
//!   remap every sticky session after a toolchain bump. Slow start is
//!   NOT applied to the ring (documented
//!   choice: rebuilding a ring mid-ramp would remap keys; consistency is
//!   the point of the algorithm). With no key (e.g. the TLS-passthrough
//!   path) ip_hash falls back to smooth weighted round-robin.
//!
//! In-flight counting: every endpoint carries an `AtomicU64` in-flight
//! counter. The upstream handle increments the picked endpoint's counter
//! at dispatch and decrements when the response (headers) resolves — NOT
//! when the streaming body completes, which the pool cannot observe
//! without wrapping bodies (documented approximation; it biases
//! least-conn/random-2 slightly optimistic during long streams).
//!
//! Slow start (`slow_start_ms`, default 0 = off): an endpoint entering the
//! set ramps its effective weight from a floor of 1 to its configured
//! weight over the window, measured from the moment it entered the set.
//! The ramp applies to smooth WRR and (through weights) ip_hash vnode
//! counts are exempt as above. Endpoints already in the set when
//! slow_start is newly enabled do NOT ramp — their carried entry instant
//! predates the window; only genuinely new addresses ramp.
//! Recovery-ramp after a health failure is
//! future work (DW-015 owns health state) — the effective-weight function
//! is the same one that integration will call.
//!
//! Hot endpoint sets / weight changes without restart: config reload
//! rebuilds the registry and calls [`UpstreamLb::rebuild`] with the new
//! endpoint list. Endpoints whose `address:port` is unchanged KEEP their
//! in-flight counter, `current_weight` (WRR phase), and slow-start entry
//! instant; new addresses start fresh (in-flight 0, full slow-start ramp
//! if configured). Documented reset semantics: removed endpoints drop
//! their state outright; re-adding one later is a fresh entry.
//!
//! Randomness for `random` (random-2) is a process-local xorshift64* seed
//! under a CAS loop — no `rand` dependency, adequate uniformity for two
//! choices.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;

use crate::config::limits::KETAMA_VNODES;
use crate::config::{Endpoint, LoadBalancer, PassiveHealth};
use crate::resilience::health::{EndpointHealth, HealthDispatch, HealthParams};

/// One endpoint's runtime row inside an [`LbState`].
struct LbEndpoint {
    address: String,
    port: u16,
    /// Configured weight (>= 1; validation enforces).
    weight: u32,
    /// When this endpoint entered the set (slow-start clock). Carried
    /// across rebuilds for unchanged addresses.
    entered: Instant,
    /// In-flight request count (incremented at dispatch by the handle).
    /// Shared (`Arc`) so a rebuild carries the LIVE counter, not a copy:
    /// guards taken before a swap decrement the same counter the next
    /// state reads.
    inflight: Arc<AtomicU64>,
    /// Smooth-WRR running weight (the nginx algorithm's per-endpoint
    /// accumulator). Carried across rebuilds for unchanged addresses as a
    /// SHARED cell (exactly like `inflight`): a pick in flight against
    /// the old snapshot while a reload swaps in a new state mutates the
    /// same accumulator the next generation reads, so no phase step is
    /// lost (#128, DW-011 review).
    current_weight: Arc<AtomicI64>,
    /// Passive health tracker (DW-012); present only when the upstream
    /// configures `health`. Carried across rebuilds for unchanged
    /// addresses, exactly like `inflight`: the live tracker survives the
    /// swap, so consecutive-failure streaks and the observation window
    /// survive config reloads.
    health: Option<Arc<EndpointHealth>>,
}

impl LbEndpoint {
    fn new(e: &Endpoint) -> Self {
        LbEndpoint {
            address: e.address.clone(),
            port: e.port,
            weight: e.weight.max(1),
            entered: Instant::now(),
            inflight: Arc::new(AtomicU64::new(0)),
            current_weight: Arc::new(AtomicI64::new(0)),
            health: None,
        }
    }

    /// Same endpoint (address:port unchanged): keep live counters, WRR
    /// phase, and slow-start clock; take the new configured weight. The
    /// WRR phase carries as the LIVE shared cell, not a copied value, so
    /// a pick racing the rebuild cannot strand a phase step in the old
    /// state (#128).
    fn carried_from(old: &LbEndpoint, e: &Endpoint) -> Self {
        LbEndpoint {
            address: old.address.clone(),
            port: old.port,
            weight: e.weight.max(1),
            entered: old.entered,
            inflight: Arc::clone(&old.inflight),
            current_weight: Arc::clone(&old.current_weight),
            health: old.health.clone(),
        }
    }

    fn same_target(&self, e: &Endpoint) -> bool {
        self.address == e.address && self.port == e.port
    }
}

/// Immutable endpoint-set snapshot + algorithm parameters. Swapped
/// atomically by [`UpstreamLb::rebuild`].
struct LbState {
    endpoints: Vec<LbEndpoint>,
    algorithm: LoadBalancer,
    slow_start: Duration,
    /// Ketama ring (hash -> endpoint index); empty unless ip_hash.
    ring: BTreeMap<u64, usize>,
    /// Resolved passive-health parameters for this generation (DW-012);
    /// `None` = passive health disabled (no ejection, no filtering).
    health: Option<Arc<HealthParams>>,
}

impl LbState {
    /// Effective weight after the slow-start ramp (floor 1 so a ramping
    /// endpoint is never excluded from the set).
    fn effective_weight(&self, e: &LbEndpoint) -> i64 {
        if self.slow_start.is_zero() {
            return e.weight as i64;
        }
        let elapsed = e.entered.elapsed();
        if elapsed >= self.slow_start {
            e.weight as i64
        } else {
            let w = e.weight as u128;
            let ramped = (w * elapsed.as_millis()) / self.slow_start.as_millis().max(1);
            ramped.max(1) as i64
        }
    }
}

/// A load balancer for one upstream: lock-free picks over an atomically
/// swappable endpoint set. Share via `Arc`; cheap to read from any task.
pub struct UpstreamLb {
    state: ArcSwap<LbState>,
    rng: AtomicU64,
    /// Millisecond clock for passive-health timing (DW-012). System clock
    /// in production; swappable for deterministic clocks in tests
    /// (`set_health_clock`). Read on every pick when health is enabled.
    health_clock: RwLock<fn() -> u64>,
    /// Picks that fell back to the full endpoint set because every
    /// endpoint was ejected (fail-open; see `choose`). Observability.
    fail_open_picks: AtomicU64,
    /// DW-042: the upstream-scoped event emitter, kept so the DNS
    /// discovery task can pass it to `rebuild_with_health_and_events`
    /// when it swaps the endpoint set live (new endpoints get
    /// event-bound health trackers, matching the reload path). None
    /// when the balancer was built without events.
    events: Option<crate::events::UpstreamEmitter>,
}

fn xorshift(x: u64) -> u64 {
    let mut x = x.wrapping_add(0x9E3779B97F4A7C15);
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    x.wrapping_mul(0x2545F4914F6CDD1D)
}

/// Default passive-health clock: Unix-epoch milliseconds.
fn system_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn build_state(
    endpoints: &[Endpoint],
    algorithm: LoadBalancer,
    slow_start: Duration,
    previous: Option<&LbState>,
    health: Option<Arc<HealthParams>>,
    events: Option<&crate::events::UpstreamEmitter>,
) -> LbState {
    let mut eps: Vec<LbEndpoint> = Vec::with_capacity(endpoints.len());
    for e in endpoints {
        let carried = previous.and_then(|p| {
            p.endpoints
                .iter()
                .find(|old| old.same_target(e))
                .map(|old| LbEndpoint::carried_from(old, e))
        });
        eps.push(carried.unwrap_or_else(|| LbEndpoint::new(e)));
    }
    // Passive health invariant: when this generation has health enabled,
    // EVERY endpoint carries a tracker (fresh ones for new addresses, the
    // carried live tracker for unchanged addresses; enabling health on a
    // rebuild gives unchanged addresses a fresh tracker with no history).
    // A fresh tracker is created WITH its ejection/recovery event binding
    // (DW-044) when the balancer was built with an upstream emitter.
    if health.is_some() {
        for e in &mut eps {
            if e.health.is_none() {
                let tracker = match events {
                    Some(events) => {
                        EndpointHealth::with_events(events.for_endpoint(&endpoint_label(e)))
                    }
                    None => EndpointHealth::new(),
                };
                e.health = Some(Arc::new(tracker));
            }
        }
    }
    let ring = if algorithm == LoadBalancer::IpHash {
        build_ring(&eps)
    } else {
        BTreeMap::new()
    };
    LbState {
        endpoints: eps,
        algorithm,
        slow_start,
        ring,
        health,
    }
}

/// Ketama ring construction: vnode count is PER UNIT OF WEIGHT — endpoint
/// i gets `KETAMA_VNODES * weight_i` vnodes. Footprint is additive (no
/// max-normalization), so an endpoint's vnode positions never move when
/// another endpoint with a different weight joins or leaves: adding a
/// weight-w endpoint to total weight W remaps only ~w/(W+w) of keys, and
/// keys between unchanged endpoints stay put. Validation bounds the total
/// ring size at `config::limits::MAX_RING_VNODES`. Collisions (same ring
/// hash) keep the later endpoint — harmless at 64-bit hash widths.
fn build_ring(eps: &[LbEndpoint]) -> BTreeMap<u64, usize> {
    let mut ring = BTreeMap::new();
    for (i, e) in eps.iter().enumerate() {
        let vnodes = (KETAMA_VNODES * e.weight.max(1) as u64).max(1);
        for v in 0..vnodes {
            let mut h = Fnv1a::new();
            h.update(e.address.as_bytes());
            h.update(&e.port.to_be_bytes());
            h.update(&v.to_be_bytes());
            ring.insert(h.finish(), i);
        }
    }
    ring
}

/// Hash a client key onto ring space (same FNV-1a as the ring uses).
/// pub(crate): the DW-040 service split hashes branch keys with the
/// SAME function so a sticky cookie maps consistently across both
/// decision layers.
pub(crate) fn key_hash(key: &str) -> u64 {
    let mut h = Fnv1a::new();
    h.update(key.as_bytes());
    h.finish()
}

/// Inline FNV-1a (64-bit). Ring positions and lookup keys must hash
/// identically for the life of a deployment, including across Rust
/// toolchain upgrades — `DefaultHasher` (SipHash) makes no stability
/// guarantee across Rust versions, so sticky sessions could silently
/// remap wholesale after a toolchain bump. FNV-1a is fully specified,
/// trivially stable, and adequate quality for consistent-hash buckets
/// (it is not used for any adversarial/table-index purpose).
struct Fnv1a(u64);

impl Fnv1a {
    fn new() -> Self {
        Fnv1a(0xcbf2_9ce4_8422_2325)
    }

    fn update(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(0x100_0000_01b3);
        }
    }

    /// Finish with a murmur3-style 64-bit finalizer: raw FNV-1a output
    /// keeps poor high-bit diffusion (outputs for inputs of different
    /// lengths occupy systematically different magnitude ranges), which
    /// collapses consistent-hash rings. The finalizer is itself fully
    /// specified and version-stable.
    fn finish(self) -> u64 {
        let mut x = self.0;
        x ^= x >> 33;
        x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
        x ^= x >> 33;
        x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
        x ^= x >> 33;
        x
    }
}

/// `address:port` label for one endpoint row, IPv6 literals bracketed
/// (the same spelling `upstream.rs` dials and the `endpoint_health`
/// metric uses, so an ejection event and the gauge series agree).
fn endpoint_label(e: &LbEndpoint) -> String {
    let host = if e.address.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{}]", e.address)
    } else {
        e.address.clone()
    };
    format!("{host}:{}", e.port)
}

/// Smooth weighted round-robin pick (nginx algorithm) over effective
/// weights, restricted to the candidate indices. Period = sum of effective
/// weights; over any full period each endpoint is picked exactly its
/// effective-weight many times.
///
/// `cand == None` means "every endpoint index" and runs allocation-free
/// (the passive-health-disabled / fail-open paths); `Some(slice)` restricts
/// the walk to the filtered candidate set.
fn smooth_weighted_rr(state: &LbState, cand: Option<&[usize]>) -> usize {
    let n = cand.map_or(state.endpoints.len(), |c| c.len());
    let resolve = |i: usize| cand.map_or(i, |c| c[i]);
    let mut total: i64 = 0;
    let mut best: usize = resolve(0);
    let mut best_cw: i64 = i64::MIN;
    for i in 0..n {
        let e = &state.endpoints[resolve(i)];
        let w = state.effective_weight(e);
        total += w;
        let cw = e.current_weight.fetch_add(w, Ordering::Relaxed) + w;
        // Strict >: ties keep the lowest index (deterministic).
        if cw > best_cw {
            best_cw = cw;
            best = resolve(i);
        }
    }
    if total <= 0 {
        // Unreachable for validated sets (weights >= 1); degrade to the
        // first candidate rather than dividing by zero elsewhere.
        return best;
    }
    state.endpoints[best]
        .current_weight
        .fetch_sub(total, Ordering::Relaxed);
    best
}

impl UpstreamLb {
    /// Build a balancer with a fresh endpoint set (all slow-start clocks
    /// start now) and passive health DISABLED. See [`UpstreamLb::new_with_health`].
    pub fn new(endpoints: &[Endpoint], algorithm: LoadBalancer, slow_start: Duration) -> Arc<Self> {
        Self::new_with_health(endpoints, algorithm, slow_start, None)
    }

    /// `new` with passive health (DW-012): when `health` is `Some`, every
    /// endpoint gets a fresh health tracker and picks skip ejected
    /// endpoints (all-ejected falls back to the full set; see `choose`).
    /// The config form is resolved via [`HealthParams::from_config`];
    /// validation guarantees its bounds.
    pub fn new_with_health(
        endpoints: &[Endpoint],
        algorithm: LoadBalancer,
        slow_start: Duration,
        health: Option<&PassiveHealth>,
    ) -> Arc<Self> {
        Self::new_with_health_and_events(endpoints, algorithm, slow_start, health, None)
    }

    /// `new_with_health` with ejection/recovery events (DW-044): fresh
    /// trackers are created bound to `events` (an upstream-labeled
    /// emitter), so their ejection/recovery transitions emit onto the
    /// event bus. Carried trackers keep the binding they were built
    /// with. `None` behaves exactly like [`UpstreamLb::new_with_health`].
    pub fn new_with_health_and_events(
        endpoints: &[Endpoint],
        algorithm: LoadBalancer,
        slow_start: Duration,
        health: Option<&PassiveHealth>,
        events: Option<&crate::events::UpstreamEmitter>,
    ) -> Arc<Self> {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x853c49e6748fea9b)
            ^ (&endpoints as *const _ as u64)
            ^ std::process::id() as u64;
        let health = health.map(|h| Arc::new(HealthParams::from_config(h)));
        Arc::new(UpstreamLb {
            state: ArcSwap::from_pointee(build_state(
                endpoints, algorithm, slow_start, None, health, events,
            )),
            rng: AtomicU64::new(seed | 1),
            health_clock: RwLock::new(system_now_ms),
            fail_open_picks: AtomicU64::new(0),
            events: events.cloned(),
        })
    }

    /// Hot-swap the endpoint set and/or algorithm (passive health
    /// disabled; see [`UpstreamLb::rebuild_with_health`]). Unchanged
    /// addresses keep their in-flight counters, WRR phase, slow-start
    /// entry instant, and health trackers; new addresses start fresh.
    /// Atomic; concurrent picks see either the old or the new set, never
    /// a mix.
    pub fn rebuild(&self, endpoints: &[Endpoint], algorithm: LoadBalancer, slow_start: Duration) {
        self.rebuild_with_health(endpoints, algorithm, slow_start, None);
    }

    /// `rebuild` with passive health parameters for the new generation
    /// (DW-012). Unchanged addresses keep their LIVE trackers (streak and
    /// observation window survive the reload); the new parameters apply
    /// to NEW observations only. Health state is carried per
    /// `address:port`, exactly like in-flight counters; removed endpoints
    /// drop their trackers outright and re-added ones start healthy with
    /// no history.
    pub fn rebuild_with_health(
        &self,
        endpoints: &[Endpoint],
        algorithm: LoadBalancer,
        slow_start: Duration,
        health: Option<&PassiveHealth>,
    ) {
        self.rebuild_with_health_and_events(endpoints, algorithm, slow_start, health, None);
    }

    /// `rebuild_with_health` with ejection/recovery events (DW-044):
    /// trackers created by THIS rebuild bind `events`; carried trackers
    /// keep their original binding (the emitter is per-dataplane and
    /// stable, so in practice the two agree). `None` behaves exactly
    /// like [`UpstreamLb::rebuild_with_health`].
    pub fn rebuild_with_health_and_events(
        &self,
        endpoints: &[Endpoint],
        algorithm: LoadBalancer,
        slow_start: Duration,
        health: Option<&PassiveHealth>,
        events: Option<&crate::events::UpstreamEmitter>,
    ) {
        let prev = self.state.load_full();
        let health = health.map(|h| Arc::new(HealthParams::from_config(h)));
        self.state.store(Arc::new(build_state(
            endpoints,
            algorithm,
            slow_start,
            Some(&prev),
            health,
            events,
        )));
    }

    /// DW-042: `rebuild_with_health_and_events` taking RESOLVED health
    /// parameters (`Arc<HealthParams>`) instead of the config form. The
    /// DNS discovery task reads the resolved parameters from the current
    /// LbState (via [`UpstreamLb::health_config`]) so a live endpoint-set
    /// swap uses the same health parameters as the initial build without
    /// re-resolving the config form.
    pub fn rebuild_with_resolved_health_and_events(
        &self,
        endpoints: &[Endpoint],
        algorithm: LoadBalancer,
        slow_start: Duration,
        health: Option<Arc<HealthParams>>,
        events: Option<&crate::events::UpstreamEmitter>,
    ) {
        let prev = self.state.load_full();
        self.state.store(Arc::new(build_state(
            endpoints,
            algorithm,
            slow_start,
            Some(&prev),
            health,
            events,
        )));
    }

    /// Current passive-health clock reading (Unix-epoch ms).
    pub fn now_ms(&self) -> u64 {
        (*self.health_clock.read().expect("health clock poisoned"))()
    }

    /// Replace the passive-health clock (Unix-epoch milliseconds; must be
    /// cheap). Intended for tests and other time-controlled setups — the
    /// same injection pattern as the rate limiter's clock (DW-004).
    /// Production code keeps the default system clock.
    pub fn set_health_clock(&self, clock: fn() -> u64) {
        *self.health_clock.write().expect("health clock poisoned") = clock;
    }

    /// Picks that served from the full endpoint set because every
    /// endpoint was ejected (fail-open). See `choose`.
    pub fn fail_open_picks(&self) -> u64 {
        self.fail_open_picks.load(Ordering::Relaxed)
    }

    /// Number of endpoints in the current set.
    pub fn len(&self) -> usize {
        self.state.load().endpoints.len()
    }

    /// Whether the current set is empty (only via unvalidated configs).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// DW-042: the load-balancing algorithm of the current state. The
    /// discovery task reads this so a live endpoint-set swap uses the
    /// same algorithm as the initial build.
    pub fn algorithm(&self) -> LoadBalancer {
        self.state.load().algorithm
    }

    /// DW-042: the slow-start window of the current state. The discovery
    /// task reads this so a live endpoint-set swap applies the same
    /// slow-start ramp as the initial build.
    pub fn slow_start(&self) -> Duration {
        self.state.load().slow_start
    }

    /// DW-042: the resolved passive-health parameters of the current
    /// state, if passive health is enabled. The discovery task reads
    /// this so a live endpoint-set swap creates health trackers with
    /// the same parameters as the initial build.
    pub fn health_config(&self) -> Option<Arc<HealthParams>> {
        self.state.load().health.clone()
    }

    /// DW-042: the upstream-scoped event emitter, if the balancer was
    /// built with one. The discovery task passes this to
    /// `rebuild_with_health_and_events` so new endpoints get
    /// event-bound health trackers.
    pub fn events(&self) -> Option<crate::events::UpstreamEmitter> {
        self.events.clone()
    }

    /// `address:port` of endpoint `idx` in the current set.
    pub fn endpoint(&self, idx: usize) -> Option<(String, u16)> {
        let s = self.state.load();
        s.endpoints.get(idx).map(|e| (e.address.clone(), e.port))
    }

    /// Every endpoint's `address:port` and passive-health tracker in the
    /// current set, in state order. Trackers are present only when the
    /// generation carries passive health (DW-012). This is the ACTIVE
    /// health engine's (DW-013) view: probe loops target a SPECIFIC
    /// endpoint and report into its live tracker, bypassing balancing.
    /// Single atomic state load, so address and tracker always correspond.
    pub fn health_targets(&self) -> Vec<(String, u16, Option<Arc<EndpointHealth>>)> {
        let s = self.state.load();
        s.endpoints
            .iter()
            .map(|e| (e.address.clone(), e.port, e.health.clone()))
            .collect()
    }

    /// Current in-flight count for endpoint `idx`.
    pub fn inflight(&self, idx: usize) -> u64 {
        self.state
            .load()
            .endpoints
            .get(idx)
            .map(|e| e.inflight.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Increment endpoint `idx`'s in-flight counter; returns a guard that
    /// decrements it on drop. Used by the upstream handle around dispatch.
    pub fn acquire_inflight(self: &Arc<Self>, idx: usize) -> Option<InflightGuard> {
        let state = self.state.load_full();
        state.endpoints.get(idx)?;
        state.endpoints[idx]
            .inflight
            .fetch_add(1, Ordering::Relaxed);
        Some(InflightGuard { state, idx })
    }

    /// Pick the endpoint index for one dispatch. `key` is the hash key
    /// (client IP) used by `ip_hash`; other algorithms ignore it. Lock-free.
    pub fn pick(&self, key: Option<&str>) -> Option<usize> {
        let state = self.state.load_full();
        self.choose(&state, key)
    }

    /// Single-load pick returning the index AND the endpoint's
    /// `address:port` from the SAME state snapshot (no reload can interleave
    /// between pick and resolution). For dispatch paths that do not need
    /// an in-flight guard (e.g. TLS passthrough).
    pub fn pick_endpoint(&self, key: Option<&str>) -> Option<(usize, String, u16)> {
        let state = self.state.load_full();
        let idx = self.choose(&state, key)?;
        state
            .endpoints
            .get(idx)
            .map(|e| (idx, e.address.clone(), e.port))
    }

    /// Single-load pick + in-flight acquisition: the algorithm choice, the
    /// endpoint resolution, and the counter increment all happen against
    /// ONE `ArcSwap` snapshot, so a concurrent rebuild cannot detach the
    /// guard from the endpoint it counted (the guard pins that snapshot).
    /// Prefer this over separate `pick`/`endpoint`/`acquire_inflight`
    /// calls on any dispatch path.
    pub fn pick_for_dispatch(self: &Arc<Self>, key: Option<&str>) -> Option<Dispatch> {
        let state = self.state.load_full();
        let idx = self.choose(&state, key)?;
        let e = state.endpoints.get(idx)?;
        e.inflight.fetch_add(1, Ordering::Relaxed);
        let health = match (&state.health, &e.health) {
            (Some(params), Some(tracker)) => Some(HealthDispatch {
                tracker: Arc::clone(tracker),
                params: Arc::clone(params),
            }),
            _ => None,
        };
        Some(Dispatch {
            idx,
            address: e.address.clone(),
            port: e.port,
            health,
            guard: InflightGuard { state, idx },
        })
    }

    /// Algorithm choice over one pinned snapshot; returns an endpoint
    /// index valid in `state`.
    ///
    /// Passive health (DW-012): when the generation carries health
    /// parameters, ejected endpoints leave the candidate set BEFORE the
    /// algorithm runs (all algorithms respect the filtered set; ip_hash
    /// walks the ring forward to the next healthy owner so keys stay as
    /// sticky as ejection allows). When EVERY endpoint is ejected, the
    /// candidate set falls back to the full set — fail-open rather than
    /// blackhole: a fully-ejected pool serving degraded traffic beats a
    /// gateway answering 503 for every request. Fail-open picks are
    /// counted ([`UpstreamLb::fail_open_picks`]) so operators can see the
    /// degraded state. Half-open endpoints join the candidate set and the
    /// endpoint a pick actually SELECTS consumes one trial slot (see
    /// `EndpointHealth::is_candidate` / `EndpointHealth::consume_probe`).
    ///
    /// Allocation discipline: the candidate set is `None` (= every
    /// endpoint index, walked by index — no heap allocation) whenever
    /// passive health is disabled or the pool fail-opens; only a genuinely
    /// filtered health path materializes a candidate `Vec`. The selected
    /// endpoint consumes its half-open probe slot on EVERY return path,
    /// including the single-candidate shortcut.
    fn choose(&self, state: &Arc<LbState>, key: Option<&str>) -> Option<usize> {
        if state.endpoints.is_empty() {
            return None;
        }
        let (cand, filtered) = match &state.health {
            Some(params) => {
                let now = self.now_ms();
                let avail: Vec<usize> = state
                    .endpoints
                    .iter()
                    .enumerate()
                    .filter(|(_, e)| {
                        e.health
                            .as_ref()
                            .is_none_or(|h| h.is_candidate(params, now))
                    })
                    .map(|(i, _)| i)
                    .collect();
                if avail.is_empty() {
                    self.fail_open_picks.fetch_add(1, Ordering::Relaxed);
                    (None, false)
                } else {
                    let filtered = avail.len() < state.endpoints.len();
                    (Some(avail), filtered)
                }
            }
            None => (None, false),
        };
        // Single candidate: no algorithm to run (random-2 needs two), but
        // a half-open selection still spends its probe slot.
        let n = cand.as_ref().map_or(state.endpoints.len(), Vec::len);
        if n == 1 {
            let idx = cand.as_deref().map_or(0, |c| c[0]);
            if let Some(h) = &state.endpoints[idx].health {
                h.consume_probe();
            }
            return Some(idx);
        }
        // Index view of the candidate set: `None` iterates 0..len
        // directly (allocation-free); `Some` maps through the slice.
        let resolve = |i: usize| cand.as_deref().map_or(i, |c| c[i]);
        let idx = match state.algorithm {
            LoadBalancer::RoundRobin => smooth_weighted_rr(state, cand.as_deref()),
            LoadBalancer::LeastRequests => (0..n)
                .map(resolve)
                .min_by_key(|&i| (state.endpoints[i].inflight.load(Ordering::Relaxed), i))
                .unwrap_or_else(|| resolve(0)),
            LoadBalancer::Random => {
                let a = (self.next_rand() % n as u64) as usize;
                let mut b = (self.next_rand() % (n as u64 - 1)) as usize;
                if b >= a {
                    b += 1; // a != b, uniform over the rest
                }
                let (ia, ib) = (&state.endpoints[resolve(a)], &state.endpoints[resolve(b)]);
                let (fa, fb) = (
                    ia.inflight.load(Ordering::Relaxed),
                    ib.inflight.load(Ordering::Relaxed),
                );
                if fa < fb {
                    resolve(a)
                } else if fb < fa {
                    resolve(b)
                } else {
                    resolve(a).min(resolve(b)) // ties: lower index, deterministic
                }
            }
            LoadBalancer::IpHash => match key {
                Some(k) => {
                    let h = key_hash(k);
                    // Membership set for the ring walk, built once per
                    // choose() when filtering is active: O(1) lookups
                    // instead of a linear scan per vnode visited.
                    let eligible_set: Option<Vec<bool>> = filtered.then(|| {
                        let mut set = vec![false; state.endpoints.len()];
                        for &i in cand.as_deref().unwrap_or(&[]) {
                            set[i] = true;
                        }
                        set
                    });
                    // Walk the ring from the key's hash; when filtering is
                    // active, skip ejected owners (and wrap) so the key
                    // lands on the next healthy endpoint instead of a
                    // black hole.
                    let eligible = |i: usize| eligible_set.as_ref().is_none_or(|set| set[i]);
                    state
                        .ring
                        .range(h..)
                        .find(|(_, &i)| eligible(i))
                        .map(|(_, &i)| i)
                        .or_else(|| {
                            state
                                .ring
                                .iter()
                                .find(|(_, &i)| eligible(i))
                                .map(|(_, &i)| i)
                        })
                        .unwrap_or_else(|| smooth_weighted_rr(state, cand.as_deref()))
                }
                None => smooth_weighted_rr(state, cand.as_deref()),
            },
        };
        // The SELECTED endpoint spends a half-open probe slot (no-op for
        // healthy endpoints; best-effort under races — see
        // `EndpointHealth::consume_probe`).
        if state.health.is_some() {
            if let Some(h) = &state.endpoints[idx].health {
                h.consume_probe();
            }
        }
        Some(idx)
    }

    /// CAS-loop xorshift draw for random-2.
    fn next_rand(&self) -> u64 {
        loop {
            let x = self.rng.load(Ordering::Relaxed);
            let nx = xorshift(x);
            if self
                .rng
                .compare_exchange(x, nx, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return nx;
            }
        }
    }
}

/// Drops => decrement of the endpoint's in-flight counter. Holds an `Arc`
/// to the state it counted in, so a concurrent rebuild never strays the
/// decrement onto a different endpoint set.
pub struct InflightGuard {
    state: Arc<LbState>,
    idx: usize,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.state.endpoints[self.idx]
            .inflight
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// One dispatch's pick: the endpoint chosen, its `address:port`, the
/// passive-health report handle (DW-012), and the in-flight guard for the
/// same snapshot the pick came from. Dropping the `Dispatch` (after the
/// response headers resolve) releases the guard.
pub struct Dispatch {
    /// Endpoint index in the snapshot the pick ran against (informational).
    pub idx: usize,
    /// Picked endpoint's address.
    pub address: String,
    /// Picked endpoint's port.
    pub port: u16,
    /// Passive health report handle for the picked endpoint, present only
    /// when the upstream configures `health`. The send path reports the
    /// outcome (transport error / status >= 500 = failure) when the
    /// response headers resolve.
    pub health: Option<HealthDispatch>,
    guard: InflightGuard,
}

impl Dispatch {
    /// Release the in-flight guard explicitly. Dropping the `Dispatch`
    /// has the same effect; this exists for call sites that want the
    /// release point named and to keep the guard field honest.
    pub fn release(self) {
        drop(self.guard);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn eps(specs: &[(&str, u16, u32)]) -> Vec<Endpoint> {
        specs
            .iter()
            .map(|&(a, p, w)| Endpoint {
                address: a.to_string(),
                port: p,
                weight: w,
            })
            .collect()
    }
    // --- slow start ---------------------------------------------------------

    #[test]
    fn slow_start_ramps_effective_weight_from_floor_to_full() {
        let spec = eps(&[("a", 1, 1), ("b", 2, 5)]);
        let lb = UpstreamLb::new(&spec, LoadBalancer::RoundRobin, Duration::from_secs(10));
        // All endpoints just entered: effective weights are the floor (1).
        // A full period therefore picks each endpoint exactly once.
        let picks: Vec<usize> = (0..2).map(|_| lb.pick(None).unwrap()).collect();
        assert_eq!(picks, vec![0, 1]);

        // Direct state inspection for the ramp endpoints: freshly entered
        // (weight 5) is at the floor; aged past the window is at full.
        let fresh = build_state(
            &spec,
            LoadBalancer::RoundRobin,
            Duration::from_secs(10),
            None,
            None,
            None,
        );
        assert_eq!(fresh.effective_weight(&fresh.endpoints[1]), 1);
        let mut aged = build_state(
            &spec,
            LoadBalancer::RoundRobin,
            Duration::from_secs(10),
            None,
            None,
            None,
        );
        for e in &mut aged.endpoints {
            e.entered = Instant::now() - Duration::from_secs(20);
        }
        assert_eq!(aged.effective_weight(&aged.endpoints[1]), 5);
        assert_eq!(aged.effective_weight(&aged.endpoints[0]), 1);

        // Slow start disabled (window 0): effective weight is the raw
        // configured weight from the first pick on.
        let off = build_state(
            &spec,
            LoadBalancer::RoundRobin,
            Duration::ZERO,
            None,
            None,
            None,
        );
        assert_eq!(off.effective_weight(&off.endpoints[1]), 5);
    }

    // --- WRR phase across a rebuild (#128) ---------------------------------
    //
    // White-box (stays in src like the slow-start test): the lost-phase
    // race is a pick mutating the OLD state snapshot's `current_weight`
    // while a rebuild has already copied state into a new generation.
    // `pick` loads and mutates within one call, so the interleave cannot
    // be forced through the public API — pinning the shared cell needs
    // private access to the pinned `Arc<LbState>` and `choose`.
    #[test]
    fn wrr_phase_cell_is_shared_across_rebuild() {
        let spec = eps(&[("a", 1, 2), ("b", 2, 1)]);
        let lb = UpstreamLb::new(&spec, LoadBalancer::RoundRobin, Duration::ZERO);
        // A pick holds the OLD snapshot across the rebuild (the shape of
        // `pick`/`pick_for_dispatch` running concurrently with a reload).
        let old = lb.state.load_full();
        lb.rebuild(&spec, LoadBalancer::RoundRobin, Duration::ZERO);
        let new = lb.state.load_full();
        for i in 0..new.endpoints.len() {
            assert!(
                Arc::ptr_eq(
                    &old.endpoints[i].current_weight,
                    &new.endpoints[i].current_weight
                ),
                "endpoint {i}: the WRR phase cell must be the SAME allocation \
                 across a rebuild, not a copied value"
            );
        }
        // The pick against the old snapshot mutates the shared cell: the
        // new generation observes the phase step (before #128 the old
        // snapshot's step was stranded and the copy went stale).
        let idx = lb.choose(&old, None).unwrap();
        assert_eq!(
            new.endpoints[idx].current_weight.load(Ordering::Relaxed),
            old.endpoints[idx].current_weight.load(Ordering::Relaxed),
            "a pick in flight against the old snapshot must advance the \
             phase the new generation reads"
        );
    }
}
