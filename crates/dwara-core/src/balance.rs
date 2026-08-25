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
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;

use crate::config::{Endpoint, LoadBalancer};

/// Ketama vnode count per unit of endpoint weight (a weight-1 endpoint
/// gets 160 vnodes; a weight-w endpoint gets `160 * w` — footprint is
/// additive, so adding an endpoint never resizes existing segments).
pub const KETAMA_VNODES: u64 = 160;

/// Validation bound on total ip_hash ring size (`sum(weight) * 160`).
/// Keeps ring construction cheap and the BTreeMap small even for skewed
/// weight sets.
pub const MAX_RING_VNODES: u64 = 65_536;

/// Validation bound for `upstreams[].slow_start_ms` (10 minutes): the ramp
/// window is per-endpoint-entry, and unbounded windows would keep recycled
/// addresses permanently underweighted.
pub const MAX_SLOW_START_MS: u64 = 600_000;

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
    /// accumulator). Carried across rebuilds for unchanged addresses.
    current_weight: AtomicI64,
}

impl LbEndpoint {
    fn new(e: &Endpoint) -> Self {
        LbEndpoint {
            address: e.address.clone(),
            port: e.port,
            weight: e.weight.max(1),
            entered: Instant::now(),
            inflight: Arc::new(AtomicU64::new(0)),
            current_weight: AtomicI64::new(0),
        }
    }

    /// Same endpoint (address:port unchanged): keep live counters, WRR
    /// phase, and slow-start clock; take the new configured weight.
    fn carried_from(old: &LbEndpoint, e: &Endpoint) -> Self {
        LbEndpoint {
            address: old.address.clone(),
            port: old.port,
            weight: e.weight.max(1),
            entered: old.entered,
            inflight: Arc::clone(&old.inflight),
            current_weight: AtomicI64::new(old.current_weight.load(Ordering::Relaxed)),
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
}

fn xorshift(x: u64) -> u64 {
    let mut x = x.wrapping_add(0x9E3779B97F4A7C15);
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    x.wrapping_mul(0x2545F4914F6CDD1D)
}

fn build_state(
    endpoints: &[Endpoint],
    algorithm: LoadBalancer,
    slow_start: Duration,
    previous: Option<&LbState>,
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
    }
}

/// Ketama ring construction: vnode count is PER UNIT OF WEIGHT — endpoint
/// i gets `KETAMA_VNODES * weight_i` vnodes. Footprint is additive (no
/// max-normalization), so an endpoint's vnode positions never move when
/// another endpoint with a different weight joins or leaves: adding a
/// weight-w endpoint to total weight W remaps only ~w/(W+w) of keys, and
/// keys between unchanged endpoints stay put. Validation bounds the total
/// ring size at [`MAX_RING_VNODES`]. Collisions (same ring hash) keep the
/// later endpoint — harmless at 64-bit hash widths.
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
fn key_hash(key: &str) -> u64 {
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

/// Smooth weighted round-robin pick (nginx algorithm) over effective
/// weights. Period = sum of effective weights; over any full period each
/// endpoint is picked exactly its effective-weight many times.
fn smooth_weighted_rr(state: &LbState) -> usize {
    let mut total: i64 = 0;
    let mut best: usize = 0;
    let mut best_cw: i64 = i64::MIN;
    for (i, e) in state.endpoints.iter().enumerate() {
        let w = state.effective_weight(e);
        total += w;
        let cw = e.current_weight.fetch_add(w, Ordering::Relaxed) + w;
        // Strict >: ties keep the lowest index (deterministic).
        if cw > best_cw {
            best_cw = cw;
            best = i;
        }
    }
    if total <= 0 {
        // Unreachable for validated sets (weights >= 1); degrade to the
        // first endpoint rather than dividing by zero elsewhere.
        return 0;
    }
    state.endpoints[best]
        .current_weight
        .fetch_sub(total, Ordering::Relaxed);
    best
}

impl UpstreamLb {
    /// Build a balancer with a fresh endpoint set (all slow-start clocks
    /// start now).
    pub fn new(endpoints: &[Endpoint], algorithm: LoadBalancer, slow_start: Duration) -> Arc<Self> {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x853c49e6748fea9b)
            ^ (&endpoints as *const _ as u64)
            ^ std::process::id() as u64;
        Arc::new(UpstreamLb {
            state: ArcSwap::from_pointee(build_state(endpoints, algorithm, slow_start, None)),
            rng: AtomicU64::new(seed | 1),
        })
    }

    /// Hot-swap the endpoint set and/or algorithm: unchanged addresses
    /// keep their in-flight counters, WRR phase, and slow-start entry
    /// instant; new addresses start fresh. Atomic; concurrent picks see
    /// either the old or the new set, never a mix.
    pub fn rebuild(&self, endpoints: &[Endpoint], algorithm: LoadBalancer, slow_start: Duration) {
        let prev = self.state.load_full();
        self.state.store(Arc::new(build_state(
            endpoints,
            algorithm,
            slow_start,
            Some(&prev),
        )));
    }

    /// Number of endpoints in the current set.
    pub fn len(&self) -> usize {
        self.state.load().endpoints.len()
    }

    /// Whether the current set is empty (only via unvalidated configs).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `address:port` of endpoint `idx` in the current set.
    pub fn endpoint(&self, idx: usize) -> Option<(String, u16)> {
        let s = self.state.load();
        s.endpoints.get(idx).map(|e| (e.address.clone(), e.port))
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
        Some(Dispatch {
            idx,
            address: e.address.clone(),
            port: e.port,
            guard: InflightGuard { state, idx },
        })
    }

    /// Algorithm choice over one pinned snapshot; returns an endpoint
    /// index valid in `state`.
    fn choose(&self, state: &Arc<LbState>, key: Option<&str>) -> Option<usize> {
        if state.endpoints.is_empty() {
            return None;
        }
        if state.endpoints.len() == 1 {
            return Some(0);
        }
        let idx = match state.algorithm {
            LoadBalancer::RoundRobin => smooth_weighted_rr(state),
            LoadBalancer::LeastRequests => state
                .endpoints
                .iter()
                .enumerate()
                .min_by_key(|(i, e)| (e.inflight.load(Ordering::Relaxed), *i))
                .map(|(i, _)| i)
                .unwrap_or(0),
            LoadBalancer::Random => {
                let n = state.endpoints.len();
                let a = (self.next_rand() % n as u64) as usize;
                let mut b = (self.next_rand() % (n as u64 - 1)) as usize;
                if b >= a {
                    b += 1; // a != b, uniform over the rest
                }
                let (ia, ib) = (&state.endpoints[a], &state.endpoints[b]);
                let (fa, fb) = (
                    ia.inflight.load(Ordering::Relaxed),
                    ib.inflight.load(Ordering::Relaxed),
                );
                if fa < fb {
                    a
                } else if fb < fa {
                    b
                } else {
                    a.min(b) // ties: lower index, deterministic
                }
            }
            LoadBalancer::IpHash => match key {
                Some(k) => {
                    let h = key_hash(k);
                    state
                        .ring
                        .range(h..)
                        .next()
                        .or_else(|| state.ring.iter().next())
                        .map(|(_, &i)| i)
                        .unwrap_or_else(|| smooth_weighted_rr(state))
                }
                None => smooth_weighted_rr(state),
            },
        };
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

/// One dispatch's pick: the endpoint chosen, its `address:port`, and the
/// in-flight guard for the same snapshot the pick came from. Dropping the
/// `Dispatch` (after the response headers resolve) releases the guard.
pub struct Dispatch {
    /// Endpoint index in the snapshot the pick ran against (informational).
    pub idx: usize,
    /// Picked endpoint's address.
    pub address: String,
    /// Picked endpoint's port.
    pub port: u16,
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
    use crate::config::{Gateway, Upstream as ConfigUpstream};
    use crate::proxy::DataPlane;
    use crate::snapshot::ConfigState;
    use proptest::prelude::*;

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

    /// Endpoints `prefix{i}` (i = 0..n) with the given weights.
    fn eps_from_weights(prefix: &str, weights: &[u32]) -> Vec<Endpoint> {
        weights
            .iter()
            .enumerate()
            .map(|(i, &w)| Endpoint {
                address: format!("{prefix}{i}"),
                port: 80,
                weight: w,
            })
            .collect()
    }

    // --- smooth weighted round-robin --------------------------------------

    #[test]
    fn smooth_rr_classic_5_1_interleave() {
        // The canonical nginx example: a(5) b(1) c(1) -> a a b a c a a.
        let lb = UpstreamLb::new(
            &eps(&[
                ("10.0.0.1", 80, 5),
                ("10.0.0.2", 80, 1),
                ("10.0.0.3", 80, 1),
            ]),
            LoadBalancer::RoundRobin,
            Duration::ZERO,
        );
        let picks: Vec<usize> = (0..7).map(|_| lb.pick(None).unwrap()).collect();
        assert_eq!(picks, vec![0, 0, 1, 0, 2, 0, 0]);
    }

    proptest! {
        #[test]
        fn smooth_rr_period_counts_match_weights(
            weights in prop::collection::vec(1u32..=5, 2..=6)
        ) {
            let total: u32 = weights.iter().sum();
            let lb = UpstreamLb::new(
                &eps_from_weights("10.0.0.", &weights),
                LoadBalancer::RoundRobin,
                Duration::ZERO,
            );
            let mut counts = vec![0u32; weights.len()];
            for _ in 0..total {
                counts[lb.pick(None).unwrap()] += 1;
            }
            prop_assert_eq!(counts, weights);
        }

        #[test]
        fn smooth_rr_deterministic_sequence(
            weights in prop::collection::vec(1u32..=4, 2..=5)
        ) {
            let total: u32 = weights.iter().sum();
            let a = UpstreamLb::new(
                &eps_from_weights("10.1.0.", &weights),
                LoadBalancer::RoundRobin,
                Duration::ZERO,
            );
            let b = UpstreamLb::new(
                &eps_from_weights("10.1.0.", &weights),
                LoadBalancer::RoundRobin,
                Duration::ZERO,
            );
            let sa: Vec<usize> = (0..total).map(|_| a.pick(None).unwrap()).collect();
            let sb: Vec<usize> = (0..total).map(|_| b.pick(None).unwrap()).collect();
            prop_assert_eq!(sa, sb);
        }
    }

    // --- least connections --------------------------------------------------

    #[test]
    fn least_conn_picks_minimal_inflight_with_lowest_index_ties() {
        let lb = UpstreamLb::new(
            &eps(&[("a", 1, 1), ("b", 2, 1), ("c", 3, 1)]),
            LoadBalancer::LeastRequests,
            Duration::ZERO,
        );
        let _g0 = lb.acquire_inflight(0).unwrap();
        let _g2 = lb.acquire_inflight(2).unwrap();
        let _g2b = lb.acquire_inflight(2).unwrap();
        assert_eq!(lb.pick(None), Some(1), "endpoint 1 has zero inflight");
        drop(_g0);
        drop(_g2b);
        assert_eq!(lb.pick(None), Some(0), "0 and 2 tie at 1; lowest index");
        drop(_g2);
        // All-zero tie: lowest index, and guards returned to zero.
        assert_eq!(lb.inflight(2), 0);
        assert_eq!(lb.pick(None), Some(0));
    }

    proptest! {
        #[test]
        fn least_conn_always_minimal(
            inflight in prop::collection::vec(0u64..=7, 2..=6)
        ) {
            let n = inflight.len();
            let list = eps_from_weights("ep-", &vec![1u32; n]);
            let lb = UpstreamLb::new(&list, LoadBalancer::LeastRequests, Duration::ZERO);
            let guards: Vec<_> = (0..inflight.len()).flat_map(|i| {
                (0..inflight[i]).map(|_| lb.acquire_inflight(i).unwrap()).collect::<Vec<_>>()
            }).collect();
            let want = inflight.iter().enumerate().min_by_key(|(i, &v)| (v, *i)).unwrap().0;
            for _ in 0..20 {
                prop_assert_eq!(lb.pick(None), Some(want));
            }
            drop(guards);
        }
    }

    // --- random-2 -----------------------------------------------------------

    #[test]
    fn random_two_picks_lower_inflight_of_two_endpoints() {
        let lb = UpstreamLb::new(
            &eps(&[("a", 1, 1), ("b", 2, 1)]),
            LoadBalancer::Random,
            Duration::ZERO,
        );
        let g = lb.acquire_inflight(1).unwrap();
        for _ in 0..200 {
            assert_eq!(lb.pick(None), Some(0), "endpoint 0 has lower inflight");
        }
        drop(g);
    }

    // --- ketama / ip_hash ---------------------------------------------------

    fn owned_keys(lb: &UpstreamLb, keys: &[String]) -> Vec<usize> {
        keys.iter()
            .map(|k| lb.pick(Some(k.as_str())).unwrap())
            .collect()
    }

    proptest! {
        #[test]
        fn ketama_remap_on_addition_is_minimal(n in 2usize..=6) {
            let keys: Vec<String> = (0..400).map(|i| format!("203.0.113.{i}")).collect();
            let spec = eps_from_weights("10.2.0.", &vec![1u32; n]);
            let lb = UpstreamLb::new(&spec, LoadBalancer::IpHash, Duration::ZERO);
            let before = owned_keys(&lb, &keys);
            // Add one endpoint: only keys whose ring segment was taken by
            // the newcomer (~1/(n+1)) may remap.
            let mut grown = spec.clone();
            grown.push(Endpoint {
                address: format!("10.2.0.{n}"),
                port: 80,
                weight: 1,
            });
            lb.rebuild(&grown, LoadBalancer::IpHash, Duration::ZERO);
            let after = owned_keys(&lb, &keys);
            let remapped = before.iter().zip(&after).filter(|(a, b)| a != b).count();
            let bound = (keys.len() * 2 / (n + 1)).max(8);
            prop_assert!(
                remapped <= bound,
                "remapped {remapped} of {} adding 1 to {n}",
                keys.len()
            );
        }

        #[test]
        fn ketama_distribution_uniform_within_tolerance(n in 2usize..=4) {
            let keys: Vec<String> = (0..800).map(|i| format!("198.51.100.{i}")).collect();
            let spec = eps_from_weights("10.3.0.", &vec![1u32; n]);
            let lb = UpstreamLb::new(&spec, LoadBalancer::IpHash, Duration::ZERO);
            let owners = owned_keys(&lb, &keys);
            let ideal = 1.0f64 / n as f64;
            for i in 0..n {
                let share =
                    owners.iter().filter(|&&o| o == i).count() as f64 / keys.len() as f64;
                prop_assert!(
                    (share - ideal).abs() < 0.2,
                    "endpoint {i} share {share:.3} vs ideal {ideal:.3}"
                );
            }
        }
    }

    #[test]
    fn ketama_same_key_is_sticky_and_weights_skew_distribution() {
        let spec = eps(&[("a", 1, 1), ("b", 2, 3)]);
        let lb = UpstreamLb::new(&spec, LoadBalancer::IpHash, Duration::ZERO);
        let first = lb.pick(Some("203.0.113.9"));
        assert_eq!(lb.pick(Some("203.0.113.9")), first);
        // Weighted vnodes: the weight-3 endpoint should own the clear
        // majority of keys.
        let keys: Vec<String> = (0..300).map(|i| format!("192.0.2.{i}")).collect();
        let owned_b = owned_keys(&lb, &keys).iter().filter(|&&o| o == 1).count();
        assert!(owned_b > 150, "weight-3 endpoint owned only {owned_b}/300");
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
        );
        assert_eq!(fresh.effective_weight(&fresh.endpoints[1]), 1);
        let mut aged = build_state(
            &spec,
            LoadBalancer::RoundRobin,
            Duration::from_secs(10),
            None,
        );
        for e in &mut aged.endpoints {
            e.entered = Instant::now() - Duration::from_secs(20);
        }
        assert_eq!(aged.effective_weight(&aged.endpoints[1]), 5);
        assert_eq!(aged.effective_weight(&aged.endpoints[0]), 1);

        // Slow start disabled (window 0): effective weight is the raw
        // configured weight from the first pick on.
        let off = build_state(&spec, LoadBalancer::RoundRobin, Duration::ZERO, None);
        assert_eq!(off.effective_weight(&off.endpoints[1]), 5);
    }

    // --- hot swap / carry-over ----------------------------------------------

    #[test]
    fn rebuild_carries_wrr_phase_and_inflight_for_unchanged_addresses() {
        let spec = eps(&[("a", 1, 2), ("b", 2, 1)]);
        let lb = UpstreamLb::new(&spec, LoadBalancer::RoundRobin, Duration::ZERO);
        // Fresh sequence for (2,1): a b a | a b a.
        assert_eq!(lb.pick(None), Some(0));
        let guard = lb.acquire_inflight(0).unwrap();
        // Same-set rebuild: phase and inflight carry; the next picks must
        // CONTINUE the sequence (b a), not restart it (a b).
        lb.rebuild(&spec, LoadBalancer::RoundRobin, Duration::ZERO);
        assert_eq!(lb.inflight(0), 1);
        assert_eq!(lb.pick(None), Some(1));
        assert_eq!(lb.pick(None), Some(0));
        drop(guard);
        assert_eq!(lb.inflight(0), 0);
    }

    #[test]
    fn rebuild_with_new_weights_takes_effect_immediately() {
        let spec = eps(&[("a", 1, 2), ("b", 2, 1)]);
        let lb = UpstreamLb::new(&spec, LoadBalancer::RoundRobin, Duration::ZERO);
        let _ = lb.pick(None);
        let reweighted = eps(&[("a", 1, 1), ("b", 2, 2)]);
        lb.rebuild(&reweighted, LoadBalancer::RoundRobin, Duration::ZERO);
        let mut counts = [0u32; 2];
        for _ in 0..3 {
            counts[lb.pick(None).unwrap()] += 1;
        }
        assert_eq!(counts, [1, 2], "new weights apply without restart");
    }

    #[test]
    fn rebuild_resets_state_for_removed_and_readded_endpoints() {
        let spec = eps(&[("a", 1, 1), ("b", 2, 1)]);
        let lb = UpstreamLb::new(&spec, LoadBalancer::RoundRobin, Duration::ZERO);
        let _ = lb.pick(None);
        let _g = lb.acquire_inflight(1).unwrap();
        // Drop endpoint b (its inflight leaves with it), re-add later: fresh.
        lb.rebuild(
            &eps(&[("a", 1, 1)]),
            LoadBalancer::RoundRobin,
            Duration::ZERO,
        );
        assert_eq!(lb.len(), 1);
        assert_eq!(lb.pick(None), Some(0));
        lb.rebuild(&spec, LoadBalancer::RoundRobin, Duration::ZERO);
        assert_eq!(lb.inflight(1), 0, "re-added endpoint starts fresh");
    }

    // --- integration through DataPlane (weights change via publish) ---------

    fn upstream_with_weights(w: (u32, u32)) -> ConfigUpstream {
        use crate::config::{Timeouts, UpstreamProtocol};
        ConfigUpstream {
            name: "pool".into(),
            load_balancer: LoadBalancer::RoundRobin,
            protocol: UpstreamProtocol::Http1,
            endpoints: vec![
                Endpoint {
                    address: "10.9.0.1".into(),
                    port: 80,
                    weight: w.0,
                },
                Endpoint {
                    address: "10.9.0.2".into(),
                    port: 80,
                    weight: w.1,
                },
            ],
            connection_cap: None,
            timeouts: Some(Timeouts {
                connect_ms: Some(60000),
                read_ms: None,
                write_ms: None,
            }),
            slow_start_ms: None,
        }
    }

    #[tokio::test]
    async fn dataplane_reload_changes_weights_without_restart() {
        let st = Arc::new(ConfigState::new());
        let mut g = Gateway {
            trusted_proxies: vec![],
            listeners: vec![],
            routes: vec![],
            services: vec![],
            upstreams: vec![upstream_with_weights((2, 1))],
            consumers: vec![],
            policies: vec![],
        };
        st.compile_and_publish(&g).expect("publish A");
        let dp = DataPlane::new(Arc::clone(&st));
        let h = dp.registry().get("pool").unwrap();
        let mut c1 = [0u32; 2];
        for _ in 0..3 {
            c1[h.lb().pick(None).unwrap()] += 1;
        }
        assert_eq!(c1, [2, 1], "original weights");

        // The reload flow: publish new weights on the SAME state, then
        // refresh the dataplane (what dwara-bin's reload path does).
        g.upstreams = vec![upstream_with_weights((1, 2))];
        st.compile_and_publish(&g).expect("publish B");
        dp.refresh();
        let h2 = dp.registry().get("pool").unwrap();
        let mut c2 = [0u32; 2];
        for _ in 0..3 {
            c2[h2.lb().pick(None).unwrap()] += 1;
        }
        assert_eq!(c2, [1, 2], "weights changed without restart");
    }
}
