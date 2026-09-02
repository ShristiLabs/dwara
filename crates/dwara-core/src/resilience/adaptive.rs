//! Adaptive + origin-driven rate-limit tuning (DW-089).
//!
//! An [`AdaptiveController`] holds per-policy atomic EWMA state for the
//! upstream error rate and latency, plus a current adaptive factor that
//! scales a policy's rate-limit quotas at check time. The controller is
//! compiled once per config generation from the `policies[].adaptive`
//! blocks (only policies with `adaptive.enabled` contribute state); it
//! is shared via `Arc` from the dataplane generation and updated on the
//! response path (`record_outcome`), then read on the request path
//! (`factor_for`) — both lock-free, the same atomic-EWMA pattern as the
//! balancer's `PeakEwmaTracker` (in `dataplane::balance`).
//!
//! # Factor logic
//!
//! The adaptive factor is bounded `[min_factor, max_factor]` (never 0,
//! never unbounded). When the upstream is stressed (error EWMA above
//! `error_threshold` OR latency EWMA above `latency_threshold_ms`) the
//! factor DECREASES toward `min_factor` (tighten — each request "costs
//! more" against the GCRA bucket, so the effective rate drops). When the
//! upstream is healthy the factor INCREASES toward `max_factor` (relax —
//! each request "costs less", so the effective rate rises). Tightening
//! is faster than relaxing (asymmetric: `TIGHTEN_RATE` < 1.0 multiplies
//! the factor down by ~5% per stressed update, `RELAX_RATE` > 1.0
//! multiplies it up by ~1% per healthy update), so the gateway errs
//! toward protecting upstreams.
//!
//! # Origin signals
//!
//! When `retry_after` is in `origin_signals` and the upstream response
//! carries a `Retry-After` header, `record_outcome` sets a backoff
//! deadline (`now + retry_after_duration`) and drops the factor to
//! `min_factor` immediately. While within the backoff window,
//! `factor_for` returns `min_factor` regardless of the EWMA state; once
//! the window elapses the EWMA-driven factor resumes.
//!
//! # Atomic f64 storage
//!
//! Error EWMA, latency EWMA, the factor, and the backoff deadline are
//! stored as `AtomicU64` holding the bits of an `f64` (`f64::to_bits` /
//! `f64::from_bits`), exactly like the balancer's `PeakEwmaTracker`
//! `cost_ns`. The
//! stamp is nanoseconds since the Unix epoch (the same
//! `system_now_ns` clock the balancer uses). All loads/stores are
//! `Ordering::Relaxed`: the values are advisory (a stale factor merely
//! tightens or relaxes one request early), so the relaxed ordering is
//! correct and the hot path stays lock-free.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::config::{AdaptiveRateLimit, Gateway, OriginSignal};
use crate::observability::Observability;

/// Per-stressed-update multiplier: the factor shrinks toward `min_factor`
/// by this fraction each update while the upstream is stressed. ~5% per
/// update tightens fast (a sustained 5xx storm reaches the floor in
/// roughly `ln(min)/ln(0.95)` updates).
const TIGHTEN_RATE: f64 = 0.95;
/// Per-healthy-update multiplier: the factor grows toward `max_factor`
/// by this fraction each update while the upstream is healthy. ~1% per
/// update relaxes slowly (recovery is deliberately gentler than the
/// tightening that preceded it).
const RELAX_RATE: f64 = 1.01;

/// Unix-epoch nanosecond clock (the same clock the balancer's
/// PeakEwmaTracker uses). System clock in production; the stamp only
/// needs to be monotonic-ish for the decay delta.
fn system_now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Per-policy adaptive state (DW-089). All fields are atomic so
/// `record_outcome` (response path) and `factor_for` (request path) are
/// lock-free. The `f64` EWMA values and the factor are stored as bits in
/// `AtomicU64`; the backoff deadline is nanoseconds since the Unix epoch.
struct AdaptivePolicyState {
    config: AdaptiveRateLimit,
    /// EWMA of the error indicator (1.0 for a 5xx, 0.0 otherwise),
    /// stored as bits of an `f64` in `[0, 1]`.
    error_ewma: AtomicU64,
    /// EWMA of the upstream latency in milliseconds, stored as bits of
    /// an `f64`.
    latency_ewma: AtomicU64,
    /// Stamp of the last EWMA update (nanoseconds since the Unix epoch).
    stamp: AtomicU64,
    /// Current adaptive factor, stored as bits of an `f64` in
    /// `[min_factor, max_factor]`. Starts at 1.0 (the configured rate).
    factor: AtomicU64,
    /// Retry-After backoff deadline: nanoseconds since the Unix epoch
    /// until which `factor_for` returns `min_factor`. 0 when no backoff
    /// is in effect.
    retry_after_until: AtomicU64,
    /// Whether this policy honors the `retry_after` origin signal
    /// (cached from `config.origin_signals` for the hot path).
    honors_retry_after: bool,
    /// Nanosecond clock (system clock in production; a test may inject a
    /// controllable clock the same way `Breaker::with_clock` does).
    now_ns: fn() -> u64,
}

impl AdaptivePolicyState {
    fn new(config: AdaptiveRateLimit, now_ns: fn() -> u64) -> Self {
        let honors_retry_after = config
            .origin_signals
            .iter()
            .any(|s| matches!(s, OriginSignal::RetryAfter));
        let now = now_ns();
        AdaptivePolicyState {
            config,
            error_ewma: AtomicU64::new(0.0f64.to_bits()),
            latency_ewma: AtomicU64::new(0.0f64.to_bits()),
            stamp: AtomicU64::new(now),
            factor: AtomicU64::new(1.0f64.to_bits()),
            retry_after_until: AtomicU64::new(0),
            honors_retry_after,
            now_ns,
        }
    }

    /// Load the current factor, honoring an active Retry-After backoff
    /// window. Within the window the factor is `min_factor`; outside it
    /// the EWMA-driven factor applies.
    fn factor(&self) -> f64 {
        let now = (self.now_ns)();
        let until = self.retry_after_until.load(Ordering::Relaxed);
        if until > 0 && now < until {
            return self.config.min_factor;
        }
        f64::from_bits(self.factor.load(Ordering::Relaxed))
    }
}

/// EWMA-feedback-driven limiter tuning (DW-089). Compiled once per
/// config generation from the `policies[].adaptive` blocks; shared via
/// `Arc` from the dataplane generation. `record_outcome` runs on the
/// response path (after the upstream exchange resolves) and `factor_for`
/// runs on the request path (inside the rate-limit check) — both
/// lock-free. Policies without an enabled `adaptive` block are absent
/// from the map; `factor_for` returns `1.0` for them (no adaptive
/// tuning, the configured quotas apply as-is).
pub struct AdaptiveController {
    states: HashMap<String, AdaptivePolicyState>,
    /// Observability handle for the adaptive-factor / origin-signal /
    /// tighten / relax metrics. `None` only in direct unit-test
    /// construction; the dataplane always wires the real registry.
    obs: Option<Arc<Observability>>,
    /// Nanosecond clock (system clock in production; a test may inject a
    /// controllable clock via [`Self::compile_with_clock`]).
    now_ns: fn() -> u64,
}

impl std::fmt::Debug for AdaptiveController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdaptiveController")
            .field("policies", &self.states.len())
            .finish()
    }
}

impl AdaptiveController {
    /// New empty controller (no adaptive policies). The fast path:
    /// `factor_for` returns `1.0` for every policy.
    pub fn new() -> Self {
        AdaptiveController {
            states: HashMap::new(),
            obs: None,
            now_ns: system_now_ns,
        }
    }

    /// Compile the controller from a gateway's policies. Only policies
    /// with an `adaptive` block whose `enabled` is true contribute
    /// state; the rest are absent (their `factor_for` returns `1.0`).
    /// The observability handle wires the metric families; pass `None`
    /// for direct unit-test construction (metrics are then a no-op).
    pub fn compile(gateway: &Gateway, obs: Option<Arc<Observability>>) -> Self {
        Self::compile_with_clock(gateway, obs, system_now_ns)
    }

    /// [`Self::compile`] with a caller-supplied nanosecond clock (Unix
    /// epoch). Intended for tests that need to advance time deterministically
    /// (the same pattern as `Breaker::with_clock`); production keeps the
    /// system clock via [`Self::compile`].
    pub fn compile_with_clock(
        gateway: &Gateway,
        obs: Option<Arc<Observability>>,
        now_ns: fn() -> u64,
    ) -> Self {
        let mut states = HashMap::new();
        for policy in &gateway.policies {
            if let Some(cfg) = &policy.adaptive {
                if cfg.enabled {
                    states.insert(
                        policy.name.clone(),
                        AdaptivePolicyState::new(cfg.clone(), now_ns),
                    );
                }
            }
        }
        AdaptiveController {
            states,
            obs,
            now_ns,
        }
    }

    /// Whether any adaptive policy is compiled in at all (the fast path:
    /// configs with no adaptive policies skip the per-request factor
    /// lookup entirely).
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    /// The current adaptive factor for `policy_name`. Returns `1.0`
    /// (no tuning) when the policy has no adaptive block. Within an
    /// active Retry-After backoff window the factor is `min_factor`.
    pub fn factor_for(&self, policy_name: &str) -> f64 {
        match self.states.get(policy_name) {
            Some(state) => state.factor(),
            None => 1.0,
        }
    }

    /// Record one upstream outcome for `policy_name` (DW-089): update
    /// the error and latency EWMAs, apply any Retry-After backoff, and
    /// recompute the adaptive factor. A no-op when the policy has no
    /// adaptive block. `status` is the upstream HTTP status (5xx counts
    /// as an error); `latency` is the upstream round-trip; `retry_after`
    /// is the parsed `Retry-After` duration (only honored when
    /// `retry_after` is in the policy's `origin_signals`).
    pub fn record_outcome(
        &self,
        policy_name: &str,
        status: u16,
        latency: Duration,
        retry_after: Option<Duration>,
    ) {
        let Some(state) = self.states.get(policy_name) else {
            return;
        };
        let now = (self.now_ns)();
        let tau = (state.config.ewma_window_secs as f64) * 1e9;

        // Retry-After backoff: set the deadline and drop the factor to
        // min immediately (the EWMA-driven factor resumes once the
        // window elapses). Only honored when the policy opts in.
        if let Some(ra) = retry_after {
            if state.honors_retry_after {
                let until = now.saturating_add(ra.as_nanos() as u64);
                state.retry_after_until.store(until, Ordering::Relaxed);
                state
                    .factor
                    .store(state.config.min_factor.to_bits(), Ordering::Relaxed);
                if let Some(obs) = &self.obs {
                    obs.record_adaptive_origin_signal(policy_name, "retry_after");
                    obs.set_adaptive_factor(policy_name, state.config.min_factor);
                }
            }
        }

        // EWMA update: w = exp(-td / tau) decays the old value toward
        // the new observation. td is the time since the last update; a
        // first update (td ~ 0) keeps w near 1, so the EWMA seeds from
        // the first observation.
        let prev_stamp = state.stamp.load(Ordering::Relaxed);
        let td = now.saturating_sub(prev_stamp) as f64;
        let w = if tau > 0.0 { (-td / tau).exp() } else { 0.0 };
        let error = if status >= 500 { 1.0 } else { 0.0 };
        let prev_err = f64::from_bits(state.error_ewma.load(Ordering::Relaxed));
        let new_err = prev_err * w + error * (1.0 - w);
        state.error_ewma.store(new_err.to_bits(), Ordering::Relaxed);

        let latency_ms = latency.as_millis() as f64;
        let prev_lat = f64::from_bits(state.latency_ewma.load(Ordering::Relaxed));
        let new_lat = prev_lat * w + latency_ms * (1.0 - w);
        state
            .latency_ewma
            .store(new_lat.to_bits(), Ordering::Relaxed);
        state.stamp.store(now, Ordering::Relaxed);

        // Factor adjustment: stressed (error OR latency above
        // threshold) tightens; healthy relaxes. Tightening is faster
        // than relaxing (asymmetric). The factor is clamped to
        // [min_factor, max_factor] and never 0.
        let prev_factor = f64::from_bits(state.factor.load(Ordering::Relaxed));
        let stressed = new_err > state.config.error_threshold
            || new_lat > state.config.max_latency_threshold();
        let new_factor = if stressed {
            (prev_factor * TIGHTEN_RATE).max(state.config.min_factor)
        } else {
            (prev_factor * RELAX_RATE).min(state.config.max_factor)
        };
        // Within an active Retry-After window the factor stays at min.
        let until = state.retry_after_until.load(Ordering::Relaxed);
        let effective = if until > 0 && now < until {
            state.config.min_factor
        } else {
            new_factor
        };
        state.factor.store(effective.to_bits(), Ordering::Relaxed);

        // Metrics (resilience may import observability per the
        // dependency direction; the controller holds the handle so the
        // dataplane caller does not need to thread metrics back).
        if let Some(obs) = &self.obs {
            obs.set_adaptive_factor(policy_name, effective);
            if stressed && effective < prev_factor {
                obs.record_adaptive_tightened(policy_name);
            } else if !stressed && effective > prev_factor {
                obs.record_adaptive_relaxed(policy_name);
            }
        }
    }
}

impl Default for AdaptiveController {
    fn default() -> Self {
        AdaptiveController::new()
    }
}

/// Helper: the latency threshold as an `f64` (ms) for the comparison.
impl AdaptiveRateLimit {
    fn max_latency_threshold(&self) -> f64 {
        self.latency_threshold_ms as f64
    }
}
