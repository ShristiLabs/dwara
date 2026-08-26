//! Per-upstream circuit breaker (DW-015, feature analysis 4.11).
//!
//! # What it is
//!
//! The breaker gates an ENTIRE upstream (all endpoints) when that upstream
//! is failing as a whole. It is a different layer from DW-012 per-ENDPOINT
//! ejection: ejection removes individual endpoints from load-balancer
//! rotation, the breaker stops sending ANY traffic to the upstream for a
//! cooling-off period. When every endpoint is ejected the balancer
//! fail-opens and picks anyway (DW-012); that pick still flows THROUGH the
//! breaker — the breaker gates the upstream, ejection gates endpoints
//! within it. The two never consume each other's state: an open breaker
//! short-circuits before the balancer is consulted, so a breaker-open
//! period ejects nothing (passive health sees no traffic, hence no
//! failures, hence no ejections), and ejections never open the breaker.
//!
//! # States and transitions
//!
//! - **Closed** (healthy): requests flow. Failures are counted two ways —
//!   a consecutive-failure streak and a rolling-window error ratio. The
//!   breaker OPENS when either trips: the streak reaches
//!   `consecutive_failures` (default 5), or the window holds at least
//!   `error_volume` (default 20) observations AND
//!   `failures / observations >= error_ratio` (default 0.5). The window is
//!   60 seconds, the same rolling-event pattern as the retry budget.
//! - **Open** (tripped): every request fails fast with `503` (body
//!   "upstream circuit open") and a `Retry-After` header carrying the
//!   whole seconds until half-open (rounded up, minimum 1). No attempts
//!   are made — no endpoint pick, no retries. Requests already in flight
//!   when the breaker opened complete normally (documented).
//! - **HalfOpen** (probing): after `open_ms` (default 30000) the next
//!   request is admitted as a trial probe (up to `half_open_probes`
//!   concurrent probes, default 1). A successful probe CLOSES the breaker
//!   (all counters reset, window cleared); a failed probe re-OPENS it for
//!   another `open_ms`. While all probes are in flight, further requests
//!   fail fast like Open (Retry-After: 1 second, the documented probing
//!   hint — exact half-open time is unknowable while a probe runs).
//!   A retried request consumes one half-open probe slot per attempt:
//!   each attempt is a trial.
//!
//! # Observation points
//!
//! The breaker is evaluated at the SAME observation points as passive
//! health: when an attempt's response HEADERS resolve — transport errors
//! and statuses >= 500 are failures, everything else (1xx-4xx) is a
//! success and counts toward the ratio denominator. Every retry attempt
//! reports too (each attempt is a real exchange with the upstream). A
//! mid-BODY abort after headers resolved does not open the breaker: the
//! exchange was classified at header time (it is still reported to
//! endpoint health per DW-014).
//!
//! Failure classification is intentionally identical to passive health so
//! operators reason about one notion of "failure" across both layers.
//!
//! Timing is wall-clock (`SystemTime`): an NTP step can lengthen or
//! shorten a wall-clock Open period.
//!
//! # Reload semantics
//!
//! Breaker STATE (current state, streak, window) is carried across config
//! reloads keyed by upstream name — exactly like balancer state and the
//! retry budget. Breaker PARAMETERS apply from the new config
//! (`BreakerParams` is resolved per generation, `Breaker` holds state
//! only, and every method takes the params explicitly — the same
//! split as `RetryParams`/`RetryBudget`).

use std::collections::VecDeque;
// DW-025: loom-model-checked Mutex under the `loom` dev feature.
#[cfg(feature = "loom")]
use loom::sync::Mutex;
#[cfg(not(feature = "loom"))]
use std::sync::Mutex;

use crate::config::BreakerConfig;

/// Rolling window the error ratio accounts over (milliseconds).
pub const BREAKER_WINDOW_MS: u64 = 60_000;
/// Retry-After (milliseconds) advertised while half-open probes are in
/// flight (exact half-open time is unknowable until a probe resolves).
pub const HALF_OPEN_RETRY_AFTER_MS: u64 = 1_000;

/// Resolved (validated) breaker parameters for one upstream. `None` on the
/// upstream handle disables the breaker entirely — the no-config behavior
/// is bit-identical to pre-DW-015.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BreakerParams {
    /// Consecutive failures (5xx + transport) that trip the breaker.
    pub consecutive_failures: u32,
    /// Error ratio in (0, 1] that trips the breaker once `error_volume`
    /// observations are in the window.
    pub error_ratio: f64,
    /// Minimum in-window observations before the ratio is evaluated.
    pub error_volume: u32,
    /// Cooling-off period before a half-open probe is admitted.
    pub open_ms: u64,
    /// Concurrent trial requests admitted in half-open.
    pub half_open_probes: u32,
}

impl BreakerParams {
    /// Resolve from the config form; `None` keeps the disabled state the
    /// caller represents separately (serde applies per-field defaults for a
    /// present block).
    pub fn from_config(cfg: &BreakerConfig) -> Self {
        BreakerParams {
            consecutive_failures: cfg.consecutive_failures,
            error_ratio: cfg.error_ratio,
            error_volume: cfg.error_volume,
            open_ms: cfg.open_ms,
            half_open_probes: cfg.half_open_probes,
        }
    }
}

/// Admission decision for one request about to be dispatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerDecision {
    /// The request may proceed to the upstream.
    Allow,
    /// Fail fast; `retry_after_ms` is the advertised cooling hint.
    Reject { retry_after_ms: u64 },
}

/// Breaker state snapshot (observability/tests).
#[derive(Debug, Clone, PartialEq)]
pub enum BreakerState {
    /// Healthy; `consecutive` is the current failure streak.
    Closed { consecutive: u32 },
    /// Tripped until `until_ms` (Unix epoch milliseconds).
    Open { until_ms: u64 },
    /// Probing; `probes_left` trial requests may still be admitted.
    HalfOpen { probes_left: u32 },
}

struct BreakerInner {
    state: BreakerState,
    window: VecDeque<(u64, bool)>,
}

/// Per-upstream circuit breaker state (see the module docs). Share via
/// `Arc` from the upstream handle; the lock is taken once per attempt
/// (report) and once per request admission (check).
pub struct Breaker {
    now_ms: fn() -> u64,
    inner: Mutex<BreakerInner>,
}

fn system_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Default for Breaker {
    fn default() -> Self {
        Breaker::new()
    }
}

impl Breaker {
    /// New closed breaker on the system clock.
    pub fn new() -> Self {
        Breaker::with_clock(system_now_ms)
    }

    /// New closed breaker with a caller-supplied millisecond clock (Unix
    /// epoch). Intended for tests; production keeps the system clock.
    pub fn with_clock(now_ms: fn() -> u64) -> Self {
        Breaker {
            now_ms,
            inner: Mutex::new(BreakerInner {
                state: BreakerState::Closed { consecutive: 0 },
                window: VecDeque::new(),
            }),
        }
    }

    fn prune_locked(inner: &mut BreakerInner, now: u64) {
        while inner
            .window
            .front()
            .is_some_and(|&(t, _)| now.saturating_sub(t) >= BREAKER_WINDOW_MS)
        {
            inner.window.pop_front();
        }
    }

    /// Whether this request may be dispatched to the upstream. Transitions
    /// Open -> HalfOpen when the cooling-off has elapsed (the caller's
    /// request becomes a trial probe) and consumes one probe slot.
    pub fn check(&self, params: &BreakerParams) -> BreakerDecision {
        let now = (self.now_ms)();
        let mut inner = self.inner.lock().expect("breaker poisoned");
        Self::prune_locked(&mut inner, now);
        match inner.state {
            BreakerState::Closed { .. } => BreakerDecision::Allow,
            BreakerState::Open { until_ms } => {
                if now < until_ms {
                    BreakerDecision::Reject {
                        retry_after_ms: until_ms - now,
                    }
                } else {
                    inner.state = BreakerState::HalfOpen {
                        probes_left: params.half_open_probes.saturating_sub(1),
                    };
                    BreakerDecision::Allow
                }
            }
            BreakerState::HalfOpen { probes_left } => {
                if probes_left == 0 {
                    BreakerDecision::Reject {
                        retry_after_ms: HALF_OPEN_RETRY_AFTER_MS,
                    }
                } else {
                    inner.state = BreakerState::HalfOpen {
                        probes_left: probes_left - 1,
                    };
                    BreakerDecision::Allow
                }
            }
        }
    }

    /// Report one attempt outcome (observed at response-header
    /// resolution; `failed` = transport error or status >= 500). Drives
    /// every state transition; see the module docs.
    pub fn report(&self, params: &BreakerParams, failed: bool) {
        let now = (self.now_ms)();
        let mut inner = self.inner.lock().expect("breaker poisoned");
        Self::prune_locked(&mut inner, now);
        inner.window.push_back((now, failed));
        match inner.state {
            BreakerState::Closed { consecutive } => {
                if !failed {
                    inner.state = BreakerState::Closed { consecutive: 0 };
                    return;
                }
                let streak = consecutive + 1;
                let total = inner.window.len() as u64;
                let failures = inner.window.iter().filter(|(_, f)| *f).count() as u64;
                let tripped = streak >= params.consecutive_failures
                    || (total >= u64::from(params.error_volume)
                        && failures as f64 / total as f64 >= params.error_ratio);
                if tripped {
                    inner.state = BreakerState::Open {
                        until_ms: now.saturating_add(params.open_ms),
                    };
                } else {
                    inner.state = BreakerState::Closed {
                        consecutive: streak,
                    };
                }
            }
            BreakerState::HalfOpen { .. } => {
                if failed {
                    // A failed probe re-opens for another full cool-off.
                    inner.state = BreakerState::Open {
                        until_ms: now.saturating_add(params.open_ms),
                    };
                } else {
                    // A successful probe closes and RESETS counters (the
                    // window too): stale pre-trip failures must not
                    // instantly re-trip the ratio.
                    inner.state = BreakerState::Closed { consecutive: 0 };
                    inner.window.clear();
                }
            }
            BreakerState::Open { .. } => {
                // In-flight requests (admitted before the trip) still
                // report; their outcomes land in the window but cannot
                // change an already-open state.
            }
        }
    }

    /// Current state (observability/tests).
    pub fn state(&self) -> BreakerState {
        let now = (self.now_ms)();
        let mut inner = self.inner.lock().expect("breaker poisoned");
        Self::prune_locked(&mut inner, now);
        inner.state.clone()
    }

    /// In-window observation totals (observability/tests).
    pub fn totals(&self) -> usize {
        let now = (self.now_ms)();
        let mut inner = self.inner.lock().expect("breaker poisoned");
        Self::prune_locked(&mut inner, now);
        inner.window.len()
    }

    /// In-window failures (observability/tests).
    pub fn failures(&self) -> usize {
        let now = (self.now_ms)();
        let mut inner = self.inner.lock().expect("breaker poisoned");
        Self::prune_locked(&mut inner, now);
        inner.window.iter().filter(|(_, f)| *f).count()
    }
}

impl std::fmt::Debug for Breaker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Breaker")
            .field("state", &self.state())
            .field("totals", &self.totals())
            .field("failures", &self.failures())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn params() -> BreakerParams {
        BreakerParams {
            consecutive_failures: 5,
            error_ratio: 0.5,
            error_volume: 20,
            open_ms: 30_000,
            half_open_probes: 1,
        }
    }

    #[test]
    fn opens_on_consecutive_failures_and_fails_fast() {
        static NOW: AtomicU64 = AtomicU64::new(1_000);
        let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
        let p = params();
        for _ in 0..4 {
            assert_eq!(b.check(&p), BreakerDecision::Allow);
            b.report(&p, true);
            assert!(matches!(b.state(), BreakerState::Closed { .. }));
        }
        // 5th consecutive failure trips it.
        b.report(&p, true);
        assert!(matches!(b.state(), BreakerState::Open { .. }));
        let BreakerDecision::Reject { retry_after_ms } = b.check(&p) else {
            panic!("open breaker must reject");
        };
        assert_eq!(retry_after_ms, 30_000);
    }

    #[test]
    fn success_resets_the_streak() {
        static NOW: AtomicU64 = AtomicU64::new(1_000);
        let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
        let p = params();
        for _ in 0..4 {
            b.report(&p, true);
        }
        b.report(&p, false);
        assert!(matches!(b.state(), BreakerState::Closed { consecutive: 0 }));
        // Four more failures after the reset do not trip (streak restarted).
        for _ in 0..4 {
            b.report(&p, true);
        }
        assert!(matches!(b.state(), BreakerState::Closed { .. }));
    }

    #[test]
    fn opens_on_ratio_with_volume() {
        static NOW: AtomicU64 = AtomicU64::new(1_000);
        let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
        let p = params();
        // 9 failures + 10 successes = 19 observations at ~47% < 50%: not
        // tripped, and below volume anyway.
        for i in 0..19 {
            b.report(&p, i % 2 == 0);
        }
        assert!(matches!(b.state(), BreakerState::Closed { .. }));
        // 20th observation is a failure: 10/20 = 50% with volume 20.
        b.report(&p, true);
        assert!(matches!(b.state(), BreakerState::Open { .. }));
    }

    #[test]
    fn ratio_needs_volume_even_when_high() {
        static NOW: AtomicU64 = AtomicU64::new(1_000);
        let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
        let p = params();
        // Streak below 5 cannot trip via ratio either (4 < 5): with volume
        // 20, 4/4 = 100% ratio still does not trip.
        for _ in 0..4 {
            b.report(&p, true);
        }
        assert!(matches!(b.state(), BreakerState::Closed { .. }));
    }

    #[test]
    fn half_open_probe_closes_on_success() {
        static NOW: AtomicU64 = AtomicU64::new(1_000);
        let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
        let p = params();
        for _ in 0..5 {
            b.report(&p, true);
        }
        assert!(matches!(b.state(), BreakerState::Open { .. }));
        // Before the cool-off: rejected with the remaining time.
        let BreakerDecision::Reject { retry_after_ms } = b.check(&p) else {
            panic!("must reject while open");
        };
        assert_eq!(retry_after_ms, 30_000);
        // Advance past open_ms: the same check admits a probe.
        NOW.store(31_001, Ordering::Relaxed);
        assert_eq!(b.check(&p), BreakerDecision::Allow);
        assert!(matches!(
            b.state(),
            BreakerState::HalfOpen { probes_left: 0 }
        ));
        // Probe succeeds: closed, counters reset.
        b.report(&p, false);
        assert!(matches!(b.state(), BreakerState::Closed { consecutive: 0 }));
        assert_eq!(b.totals(), 0, "window cleared on close");
    }

    #[test]
    fn half_open_probe_failure_reopens() {
        static NOW: AtomicU64 = AtomicU64::new(1_000);
        let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
        let p = params();
        for _ in 0..5 {
            b.report(&p, true);
        }
        NOW.store(31_000, Ordering::Relaxed);
        assert_eq!(b.check(&p), BreakerDecision::Allow);
        b.report(&p, true);
        assert!(matches!(b.state(), BreakerState::Open { until_ms: 61_000 }));
    }

    #[test]
    fn half_open_second_probe_rejected_until_resolved() {
        static NOW: AtomicU64 = AtomicU64::new(1_000);
        let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
        let p = params();
        for _ in 0..5 {
            b.report(&p, true);
        }
        NOW.store(31_000, Ordering::Relaxed);
        assert_eq!(b.check(&p), BreakerDecision::Allow);
        // All probes (default 1) in flight: the next request is rejected.
        let BreakerDecision::Reject { retry_after_ms } = b.check(&p) else {
            panic!("must reject while probing");
        };
        assert_eq!(retry_after_ms, HALF_OPEN_RETRY_AFTER_MS);
    }

    #[test]
    fn multiple_half_open_probes_admitted() {
        static NOW: AtomicU64 = AtomicU64::new(1_000);
        let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
        let p = BreakerParams {
            half_open_probes: 3,
            ..params()
        };
        for _ in 0..5 {
            b.report(&p, true);
        }
        NOW.store(31_000, Ordering::Relaxed);
        assert_eq!(b.check(&p), BreakerDecision::Allow);
        assert_eq!(b.check(&p), BreakerDecision::Allow);
        assert_eq!(b.check(&p), BreakerDecision::Allow);
        assert!(matches!(b.check(&p), BreakerDecision::Reject { .. }));
    }

    #[test]
    fn in_flight_reports_do_not_change_open_state() {
        static NOW: AtomicU64 = AtomicU64::new(1_000);
        let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
        let p = params();
        for _ in 0..5 {
            b.report(&p, true);
        }
        // A request admitted before the trip now succeeds: Open holds (the
        // probe protocol, not stale successes, closes the breaker).
        b.report(&p, false);
        assert!(matches!(b.state(), BreakerState::Open { .. }));
    }

    #[test]
    fn window_expires_old_observations() {
        static NOW: AtomicU64 = AtomicU64::new(1_000);
        let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
        let p = params();
        // 5 failures trip via the streak; use success mix to keep Closed
        // and then age the window out entirely.
        let p2 = BreakerParams {
            consecutive_failures: 100,
            ..p
        };
        for i in 0..20 {
            b.report(&p2, i % 2 == 0);
        }
        assert!(matches!(b.state(), BreakerState::Closed { .. }));
        assert_eq!(b.totals(), 20);
        NOW.store(1_000 + BREAKER_WINDOW_MS + 1, Ordering::Relaxed);
        assert_eq!(b.totals(), 0);
        // 20 more failures at the new time re-trip on ratio (streak is
        // also 100-bound; ratio 20/20 trips).
        for _ in 0..20 {
            b.report(&p2, true);
        }
        assert!(matches!(b.state(), BreakerState::Open { .. }));
    }

    #[test]
    fn ratio_below_volume_never_trips_even_at_full_failure_ratio() {
        // 19/19 = 100% failures is the worst possible ratio, but volume 19
        // is one short of `error_volume` 20: the ratio gate stays closed.
        // Pins that volume gates the ratio regardless of how bad it is
        // (the streak is suppressed at consecutive_failures 100).
        static NOW: AtomicU64 = AtomicU64::new(1_000);
        let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
        let p = BreakerParams {
            consecutive_failures: 100,
            ..params()
        };
        for _ in 0..19 {
            b.report(&p, true);
        }
        assert!(
            matches!(b.state(), BreakerState::Closed { consecutive: 19 }),
            "volume-1 must not trip even at a 100% ratio"
        );
        // The 20th failure lands exactly at volume with 20/20 >= 0.5.
        b.report(&p, true);
        assert!(matches!(b.state(), BreakerState::Open { .. }));
    }

    #[test]
    fn aged_out_failures_no_longer_count_toward_volume() {
        // 19 failures age out of the 60 s window; 19 FRESH failures then
        // hold a 100% ratio but only volume 19: not tripped. The window
        // (not lifetime history) is the denominator; the 20th fresh
        // failure completes the fresh volume and trips.
        static NOW: AtomicU64 = AtomicU64::new(1_000);
        let b = Breaker::with_clock(|| NOW.load(Ordering::Relaxed));
        let p = BreakerParams {
            consecutive_failures: 100,
            ..params()
        };
        for _ in 0..19 {
            b.report(&p, true);
        }
        NOW.store(1_000 + BREAKER_WINDOW_MS + 1, Ordering::Relaxed);
        for _ in 0..19 {
            b.report(&p, true);
        }
        assert!(
            matches!(b.state(), BreakerState::Closed { .. }),
            "stale failures must not count toward volume"
        );
        b.report(&p, true);
        assert!(matches!(b.state(), BreakerState::Open { .. }));
    }
}
