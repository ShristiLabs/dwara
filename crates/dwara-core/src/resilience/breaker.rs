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
//!
//! # Events (DW-044)
//!
//! A breaker constructed with
//! [`Breaker::with_clock_and_events`] emits one event
//! per STATE TRANSITION (never per report): `breaker_opened` (with the
//! rule that tripped, or "half_open_probe_failed" for a failed probe
//! re-opening it), `breaker_half_open` (the first admitted probe after
//! the cooling-off), and `breaker_closed` (a successful probe). Emission
//! is the event bus's bounded non-blocking hand-off — a full queue drops
//! and counts, never blocks the report path. A `None` emitter (every
//! direct/test construction) is a documented no-op.

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
    /// Transition-event emitter (DW-044); `None` = no event wiring
    /// (tests, direct construction). Bound to this breaker's upstream
    /// label at construction; see the module docs.
    events: Option<crate::events::UpstreamEmitter>,
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
        Breaker::with_clock_and_events(now_ms, None)
    }

    /// `with_clock` with transition events (DW-044): the upstream
    /// handle's wiring (the emitter is pre-bound to the upstream's
    /// label; `None` keeps event emission off).
    pub fn with_clock_and_events(
        now_ms: fn() -> u64,
        events: Option<crate::events::UpstreamEmitter>,
    ) -> Self {
        Breaker {
            now_ms,
            inner: Mutex::new(BreakerInner {
                state: BreakerState::Closed { consecutive: 0 },
                window: VecDeque::new(),
            }),
            events,
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

    /// Emit one transition event (DW-044). Called with the inner lock
    /// HELD, immediately after the transition is written (so the event
    /// can never disagree with the state): emission is a `try_send`
    /// plus an atomic — it never blocks and never fails the transition.
    fn emit_transition_locked(&self, kind: crate::events::EventKind, detail: Option<&'static str>) {
        if let Some(events) = &self.events {
            events.breaker_transition(kind, detail);
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
                    // DW-044: the cooling-off elapsed and this request
                    // became the first half-open probe.
                    self.emit_transition_locked(crate::events::EventKind::BreakerHalfOpen, None);
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
                let streak_tripped = streak >= params.consecutive_failures;
                let ratio_tripped = total >= u64::from(params.error_volume)
                    && failures as f64 / total as f64 >= params.error_ratio;
                if streak_tripped || ratio_tripped {
                    inner.state = BreakerState::Open {
                        until_ms: now.saturating_add(params.open_ms),
                    };
                    // DW-044: name the rule that tripped (a stale detail
                    // would send an operator chasing the wrong knob).
                    let detail = if streak_tripped {
                        "consecutive_failures"
                    } else {
                        "error_ratio"
                    };
                    self.emit_transition_locked(
                        crate::events::EventKind::BreakerOpened,
                        Some(detail),
                    );
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
                    self.emit_transition_locked(
                        crate::events::EventKind::BreakerOpened,
                        Some("half_open_probe_failed"),
                    );
                } else {
                    // A successful probe closes and RESETS counters (the
                    // window too): stale pre-trip failures must not
                    // instantly re-trip the ratio.
                    inner.state = BreakerState::Closed { consecutive: 0 };
                    inner.window.clear();
                    self.emit_transition_locked(
                        crate::events::EventKind::BreakerClosed,
                        Some("half_open_probe_succeeded"),
                    );
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
