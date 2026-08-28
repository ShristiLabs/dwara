//! Passive health checking / outlier detection (DW-012, feature analysis
//! 4.5).
//!
//! Passive health watches REAL traffic outcomes — no synthetic probes are
//! sent while an endpoint is serving. Each endpoint of an upstream carries
//! one [`EndpointHealth`] tracker; the proxy's send path classifies every
//! dispatched request's outcome and reports it to the picked endpoint's
//! tracker ([`EndpointHealth::report`]). The load balancer consults
//! [`EndpointHealth::acquire`] on every pick (lock-free: atomics only) and
//! skips endpoints that are currently ejected.
//!
//! # Ejection model
//!
//! An endpoint is ejected when EITHER:
//!
//! - **consecutive failures**: `consecutive_failures` (default 5) transport
//!   or 5xx outcomes in a row, regardless of volume; or
//! - **failure ratio with volume**: within the rolling `window_ms`
//!   (default 60 s) observation window, the 5xx/transport share of
//!   observations is >= `failure_ratio` (default 0.5) AND the window saw at
//!   least `failure_min_volume` (default 20) observations. The volume gate
//!   keeps a 2-of-3 blip from ejecting on a trickle of traffic.
//!
//! Outcome classification (reported at response-header resolution, the same
//! point the in-flight guard releases): transport errors (connect timeout,
//! refused, reset, client framing errors) are failures; HTTP status >= 500
//! is a failure; 1xx-4xx are successes. 429 and 408 are deliberately
//! successes in v1: they describe the CALLER or queueing pressure, not the
//! endpoint's health, and ejecting on them would remove healthy capacity
//! exactly when backpressure is needed (documented choice).
//!
//! Active health probes report through [`EndpointHealth::report_probe`],
//! which drives the SAME consecutive streak and ejection/recovery
//! transitions but never inserts an observation into the rolling window:
//! synthetic probes never mix into real-traffic ratios.
//!
//! # Recovery (half-open)
//!
//! After `eject_ms` (default 30 s) the tracker moves to half-open on the
//! next pick: the first `half_open_probes` (default 1) requests are allowed
//! through (each pick consumes one probe); everything else keeps skipping
//! the endpoint. A successful probe restores the endpoint to healthy and
//! clears its failure history (so the old failures cannot immediately
//! re-eject it); a failed probe re-ejects for another full `eject_ms`. A
//! success observed on an EJECTED endpoint (only possible via the
//! all-ejected fail-open path) also restores health — real traffic to it
//! just worked, which is the strongest possible health signal.
//!
//! # Fail-open
//!
//! If EVERY endpoint of an upstream is ejected, picks fall back to the full
//! set rather than blackholing traffic (documented choice; a gateway that
//! returns 503 for a fully-ejected pool has converted an upstream brownout
//! into a guaranteed outage). The balancer counts these fallbacks
//! (`UpstreamLb::fail_open_picks`) so operators can see the degraded
//! state.
//!
//! # Time
//!
//! All timing runs on a millisecond clock resolved per call from the owning
//! balancer (see `UpstreamLb::now_ms`), which defaults to the system clock
//! and can be swapped for a deterministic clock in tests
//! (`UpstreamLb::set_health_clock`) — the same injection pattern the rate
//! limiter (DW-004) uses.
//!
//! # Concurrency
//!
//! Status transitions are CAS loops on a status atomic; the observation
//! window is a `Mutex<VecDeque>` mutated only on the report path (never on
//! picks). Races between concurrent reports and picks resolve
//! best-effort: a probe slot may occasionally be granted to a request that
//! observes slightly stale state, which is harmless — the next report
//! re-synchronizes the tracker. Tracker state (`Arc<EndpointHealth>`) is
//! keyed by endpoint `address:port` and carried across config rebuilds like
//! the in-flight counters; config changes to the health parameters apply to
//! NEW observations (the window and consecutive counter live on).
//!
//! # Events (DW-044)
//!
//! A tracker constructed with [`EndpointHealth::with_events`] emits
//! `endpoint_ejected` and `endpoint_recovered` on the two state
//! transitions (bound to its upstream and `address:port` labels by the
//! balancer at construction). Both passive reports and ACTIVE probe
//! reports funnel through the same transition code, so either signal
//! ejecting or recovering an endpoint emits. Emission is the event
//! bus's bounded non-blocking hand-off (full queue = drop and count);
//! `None` (direct/test constructions) is a documented no-op.

use std::collections::VecDeque;
// DW-025: under the `loom` dev feature the synchronization primitives are
// swapped for loom's model-checked equivalents so the CAS transition logic
// can be exhaustively explored; builds are bit-identical otherwise.
#[cfg(feature = "loom")]
use loom::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
#[cfg(not(feature = "loom"))]
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
// Arc stays std even under loom: it is a container, not a synchronization
// primitive, and keeping it std avoids infecting cross-module signatures
// (balance.rs Dispatch/HealthDispatch) with loom types.
#[cfg(feature = "loom")]
use loom::sync::Mutex;
#[cfg(feature = "loom")]
use std::sync::Arc;
#[cfg(not(feature = "loom"))]
use std::sync::{Arc, Mutex};

/// Default rolling observation window in milliseconds.
pub const DEFAULT_WINDOW_MS: u64 = 60_000;
/// Default consecutive-failure ejection threshold.
pub const DEFAULT_CONSECUTIVE_FAILURES: u32 = 5;
/// Default failure ratio (0 < r <= 1).
pub const DEFAULT_FAILURE_RATIO: f64 = 0.5;
/// Default minimum observations in the window before the ratio applies.
pub const DEFAULT_FAILURE_MIN_VOLUME: u32 = 20;
/// Default ejection duration in milliseconds.
pub const DEFAULT_EJECT_MS: u64 = 30_000;
/// Default trial requests allowed through per half-open recovery attempt.
pub const DEFAULT_HALF_OPEN_PROBES: u32 = 1;

/// Resolved (validated) passive-health parameters, shared per upstream and
/// snapshotted inside each balancer state generation. A rebuild with new
/// config swaps the whole `Arc`; in-flight reports pin the generation they
/// were dispatched with, so parameter changes apply only to new
/// observations.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HealthParams {
    /// Rolling observation window for the failure ratio (milliseconds).
    pub window_ms: u64,
    /// Eject after this many consecutive transport/5xx outcomes.
    pub consecutive_failures: u32,
    /// Eject when the in-window failure share is >= this ratio AND volume
    /// is >= `failure_min_volume`.
    pub failure_ratio: f64,
    /// Minimum observations in the window before `failure_ratio` applies.
    pub failure_min_volume: u32,
    /// How long an ejected endpoint stays out of rotation (milliseconds).
    pub eject_ms: u64,
    /// Trial requests allowed through per half-open recovery attempt.
    pub half_open_probes: u32,
}

impl HealthParams {
    /// Resolve from the config form (serde already applied defaults; this
    /// is the single place production defaults live for direct
    /// construction too).
    pub fn from_config(h: &crate::config::PassiveHealth) -> Self {
        HealthParams {
            window_ms: h.window_ms,
            consecutive_failures: h.consecutive_failures,
            failure_ratio: h.failure_ratio,
            failure_min_volume: h.failure_min_volume,
            eject_ms: h.eject_ms,
            half_open_probes: h.half_open_probes,
        }
    }
}

// Status atomic discriminants.
const HEALTHY: u8 = 0;
const EJECTED: u8 = 1;
const HALF_OPEN: u8 = 2;

/// Per-endpoint passive health tracker. All pick-path reads are atomic;
/// only the observation window takes a lock (report path). Share via `Arc`
/// from the balancer state; carried across rebuilds for unchanged
/// `address:port`.
#[derive(Debug, Default)]
pub struct EndpointHealth {
    status: AtomicU8,
    /// Ejection expiry (Unix-epoch ms); meaningful while status == EJECTED.
    ejected_until_ms: AtomicU64,
    /// Probe slots left in the current half-open attempt; meaningful while
    /// status == HALF_OPEN.
    probes_remaining: AtomicU32,
    /// Consecutive-failure streak (reported failures only). Atomic;
    /// only mutated on the report path, under the events lock.
    consecutive_failures: AtomicU32,
    /// Rolling (timestamp_ms, is_failure) observations inside the window.
    events: Mutex<VecDeque<(u64, bool)>>,
    /// Total ejections observed on this tracker (observability).
    ejections: AtomicU64,
    /// Ejection/recovery event sink (DW-044); `None` = no event wiring
    /// (tests, direct construction). Bound to this tracker's upstream
    /// and `address:port` labels by the balancer at construction — the
    /// tracker itself knows its state machine, not its own address.
    sink: Option<crate::events::EndpointEvents>,
}

impl EndpointHealth {
    /// Fresh tracker: healthy, empty window.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fresh tracker with ejection/recovery events (DW-044); see the
    /// module docs.
    pub fn with_events(sink: crate::events::EndpointEvents) -> Self {
        EndpointHealth {
            sink: Some(sink),
            ..Self::default()
        }
    }

    /// Whether a pick may use this endpoint at `now` (Unix-epoch ms);
    /// consumes one probe slot when the endpoint is half-open. Lock-free.
    ///
    /// Side effects: an expired ejection transitions to half-open here
    /// (the first pick after `eject_ms` re-arms the probe budget) — the
    /// transition therefore happens lazily on traffic rather than on a
    /// timer.
    pub fn acquire(&self, params: &HealthParams, now: u64) -> bool {
        match self.status.load(Ordering::Acquire) {
            HEALTHY => true,
            EJECTED => {
                if now < self.ejected_until_ms.load(Ordering::Acquire) {
                    return false;
                }
                // Ejection expired: one winner arms the probe budget and
                // flips to half-open; everyone then races for slots.
                if self
                    .status
                    .compare_exchange(EJECTED, HALF_OPEN, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    self.probes_remaining
                        .store(params.half_open_probes, Ordering::Release);
                }
                self.try_probe()
            }
            _ => self.try_probe(),
        }
    }

    /// Whether a pick MAY consider this endpoint at `now` (Unix-epoch ms)
    /// — non-consuming. The balancer's candidate filter calls this for
    /// every endpoint; the endpoint actually SELECTED then consumes a
    /// half-open probe slot via [`EndpointHealth::consume_probe`].
    /// Consuming only at selection keeps a half-open attempt from
    /// deadlocking: probe slots are never burned by picks that go
    /// elsewhere. Side effect: an expired ejection transitions to
    /// half-open here (the first traffic after `eject_ms` re-arms the
    /// probe budget) — the transition happens lazily on traffic rather
    /// than on a timer.
    pub fn is_candidate(&self, params: &HealthParams, now: u64) -> bool {
        match self.status.load(Ordering::Acquire) {
            HEALTHY => true,
            EJECTED => {
                if now < self.ejected_until_ms.load(Ordering::Acquire) {
                    return false;
                }
                if self
                    .status
                    .compare_exchange(EJECTED, HALF_OPEN, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    self.probes_remaining
                        .store(params.half_open_probes, Ordering::Release);
                }
                true
            }
            _ => self.probes_remaining.load(Ordering::Acquire) > 0,
        }
    }

    /// Consume one half-open probe slot for a pick that SELECTED this
    /// endpoint. Best-effort: if a concurrent pick took the last slot,
    /// this pick still proceeds (one extra request beyond the probe
    /// budget may reach a recovering endpoint; the next report
    /// re-synchronizes the tracker).
    pub fn consume_probe(&self) {
        let _ = self
            .probes_remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                if left > 0 {
                    Some(left - 1)
                } else {
                    None
                }
            });
    }

    /// Race for a half-open probe slot; at least one slot per attempt is
    /// granted (the pick that wins the EJECTED->HALF_OPEN transition above
    /// may lose its own slot race to a concurrent pick — acceptable, the
    /// probe still happens against this endpoint).
    fn try_probe(&self) -> bool {
        loop {
            let left = self.probes_remaining.load(Ordering::Acquire);
            if left == 0 {
                return false;
            }
            if self
                .probes_remaining
                .compare_exchange(left, left - 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Whether the endpoint is currently available WITHOUT consuming a
    /// probe (observability; not the pick path).
    pub fn is_available(&self, now: u64) -> bool {
        match self.status.load(Ordering::Acquire) {
            HEALTHY => true,
            EJECTED => now >= self.ejected_until_ms.load(Ordering::Acquire),
            _ => self.probes_remaining.load(Ordering::Acquire) > 0,
        }
    }

    /// Total times this tracker has ejected an endpoint (observability).
    pub fn ejections(&self) -> u64 {
        self.ejections.load(Ordering::Relaxed)
    }

    /// Human state label for observability surfaces (admin `/health`,
    /// DW-022): `healthy`, `ejected`, or `half_open`. An ejection whose
    /// window has expired but not yet transitioned reports `half_open`
    /// (the next pick arms the probe budget), mirroring
    /// [`Self::is_available`]'s view of expiry.
    pub fn state_label(&self, now: u64) -> &'static str {
        match self.status.load(Ordering::Acquire) {
            HEALTHY => "healthy",
            EJECTED => {
                if now >= self.ejected_until_ms.load(Ordering::Acquire) {
                    "half_open"
                } else {
                    "ejected"
                }
            }
            _ => "half_open",
        }
    }

    /// Report one observation for this endpoint at `now` (Unix-epoch ms):
    /// `is_failure` = transport error or HTTP status >= 500 (see the
    /// module docs for the 1xx-4xx policy). Applies the ejection rules
    /// against `params`.
    pub fn report(&self, params: &HealthParams, now: u64, is_failure: bool) {
        let mut events = self.events.lock().expect("health tracker poisoned");
        events.push_back((now, is_failure));
        let window = params.window_ms;
        while events
            .front()
            .is_some_and(|&(t, _)| now.saturating_sub(t) >= window)
        {
            events.pop_front();
        }
        self.apply_observation(&mut events, params, now, is_failure);
    }

    /// Report one ACTIVE (synthetic probe) observation at `now` (Unix-epoch
    /// ms). Runs the same state machine as [`EndpointHealth::report`] —
    /// the shared consecutive-failure streak and every ejection/recovery
    /// transition — but the observation NEVER enters the rolling
    /// failure-ratio window: that window is real traffic only, so probes
    /// cannot contaminate the passive ratios (the ratio rule also stays
    /// disabled by the caller's parameters as a second line of defense).
    pub fn report_probe(&self, params: &HealthParams, now: u64, is_failure: bool) {
        let mut events = self.events.lock().expect("health tracker poisoned");
        self.apply_observation(&mut events, params, now, is_failure);
    }

    /// Streak update plus status transitions, shared by passive and probe
    /// reports. Caller holds the events lock (probe reports hold it too,
    /// so transitions stay consistent with the window they read).
    fn apply_observation(
        &self,
        events: &mut VecDeque<(u64, bool)>,
        params: &HealthParams,
        now: u64,
        is_failure: bool,
    ) {
        if is_failure {
            self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        } else {
            self.consecutive_failures.store(0, Ordering::Relaxed);
        }

        match self.status.load(Ordering::Acquire) {
            HALF_OPEN => {
                if is_failure {
                    self.eject_locked(events, params, now);
                } else {
                    // Successful probe (or a fail-open success racing the
                    // probe): back to healthy with a clean history.
                    self.recover_locked(events);
                }
            }
            EJECTED => {
                if !is_failure {
                    // Only reachable via the all-ejected fail-open path:
                    // real traffic to this endpoint just succeeded.
                    self.recover_locked(events);
                }
                // Failures while ejected (fail-open traffic) leave the
                // ejection standing; the expiry/half-open cycle is the
                // designed recovery path.
            }
            _ => {
                if is_failure && self.should_eject_locked(events, params) {
                    self.eject_locked(events, params, now);
                }
            }
        }
    }

    /// Ejection rules for a healthy endpoint: the consecutive streak OR the
    /// in-window ratio with sufficient volume. The events guard is held by
    /// the caller (so the window snapshot and the decision are consistent).
    fn should_eject_locked(&self, events: &VecDeque<(u64, bool)>, params: &HealthParams) -> bool {
        if self.consecutive_failures.load(Ordering::Relaxed) >= params.consecutive_failures {
            return true;
        }
        let volume = events.len();
        if (volume as u32) < params.failure_min_volume {
            return false;
        }
        let failures = events.iter().filter(|(_, f)| *f).count();
        (failures as f64) >= params.failure_ratio * volume as f64
    }

    /// Move to EJECTED until `now + eject_ms`, resetting the streak and
    /// the window (a clean slate for the half-open attempt). Caller holds
    /// the events lock.
    fn eject_locked(&self, events: &mut VecDeque<(u64, bool)>, params: &HealthParams, now: u64) {
        self.ejected_until_ms
            .store(now + params.eject_ms, Ordering::Release);
        self.status.store(EJECTED, Ordering::Release);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        events.clear();
        self.ejections.fetch_add(1, Ordering::Relaxed);
        // DW-044: emitted under the events lock, immediately after the
        // transition — a `try_send`, never a block.
        if let Some(sink) = &self.sink {
            sink.emit(crate::events::EventKind::EndpointEjected);
        }
    }

    /// Move to HEALTHY with a clean history. Caller holds the events lock.
    fn recover_locked(&self, events: &mut VecDeque<(u64, bool)>) {
        self.status.store(HEALTHY, Ordering::Release);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        events.clear();
        // DW-044: see eject_locked. Recovery covers both paths that
        // restore an endpoint (a successful half-open probe and the
        // all-ejected fail-open success).
        if let Some(sink) = &self.sink {
            sink.emit(crate::events::EventKind::EndpointRecovered);
        }
    }
}

/// The per-dispatch health report handle carried out of a pick: the
/// endpoint's tracker plus the parameter generation the pick ran against.
/// The send path reports the outcome exactly once.
#[derive(Clone)]
pub struct HealthDispatch {
    pub(crate) tracker: Arc<EndpointHealth>,
    pub(crate) params: Arc<HealthParams>,
}

impl HealthDispatch {
    /// Report one outcome (transport error or status >= 500 = failure) at
    /// `now` (Unix-epoch ms). Called when the response headers resolve or
    /// the send fails at transport level.
    pub fn report(&self, now: u64, is_failure: bool) {
        self.tracker.report(&self.params, now, is_failure);
    }

    /// The tracker behind this dispatch (observability/tests).
    pub fn tracker(&self) -> &Arc<EndpointHealth> {
        &self.tracker
    }
}
