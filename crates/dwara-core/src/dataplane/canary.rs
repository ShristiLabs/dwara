//! Auto-canary analysis (DW-091): metrics-driven promotion/rollback of
//! canary split weights.
//!
//! A [`CanaryController`] holds per-group state (one group per service
//! split or AI model alias that configures `canary_analysis`). The
//! controller maintains its OWN per-version sliding windows for error
//! rate and latency (no new Prometheus histograms) using atomic
//! counters and a bounded `VecDeque` of latency samples — the same
//! lightweight pattern as the resilience domain's `AdaptiveController`
//! (DW-089) and the balancer's `PeakEwmaTracker`.
//!
//! # Lifecycle
//!
//! Compiled once per config generation from the `canary_analysis`
//! blocks on service splits and AI model aliases; shared via `Arc`
//! from the dataplane generation. `record_outcome` runs on the
//! response path (after the upstream exchange resolves) and
//! `evaluate` runs on the background [`CanaryRunner`] loop. Weight
//! changes are TRANSIENT: the runner calls
//! `DataPlane::apply_service_split_weights` /
//! `apply_ai_canary_weights`, which clone the current generation's
//! split/runtime, rebuild with new weights, and ArcSwap-store. A
//! config reload rebuilds the generation from the published config,
//! reverting any transient weight changes (the controller's sliding
//! windows reset with the generation, like the adaptive controller).
//!
//! # Step semantics
//!
//! Configurable step in weight units. Promote: increase canary weight
//! by `step` (up to `total_weight`). Rollback: decrease by `step`
//! (down to 0). Severe regression (>2x the rollback threshold):
//! immediate rollback to 0. The total weight stays constant: when
//! the canary weight changes, the baseline absorbs the difference,
//! preserving the hash distribution for existing sessions (the
//! DW-040 invariant).
//!
//! # Guards
//!
//! - **Cooldown**: after one adjustment, the next is suppressed until
//!   `cooldown_seconds` elapses.
//! - **min_requests**: the controller does not act until at least
//!   `min_requests` total observations (baseline + canary) have been
//!   recorded.
//! - **Disabled**: a `canary_analysis` block with `enabled: false`
//!   compiles no group (the fast path: `record_outcome` and
//!   `evaluate` are no-ops).

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::{CanaryAnalysis, CanaryMetric, Gateway};
use crate::dataplane::proxy::DataPlane;
use crate::events::{EventKind, EventPayload};
use crate::observability::Observability;

/// Maximum latency samples kept per side (the sliding window cap).
/// 1000 samples is enough for a stable p99 estimate without
/// unbounded memory growth. The `window_seconds` config field
/// documents the intended look-back period; the actual window is
/// sample-count-bounded (the last 1000 observations), which is
/// simpler and avoids a time-based eviction timer on the hot path.
const MAX_LATENCY_SAMPLES: usize = 1000;

/// Unix-epoch second clock (the same clock the adaptive controller
/// uses, in seconds). System clock in production; swappable for
/// deterministic clocks in tests via [`CanaryController::compile_with_clock`].
fn system_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether a canary group is a service-level split or an AI model
/// canary (DW-091). Determines which `apply_*_weights` method the
/// runner calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CanaryKind {
    /// A service-level traffic split (`services[].split.canary_analysis`).
    Service,
    /// An AI model canary split (`ai.models.<alias>.canary_analysis`).
    Ai,
}

/// One side of a canary comparison (baseline or canary). All fields
/// are atomic or mutex-guarded so `record_outcome` is lock-free for
/// the counters and briefly locks only the latency window.
struct CanarySide {
    /// Total requests observed on this side.
    requests: AtomicU64,
    /// Requests that returned a 5xx status.
    errors: AtomicU64,
    /// Sliding window of latency samples (milliseconds), capped at
    /// [`MAX_LATENCY_SAMPLES`]. A `Mutex<VecDeque<f64>>` — the lock
    /// is held only for the push/trim, never across a network call.
    latency_samples: Mutex<VecDeque<f64>>,
}

impl CanarySide {
    fn new() -> Self {
        CanarySide {
            requests: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            latency_samples: Mutex::new(VecDeque::with_capacity(MAX_LATENCY_SAMPLES)),
        }
    }

    fn record(&self, status: u16, latency_ms: f64) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        if status >= 500 {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
        if let Ok(mut samples) = self.latency_samples.lock() {
            if samples.len() >= MAX_LATENCY_SAMPLES {
                samples.pop_front();
            }
            samples.push_back(latency_ms);
        }
    }

    fn request_count(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }

    fn error_count(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }

    /// Error rate as a fraction in [0.0, 1.0]. Returns 0.0 when no
    /// requests have been observed (avoids division by zero).
    fn error_rate(&self) -> f64 {
        let req = self.request_count();
        if req == 0 {
            return 0.0;
        }
        self.error_count() as f64 / req as f64
    }

    /// The requested latency percentile in milliseconds. Returns 0.0
    /// when no samples have been collected. Uses a simple sort-based
    /// selection (the window is capped at 1000 samples, so the sort
    /// is cheap and runs only on the evaluation loop, never on the
    /// request path).
    fn percentile(&self, pct: f64) -> f64 {
        let Ok(samples) = self.latency_samples.lock() else {
            return 0.0;
        };
        if samples.is_empty() {
            return 0.0;
        }
        let mut sorted: Vec<f64> = samples.iter().copied().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let idx = ((pct / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }
}

/// One canary group: a service split or AI model alias with
/// `canary_analysis` configured. Holds the baseline and canary
/// sliding windows, the current canary weight, and the cooldown
/// timestamp.
struct CanaryGroup {
    name: String,
    kind: CanaryKind,
    config: CanaryAnalysis,
    baseline: CanarySide,
    canary: CanarySide,
    /// Timestamp (seconds) of the last weight adjustment. 0 = never.
    last_adjustment: AtomicU64,
    /// Current canary weight (transient; reverts on config reload).
    current_canary_weight: AtomicU64,
    /// Total weight (constant; baseline + canary = total).
    total_weight: u64,
    /// Second clock (system clock in production; injected in tests).
    now_secs: fn() -> u64,
}

impl CanaryGroup {
    fn new(
        name: String,
        kind: CanaryKind,
        config: CanaryAnalysis,
        total_weight: u64,
        initial_canary_weight: u64,
        now_secs: fn() -> u64,
    ) -> Self {
        CanaryGroup {
            name,
            kind,
            config,
            baseline: CanarySide::new(),
            canary: CanarySide::new(),
            last_adjustment: AtomicU64::new(0),
            current_canary_weight: AtomicU64::new(initial_canary_weight),
            total_weight,
            now_secs,
        }
    }

    /// The current transient canary weight.
    pub fn current_canary_weight(&self) -> u64 {
        self.current_canary_weight.load(Ordering::Relaxed)
    }

    /// Compute the metric value for one side per the rule's metric kind.
    fn metric_for(&self, side: &CanarySide, metric: CanaryMetric) -> f64 {
        match metric {
            CanaryMetric::ErrorRate => side.error_rate(),
            CanaryMetric::LatencyP99 => side.percentile(99.0),
            CanaryMetric::LatencyP95 => side.percentile(95.0),
            CanaryMetric::LatencyP50 => side.percentile(50.0),
        }
    }

    /// Evaluate this group and return an action if one is warranted.
    /// Returns `None` when cooldown or min_requests suppresses the
    /// evaluation, or when the canary is neither promoting nor
    /// regressing.
    fn evaluate(&self) -> Option<CanaryAction> {
        let now = (self.now_secs)();
        let last = self.last_adjustment.load(Ordering::Relaxed);
        if last > 0 {
            let elapsed = now.saturating_sub(last);
            if elapsed < self.config.cooldown_seconds {
                return None;
            }
        }
        let baseline_req = self.baseline.request_count();
        let canary_req = self.canary.request_count();
        let total_req = baseline_req + canary_req;
        if total_req < self.config.min_requests {
            return None;
        }
        let current_weight = self.current_canary_weight();
        // Severe regression (>2x rollback threshold): immediate
        // rollback to 0, ignoring the step.
        let canary_rollback_metric = self.metric_for(&self.canary, self.config.rollback.metric);
        if canary_rollback_metric > self.config.rollback.threshold * 2.0 {
            if current_weight == 0 {
                return None;
            }
            return Some(CanaryAction {
                group: self.name.clone(),
                kind: self.kind,
                new_canary_weight: 0,
                reason: "severe_regression".to_string(),
                metric_value: canary_rollback_metric,
                threshold: self.config.rollback.threshold,
            });
        }
        // Rollback: canary metric above the rollback threshold.
        if canary_rollback_metric > self.config.rollback.threshold {
            let new_weight = current_weight.saturating_sub(self.config.step as u64);
            if new_weight == current_weight {
                return None;
            }
            return Some(CanaryAction {
                group: self.name.clone(),
                kind: self.kind,
                new_canary_weight: new_weight,
                reason: "rollback".to_string(),
                metric_value: canary_rollback_metric,
                threshold: self.config.rollback.threshold,
            });
        }
        // Promote: canary metric below the promote threshold (good).
        let canary_promote_metric = self.metric_for(&self.canary, self.config.promote.metric);
        if canary_promote_metric < self.config.promote.threshold {
            let new_weight = (current_weight + self.config.step as u64).min(self.total_weight);
            if new_weight == current_weight {
                return None;
            }
            return Some(CanaryAction {
                group: self.name.clone(),
                kind: self.kind,
                new_canary_weight: new_weight,
                reason: "promote".to_string(),
                metric_value: canary_promote_metric,
                threshold: self.config.promote.threshold,
            });
        }
        None
    }
}

/// One evaluation result: the controller recommends adjusting
/// `group`'s canary weight to `new_canary_weight` for the given
/// `reason`.
#[derive(Debug, Clone, PartialEq)]
pub struct CanaryAction {
    /// The group name (service name or AI alias).
    pub group: String,
    /// Whether this is a service-level or AI canary.
    pub kind: CanaryKind,
    /// The recommended new canary weight.
    pub new_canary_weight: u64,
    /// Why: "promote", "rollback", or "severe_regression".
    pub reason: String,
    /// The metric value that triggered the action.
    pub metric_value: f64,
    /// The threshold the metric was compared against.
    pub threshold: f64,
}

/// The per-generation canary analysis controller (DW-091). Compiled
/// once per config generation from the `canary_analysis` blocks on
/// service splits and AI model aliases; shared via `Arc` from the
/// dataplane generation. `record_outcome` runs on the response path
/// and `evaluate` runs on the background [`CanaryRunner`] loop.
pub struct CanaryController {
    groups: HashMap<String, CanaryGroup>,
    /// Observability handle for the canary metrics. `None` only in
    /// direct unit-test construction; the dataplane always wires the
    /// real registry.
    obs: Option<Arc<Observability>>,
    /// Second clock (system clock in production; a test may inject a
    /// controllable clock via [`Self::compile_with_clock`]).
    now_secs: fn() -> u64,
}

impl std::fmt::Debug for CanaryController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CanaryController")
            .field("groups", &self.groups.len())
            .finish()
    }
}

impl CanaryController {
    /// New empty controller (no canary groups). The fast path:
    /// `record_outcome` and `evaluate` are no-ops.
    pub fn new() -> Self {
        CanaryController {
            groups: HashMap::new(),
            obs: None,
            now_secs: system_now_secs,
        }
    }

    /// Compile the controller from a gateway's service splits and AI
    /// model aliases. Only services/aliases with an enabled
    /// `canary_analysis` block contribute a group. The observability
    /// handle wires the metric families; pass `None` for direct
    /// unit-test construction (metrics are then a no-op).
    pub fn compile(gateway: &Gateway, obs: Option<Arc<Observability>>) -> Self {
        Self::compile_with_clock(gateway, obs, system_now_secs)
    }

    /// [`Self::compile`] with a caller-supplied second clock (Unix
    /// epoch). Intended for tests that need to advance time
    /// deterministically (the same pattern as
    /// `AdaptiveController::compile_with_clock`); production keeps the
    /// system clock via [`Self::compile`].
    pub fn compile_with_clock(
        gateway: &Gateway,
        obs: Option<Arc<Observability>>,
        now_secs: fn() -> u64,
    ) -> Self {
        let mut groups = HashMap::new();
        // Service-level splits: canary_analysis on a 2-target split.
        for service in &gateway.services {
            let Some(split) = &service.split else {
                continue;
            };
            let Some(analysis) = &split.canary_analysis else {
                continue;
            };
            if !analysis.enabled {
                continue;
            }
            // Only 2-target splits are canary-shaped (baseline + canary).
            if split.targets.len() != 2 {
                continue;
            }
            let total: u64 = split.targets.iter().map(|t| t.weight as u64).sum();
            if total == 0 {
                continue;
            }
            // The canary is the SECOND target (index 1); the baseline
            // is the first (index 0). The initial canary weight is
            // the configured weight of the second target.
            let initial_canary = split.targets[1].weight as u64;
            groups.insert(
                service.name.clone(),
                CanaryGroup::new(
                    service.name.clone(),
                    CanaryKind::Service,
                    analysis.clone(),
                    total,
                    initial_canary,
                    now_secs,
                ),
            );
        }
        // AI model canaries: canary_analysis on a 2-version canary.
        if let Some(ai) = &gateway.ai {
            for (alias, model) in &ai.models {
                let Some(analysis) = &model.canary_analysis else {
                    continue;
                };
                if !analysis.enabled {
                    continue;
                }
                // Only 2-version canaries are canary-shaped.
                if model.canary.len() != 2 {
                    continue;
                }
                let total: u64 = model.canary.iter().map(|v| v.weight as u64).sum();
                if total == 0 {
                    continue;
                }
                let initial_canary = model.canary[1].weight as u64;
                groups.insert(
                    alias.clone(),
                    CanaryGroup::new(
                        alias.clone(),
                        CanaryKind::Ai,
                        analysis.clone(),
                        total,
                        initial_canary,
                        now_secs,
                    ),
                );
            }
        }
        // Seed the canary weight gauges for the initial state.
        if let Some(obs) = &obs {
            for group in groups.values() {
                obs.set_canary_weight(&group.name, group.current_canary_weight() as f64);
            }
        }
        CanaryController {
            groups,
            obs,
            now_secs,
        }
    }

    /// Whether any canary group is compiled in at all (the fast path:
    /// configs with no canary_analysis skip the per-request
    /// record_outcome entirely).
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Record one upstream outcome for `group_name` (DW-091):
    /// increment the appropriate side's request/error counters and
    /// add the latency sample. A no-op when the group has no
    /// canary_analysis. `is_canary` selects the side (true = canary,
    /// false = baseline); `status` is the upstream HTTP status (5xx
    /// counts as an error); `latency_ms` is the upstream round-trip
    /// in milliseconds.
    pub fn record_outcome(&self, group_name: &str, is_canary: bool, status: u16, latency_ms: f64) {
        let Some(group) = self.groups.get(group_name) else {
            return;
        };
        if is_canary {
            group.canary.record(status, latency_ms);
        } else {
            group.baseline.record(status, latency_ms);
        }
    }

    /// Evaluate all groups and return the actions the runner should
    /// apply. Each action carries the recommended new canary weight.
    /// The runner applies them and emits events; the controller's
    /// `last_adjustment` and `current_canary_weight` are updated by
    /// [`Self::note_applied`].
    pub fn evaluate(&self) -> Vec<CanaryAction> {
        let mut actions = Vec::new();
        for group in self.groups.values() {
            if let Some(action) = group.evaluate() {
                actions.push(action);
            }
        }
        actions
    }

    /// Note that an action was successfully applied (the runner calls
    /// this after `apply_*_weights` returns true). Updates the
    /// group's `last_adjustment` and `current_canary_weight`, and
    /// records the promotion/rollback metric.
    pub fn note_applied(&self, action: &CanaryAction) {
        let Some(group) = self.groups.get(&action.group) else {
            return;
        };
        let now = (self.now_secs)();
        group.last_adjustment.store(now, Ordering::Relaxed);
        group
            .current_canary_weight
            .store(action.new_canary_weight, Ordering::Relaxed);
        if let Some(obs) = &self.obs {
            obs.set_canary_weight(&action.group, action.new_canary_weight as f64);
            if action.new_canary_weight == 0
                || action.reason == "rollback"
                || action.reason == "severe_regression"
            {
                obs.record_canary_rollback(&action.group);
            } else {
                obs.record_canary_promotion(&action.group);
            }
        }
    }

    /// The current transient canary weight for a group (tests /
    /// diagnostics). Returns `None` when the group does not exist.
    pub fn current_canary_weight(&self, group: &str) -> Option<u64> {
        self.groups.get(group).map(|g| g.current_canary_weight())
    }

    /// The total weight for a group (tests / diagnostics).
    pub fn total_weight(&self, group: &str) -> Option<u64> {
        self.groups.get(group).map(|g| g.total_weight)
    }
}

impl Default for CanaryController {
    fn default() -> Self {
        CanaryController::new()
    }
}

/// The background canary evaluation loop (DW-091). Spawned by
/// dwara-bin after the dataplane is initialized; periodically calls
/// `CanaryController::evaluate`, applies the returned actions through
/// the dataplane's transient weight-swap methods, and emits
/// `CanaryPromoted` / `CanaryRolledBack` events. Dropping the runner
/// (or shutdown) aborts the loop.
pub struct CanaryRunner {
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl CanaryRunner {
    /// Spawn the background evaluation loop. `interval` is the
    /// evaluation period (the operator picks it; a shorter interval
    /// reacts faster but does more work). The loop stops when the
    /// dataplane is dropped or the task is aborted.
    pub fn spawn(dp: Arc<DataPlane>, interval: Duration) -> Self {
        let handle = tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            timer.tick().await; // skip the first immediate tick
            loop {
                timer.tick().await;
                let gen = dp.current();
                let Some(canary) = gen.canary() else {
                    continue;
                };
                if canary.is_empty() {
                    continue;
                }
                let actions = canary.evaluate();
                for action in actions {
                    let success = match action.kind {
                        CanaryKind::Service => {
                            dp.apply_service_split_weights(&action.group, action.new_canary_weight)
                        }
                        CanaryKind::Ai => {
                            dp.apply_ai_canary_weights(&action.group, action.new_canary_weight)
                        }
                    };
                    if success {
                        canary.note_applied(&action);
                        let kind = if action.new_canary_weight == 0
                            || action.reason == "rollback"
                            || action.reason == "severe_regression"
                        {
                            EventKind::CanaryRolledBack
                        } else {
                            EventKind::CanaryPromoted
                        };
                        dp.events().emitter().emit(
                            kind,
                            EventPayload {
                                canary_group: Some(action.group.clone()),
                                canary_action: Some(action.reason.clone()),
                                canary_weight: Some(action.new_canary_weight),
                                canary_metric_value: Some(action.metric_value),
                                ..EventPayload::default()
                            },
                        );
                    }
                }
            }
        });
        CanaryRunner {
            handle: Some(handle),
        }
    }

    /// Abort the evaluation loop (stops at the next await point).
    pub fn abort(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

impl Drop for CanaryRunner {
    fn drop(&mut self) {
        self.abort();
    }
}
