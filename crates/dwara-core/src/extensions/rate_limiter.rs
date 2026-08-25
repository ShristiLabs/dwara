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
//! (`dashmap` feature: one shard-parallel map per window, no global mutex;
//! contrast [`InMemoryRateLimiter`]'s single `Mutex<HashMap>`, which is
//! why it stayed a skeleton). A limiter may STACK several windows
//! (e.g. 10 r/s AND 100 r/hour): each window is an independent GCRA cell
//! per key and the decision is the AND of all windows — denied if ANY
//! window denies, `retry_after` from the denying (binding) window.
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
//! **Known v1 limitation — no per-key eviction:** every distinct key a
//! rule sees creates permanent GCRA state in that window's dashmap; the
//! maps are only reset by a config reload (generation swap). With `[ip]`
//! or `[ip, route]` selectors this is a memory-amplification vector: an
//! attacker spraying requests from many source IPs (or spoofed keys, if
//! the peer IP is not connection-derived) grows the state map without
//! bound for the process lifetime. Key-state eviction / TTL is a
//! recorded follow-up, not implemented in v1.
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

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use governor::clock::Clock as _;
use governor::clock::DefaultClock;
use governor::middleware::StateInformationMiddleware;
use governor::state::keyed::DashMapStateStore;
use governor::state::RateLimiter as GovernorLimiter;
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

/// One stacked GCRA window (DW-017): `requests` per `window` with a
/// `burst`-token bucket, backed by its own sharded keyed state.
struct GcraWindow {
    limiter: GovernorLimiter<
        String,
        DashMapStateStore<String>,
        DefaultClock,
        StateInformationMiddleware,
    >,
    /// Bucket size (governor's max_burst) — the `X-RateLimit-Limit` this
    /// window reports when it is the binding constraint.
    burst: NonZeroU32,
    /// Full-bucket refill time (`burst_size_replenished_in`) — used when
    /// a cost can never fit the bucket.
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
/// **Clock:** governor runs on its own quanta monotonic clock; there is
/// deliberately no clock injection here. Tests use real time with tiny
/// windows (sub-second) instead of a fake clock.
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
                GcraWindow {
                    limiter: GovernorLimiter::dashmap(quota)
                        .with_middleware::<StateInformationMiddleware>(),
                    burst,
                    full_refill_ms: quota.burst_size_replenished_in().as_millis() as u64,
                }
            })
            .collect();
        Some(Self { windows })
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

fn denied_outcome(limit: u32, retry_after_ms: u64) -> GcraOutcome {
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
struct EngineRule {
    selectors: Vec<crate::config::RateLimitSelector>,
    limiter: GcraRateLimiter,
}

/// The per-request attributes a rule key can be built from (DW-017).
#[derive(Debug, Clone, Copy)]
pub struct RateLimitKeyContext<'a> {
    /// Direct connection peer (the `ip` selector; same IP as X-Real-IP).
    pub peer: std::net::IpAddr,
    /// Authenticated consumer name; `None` until DW-019 wires authN —
    /// the `credential` selector then falls back to the peer IP.
    pub consumer: Option<&'a str>,
    /// Name of the matched route (the `route` selector).
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
/// policies apply and are AND-ed; the resolution order is consumer (LIVE
/// since DW-019: authenticated requests carry their consumer's policies),
/// then route, then service. Listener- and global-attached policies have
/// no config attachment point yet (v1 schema attaches policies only at
/// consumers, routes, and services) — those links go live with their
/// config fields.
///
/// Key building per rule: each selector contributes one component
/// (`ip` = peer, `credential` = consumer or peer fallback, `route` =
/// route name); components are joined with `|` into one key. Rules
/// attached to the same policy share a limiter instance, so two rules
/// with identical selectors and windows would double-count — validation
/// does not reject it (harmless), operators just should not write it.
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
                            limiter: GcraRateLimiter::new(vec![GcraWindowSpec {
                                requests,
                                window: Duration::from_secs(rl.window_seconds),
                                burst: Some(requests),
                            }])
                            .expect("one window spec"),
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
                        limiter,
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

    /// Resolve the applicable rules for one request and check them.
    /// `consumer_policies`/`route_policies`/`service_policies` are the
    /// policy name lists attached to the authenticated consumer (DW-019;
    /// empty for anonymous traffic), the matched route, and its service.
    /// All applicable rules apply (AND); on success the reported
    /// constraint is the tightest one (least remaining budget). On denial
    /// the FIRST denying rule binds the Limit/Remaining/Reset headers,
    /// but evaluation continues through the remaining applicable rules so
    /// `retry_after_s` (and the matching Reset) reflect the MAXIMUM wait
    /// any denying rule demands — a client honoring the hint never
    /// retries into a second 429 with an understated Retry-After.
    pub fn check(
        &self,
        ctx: &RateLimitKeyContext<'_>,
        consumer_policies: &[String],
        route_policies: &[String],
        service_policies: &[String],
    ) -> RateLimitOutcome {
        // Resolution order (precedence): consumer > route > service.
        // Header binding: the FIRST denying rule supplies Limit /
        // Remaining / Reset (the tightest constraint in resolution
        // order); Retry-After is the MAX wait across every denying rule,
        // so a client honoring it never retries into a second 429 with
        // an understated hint. Allowed outcomes are irrelevant once any
        // rule has denied (the response is a 429 regardless).
        let mut acc: Option<RateLimitOutcome> = None;
        let mut denied: Option<RateLimitOutcome> = None;
        for name in consumer_policies
            .iter()
            .chain(route_policies)
            .chain(service_policies)
        {
            for (policy_name, rule) in &self.rules {
                if policy_name != name {
                    continue;
                }
                let key = build_key(ctx, &rule.selectors);
                match rate_outcome(rule.limiter.check(&key, 1)) {
                    RateLimitOutcome::Denied {
                        limit,
                        remaining,
                        reset_epoch_s,
                        retry_after_s,
                    } => match denied.as_mut() {
                        // First denial binds the headers.
                        None => {
                            denied = Some(RateLimitOutcome::Denied {
                                limit,
                                remaining,
                                reset_epoch_s,
                                retry_after_s,
                            });
                        }
                        // Later denials only stretch Retry-After (and the
                        // matching Reset) when they wait longer.
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
                        // `denied` only ever holds a Denied variant.
                        Some(_) => unreachable!("denied is only set to Denied"),
                    },
                    next @ RateLimitOutcome::Allowed { remaining, .. } => {
                        if denied.is_some() {
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
        denied.unwrap_or(acc.unwrap_or(RateLimitOutcome::NotLimited))
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allows_until_limit_then_denies_with_retry_after() {
        let limiter = InMemoryRateLimiter::new(2, 60_000);
        let first = limiter.check("consumer-a", 1).await.unwrap();
        assert!(first.allowed);
        assert_eq!(first.remaining, 1);
        let second = limiter.check("consumer-a", 1).await.unwrap();
        assert!(second.allowed);
        assert_eq!(second.remaining, 0);
        let denied = limiter.check("consumer-a", 1).await.unwrap();
        assert!(!denied.allowed);
        assert!(denied.retry_after_ms.is_some());
    }

    /// Deterministic clock: a thread-local millisecond counter the tests
    /// advance. Each #[tokio::test] runs on its own thread, so tests using
    /// the clock are isolated from each other.
    fn set_clock(limiter: &mut InMemoryRateLimiter) -> impl Fn(u64) + use<> {
        thread_local! {
            static TIME: std::cell::Cell<u64> = const { std::cell::Cell::new(1_000) };
        }
        limiter.now_ms = || u128::from(TIME.with(|t| t.get()));
        move |ms: u64| TIME.with(|t| t.set(ms))
    }

    #[tokio::test]
    async fn denial_reports_positive_retry_after_within_window() {
        let mut limiter = InMemoryRateLimiter::new(1, 10_000);
        let time = set_clock(&mut limiter);
        limiter.check("k", 1).await.unwrap();
        time(4_000);
        let denied = limiter.check("k", 1).await.unwrap();
        assert!(!denied.allowed);
        assert_eq!(denied.remaining, 0);
        // 10s window started at t=1000; at t=4000 the caller must wait 7s.
        assert_eq!(denied.retry_after_ms, Some(7_000));
    }

    #[tokio::test]
    async fn window_resets_after_injected_clock_advance() {
        let mut limiter = InMemoryRateLimiter::new(1, 10_000);
        let time = set_clock(&mut limiter);
        assert!(limiter.check("k", 1).await.unwrap().allowed);
        assert!(!limiter.check("k", 1).await.unwrap().allowed);
        time(11_000);
        let after_reset = limiter.check("k", 1).await.unwrap();
        assert!(after_reset.allowed);
        assert_eq!(after_reset.remaining, 0);
        assert_eq!(after_reset.retry_after_ms, None);
    }

    #[tokio::test]
    async fn multi_unit_cost_consumes_multiple_allowances_atomically() {
        let limiter = InMemoryRateLimiter::new(5, 60_000);
        let bulk = limiter.check("k", 3).await.unwrap();
        assert!(bulk.allowed);
        assert_eq!(bulk.remaining, 2);
        // 3 more would exceed the remaining 2: denied whole, nothing consumed.
        let denied = limiter.check("k", 3).await.unwrap();
        assert!(!denied.allowed);
        assert_eq!(denied.remaining, 2);
        let fits = limiter.check("k", 2).await.unwrap();
        assert!(fits.allowed);
        assert_eq!(fits.remaining, 0);
    }

    #[tokio::test]
    async fn distinct_keys_have_independent_windows() {
        let limiter = InMemoryRateLimiter::new(1, 60_000);
        assert!(limiter.check("a", 1).await.unwrap().allowed);
        let b = limiter.check("b", 1).await.unwrap();
        assert!(b.allowed, "key b must not be affected by key a's usage");
        assert!(!limiter.check("a", 1).await.unwrap().allowed);
        assert!(limiter.check("c", 1).await.unwrap().allowed);
    }

    #[tokio::test]
    async fn concurrent_checks_on_same_key_allow_exactly_limit() {
        let limiter = std::sync::Arc::new(InMemoryRateLimiter::new(4, 60_000));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let limiter = std::sync::Arc::clone(&limiter);
            handles.push(tokio::spawn(async move {
                limiter.check("raced", 1).await.unwrap().allowed
            }));
        }
        let mut allowed = 0;
        for h in handles {
            if h.await.unwrap() {
                allowed += 1;
            }
        }
        assert_eq!(
            allowed, 4,
            "atomic decide-and-reserve must admit exactly the limit"
        );
    }

    // --- DW-017: GCRA limiter + policy engine --------------------------------
    //
    // Governor runs on its own quanta monotonic clock; there is no clock
    // injection (deliberate, see GcraRateLimiter docs). These tests use
    // REAL time with tiny windows and tolerant assertions instead.

    use std::net::IpAddr;

    fn window(requests: u32, window_secs: u64, burst: Option<u32>) -> GcraWindowSpec {
        GcraWindowSpec {
            requests: NonZeroU32::new(requests).unwrap(),
            window: Duration::from_secs(window_secs),
            burst: burst.map(|b| NonZeroU32::new(b).unwrap()),
        }
    }

    fn nz(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap()
    }

    #[tokio::test]
    async fn gcra_burst_passes_then_denies_with_retry_after() {
        // 10 r/s with a 20-token bucket: 20 rapid requests all pass.
        let limiter = GcraRateLimiter::new(vec![window(10, 1, Some(20))]).unwrap();
        for i in 0..20 {
            let out = limiter.check("k", 1);
            assert!(out.decision.allowed, "burst request {i} must pass");
        }
        // The 21st within the same second is denied with a retry hint of
        // roughly one replenish interval (100ms) — bounded generously for
        // scheduling jitter on real time.
        let denied = limiter.check("k", 1);
        assert!(!denied.decision.allowed);
        assert_eq!(denied.decision.remaining, 0);
        assert_eq!(denied.limit, 20);
        let retry = denied.decision.retry_after_ms.unwrap();
        assert!(
            retry > 0 && retry <= 900,
            "retry hint {retry}ms out of range"
        );
    }

    #[tokio::test]
    async fn gcra_sustained_rate_admits_again_after_backoff() {
        // 10 r/s burst 3: 3 pass immediately, the 4th is denied; after
        // ~one replenish interval (100ms) a slot has refilled.
        let limiter = GcraRateLimiter::new(vec![window(10, 1, None)]).unwrap();
        for _ in 0..10 {
            assert!(limiter.check("k", 1).decision.allowed);
        }
        assert!(!limiter.check("k", 1).decision.allowed);
        tokio::time::sleep(Duration::from_millis(250)).await;
        let after = limiter.check("k", 1);
        assert!(after.decision.allowed, "sustained below the rate must flow");
    }

    #[tokio::test]
    async fn gcra_stacked_windows_deny_on_either_constraint() {
        // 100 r/s AND 3 per 10s: the hour-like window is the binding one.
        let limiter =
            GcraRateLimiter::new(vec![window(100, 1, None), window(3, 10, None)]).unwrap();
        for i in 0..3 {
            assert!(
                limiter.check("k", 1).decision.allowed,
                "slow-window request {i} must pass"
            );
        }
        let denied = limiter.check("k", 1);
        assert!(!denied.decision.allowed);
        assert_eq!(denied.limit, 3, "the 3-per-10s window is the binding one");
        let retry = denied.decision.retry_after_ms.unwrap();
        // One token per 10s/3 = 3.33s; allow scheduling slack.
        assert!((2_000..=4_000).contains(&retry), "retry hint {retry}ms");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gcra_concurrent_checks_on_same_key_allow_exactly_burst() {
        // 12 concurrent checks on ONE key, limit 5 burst 5 over a 60s
        // window (one token per 12s — no replenishment can interfere):
        // dashmap-backed state must linearize, admitting EXACTLY 5 and
        // denying 7 (mirrors the InMemory concurrency pin).
        let limiter =
            std::sync::Arc::new(GcraRateLimiter::new(vec![window(5, 60, Some(5))]).unwrap());
        let mut handles = Vec::new();
        for _ in 0..12 {
            let limiter = std::sync::Arc::clone(&limiter);
            handles.push(tokio::spawn(async move {
                limiter.check("raced", 1).decision.allowed
            }));
        }
        let mut allowed = 0;
        for h in handles {
            if h.await.unwrap() {
                allowed += 1;
            }
        }
        assert_eq!(
            allowed, 5,
            "atomic decide-and-reserve must admit exactly the burst size"
        );
    }

    #[tokio::test]
    async fn gcra_distinct_keys_are_independent() {
        let limiter = GcraRateLimiter::new(vec![window(2, 60, None)]).unwrap();
        assert!(limiter.check("a", 1).decision.allowed);
        assert!(limiter.check("a", 1).decision.allowed);
        assert!(!limiter.check("a", 1).decision.allowed);
        assert!(
            limiter.check("b", 1).decision.allowed,
            "key b must not be affected by key a"
        );
    }

    #[tokio::test]
    async fn gcra_is_usable_as_a_dyn_rate_limiter_trait_object() {
        let limiter: std::sync::Arc<dyn RateLimiter> =
            std::sync::Arc::new(GcraRateLimiter::new(vec![window(2, 60, None)]).unwrap());
        assert!(limiter.check("k", 1).await.unwrap().allowed);
        assert!(limiter.check("k", 1).await.unwrap().allowed);
        let denied = limiter.check("k", 1).await.unwrap();
        assert!(!denied.allowed);
        assert!(denied.retry_after_ms.is_some());
    }

    fn engine_from(yaml: &str) -> RateLimitEngine {
        RateLimitEngine::compile(&crate::config::parse_gateway(yaml).unwrap())
    }

    fn ctx(peer: &str, route: &'static str) -> RateLimitKeyContext<'static> {
        RateLimitKeyContext {
            peer: peer.parse::<IpAddr>().unwrap(),
            consumer: None,
            route,
        }
    }

    const IP_RULES_YAML: &str = r#"
policies:
  - name: per-ip
    rate_limits:
      - selector: [ip]
        requests_per: { minute: 3 }
  - name: ip-route
    rate_limits:
      - selector: [ip, route]
        requests_per: { minute: 3 }
routes:
  - name: a
    service: svc
    match: { path: { type: prefix, value: /a } }
    action: { type: respond, status: 200 }
    policies: [ip-route]
  - name: b
    service: svc
    match: { path: { type: prefix, value: /b } }
    action: { type: respond, status: 200 }
    policies: [ip-route]
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
consumers: []
"#;

    #[tokio::test]
    async fn engine_selector_ip_keys_clients_independently() {
        let engine = engine_from(IP_RULES_YAML);
        // Attach per-ip via a service to keep the yaml single-purpose.
        let per_ip: Vec<String> = vec!["per-ip".into()];
        for _ in 0..3 {
            assert!(matches!(
                engine.check(&ctx("10.0.0.1", "a"), &[], &[], &per_ip),
                RateLimitOutcome::Allowed { .. }
            ));
        }
        assert!(matches!(
            engine.check(&ctx("10.0.0.1", "a"), &[], &[], &per_ip),
            RateLimitOutcome::Denied { limit: 3, .. }
        ));
        assert!(
            matches!(
                engine.check(&ctx("10.0.0.2", "a"), &[], &[], &per_ip),
                RateLimitOutcome::Allowed { .. }
            ),
            "a different client IP has an independent key"
        );
    }

    #[tokio::test]
    async fn engine_selector_ip_route_keys_pairs_independently() {
        let engine = engine_from(IP_RULES_YAML);
        let ip_route: Vec<String> = vec!["ip-route".into()];
        for _ in 0..3 {
            assert!(matches!(
                engine.check(&ctx("10.0.0.1", "a"), &[], &ip_route, &[]),
                RateLimitOutcome::Allowed { .. }
            ));
        }
        assert!(matches!(
            engine.check(&ctx("10.0.0.1", "a"), &[], &ip_route, &[]),
            RateLimitOutcome::Denied { .. }
        ));
        // Same IP, different route: independent (ip, route) key.
        assert!(matches!(
            engine.check(&ctx("10.0.0.1", "b"), &[], &ip_route, &[]),
            RateLimitOutcome::Allowed { .. }
        ));
    }

    #[tokio::test]
    async fn engine_without_matching_policy_is_not_limited() {
        let engine = engine_from(IP_RULES_YAML);
        for _ in 0..10 {
            assert_eq!(
                engine.check(&ctx("10.0.0.1", "a"), &[], &[], &[]),
                RateLimitOutcome::NotLimited
            );
        }
    }

    #[tokio::test]
    async fn engine_legacy_rate_limit_maps_to_route_scoped_rule() {
        let engine = engine_from(
            "
policies:
  - name: legacy
    rate_limit: { requests: 2, window_seconds: 60 }
",
        );
        let legacy: Vec<String> = vec!["legacy".into()];
        assert!(matches!(
            engine.check(&ctx("10.0.0.1", "r"), &[], &legacy, &[]),
            RateLimitOutcome::Allowed { .. }
        ));
        assert!(matches!(
            engine.check(&ctx("10.0.0.1", "r"), &[], &legacy, &[]),
            RateLimitOutcome::Allowed { .. }
        ));
        // Legacy field keys by ROUTE: a second client on the same route
        // shares the budget (the documented [route] mapping).
        assert!(matches!(
            engine.check(&ctx("10.0.0.2", "r"), &[], &legacy, &[]),
            RateLimitOutcome::Denied { limit: 2, .. }
        ));
    }

    #[tokio::test]
    async fn engine_reports_decreasing_remaining_and_reset() {
        let engine = engine_from(IP_RULES_YAML);
        let per_ip: Vec<String> = vec!["per-ip".into()];
        let first = engine.check(&ctx("10.0.0.9", "a"), &[], &[], &per_ip);
        let second = engine.check(&ctx("10.0.0.9", "a"), &[], &[], &per_ip);
        match (first, second) {
            (
                RateLimitOutcome::Allowed {
                    remaining: r1,
                    reset_epoch_s: s1,
                    ..
                },
                RateLimitOutcome::Allowed {
                    remaining: r2,
                    reset_epoch_s: s2,
                    ..
                },
            ) => {
                assert_eq!(r1, 2, "burst 3 minus the first admission");
                assert_eq!(r2, 1, "remaining must decrease per admitted request");
                assert!(s2 >= s1, "reset estimate must not go backwards");
            }
            other => panic!("expected Allowed outcomes, got {other:?}"),
        }
    }

    // --- burst vs sustained (real time, tiny windows, tolerant bounds) ------

    #[tokio::test]
    async fn gcra_burst_ten_at_five_per_s_then_eleventh_denied() {
        // 5 r/s with a 10-token bucket: the first 10 rapid requests are
        // the burst and all pass...
        let limiter = GcraRateLimiter::new(vec![window(5, 1, Some(10))]).unwrap();
        for i in 0..10 {
            assert!(
                limiter.check("k", 1).decision.allowed,
                "burst request {i} must pass"
            );
        }
        // ...and the 11th within the same instant is denied with a retry
        // hint of roughly one replenish interval (200ms), bounded for
        // scheduling jitter.
        let denied = limiter.check("k", 1);
        assert!(!denied.decision.allowed);
        assert_eq!(denied.limit, 10);
        let retry = denied.decision.retry_after_ms.unwrap();
        assert!(
            retry > 0 && retry <= 900,
            "retry hint {retry}ms out of range"
        );
    }

    #[tokio::test]
    async fn gcra_sustained_above_rate_earns_denials_within_seconds() {
        // 5 r/s burst 5 (one token per 200ms): driving ~10 r/s (one
        // request per 100ms) outruns replenishment, so once the burst is
        // spent the limiter must start denying. 30 requests over >= 2.9s
        // of wall clock: even with generous scheduler overshoot on every
        // sleep the bucket cannot cover 30 (that would need >= 5s).
        let limiter = GcraRateLimiter::new(vec![window(5, 1, Some(5))]).unwrap();
        let mut allowed = 0;
        let mut denied = 0;
        for _ in 0..30 {
            if limiter.check("k", 1).decision.allowed {
                allowed += 1;
            } else {
                denied += 1;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(denied >= 1, "sustained above-rate traffic must throttle");
        assert!(
            allowed >= 6,
            "the burst plus replenishment must admit several"
        );
    }

    #[tokio::test]
    async fn gcra_sustained_below_rate_is_never_denied() {
        // 20 r/s burst 20 (one token per 50ms): driving ~13 r/s (one
        // request per 75ms) stays under replenishment, so the bucket
        // never empties. tokio sleeps never fire early, so every interval
        // is >= 75ms and at most one token in 50ms of budget is spent —
        // deterministic even on real time.
        let limiter = GcraRateLimiter::new(vec![window(20, 1, Some(20))]).unwrap();
        for i in 0..25 {
            assert!(
                limiter.check("k", 1).decision.allowed,
                "below-rate request {i} must never be denied"
            );
            tokio::time::sleep(Duration::from_millis(75)).await;
        }
    }

    #[test]
    fn gcra_new_rejects_empty_window_list() {
        assert!(GcraRateLimiter::new(vec![]).is_none());
    }

    #[test]
    fn window_spec_helpers_build_nonzero() {
        let spec = window(1, 1, None);
        assert_eq!(spec.requests, nz(1));
        assert!(spec.burst.is_none());
    }
}
