//! Upstream retries: resolved parameters, retry budget, backoff with full
//! jitter (DW-014, feature analysis 4.11).
//!
//! # What retries are
//!
//! All knobs live on the UPSTREAM (`upstreams[].retries`); there is no
//! per-route retry configuration in v1. [`RetryParams`] is the resolved,
//! validated form carried by each [`crate::upstream::UpstreamHandle`];
//! [`RetryConfig`] is the serde schema form (defaults applied there).
//!
//! # Retry budget
//!
//! Each upstream owns one [`RetryBudget`]: a rolling 10-second window of
//! `(timestamp, is_retry)` events. A request may be retried only while the
//! invariant `(retries + 1) * 100 <= percent * totals` holds inside the
//! window, where `totals` counts proxied requests to that upstream (one
//! record per request, not per attempt) and `retries` counts retry
//! attempts. The check-and-reserve is a single lock-protected step, so the
//! invariant is never transiently violated by concurrent requests; the
//! conservative form (charging the retry BEFORE it happens) means a fresh
//! window with little volume grants few or no retries rather than allowing
//! a burst — a deliberately safe bias for a gateway protecting an already
//! struggling upstream. Budget state is carried across config reloads
//! (keyed by upstream name, exactly like balancer state).
//!
//! # Backoff
//!
//! Nominal delay before retry n (n = 1 for the first retry) is
//! `min(base * 2^(n-1), cap)` (saturating). The actual sleep applies FULL
//! JITTER, AWS style: a uniform random duration in `[0, nominal]`
//! (`backoff_with_full_jitter`). Full jitter avoids the thundering-herd
//! synchronization of decorrelated jitter while still bounding the worst
//! case by the nominal delay. Randomness is a process-local xorshift64*
//! seed under a CAS loop — the same pattern as the load balancer's
//! `random-2` draws, no `rand` dependency.
//!
//! # Total latency
//!
//! There is no cross-attempt total deadline in v1: worst case the retry
//! loop adds up to `attempts * (read_ms + backoff_cap_ms)` of latency to a
//! single request (each attempt pays its own read timeout plus at most the
//! backoff cap before it).

use std::collections::VecDeque;
// DW-025: loom-model-checked Mutex under the `loom` dev feature.
#[cfg(feature = "loom")]
use loom::sync::Mutex;
#[cfg(not(feature = "loom"))]
use std::sync::Mutex;
// OnceLock seeds the jitter RNG in production code; it stays std.
use std::sync::OnceLock;
use std::time::Duration;

use crate::config::RetryConfig;

/// Rolling window the retry budget accounts over (milliseconds).
pub const RETRY_BUDGET_WINDOW_MS: u64 = 10_000;
/// Validation bound on `retries.attempts` (mirrored in `snapshot::validate`).
pub const MAX_RETRY_ATTEMPTS: u32 = 10;
/// Default retry statuses (`502, 503, 504`).
pub const DEFAULT_RETRY_STATUSES: [u16; 3] = [502, 503, 504];

/// Resolved (validated) retry parameters for one upstream. `attempts == 0`
/// disables retries entirely — the single-attempt path then performs no
/// body buffering and no extra per-request work (the budget denominator is
/// still recorded: the window counts all proxied traffic).
#[derive(Debug, Clone, PartialEq)]
pub struct RetryParams {
    /// Maximum retries beyond the first attempt.
    pub attempts: u32,
    /// Whether POST requests may be retried (opt-in). Governs POST only:
    /// other non-idempotent methods (DELETE, PATCH, ...) are never retried.
    pub retry_post: bool,
    /// Backoff base (milliseconds).
    pub backoff_base_ms: u64,
    /// Backoff ceiling (milliseconds).
    pub backoff_cap_ms: u64,
    /// Response statuses that trigger a retry.
    pub retry_statuses: Vec<u16>,
    /// Whether transport errors and per-attempt read timeouts trigger a
    /// retry.
    pub retry_transport: bool,
    /// Retry budget percentage in (0, 100].
    pub budget_percent: u32,
    /// Request-body buffering cap in bytes.
    pub buffer_max_bytes: u64,
}

impl Default for RetryParams {
    fn default() -> Self {
        RetryParams {
            attempts: 0,
            retry_post: false,
            backoff_base_ms: 25,
            backoff_cap_ms: 250,
            retry_statuses: DEFAULT_RETRY_STATUSES.to_vec(),
            retry_transport: true,
            budget_percent: 10,
            buffer_max_bytes: 0,
        }
    }
}

impl RetryParams {
    /// Resolve from the config form; `None` yields the disabled default
    /// (serde has already applied per-field defaults for a present block).
    pub fn from_config(cfg: Option<&RetryConfig>) -> Self {
        match cfg {
            None => RetryParams::default(),
            Some(c) => RetryParams {
                attempts: c.attempts,
                retry_post: c.retry_post,
                backoff_base_ms: c.backoff_base_ms,
                backoff_cap_ms: c.backoff_cap_ms,
                retry_statuses: c.retry_statuses.clone(),
                retry_transport: c.retry_transport,
                budget_percent: c.budget_percent,
                buffer_max_bytes: c.buffer_max_bytes,
            },
        }
    }

    /// Whether a response status triggers a retry under these parameters.
    pub fn retries_status(&self, status: u16) -> bool {
        self.retry_statuses.contains(&status)
    }
}

/// Unix-epoch milliseconds (the same clock convention as passive health).
fn system_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Per-upstream rolling-window retry budget. Share via `Arc` from the
/// upstream handle; the lock is taken once per proxied request (record)
/// and once per retry decision (reserve) — never per attempt frame.
pub struct RetryBudget {
    window_ms: u64,
    now_ms: fn() -> u64,
    events: Mutex<VecDeque<(u64, bool)>>,
}

impl Default for RetryBudget {
    fn default() -> Self {
        RetryBudget::new()
    }
}

impl RetryBudget {
    /// New budget on the system clock with the standard window.
    pub fn new() -> Self {
        RetryBudget::with_clock(RETRY_BUDGET_WINDOW_MS, system_now_ms)
    }

    /// New budget with a caller-supplied millisecond clock (Unix epoch).
    /// Intended for tests; production keeps the system clock.
    pub fn with_clock(window_ms: u64, now_ms: fn() -> u64) -> Self {
        RetryBudget {
            window_ms,
            now_ms,
            events: Mutex::new(VecDeque::new()),
        }
    }

    fn prune_locked(&self, events: &mut VecDeque<(u64, bool)>, now: u64) {
        while events
            .front()
            .is_some_and(|&(t, _)| now.saturating_sub(t) >= self.window_ms)
        {
            events.pop_front();
        }
    }

    /// Record one proxied request (the denominator of the budget ratio).
    /// Called once per request, never per attempt.
    pub fn record_request(&self) {
        let now = (self.now_ms)();
        let mut events = self.events.lock().expect("retry budget poisoned");
        self.prune_locked(&mut events, now);
        events.push_back((now, false));
    }

    /// Whether a retry may be issued under `percent`, charging it
    /// atomically (check + record under one lock acquisition) so the
    /// in-window invariant `retries * 100 <= percent * requests` is never
    /// exceeded, even under concurrent retries. `requests` counts the
    /// ORIGINAL proxied requests only (retry events are excluded from the
    /// denominator — the budget bounds retries as a share of real
    /// traffic). The candidate retry is charged BEFORE it runs: allowing
    /// requires `(retries + 1) * 100 <= percent * requests` to hold
    /// already, so a fresh window with little volume grants few or no
    /// retries rather than a burst.
    pub fn try_reserve_retry(&self, percent: u32) -> bool {
        let now = (self.now_ms)();
        let mut events = self.events.lock().expect("retry budget poisoned");
        self.prune_locked(&mut events, now);
        let requests = events.iter().filter(|(_, r)| !*r).count() as u64;
        let retries = events.len() as u64 - requests;
        if (retries + 1) * 100 <= u64::from(percent) * requests {
            events.push_back((now, true));
            true
        } else {
            false
        }
    }

    /// In-window totals (observability/tests).
    pub fn totals(&self) -> usize {
        let now = (self.now_ms)();
        let mut events = self.events.lock().expect("retry budget poisoned");
        self.prune_locked(&mut events, now);
        events.len()
    }

    /// In-window retries (observability/tests).
    pub fn retries(&self) -> usize {
        let now = (self.now_ms)();
        let mut events = self.events.lock().expect("retry budget poisoned");
        self.prune_locked(&mut events, now);
        events.iter().filter(|(_, r)| *r).count()
    }
}

impl std::fmt::Debug for RetryBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetryBudget")
            .field("window_ms", &self.window_ms)
            .field("totals", &self.totals())
            .field("retries", &self.retries())
            .finish()
    }
}

fn xorshift(x: u64) -> u64 {
    let mut x = x.wrapping_add(0x9E3779B97F4A7C15);
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    x.wrapping_mul(0x2545F4914F6CDD1D)
}

fn jitter_rng() -> u64 {
    static SEED: OnceLock<u64> = OnceLock::new();
    static STATE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seed = *SEED.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x853c49e6748fea9b)
            ^ (std::process::id() as u64)
    });
    loop {
        let x = STATE.load(std::sync::atomic::Ordering::Relaxed);
        // A zero state would freeze xorshift at 0; fold the seed in so the
        // first draw (and every wrap) is nonzero.
        let nx = xorshift(x ^ seed);
        if STATE
            .compare_exchange(
                x,
                nx,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
        {
            return nx;
        }
    }
}

/// Nominal (pre-jitter) backoff for retry number `retry` (1 = the first
/// retry): `min(base * 2^(retry-1), cap)`, saturating on both the shift
/// and the multiply.
pub fn nominal_backoff_ms(base_ms: u64, cap_ms: u64, retry: u32) -> u64 {
    let shift = (retry - 1).min(63);
    base_ms
        .saturating_mul(1u64 << shift)
        .min(cap_ms.max(base_ms))
}

/// Full-jitter sleep duration for retry number `retry` (1 = the first
/// retry): a uniform draw in `[0, nominal_backoff_ms(base, cap, retry)]`
/// (AWS "Exponential Backoff and Jitter" full jitter). Pure in `rand` so
/// tests can pin bounds; the production draw is [`jitter_delay`].
pub fn backoff_with_full_jitter(base_ms: u64, cap_ms: u64, retry: u32, rand: u64) -> Duration {
    let nominal = nominal_backoff_ms(base_ms, cap_ms, retry);
    Duration::from_millis(rand % (nominal + 1))
}

/// [`backoff_with_full_jitter`] drawing from the process-local rng.
pub fn jitter_delay(base_ms: u64, cap_ms: u64, retry: u32) -> Duration {
    backoff_with_full_jitter(base_ms, cap_ms, retry, jitter_rng())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nominal_backoff_doubles_then_caps() {
        assert_eq!(nominal_backoff_ms(25, 250, 1), 25);
        assert_eq!(nominal_backoff_ms(25, 250, 2), 50);
        assert_eq!(nominal_backoff_ms(25, 250, 3), 100);
        assert_eq!(nominal_backoff_ms(25, 250, 4), 200);
        assert_eq!(nominal_backoff_ms(25, 250, 5), 250, "capped");
        assert_eq!(nominal_backoff_ms(25, 250, 20), 250);
        // Saturating shifts never panic or wrap.
        assert_eq!(nominal_backoff_ms(u64::MAX / 2, u64::MAX, 3), u64::MAX);
    }

    #[test]
    fn full_jitter_stays_within_bounds() {
        for retry in 1..=6 {
            let nominal = nominal_backoff_ms(25, 250, retry);
            for rand in [0, 1, 7, nominal, nominal + 1, u64::MAX] {
                let d = backoff_with_full_jitter(25, 250, retry, rand);
                assert!(d.as_millis() as u64 <= nominal, "{d:?} > nominal {nominal}");
            }
            // rand = 0 and rand = nominal pin the endpoints exactly.
            assert_eq!(backoff_with_full_jitter(25, 250, retry, 0), Duration::ZERO);
        }
    }

    #[test]
    fn budget_invariant_holds_under_exhaustion() {
        static NOW: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1_000);
        let budget =
            RetryBudget::with_clock(10_000, || NOW.load(std::sync::atomic::Ordering::Relaxed));
        // 20 recorded requests, 10% budget: at most 2 retries allowed.
        for _ in 0..20 {
            budget.record_request();
        }
        let mut allowed = 0;
        while budget.try_reserve_retry(10) {
            allowed += 1;
            assert!(allowed <= 2, "budget overshot: {allowed} retries");
        }
        assert_eq!(allowed, 2);
        assert_eq!(budget.totals(), 22);
        assert_eq!(budget.retries(), 2);
        // Invariant: retries * 100 <= percent * non-retry totals is checked
        // as (retries+1)*100 <= percent*totals; after exhaustion the next
        // reservation must fail.
        assert!(!budget.try_reserve_retry(10));
    }

    #[test]
    fn budget_window_expires_and_grants_again() {
        static NOW: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1_000);
        let budget =
            RetryBudget::with_clock(10_000, || NOW.load(std::sync::atomic::Ordering::Relaxed));
        budget.record_request();
        assert!(budget.try_reserve_retry(100), "100% of 1 total allows 1");
        assert!(
            !budget.try_reserve_retry(100),
            "1 retry per 1 total at 100%"
        );
        NOW.store(12_000, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(budget.totals(), 0, "window expired");
        assert!(!budget.try_reserve_retry(100), "no totals: no retries");
    }

    #[test]
    fn resolved_params_default_is_off() {
        assert_eq!(RetryParams::from_config(None).attempts, 0);
        assert_eq!(
            RetryParams::from_config(Some(&RetryConfig::default())).attempts,
            0
        );
        let p = RetryParams::from_config(Some(&RetryConfig {
            attempts: 3,
            ..RetryConfig::default()
        }));
        assert_eq!(p.attempts, 3);
        assert_eq!(p.retry_statuses, vec![502, 503, 504]);
        assert!(p.retries_status(503));
        assert!(!p.retries_status(500));
        assert_eq!(p.buffer_max_bytes, 0);
    }
}
