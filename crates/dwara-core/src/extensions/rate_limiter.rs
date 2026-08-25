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
//! **Editions:** OSS ships [`InMemoryRateLimiter`] (fixed window; DW-017
//! builds the real sharded limiter behind this same trait). Additional
//! distributed limiter backends may be provided separately in future
//! editions.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

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
/// Real sharded limiter with per-consumer policies lands in DW-017; this
/// skeleton provides the same decide-and-reserve semantics with a single
/// global budget per key so call sites and signatures are already final.
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
}
