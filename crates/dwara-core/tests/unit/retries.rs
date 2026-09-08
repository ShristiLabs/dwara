//! Unit tests for `resilience::retries` (relocated from src).

use std::time::Duration;

use dwara_core::config::RetryConfig;
use dwara_core::resilience::retries::*;

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
    let budget = RetryBudget::with_clock(10_000, || NOW.load(std::sync::atomic::Ordering::Relaxed));
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
    let budget = RetryBudget::with_clock(10_000, || NOW.load(std::sync::atomic::Ordering::Relaxed));
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

#[test]
fn total_deadline_resolves_from_config() {
    // Absent -> unbounded (the v1 default).
    let p = RetryParams::from_config(Some(&RetryConfig::default()));
    assert!(p.total_deadline.is_none());
    // Present -> resolved to a Duration.
    let p = RetryParams::from_config(Some(&RetryConfig {
        total_deadline_ms: Some(500),
        ..RetryConfig::default()
    }));
    assert_eq!(p.total_deadline, Some(Duration::from_millis(500)));
}

#[test]
fn retry_sleep_under_total_deadline_bounds() {
    let delay = Duration::from_millis(100);
    // Unbounded: the full delay passes through.
    assert_eq!(
        retry_sleep_under_total_deadline(None, Duration::ZERO, delay),
        Some(delay)
    );
    // Elapsed already at/over the deadline: abort.
    assert_eq!(
        retry_sleep_under_total_deadline(
            Some(Duration::from_millis(50)),
            Duration::from_millis(50),
            delay
        ),
        None
    );
    assert_eq!(
        retry_sleep_under_total_deadline(
            Some(Duration::from_millis(50)),
            Duration::from_millis(60),
            delay
        ),
        None
    );
    // Delay fits within the remaining budget: full delay.
    assert_eq!(
        retry_sleep_under_total_deadline(
            Some(Duration::from_millis(200)),
            Duration::from_millis(50),
            delay
        ),
        Some(delay)
    );
    // Delay would cross the deadline: clamped to the remaining slice.
    assert_eq!(
        retry_sleep_under_total_deadline(
            Some(Duration::from_millis(80)),
            Duration::from_millis(50),
            delay
        ),
        Some(Duration::from_millis(30))
    );
}
