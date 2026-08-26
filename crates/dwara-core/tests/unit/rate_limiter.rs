//! Unit tests for `extensions::rate_limiter` (relocated from src).
//!
//! The two formerly white-box clock tests construct the limiter through
//! the public [`InMemoryRateLimiter::with_clock`] API instead of writing
//! the private `now_ms` field.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::time::Duration;

use dwara_core::extensions::rate_limiter::*;

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

// Deterministic clock: a thread-local millisecond counter the tests
// advance. Each #[tokio::test] runs on its own thread, so tests using
// the clock are isolated from each other.
thread_local! {
    static TIME: std::cell::Cell<u64> = const { std::cell::Cell::new(1_000) };
}

/// The plain-`fn` clock handed to `InMemoryRateLimiter::with_clock`.
fn test_clock() -> u128 {
    u128::from(TIME.with(|t| t.get()))
}

fn advance_clock(ms: u64) {
    TIME.with(|t| t.set(ms));
}

#[tokio::test]
async fn denial_reports_positive_retry_after_within_window() {
    let limiter = InMemoryRateLimiter::with_clock(1, 10_000, test_clock);
    limiter.check("k", 1).await.unwrap();
    advance_clock(4_000);
    let denied = limiter.check("k", 1).await.unwrap();
    assert!(!denied.allowed);
    assert_eq!(denied.remaining, 0);
    // 10s window started at t=1000; at t=4000 the caller must wait 7s.
    assert_eq!(denied.retry_after_ms, Some(7_000));
}

#[tokio::test]
async fn window_resets_after_injected_clock_advance() {
    let limiter = InMemoryRateLimiter::with_clock(1, 10_000, test_clock);
    assert!(limiter.check("k", 1).await.unwrap().allowed);
    assert!(!limiter.check("k", 1).await.unwrap().allowed);
    advance_clock(11_000);
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
    let limiter = GcraRateLimiter::new(vec![window(100, 1, None), window(3, 10, None)]).unwrap();
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
    let limiter = std::sync::Arc::new(GcraRateLimiter::new(vec![window(5, 60, Some(5))]).unwrap());
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
    RateLimitEngine::compile(&dwara_core::config::parse_gateway(yaml).unwrap())
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
