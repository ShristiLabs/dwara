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

/// The millisecond clock handed to `GcraRateLimiter::with_clock` (the
/// eviction-bookkeeping clock; the GCRA math stays on governor's clock).
fn test_clock_ms() -> u64 {
    TIME.with(|t| t.get())
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
    // shard-store state must linearize, admitting EXACTLY 5 and
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

/// Context variant with an authenticated consumer (the `credential`
/// selector path; `None` exercises the documented peer fallback).
fn ctx_consumer(peer: &str, consumer: Option<&'static str>) -> RateLimitKeyContext<'static> {
    RateLimitKeyContext {
        peer: peer.parse::<IpAddr>().unwrap(),
        consumer,
        route: "a",
    }
}

/// Two rules with DIFFERENT selectors and caps, both applicable to one
/// request: each compiled rule owns an independent limiter/store, so
/// their caps must not leak into each other even when they build the
/// SAME key string (see the per-rule isolation test).
const IP_AND_CREDENTIAL_RULES_YAML: &str = r#"
policies:
  - name: per-ip
    rate_limits:
      - selector: [ip]
        requests_per: { minute: 3 }
  - name: per-cred
    rate_limits:
      - selector: [credential]
        requests_per: { minute: 2 }
"#;

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
            engine.check(&ctx("10.0.0.1", "a"), &[], &[], &per_ip, &[], &[]),
            RateLimitOutcome::Allowed { .. }
        ));
    }
    assert!(matches!(
        engine.check(&ctx("10.0.0.1", "a"), &[], &[], &per_ip, &[], &[]),
        RateLimitOutcome::Denied { limit: 3, .. }
    ));
    assert!(
        matches!(
            engine.check(&ctx("10.0.0.2", "a"), &[], &[], &per_ip, &[], &[]),
            RateLimitOutcome::Allowed { .. }
        ),
        "a different client IP has an independent key"
    );
}

#[tokio::test]
async fn engine_resolves_a_policy_listed_at_two_levels_once() {
    // The SAME policy attached at two levels (here consumer AND global)
    // is ONE evaluation: the name resolves at its first — most
    // specific — chain position only, so the minute:3 budget admits
    // exactly three requests with Remaining stepping 2 -> 1 -> 0 and
    // denies the fourth. The pre-dedup engine evaluated the rule once
    // per attaching level and throttled at request 2.
    let engine = engine_from(IP_RULES_YAML);
    let per_ip: Vec<String> = vec!["per-ip".into()];
    for expected_remaining in [2, 1, 0] {
        assert!(
            matches!(
                engine.check(&ctx("10.0.0.1", "a"), &per_ip, &[], &[], &[], &per_ip),
                RateLimitOutcome::Allowed { remaining, .. }
                    if remaining == expected_remaining
            ),
            "single evaluation: remaining must be {expected_remaining} after one admission"
        );
    }
    assert!(matches!(
        engine.check(&ctx("10.0.0.1", "a"), &per_ip, &[], &[], &[], &per_ip),
        RateLimitOutcome::Denied {
            limit: 3,
            remaining: 0,
            ..
        }
    ));
}

#[tokio::test]
async fn engine_selector_ip_route_keys_pairs_independently() {
    let engine = engine_from(IP_RULES_YAML);
    let ip_route: Vec<String> = vec!["ip-route".into()];
    for _ in 0..3 {
        assert!(matches!(
            engine.check(&ctx("10.0.0.1", "a"), &[], &ip_route, &[], &[], &[]),
            RateLimitOutcome::Allowed { .. }
        ));
    }
    assert!(matches!(
        engine.check(&ctx("10.0.0.1", "a"), &[], &ip_route, &[], &[], &[]),
        RateLimitOutcome::Denied { .. }
    ));
    // Same IP, different route: independent (ip, route) key.
    assert!(matches!(
        engine.check(&ctx("10.0.0.1", "b"), &[], &ip_route, &[], &[], &[]),
        RateLimitOutcome::Allowed { .. }
    ));
}

#[tokio::test]
async fn engine_without_matching_policy_is_not_limited() {
    let engine = engine_from(IP_RULES_YAML);
    for _ in 0..10 {
        assert_eq!(
            engine.check(&ctx("10.0.0.1", "a"), &[], &[], &[], &[], &[]),
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
        engine.check(&ctx("10.0.0.1", "r"), &[], &legacy, &[], &[], &[]),
        RateLimitOutcome::Allowed { .. }
    ));
    assert!(matches!(
        engine.check(&ctx("10.0.0.1", "r"), &[], &legacy, &[], &[], &[]),
        RateLimitOutcome::Allowed { .. }
    ));
    // Legacy field keys by ROUTE: a second client on the same route
    // shares the budget (the documented [route] mapping).
    assert!(matches!(
        engine.check(&ctx("10.0.0.2", "r"), &[], &legacy, &[], &[], &[]),
        RateLimitOutcome::Denied { limit: 2, .. }
    ));
}

#[tokio::test]
async fn engine_reports_decreasing_remaining_and_reset() {
    let engine = engine_from(IP_RULES_YAML);
    let per_ip: Vec<String> = vec!["per-ip".into()];
    let first = engine.check(&ctx("10.0.0.9", "a"), &[], &[], &per_ip, &[], &[]);
    let second = engine.check(&ctx("10.0.0.9", "a"), &[], &[], &per_ip, &[], &[]);
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

// --- #122: size-capped per-key eviction ----------------------------------
//
// The store is bounded at MAX_RATE_LIMITER_KEYS_PER_SHARD per shard with
// GCRA_STORE_SHARDS fixed shards. Eviction is idlest-first by
// (last_touch_ms, key); a key re-touched at the newest stamp with the
// lexically greatest key of its stamp group can never be the eviction
// victim, which is what makes the "hot key" assertions below
// deterministic (the sweep evicts only the OLDEST half).

/// Bound helper: the whole-store worst case per window.
fn store_bound() -> usize {
    dwara_core::config::limits::MAX_RATE_LIMITER_KEYS_PER_SHARD * GCRA_STORE_SHARDS
}

/// Spraying far more distinct keys than the whole-store bound must keep
/// the live key count under the bound (pigeonhole: 100_000 keys over a
/// 65_536-capacity store forces sweeps, deterministically), and a key
/// hammered at the newest stamp throughout must stay enforced.
#[tokio::test]
async fn gcra_key_spray_is_size_capped_and_hot_key_stays_enforced() {
    // 3 per 60s (one token per 20s of real time — no refill can
    // interfere within the test's runtime).
    let limiter = GcraRateLimiter::with_clock(vec![window(3, 60, None)], test_clock_ms).unwrap();
    let mut hot_allowed = 0;
    for i in 0..100_000u64 {
        // Strictly increasing stamps so idle eviction and idlest-first
        // ordering are exercised exactly, not by wall-clock accident.
        advance_clock(i + 1);
        let _ = limiter.check(&format!("spray-{i:06}"), 1);
        // "zz-hot" sorts lexically after every "spray-*" key, so within
        // its (newest) stamp group it is the last possible victim.
        if limiter.check("zz-hot", 1).decision.allowed {
            hot_allowed += 1;
        }
    }
    assert!(
        limiter.live_keys() <= store_bound(),
        "sprayed key set {} exceeds the store bound {}",
        limiter.live_keys(),
        store_bound()
    );
    assert!(limiter.evictions() > 0, "the spray must have swept");
    // The hot key survived every sweep: its burst of 3 was spent long
    // ago and the spent state was never dropped.
    assert_eq!(hot_allowed, 3, "burst 3 admits exactly three, then denies");
    assert!(
        !limiter.check("zz-hot", 1).decision.allowed,
        "hot key must still be under enforcement after the spray"
    );
    // And the limiter keeps working for fresh keys.
    assert!(limiter.check("fresh", 1).decision.allowed);
}

/// A cell idle for at least one full refill is dropped by the sweep's
/// idle pass: its next check starts from a FRESH bucket (allowed), not
/// the spent one. The crowd keys land across all 16 shards (400_000
/// keys, ~25_000 expected per shard vs a 4_096 cap — a >270-sigma
/// margin that "k"'s own shard also reaches its cap and sweeps).
#[tokio::test]
async fn gcra_idle_cells_evicted_by_the_sweep() {
    // 2 per 60s: full refill = one full window.
    let limiter = GcraRateLimiter::with_clock(vec![window(2, 60, None)], test_clock_ms).unwrap();
    advance_clock(1_000);
    assert!(limiter.check("k", 1).decision.allowed);
    assert!(limiter.check("k", 1).decision.allowed);
    assert!(!limiter.check("k", 1).decision.allowed, "burst 2 is spent");
    // Idle past one full refill, then crowd every shard to force sweeps.
    advance_clock(62_000);
    for i in 0..400_000u32 {
        let _ = limiter.check(&format!("crowd-{i:06}"), 1);
    }
    assert!(limiter.evictions() > 0);
    assert!(limiter.live_keys() <= store_bound());
    assert!(
        limiter.check("k", 1).decision.allowed,
        "the idle cell must have been dropped: k starts from a fresh bucket"
    );
}

/// Integration-ish spray through the policy ENGINE (the public request
/// path): 100_000 distinct client IPs against an [ip]-selector rule,
/// with one hot IP re-checked every iteration. The engine builds keys
/// (peer IP strings) exactly as the gateway does at request time.
#[tokio::test]
async fn engine_ip_spray_key_set_is_bounded_and_hot_ip_enforced() {
    let engine = engine_from(IP_RULES_YAML);
    let per_ip: Vec<String> = vec!["per-ip".into()];
    let hot = "10.9.9.9"; // sorts lexically after every "10.0.*"/"10.1.*" spray IP
    let mut hot_allowed = 0;
    for i in 0..100_000u32 {
        let ip = format!("10.{}.{}.{}", i >> 16, (i >> 8) & 0xff, i & 0xff);
        let _ = engine.check(&ctx(&ip, "a"), &[], &[], &per_ip, &[], &[]);
        if matches!(
            engine.check(&ctx(hot, "a"), &[], &[], &per_ip, &[], &[]),
            RateLimitOutcome::Allowed { .. }
        ) {
            hot_allowed += 1;
        }
    }
    assert!(
        engine.live_keys() <= store_bound(),
        "engine key set {} exceeds the store bound {}",
        engine.live_keys(),
        store_bound()
    );
    assert!(engine.evictions() > 0);
    // minute: 3 admits exactly three over the whole spray, then the hot
    // IP stays denied (its state was never the eviction victim).
    assert_eq!(hot_allowed, 3);
    assert!(matches!(
        engine.check(&ctx(hot, "a"), &[], &[], &per_ip, &[], &[]),
        RateLimitOutcome::Denied { .. }
    ));
}

/// Denied checks must refresh `last_touch`: a key ACTIVELY under
/// enforcement (re-checked every step, throttled since its burst was
/// spent) must survive every sweep its shard takes while a spray keeps
/// the shard crowded — the early size passes (nothing idle yet, the key
/// protected by recency) AND the late idle passes (stale spray cells
/// are the victims; the key is within one step of `now`). If denials
/// stopped refreshing the stamp, the enforced cell would age out and
/// the key would be re-admitted from a fresh bucket (#122: "a throttled
/// key is an ACTIVE key").
#[tokio::test]
async fn gcra_denied_checks_refresh_touch_so_throttled_key_survives_sweeps() {
    // 1 per 60s burst 1: the idle threshold (one full refill) is 60s.
    let limiter = GcraRateLimiter::with_clock(vec![window(1, 60, None)], test_clock_ms).unwrap();
    advance_clock(1_000);
    assert!(limiter.check("zz-hot", 1).decision.allowed);
    assert!(
        !limiter.check("zz-hot", 1).decision.allowed,
        "burst 1 is spent; the denial itself refreshes last_touch"
    );
    // 0.25ms of bookkeeping time per step: the first shards cap around
    // step ~65k with NO idle cells yet (size-pass regime), and by the
    // last steps the oldest ~150k spray cells are past the 60s idle
    // threshold (idle-pass regime with plenty of victims).
    let mut hot_allowed = 0;
    for i in 0..400_000u32 {
        advance_clock(61_000 + u64::from(i) / 4);
        let _ = limiter.check(&format!("spray-{i:06}"), 1);
        if limiter.check("zz-hot", 1).decision.allowed {
            hot_allowed += 1;
        }
    }
    assert_eq!(
        hot_allowed, 0,
        "a throttled key re-checked every step must never be re-admitted"
    );
    assert!(
        !limiter.check("zz-hot", 1).decision.allowed,
        "enforcement must survive every sweep of the sustained spray"
    );
    assert!(limiter.evictions() > 0, "the spray must have swept");
    assert!(limiter.live_keys() <= store_bound());
}

/// All-fresh spray at the cap, hot key under CONTINUOUS enforcement:
/// the size pass evicts the IDLEST half, and a key re-checked every 64
/// spray steps is always within ~8ms of `now` while the shard's 4,096
/// cells span ~8s of stamps — so the hammered key is never the eviction
/// victim and keeps its spent cell for the whole flood. This pins the
/// benign half of the documented size-pass trade (#122).
#[tokio::test]
async fn gcra_all_fresh_spray_keeps_continuously_hammered_key_enforced() {
    let limiter = GcraRateLimiter::with_clock(vec![window(1, 60, None)], test_clock_ms).unwrap();
    advance_clock(1_000);
    let mut hot_allowed = usize::from(limiter.check("zz-hot", 1).decision.allowed);
    // 1ms per 8 keys: the 400k-key flood spans 50s of bookkeeping time,
    // under the 60s idle threshold — every crowded sweep is a pure SIZE
    // pass (no idle victims can exist).
    for i in 0..400_000u32 {
        advance_clock(2_000 + u64::from(i) / 8);
        let _ = limiter.check(&format!("fresh-{i:06}"), 1);
        if i % 64 == 0 && limiter.check("zz-hot", 1).decision.allowed {
            hot_allowed += 1;
        }
    }
    assert_eq!(
        hot_allowed, 1,
        "a continuously hammered key must never be reset by the size pass"
    );
    assert!(!limiter.check("zz-hot", 1).decision.allowed);
    assert!(
        limiter.evictions() > 0,
        "the all-fresh flood must have forced size passes"
    );
    assert!(limiter.live_keys() <= store_bound());
}

/// The honest other half of the size-pass trade (#122): a key whose
/// re-checks are SPARSER than its shard's turnover (one sweep cycle is
/// cap/2 arrivals in the shard = ~32,768 flood steps) sits in the
/// idlest half when a sweep lands and LOSES its cell — the next check
/// starts from a fresh bucket (fail-open for that key). Pinned as a
/// bounded trade: at most one burst re-admission per hot check, and at
/// least one reset over the flood (the first sweep evicts the oldest
/// cell in the shard with certainty: ~25,000 keys per shard vs the
/// 4,096 cap is a >100-sigma guarantee the shard caps).
#[tokio::test]
async fn gcra_all_fresh_spray_resets_slowly_rechecked_key_with_bounded_admissions() {
    let limiter = GcraRateLimiter::with_clock(vec![window(1, 60, None)], test_clock_ms).unwrap();
    advance_clock(1_000);
    let mut hot_allowed = usize::from(limiter.check("zz-hot", 1).decision.allowed);
    // Hot re-checked every 100,000 steps (~3 sweep cycles apart): the
    // initial + 5 loop checks bound the admissions structurally at 6.
    for i in 0..=400_000u32 {
        advance_clock(2_000 + u64::from(i) / 8);
        let _ = limiter.check(&format!("fresh-{i:06}"), 1);
        if i % 100_000 == 0 && limiter.check("zz-hot", 1).decision.allowed {
            hot_allowed += 1;
        }
    }
    assert!(
        (2..=6).contains(&hot_allowed),
        "slowly re-checked key must be reset at least once ({hot_allowed}) \
         but readmitted at most once per re-check ({hot_allowed} > 6)"
    );
    assert!(limiter.evictions() > 0);
    assert!(limiter.live_keys() <= store_bound());
}

/// Distribution sanity below the cap (#122): 32,768 distinct keys is
/// half the whole-store bound (~2,048 per shard, >40 sigma under the
/// 4,096 cap), so NO shard may sweep — zero evictions and an EXACT live
/// count. Two stacked windows each hold their own copy of every key:
/// `live_keys` sums both (2 x 32,768), proving the accounting spans
/// every shard of every window (a missed shard would short the count; a
/// collapsed distribution would trip the cap and evict).
#[tokio::test]
async fn gcra_below_cap_spray_never_sweeps_and_counts_every_shard_and_window() {
    let limiter = GcraRateLimiter::with_clock(
        vec![window(3, 60, None), window(100, 3_600, None)],
        test_clock_ms,
    )
    .unwrap();
    advance_clock(1_000);
    for i in 0..32_768u32 {
        let _ = limiter.check(&format!("spread-{i:06}"), 1);
    }
    assert_eq!(limiter.evictions(), 0, "half-capacity spray must not evict");
    assert_eq!(
        limiter.live_keys(),
        65_536,
        "two windows x 32,768 keys, all live"
    );
}

/// Engine-level: the `credential` selector keys by CONSUMER (not peer),
/// anonymous traffic falls back to the peer IP per key, and two rules
/// with different selectors keep SEPARATE state even when they compose
/// the same key string — the per-cred rule's anonymous fallback builds
/// "10.0.0.2", the very string the per-ip rule uses, yet exhausting one
/// never touches the other's budget (#122 store-per-rule isolation).
#[tokio::test]
async fn engine_credential_rule_keys_by_consumer_and_rules_are_isolated() {
    let engine = engine_from(IP_AND_CREDENTIAL_RULES_YAML);
    let both: Vec<String> = vec!["per-ip".into(), "per-cred".into()];
    let per_ip_only: Vec<String> = vec!["per-ip".into()];
    let per_cred_only: Vec<String> = vec!["per-cred".into()];

    let alice = ctx_consumer("10.0.0.1", Some("alice"));
    // Both rules apply; the credential rule (cap 2) is the tighter one.
    assert!(matches!(
        engine.check(&alice, &[], &both, &[], &[], &[]),
        RateLimitOutcome::Allowed {
            limit: 2,
            remaining: 1,
            ..
        }
    ));
    assert!(matches!(
        engine.check(&alice, &[], &both, &[], &[], &[]),
        RateLimitOutcome::Allowed {
            limit: 2,
            remaining: 0,
            ..
        }
    ));
    // Third check: the credential rule denies (cap 2) while the ip rule
    // still had budget — rules evaluate independently.
    assert!(matches!(
        engine.check(&alice, &[], &both, &[], &[], &[]),
        RateLimitOutcome::Denied { limit: 2, .. }
    ));
    // Same consumer from a fresh IP: still denied — the credential key
    // is the consumer, not the peer.
    assert!(matches!(
        engine.check(
            &ctx_consumer("10.0.0.2", Some("alice")),
            &[],
            &both,
            &[],
            &[],
            &[]
        ),
        RateLimitOutcome::Denied { limit: 2, .. }
    ));
    // Same IP, different consumer: denied by the IP rule (3/3 spent by
    // alice's checks) while bob's credential budget is untouched.
    assert!(matches!(
        engine.check(
            &ctx_consumer("10.0.0.1", Some("bob")),
            &[],
            &both,
            &[],
            &[],
            &[]
        ),
        RateLimitOutcome::Denied { limit: 3, .. }
    ));
    // Anonymous traffic under the credential rule falls back to the
    // peer IP string and gets its own independent cap-2 budget.
    for _ in 0..2 {
        assert!(matches!(
            engine.check(
                &ctx_consumer("10.0.0.2", None),
                &[],
                &per_cred_only,
                &[],
                &[],
                &[]
            ),
            RateLimitOutcome::Allowed { .. }
        ));
    }
    assert!(matches!(
        engine.check(
            &ctx_consumer("10.0.0.2", None),
            &[],
            &per_cred_only,
            &[],
            &[],
            &[]
        ),
        RateLimitOutcome::Denied { limit: 2, .. }
    ));
    // Isolation with identical key strings: the per-ip rule's
    // "10.0.0.2" cell has served exactly ONE request above (alice's
    // fresh-IP check) — the credential rule's anonymous "10.0.0.2"
    // cells never consumed it. Carol still gets the ip budget.
    assert!(matches!(
        engine.check(
            &ctx_consumer("10.0.0.2", Some("carol")),
            &[],
            &per_ip_only,
            &[],
            &[],
            &[]
        ),
        RateLimitOutcome::Allowed {
            limit: 3,
            remaining: 1,
            ..
        }
    ));
    // State-level isolation: two ip cells + three credential cells.
    assert_eq!(engine.live_keys(), 5);
}

/// #132: the eviction and live-key accessors surface as /metrics
/// families. The scrape-time walk (`refresh_rate_limiter_gauges`, on
/// the dataplane — the engine must not import observability) reads the
/// engine's aggregates and sets the two unlabeled gauges; this drives a
/// real key spray past the sharded-store bound and pins that the
/// rendered text carries the engine's actual figures.
#[tokio::test]
async fn evictions_and_live_keys_surface_through_the_scrape_walk() {
    let obs = dwara_core::observability::Observability::new();
    // Zero engine: the walk reports an empty aggregate. A config with
    // no policies compiles an engine with no rules.
    let empty = engine_from("routes:\n  - name: r\n    service: s\n    match:\n      path: { type: prefix, value: / }\n    action: { type: proxy }\nservices:\n  - name: s\n    upstream: u\nupstreams:\n  - name: u\n    endpoints:\n      - { address: 127.0.0.1, port: 1 }\n");
    dwara_core::dataplane::proxy::refresh_rate_limiter_gauges(&empty, &obs);
    let text = obs.render();
    assert!(
        text.contains("dwara_rate_limiter_evictions_total 0"),
        "empty engine renders zero evictions:\n{text}"
    );
    assert!(
        text.contains("dwara_rate_limiter_live_keys 0"),
        "empty engine renders zero live keys:\n{text}"
    );

    // Spray distinct peer IPs past the sharded-store bound: shards fill,
    // the size pass evicts, and the aggregates go non-zero.
    let engine = engine_from(IP_RULES_YAML);
    let per_ip: Vec<String> = vec!["per-ip".into()];
    for i in 0..100_000u32 {
        let ip = format!("10.{}.{}.{}", i >> 16, (i >> 8) & 0xff, i & 0xff);
        let _ = engine.check(&ctx(&ip, "a"), &[], &[], &per_ip, &[], &[]);
    }
    assert!(engine.evictions() > 0, "spray must have evicted");
    assert!(engine.live_keys() <= store_bound());
    dwara_core::dataplane::proxy::refresh_rate_limiter_gauges(&engine, &obs);
    let text = obs.render();
    assert!(
        text.contains(&format!(
            "dwara_rate_limiter_evictions_total {}",
            engine.evictions()
        )),
        "eviction gauge carries the engine's figure:\n{text}"
    );
    assert!(
        text.contains(&format!(
            "dwara_rate_limiter_live_keys {}",
            engine.live_keys()
        )),
        "live-keys gauge carries the engine's figure:\n{text}"
    );
}
