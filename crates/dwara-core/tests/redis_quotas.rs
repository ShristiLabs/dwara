//! Integration tests for the Redis-backed distributed quota checker
//! (DW-155, ent feature only).
//!
//! The real-Redis smoke test is skipped when `REDIS_URL` is unset, so
//! the default CI matrix (no Redis) never runs it. Set `REDIS_URL` to
//! a real Redis instance to exercise the atomic Lua check-and-reserve
//! round-trip.

#![cfg(feature = "ent")]

use std::time::Duration;

use dwara_core::config::ConsumerQuotas;
use dwara_core::extensions::redis_quotas::RedisQuotaChecker;
use dwara_core::state::quotas::{Budget, QuotaOutcome};

/// A real-Redis smoke test, skipped when REDIS_URL is unset. Verifies
/// the RedisQuotaChecker atomically check-and-reserves a daily budget:
/// requests under the limit are allowed, the limit-th request is
/// allowed, and the next request is denied. A second "instance"
/// (checker sharing the same Redis) sees the counter the first
/// instance wrote, so a fleet of N instances enforces the CONFIGURED
/// cap (not N x cap).
#[tokio::test]
async fn redis_quota_checker_enforces_shared_cap() {
    let Ok(url) = std::env::var("REDIS_URL") else {
        eprintln!("skipping redis quota smoke test: REDIS_URL not set");
        return;
    };
    let client = redis::Client::open(url.as_str()).expect("redis client");
    let conn = tokio::time::timeout(Duration::from_secs(2), client.get_connection_manager())
        .await
        .expect("connect timeout")
        .expect("connect");

    // Unique prefix so this test run does not collide with others.
    let prefix = format!("dwara:test:quota:{}:", std::process::id());

    // Clean any leftover from a prior run.
    {
        let mut c = redis::aio::ConnectionManager::new(
            redis::Client::open(url.as_str()).expect("redis client"),
        )
        .await
        .expect("connect");
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(format!("{prefix}*"))
            .query_async(&mut c)
            .await
            .expect("keys");
        if !keys.is_empty() {
            let _: () = redis::cmd("DEL")
                .arg(keys)
                .query_async(&mut c)
                .await
                .expect("del");
        }
    }

    // Consumer 42, daily limit 5, no monthly limit.
    let quotas = ConsumerQuotas {
        daily_requests: Some(5),
        monthly_requests: None,
        dry_run: false,
    };
    // Use a fixed epoch that falls inside a known day window so the
    // key is deterministic.
    let now_epoch_s = 1_787_961_600; // 2026-08-29T00:00:00Z

    // Instance A: spend 3 of the 5 daily budget.
    let checker_a = RedisQuotaChecker::new(conn.clone(), true, prefix.clone());
    for _ in 0..3 {
        let outcome = checker_a.check(42, &quotas, now_epoch_s).await;
        match outcome {
            QuotaOutcome::Allowed { limit, .. } => assert_eq!(limit, 5),
            other => panic!("expected Allowed, got {other:?}"),
        }
    }

    // Instance B (shares the same Redis): spend the remaining 2.
    let checker_b = RedisQuotaChecker::new(conn.clone(), true, prefix.clone());
    for _ in 0..2 {
        let outcome = checker_b.check(42, &quotas, now_epoch_s).await;
        match outcome {
            QuotaOutcome::Allowed {
                limit, remaining, ..
            } => {
                assert_eq!(limit, 5);
                assert!(remaining < 5, "remaining should be below limit");
            }
            other => panic!("expected Allowed, got {other:?}"),
        }
    }

    // The 6th request (from either instance) must be denied — the
    // shared counter is at 5, the configured cap.
    let outcome = checker_a.check(42, &quotas, now_epoch_s).await;
    match outcome {
        QuotaOutcome::Denied {
            limit,
            budget,
            retry_after_s,
            ..
        } => {
            assert_eq!(limit, 5);
            assert_eq!(budget, Budget::Daily);
            assert!(retry_after_s > 0, "denied request must advertise a wait");
        }
        other => panic!("expected Denied, got {other:?}"),
    }

    // A different consumer (43) has its OWN counter — not affected by
    // consumer 42's exhaustion.
    let outcome = checker_b.check(43, &quotas, now_epoch_s).await;
    match outcome {
        QuotaOutcome::Allowed { limit, .. } => assert_eq!(limit, 5),
        other => panic!("expected Allowed for consumer 43, got {other:?}"),
    }
}

/// A real-Redis test for the fail-closed policy, skipped when
/// REDIS_URL is unset. Verifies that when fail_open=false and Redis is
/// reachable, a configured budget is enforced (the deny path). This is
/// the complement of the fail-open test above.
#[tokio::test]
async fn redis_quota_checker_fail_closed_denies() {
    let Ok(url) = std::env::var("REDIS_URL") else {
        eprintln!("skipping redis quota fail-closed test: REDIS_URL not set");
        return;
    };
    let client = redis::Client::open(url.as_str()).expect("redis client");
    let conn = tokio::time::timeout(Duration::from_secs(2), client.get_connection_manager())
        .await
        .expect("connect timeout")
        .expect("connect");

    let prefix = format!("dwara:test:quota:fc:{}:", std::process::id());

    // Clean any leftover from a prior run.
    {
        let mut c = redis::aio::ConnectionManager::new(
            redis::Client::open(url.as_str()).expect("redis client"),
        )
        .await
        .expect("connect");
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(format!("{prefix}*"))
            .query_async(&mut c)
            .await
            .expect("keys");
        if !keys.is_empty() {
            let _: () = redis::cmd("DEL")
                .arg(keys)
                .query_async(&mut c)
                .await
                .expect("del");
        }
    }

    // Consumer 7, daily limit 1, fail-closed.
    let quotas = ConsumerQuotas {
        daily_requests: Some(1),
        monthly_requests: None,
        dry_run: false,
    };
    let now_epoch_s = 1_787_961_600;
    let checker = RedisQuotaChecker::new(conn, false, prefix.clone());

    // First request: allowed (counter 0 -> 1).
    let outcome = checker.check(7, &quotas, now_epoch_s).await;
    assert!(matches!(outcome, QuotaOutcome::Allowed { .. }));

    // Second request: denied (counter 1, limit 1).
    let outcome = checker.check(7, &quotas, now_epoch_s).await;
    match outcome {
        QuotaOutcome::Denied { budget, .. } => assert_eq!(budget, Budget::Daily),
        other => panic!("expected Denied, got {other:?}"),
    }
}
