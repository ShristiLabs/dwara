//! Distributed Redis-backed consumer request quotas (DW-155, ent feature).
//!
//! The same budget semantics as the local
//! [`state::quotas`](crate::config::quotas) module (daily/monthly
//! calendar windows, decide-and-reserve, stop-at-first-denial, max-wait
//! peeking), but the per-consumer per-window counters live in Redis and
//! are incremented atomically via a Lua script in a SINGLE round-trip
//! per budget. Two or more gateway instances sharing one Redis therefore
//! share one quota: a request spent on instance A is seen as spent by
//! instance B, so a fleet of N instances enforces the CONFIGURED cap
//! (not N x cap).
//!
//! # Why a Lua script (not INCR + check)
//!
//! A quota check-and-reserve is a read-modify-write: read the current
//! counter, compare against the limit, increment only if under. Doing
//! this as separate Redis commands (GET, compare, INCR) has a race
//! window between the read and the increment — two instances can both
//! read "99", both see "under the 100 limit", and both increment to
//! 100, admitting 101. The Lua script makes the read-compare-increment
//! atomic: Redis executes scripts single-threaded, so no other command
//! interleaves. One round-trip, no race.
//!
//! # The Lua script
//!
//! `QUOTA_LUA` takes the counter key, the window start, the limit, the
//! increment (always 1 today), and a TTL. It atomically:
//!
//! 1. Reads the counter for the current window (defaulting to 0 if
//!    absent — a fresh window).
//! 2. If `counter + increment > limit`: DENY — return `{0, counter}`
//!    (remaining = limit - counter, no write).
//! 3. Else: ALLOW — increment the counter, set the key's TTL to the
//!    window duration (so stale windows auto-expire), return
//!    `{1, counter + increment}`.
//!
//! # Key format
//!
//! Each (consumer, budget, window) triple gets its own Redis key:
//! `{prefix}{consumer}:{budget}:{window_start}` (e.g.
//! `dwara:quota:42:daily:1787961600`). The window_start in the key
//! ensures a new window starts at 0, not at the previous window's
//! leftover count.
//!
//! # Fail-open / fail-closed
//!
//! If Redis is unreachable, [`RedisQuotaChecker::check`] applies the
//! configured `fail_open` policy, mirroring the Redis rate limiter:
//!
//! - `fail_open: true` (default): the budget is SKIPPED (treated as
//!   allowing). Redis down means no quota enforcement, which is the
//!   safer default for availability.
//! - `fail_open: false`: the budget DENIES. The request gets a 429
//!   from the first budget that cannot reach Redis.
//!
//! # Connection pooling
//!
//! Uses `redis::aio::ConnectionManager` — the same multiplexed,
//! Arc-based, auto-reconnecting connection the Redis rate limiter uses.
//! The connection is established ONCE at startup (in dwara-bin) and
//! cloned cheaply per check.

use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::Script;

use crate::config::quotas::{retry_after, Budget, QuotaOutcome};
use crate::config::ConsumerQuotas;

/// The atomic quota check-and-reserve Lua script (see the module docs).
///
/// KEYS[1] = the counter key ({prefix}{consumer}:{budget}:{window_start})
/// ARGV[1] = window_start (epoch seconds; used only for documentation)
/// ARGV[2] = limit (the configured cap)
/// ARGV[3] = increment (always 1 today)
/// ARGV[4] = ttl_s (key TTL = window duration, so stale windows expire)
/// Returns: {allowed (1/0), counter_after}
const QUOTA_LUA: &str = r#"
local counter = tonumber(redis.call('GET', KEYS[1]) or '0')
local limit = tonumber(ARGV[2])
local increment = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
if counter + increment > limit then
    return {0, counter}
end
local new_counter = counter + increment
redis.call('SET', KEYS[1], new_counter, 'EX', ttl)
return {1, new_counter}
"#;

/// The TTL to set on daily quota keys (seconds in a day + margin).
const DAILY_TTL_S: u64 = 86_400 + 300; // 24h + 5min margin

/// The TTL to set on monthly quota keys (seconds in 31 days + margin).
/// 31 days is the longest month; shorter months' keys expire sooner
/// than this, which is fine — the window_start in the key ensures the
/// next month starts at 0.
const MONTHLY_TTL_S: u64 = 31 * 86_400 + 3_600; // 31d + 1h margin

/// Distributed Redis-backed quota checker (DW-155, ent feature).
///
/// Implements the same budget semantics as
/// [`state::quotas::check`](crate::config::quotas::check), but the
/// per-consumer per-window counters live in Redis and are updated
/// atomically via a Lua script. See the module docs for the algorithm,
/// key format, and fail-open/fail-closed semantics.
pub struct RedisQuotaChecker {
    /// Multiplexed Redis connection (cloned cheaply; Arc-based).
    conn: ConnectionManager,
    /// Fail-open (true) or fail-closed (false) when Redis is unreachable.
    fail_open: bool,
    /// Prefix for Redis keys (e.g. `dwara:quota:`).
    key_prefix: String,
    /// The compiled quota Lua script (EVALSHA-cached by the redis crate).
    script: Script,
}

impl std::fmt::Debug for RedisQuotaChecker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisQuotaChecker")
            .field("fail_open", &self.fail_open)
            .field("key_prefix", &self.key_prefix)
            .finish()
    }
}

/// The trait the dataplane calls to check-and-reserve a quota budget.
/// The local store-backed checker (`state::quotas::check`) is the OSS
/// implementation; [`RedisQuotaChecker`] is the Ent implementation.
/// Both return the same [`QuotaOutcome`] so the request path answers
/// identically regardless of which backend is active.
#[async_trait]
pub trait QuotaChecker: Send + Sync + 'static {
    /// Check-and-reserve one request against every configured budget of
    /// `quotas` for consumer `consumer_id`. See
    /// [`state::quotas::check`](crate::config::quotas::check) for the
    /// evaluation order, the stacking consumption trade, and the
    /// failure model.
    async fn check(
        &self,
        consumer_id: i64,
        quotas: &ConsumerQuotas,
        now_epoch_s: i64,
    ) -> QuotaOutcome;
}

impl RedisQuotaChecker {
    /// New checker over the given Redis connection. The connection is
    /// cloned (cheap, Arc-based) — the caller's handle stays valid.
    pub fn new(conn: ConnectionManager, fail_open: bool, key_prefix: String) -> Self {
        Self {
            conn,
            fail_open,
            key_prefix,
            script: Script::new(QUOTA_LUA),
        }
    }

    /// New checker from a [`crate::config::RedisQuotaConfig`] (the
    /// config block on `Gateway`). Convenience wrapper around
    /// [`Self::new`].
    pub fn from_config(conn: ConnectionManager, config: &crate::config::RedisQuotaConfig) -> Self {
        Self::new(conn, config.fail_open, config.key_prefix.clone())
    }

    /// Check-and-reserve one request against every configured budget
    /// (see the module docs for the evaluation semantics). Returns a
    /// [`QuotaOutcome`] (the same type the local
    /// [`state::quotas::check`](crate::config::quotas::check) returns)
    /// so the request path answers identically regardless of backend.
    pub async fn check(
        &self,
        consumer_id: i64,
        quotas: &ConsumerQuotas,
        now_epoch_s: i64,
    ) -> QuotaOutcome {
        let mut binding: Option<(u64, u64, u64)> = None; // (limit, remaining, reset)

        for budget in Budget::ALL {
            let Some(limit) = budget.limit(quotas) else {
                continue;
            };
            let (window_start, reset_epoch_s) = budget.window(now_epoch_s);
            let ttl = match budget {
                Budget::Daily => DAILY_TTL_S,
                Budget::Monthly => MONTHLY_TTL_S,
            };
            let redis_key = format!(
                "{}{}:{}:{}",
                self.key_prefix,
                consumer_id,
                budget.key(),
                window_start
            );

            match self.check_budget(&redis_key, limit, 1, ttl).await {
                Ok((true, counter_after)) => {
                    let remaining = limit.saturating_sub(counter_after);
                    let reset = reset_epoch_s.unsigned_abs();
                    if binding
                        .as_ref()
                        .is_none_or(|(_, best, _)| remaining < *best)
                    {
                        binding = Some((limit, remaining, reset));
                    }
                }
                Ok((false, counter)) => {
                    // Denied: peek later budgets for max-wait, same as
                    // the local checker.
                    let mut retry_after_s = retry_after(reset_epoch_s, now_epoch_s);
                    let mut denied_reset = reset_epoch_s.unsigned_abs();
                    for later in Budget::ALL {
                        if *later == *budget {
                            continue;
                        }
                        let Some(later_limit) = later.limit(quotas) else {
                            continue;
                        };
                        let (later_start, later_reset) = later.window(now_epoch_s);
                        let later_key = format!(
                            "{}{}:{}:{}",
                            self.key_prefix,
                            consumer_id,
                            later.key(),
                            later_start
                        );
                        // Peek read-only: GET the counter, no increment.
                        if let Ok(used) = self.peek_budget(&later_key).await {
                            if used >= later_limit {
                                let wait = retry_after(later_reset, now_epoch_s);
                                if wait > retry_after_s {
                                    retry_after_s = wait;
                                    denied_reset = later_reset.unsigned_abs();
                                }
                            }
                        }
                    }
                    return QuotaOutcome::Denied {
                        limit,
                        remaining: limit.saturating_sub(counter),
                        reset_epoch_s: denied_reset,
                        retry_after_s,
                        budget: *budget,
                    };
                }
                Err(_) => {
                    // Redis unreachable: apply fail-open/fail-closed.
                    if self.fail_open {
                        // Skip this budget (treat as allowing). If ALL
                        // budgets fail, the request is allowed with no
                        // binding constraint — NotQuotaed.
                        continue;
                    } else {
                        // Fail-closed: deny.
                        return QuotaOutcome::Denied {
                            limit,
                            remaining: 0,
                            reset_epoch_s: reset_epoch_s.unsigned_abs(),
                            retry_after_s: retry_after(reset_epoch_s, now_epoch_s),
                            budget: *budget,
                        };
                    }
                }
            }
        }

        match binding {
            Some((limit, remaining, reset_epoch_s)) => QuotaOutcome::Allowed {
                limit,
                remaining,
                reset_epoch_s,
            },
            None => QuotaOutcome::NotQuotaed,
        }
    }

    /// Run the atomic check-and-reserve Lua script for one budget.
    /// Returns `Ok((allowed, counter_after))` on success.
    async fn check_budget(
        &self,
        key: &str,
        limit: u64,
        increment: u64,
        ttl_s: u64,
    ) -> Result<(bool, u64), redis::RedisError> {
        let mut conn = self.conn.clone();
        let result: Vec<i64> = self
            .script
            .key(key)
            .arg(0) // window_start (unused in script, kept for docs)
            .arg(limit as i64)
            .arg(increment as i64)
            .arg(ttl_s as i64)
            .invoke_async(&mut conn)
            .await?;
        let allowed = result.first().copied().unwrap_or(0) == 1;
        let counter = result.get(1).copied().unwrap_or(0) as u64;
        Ok((allowed, counter))
    }

    /// Read-only peek at a budget's counter (no increment). Used for
    /// the max-wait peek of later budgets after a denial.
    async fn peek_budget(&self, key: &str) -> Result<u64, redis::RedisError> {
        use redis::AsyncCommands;
        let mut conn = self.conn.clone();
        let val: Option<i64> = conn.get(key).await?;
        Ok(val.unwrap_or(0) as u64)
    }
}

#[async_trait]
impl QuotaChecker for RedisQuotaChecker {
    async fn check(
        &self,
        consumer_id: i64,
        quotas: &ConsumerQuotas,
        now_epoch_s: i64,
    ) -> QuotaOutcome {
        RedisQuotaChecker::check(self, consumer_id, quotas, now_epoch_s).await
    }
}
