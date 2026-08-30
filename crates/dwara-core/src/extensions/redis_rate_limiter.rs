//! Distributed Redis-backed GCRA rate limiter (DW-031, ent feature only).
//!
//! The same GCRA (Generic Cell Rate Algorithm) as the local
//! [`GcraRateLimiter`](super::rate_limiter::GcraRateLimiter), but the
//! per-key bucket state (the theoretical arrival time, TAT) lives in
//! Redis and is read, updated, and decided in a SINGLE atomic Lua
//! script call — one Redis round-trip per window per request. Two or
//! more gateway instances sharing one Redis therefore share one rate
//! limit: a token spent on instance A is seen as spent by instance B.
//!
//! # Why GCRA in Redis (not a token bucket)
//!
//! GCRA needs exactly ONE piece of state per key (the TAT, a single
//! integer), so the Lua script is a read-modify-write of one hash
//! field — minimal Redis overhead, no race window, no background
//! refill tick. A token bucket would need two fields (tokens +
//! last-refill timestamp) and a more complex script; GCRA's single
//! integer is the cheapest correct atomic rate limit in Redis.
//!
//! # The Lua script
//!
//! The script (`GCRA_LUA`) takes the rate-limit key and four
//! arguments (emission interval, burst tolerance, cost, current time
//! in Unix nanoseconds) and returns `{allowed, remaining,
//! retry_after_ms}`. It atomically:
//!
//! 1. Reads the TAT from the key's hash (defaulting to `now` if
//!    absent — a fresh bucket).
//! 2. Computes `new_tat = max(tat, now) + interval * cost` (the
//!    arrival time after this request's tokens).
//! 3. Computes `allow_at = new_tat - burst` (the earliest time a
//!    request would have been denied).
//! 4. If `allow_at <= now`: ALLOW — write the new TAT, set EXPIRE,
//!    return `{1, remaining, 0}`.
//! 5. Else: DENY — return `{0, 0, retry_after_ms}` (the TAT is left
//!    untouched; a denied request does not consume a token).
//!
//! # Fail-open / fail-closed
//!
//! If Redis is unreachable, [`RedisRateLimiter::check`] applies the
//! configured `fail_open` policy:
//!
//! - `fail_open: true` (default): the window is SKIPPED (treated as
//!   allowing). If ALL windows fail, the request is allowed with the
//!   full burst capacity reported as remaining — Redis down means no
//!   rate limiting, which is the safer default for availability.
//! - `fail_open: false`: the window DENIES. The request gets a 429
//!   from the first window that cannot reach Redis.
//!
//! # Key format
//!
//! Each stacked window gets its own Redis key:
//! `{prefix}{key}:{window_index}` (e.g. `dwara:rl:10.0.0.1|route-a:0`).
//! Windows are independent GCRA cells, exactly as in the local limiter.
//!
//! # Connection pooling
//!
//! Uses `redis::aio::ConnectionManager` — a multiplexed connection
//! that clones cheaply (Arc-based) and reconnects automatically on
//! failure. The connection is established ONCE at startup (in
//! dwara-bin) and cloned per-rule at engine compile time.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::Script;

use super::rate_limiter::{denied_outcome, GcraOutcome, GcraWindowSpec, RateDecision, RateLimiter};
use super::ExtensionsError;

/// The atomic GCRA Lua script (see the module docs for the algorithm).
///
/// KEYS[1] = the rate limit key
/// ARGV[1] = emission_interval (nanoseconds between tokens)
/// ARGV[2] = burst_tolerance (nanoseconds of burst allowed)
/// ARGV[3] = cost (units to reserve)
/// ARGV[4] = current_time (Unix nanoseconds)
/// ARGV[5] = key_ttl_s (minimum TTL for the key)
/// Returns: {allowed (1/0), remaining, retry_after_ms}
const GCRA_LUA: &str = r#"
local state = redis.call('HMGET', KEYS[1], 'tat')
local tat = tonumber(state[1])
if tat == nil then tat = tonumber(ARGV[4]) end
local interval = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])
local now = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])
local new_tat = math.max(tat, now) + interval * cost
local allow_at = new_tat - burst
if allow_at <= now then
    redis.call('HMSET', KEYS[1], 'tat', new_tat)
    redis.call('EXPIRE', KEYS[1], math.max(math.ceil(burst / 1e9) + 1, ttl))
    return {1, math.floor((burst - (new_tat - now)) / interval), 0}
else
    return {0, 0, math.ceil((allow_at - now) / 1e6)}
end
"#;

/// One stacked GCRA window backed by Redis (DW-031).
struct RedisWindow {
    /// Nanoseconds between token emissions (= window_ns / requests).
    emission_interval_ns: u64,
    /// Nanoseconds of burst tolerance (= emission_interval * burst).
    burst_tolerance_ns: u64,
    /// Bucket size (governor's max_burst) — `X-RateLimit-Limit` when
    /// this window is the binding constraint.
    burst: u32,
    /// Full-bucket refill time in milliseconds — the basis of
    /// `X-RateLimit-Reset`.
    full_refill_ms: u64,
}

/// Distributed Redis-backed GCRA rate limiter (DW-031, ent feature).
///
/// Implements the [`RateLimiter`] trait with the same GCRA algorithm
/// as [`GcraRateLimiter`](super::rate_limiter::GcraRateLimiter), but
/// the per-key TAT lives in Redis and is updated atomically via a Lua
/// script. See the module docs for the algorithm, key format, and
/// fail-open/fail-closed semantics.
pub struct RedisRateLimiter {
    /// Multiplexed Redis connection (cloned cheaply per rule; Arc-based).
    conn: ConnectionManager,
    /// Stacked windows, shortest-first (same ordering as the local
    /// limiter; see the rate_limiter module docs for the
    /// stop-at-first-denial consumption semantics).
    windows: Vec<RedisWindow>,
    /// Fail-open (true) or fail-closed (false) when Redis is unreachable.
    fail_open: bool,
    /// Prefix for Redis keys (e.g. `dwara:rl:`).
    key_prefix: String,
    /// Minimum TTL for Redis keys (seconds).
    key_ttl_s: u64,
    /// The compiled GCRA Lua script (EVALSHA-cached by the redis crate).
    script: Script,
}

impl std::fmt::Debug for RedisRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisRateLimiter")
            .field("windows", &self.windows.len())
            .field("fail_open", &self.fail_open)
            .field("key_prefix", &self.key_prefix)
            .finish()
    }
}

impl RedisRateLimiter {
    /// New limiter over the given window specs, sharing the provided
    /// connection. Returns `None` for an empty spec list (a limiter
    /// with no windows cannot make decisions). The connection is
    /// cloned (cheap, Arc-based) — the caller's handle stays valid.
    pub fn new(
        conn: ConnectionManager,
        specs: Vec<GcraWindowSpec>,
        fail_open: bool,
        key_prefix: String,
        key_ttl_s: u64,
    ) -> Option<Self> {
        if specs.is_empty() {
            return None;
        }
        let windows = build_windows(specs);
        Some(Self {
            conn,
            windows,
            fail_open,
            key_prefix,
            key_ttl_s,
            script: Script::new(GCRA_LUA),
        })
    }

    /// New limiter from a [`crate::config::RedisRateLimiterConfig`] (the config block
    /// on `Gateway`). Convenience wrapper around [`Self::new`] that
    /// extracts the config fields.
    pub fn from_config(
        conn: ConnectionManager,
        specs: Vec<GcraWindowSpec>,
        config: &crate::config::RedisRateLimiterConfig,
    ) -> Option<Self> {
        Self::new(
            conn,
            specs,
            config.fail_open,
            config.key_prefix.clone(),
            config.key_ttl_s,
        )
    }

    /// Check-and-reserve `cost` units for `key` across all stacked
    /// windows (see the rate_limiter module docs for the
    /// stop-at-first-denial consumption semantics). `cost` 0 is
    /// treated as 1 (a request always costs at least one unit).
    ///
    /// Returns a [`GcraOutcome`] (the same rich type the local
    /// [`GcraRateLimiter`](super::rate_limiter::GcraRateLimiter)
    /// returns) so the [`RateLimitEngine`](super::rate_limiter::RateLimitEngine)
    /// can use either limiter uniformly.
    pub async fn check(&self, key: &str, cost: u32) -> GcraOutcome {
        let cost = cost.max(1);
        let now_ns = unix_nanos();

        let mut binding: Option<GcraOutcome> = None;
        for (i, window) in self.windows.iter().enumerate() {
            let redis_key = format!("{}{}:{}", self.key_prefix, key, i);
            match self.check_window(&redis_key, window, cost, now_ns).await {
                Ok((true, remaining, _)) => {
                    let candidate = GcraOutcome {
                        decision: RateDecision {
                            allowed: true,
                            remaining,
                            retry_after_ms: None,
                        },
                        limit: window.burst,
                        refill_ms: window.full_refill_ms,
                    };
                    if binding
                        .as_ref()
                        .is_none_or(|b| candidate.decision.remaining < b.decision.remaining)
                    {
                        binding = Some(candidate);
                    }
                }
                Ok((false, _, retry_after_ms)) => {
                    return denied_outcome(window.burst, retry_after_ms);
                }
                Err(err) => {
                    tracing::warn!(
                        code = "redis_rate_limiter_backend_error",
                        key = %redis_key,
                        "Redis rate limiter backend error: {err}; \
                         fail_open={}",
                        self.fail_open,
                    );
                    if self.fail_open {
                        // Skip this window — treat as allowing. If all
                        // windows fail, binding stays None and the
                        // fallback below returns a permissive outcome.
                        continue;
                    } else {
                        // Fail-closed: deny from this window.
                        return denied_outcome(window.burst, window.full_refill_ms);
                    }
                }
            }
        }
        // All windows either allowed or (fail-open) skipped. If
        // binding is None (every window failed with fail-open),
        // return a permissive outcome with the first window's
        // capacity — Redis down means no rate limiting.
        binding.unwrap_or_else(|| {
            let w = self
                .windows
                .first()
                .expect("non-empty window list (checked in new)");
            GcraOutcome {
                decision: RateDecision {
                    allowed: true,
                    remaining: u64::from(w.burst),
                    retry_after_ms: None,
                },
                limit: w.burst,
                refill_ms: w.full_refill_ms,
            }
        })
    }

    /// Run the GCRA Lua script for one window. Returns
    /// `(allowed, remaining, retry_after_ms)` on success, or an
    /// `ExtensionsError::Backend` on Redis failure.
    async fn check_window(
        &self,
        redis_key: &str,
        window: &RedisWindow,
        cost: u32,
        now_ns: u64,
    ) -> Result<(bool, u64, u64), ExtensionsError> {
        let mut conn = self.conn.clone();
        let result: Vec<i64> = self
            .script
            .key(redis_key)
            .arg(window.emission_interval_ns)
            .arg(window.burst_tolerance_ns)
            .arg(u64::from(cost))
            .arg(now_ns)
            .arg(self.key_ttl_s)
            .invoke_async(&mut conn)
            .await
            .map_err(|e| ExtensionsError::Backend(format!("redis gcra script error: {e}")))?;
        // The Lua script returns {allowed (1/0), remaining, retry_after_ms}.
        let allowed = result.first().copied().unwrap_or(0) == 1;
        let remaining = u64::try_from(result.get(1).copied().unwrap_or(0)).unwrap_or(0);
        let retry_after_ms = u64::try_from(result.get(2).copied().unwrap_or(0)).unwrap_or(0);
        Ok((allowed, remaining, retry_after_ms))
    }
}

#[async_trait]
impl RateLimiter for RedisRateLimiter {
    async fn check(&self, key: &str, cost: u32) -> Result<RateDecision, ExtensionsError> {
        Ok(self.check(key, cost).await.decision)
    }
}

/// Build the Redis window specs from the same [`GcraWindowSpec`] the
/// local limiter uses, sorted shortest-first. Each window becomes one
/// Redis key per rate-limit key.
fn build_windows(specs: Vec<GcraWindowSpec>) -> Vec<RedisWindow> {
    let mut specs = specs;
    specs.sort_by_key(|s| s.window);
    specs
        .into_iter()
        .map(|spec| {
            let burst = spec.burst.unwrap_or(spec.requests);
            let requests = u64::from(spec.requests.get());
            let window_ns = spec.window.as_nanos() as u64;
            // Emission interval = window / requests (nanoseconds
            // between tokens). Sub-nanosecond intervals clamp to 1ns
            // (the local limiter does the same via governor).
            let emission_interval_ns = (window_ns / requests).max(1);
            let burst_tolerance_ns = emission_interval_ns * u64::from(burst.get());
            let full_refill_ms = burst_tolerance_ns / 1_000_000;
            RedisWindow {
                emission_interval_ns,
                burst_tolerance_ns,
                burst: burst.get(),
                full_refill_ms,
            }
        })
        .collect()
}

/// Current time as Unix nanoseconds (the clock the Lua script uses).
fn unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Establish a Redis connection with a timeout. Used at startup (in
/// dwara-bin) to create the shared [`ConnectionManager`] that is
/// cloned per-rule at engine compile time.
pub async fn connect(url: &str, timeout: Duration) -> Result<ConnectionManager, ExtensionsError> {
    let client = redis::Client::open(url)
        .map_err(|e| ExtensionsError::Backend(format!("redis client open error: {e}")))?;
    tokio::time::timeout(timeout, ConnectionManager::new(client))
        .await
        .map_err(|_| {
            ExtensionsError::Backend(format!(
                "redis connection timeout after {}ms",
                timeout.as_millis()
            ))
        })?
        .map_err(|e| ExtensionsError::Backend(format!("redis connection error: {e}")))
}

// White-box unit tests of the GCRA math (the same algorithm as the
// local limiter, just distributed). These stay in src/ because they
// test the private `build_windows` function's math, which cannot be
// exercised through the public API without a real Redis.
#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU32;

    fn window(requests: u32, window_secs: u64, burst: Option<u32>) -> GcraWindowSpec {
        GcraWindowSpec {
            requests: NonZeroU32::new(requests).unwrap(),
            window: Duration::from_secs(window_secs),
            burst: burst.map(|b| NonZeroU32::new(b).unwrap()),
        }
    }

    #[test]
    fn build_windows_sorts_shortest_first() {
        let ws = build_windows(vec![
            window(100, 3600, None), // 1h window
            window(10, 1, Some(20)), // 1s window
            window(100, 60, None),   // 1m window
        ]);
        assert_eq!(ws.len(), 3);
        // Shortest window first.
        assert_eq!(ws[0].burst, 20);
        assert_eq!(ws[1].burst, 100);
        assert_eq!(ws[2].burst, 100);
    }

    #[test]
    fn build_windows_computes_emission_interval() {
        // 10 requests per 1 second = 1 token per 100ms = 100_000_000 ns.
        let ws = build_windows(vec![window(10, 1, None)]);
        assert_eq!(ws[0].emission_interval_ns, 100_000_000);
        // burst defaults to requests (10), so burst_tolerance = 10 * 100ms = 1s.
        assert_eq!(ws[0].burst_tolerance_ns, 1_000_000_000);
        assert_eq!(ws[0].full_refill_ms, 1000);
    }

    #[test]
    fn build_windows_burst_overrides_default() {
        // 10 r/s with burst 20: emission = 100ms, burst_tolerance = 2s.
        let ws = build_windows(vec![window(10, 1, Some(20))]);
        assert_eq!(ws[0].emission_interval_ns, 100_000_000);
        assert_eq!(ws[0].burst_tolerance_ns, 2_000_000_000);
        assert_eq!(ws[0].burst, 20);
        assert_eq!(ws[0].full_refill_ms, 2000);
    }

    #[test]
    fn build_windows_clamps_sub_nanos_interval() {
        // 1 billion requests per 1 second = sub-nanosecond interval.
        let ws = build_windows(vec![window(1_000_000_000, 1, None)]);
        assert_eq!(ws[0].emission_interval_ns, 1); // clamped to 1ns
    }
}
