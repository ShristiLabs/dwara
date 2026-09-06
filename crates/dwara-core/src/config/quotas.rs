//! Pure quota types shared by the state-store and Redis-backed quota
//! implementations (DW-033, DW-155).
//!
//! This module lives in `config` (the lowest consuming domain) so both
//! `state::quotas` (the OSS local-counter implementation) and
//! `extensions::redis_quotas` (the Ent Redis-backed implementation) can
//! import it without violating the downward-only dependency direction.
//! The types here are pure: no I/O, no state store, no Redis. The
//! stateful logic lives in the consuming domains.

/// Counter-key of the daily budget (`quota_counters.counter_key`).
pub const DAILY_KEY: &str = "daily";
/// Counter-key of the monthly budget (`quota_counters.counter_key`).
pub const MONTHLY_KEY: &str = "monthly";

/// Seconds per day (the daily window's whole length).
const SECS_PER_DAY: i64 = 86_400;

/// One of the two budget kinds (DW-033). The set is closed: budgets are
/// calendar windows, not arbitrary durations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Budget {
    Daily,
    Monthly,
}

impl Budget {
    /// Counter-key spelling (the `quota_counters.counter_key` value).
    pub fn key(self) -> &'static str {
        match self {
            Budget::Daily => DAILY_KEY,
            Budget::Monthly => MONTHLY_KEY,
        }
    }

    /// Label spelling (metric label values, event payloads, admin API).
    pub fn as_str(self) -> &'static str {
        self.key()
    }

    /// This budget's configured limit, when the config sets one.
    pub fn limit(self, quotas: &crate::config::ConsumerQuotas) -> Option<u64> {
        match self {
            Budget::Daily => quotas.daily_requests,
            Budget::Monthly => quotas.monthly_requests,
        }
    }

    /// The window (start, reset) this budget's counter keys on at
    /// `now_epoch_s`.
    pub fn window(self, now_epoch_s: i64) -> (i64, i64) {
        match self {
            Budget::Daily => day_window(now_epoch_s),
            Budget::Monthly => month_window(now_epoch_s),
        }
    }

    /// Both budgets, shortest window first (the evaluation order; see
    /// the module docs).
    pub const ALL: &'static [Budget] = &[Budget::Daily, Budget::Monthly];
}

/// The UTC day window containing `now_epoch_s`:
/// (window_start_epoch_s, next_reset_epoch_s). Pure; floor semantics
/// for any input (negative epochs round toward the past, matching
/// euclidean division).
pub fn day_window(now_epoch_s: i64) -> (i64, i64) {
    let days = now_epoch_s.div_euclid(SECS_PER_DAY);
    let start = days * SECS_PER_DAY;
    (start, start + SECS_PER_DAY)
}

/// The UTC month window containing `now_epoch_s`:
/// (window_start_epoch_s, next_reset_epoch_s). Calendar-correct across
/// month lengths and leap years (the standard civil-from-days
/// algorithm; no calendar dependency). Pure.
pub fn month_window(now_epoch_s: i64) -> (i64, i64) {
    let days = now_epoch_s.div_euclid(SECS_PER_DAY);
    let (y, m, _) = civil_from_days(days);
    let start_days = days_from_civil(y, m, 1);
    let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
    let reset_days = days_from_civil(ny, nm, 1);
    (start_days * SECS_PER_DAY, reset_days * SECS_PER_DAY)
}

/// Civil date (year, month 1..=12, day 1..=31) from days since the
/// Unix epoch (Howard Hinnant's `civil_from_days`; valid for the whole
/// proleptic Gregorian calendar the epoch-seconds domain can express).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Days since the Unix epoch from a civil date (the exact inverse of
/// [`civil_from_days`]).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400); // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64; // [0, 11]
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// What the quota check decided for one request (DW-033). Shape mirrors
/// the rate limiter's outcome type (extensions::rate_limiter, named
/// textually — a doc link would be an upward import) so the request
/// path answers both with the same 429 builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaOutcome {
    /// No budget applied (no quota config, anonymous traffic, or no
    /// state store attached): the request is not quota-gated and
    /// carries no quota headers.
    NotQuotaed,
    /// Admitted (the unit is already spent — `check` reserves like the
    /// rate limiter does). `limit`/`remaining`/`reset_epoch_s` describe
    /// the binding constraint (the budget with the least remaining).
    /// Quotas stamp headers on DENIALS only: an admitted response's
    /// `X-RateLimit-*` family belongs to the rate limiter when it
    /// applies (documented choice — two mechanisms would race to write
    /// the same header names on every success).
    Allowed {
        limit: u64,
        remaining: u64,
        reset_epoch_s: u64,
    },
    /// Over budget: answer 429 with `Retry-After` = `retry_after_s`
    /// (ceil to the window boundary, min 1) and the binding budget's
    /// Limit/Remaining/Reset headers. `budget` names which wall was hit
    /// (the metric label); when both budgets deny, the headers come
    /// from the first (daily) and `retry_after_s` is the MAXIMUM wait.
    Denied {
        limit: u64,
        remaining: u64,
        reset_epoch_s: u64,
        retry_after_s: u32,
        budget: Budget,
    },
    /// The store failed mid-check: the gateway cannot vouch for the
    /// budget either way. The request path answers 500 (the authN
    /// "unavailable" posture), never a guess.
    Unavailable,
}

/// `Retry-After` seconds: whole seconds until `reset_epoch_s`, rounded
/// up, minimum 1 (a denied request inside the last partial second must
/// still advertise a wait, never 0).
pub fn retry_after(reset_epoch_s: i64, now_epoch_s: i64) -> u32 {
    u32::try_from((reset_epoch_s - now_epoch_s).max(1)).unwrap_or(1)
}
