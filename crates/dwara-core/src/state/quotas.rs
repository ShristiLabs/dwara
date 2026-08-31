//! Consumer request budgets (DW-033): daily/monthly quotas and metering.
//!
//! # What a quota is (and is not)
//!
//! A quota is a BUDGET, not a rate: [`crate::config::ConsumerQuotas`]
//! caps the total number of requests one consumer may make inside a
//! fixed UTC calendar window — a day (midnight to midnight UTC) or a
//! month (the first through the last instant of the UTC month). The
//! rate limiter (DW-017) shapes traffic inside seconds or minutes via
//! GCRA replenishment; a quota never replenishes inside its window,
//! just resets whole at the boundary. The two mechanisms are SEPARATE
//! by design and compose: both apply when both are configured, and
//! quota 429s carry the same header family as rate-limit 429s
//! (`Retry-After` + `X-RateLimit-Limit` / `-Remaining` / `-Reset`)
//! because the client-facing contract is identical — "you may retry at
//! this time".
//!
//! # Counters and durability
//!
//! Usage counters are the state store's `quota_counters` rows (DW-018
//! seeded the table and [`StateStore::incr_quota`]'s atomic
//! increment-or-refuse — this module is the policy layer that was
//! missing). Counters therefore persist restarts and crashes like the
//! rest of the store: every accepted request's increment is a
//! synchronous point write committed before the request proceeds, not
//! a fire-and-forget record, so a crash can lose at most the request
//! that was in flight — never a committed counter. This is the OSS
//! local-counter implementation the issue scopes: per-instance SQLite
//! (or in-memory) truth. A fleet-wide shared-counter variant (Redis)
//! is the Ent follow-up (DW-155) and deliberately does not exist here.
//!
//! # Hot-path cost (documented trade)
//!
//! Every request of a quota-configured consumer performs one or two
//! SYNCHRONOUS SQLite write transactions (`incr_quota`) on the single
//! mutex-guarded state-store connection — and that store keeps
//! SQLite's default `synchronous=FULL` (an fsync per commit; the
//! analytics store pins `NORMAL` for contrast, but relaxing the state
//! store's durability is a separate decision touching credential-write
//! semantics, not this feature's call). Budgets therefore add a
//! per-request fsync and serialize quota'd traffic through one
//! connection — the accepted OSS per-instance shape; scaling quota
//! enforcement across a fleet is exactly the DW-155 follow-up.
//!
//! # Window math
//!
//! Windows are UTC calendar aligned and computed purely from an
//! epoch-seconds input ([`day_window`], [`month_window`]) so tests are
//! deterministic. The day window is `days * 86400`; the month window
//! uses the standard civil-calendar days algorithm (no calendar
//! dependency). `reset_epoch_s` is the boundary at which the budget
//! becomes whole again — the value advertised in `X-RateLimit-Reset`.
//!
//! # Evaluation semantics (mirrors DW-017 where the client sees it)
//!
//! Budgets evaluate shortest-window-first (daily, then monthly). All
//! configured budgets apply (AND). A denied request answers 429 with
//! `Retry-After` = seconds until the denying budget's window resets
//! (rounded up, minimum 1) and the FIRST denying budget's
//! Limit/Remaining/Reset headers; when a LATER budget is ALSO
//! exhausted, `Retry-After` stretches to that later wall (the monthly
//! boundary is a midnight at or after the daily one) — a client
//! honoring the hint never retries out of the daily wall straight into
//! the monthly one, the same max-wait rule the multi-rule rate limiter
//! applies. Evaluation is decide-and-reserve and STOPS at the first
//! denial (the GCRA stacking rule): a request denied by the monthly
//! budget has already spent its daily unit (the daily window evaluated
//! first), while a request denied by the daily budget consumes
//! NOTHING — later budgets are peeked read-only for the max-wait
//! computation, never incremented for a refused request. The stacking
//! waste is one unit in the faster-resetting window; never more
//! permissive, bounded, documented.
//!
//! # Failure model
//!
//! The store's failure answers are surfaced, not hidden:
//! [`QuotaOutcome::Unavailable`] (a SQLite error) maps to a 500 on the
//! request path — the gateway cannot vouch for the budget either way,
//! the same posture as an authN backend failure. A consumer present in
//! config but absent from the store (sync never ran) fails OPEN with a
//! logged warn: there is no counter to enforce, and 500-ing every
//! request of an unsynced consumer would turn a wiring gap into an
//! outage. Quota config without ANY attached state store is likewise
//! inert (warned once at request time from the dataplane — validation
//! cannot see `DWARA_STATE_DB`, which is runtime environment, not
//! config).
//!
//! # Metering
//!
//! Usage is queryable three ways: the admin API's `GET /quotas/usage`
//! (current windows, per consumer), the `dwara_quota_used` /
//! `dwara_quota_limit` / `dwara_quota_denied_total` metric families
//! (DW-021 conventions), and the analytics store — a quota-denied
//! request completes with `rate_limited = true` and its consumer name,
//! so the existing per-consumer analytics axis (raw rows and the
//! `rollup_fixed` consumer dimension) already answers "how much did
//! this consumer send and how much was refused" over history.

use super::store::{StateStore, StoreError};
use crate::config::ConsumerQuotas;

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
    pub fn limit(self, quotas: &ConsumerQuotas) -> Option<u64> {
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

/// Check-and-reserve one request against every configured budget of
/// `quotas` for consumer row `consumer_id` (DW-033). Pure policy over
/// [`StateStore::incr_quota`]; see the module docs for the evaluation
/// order, the stacking consumption trade, and the failure model.
///
/// Evaluation STOPS at the first denying budget (the GCRA stacking
/// rule: a refused request never consumes a longer window's budget),
/// but every REMAINING budget is then PEEKED (read-only) for a
/// would-deny — when a later budget is also exhausted, the reported
/// `Retry-After` stretches to the LATER reset so a client honoring the
/// hint never retries out of the daily wall straight into the monthly
/// one (the DW-017 max-wait rule, implemented without reservation).
///
/// `now_epoch_s` is the request time (injected so tests are
/// deterministic; the caller passes wall-clock seconds).
pub fn check(
    store: &StateStore,
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
        match store.incr_quota(consumer_id, budget.key(), window_start, 1, Some(limit)) {
            Ok(used_after) => {
                let remaining = limit.saturating_sub(used_after);
                let reset = reset_epoch_s.unsigned_abs();
                // The tightest budget (least remaining) is the binding
                // constraint on success — the rate limiter's rule.
                if binding
                    .as_ref()
                    .is_none_or(|(_, best, _)| remaining < *best)
                {
                    binding = Some((limit, remaining, reset));
                }
            }
            // Nothing was written: the budget is exhausted. remaining
            // is the honest post-check figure the headers advertise.
            Err(StoreError::QuotaExceeded { used, .. }) => {
                let mut retry_after_s = retry_after(reset_epoch_s, now_epoch_s);
                let mut denied_reset = reset_epoch_s.unsigned_abs();
                // Peek every later budget read-only: an exhausted one's
                // reset is strictly later (a month boundary is a
                // midnight at or after the day boundary), so any
                // would-deny stretches the wait.
                for later in Budget::ALL {
                    if *later == *budget {
                        continue;
                    }
                    let Some(later_limit) = later.limit(quotas) else {
                        continue;
                    };
                    let (later_start, later_reset) = later.window(now_epoch_s);
                    if let Ok(used) = store.get_quota(consumer_id, later.key(), later_start) {
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
                    remaining: limit.saturating_sub(used),
                    reset_epoch_s: denied_reset,
                    retry_after_s,
                    budget: *budget,
                };
            }
            // Unknown consumer row: fail open (module docs). Surface as
            // not-quotaed — the caller logged the gap at most once.
            Err(StoreError::UnknownConsumer(_)) => return QuotaOutcome::NotQuotaed,
            // Any other store failure: the budget cannot be vouched for.
            Err(StoreError::Sqlite(_)) => return QuotaOutcome::Unavailable,
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

/// `Retry-After` seconds: whole seconds until `reset_epoch_s`, rounded
/// up, minimum 1 (a denied request inside the last partial second must
/// still advertise a wait, never 0).
fn retry_after(reset_epoch_s: i64, now_epoch_s: i64) -> u32 {
    u32::try_from((reset_epoch_s - now_epoch_s).max(1)).unwrap_or(1)
}

/// One budget's current-window usage figure (the admin API and metric
/// gauges' read model).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetUsage {
    pub budget: Budget,
    /// Configured cap.
    pub limit: u64,
    /// Requests counted in the current window.
    pub used: u64,
    /// `limit - used` (saturating; always in range while counters and
    /// config agree).
    pub remaining: u64,
    /// Window start (epoch seconds) — the counter row's key.
    pub window_start_epoch_s: u64,
    /// When the budget becomes whole again (epoch seconds).
    pub reset_epoch_s: u64,
}

/// Read the current-window usage of every configured budget for one
/// consumer (no reservation, no increment — the query side of
/// metering). A store that cannot answer yields an empty read; callers
/// surface the gap their own way (the admin endpoint 500s, the gauge
/// refresh skips).
pub fn current_usage(
    store: &StateStore,
    consumer_id: i64,
    quotas: &ConsumerQuotas,
    now_epoch_s: i64,
) -> Vec<BudgetUsage> {
    let mut out = Vec::new();
    for budget in Budget::ALL {
        let Some(limit) = budget.limit(quotas) else {
            continue;
        };
        let (window_start, reset_epoch_s) = budget.window(now_epoch_s);
        match store.get_quota(consumer_id, budget.key(), window_start) {
            Ok(used) => out.push(BudgetUsage {
                budget: *budget,
                limit,
                used,
                remaining: limit.saturating_sub(used),
                window_start_epoch_s: window_start.unsigned_abs(),
                reset_epoch_s: reset_epoch_s.unsigned_abs(),
            }),
            Err(_) => return Vec::new(),
        }
    }
    out
}

// White-box tests staying in src/ per AGENTS.md: the calendar-arithmetic
// helpers (`days_from_civil`, `civil_from_days`, `SECS_PER_DAY`,
// `retry_after`) are private and cannot be exercised through the public
// API. The end-to-end `check`/`current_usage` tests use these private
// helpers to construct exact epoch values for deterministic assertions.
#[cfg(test)]
mod tests {
    use super::*;

    /// The civil-calendar pair over a spread of epochs (leap years,
    /// century non-leap 2100, month/year boundaries both directions).
    #[test]
    fn day_and_month_windows_are_calendar_aligned() {
        // Epoch day 0 = 1970-01-01 (Thursday).
        assert_eq!(day_window(0), (0, 86_400));
        // Mid-day stays in the same window; the boundary rolls exactly.
        assert_eq!(day_window(86_399), (0, 86_400));
        assert_eq!(day_window(86_400), (86_400, 172_800));
        // 2026-08-29T00:00:00Z = 1787961600 (a verified UTC midnight).
        assert_eq!(
            day_window(1_787_961_600),
            (1_787_961_600, 1_787_961_600 + 86_400)
        );
        assert_eq!(
            day_window(1_787_961_600 + 86_399),
            (1_787_961_600, 1_787_961_600 + 86_400)
        );
    }

    #[test]
    fn month_windows_cross_month_year_and_leap_boundaries() {
        // 1970-01-01: the first month window.
        assert_eq!(month_window(0), (0, 2_678_400)); // 31 days
                                                     // 1970-01-31 23:59:59 still January; one second later is
                                                     // February (28 days in 1970).
        assert_eq!(month_window(2_678_399), (0, 2_678_400));
        assert_eq!(month_window(2_678_400), (2_678_400, 2_678_400 + 2_419_200));
        // Leap year 1972: February has 29 days (25 days = 2_160_000 s
        // into the epoch-year; compute from civil instead of magic).
        let feb72 = days_from_civil(1972, 2, 1) * SECS_PER_DAY;
        let mar72 = days_from_civil(1972, 3, 1) * SECS_PER_DAY;
        assert_eq!(month_window(feb72), (feb72, mar72));
        assert_eq!(mar72 - feb72, 29 * SECS_PER_DAY);
        // Century non-leap 2100: February has 28 days there.
        let feb2100 = days_from_civil(2100, 2, 1) * SECS_PER_DAY;
        let mar2100 = days_from_civil(2100, 3, 1) * SECS_PER_DAY;
        assert_eq!(month_window(feb2100), (feb2100, mar2100));
        assert_eq!(mar2100 - feb2100, 28 * SECS_PER_DAY);
        // December rolls into the next YEAR.
        let dec2026 = days_from_civil(2026, 12, 1) * SECS_PER_DAY;
        let jan2027 = days_from_civil(2027, 1, 1) * SECS_PER_DAY;
        assert_eq!(month_window(dec2026), (dec2026, jan2027));
        // Civil round trip: every day of 2026 maps back to itself.
        for d in days_from_civil(2026, 1, 1)..days_from_civil(2027, 1, 1) {
            let (y, m, day) = civil_from_days(d);
            assert_eq!(days_from_civil(y, m, day), d);
        }
    }

    fn quotas(daily: Option<u64>, monthly: Option<u64>) -> ConsumerQuotas {
        ConsumerQuotas {
            daily_requests: daily,
            monthly_requests: monthly,
        }
    }

    #[test]
    fn check_admits_under_budget_and_denies_at_it_with_reset() {
        let store = StateStore::open_in_memory().unwrap();
        let cid = store.upsert_consumer("acme", None, &[]).unwrap().id;
        let now = 1_787_961_600_i64 + 40_000; // mid-day 2026-08-29 UTC
        let q = quotas(Some(2), None);
        assert_eq!(
            check(&store, cid, &q, now),
            QuotaOutcome::Allowed {
                limit: 2,
                remaining: 1,
                reset_epoch_s: 1_787_961_600_u64 + 86_400,
            }
        );
        // Second request: budget now exhausted for the next one.
        check(&store, cid, &q, now);
        let (start, reset) = day_window(now);
        assert_eq!(
            check(&store, cid, &q, now),
            QuotaOutcome::Denied {
                limit: 2,
                remaining: 0,
                reset_epoch_s: reset.unsigned_abs(),
                retry_after_s: (reset - now) as u32,
                budget: Budget::Daily,
            }
        );
        // Next day, same second-of-day: a fresh window admits again.
        assert_eq!(day_window(now + SECS_PER_DAY).0, start + SECS_PER_DAY);
        assert!(matches!(
            check(&store, cid, &q, now + SECS_PER_DAY),
            QuotaOutcome::Allowed { .. }
        ));
        // Denials do not consume: the exhausted-budget request above
        // left `used` at 2 (the next-day window is a different row).
        assert_eq!(store.get_quota(cid, DAILY_KEY, start).unwrap(), 2);
    }

    #[test]
    fn monthly_denial_reports_month_scale_retry_and_daily_was_consumed() {
        let store = StateStore::open_in_memory().unwrap();
        let cid = store.upsert_consumer("acme", None, &[]).unwrap().id;
        let now = days_from_civil(2026, 8, 29) * SECS_PER_DAY + 3600;
        // A daily budget the request fits, a monthly budget it does not
        // (already at its limit from a request earlier this month).
        let q = quotas(Some(10), Some(1));
        store
            .incr_quota(cid, MONTHLY_KEY, month_window(now).0, 1, Some(1))
            .unwrap();
        let outcome = check(&store, cid, &q, now);
        let (_, month_reset) = month_window(now);
        assert_eq!(
            outcome,
            QuotaOutcome::Denied {
                limit: 1,
                remaining: 0,
                reset_epoch_s: month_reset.unsigned_abs(),
                retry_after_s: (month_reset - now) as u32,
                budget: Budget::Monthly,
            }
        );
        // The documented stacking trade: the daily unit was spent by
        // the request the monthly budget refused.
        let (day_start, _) = day_window(now);
        assert_eq!(store.get_quota(cid, DAILY_KEY, day_start).unwrap(), 1);
    }

    #[test]
    fn both_budgets_exhausted_reports_the_later_wall() {
        let store = StateStore::open_in_memory().unwrap();
        let cid = store.upsert_consumer("acme", None, &[]).unwrap().id;
        let now = days_from_civil(2026, 8, 29) * SECS_PER_DAY + 3600;
        let (day_start, day_reset) = day_window(now);
        let (month_start, month_reset) = month_window(now);
        assert!(month_reset > day_reset);
        // Both budgets already at their limits from earlier traffic
        // (daily cap 1 spent; monthly cap 1 spent).
        store
            .incr_quota(cid, DAILY_KEY, day_start, 1, Some(1))
            .unwrap();
        store
            .incr_quota(cid, MONTHLY_KEY, month_start, 1, Some(1))
            .unwrap();
        let out = check(&store, cid, &quotas(Some(1), Some(1)), now);
        match out {
            QuotaOutcome::Denied {
                limit,
                budget,
                retry_after_s,
                reset_epoch_s,
                ..
            } => {
                // Daily denies first (shortest window evaluated first)
                // and binds the Limit/Remaining headers...
                assert_eq!(budget, Budget::Daily);
                assert_eq!(limit, 1);
                // ...but the monthly budget is also exhausted, and its
                // wall is later: the max-wait peek stretches Retry-After
                // (and the matching Reset) past the daily reset, so a
                // client honoring the hint never retries out of the
                // daily wall straight into the monthly one.
                assert_eq!(retry_after_s as i64 + now, month_reset);
                assert_eq!(reset_epoch_s, month_reset.unsigned_abs());
                assert!(retry_after_s as i64 + now > day_reset);
            }
            other => panic!("expected denial, got {other:?}"),
        }
        // The refused request consumed nothing in either window.
        assert_eq!(store.get_quota(cid, DAILY_KEY, day_start).unwrap(), 1);
        assert_eq!(store.get_quota(cid, MONTHLY_KEY, month_start).unwrap(), 1);
    }

    #[test]
    fn unknown_consumer_fails_open_and_empty_config_is_not_quotaed() {
        let store = StateStore::open_in_memory().unwrap();
        // No consumer row: fail-open, never a 500 loop.
        assert_eq!(
            check(&store, 9999, &quotas(Some(5), None), 1000),
            QuotaOutcome::NotQuotaed
        );
        // Configured consumer with no budgets set at all.
        let cid = store.upsert_consumer("acme", None, &[]).unwrap().id;
        assert_eq!(
            check(&store, cid, &quotas(None, None), 1000),
            QuotaOutcome::NotQuotaed
        );
        // current_usage mirrors: empty config -> empty read.
        assert!(current_usage(&store, cid, &quotas(None, None), 1000).is_empty());
    }

    #[test]
    fn retry_after_is_ceiled_and_never_zero() {
        assert_eq!(retry_after(100, 100), 1);
        assert_eq!(retry_after(99, 100), 1);
        assert_eq!(retry_after(101, 100), 1);
        assert_eq!(retry_after(160, 100), 60);
    }

    #[test]
    fn current_usage_reads_both_budgets_current_windows_only() {
        let store = StateStore::open_in_memory().unwrap();
        let cid = store.upsert_consumer("acme", None, &[]).unwrap().id;
        let now = days_from_civil(2026, 8, 29) * SECS_PER_DAY + 7200;
        let q = quotas(Some(10), Some(100));
        // Yesterday's usage must not leak into today's figures.
        store
            .incr_quota(cid, DAILY_KEY, day_window(now - SECS_PER_DAY).0, 9, None)
            .unwrap();
        store
            .incr_quota(cid, MONTHLY_KEY, month_window(now).0, 3, None)
            .unwrap();
        store
            .incr_quota(cid, DAILY_KEY, day_window(now).0, 2, None)
            .unwrap();
        let usage = current_usage(&store, cid, &q, now);
        assert_eq!(usage.len(), 2);
        assert_eq!(
            usage[0],
            BudgetUsage {
                budget: Budget::Daily,
                limit: 10,
                used: 2,
                remaining: 8,
                window_start_epoch_s: day_window(now).0 as u64,
                reset_epoch_s: day_window(now).1 as u64,
            }
        );
        assert_eq!(usage[1].budget, Budget::Monthly);
        assert_eq!(usage[1].used, 3);
    }
}
