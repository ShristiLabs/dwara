//! Scheduled usage-report exports (DW-120).
//!
//! DW-043 made the analytics store QUERYABLE live; this module makes
//! it REPORTABLE durably: a background worker closes each UTC calendar
//! window of the configured kind (hourly/daily/monthly) and writes the
//! per-consumer usage statement — period totals of requests, errors,
//! error rate, rate-limited and shed counts, plus the quota budget
//! figures a billing pipeline consumes — as one deterministic file per
//! configured format (CSV and JSON in v1; Parquet is deferred to the
//! DW-156 backlog) into a configured directory. Distinct from the
//! query API on purpose: this is durable, scheduled OUTPUT, not an ad
//! hoc query.
//!
//! # Reconciliation with the query API (the acceptance contract)
//!
//! The statement's analytics numbers ARE the structured query
//! endpoint's numbers: [`run_export`] builds them by calling
//! [`query::structured`] itself (grouped by `consumer`, plus one
//! ungrouped totals row) over the same `rollup_fixed` tables through
//! the same aggregation helpers. Equality with `POST
//! /analytics/query` for the same period holds BY CONSTRUCTION — and
//! is pinned by a test that parses the written JSON file and compares
//! it against an independent `structured()` call. The per-statement
//! consumer cap is 10_000 (the grouped query's limit).
//!
//! # Scheduling
//!
//! The worker (spawned by the dataplane via
//! `DataPlane::spawn_export_worker` in `dataplane::proxy`) ticks
//! on the same interval-plus-shutdown-watch machinery as the rollup
//! cascade, reads the CURRENT config generation each tick (a reload
//! can add/remove exports without a restart), and exports every
//! closed window that has no successful run record yet — oldest
//! first, so a restart backfills missed windows. A window is due once
//! its close is at least
//! [`EXPORT_DELAY_MS`] in the past (writer flush + rollup grace +
//! cascade headroom); the delay keeps the statement as complete as
//! the store can make it. [`run_export`] also forces one `maintain()`
//! pass first, so even a manual trigger reads settled rollups.
//!
//! # Quota columns and window alignment
//!
//! The quota figures come from the STATE store's `quota_counters`
//! (DW-033) — a domain this module cannot import (see
//! `scripts/check_deps.py`), so callers ABOVE both domains (the
//! dataplane worker, the admin trigger endpoint) read the counters
//! and hand them in as plain [`QuotaFigures`] per consumer name. The
//! alignment rule: a budget's figures appear only when its quota
//! window FULLY CONTAINS the export window — a daily export carries
//! the same-UTC-day `daily` counter (exact period consumption) and
//! the month-to-date `monthly` counter; a monthly export carries only
//! the `monthly` counter (the daily budget's per-day rows do not sum
//! to the month by construction and are omitted, never fabricated).
//! The monthly column reads the store's LIVE month-to-date counter,
//! so a backfilled or re-exported window can carry a different
//! `quota_monthly_used` than the original run: analytics columns are
//! deterministic, quota columns are generation-time snapshots
//! ([`QuotaBudget`]'s `window_start_epoch_s`/`reset_epoch_s` bound
//! what `used` covers).
//!
//! # Retention and partial windows
//!
//! Rollup retention deletes old windows (DW-043); a window older than
//! the chosen granularity's retention may be undercounted without the
//! store being able to know. Such runs are written with
//! `partial: true` in the file header and run record — real data,
//! flagged — and the scheduler never AUTO-exports windows past the
//! horizon (only a manual trigger can, still flagged). Quiet windows
//! (no traffic) are not loss: the statement's counts are exact
//! whenever `partial` is false.
//!
//! # Output shape
//!
//! Files are named `dwara-usage-{window}-{utc-stamp}.{ext}` (stamp
//! `YYYY-MM-DDThHZ` hourly, `YYYY-MM-DD` daily, `YYYY-MM-` trimmed to
//! `YYYY-MM` monthly) and written atomically and DURABLY (temp
//! file, then fsync, rename, and a directory fsync — all inside the
//! destination directory): a re-export of the same window simply
//! overwrites — output is idempotent, the rollup recompute
//! philosophy. CSV is RFC 4180 (CRLF rows, quoted fields containing
//! commas/quotes/CR/LF, doubled quotes); absent quota cells are EMPTY
//! strings (zero means configured-and-zero-used). JSON is pretty and
//! self-describing (window bounds, generation time, partial flag,
//! totals, per-consumer rows).

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use serde::Deserialize;
use serde::Serialize;

use super::query;
use super::EmbeddedAnalytics;

/// How long after a window's close before the scheduler will export
/// it: the writer's flush tick plus the rollup grace plus cascade
/// headroom, with margin. Not a correctness knob — a manual trigger
/// bypasses it.
pub const EXPORT_DELAY_MS: i64 = 5 * 60_000;

/// The scheduler worker's tick (same cadence class as the rollup
/// cascade's 30 s; the per-tick work is one cheap SQL probe).
pub const EXPORT_TICK_MS: u64 = 30_000;

/// Backfill bound per tick: after a long downtime the oldest-first
/// catch-up drains at most this many windows per tick (one query +
/// file writes each), keeping any single tick's work bounded.
pub const MAX_CATCHUP_WINDOWS: usize = 64;

/// How long a FAILED window stays skipped before the scheduler
/// retries it: without this, a persistent failure (unwritable
/// directory, unusable store) would re-burn a full export attempt on
/// every 30 s tick, forever. Time-based, not attempt-count-based —
/// no schema change.
pub const FAILURE_RETRY_MS: i64 = 10 * 60_000;

/// Process-unique suffix for temp files (concurrent exports of the
/// same window may race; atomic rename means last-writer-wins, never
/// a torn file).
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// One budget's figures as carried in a statement (plain DTO: the
/// state-store types stay in the state domain, which this module
/// cannot import).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct QuotaBudget {
    /// Requests counted against the budget in its window.
    pub used: u64,
    /// The configured cap.
    pub limit: u64,
    /// The counter's window start (epoch seconds) — the denominator's
    /// bounds, so a billing consumer knows exactly what `used` covers.
    pub window_start_epoch_s: i64,
    /// When the budget becomes whole again (epoch seconds).
    pub reset_epoch_s: i64,
}

/// A consumer's quota figures for one export window (see the module
/// docs' alignment rule: only budgets whose window fully contains the
/// export window appear).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuotaFigures {
    pub daily: Option<QuotaBudget>,
    pub monthly: Option<QuotaBudget>,
}

/// The export window kinds (DW-120): fixed UTC calendar windows, the
/// closed set behind `analytics.exports.window`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WindowKind {
    Hourly,
    Daily,
    Monthly,
}

impl WindowKind {
    /// Parse the admin trigger's `window` field. The closed set.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "hourly" => Some(WindowKind::Hourly),
            "daily" => Some(WindowKind::Daily),
            "monthly" => Some(WindowKind::Monthly),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            WindowKind::Hourly => "hourly",
            WindowKind::Daily => "daily",
            WindowKind::Monthly => "monthly",
        }
    }

    /// The (start, end) UTC calendar window containing `ts_ms`, in
    /// the analytics time domain (epoch milliseconds).
    pub fn window_of(self, ts_ms: i64) -> (i64, i64) {
        match self {
            WindowKind::Hourly => {
                let g = 3_600_000_i64;
                let start = ts_ms.div_euclid(g) * g;
                (start, start + g)
            }
            WindowKind::Daily => {
                let g = 86_400_000_i64;
                let start = ts_ms.div_euclid(g) * g;
                (start, start + g)
            }
            WindowKind::Monthly => month_window_ms(ts_ms),
        }
    }

    /// The rollup granularity the statement queries (see module docs):
    /// 1-hour rows for hourly and daily windows (short settle lag,
    /// well inside the 1h table's retention), 1-day rows for monthly
    /// windows (a month of 1-hour windows would outrun the 1h table's
    /// default retention).
    pub fn gran(self) -> usize {
        match self {
            WindowKind::Hourly | WindowKind::Daily => 2,
            WindowKind::Monthly => 3,
        }
    }

    /// One deterministic filename (no extension) for a window: the
    /// UTC stamp `YYYY-MM-DDThHZ` (hourly), `YYYY-MM-DD` (daily), or
    /// `YYYY-MM` (monthly).
    fn file_stem(self, window_start_ms: i64) -> String {
        let (y, m, d) = civil_from_days(window_start_ms.div_euclid(86_400_000));
        let stamp = match self {
            WindowKind::Hourly => {
                let hour = window_start_ms.rem_euclid(86_400_000) / 3_600_000;
                format!("{y:04}-{m:02}-{d:02}T{hour:02}Z")
            }
            WindowKind::Daily => format!("{y:04}-{m:02}-{d:02}"),
            WindowKind::Monthly => format!("{y:04}-{m:02}"),
        };
        format!("dwara-usage-{}-{stamp}", self.as_str())
    }
}

/// One output format (DW-120). Parquet is deliberately absent (lean
/// dependency rule; see the DW-156 backlog issue).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExportFormat {
    Csv,
    Json,
}

impl ExportFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            ExportFormat::Csv => "csv",
            ExportFormat::Json => "json",
        }
    }

    fn extension(self) -> &'static str {
        self.as_str()
    }
}

/// Config-vocabulary conversion without repeating the same match
/// arms per type: `impl_from_config!(Ty, ConfigEnum, Variants...)`
/// generates `From<config::ConfigEnum> for Ty` over identically named
/// variants.
macro_rules! impl_from_config {
    ($ty:ident, $cfg:ident, $($v:ident),+ $(,)?) => {
        impl From<crate::config::$cfg> for $ty {
            fn from(c: crate::config::$cfg) -> Self {
                match c {
                    $(crate::config::$cfg::$v => $ty::$v,)+
                }
            }
        }
    };
}

impl_from_config!(WindowKind, AnalyticsExportWindow, Hourly, Daily, Monthly);
impl_from_config!(ExportFormat, AnalyticsExportFormat, Csv, Json);

/// One per-consumer statement row (the JSON member shape; the CSV
/// writer flattens the same fields in a fixed column order).
#[derive(Debug, Serialize)]
pub struct StatementRow {
    pub consumer: String,
    pub requests: i64,
    pub errors: i64,
    pub error_rate: f64,
    pub rate_limited: i64,
    pub shed: i64,
    pub avg_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_daily: Option<QuotaBudget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_monthly: Option<QuotaBudget>,
}

/// The JSON file's document shape.
#[derive(Debug, Serialize)]
struct UsageStatement {
    kind: &'static str,
    window: &'static str,
    from_ms: i64,
    to_ms: i64,
    generated_at_ms: i64,
    partial: bool,
    /// Distinct rollup windows with any data in range (informational:
    /// quiet windows have no rows and are not loss).
    windows_nonempty: i64,
    totals: Option<query::QueryRow>,
    consumers: Vec<StatementRow>,
}

/// One export attempt's ledger row (the `export_runs` table and the
/// admin list endpoint's shape).
#[derive(Debug, Serialize)]
pub struct ExportRun {
    pub kind: String,
    pub window_start_ms: i64,
    pub window_end_ms: i64,
    /// `ok` or `failed`.
    pub status: String,
    pub partial: bool,
    pub formats: Vec<String>,
    pub directory: String,
    pub consumers: usize,
    pub requests: i64,
    pub windows_nonempty: i64,
    pub error: String,
    pub generated_at_ms: i64,
}

/// The effective exports schedule from the config block: window kind
/// (default daily) and formats (default both).
pub fn effective_window(cfg: &crate::config::AnalyticsExports) -> WindowKind {
    cfg.window
        .map(WindowKind::from)
        .unwrap_or(WindowKind::Daily)
}

/// The effective formats: the configured list, or both when the list
/// is omitted or empty (the config default and the validation rule
/// agree — an empty list MEANS both, it is never an error).
pub fn effective_formats(cfg: &crate::config::AnalyticsExports) -> Vec<ExportFormat> {
    if cfg.formats.is_empty() {
        vec![ExportFormat::Csv, ExportFormat::Json]
    } else {
        cfg.formats.iter().map(|f| ExportFormat::from(*f)).collect()
    }
}

/// Export one window: settle rollups, read the statement through the
/// query API's own aggregation, write one file per format, and upsert
/// the run record. `quota_at` supplies the quota figures for the
/// window (period bounds in epoch SECONDS). Never panics on I/O: a
/// failed run is recorded `failed` with the error string.
pub fn run_export(
    store: &EmbeddedAnalytics,
    directory: &str,
    window: WindowKind,
    window_start_ms: i64,
    formats: &[ExportFormat],
    quota_at: &dyn Fn(i64, i64) -> HashMap<String, QuotaFigures>,
    now_ms: i64,
) -> ExportRun {
    let (from_ms, to_ms) = window.window_of(window_start_ms);
    let gran = window.gran();
    // Settle the rollup cascade as far as the grace allows so the
    // statement reads complete windows (idempotent, cursor-guarded).
    store.maintain();
    let retention = store.retention_ms[gran + 1];
    let partial = from_ms < now_ms.saturating_sub(retention);

    let mut run = ExportRun {
        kind: window.as_str().to_string(),
        window_start_ms: from_ms,
        window_end_ms: to_ms,
        status: "ok".to_string(),
        partial,
        formats: formats.iter().map(|f| f.as_str().to_string()).collect(),
        directory: directory.to_string(),
        consumers: 0,
        requests: 0,
        windows_nonempty: 0,
        error: String::new(),
        generated_at_ms: now_ms,
    };

    // The statement IS the query API's answer: same tables, same
    // helpers, same period bounds.
    let read = store.query(|c| {
        let grouped = query::structured(
            c,
            &query::StructuredQuery {
                from_ms,
                to_ms,
                gran,
                group_by: vec!["consumer".to_string()],
                filters: query::FiltersBody::default(),
                limit: Some(10_000),
            },
        )?;
        let totals = query::structured(
            c,
            &query::StructuredQuery {
                from_ms,
                to_ms,
                gran,
                group_by: Vec::new(),
                filters: query::FiltersBody::default(),
                limit: Some(1),
            },
        )?;
        let nonempty: i64 = c.query_row(
            "SELECT COUNT(DISTINCT window_start) FROM rollup_fixed
             WHERE gran = ?1 AND window_start >= ?2 AND window_start < ?3",
            rusqlite::params![gran as i64, from_ms, to_ms],
            |r| r.get(0),
        )?;
        Ok((grouped, totals, nonempty))
    });
    let (grouped, totals, nonempty) = match read {
        Ok(v) => v,
        Err(e) => {
            return record_run(
                store,
                failed_run(run, &format!("analytics query failed: {e}")),
            );
        }
    };

    let quotas = quota_at(from_ms / 1000, to_ms / 1000);
    let mut rows = Vec::with_capacity(grouped.len());
    for r in &grouped {
        let q = quotas.get(&r.key[0]).copied().unwrap_or_default();
        rows.push(StatementRow {
            consumer: r.key[0].clone(),
            requests: r.requests,
            errors: r.errors,
            error_rate: r.error_rate,
            rate_limited: r.rate_limited,
            shed: r.shed,
            avg_ms: r.avg_ms,
            quota_daily: q.daily,
            quota_monthly: q.monthly,
        });
    }
    run.consumers = rows.len();
    run.requests = totals.first().map(|t| t.requests).unwrap_or(0);
    run.windows_nonempty = nonempty;

    let statement = UsageStatement {
        kind: "usage_statement",
        window: window.as_str(),
        from_ms,
        to_ms,
        generated_at_ms: now_ms,
        partial,
        windows_nonempty: nonempty,
        totals: totals.into_iter().next(),
        consumers: rows,
    };

    // Directory + files. Any write failure fails the run (files that
    // did land stay on disk — the record says which formats ran).
    let dir = Path::new(directory);
    if let Err(e) = std::fs::create_dir_all(dir) {
        return record_run(
            store,
            failed_run(run, &format!("export directory unusable: {e}")),
        );
    }
    for f in formats {
        let filename = format!("{}.{}", window.file_stem(from_ms), f.extension());
        let bytes = match f {
            ExportFormat::Json => match serde_json::to_vec_pretty(&statement) {
                Ok(b) => b,
                Err(e) => {
                    return record_run(store, failed_run(run, &format!("JSON render failed: {e}")))
                }
            },
            ExportFormat::Csv => render_csv(&statement),
        };
        if let Err(e) = write_atomic(dir, &filename, &bytes) {
            return record_run(
                store,
                failed_run(run, &format!("write {filename} failed: {e}")),
            );
        }
    }
    record_run(store, run)
}

/// The scheduler's per-tick entry (DW-120): export every closed,
/// settled window of the configured kind that has no successful run
/// record yet — oldest first, bounded by [`MAX_CATCHUP_WINDOWS`] per
/// tick and by the query granularity's retention horizon (windows
/// past it would be `partial`; a manual trigger can still force
/// them). Failed runs are retried on later ticks, at most once per
/// [`FAILURE_RETRY_MS`] window (the backoff).
pub fn run_due(
    store: &EmbeddedAnalytics,
    cfg: &crate::config::AnalyticsExports,
    quota_at: &dyn Fn(i64, i64) -> HashMap<String, QuotaFigures>,
    now_ms: i64,
) -> Vec<ExportRun> {
    let window = effective_window(cfg);
    let formats = effective_formats(cfg);
    let gran = window.gran();
    // The most recent window whose close is at least the delay in the
    // past (the window containing `now - delay` is still open by
    // construction, so `last_closed_window` answers the one before
    // it); everything older is exportable too (backfill).
    let mut start = last_closed_window(window, now_ms.saturating_sub(EXPORT_DELAY_MS));
    let horizon = now_ms.saturating_sub(store.retention_ms[gran + 1]);

    // The ledger holds one row per (kind, window_start_ms); keep the
    // per-window status and generated_at_ms so a failed window can be
    // skipped until its backoff elapses.
    let done: HashMap<i64, (String, i64)> = store
        .query(|c| {
            let mut stmt = c.prepare(
                "SELECT window_start_ms, status, generated_at_ms FROM export_runs
                 WHERE kind = ?1",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![window.as_str()], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                })?
                .map(|r| r.map(|(w, s, g)| (w, (s, g))))
                .collect::<Result<HashMap<_, _>, _>>()?;
            Ok(rows)
        })
        .unwrap_or_default();

    let mut due = Vec::new();
    while due.len() < MAX_CATCHUP_WINDOWS {
        if start < horizon || start < 0 {
            break;
        }
        if let Some((status, at_ms)) = done.get(&start) {
            let ok = status == "ok";
            let failed_recently = status == "failed" && now_ms - at_ms < FAILURE_RETRY_MS;
            if ok || failed_recently {
                break;
            }
        }
        due.push(start);
        let (prev, _) = window.window_of(start - 1);
        start = prev;
    }
    due.reverse();
    due.iter()
        .map(|&s| run_export(store, &cfg.directory, window, s, &formats, quota_at, now_ms))
        .collect()
}

/// The most recent CLOSED window of a kind (the manual trigger's
/// default): the window containing `now` is still open by
/// construction, so the answer is always the previous one — including
/// at the exact boundary instant, where the previous window has just
/// closed.
pub fn last_closed_window(window: WindowKind, now_ms: i64) -> i64 {
    let (start, _) = window.window_of(now_ms);
    let (prev, _) = window.window_of(start - 1);
    prev
}

/// List run records, newest first (the admin GET endpoint's read).
pub fn list_runs(store: &EmbeddedAnalytics, limit: usize) -> rusqlite::Result<Vec<ExportRun>> {
    store.query(|c| {
        let mut stmt = c.prepare(
            "SELECT kind, window_start_ms, window_end_ms, status, partial,
                    formats, directory, consumers, requests, windows_nonempty,
                    error, generated_at_ms
             FROM export_runs
             ORDER BY generated_at_ms DESC, kind ASC
             LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![limit as i64], |r| {
                Ok(ExportRun {
                    kind: r.get(0)?,
                    window_start_ms: r.get(1)?,
                    window_end_ms: r.get(2)?,
                    status: r.get(3)?,
                    partial: r.get::<_, i64>(4)? != 0,
                    formats: r
                        .get::<_, String>(5)?
                        .split(',')
                        .map(str::to_string)
                        .collect(),
                    directory: r.get(6)?,
                    consumers: r.get::<_, i64>(7)? as usize,
                    requests: r.get(8)?,
                    windows_nonempty: r.get(9)?,
                    error: r.get(10)?,
                    generated_at_ms: r.get(11)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

/// The manual trigger's request body (DW-120 admin endpoint): which
/// window kind to export and optionally which aligned window start.
#[derive(Debug, Default, Deserialize)]
pub struct ManualRunBody {
    pub window: Option<String>,
    pub window_start_ms: Option<i64>,
}

fn failed_run(mut run: ExportRun, error: &str) -> ExportRun {
    run.status = "failed".to_string();
    run.error = error.to_string();
    run
}

/// Upsert the run record (the ledger's one write; last run per window
/// wins, matching the idempotent file output). A record-write failure
/// is logged and swallowed — the run itself already happened.
fn record_run(store: &EmbeddedAnalytics, run: ExportRun) -> ExportRun {
    let row = (
        run.kind.as_str(),
        run.window_start_ms,
        run.window_end_ms,
        run.status.as_str(),
        i64::from(run.partial),
        run.formats.join(","),
        run.directory.as_str(),
        run.consumers as i64,
        run.requests,
        run.windows_nonempty,
        run.error.as_str(),
        run.generated_at_ms,
    );
    if let Err(e) = store.query(|c| {
        c.execute(
            "INSERT INTO export_runs (
                kind, window_start_ms, window_end_ms, status, partial,
                formats, directory, consumers, requests, windows_nonempty,
                error, generated_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(kind, window_start_ms) DO UPDATE SET
                window_end_ms = excluded.window_end_ms,
                status = excluded.status,
                partial = excluded.partial,
                formats = excluded.formats,
                directory = excluded.directory,
                consumers = excluded.consumers,
                requests = excluded.requests,
                windows_nonempty = excluded.windows_nonempty,
                error = excluded.error,
                generated_at_ms = excluded.generated_at_ms",
            rusqlite::params![
                row.0, row.1, row.2, row.3, row.4, row.5, row.6, row.7, row.8, row.9, row.10,
                row.11
            ],
        )?;
        Ok(())
    }) {
        tracing::warn!(
            code = "analytics_export_record_failed",
            "export run record write failed: {e}"
        );
    }
    if run.status == "failed" {
        tracing::warn!(
            code = "analytics_export_failed",
            window = %run.kind,
            from_ms = run.window_start_ms,
            "{}",
            run.error
        );
    } else {
        tracing::info!(
            code = "analytics_export_ok",
            window = %run.kind,
            from_ms = run.window_start_ms,
            consumers = run.consumers,
            requests = run.requests,
            partial = run.partial,
            "usage statement exported"
        );
    }
    run
}

/// Render the statement as RFC 4180 CSV: fixed header, one row per
/// consumer, CRLF terminators, fields quoted when they contain a
/// comma, quote, CR, or LF (quotes doubled). Absent quota cells are
/// EMPTY (zero means configured-and-zero-used — the distinction is
/// load-bearing for billing).
fn render_csv(s: &UsageStatement) -> Vec<u8> {
    let mut out = String::new();
    let mut header = Vec::new();
    for h in [
        "consumer",
        "requests",
        "errors",
        "error_rate",
        "rate_limited",
        "shed",
        "avg_ms",
        "quota_daily_used",
        "quota_daily_limit",
        "quota_monthly_used",
        "quota_monthly_limit",
    ] {
        header.push(h.to_string());
    }
    push_csv_row(&mut out, &header);
    for c in &s.consumers {
        let mut fields = vec![
            c.consumer.clone(),
            c.requests.to_string(),
            c.errors.to_string(),
            c.error_rate.to_string(),
            c.rate_limited.to_string(),
            c.shed.to_string(),
            c.avg_ms.to_string(),
        ];
        for q in [c.quota_daily, c.quota_monthly] {
            match q {
                Some(b) => {
                    fields.push(b.used.to_string());
                    fields.push(b.limit.to_string());
                }
                None => {
                    fields.push(String::new());
                    fields.push(String::new());
                }
            }
        }
        push_csv_row(&mut out, &fields);
    }
    out.into_bytes()
}

/// One CSV row (fields + CRLF), with per-field RFC 4180 escaping.
fn push_csv_row(out: &mut String, fields: &[String]) {
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        if f.bytes()
            .any(|b| b == b',' || b == b'"' || b == b'\r' || b == b'\n')
        {
            out.push('"');
            for ch in f.chars() {
                if ch == '"' {
                    out.push('"');
                }
                out.push(ch);
            }
            out.push('"');
        } else {
            out.push_str(f);
        }
    }
    out.push_str("\r\n");
}

/// Atomic DURABLE file write: temp file in the SAME directory,
/// fsync the file, rename over the destination, then fsync the
/// directory so the rename itself survives a crash (these are
/// billing artifacts — "written" must mean "on the disk", not "in
/// the page cache"). Atomic on POSIX; a crash mid-write leaves only
/// a stray temp, never a torn export. The directory fsync's io error
/// propagates like any other step's (never swallowed).
fn write_atomic(dir: &Path, filename: &str, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = dir.join(format!(
        ".{filename}.{}.tmp",
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = std::fs::File::create(&tmp)?;
    std::io::Write::write_all(&mut file, bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, dir.join(filename))?;
    std::fs::File::open(dir)?.sync_all()
}

/// UTC month window containing `ts_ms`, in epoch milliseconds. The
/// civil-calendar twin of `state::quotas::month_window` (epoch
/// SECONDS there) — this module cannot import the state domain (see
/// `scripts/check_deps.py`), so the algorithm lives twice, each copy
/// pinned by tests to the same boundary values.
fn month_window_ms(ts_ms: i64) -> (i64, i64) {
    const MS_PER_DAY: i64 = 86_400_000;
    let days = ts_ms.div_euclid(MS_PER_DAY);
    let (y, m, _) = civil_from_days(days);
    let start_days = days_from_civil(y, m, 1);
    let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
    let reset_days = days_from_civil(ny, nm, 1);
    (start_days * MS_PER_DAY, reset_days * MS_PER_DAY)
}

/// Civil date from days since the Unix epoch (Howard Hinnant's
/// `civil_from_days`; identical to the state domain's copy — see
/// [`month_window_ms`]).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The exact inverse of [`civil_from_days`] (`days_from_civil`).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

// White-box residual (the repo's relocated-unit-test convention keeps
// src suites for private-item coverage only): the CSV row writer, the
// filename stamper, and the civil-calendar twin are private, and
// their exactness IS the file format — everything else lives in
// tests/unit/exports.rs and tests/exports.rs.
#[cfg(test)]
mod tests {
    use super::*;

    /// A parse-and-split CSV reader sufficient for roundtrip tests:
    /// RFC 4180 fields (quoted when needed, embedded quotes doubled).
    fn parse_csv(text: &str) -> Vec<Vec<String>> {
        let mut rows = Vec::new();
        let mut row = Vec::new();
        let mut field = String::new();
        let mut in_quotes = false;
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            if in_quotes {
                if c == '"' {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        field.push('"');
                    } else {
                        in_quotes = false;
                    }
                } else {
                    field.push(c);
                }
            } else {
                match c {
                    '"' => in_quotes = true,
                    ',' => {
                        row.push(std::mem::take(&mut field));
                    }
                    '\r' => {}
                    '\n' => {
                        row.push(std::mem::take(&mut field));
                        rows.push(std::mem::take(&mut row));
                    }
                    _ => field.push(c),
                }
            }
        }
        if !field.is_empty() || !row.is_empty() {
            row.push(field);
            rows.push(row);
        }
        rows
    }

    #[test]
    fn csv_writer_escapes_rfc4180_and_roundtrips() {
        let mut rows = vec![vec![
            "consumer".to_string(),
            "plain".to_string(),
            "a,b".to_string(),
            "has\"quote".to_string(),
            "line\nbreak".to_string(),
            "cr\r lf".to_string(),
            "".to_string(),
        ]];
        let hostile = vec!["x\",y".to_string(), ",,\r\n\"".to_string()];
        rows.push(hostile.clone());
        let mut text = String::new();
        for r in &rows {
            push_csv_row(&mut text, r);
        }
        assert!(text.contains("\"a,b\""));
        assert!(text.contains("\"has\"\"quote\""));
        assert!(text.ends_with("\r\n"));
        let parsed = parse_csv(&text);
        assert_eq!(parsed.len(), rows.len());
        for (got, want) in parsed.iter().zip(rows.iter()) {
            assert_eq!(got, want);
        }
    }

    #[test]
    fn month_windows_are_calendar_correct() {
        // 1970-01: [0, 31 days).
        assert_eq!(month_window_ms(0), (0, 31 * 86_400_000));
        // 1970-02 (28 days) -> March 1st.
        let feb = 31 * 86_400_000;
        assert_eq!(month_window_ms(feb), (feb, 59 * 86_400_000));
        // 1972-02 is a leap year: 29 days.
        let leap_feb_ms = days_from_civil(1972, 2, 1) * 86_400_000;
        let mar72 = days_from_civil(1972, 3, 1) * 86_400_000;
        assert_eq!(month_window_ms(leap_feb_ms), (leap_feb_ms, mar72));
        assert_eq!(mar72 - leap_feb_ms, 29 * 86_400_000);
        // Year rollover: 2026-12 -> 2027-01.
        let dec26 = days_from_civil(2026, 12, 1) * 86_400_000;
        let jan27 = days_from_civil(2027, 1, 1) * 86_400_000;
        assert_eq!(month_window_ms(dec26 + 1000), (dec26, jan27));
        // Civil/days are exact inverses across a spread.
        for (y, m, d) in [
            (1970, 1, 1),
            (2000, 2, 29),
            (2026, 8, 29),
            (2100, 3, 1),
            (2400, 12, 31),
        ] {
            assert_eq!(civil_from_days(days_from_civil(y, m, d)), (y, m, d));
        }
    }

    #[test]
    fn file_stems_are_deterministic_and_distinct() {
        let day = 1_787_961_600_000; // 2026-08-29.
        assert_eq!(
            WindowKind::Daily.file_stem(day),
            "dwara-usage-daily-2026-08-29"
        );
        assert_eq!(
            WindowKind::Hourly.file_stem(day + 13 * 3_600_000),
            "dwara-usage-hourly-2026-08-29T13Z"
        );
        assert_eq!(
            WindowKind::Monthly.file_stem(day),
            "dwara-usage-monthly-2026-08"
        );
    }
}
