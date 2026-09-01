//! Usage-report export tests (DW-120): the statement's reconciliation
//! with the query API (the acceptance criterion — pinned here as an
//! equality assertion against an independent `structured()` call over
//! the same store and period), the file outputs (CSV shape, JSON
//! shape, quota columns, idempotent overwrite), the scheduler's
//! due/backfill/skip behavior, partial-window flagging, and failed
//! run recording. Everything drives the store directly with synthetic
//! clocks — deterministic, no async machinery needed (admin-endpoint
//! coverage lives in the dwara-admin API suite; a follow-up test pass
//! adds it).
//!
//! Timing note: `run_export` settles rollups via the store's
//! `maintain()` pass, whose retention sweep runs on the REAL clock —
//! so synthetic epoch-0 windows are only safe with the
//! never-deleting [`RETAIN_EVERYTHING`] keep (any real retention
//! would classify 1970 as long-expired). The partial-flag test is the
//! one that must interlock with the real clock, and anchors to it.

use std::collections::HashMap;
use std::sync::Arc;

use dwara_core::analytics::exports::{self, ExportFormat, QuotaBudget, QuotaFigures, WindowKind};
use dwara_core::analytics::{query, rollup, EmbeddedAnalytics};
use dwara_core::config::parse_gateway;
use dwara_core::proxy::DataPlane;
use dwara_core::snapshot::ConfigState;
use dwara_core::state::quotas::Budget;
use dwara_core::state::store::{sync_consumers_from_config, StateStore};

/// Retention that never deletes (see the module docs' timing note).
const RETAIN_EVERYTHING: [i64; 5] = [i64::MAX; 5];

fn real_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn open_store(dir: &tempfile::TempDir, retention: [i64; 5]) -> std::sync::Arc<EmbeddedAnalytics> {
    EmbeddedAnalytics::open(
        dir.path().join("a.db").to_str().unwrap(),
        retention,
        1000,
        0,
    )
    .unwrap()
}

/// Insert one raw row (the redacted AccessRecord field set).
fn raw(conn: &rusqlite::Connection, ts_ms: i64, consumer: &str, status: u16, rate_limited: bool) {
    conn.execute(
        "INSERT INTO raw (ts_ms, listener, route, consumer, upstream, method,
                          status, status_class, duration_ms, attempts,
                          rate_limited, broken, shed, dims)
         VALUES (?1, 'edge', 'api', ?2, 'up', 'GET', ?3, ?4, 10.0, 1,
                 ?5, 0, 0, '{}')",
        rusqlite::params![
            ts_ms,
            consumer,
            status,
            format!("{}xx", status / 100),
            i64::from(rate_limited),
        ],
    )
    .unwrap();
}

/// Seed day 0 (1970-01-01) with deterministic traffic: acme 3 requests
/// (one 5xx, one rate-limited 429), beta 1 request, and one consumer
/// whose name is CSV-hostile. Rolled to 1-minute windows (run_export's
/// maintain() cascades them the rest of the way).
fn seed_day0(store: &EmbeddedAnalytics) {
    store
        .query(|c| {
            raw(c, 60_000, "acme", 200, false);
            raw(c, 120_000, "acme", 500, false);
            raw(c, 180_000, "acme", 429, true);
            raw(c, 240_000, "beta", 200, false);
            raw(c, 300_000, "weird,\"name", 200, false);
            rollup::roll_raw_range(c, 0, 86_400_000).unwrap();
            Ok(())
        })
        .unwrap();
}

fn no_quota(_: i64, _: i64) -> HashMap<String, QuotaFigures> {
    HashMap::new()
}

fn run_day0(store: &EmbeddedAnalytics, dir: &str, now_ms: i64) -> exports::ExportRun {
    exports::run_export(
        store,
        dir,
        WindowKind::Daily,
        0,
        &[ExportFormat::Csv, ExportFormat::Json],
        &no_quota,
        now_ms,
    )
}

fn read(dir: &str, name: &str) -> String {
    std::fs::read_to_string(std::path::Path::new(dir).join(name)).unwrap()
}

/// THE acceptance test (issue #143): the per-consumer usage statement
/// for a period matches the analytics query API's own numbers for that
/// period — asserted against an INDEPENDENT structured() call, both
/// reading the written file and the live query.
#[test]
fn statement_matches_the_query_api_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, RETAIN_EVERYTHING);
    seed_day0(&store);
    let out = dir.path().join("out");
    let out_str = out.to_str().unwrap().to_string();
    let now = 3 * 86_400_000;

    let run = run_day0(&store, &out_str, now);
    assert_eq!(run.status, "ok", "{}", run.error);
    assert_eq!(run.window_start_ms, 0);
    assert_eq!(run.window_end_ms, 86_400_000);
    assert!(!run.partial, "fresh window within retention");
    assert_eq!(run.consumers, 3);
    assert_eq!(run.requests, 5);

    // Independent query-API read of the same period (same granularity
    // the statement uses: 1-hour rows for a daily window).
    let rows = store
        .query(|c| {
            query::structured(
                c,
                &query::StructuredQuery {
                    from_ms: 0,
                    to_ms: 86_400_000,
                    gran: 2,
                    group_by: vec!["consumer".to_string()],
                    filters: query::FiltersBody::default(),
                    limit: Some(100),
                },
            )
        })
        .unwrap();
    assert_eq!(rows.len(), 3, "same consumer set as the statement");

    let doc: serde_json::Value =
        serde_json::from_str(&read(&out_str, "dwara-usage-daily-1970-01-01.json")).unwrap();
    assert_eq!(doc["kind"], "usage_statement");
    assert_eq!(doc["window"], "daily");
    assert_eq!(doc["from_ms"], 0);
    assert_eq!(doc["to_ms"], 86_400_000);
    assert_eq!(doc["partial"], false);
    assert_eq!(doc["totals"]["requests"], 5);
    assert_eq!(doc["totals"]["errors"], 1);

    for r in &rows {
        let stmt = doc["consumers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["consumer"] == serde_json::json!(r.key[0]))
            .unwrap_or_else(|| panic!("consumer {} missing from statement", r.key[0]));
        assert_eq!(stmt["requests"], r.requests, "{} requests", r.key[0]);
        assert_eq!(stmt["errors"], r.errors, "{} errors", r.key[0]);
        assert_eq!(
            stmt["rate_limited"], r.rate_limited,
            "{} rate_limited",
            r.key[0]
        );
        assert_eq!(stmt["shed"], r.shed, "{} shed", r.key[0]);
        let stmt_rate = stmt["error_rate"].as_f64().unwrap();
        assert!(
            (stmt_rate - r.error_rate).abs() < 1e-12,
            "{} error_rate: statement {stmt_rate} vs query {}",
            r.key[0],
            r.error_rate
        );
    }
    // Spot pins: acme 3 requests / 1 error / 1 rate-limited.
    let acme = doc["consumers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["consumer"] == "acme")
        .unwrap();
    assert_eq!(acme["requests"], 3);
    assert_eq!(acme["errors"], 1);
    assert_eq!(acme["rate_limited"], 1);
}

/// The CSV twin: fixed header, one row per consumer (query-API order),
/// RFC 4180 quoting for hostile names, empty (not zero) quota cells.
#[test]
fn csv_file_carries_the_same_numbers_and_escapes_hostile_names() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, RETAIN_EVERYTHING);
    seed_day0(&store);
    let out = dir.path().join("out").to_str().unwrap().to_string();

    let quota_budget = QuotaBudget {
        used: 2,
        limit: 1000,
        window_start_epoch_s: 0,
        reset_epoch_s: 86_400,
    };
    let run = exports::run_export(
        &store,
        &out,
        WindowKind::Daily,
        0,
        &[ExportFormat::Csv],
        &|_, _| {
            let mut m = HashMap::new();
            m.insert(
                "acme".to_string(),
                QuotaFigures {
                    daily: Some(quota_budget),
                    monthly: None,
                },
            );
            m
        },
        3 * 86_400_000,
    );
    assert_eq!(run.status, "ok", "{}", run.error);

    let csv = read(&out, "dwara-usage-daily-1970-01-01.csv");
    assert!(csv.starts_with("consumer,requests,errors,error_rate,rate_limited,shed,avg_ms,quota_daily_used,quota_daily_limit,quota_monthly_used,quota_monthly_limit,prompt_tokens,completion_tokens,total_tokens,cost_micros\r\n"));
    // Hostile name is quoted with doubled quotes.
    assert!(csv.contains("\"weird,\"\"name\",1,0,"), "{csv}");
    // acme carries its quota figures; beta's cells are EMPTY, not 0.
    assert!(csv.contains("acme,3,1,"), "{csv}");
    let acme_line = csv.lines().find(|l| l.starts_with("acme")).unwrap();
    assert!(
        acme_line.ends_with(",2,1000,,,0,0,0,0"),
        "acme row: {acme_line}"
    );
    let beta_line = csv.lines().find(|l| l.starts_with("beta")).unwrap();
    assert!(beta_line.ends_with(",,,,0,0,0,0"), "beta row: {beta_line}");
    assert!(csv.ends_with("\r\n"));
}

/// Re-exporting a window is idempotent: same filenames, overwritten
/// content, ONE ledger row.
#[test]
fn reexport_overwrites_files_and_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, RETAIN_EVERYTHING);
    seed_day0(&store);
    let out = dir.path().join("out").to_str().unwrap().to_string();

    let first = run_day0(&store, &out, 3 * 86_400_000);
    assert_eq!(first.status, "ok", "{}", first.error);
    let second = run_day0(&store, &out, 4 * 86_400_000);
    assert_eq!(second.status, "ok", "{}", second.error);

    let files: Vec<_> = std::fs::read_dir(&out)
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(files.len(), 2, "csv + json, overwritten in place");
    let runs = exports::list_runs(&store, 10).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].generated_at_ms, 4 * 86_400_000, "latest run wins");
}

/// A period older than the query granularity's retention is exported
/// but flagged partial — real data, honestly marked, never fabricated.
/// Anchored to the real clock: the window must survive maintain()'s
/// real-clock sweep (yesterday, 2-day keep) while the synthetic NOW
/// pushed past the retention marks it partial.
#[test]
fn window_older_than_retention_is_flagged_partial() {
    let dir = tempfile::tempdir().unwrap();
    // Every granularity kept 2 days.
    let keep = 2 * 86_400_000;
    let store = open_store(&dir, [keep; 5]);
    let now = real_now_ms();
    let day = (now - 86_400_000).div_euclid(86_400_000) * 86_400_000; // yesterday, UTC.
    store
        .query(|c| {
            raw(c, day + 60_000, "acme", 200, false);
            rollup::roll_raw_range(c, day, day + 86_400_000).unwrap();
            Ok(())
        })
        .unwrap();
    let out = dir.path().join("out").to_str().unwrap().to_string();

    // Synthetic now four days past the window: beyond the 2-day keep.
    let run = exports::run_export(
        &store,
        &out,
        WindowKind::Daily,
        day,
        &[ExportFormat::Json],
        &no_quota,
        now + 3 * 86_400_000,
    );
    assert_eq!(run.status, "ok", "{}", run.error);
    assert!(run.partial);
    let doc: serde_json::Value = serde_json::from_str(&read(
        &out,
        &format!("dwara-usage-daily-{}.json", stamp(day)),
    ))
    .unwrap();
    assert_eq!(doc["partial"], true, "the file says what the run says");
}

/// An empty period still produces valid, explicitly-empty files (a
/// zero-traffic day is a reportable day).
#[test]
fn empty_period_writes_valid_empty_statements() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, RETAIN_EVERYTHING);
    let out = dir.path().join("out").to_str().unwrap().to_string();
    // Export day 1 (nothing seeded there).
    let run = exports::run_export(
        &store,
        &out,
        WindowKind::Daily,
        86_400_000,
        &[ExportFormat::Csv, ExportFormat::Json],
        &no_quota,
        3 * 86_400_000,
    );
    assert_eq!(run.status, "ok", "{}", run.error);
    assert_eq!(run.consumers, 0);
    assert_eq!(run.requests, 0);
    let csv = read(&out, "dwara-usage-daily-1970-01-02.csv");
    assert_eq!(csv.matches("\r\n").count(), 1, "header only: {csv}");
    let doc: serde_json::Value =
        serde_json::from_str(&read(&out, "dwara-usage-daily-1970-01-02.json")).unwrap();
    assert_eq!(doc["consumers"].as_array().unwrap().len(), 0);
    assert_eq!(doc["totals"]["requests"], 0);
}

/// An unusable directory fails the run LOUD: status failed, error
/// recorded, nothing written — and the ledger carries the failure.
#[test]
fn unusable_directory_records_a_failed_run() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, RETAIN_EVERYTHING);
    seed_day0(&store);
    // A FILE where the directory should be.
    let not_a_dir = dir.path().join("file");
    std::fs::write(&not_a_dir, b"occupied").unwrap();

    let run = exports::run_export(
        &store,
        not_a_dir.to_str().unwrap(),
        WindowKind::Daily,
        0,
        &[ExportFormat::Csv],
        &no_quota,
        3 * 86_400_000,
    );
    assert_eq!(run.status, "failed");
    assert!(run.error.contains("directory unusable"), "{}", run.error);
    let runs = exports::list_runs(&store, 10).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].status, "failed");
}

/// The scheduler: exports every closed+settled window with no ok
/// record (backfill, oldest first, here bounded by the epoch floor —
/// hours 0..=8 of day 0), and a second tick exports nothing new.
#[test]
fn run_due_backfills_then_quiets_down() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, RETAIN_EVERYTHING);
    store
        .query(|c| {
            raw(c, 60_000, "acme", 200, false);
            rollup::roll_raw_range(c, 0, 86_400_000).unwrap();
            Ok(())
        })
        .unwrap();
    let out = dir.path().join("out").to_str().unwrap().to_string();
    let cfg = exports_config(&out, "hourly", &["csv"]);

    // 09:20 on day 0: hour 8 closed 20 minutes ago (past the 5-minute
    // settle delay); hour 9 is still open.
    let now = 9 * 3_600_000 + 20 * 60_000;
    let runs = exports::run_due(&store, &cfg, &no_quota, now);
    assert_eq!(runs.len(), 9, "hours 0..=8, the epoch floor stops the walk");
    assert!(
        runs.iter().all(|r| r.status == "ok"),
        "all backfilled windows export clean"
    );
    // Oldest first; the newest export is the just-settled hour 8.
    let stems: Vec<i64> = runs.iter().map(|r| r.window_start_ms).collect();
    let mut sorted = stems.clone();
    sorted.sort_unstable();
    assert_eq!(stems, sorted);
    assert_eq!(*stems.last().unwrap(), 8 * 3_600_000);

    // Idempotence: nothing new on the next tick.
    let again = exports::run_due(&store, &cfg, &no_quota, now + 60_000);
    assert!(
        again
            .iter()
            .filter(|r| r.window_start_ms < 9 * 3_600_000)
            .count()
            == 0,
        "already-ok windows are skipped"
    );
}

/// The settle delay: a window closed less than
/// [`exports::EXPORT_DELAY_MS`] ago is not due yet.
#[test]
fn run_due_respects_the_settle_delay() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, RETAIN_EVERYTHING);
    let out = dir.path().join("out").to_str().unwrap().to_string();
    let cfg = exports_config(&out, "hourly", &["csv"]);
    // Hour 9 closed ONE minute ago: not due; hour 8 is.
    let now = 10 * 3_600_000 + 60_000;
    let runs = exports::run_due(&store, &cfg, &no_quota, now);
    assert!(
        runs.iter().all(|r| r.window_start_ms < 9 * 3_600_000),
        "the just-closed hour is not exported yet"
    );
    assert!(
        !runs.is_empty() && runs.iter().any(|r| r.window_start_ms == 8 * 3_600_000),
        "the previous hour is"
    );
}

/// The failure backoff: a failed window is not retried while its last
/// attempt is inside [`exports::FAILURE_RETRY_MS`], and becomes due
/// again the instant the backoff elapses (>= is a retry).
#[test]
fn run_due_backs_off_failed_windows() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, RETAIN_EVERYTHING);
    // A FILE where the directory should be: every run fails.
    let not_a_dir = dir.path().join("file");
    std::fs::write(&not_a_dir, b"occupied").unwrap();
    let cfg = exports_config(not_a_dir.to_str().unwrap(), "hourly", &["csv"]);

    // 09:20 on day 0: hours 0..=8 due, all failing.
    let now = 9 * 3_600_000 + 20 * 60_000;
    let runs = exports::run_due(&store, &cfg, &no_quota, now);
    assert_eq!(runs.len(), 9);
    assert!(runs.iter().all(|r| r.status == "failed"));

    // The next tick (30 s) and a later one (9 min) are inside the
    // 10-minute backoff: nothing retries.
    assert!(exports::run_due(&store, &cfg, &no_quota, now + 30_000).is_empty());
    assert!(
        exports::run_due(&store, &cfg, &no_quota, now + 9 * 60_000).is_empty(),
        "still inside the backoff"
    );

    // At exactly the backoff boundary the windows are due again (the
    // same failed set, one fresh attempt each).
    let retry = exports::run_due(&store, &cfg, &no_quota, now + exports::FAILURE_RETRY_MS);
    assert_eq!(retry.len(), 9, "the backoff elapses, not expires");
    assert!(retry.iter().all(|r| r.status == "failed"));
}

// --- quota-column containment (DW-120: the dataplane seam) ----------------
//
// The statement's quota columns come from `quota_figures_at`, which
// reads the CURRENT generation's quota blocks and the state store's
// `quota_counters` — windows are keyed by their start, so fixed epoch
// anchors make the whole matrix clock-free and deterministic.

/// 2026-08-01T00:00:00Z and 2026-08-29T00:00:00Z (epoch seconds): the
/// fixed UTC anchors of the containment tests. August has 31 days, so
/// the day of Aug 29 sits strictly inside the month and Sep 1 is
/// `AUG_1_2026_S + 31 * 86_400`.
const AUG_1_2026_S: i64 = 1_785_542_400;
const AUG_29_2026_S: i64 = 1_787_961_600;

/// The quota-figures fixture config: `acme` carries both budgets,
/// `free` has none (the no-quotas-block control).
fn quotas_yaml() -> String {
    "consumers:
  - name: acme
    credentials:
      - type: api_key
        key: acme-key
    quotas:
      daily_requests: 100
      monthly_requests: 1000
  - name: free
    credentials:
      - type: api_key
        key: free-key
routes:
  - name: r
    service: svc
    match: { path: { type: prefix, value: /r } }
    action: { type: respond, status: 200, body: ok }
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
"
    .to_string()
}

/// A dataplane with the quota fixture's consumers and a synced
/// in-memory state store — the `quota_figures_at` seam, mirroring the
/// DW-033 fixtures in tests/quotas.rs.
fn figures_dataplane() -> (Arc<DataPlane>, Arc<StateStore>) {
    let gateway = parse_gateway(&quotas_yaml()).expect("test config parses");
    let state = Arc::new(ConfigState::new());
    state
        .compile_and_publish(&gateway)
        .expect("test config publishes");
    let store = Arc::new(StateStore::open_in_memory().unwrap());
    sync_consumers_from_config(&store, &gateway, None).expect("consumer seed");
    let dp = DataPlane::new(state);
    dp.set_state_store(Arc::clone(&store));
    (dp, store)
}

/// A daily export window carries exactly the containment rule's two
/// budgets: the same-UTC-day `daily` counter (exact period
/// consumption) and the month-to-date `monthly` counter — each with
/// the bounds a billing consumer needs to interpret `used`. A consumer
/// without a quotas block carries NO figures at all (never fabricated
/// zeros).
#[test]
fn quota_figures_for_a_daily_window_carry_same_day_and_month_to_date() {
    let (dp, store) = figures_dataplane();
    let acme_id = store.lookup_consumer("acme").unwrap().unwrap().id;
    store
        .incr_quota(acme_id, Budget::Daily.key(), AUG_29_2026_S, 7, None)
        .unwrap();
    store
        .incr_quota(acme_id, Budget::Monthly.key(), AUG_1_2026_S, 41, None)
        .unwrap();

    // The daily export window [Aug 29, Aug 30).
    let figures = dp.quota_figures_at(AUG_29_2026_S, AUG_29_2026_S + 86_400);
    let acme = figures
        .get("acme")
        .expect("budgeted consumer carries figures");
    let daily = acme
        .daily
        .expect("the same-UTC-day daily counter contains the window");
    assert_eq!((daily.used, daily.limit), (7, 100));
    assert_eq!(daily.window_start_epoch_s, AUG_29_2026_S);
    assert_eq!(daily.reset_epoch_s, AUG_29_2026_S + 86_400);
    let monthly = acme
        .monthly
        .expect("the month-to-date counter contains the window");
    assert_eq!((monthly.used, monthly.limit), (41, 1000));
    assert_eq!(monthly.window_start_epoch_s, AUG_1_2026_S);
    assert_eq!(monthly.reset_epoch_s, AUG_1_2026_S + 31 * 86_400, "Sep 1");
    assert!(
        !figures.contains_key("free"),
        "a consumer without a quotas block carries no figures: {figures:?}"
    );
}

/// A monthly export window carries ONLY the monthly counter: the daily
/// budget's window (the day containing the month's start) does not
/// contain the month, so its figures are OMITTED — even though the
/// counter exists with usage in it. Omitted, never zeroed: a zero
/// would tell billing the day's budget went unused.
#[test]
fn quota_figures_for_a_monthly_window_omit_non_containing_daily_budgets() {
    let (dp, store) = figures_dataplane();
    let acme_id = store.lookup_consumer("acme").unwrap().unwrap().id;
    // The daily counter of Aug 1 EXISTS and is spent — containment, not
    // absence, is what must drop it from a monthly statement.
    store
        .incr_quota(acme_id, Budget::Daily.key(), AUG_1_2026_S, 5, None)
        .unwrap();
    store
        .incr_quota(acme_id, Budget::Monthly.key(), AUG_1_2026_S, 41, None)
        .unwrap();

    // The monthly export window [Aug 1, Sep 1).
    let figures = dp.quota_figures_at(AUG_1_2026_S, AUG_1_2026_S + 31 * 86_400);
    let acme = figures
        .get("acme")
        .expect("budgeted consumer carries figures");
    assert!(
        acme.daily.is_none(),
        "the Aug-1 daily window does not contain August: {acme:?}"
    );
    let monthly = acme
        .monthly
        .expect("the monthly counter contains itself exactly");
    assert_eq!(monthly.used, 41);
    assert_eq!(monthly.window_start_epoch_s, AUG_1_2026_S);
}

/// The retention horizon: `run_due` never AUTO-exports a window older
/// than the query granularity's retention (it could only be
/// undercounted), while a manual `run_export` of the same window still
/// writes it — flagged `partial`, real data honestly marked.
#[test]
fn run_due_skips_past_horizon_windows_but_a_manual_run_forces_them() {
    let dir = tempfile::tempdir().unwrap();
    // Every granularity kept 2 days: at synthetic now = day 3 the
    // horizon is day 1, so day 1 exports and day 0 does not.
    let keep = 2 * 86_400_000;
    let store = open_store(&dir, [keep; 5]);
    let out = dir.path().join("out").to_str().unwrap().to_string();
    let cfg = exports_config(&out, "daily", &["json"]);
    let now = 3 * 86_400_000;

    let runs = exports::run_due(&store, &cfg, &no_quota, now);
    assert_eq!(runs.len(), 1, "only the within-horizon window is due");
    assert_eq!(runs[0].window_start_ms, 86_400_000, "day 1, not day 0");
    assert_eq!(runs[0].status, "ok", "{}", runs[0].error);
    assert!(!runs[0].partial, "day 1 is inside the 2-day keep");

    // Day 0 was skipped entirely: no ledger row, no file — while day
    // 1's file did land.
    let ledger = exports::list_runs(&store, 10).unwrap();
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger[0].window_start_ms, 86_400_000);
    assert!(!std::path::Path::new(&out)
        .join("dwara-usage-daily-1970-01-01.json")
        .exists());
    assert!(std::path::Path::new(&out)
        .join("dwara-usage-daily-1970-01-02.json")
        .exists());

    // A manual trigger forces the too-old window: written, partial.
    let run = exports::run_export(
        &store,
        &out,
        WindowKind::Daily,
        0,
        &[ExportFormat::Json],
        &no_quota,
        now,
    );
    assert_eq!(run.status, "ok", "{}", run.error);
    assert!(
        run.partial,
        "past the horizon the statement is flagged partial"
    );
    let doc: serde_json::Value =
        serde_json::from_str(&read(&out, "dwara-usage-daily-1970-01-01.json")).unwrap();
    assert_eq!(doc["partial"], true, "the file says what the run says");
    let ledger = exports::list_runs(&store, 10).unwrap();
    assert_eq!(ledger.len(), 2, "the forced run records too");
}

/// A monthly statement over a multi-day span: the file stem is the
/// month stamp, the totals are the whole-month sum, and the numbers
/// fingerprint the 1-day granularity choice — exactly TWO nonempty
/// rollup windows for two seeded days (an hour-row statement would
/// count one per seeded hour, six here).
#[test]
fn monthly_statement_spans_days_on_one_day_rows() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, RETAIN_EVERYTHING);
    seed_day0(&store);
    // Day 1: acme 2 more (one 5xx), beta 1 — across hours 0 and 1 of
    // 1970-01-02 (3 distinct nonempty hour windows over the two days:
    // day 0's seeds all sit in hour 0).
    store
        .query(|c| {
            raw(c, 86_400_000 + 60_000, "acme", 200, false);
            raw(c, 86_400_000 + 3_600_000 + 30_000, "acme", 503, false);
            raw(c, 86_400_000 + 3_600_000 + 60_000, "beta", 200, false);
            rollup::roll_raw_range(c, 86_400_000, 2 * 86_400_000).unwrap();
            Ok(())
        })
        .unwrap();
    let out = dir.path().join("out").to_str().unwrap().to_string();

    let run = exports::run_export(
        &store,
        &out,
        WindowKind::Monthly,
        0,
        &[ExportFormat::Csv, ExportFormat::Json],
        &no_quota,
        3 * 86_400_000,
    );
    assert_eq!(run.status, "ok", "{}", run.error);
    assert_eq!(run.window_start_ms, 0);
    assert_eq!(run.window_end_ms, 31 * 86_400_000, "all of January");
    assert!(!run.partial);
    assert_eq!(run.consumers, 3);
    assert_eq!(run.requests, 8, "5 (day 0) + 3 (day 1)");
    assert_eq!(run.windows_nonempty, 2, "ONE row per DAY, not per hour");

    // The month stamp names both files.
    let doc: serde_json::Value =
        serde_json::from_str(&read(&out, "dwara-usage-monthly-1970-01.json")).unwrap();
    assert_eq!(doc["kind"], "usage_statement");
    assert_eq!(doc["window"], "monthly");
    assert_eq!(doc["windows_nonempty"], 2);
    assert_eq!(doc["totals"]["requests"], 8);
    assert_eq!(doc["totals"]["errors"], 2);
    assert!(std::path::Path::new(&out)
        .join("dwara-usage-monthly-1970-01.csv")
        .exists());

    // The reconciliation contract holds at month scale too: the file's
    // per-consumer numbers equal an independent structured() call over
    // the same period (1-day rows, grouped by consumer).
    let rows = store
        .query(|c| {
            query::structured(
                c,
                &query::StructuredQuery {
                    from_ms: 0,
                    to_ms: 31 * 86_400_000,
                    gran: 3,
                    group_by: vec!["consumer".to_string()],
                    filters: query::FiltersBody::default(),
                    limit: Some(100),
                },
            )
        })
        .unwrap();
    assert_eq!(rows.len(), 3);
    for r in &rows {
        let stmt = doc["consumers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["consumer"] == serde_json::json!(r.key[0]))
            .unwrap_or_else(|| panic!("consumer {} missing from statement", r.key[0]));
        assert_eq!(stmt["requests"], r.requests, "{} requests", r.key[0]);
        assert_eq!(stmt["errors"], r.errors, "{} errors", r.key[0]);
    }
    // Spot pins: acme spans both days (3 + 2), beta 1 + 1, weird 1.
    let consumers = doc["consumers"].as_array().unwrap();
    let find = |n: &str| consumers.iter().find(|c| c["consumer"] == n).unwrap();
    assert_eq!(find("acme")["requests"], 5);
    assert_eq!(find("acme")["errors"], 2);
    assert_eq!(find("beta")["requests"], 2);
    assert_eq!(find("weird,\"name")["requests"], 1);
}

fn exports_config(
    directory: &str,
    window: &str,
    formats: &[&str],
) -> dwara_core::config::AnalyticsExports {
    dwara_core::config::AnalyticsExports {
        directory: directory.to_string(),
        window: Some(match window {
            "hourly" => dwara_core::config::AnalyticsExportWindow::Hourly,
            "monthly" => dwara_core::config::AnalyticsExportWindow::Monthly,
            _ => dwara_core::config::AnalyticsExportWindow::Daily,
        }),
        formats: formats
            .iter()
            .map(|f| match *f {
                "csv" => dwara_core::config::AnalyticsExportFormat::Csv,
                _ => dwara_core::config::AnalyticsExportFormat::Json,
            })
            .collect(),
    }
}

/// `YYYY-MM-DD` stamp of a UTC window start (the daily filename's
/// date segment — mirrors the engine's own civil-calendar stamp so
/// this test can compute expected filenames without duplicating more
/// of the formatter).
fn stamp(day_start_ms: i64) -> String {
    let days = day_start_ms.div_euclid(86_400_000);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}
