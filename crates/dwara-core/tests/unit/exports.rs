//! Usage-report exports, unit layer (DW-120): window-kind boundary
//! math through the public API, the closed vocabularies (parse, config
//! conversion, effective defaults), the manual trigger's default
//! window, and the v2 schema's ledger table. The statement/file/
//! scheduler behavior lives in `tests/exports.rs`; the private CSV
//! writer, filename stamper, and civil calendar are pinned white-box
//! in `analytics/exports.rs` itself.

use dwara_core::analytics::exports::{self, ExportFormat, WindowKind};
use dwara_core::analytics::{EmbeddedAnalytics, DEFAULT_RETENTION_MS};

#[test]
fn window_kinds_align_to_utc_boundaries() {
    let h = WindowKind::Hourly;
    assert_eq!(h.window_of(0), (0, 3_600_000));
    assert_eq!(h.window_of(3_599_999), (0, 3_600_000));
    assert_eq!(h.window_of(3_600_000), (3_600_000, 7_200_000));
    let d = WindowKind::Daily;
    assert_eq!(d.window_of(86_399_999), (0, 86_400_000));
    assert_eq!(d.window_of(86_400_000), (86_400_000, 172_800_000));
    // 2026-08-29T00:00:00Z = 1787961600 s.
    let day = 1_787_961_600_000;
    assert_eq!(d.window_of(day), (day, day + 86_400_000));
}

#[test]
fn monthly_windows_are_calendar_aligned() {
    let m = WindowKind::Monthly;
    // 1970-01: [0, 31 days); 1970-02 (28 days) ends March 1st.
    assert_eq!(m.window_of(0), (0, 31 * 86_400_000));
    let feb = 31 * 86_400_000;
    assert_eq!(m.window_of(feb), (feb, 59 * 86_400_000));
    // 2026-08-29 falls inside [Aug 1, Sep 1).
    let aug = 1_787_961_600_000; // 2026-08-29.
    let aug_start = 1_785_542_400_000; // 2026-08-01T00:00:00Z.
    assert_eq!(m.window_of(aug), (aug_start, aug_start + 31 * 86_400_000));
    // The LAST instant of August still belongs to August.
    assert_eq!(m.window_of(aug_start + 31 * 86_400_000 - 1).0, aug_start);
}

#[test]
fn window_kind_parse_is_the_closed_set() {
    assert_eq!(WindowKind::parse("hourly"), Some(WindowKind::Hourly));
    assert_eq!(WindowKind::parse("daily"), Some(WindowKind::Daily));
    assert_eq!(WindowKind::parse("monthly"), Some(WindowKind::Monthly));
    for bad in ["weekly", "Daily", "", "cron(0 0 * * *)", "parquet"] {
        assert_eq!(WindowKind::parse(bad), None, "{bad}");
    }
    assert_eq!(WindowKind::Hourly.as_str(), "hourly");
}

#[test]
fn effective_defaults_are_daily_and_both_formats() {
    let cfg = dwara_core::config::AnalyticsExports {
        directory: "/tmp/x".to_string(),
        window: None,
        formats: vec![],
    };
    assert_eq!(exports::effective_window(&cfg), WindowKind::Daily);
    assert_eq!(
        exports::effective_formats(&cfg),
        vec![ExportFormat::Csv, ExportFormat::Json]
    );
    // Configured values pass through (config vocabulary -> engine).
    let cfg = dwara_core::config::AnalyticsExports {
        directory: "/tmp/x".to_string(),
        window: Some(dwara_core::config::AnalyticsExportWindow::Hourly),
        formats: vec![dwara_core::config::AnalyticsExportFormat::Json],
    };
    assert_eq!(exports::effective_window(&cfg), WindowKind::Hourly);
    assert_eq!(exports::effective_formats(&cfg), vec![ExportFormat::Json]);
}

#[test]
fn last_closed_window_never_returns_an_open_one() {
    let d = WindowKind::Daily;
    let day = 86_400_000;
    // Mid-day-1: the last FULLY closed daily window is day 0.
    assert_eq!(exports::last_closed_window(d, day + day / 2), 0);
    // At the 2-day boundary, day 1 has just closed: it is the default.
    assert_eq!(exports::last_closed_window(d, 2 * day), day);
    assert_eq!(exports::last_closed_window(d, 3 * day), 2 * day);
    // The final millisecond of day 0: day 0 is still open (1 ms
    // left), so the last closed window is the pre-epoch day — floor
    // semantics, negative epochs included.
    assert_eq!(exports::last_closed_window(d, day - 1), -day);
}

#[test]
fn schema_v2_export_runs_table_exists() {
    let dir = tempfile::tempdir().unwrap();
    let store = EmbeddedAnalytics::open(
        dir.path().join("a.db").to_str().unwrap(),
        DEFAULT_RETENTION_MS,
        1000,
    )
    .unwrap();
    store
        .query(|c| {
            let n: i64 = c.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'export_runs'",
                [],
                |r| r.get(0),
            )?;
            assert_eq!(n, 1);
            let v: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0))?;
            assert_eq!(v, 2);
            Ok(())
        })
        .unwrap();
}
