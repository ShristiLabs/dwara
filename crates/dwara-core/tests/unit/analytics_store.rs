//! Unit tests for the embedded analytics STORE (DW-043): schema and
//! migrations, percentile math, rollup cascade correctness (exact
//! counts, idempotent recompute, cursor guarding, crash-recovery
//! determinism), retention, the never-block drop policy, the writer's
//! shutdown drain, and the query layer (closed grammar, dashboard
//! series, Top-N). The extension-seam contract's own tests live in
//! `tests/unit/analytics.rs`.
//!
//! Determinism strategy: rollup and query tests drive the SQLite
//! connection DIRECTLY (migrate + INSERT raw + call the rollup
//! functions) — the async writer only transports rows, so testing the
//! math through it would only add timing. The writer itself gets its
//! own test (real store, real workers, real flush tick and drain).

use dwara_core::analytics::query::{
    dashboard, structured, top, Filters, QueryError, StructuredQuery, TopKind,
};
use dwara_core::analytics::rollup::{
    cascade_range, cursor, roll_raw_range, roll_raw_to_1m, sweep_retention,
};
use dwara_core::analytics::schema::{
    bucket_of, migrate, percentile, LATEST_SCHEMA_VERSION, MS_BUCKETS,
};
use dwara_core::analytics::{EmbeddedAnalytics, DEFAULT_RETENTION_MS};
use dwara_core::observability::AccessRecord;

fn tmp_db(label: &str) -> (tempfile::TempDir, rusqlite::Connection) {
    let dir = tempfile::tempdir().unwrap();
    let conn = rusqlite::Connection::open(dir.path().join(format!("{label}.db"))).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")
        .unwrap();
    migrate(&conn).unwrap();
    (dir, conn)
}

fn insert_raw(
    conn: &rusqlite::Connection,
    ts_ms: i64,
    route: &str,
    consumer: &str,
    status: u16,
    duration_ms: f64,
    dims: &str,
) {
    conn.execute(
        "INSERT INTO raw (ts_ms, listener, route, consumer, upstream, method, status,
                          status_class, duration_ms, attempts, rate_limited, broken,
                          shed, dims)
         VALUES (?1, 'edge', ?2, ?3, 'up', 'GET', ?4, ?5, ?6, 1, 0, 0, 0, ?7)",
        rusqlite::params![
            ts_ms,
            route,
            consumer,
            status as i64,
            format!("{}xx", status / 100),
            duration_ms,
            dims
        ],
    )
    .unwrap();
}

fn raw_count(conn: &rusqlite::Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM raw", [], |r| r.get(0))
        .unwrap()
}

fn rollup_sum(conn: &rusqlite::Connection, gran: usize) -> (i64, i64, f64) {
    conn.query_row(
        "SELECT SUM(requests), SUM(errors), SUM(duration_sum_ms) FROM rollup_fixed \
         WHERE gran = ?1",
        [gran as i64],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .unwrap()
}

#[test]
fn schema_migrates_fresh_and_stamps_version() {
    let (_dir, conn) = tmp_db("migrate");
    let v: u32 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, LATEST_SCHEMA_VERSION);
    // Re-run is a no-op (idempotent DDL, version unchanged).
    migrate(&conn).unwrap();
    let v2: u32 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v2, LATEST_SCHEMA_VERSION);
}

#[test]
fn percentile_math_is_bounded_and_monotone() {
    assert_eq!(bucket_of(0.5), 0);
    assert_eq!(bucket_of(1.0), 0);
    assert_eq!(bucket_of(1.1), 1);
    assert_eq!(bucket_of(250.0), 7);
    assert_eq!(bucket_of(9_999.0), MS_BUCKETS.len()); // overflow bucket
                                                      // Empty: zero, not a panic.
    assert_eq!(percentile(&[0; 13], 0.95), 0.0);
    // Ten equal samples in bucket 1 (2 ms): every percentile is that
    // bucket's bound.
    let mut buckets = [0i64; 13];
    buckets[1] = 10;
    assert_eq!(percentile(&buckets, 0.50), 2.0);
    assert_eq!(percentile(&buckets, 0.99), 2.0);
    // Nine fast + one very slow: p50/p90 stay fast, p95 crosses into
    // the overflow bucket and reports the last bound's floor.
    let mut mixed = [0i64; 13];
    mixed[0] = 9; // <= 1 ms
    mixed[12] = 1; // overflow (> 5 s)
    assert_eq!(percentile(&mixed, 0.50), 1.0);
    assert_eq!(percentile(&mixed, 0.90), 1.0);
    assert_eq!(percentile(&mixed, 0.95), MS_BUCKETS[MS_BUCKETS.len() - 1]);
}

#[test]
fn raw_rollup_counts_errors_and_buckets_exactly() {
    let (_dir, conn) = tmp_db("roll1");
    // Minute 0 (window [0, 60000)): three 200s and one 500.
    insert_raw(&conn, 1_000, "r1", "a", 200, 5.0, "{}");
    insert_raw(&conn, 2_000, "r1", "a", 200, 8.0, "{}");
    insert_raw(&conn, 3_000, "r1", "b", 200, 100.0, "{}");
    insert_raw(&conn, 4_000, "r1", "a", 500, 50.0, "{}");
    // Minute 1: one 200.
    insert_raw(&conn, 61_000, "r1", "a", 200, 2.0, "{}");
    roll_raw_range(&conn, 0, 120_000).unwrap();
    let (req, err, dur) = rollup_sum(&conn, 0);
    assert_eq!((req, err), (5, 1));
    assert!((dur - 165.0).abs() < 1e-6, "sum of durations: {dur}");
    // Per-key row: (minute 0, route r1, consumer a, status 2xx) = 2.
    let a2xx: i64 = conn
        .query_row(
            "SELECT requests FROM rollup_fixed WHERE gran = 0 AND window_start = 0 \
             AND route = 'r1' AND consumer = 'a' AND status_class = '2xx'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(a2xx, 2);
    // Buckets are non-cumulative one-hots with INCLUSIVE bounds: for
    // consumer a's minute-0 rows, 5 ms lands in bucket 2 (<= 5 ms) and
    // 8 ms in bucket 3 (<= 10 ms) — the 50 ms 5xx row is a different
    // status_class row entirely.
    let b2: i64 = conn
        .query_row(
            "SELECT SUM(b2) FROM rollup_fixed WHERE gran = 0 AND window_start = 0 \
             AND consumer = 'a'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(b2, 1, "the 5 ms row");
    let b3: i64 = conn
        .query_row(
            "SELECT SUM(b3) FROM rollup_fixed WHERE gran = 0 AND window_start = 0 \
             AND consumer = 'a'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(b3, 1, "the 8 ms row");
}

#[test]
fn raw_rollup_is_idempotent_and_cursor_guarded() {
    let (_dir, conn) = tmp_db("roll2");
    insert_raw(&conn, 1_000, "r", "a", 200, 5.0, "{}");
    insert_raw(&conn, 70_000, "r", "a", 200, 5.0, "{}");
    // now = 181 s, grace 60 s -> frontier floors to 120 s: BOTH fine
    // windows ([0,60s) and [60s,120s)) are complete and roll.
    let now = 120_000 + 61_000;
    let n = roll_raw_to_1m(&conn, now, 60_000).unwrap();
    assert_eq!(n, 2, "both completed windows");
    assert_eq!(cursor(&conn, 0), 120_000);
    let (req, _, _) = rollup_sum(&conn, 0);
    assert_eq!(req, 2);
    // Re-run over the same ground: no double counting.
    let n2 = roll_raw_to_1m(&conn, now, 60_000).unwrap();
    assert_eq!(n2, 0);
    // Even with a RESET cursor (the crash-recovery shape): identical
    // result — idempotence comes from wholesale recompute.
    conn.execute("UPDATE meta SET value = '0' WHERE key = 'g0_cursor_ms'", [])
        .unwrap();
    let n3 = roll_raw_to_1m(&conn, now, 60_000).unwrap();
    assert_eq!(n3, 2);
    let (req2, _, _) = rollup_sum(&conn, 0);
    assert_eq!(req2, 2, "recompute does not double-count");
}

#[test]
fn cascade_1m_to_5m_sums_windows() {
    let (_dir, conn) = tmp_db("cascade");
    // Five minutes, two requests per minute (one of them a 503).
    for m in 0..5i64 {
        insert_raw(&conn, m * 60_000 + 1_000, "r", "a", 200, 10.0, "{}");
        insert_raw(&conn, m * 60_000 + 2_000, "r", "a", 503, 10.0, "{}");
    }
    roll_raw_range(&conn, 0, 300_000).unwrap();
    cascade_range(&conn, 0, 0, 300_000).unwrap();
    let (req, err, dur) = rollup_sum(&conn, 1);
    assert_eq!((req, err), (10, 5));
    assert!((dur - 100.0).abs() < 1e-6);
    let windows: i64 = conn
        .query_row(
            "SELECT COUNT(DISTINCT window_start) FROM rollup_fixed WHERE gran = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(windows, 1, "five minutes collapse into one 5m window");
    // Cascade idempotence: same re-run, same numbers.
    cascade_range(&conn, 0, 0, 300_000).unwrap();
    let (req2, _, _) = rollup_sum(&conn, 1);
    assert_eq!(req2, 10);
}

#[test]
fn dim_rollup_groups_by_name_and_value() {
    let (_dir, conn) = tmp_db("dims");
    insert_raw(&conn, 1_000, "r", "a", 200, 5.0, r#"{"plan":"pro"}"#);
    insert_raw(&conn, 2_000, "r", "a", 200, 5.0, r#"{"plan":"free"}"#);
    insert_raw(&conn, 3_000, "r", "b", 500, 5.0, r#"{"plan":"pro"}"#);
    // A row with NO dims contributes to no dim rollup.
    insert_raw(&conn, 4_000, "r", "b", 200, 5.0, "{}");
    roll_raw_range(&conn, 0, 60_000).unwrap();
    let pro: (i64, i64) = conn
        .query_row(
            "SELECT requests, errors FROM rollup_dim WHERE gran = 0 AND dim = 'plan' \
             AND value = 'pro'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(pro, (2, 1));
    let free: i64 = conn
        .query_row(
            "SELECT requests FROM rollup_dim WHERE gran = 0 AND dim = 'plan' \
             AND value = 'free'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(free, 1);
    // Dims cascade too.
    cascade_range(&conn, 0, 0, 300_000).unwrap();
    let pro5: i64 = conn
        .query_row(
            "SELECT requests FROM rollup_dim WHERE gran = 1 AND dim = 'plan' \
             AND value = 'pro'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(pro5, 2);
}

#[test]
fn retention_sweep_drops_expired_and_keeps_fresh() {
    let (_dir, conn) = tmp_db("retention");
    insert_raw(&conn, 1_000, "r", "a", 200, 5.0, "{}");
    insert_raw(&conn, 10 * 86_400_000, "r", "a", 200, 5.0, "{}");
    // Roll BOTH minutes (the fresh row sits at the 10-day mark).
    roll_raw_range(&conn, 0, 10 * 86_400_000 + 1).unwrap();
    let now = 10 * 86_400_000 + 1;
    // Keep raw 5 days, 1m 1 day: the old raw row and its 1m rollup
    // both expire; the fresh pair stays.
    let deleted = sweep_retention(&conn, 5 * 86_400_000, [86_400_000, 0, 0, 0], now, 64).unwrap();
    assert!(deleted >= 2, "raw + rollup rows deleted: {deleted}");
    assert_eq!(raw_count(&conn), 1, "fresh raw row kept");
    let kept: i64 = conn
        .query_row(
            "SELECT requests FROM rollup_fixed WHERE window_start = ?",
            [10 * 86_400_000 / 60_000 * 60_000],
            |r| r.get(0),
        )
        .unwrap_or(0);
    assert_eq!(kept, 1);
}

#[test]
fn record_drops_when_channel_full_and_never_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("full.db");
    let store =
        EmbeddedAnalytics::open(path.to_str().unwrap(), DEFAULT_RETENTION_MS, 100, 0).unwrap();
    // No workers spawned: nothing drains the channel.
    let rec = AccessRecord::new("rid".into(), "GET".into(), "/".into(), "edge".into());
    for _ in 0..5000 {
        store.record(&rec);
    }
    // The honest counter is the proof: 5000 offered against a 4096
    // capacity, so at least 5000 - 4096 dropped (and every call
    // returned — try_send never blocks).
    assert!(
        store.dropped_records() >= 5000 - 4096,
        "dropped: {}",
        store.dropped_records()
    );
}

#[tokio::test]
async fn writer_flushes_batches_and_drains_on_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("writer.db");
    let store =
        EmbeddedAnalytics::open(path.to_str().unwrap(), DEFAULT_RETENTION_MS, 50, 0).unwrap();
    let (tx, rx) = tokio::sync::watch::channel(());
    let handles = store.spawn_workers(rx);
    for i in 0..25 {
        let mut r = AccessRecord::new(format!("rid-{i}"), "GET".into(), "/x".into(), "edge".into());
        r.route = "api".into();
        r.consumer = "acme".into();
        r.status = 200;
        r.duration_ms = 7.0;
        store.record(&r);
    }
    // Shutdown: drop the sender -> workers drain, final-flush, stop.
    drop(tx);
    for h in handles {
        tokio::time::timeout(std::time::Duration::from_secs(5), h)
            .await
            .expect("workers stop promptly")
            .expect("worker ok");
    }
    let n = store.query(|c| Ok(raw_count(c))).unwrap();
    assert_eq!(n, 25, "every record drained and flushed on shutdown");
}

#[test]
fn structured_query_validates_the_closed_grammar() {
    let q = |group_by: &[&str], gran: usize, from: i64, to: i64| StructuredQuery {
        from_ms: from,
        to_ms: to,
        gran,
        group_by: group_by.iter().map(|s| s.to_string()).collect(),
        filters: Default::default(),
        limit: None,
    };
    assert!(q(&["consumer"], 0, 0, 1).validate().is_ok());
    assert!(q(&[], 3, 0, 1).validate().is_ok());
    // SQL text is never accepted — not by rejecting strings that LOOK
    // like SQL, but because only the six column names can match.
    assert!(matches!(
        q(&["consumer; DROP TABLE raw"], 0, 0, 1)
            .validate()
            .unwrap_err(),
        QueryError::UnknownGroupBy(_)
    ));
    assert!(matches!(
        q(&[], 4, 0, 1).validate().unwrap_err(),
        QueryError::BadGranularity(4)
    ));
    assert!(matches!(
        q(&[], 0, 1, 1).validate().unwrap_err(),
        QueryError::BadRange
    ));
}

#[test]
fn structured_query_dashboard_and_top_serve_seeded_rollups() {
    let (_dir, conn) = tmp_db("query");
    // Two consumers over two minutes; acme has an error, beta is slow.
    insert_raw(&conn, 1_000, "api", "acme", 200, 5.0, "{}");
    insert_raw(&conn, 2_000, "api", "acme", 500, 5.0, "{}");
    insert_raw(&conn, 61_000, "api", "beta", 200, 500.0, "{}");
    insert_raw(&conn, 62_000, "web", "beta", 200, 499.0, "{}");
    roll_raw_range(&conn, 0, 120_000).unwrap();

    // Structured: group by consumer.
    let q = StructuredQuery {
        from_ms: 0,
        to_ms: 120_000,
        gran: 0,
        group_by: vec!["consumer".to_string()],
        filters: Default::default(),
        limit: None,
    };
    let rows = structured(&conn, &q).unwrap();
    assert_eq!(rows.len(), 2);
    let acme = rows.iter().find(|r| r.key == ["acme".to_string()]).unwrap();
    assert_eq!((acme.requests, acme.errors), (2, 1));
    assert!((acme.error_rate - 0.5).abs() < 1e-9);
    let beta = rows.iter().find(|r| r.key == ["beta".to_string()]).unwrap();
    assert_eq!(beta.requests, 2);
    assert!((beta.avg_ms - 499.5).abs() < 1e-6);
    assert_eq!(beta.p95_ms, 500.0, "p95 falls in the <=500ms bucket");

    // Structured: filter to one route.
    let qf = StructuredQuery {
        filters: dwara_core::analytics::query::FiltersBody {
            route: Some("web".to_string()),
            ..Default::default()
        },
        ..q
    };
    let rowsf = structured(&conn, &qf).unwrap();
    assert_eq!(rowsf.len(), 1);
    assert_eq!(rowsf[0].requests, 1);

    // Dashboard: per-window series, grouped by consumer.
    let filters = Filters::default();
    let points = dashboard(&conn, 0, 120_000, 0, Some("consumer"), &filters).unwrap();
    assert_eq!(
        points.len(),
        2,
        "acme owns minute 0 (2 requests), beta owns minute 1 (2 requests)"
    );
    let first = points
        .iter()
        .find(|p| p.key.as_deref() == Some("acme") && p.window_start == 0)
        .unwrap();
    assert_eq!(first.requests, 2);
    assert_eq!(first.error_rate, 0.5);

    // Top-N: every kind answers, volumes sum to the seeded total.
    let top_c = top(&conn, TopKind::Consumers, 0, 120_000, 10).unwrap();
    assert_eq!(top_c.len(), 2);
    assert_eq!(top_c.iter().map(|e| e.requests).sum::<i64>(), 4);
    let slow = top(&conn, TopKind::Slowest, 0, 120_000, 10).unwrap();
    assert_eq!(
        slow[0].name, "web",
        "web's single request averages 499ms; api averages 170ms"
    );
    let errp = top(&conn, TopKind::ErrorProne, 0, 120_000, 10).unwrap();
    assert_eq!(errp[0].name, "api", "entries: {errp:?}");
    // api spans BOTH consumers: 3 requests (200, 500, 200), 1 error.
    assert!(
        (errp[0].error_rate - 1.0 / 3.0).abs() < 1e-9,
        "entries: {errp:?}"
    );
    let rl = top(&conn, TopKind::RateLimited, 0, 120_000, 10).unwrap();
    assert_eq!(rl.iter().map(|e| e.rate_limited).sum::<i64>(), 0);
}
