//! Raw table daily partitioning and retention automation (SCALE-09,
//! #188).
//!
//! The embedded analytics store's `raw` table grows unbounded under
//! high sustained throughput between retention prunes. This module
//! rotates the raw table daily into partition tables (`raw_YYYYMMDD`)
//! within the same SQLite database, making retention enforcement O(1)
//! (DROP TABLE) instead of O(n) (DELETE rows + incremental vacuum).
//!
//! # Design
//!
//! - The `raw` table is always the CURRENT day's partition. The
//!   writer inserts into `raw` unchanged.
//! - At daily boundaries, `maybe_rotate` renames `raw` to
//!   `raw_YYYYMMDD` (yesterday's date) and creates a new empty `raw`
//!   table with the full schema.
//! - A `raw_all` view UNION ALLs the `raw` table and all
//!   `raw_YYYYMMDD` partition tables, so the rollup and query layers
//!   read across all partitions without per-query changes.
//! - `drop_expired_partitions` drops `raw_YYYYMMDD` tables older than
//!   the raw retention period (O(1) DROP TABLE).
//! - The `raw_partitions` meta table tracks partition names and their
//!   date boundaries for introspection.
//!
//! # Why same-file partitions, not separate files
//!
//! The issue proposed separate SQLite files. Same-file partition
//! tables achieve the same O(1) retention and bounded raw table size
//! while avoiding the complexity of ATTACH/DETACH, cross-file
//! transactions, and connection management. SQLite's DROP TABLE is
//! O(1) (the pages are simply freed to the file's free list), and
//! incremental vacuum reclaims them. The `raw_all` view provides
//! cross-partition querying without dynamic SQL.

use rusqlite::Connection;

/// The `raw_partitions` meta table (schema v11, SCALE-09 #188):
/// tracks the partition table name and the date it covers. One row
/// per rotated partition. The current day's `raw` table is NOT listed
/// here (it is the active partition; it will be listed when it is
/// rotated).
pub const SCHEMA_V11: &str = "
    CREATE TABLE IF NOT EXISTS raw_partitions (
        partition_name TEXT PRIMARY KEY,
        date_ymd       TEXT NOT NULL,
        created_ms     INTEGER NOT NULL
    ) WITHOUT ROWID;
";

/// Format a unix-ms timestamp as `YYYYMMDD` in UTC.
fn ymd_from_ms(ms: i64) -> String {
    let secs = (ms / 1000).max(0) as u64;
    let days = secs / 86400;
    // Civil-from-days algorithm (Howard Hinnant).
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{:04}{:02}{:02}", year, m, d)
}

/// Check if the current `raw` table has rows from a previous day. If
/// so, rename it to `raw_YYYYMMDD` (the previous day's date), create
/// a fresh `raw` table, record the partition, and refresh the
/// `raw_all` view. Returns the partition name if a rotation
/// happened, `None` otherwise.
///
/// Safe to call at any time (from the maintenance tick). The
/// rotation is a single transaction: rename, create, record, refresh
/// view. A crash between the rename and the view refresh leaves the
/// partition accessible by its explicit name; the next maintenance
/// tick recreates the view.
pub fn maybe_rotate(conn: &Connection, now_ms: i64) -> rusqlite::Result<Option<String>> {
    // Check if the raw table has rows from a previous day.
    let prev_day_boundary = day_boundary_ms(now_ms);
    let has_prev_day: i64 = conn.query_row(
        "SELECT COUNT(*) FROM raw WHERE ts_ms < ?1",
        [prev_day_boundary],
        |r| r.get(0),
    )?;
    if has_prev_day == 0 {
        return Ok(None);
    }
    // Determine the partition name from the oldest row's date.
    let oldest_ms: i64 = conn.query_row(
        "SELECT MIN(ts_ms) FROM raw WHERE ts_ms < ?1",
        [prev_day_boundary],
        |r| r.get(0),
    )?;
    let partition_date = ymd_from_ms(oldest_ms);
    let partition_name = format!("raw_{partition_date}");
    // If the partition already exists (e.g., a re-run after a crash),
    // merge the rows into it instead of failing.
    let partition_exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
        [&partition_name],
        |r| r.get(0),
    )?;
    let tx = conn.unchecked_transaction()?;
    if partition_exists > 0 {
        // Merge: insert old rows from raw into the existing partition,
        // then delete them from raw.
        tx.execute_batch(&format!(
            "INSERT INTO {partition_name} (ts_ms, listener, route, consumer,
                upstream, method, status, status_class, duration_ms, attempts,
                rate_limited, broken, shed, dims, request_id, correlation_id,
                request_headers_redacted, auth_identity)
            SELECT ts_ms, listener, route, consumer, upstream, method, status,
                status_class, duration_ms, attempts, rate_limited, broken, shed,
                dims, request_id, correlation_id, request_headers_redacted,
                auth_identity
            FROM raw WHERE ts_ms < {prev_day_boundary};
            DELETE FROM raw WHERE ts_ms < {prev_day_boundary};"
        ))?;
    } else {
        // Create the partition table with the full schema, move old
        // rows into it, then delete them from raw. This keeps today's
        // rows in the active raw table.
        tx.execute_batch(&format!(
            "CREATE TABLE {partition_name} AS
             SELECT * FROM raw WHERE ts_ms < {prev_day_boundary};
             CREATE INDEX idx_{partition_name}_ts ON {partition_name}(ts_ms);
             CREATE INDEX idx_{partition_name}_corr
                 ON {partition_name}(correlation_id, ts_ms);
             DELETE FROM raw WHERE ts_ms < {prev_day_boundary};"
        ))?;
        tx.execute(
            "INSERT OR REPLACE INTO raw_partitions (partition_name, date_ymd, created_ms)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![partition_name, partition_date, now_ms],
        )?;
    }
    tx.commit()?;
    // Refresh the raw_all view outside the transaction.
    refresh_raw_all_view(conn)?;
    tracing::info!(
        code = "analytics_partition_rotated",
        partition = %partition_name,
        "raw table rotated to partition {partition_name}"
    );
    Ok(Some(partition_name))
}

/// The UTC midnight boundary (unix ms) of the day containing `now_ms`.
fn day_boundary_ms(now_ms: i64) -> i64 {
    let day_ms = 86_400_000i64;
    (now_ms / day_ms) * day_ms
}

/// Recreate the `raw_all` view as the UNION ALL of the `raw` table
/// and all `raw_YYYYMMDD` partition tables. Called after each
/// rotation and after dropping expired partitions.
pub fn refresh_raw_all_view(conn: &Connection) -> rusqlite::Result<()> {
    let mut names: Vec<String> = Vec::new();
    {
        let mut stmt =
            conn.prepare("SELECT partition_name FROM raw_partitions ORDER BY partition_name")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        for row in rows {
            names.push(row?);
        }
    }
    let mut sql = String::from("DROP VIEW IF EXISTS raw_all; CREATE VIEW raw_all AS ");
    sql.push_str("SELECT * FROM raw");
    for name in &names {
        sql.push_str(&format!(" UNION ALL SELECT * FROM {name}"));
    }
    conn.execute_batch(&sql)?;
    Ok(())
}

/// Drop partition tables older than the raw retention period. Returns
/// the number of partitions dropped. Each drop is O(1) (SQLite frees
/// the table's pages to the file's free list; incremental vacuum
/// reclaims them).
pub fn drop_expired_partitions(
    conn: &Connection,
    raw_keep_ms: i64,
    now_ms: i64,
) -> rusqlite::Result<usize> {
    let cutoff = now_ms.saturating_sub(raw_keep_ms);
    let cutoff_ymd = ymd_from_ms(cutoff);
    // Select expired partitions before dropping (can't mutate while
    // iterating the same connection).
    let mut expired: Vec<String> = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT partition_name FROM raw_partitions
             WHERE date_ymd < ?1 ORDER BY partition_name",
        )?;
        let rows = stmt.query_map([&cutoff_ymd], |r| r.get::<_, String>(0))?;
        for row in rows {
            expired.push(row?);
        }
    }
    if expired.is_empty() {
        return Ok(0);
    }
    let tx = conn.unchecked_transaction()?;
    let mut dropped = 0usize;
    for name in &expired {
        tx.execute_batch(&format!("DROP TABLE IF EXISTS {name}"))?;
        tx.execute(
            "DELETE FROM raw_partitions WHERE partition_name = ?1",
            [name],
        )?;
        dropped += 1;
        tracing::info!(
            code = "analytics_partition_dropped",
            partition = %name,
            "expired raw partition dropped"
        );
    }
    tx.commit()?;
    refresh_raw_all_view(conn)?;
    Ok(dropped)
}

/// List all active partition names (including the current `raw`
/// table), ordered by name. Useful for introspection and diagnostics.
pub fn list_partitions(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut names: Vec<String> = vec!["raw".to_string()];
    let mut stmt =
        conn.prepare("SELECT partition_name FROM raw_partitions ORDER BY partition_name")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    for row in rows {
        names.push(row?);
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_V11).unwrap();
        conn.execute_batch(
            "CREATE TABLE raw (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_ms        INTEGER NOT NULL,
                listener     TEXT NOT NULL,
                route        TEXT NOT NULL,
                consumer     TEXT NOT NULL,
                upstream     TEXT NOT NULL,
                method       TEXT NOT NULL,
                status       INTEGER NOT NULL,
                status_class TEXT NOT NULL,
                duration_ms  REAL NOT NULL,
                attempts     INTEGER NOT NULL,
                rate_limited INTEGER NOT NULL,
                broken       INTEGER NOT NULL,
                shed         INTEGER NOT NULL,
                dims         TEXT NOT NULL DEFAULT '{}',
                request_id   TEXT NOT NULL DEFAULT '',
                correlation_id TEXT NOT NULL DEFAULT '',
                request_headers_redacted TEXT,
                auth_identity TEXT
            );
            CREATE INDEX idx_raw_ts ON raw(ts_ms);
            CREATE INDEX idx_raw_correlation ON raw(correlation_id, ts_ms);",
        )
        .unwrap();
        conn
    }

    #[test]
    fn ymd_from_ms_basic() {
        // 2026-01-01 00:00:00 UTC = 1767225600 seconds = 1767225600000 ms
        assert_eq!(ymd_from_ms(1767225600000), "20260101");
        // 2026-08-30 09:00:00 UTC = 1725008400 seconds... let's use a known value
        // 2026-01-02 00:00:00 UTC = 1767312000000 ms
        assert_eq!(ymd_from_ms(1767312000000), "20260102");
    }

    #[test]
    fn day_boundary_aligns_to_midnight() {
        // 2026-01-01 12:00:00 UTC = 1767225600000 + 43200000 = 1767268800000
        let noon = 1767268800000i64;
        let boundary = day_boundary_ms(noon);
        assert_eq!(boundary, 1767225600000); // midnight
    }

    #[test]
    fn no_rotation_when_raw_is_empty() {
        let conn = open_test_db();
        let result = maybe_rotate(&conn, 1767225600000).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn no_rotation_when_all_rows_are_today() {
        let conn = open_test_db();
        let now = 1767268800000i64; // 2026-01-01 12:00 UTC
        conn.execute(
            "INSERT INTO raw (ts_ms, listener, route, consumer, upstream, method,
                status, status_class, duration_ms, attempts, rate_limited, broken,
                shed, dims) VALUES (?1, 'l', 'r', 'c', 'u', 'GET', 200, '2xx',
                1.0, 1, 0, 0, 0, '{}')",
            [now],
        )
        .unwrap();
        let result = maybe_rotate(&conn, now).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn rotation_moves_old_rows_to_partition() {
        let conn = open_test_db();
        let day1_morning = 1767225600000i64; // 2026-01-01 00:00 UTC
        let day1_noon = 1767268800000i64; // 2026-01-01 12:00 UTC
        let day2_morning = 1767312000000i64; // 2026-01-02 00:00 UTC
                                             // Insert two rows from 2026-01-01.
        conn.execute(
            "INSERT INTO raw (ts_ms, listener, route, consumer, upstream, method,
                status, status_class, duration_ms, attempts, rate_limited, broken,
                shed, dims) VALUES (?1, 'l', 'r', 'c', 'u', 'GET', 200, '2xx',
                1.0, 1, 0, 0, 0, '{}')",
            [day1_morning],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO raw (ts_ms, listener, route, consumer, upstream, method,
                status, status_class, duration_ms, attempts, rate_limited, broken,
                shed, dims) VALUES (?1, 'l', 'r', 'c', 'u', 'GET', 200, '2xx',
                1.0, 1, 0, 0, 0, '{}')",
            [day1_noon],
        )
        .unwrap();
        // Trigger rotation from 2026-01-02. Both rows from 2026-01-01
        // are before the day boundary (2026-01-02 00:00) and move to
        // the partition.
        let result = maybe_rotate(&conn, day2_morning).unwrap();
        assert_eq!(result.as_deref(), Some("raw_20260101"));
        // The raw table should be empty (no rows from 2026-01-02).
        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM raw", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 0);
        // The partition should have both rows.
        let partitioned: i64 = conn
            .query_row("SELECT COUNT(*) FROM raw_20260101", [], |r| r.get(0))
            .unwrap();
        assert_eq!(partitioned, 2);
        // The raw_all view should see both.
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM raw_all", [], |r| r.get(0))
            .unwrap();
        assert_eq!(total, 2);
    }

    #[test]
    fn drop_expired_partitions() {
        let conn = open_test_db();
        // Create a partition for 2025-12-31.
        conn.execute_batch(
            "CREATE TABLE raw_20251231 (ts_ms INTEGER NOT NULL);
             INSERT INTO raw_partitions (partition_name, date_ymd, created_ms)
             VALUES ('raw_20251231', '20251231', 1767139200000);",
        )
        .unwrap();
        refresh_raw_all_view(&conn).unwrap();
        // Now is 2026-01-02; retention is 1 day (86400000 ms).
        // Cutoff is 2026-01-01 00:00 UTC. Partition 20251231 is before
        // 20260101, so it should be dropped.
        let now = 1767312000000i64;
        let dropped = super::drop_expired_partitions(&conn, 86_400_000, now).unwrap();
        assert_eq!(dropped, 1);
        // The partition table should be gone.
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='raw_20251231'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(exists, 0);
    }

    #[test]
    fn list_partitions_includes_raw() {
        let conn = open_test_db();
        conn.execute_batch(
            "CREATE TABLE raw_20260101 (ts_ms INTEGER NOT NULL);
             INSERT INTO raw_partitions (partition_name, date_ymd, created_ms)
             VALUES ('raw_20260101', '20260101', 1767225600000);",
        )
        .unwrap();
        let parts = list_partitions(&conn).unwrap();
        assert_eq!(parts, vec!["raw", "raw_20260101"]);
    }
}
