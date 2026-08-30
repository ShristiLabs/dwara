//! Rollup cascade and retention (DW-043).
//!
//! Four granularities roll in a fixed cascade — raw → 1m → 5m → 1h →
//! 1d — each stage aggregating the PREVIOUS stage's completed windows,
//! never raw twice (except by deterministic recompute, see below):
//!
//! - A window is COMPLETE when its end plus a safety grace (writer
//!   lag headroom) is in the past; the grace means a straggler record
//!   flushed late still lands in the window it belongs to. Rows
//!   arriving later than the grace are documented as rollup-lost
//!   (they remain queryable in `raw` until raw retention expires).
//! - Each granularity keeps a CURSOR (exclusive ms frontier) in
//!   `meta`, advanced in the SAME transaction as the rows it covers:
//!   a crash mid-cascade never double-counts.
//! - Every aggregation is a wholesale window RECOMPUTE
//!   (`INSERT OR REPLACE` over the window's full source range), so
//!   re-running any window — after a crash, a restored backup, or a
//!   cursor reset — reproduces byte-identical rows. Idempotence comes
//!   from determinism, not from merge arithmetic (upsert-merge would
//!   double-count on re-run).
//! - Custom-dimension rollups aggregate the same raw range in RUST
//!   (the source column is a JSON object; keeping JSON out of SQL
//!   avoids depending on the bundled SQLite's JSON1 build flags).
//!
//! Retention deletes expired rows per granularity (raw by `ts_ms`,
//! rollups by `window_start`) and incrementally vacuums, which is the
//! bounded-disk half of the done-when: pages return to the file
//! system without a full VACUUM ever blocking the writer.

use std::collections::BTreeMap;

use rusqlite::Connection;

use super::schema::{bucket_of, BUCKET_COLS};

/// The four granularities, in cascade order (index = the `gran`
/// column value stored in the rollup tables).
pub const GRANULARITIES_MS: [i64; 4] = [60_000, 300_000, 3_600_000, 86_400_000];

/// Meta key for a granularity's cursor (`g0`..`g3`; `g0` is the
/// raw→1m frontier).
fn cursor_key(gran: usize) -> String {
    format!("g{gran}_cursor_ms")
}

/// Read a cursor (0 when never set).
pub fn cursor(conn: &Connection, gran: usize) -> i64 {
    conn.query_row(
        "SELECT value FROM meta WHERE key = ?1",
        [cursor_key(gran)],
        |r| r.get::<_, String>(0),
    )
    .ok()
    .and_then(|v| v.parse().ok())
    .unwrap_or(0)
}

fn set_cursor_tx(conn: &Connection, gran: usize, frontier: i64) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![cursor_key(gran), frontier.to_string()],
    )?;
    Ok(())
}

/// Window start (floor to granularity) of a timestamp.
pub fn window_of(ts_ms: i64, gran_ms: i64) -> i64 {
    (ts_ms / gran_ms) * gran_ms
}

/// One raw→1m pass: aggregate raw rows in `[cursor, frontier)` into
/// completed 1-minute windows, recompute-style. `frontier` must be the
/// end of the last COMPLETE window (the caller computes it with the
/// grace). Returns the number of 1m windows written.
pub fn roll_raw_to_1m(conn: &Connection, now_ms: i64, grace_ms: i64) -> rusqlite::Result<usize> {
    let gran_ms = GRANULARITIES_MS[0];
    let frontier = window_of(now_ms.saturating_sub(grace_ms), gran_ms);
    let cur = cursor(conn, 0);
    if frontier <= cur {
        return Ok(0);
    }
    let tx = conn.unchecked_transaction()?;
    let n = roll_raw_range(&tx, cur, frontier)?;
    set_cursor_tx(&tx, 0, frontier)?;
    tx.commit()?;
    Ok(n)
}

/// Aggregate raw `[lo, hi)` into `rollup_fixed`/`rollup_dim` at
/// granularity 0, wholesale over the range (idempotent recompute).
/// Split from [`roll_raw_to_1m`] so tests can drive exact ranges.
pub fn roll_raw_range(conn: &Connection, lo: i64, hi: i64) -> rusqlite::Result<usize> {
    let windows = roll_raw_fixed(conn, lo, hi)?;
    roll_raw_dims(conn, lo, hi)?;
    Ok(windows)
}

/// The fixed-dimension pass: pure SQL GROUP BY with per-row bucket
/// one-hots. Each request contributes to exactly one bucket column,
/// so SUM(b_i) is the non-cumulative bucket histogram.
fn roll_raw_fixed(conn: &Connection, lo: i64, hi: i64) -> rusqlite::Result<usize> {
    let before: i64 = conn.query_row(
        "SELECT COUNT(DISTINCT (ts_ms / 60000)) FROM raw WHERE ts_ms >= ?1 AND ts_ms < ?2",
        [lo, hi],
        |r| r.get(0),
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO rollup_fixed (
            gran, window_start, listener, route, upstream, consumer,
            method, status_class, requests, errors, rate_limited, shed,
            duration_sum_ms, duration_max_ms,
            b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12
        )
        SELECT 0,
            (ts_ms / 60000) * 60000,
            listener, route, upstream, consumer, method, status_class,
            COUNT(*),
            SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END),
            SUM(rate_limited), SUM(shed),
            SUM(duration_ms), MAX(duration_ms),
            SUM(CASE WHEN duration_ms <= 1.0 THEN 1 ELSE 0 END),
            SUM(CASE WHEN duration_ms > 1.0 AND duration_ms <= 2.0 THEN 1 ELSE 0 END),
            SUM(CASE WHEN duration_ms > 2.0 AND duration_ms <= 5.0 THEN 1 ELSE 0 END),
            SUM(CASE WHEN duration_ms > 5.0 AND duration_ms <= 10.0 THEN 1 ELSE 0 END),
            SUM(CASE WHEN duration_ms > 10.0 AND duration_ms <= 25.0 THEN 1 ELSE 0 END),
            SUM(CASE WHEN duration_ms > 25.0 AND duration_ms <= 50.0 THEN 1 ELSE 0 END),
            SUM(CASE WHEN duration_ms > 50.0 AND duration_ms <= 100.0 THEN 1 ELSE 0 END),
            SUM(CASE WHEN duration_ms > 100.0 AND duration_ms <= 250.0 THEN 1 ELSE 0 END),
            SUM(CASE WHEN duration_ms > 250.0 AND duration_ms <= 500.0 THEN 1 ELSE 0 END),
            SUM(CASE WHEN duration_ms > 500.0 AND duration_ms <= 1000.0 THEN 1 ELSE 0 END),
            SUM(CASE WHEN duration_ms > 1000.0 AND duration_ms <= 2500.0 THEN 1 ELSE 0 END),
            SUM(CASE WHEN duration_ms > 2500.0 AND duration_ms <= 5000.0 THEN 1 ELSE 0 END),
            SUM(CASE WHEN duration_ms > 5000.0 THEN 1 ELSE 0 END)
        FROM raw
        WHERE ts_ms >= ?1 AND ts_ms < ?2
        GROUP BY (ts_ms / 60000), listener, route, upstream, consumer,
                 method, status_class",
        [lo, hi],
    )?;
    Ok(before as usize)
}

/// The custom-dimension pass, in Rust: one scan of the range's
/// (ts, dims, status, duration) rows, grouped by
/// (minute, dim name, value). Dims rows do NOT split by fixed
/// dimensions — a dimension value aggregates every request carrying
/// it (that is the point of a custom dimension).
fn roll_raw_dims(conn: &Connection, lo: i64, hi: i64) -> rusqlite::Result<()> {
    #[derive(Default)]
    struct Acc {
        requests: i64,
        errors: i64,
        duration_sum_ms: f64,
        buckets: Vec<i64>,
    }
    let mut groups: BTreeMap<(i64, String, String), Acc> = BTreeMap::new();
    {
        let mut stmt = conn.prepare(
            "SELECT ts_ms, dims, status, duration_ms FROM raw
             WHERE ts_ms >= ?1 AND ts_ms < ?2",
        )?;
        let mut rows = stmt.query([lo, hi])?;
        while let Some(row) = rows.next()? {
            let ts: i64 = row.get(0)?;
            let dims_json: String = row.get(1)?;
            let status: i64 = row.get(2)?;
            let duration_ms: f64 = row.get(3)?;
            let Ok(map) =
                serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&dims_json)
            else {
                continue;
            };
            let minute = window_of(ts, 60_000);
            for (dim, value) in map {
                let Some(value) = value.as_str().map(str::to_string) else {
                    continue;
                };
                let acc = groups
                    .entry((minute, dim.clone(), value))
                    .or_insert_with(|| Acc {
                        buckets: vec![0; BUCKET_COLS],
                        ..Acc::default()
                    });
                acc.requests += 1;
                if status >= 500 {
                    acc.errors += 1;
                }
                acc.duration_sum_ms += duration_ms;
                acc.buckets[bucket_of(duration_ms)] += 1;
            }
        }
    }
    let mut stmt = conn.prepare(
        "INSERT OR REPLACE INTO rollup_dim (
            gran, window_start, dim, value, requests, errors,
            duration_sum_ms, b0, b1, b2, b3, b4, b5, b6, b7, b8, b9,
            b10, b11, b12
        ) VALUES (0, ?1, ?2, ?3, ?4, ?5, ?6,
                  ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
                  ?18, ?19)",
    )?;
    for ((minute, dim, value), acc) in groups {
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![
            Box::new(minute),
            Box::new(dim),
            Box::new(value),
            Box::new(acc.requests),
            Box::new(acc.errors),
            Box::new(acc.duration_sum_ms),
        ];
        for b in &acc.buckets {
            params.push(Box::new(*b));
        }
        stmt.execute(rusqlite::params_from_iter(
            params.iter().map(|p| p.as_ref()),
        ))?;
    }
    Ok(())
}

/// One cascade stage: aggregate granularity `from`'s completed windows
/// into granularity `to` (`from + 1`). Wholesale recompute per coarse
/// window, cursor-guarded exactly like the raw pass.
pub fn roll_cascade(
    conn: &Connection,
    from: usize,
    now_ms: i64,
    grace_ms: i64,
) -> rusqlite::Result<usize> {
    debug_assert!(from + 1 < GRANULARITIES_MS.len());
    let coarse = GRANULARITIES_MS[from + 1];
    let frontier = window_of(now_ms.saturating_sub(grace_ms), coarse);
    let cur = cursor(conn, from + 1);
    if frontier <= cur {
        return Ok(0);
    }
    let tx = conn.unchecked_transaction()?;
    let n = cascade_range(&tx, from, cur, frontier)?;
    set_cursor_tx(&tx, from + 1, frontier)?;
    tx.commit()?;
    Ok(n)
}

/// Aggregate the finer table's `[lo, hi)` into the next coarser
/// granularity, wholesale. Every stored column merges by SUM (or MAX
/// for the max), which is exactly why the schema stores NON-cumulative
/// bucket counts and additive sums.
pub fn cascade_range(conn: &Connection, from: usize, lo: i64, hi: i64) -> rusqlite::Result<usize> {
    let coarse = GRANULARITIES_MS[from + 1];
    let before: i64 = conn.query_row(
        "SELECT COUNT(DISTINCT (window_start / ?3)) FROM rollup_fixed
         WHERE gran = ?1 AND window_start >= ?2 AND window_start < ?4",
        rusqlite::params![from as i64, lo, coarse, hi],
        |r| r.get(0),
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO rollup_fixed (
            gran, window_start, listener, route, upstream, consumer,
            method, status_class, requests, errors, rate_limited, shed,
            duration_sum_ms, duration_max_ms,
            b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12
        )
        SELECT ?4,
            (window_start / ?5) * ?5,
            listener, route, upstream, consumer, method, status_class,
            SUM(requests), SUM(errors), SUM(rate_limited), SUM(shed),
            SUM(duration_sum_ms), MAX(duration_max_ms),
            SUM(b0), SUM(b1), SUM(b2), SUM(b3), SUM(b4), SUM(b5),
            SUM(b6), SUM(b7), SUM(b8), SUM(b9), SUM(b10), SUM(b11),
            SUM(b12)
        FROM rollup_fixed
        WHERE gran = ?1 AND window_start >= ?2 AND window_start < ?3
        GROUP BY (window_start / ?5), listener, route, upstream,
                 consumer, method, status_class",
        rusqlite::params![from as i64, lo, hi, (from + 1) as i64, coarse],
    )?;
    // Custom dims cascade the same way (their schema is the additive
    // subset).
    conn.execute(
        "INSERT OR REPLACE INTO rollup_dim (
            gran, window_start, dim, value, requests, errors,
            duration_sum_ms, b0, b1, b2, b3, b4, b5, b6, b7, b8, b9,
            b10, b11, b12
        )
        SELECT ?4,
            (window_start / ?5) * ?5,
            dim, value,
            SUM(requests), SUM(errors), SUM(duration_sum_ms),
            SUM(b0), SUM(b1), SUM(b2), SUM(b3), SUM(b4), SUM(b5),
            SUM(b6), SUM(b7), SUM(b8), SUM(b9), SUM(b10), SUM(b11),
            SUM(b12)
        FROM rollup_dim
        WHERE gran = ?1 AND window_start >= ?2 AND window_start < ?3
        GROUP BY (window_start / ?5), dim, value",
        rusqlite::params![from as i64, lo, hi, (from + 1) as i64, coarse],
    )?;
    Ok(before as usize)
}

/// Retention sweep: delete expired rows per table and incrementally
/// vacuum up to `vacuum_pages` pages. Returns rows deleted.
pub fn sweep_retention(
    conn: &Connection,
    raw_keep_ms: i64,
    gran_keep_ms: [i64; 4],
    now_ms: i64,
    vacuum_pages: u32,
) -> rusqlite::Result<usize> {
    let mut deleted = 0usize;
    let tx = conn.unchecked_transaction()?;
    deleted += tx.execute(
        "DELETE FROM raw WHERE ts_ms < ?1",
        [now_ms.saturating_sub(raw_keep_ms)],
    )?;
    for (gran, keep) in gran_keep_ms.iter().enumerate() {
        let cutoff = now_ms.saturating_sub(*keep);
        deleted += tx.execute(
            "DELETE FROM rollup_fixed WHERE gran = ?1 AND window_start < ?2",
            rusqlite::params![gran as i64, cutoff],
        )?;
        deleted += tx.execute(
            "DELETE FROM rollup_dim WHERE gran = ?1 AND window_start < ?2",
            rusqlite::params![gran as i64, cutoff],
        )?;
    }
    tx.commit()?;
    // Vacuum outside the transaction (it is its own).
    let _ = conn.execute_batch(&format!("PRAGMA incremental_vacuum={vacuum_pages};"));
    Ok(deleted)
}
