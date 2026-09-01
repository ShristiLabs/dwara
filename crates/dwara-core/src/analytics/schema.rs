//! Analytics store schema (DW-043).
//!
//! The analytics database is a SEPARATE SQLite file from the state
//! store (DW-018): different lifecycle (retention deletes vs identity
//! upserts), different write pattern (high-churn batched appends vs
//! request-path point lookups), and an independent bounded-disk story
//! (incremental vacuum reclaims retention deletes here without ever
//! compacting the identity store). It owns its own `PRAGMA user_version`
//! namespace — a state-store database and an analytics database can
//! never be confused for one another, and the state store's
//! forward-only migration contract stays untouched by analytics churn.
//!
//! Schema v1 (this file is migration 001; v2 adds the DW-120
//! `export_runs` ledger — see [`SCHEMA_V2`]):
//!
//! - `meta` — rollup cursors (see [`super::rollup`]): the exclusive
//!   upper bound each granularity has durably rolled through, written
//!   in the SAME transaction as the rollup rows it covers, so a crash
//!   between rollups never double-counts a window.
//! - `raw` — one row per completed request, exactly the redacted
//!   [`AccessRecord`](crate::observability::AccessRecord) field set
//!   plus a JSON object of custom dimensions. Raw retention is SHORT
//!   (default 24 h): raw exists to seed rollups and answer
//!   custom-dimension ad hoc queries; the durable history is the
//!   rollup tables.
//! - `rollup_fixed` — pre-aggregated counters per (granularity,
//!   window, fixed dimension tuple). Latency lives as 13 fixed
//!   per-bucket counts ([`MS_BUCKETS`] bounds) so any set of windows
//!   merges by summation and percentiles are estimable without
//!   storing per-request samples.
//! - `rollup_dim` — the custom-dimension twin: one row per
//!   (granularity, window, dimension name, value), aggregated in Rust
//!   (the source is a JSON column; keeping the aggregation out of SQL
//!   avoids a JSON1 feature dependency in the bundled SQLite).

/// Latency bucket UPPER bounds in milliseconds (inclusive). A request
/// lands in exactly one bucket: the first bound it does not exceed,
/// else the overflow bucket (index 12). The bounds are the
/// observability histogram's shape at millisecond granularity —
/// sub-millisecond precision is noise at gateway scale, 10 s covers
/// every classified timeout. Counts are stored NON-cumulative
/// (per-bucket); cumulative form is computed at read time.
pub const MS_BUCKETS: [f64; 12] = [
    1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0,
];

/// Total stored bucket counts per rollup row: 12 bounded + overflow.
pub const BUCKET_COLS: usize = MS_BUCKETS.len() + 1;

/// Bucket index for one duration (the overflow bucket for anything
/// past the last bound).
pub fn bucket_of(duration_ms: f64) -> usize {
    MS_BUCKETS
        .iter()
        .position(|b| duration_ms <= *b)
        .unwrap_or(MS_BUCKETS.len())
}

/// Percentile estimate from non-cumulative bucket counts: the first
/// bound whose cumulative count reaches `p * total` (else the last
/// bound — everything past it is reported as 10 s, the honest ceiling).
pub fn percentile(buckets: &[i64], p: f64) -> f64 {
    let total: i64 = buckets.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let target = (p * total as f64).ceil() as i64;
    let mut cum = 0i64;
    for (i, b) in buckets.iter().enumerate() {
        cum += b;
        if cum >= target {
            return if i < MS_BUCKETS.len() {
                MS_BUCKETS[i]
            } else {
                // Overflow bucket: report the last bound as the floor.
                MS_BUCKETS[MS_BUCKETS.len() - 1]
            };
        }
    }
    MS_BUCKETS[MS_BUCKETS.len() - 1]
}

/// The full v1 DDL. Idempotent (`IF NOT EXISTS`) so a fresh database
/// and a re-run both land at version 1. Connection-level pragmas
/// (WAL, synchronous, auto_vacuum) are applied at open time — several
/// of them return rows and cannot live in an `execute_batch`.
pub const SCHEMA_V1: &str = "
    CREATE TABLE IF NOT EXISTS meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS raw (
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
        dims         TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX IF NOT EXISTS idx_raw_ts ON raw(ts_ms);

    CREATE TABLE IF NOT EXISTS rollup_fixed (
        gran           INTEGER NOT NULL,
        window_start   INTEGER NOT NULL,
        listener       TEXT NOT NULL,
        route          TEXT NOT NULL,
        upstream       TEXT NOT NULL,
        consumer       TEXT NOT NULL,
        method         TEXT NOT NULL,
        status_class   TEXT NOT NULL,
        requests       INTEGER NOT NULL,
        errors         INTEGER NOT NULL,
        rate_limited   INTEGER NOT NULL,
        shed           INTEGER NOT NULL,
        duration_sum_ms REAL NOT NULL,
        duration_max_ms REAL NOT NULL,
        b0  INTEGER NOT NULL, b1  INTEGER NOT NULL, b2  INTEGER NOT NULL,
        b3  INTEGER NOT NULL, b4  INTEGER NOT NULL, b5  INTEGER NOT NULL,
        b6  INTEGER NOT NULL, b7  INTEGER NOT NULL, b8  INTEGER NOT NULL,
        b9  INTEGER NOT NULL, b10 INTEGER NOT NULL, b11 INTEGER NOT NULL,
        b12 INTEGER NOT NULL,
        PRIMARY KEY (gran, window_start, listener, route, upstream,
                     consumer, method, status_class)
    ) WITHOUT ROWID;

    CREATE TABLE IF NOT EXISTS rollup_dim (
        gran            INTEGER NOT NULL,
        window_start    INTEGER NOT NULL,
        dim             TEXT NOT NULL,
        value           TEXT NOT NULL,
        requests        INTEGER NOT NULL,
        errors          INTEGER NOT NULL,
        duration_sum_ms REAL NOT NULL,
        b0  INTEGER NOT NULL, b1  INTEGER NOT NULL, b2  INTEGER NOT NULL,
        b3  INTEGER NOT NULL, b4  INTEGER NOT NULL, b5  INTEGER NOT NULL,
        b6  INTEGER NOT NULL, b7  INTEGER NOT NULL, b8  INTEGER NOT NULL,
        b9  INTEGER NOT NULL, b10 INTEGER NOT NULL, b11 INTEGER NOT NULL,
        b12 INTEGER NOT NULL,
        PRIMARY KEY (gran, window_start, dim, value)
    ) WITHOUT ROWID;
";

/// Schema v2 (DW-120): the `export_runs` ledger. One row per
/// scheduled-or-manual usage-statement export attempt per window
/// (primary key; a re-export REPLACES the row — the file output is
/// equally idempotent). `status` is `ok` or `failed`; `partial` flags
/// a window older than the query granularity's retention (undercounts
/// are possible) so billing consumers can reject flagged statements
/// instead of trusting them; `windows_nonempty` counts the range's
/// rollup windows that carry any data (informational — quiet windows
/// have no rows and are not loss).
pub const SCHEMA_V2: &str = "
    CREATE TABLE IF NOT EXISTS export_runs (
        kind             TEXT NOT NULL,
        window_start_ms  INTEGER NOT NULL,
        window_end_ms    INTEGER NOT NULL,
        status           TEXT NOT NULL,
        partial          INTEGER NOT NULL,
        formats          TEXT NOT NULL,
        directory        TEXT NOT NULL,
        consumers        INTEGER NOT NULL,
        requests         INTEGER NOT NULL,
        windows_nonempty INTEGER NOT NULL,
        error            TEXT NOT NULL DEFAULT '',
        generated_at_ms  INTEGER NOT NULL,
        PRIMARY KEY (kind, window_start_ms)
    ) WITHOUT ROWID;
";

/// Schema v3 (DW-079): the `ai_spend` table. One row per completed AI
/// request carrying the provider-reported token usage and the priced
/// cost (micro-USD), attributed to the consumer/team/model/provider
/// that served it. The spend query surface
/// ([`super::query::spend_summary`]) aggregates these rows per
/// consumer/team/model for billing reconciliation; the export
/// statement (DW-120) folds the per-consumer totals into its rows.
pub const SCHEMA_V3: &str = "
    CREATE TABLE IF NOT EXISTS ai_spend (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        ts_ms             INTEGER NOT NULL,
        consumer          TEXT NOT NULL,
        team              TEXT NOT NULL DEFAULT '',
        provider          TEXT NOT NULL,
        model             TEXT NOT NULL,
        version           TEXT NOT NULL DEFAULT '',
        prompt_tokens     INTEGER NOT NULL,
        completion_tokens INTEGER NOT NULL,
        total_tokens      INTEGER NOT NULL,
        cost_micros       INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_ai_spend_ts ON ai_spend(ts_ms);
    CREATE INDEX IF NOT EXISTS idx_ai_spend_consumer ON ai_spend(consumer);
    CREATE INDEX IF NOT EXISTS idx_ai_spend_model ON ai_spend(model);
";

/// Schema v4 (DW-084): the `ai_governance_events` table. One row per
/// governance check outcome (allow or deny) when the audit switch is
/// on, plus every DENIAL even when the audit switch is off (the
/// done-when requirement: a blocked attempt appears in the audit
/// log). The admin `/analytics/governance-audit` endpoint reads these
/// rows for shadow review.
pub const SCHEMA_V4: &str = "
    CREATE TABLE IF NOT EXISTS ai_governance_events (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts_ms       INTEGER NOT NULL,
        consumer    TEXT NOT NULL,
        team        TEXT NOT NULL DEFAULT '',
        model       TEXT NOT NULL,
        verdict     TEXT NOT NULL,
        reason      TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_ai_governance_ts ON ai_governance_events(ts_ms);
    CREATE INDEX IF NOT EXISTS idx_ai_governance_consumer ON ai_governance_events(consumer);
";

/// Latest analytics schema version this build knows.
pub const LATEST_SCHEMA_VERSION: u32 = 4;

/// Apply migrations to a fresh-or-existing analytics connection. A
/// database at a NEWER version than this build is a hard error (the
/// state store's forward-only rule, same rationale).
pub fn migrate(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    let version: u32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version > LATEST_SCHEMA_VERSION {
        return Err(rusqlite::Error::ToSqlConversionFailure(Box::new(
            std::io::Error::other(format!(
                "analytics database schema version {version} is newer than this \
                 build's {LATEST_SCHEMA_VERSION}; forward-only: upgrade the binary"
            )),
        )));
    }
    // Forward-only sequential migrations: each version's batch is
    // idempotent (IF NOT EXISTS) so a crash between batches re-runs
    // safely on the next open.
    if version < 1 {
        conn.execute_batch(SCHEMA_V1)?;
        conn.pragma_update(None, "user_version", 1)?;
    }
    if version < 2 {
        conn.execute_batch(SCHEMA_V2)?;
        conn.pragma_update(None, "user_version", 2)?;
    }
    if version < 3 {
        conn.execute_batch(SCHEMA_V3)?;
        conn.pragma_update(None, "user_version", 3)?;
    }
    if version < 4 {
        conn.execute_batch(SCHEMA_V4)?;
        conn.pragma_update(None, "user_version", 4)?;
    }
    Ok(())
}
