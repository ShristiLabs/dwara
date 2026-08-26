//! Versioned, transactional SQLite schema migrations (DW-115).
//!
//! # Model
//!
//! All schema evolution is expressed as an ordered list of UP migrations
//! ([`migrations`]) applied by `rusqlite_migration`, which records progress
//! in `PRAGMA user_version` — the same pragma the DW-018 hand-rolled schema
//! used. A database at `user_version = 1` with the DW-018 tables IS
//! migration state 1: migration 001 below is that exact baseline DDL
//! (kept idempotent via `IF NOT EXISTS`), so a fresh database runs 001 to
//! reach state 1, while an existing DW-018 database already reports state 1
//! and 001 is correctly treated as applied.
//!
//! # Forward-only
//!
//! There are NO down migrations. Rolling a gateway binary back onto a
//! newer-schema data directory is refused (see
//! [`StateStore`][crate::state::store::StateStore] open: `user_version` greater
//! than the binary's latest is a hard error), and downgrading in place is
//! unsupported. The documented rebuild path, since schema v1 content is
//! entirely re-derivable:
//!
//! 1. Stop the gateway. Every migration takes a backup first — see
//!    "Backup before migrate" in [`crate::state::store`] — so locate the newest
//!    `<db>.bak-<version>-<timestamp>` file for the version you want.
//! 2. Replace the live db file with that backup (it is a consistent
//!    `VACUUM INTO` snapshot at the pre-migration version).
//! 3. Restart. Consumers and credentials are also re-seedable from
//!    config via [`sync_consumers_from_config`][crate::state::store::sync_consumers_from_config]
//!    if no backup exists, so the honest v1 answer is: restore the backup,
//!    or recreate the data dir and let config seeding repopulate it.
//!
//! # Adding a migration
//!
//! Append ONE `M::up` entry and bump [`LATEST_SCHEMA_VERSION`].
//! Migrations must be additive (create table/index, add column with a
//! default) so every historical version migrates forward with zero data
//! loss — tests here open a hand-built v1 database through every version
//! to HEAD. Never edit an existing migration: databases in the wild have
//! already recorded it.

use rusqlite_migration::{Migrations, M};

/// Latest schema version this build knows how to produce. Equals the
/// number of entries in [`migrations`]; asserted by test.
pub const LATEST_SCHEMA_VERSION: u32 = 2;

/// Migration 001: the DW-018 baseline schema, verbatim (idempotent).
///
/// Runs on fresh databases only: a database already at `user_version = 1`
/// (the DW-018 hand-rolled schema) is recognized as migration state 1 and
/// skips this entry.
const MIGRATION_001_BASELINE: &str = "
    CREATE TABLE IF NOT EXISTS consumers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        priority INTEGER,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        consumer_id INTEGER NOT NULL REFERENCES consumers(id),
        kind TEXT NOT NULL CHECK (kind IN ('api_key', 'jwt', 'mtls')),
        hash TEXT NOT NULL,
        salt TEXT,
        selector TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        revoked_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_credentials_selector
        ON credentials (selector);
    CREATE TABLE IF NOT EXISTS quota_counters (
        consumer_id INTEGER NOT NULL REFERENCES consumers(id),
        counter_key TEXT NOT NULL,
        window_start INTEGER NOT NULL,
        used INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (consumer_id, counter_key, window_start)
    );
";

/// Migration 002: index `quota_counters (window_start)`.
///
/// Additive (a CREATE INDEX over existing rows changes no data). The
/// retention prune in [`StateStore::incr_quota`][crate::state::store::StateStore::incr_quota]
/// runs `DELETE ... WHERE window_start < (SELECT MAX(window_start) ...)` on
/// every quota write; without an index on `window_start` that subquery and
/// delete scan the whole table, which grows with one row per (consumer,
/// key, window). Chosen over an `issued_at` column on credentials because
/// it removes a real per-write cost on the quota hot-ish path today,
/// whereas nothing yet consumes a credential issue timestamp (DW-019's
/// authenticator will decide that schema when it lands).
const MIGRATION_002_QUOTA_WINDOW_INDEX: &str =
    "CREATE INDEX IF NOT EXISTS idx_quota_counters_window ON quota_counters (window_start);";

/// The full forward migration set, in order. See the module docs for the
/// baseline recognition rule and the forward-only policy.
pub fn migrations() -> Migrations<'static> {
    Migrations::new(vec![
        M::up(MIGRATION_001_BASELINE),
        M::up(MIGRATION_002_QUOTA_WINDOW_INDEX),
    ])
}

/// Current vs latest schema version, for the admin surface (DW-022 will
/// expose this via the admin API; `current < latest` after open should be
/// impossible because [`StateStore::open`][crate::state::store::StateStore::open]
/// migrates automatically — the seam exists for reporting, not gating).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaInfo {
    /// `PRAGMA user_version` of the live database.
    pub current: u32,
    /// Highest version this build can migrate to ([`LATEST_SCHEMA_VERSION`]).
    pub latest: u32,
}
