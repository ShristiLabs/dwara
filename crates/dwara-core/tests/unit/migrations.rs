//! Unit tests for `state::migrations` (relocated from src).

use dwara_core::state::migrations::*;
use rusqlite_migration::{Migrations, M};

#[test]
fn latest_version_constant_matches_migration_count() {
    // Migrations applies versions 1..=len; the const must agree.
    let mut conn = rusqlite::Connection::open_in_memory().unwrap();
    migrations().to_latest(&mut conn).unwrap();
    let v: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, i64::from(LATEST_SCHEMA_VERSION));
}

#[test]
fn migration_failure_rolls_back_and_keeps_old_version() {
    // Transactionality proof: a migration whose SECOND statement fails
    // must leave no partial work behind and must not bump user_version.
    // rusqlite_migration runs the whole pending set in one transaction,
    // so even the SUCCESSFUL earlier migration rolls back with it and
    // the database stays at its pre-migration version.
    let bad = Migrations::new(vec![
        M::up("CREATE TABLE tx_probe (id INTEGER PRIMARY KEY);"),
        M::up(
            "CREATE TABLE tx_probe2 (id INTEGER PRIMARY KEY);
                 INSERT INTO no_such_table VALUES (1);",
        ),
    ]);
    let mut conn = rusqlite::Connection::open_in_memory().unwrap();
    let err = bad.to_latest(&mut conn).unwrap_err();
    assert!(err.to_string().contains("no_such_table"), "got: {err}");
    let v: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, 0, "version must stay at the pre-migration value");
    // Partial work from the failed migration rolled back entirely.
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'tx_probe2'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    // The earlier SUCCESSFUL migration rolled back with the same
    // transaction: nothing from this run persisted.
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'tx_probe'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn migrations_are_forward_only() {
    // No down migration exists: asking to go back below the current
    // version must be refused (rusqlite_migration reports the
    // migration "cannot be reverted"), which is the forward-only
    // policy made executable.
    let mut conn = rusqlite::Connection::open_in_memory().unwrap();
    let m = migrations();
    m.to_latest(&mut conn).unwrap();
    let err = m.to_version(&mut conn, 1).unwrap_err();
    assert!(
        err.to_string()
            .to_lowercase()
            .contains("cannot be reverted"),
        "expected cannot-be-reverted error, got: {err}"
    );
    let v: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, i64::from(LATEST_SCHEMA_VERSION));
}
