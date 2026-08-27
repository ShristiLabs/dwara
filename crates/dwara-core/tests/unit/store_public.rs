//! Public-API unit tests for `state::store` (relocated from src; the
//! seven white-box tests that reach into `store.conn`, `now_secs`,
//! `QUOTA_RETENTION_SECS`, or `backup_file_name` remain in src).

use std::path::Path;
use std::sync::Arc;

use rusqlite::Connection;

use dwara_core::config::parse_gateway;
use dwara_core::state::migrations::{SchemaInfo, LATEST_SCHEMA_VERSION};
use dwara_core::state::store::*;

fn seeded_store() -> StateStore {
    let store = StateStore::open_in_memory().unwrap();
    store.upsert_consumer("acme", Some(7), &[]).unwrap();
    store
}

#[test]
fn consumer_roundtrip_in_memory_and_on_disk() {
    let store = StateStore::open_in_memory().unwrap();
    let a = store.upsert_consumer("acme", Some(7), &[]).unwrap();
    assert_eq!(a.name, "acme");
    assert_eq!(a.priority, Some(7));
    let listed = store.list_consumers().unwrap();
    assert_eq!(listed, vec![a.clone()]);

    let dir = tempfile::tempdir().unwrap();
    let disk = StateStore::open(&dir.path().join("state.db")).unwrap();
    let b = disk.upsert_consumer("acme", None, &[]).unwrap();
    assert_eq!(b.name, "acme");
    // Reopen the same file: the row persisted, schema not recreated.
    let disk2 = StateStore::open(&dir.path().join("state.db")).unwrap();
    assert_eq!(disk2.list_consumers().unwrap(), vec![b]);
}

#[test]
fn consumer_name_is_unique_via_upsert() {
    let store = StateStore::open_in_memory().unwrap();
    store.upsert_consumer("acme", None, &[]).unwrap();
    store.upsert_consumer("acme", Some(9), &[]).unwrap();
    let listed = store.list_consumers().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].priority, Some(9));
}

#[test]
fn credential_requires_existing_consumer() {
    let store = StateStore::open_in_memory().unwrap();
    let err = store
        .add_credential(999, CredentialKind::ApiKey, "h".into(), None, "sel".into())
        .unwrap_err();
    assert!(matches!(err, StoreError::UnknownConsumer(_)));
}

#[test]
fn credential_roundtrip_and_revocation() {
    let store = seeded_store();
    let consumer = store.lookup_consumer("acme").unwrap().unwrap();
    let cred = store
        .add_credential(
            consumer.id,
            CredentialKind::ApiKey,
            "hashed".into(),
            Some("salt".into()),
            "key-1".into(),
        )
        .unwrap();
    let found = store.lookup_credentials_by_selector("key-1").unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, cred.id);
    assert_eq!(found[0].consumer_name, "acme");
    assert_eq!(found[0].kind, CredentialKind::ApiKey);
    assert_eq!(found[0].salt.as_deref(), Some("salt"));

    assert!(store.revoke_credential(cred.id).unwrap());
    assert!(!store.revoke_credential(cred.id).unwrap()); // idempotent
    assert!(store
        .lookup_credentials_by_selector("key-1")
        .unwrap()
        .is_empty());
}

#[test]
fn quota_within_limit_and_refusal_writes_nothing() {
    let store = seeded_store();
    let consumer = store.lookup_consumer("acme").unwrap().unwrap();
    assert_eq!(
        store
            .incr_quota(consumer.id, "rpm", 1000, 5, Some(10))
            .unwrap(),
        5
    );
    assert_eq!(
        store
            .incr_quota(consumer.id, "rpm", 1000, 5, Some(10))
            .unwrap(),
        10
    );
    let err = store
        .incr_quota(consumer.id, "rpm", 1000, 1, Some(10))
        .unwrap_err();
    assert!(matches!(
        err,
        StoreError::QuotaExceeded {
            used: 10,
            limit: 10,
            requested: 1
        }
    ));
    // Refusal did not write.
    assert_eq!(store.get_quota(consumer.id, "rpm", 1000).unwrap(), 10);
}

#[test]
fn quota_window_rollover_is_a_new_counter() {
    let store = seeded_store();
    let consumer = store.lookup_consumer("acme").unwrap().unwrap();
    store.incr_quota(consumer.id, "rpm", 1000, 7, None).unwrap();
    // Next window: independent counter starting from zero.
    assert_eq!(store.get_quota(consumer.id, "rpm", 2000).unwrap(), 0);
    assert_eq!(
        store.incr_quota(consumer.id, "rpm", 2000, 1, None).unwrap(),
        1
    );
    assert_eq!(store.get_quota(consumer.id, "rpm", 1000).unwrap(), 7);
}

#[test]
fn hot_path_is_disk_free_after_warmup() {
    let store = seeded_store();
    let consumer = store.lookup_consumer("acme").unwrap().unwrap();
    store
        .add_credential(
            consumer.id,
            CredentialKind::ApiKey,
            "h".into(),
            None,
            "key-1".into(),
        )
        .unwrap();
    store.lookup_credential("key-1").unwrap(); // warmup (1 disk read)
    let reads_after_warmup = store.disk_reads();
    for _ in 0..100 {
        let entry = store.lookup_credential("key-1").unwrap().unwrap();
        assert_eq!(entry.len(), 1);
        assert_eq!(entry[0].hash, "h");
    }
    assert_eq!(store.disk_reads(), reads_after_warmup);
    assert!(store.cache_hits() >= 100);
    // Negative caching: unknown selectors also stop touching disk.
    store.lookup_credential("nope").unwrap();
    let after_negative = store.disk_reads();
    for _ in 0..50 {
        assert!(store.lookup_credential("nope").unwrap().unwrap().is_empty());
    }
    assert_eq!(store.disk_reads(), after_negative);
}

#[test]
fn writes_through_the_handle_invalidate_the_cache() {
    let store = seeded_store();
    let consumer = store.lookup_consumer("acme").unwrap().unwrap();
    store
        .add_credential(
            consumer.id,
            CredentialKind::ApiKey,
            "h1".into(),
            None,
            "key-1".into(),
        )
        .unwrap();
    assert_eq!(store.lookup_credential("key-1").unwrap().unwrap().len(), 1);
    store
        .add_credential(
            consumer.id,
            CredentialKind::ApiKey,
            "h2".into(),
            None,
            "key-1".into(),
        )
        .unwrap();
    // add_credential invalidated: exactly one disk read, then fresh state.
    let before = store.disk_reads();
    let entry = store.lookup_credential("key-1").unwrap().unwrap();
    assert_eq!(store.disk_reads(), before + 1);
    assert_eq!(entry.len(), 2);
    // Revoke also invalidates.
    store.revoke_credential(entry[0].id).unwrap();
    assert_eq!(store.lookup_credential("key-1").unwrap().unwrap().len(), 1);
}

#[test]
fn invalidate_all_forces_one_disk_read_per_selector() {
    let store = seeded_store();
    let consumer = store.lookup_consumer("acme").unwrap().unwrap();
    store
        .add_credential(
            consumer.id,
            CredentialKind::ApiKey,
            "h".into(),
            None,
            "k".into(),
        )
        .unwrap();
    store.lookup_credential("k").unwrap();
    store.invalidate_all();
    let before = store.disk_reads();
    store.lookup_credential("k").unwrap();
    assert_eq!(store.disk_reads(), before + 1);
}

#[tokio::test]
async fn concurrent_lookups_share_the_cache() {
    let store = Arc::new(seeded_store());
    let consumer = store.lookup_consumer("acme").unwrap().unwrap();
    store
        .add_credential(
            consumer.id,
            CredentialKind::ApiKey,
            "h".into(),
            None,
            "k".into(),
        )
        .unwrap();
    store.lookup_credential("k").unwrap(); // warmup
    let reads_at_start = store.disk_reads();
    let mut handles = Vec::new();
    for _ in 0..32 {
        let store = Arc::clone(&store);
        handles.push(tokio::task::spawn_blocking(move || {
            for _ in 0..50 {
                assert_eq!(store.lookup_credential("k").unwrap().unwrap().len(), 1);
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    assert_eq!(store.disk_reads(), reads_at_start);
}

#[test]
fn seeding_from_config_is_idempotent_and_hashed() {
    let config = parse_gateway(
        "consumers:\n  - name: acme\n    priority: 3\n    credentials:\n      - \
         type: api_key\n        key: secret-key\n      - type: jwt\n        issuer: \
         https://issuer.example\n      - type: mtls\n        fingerprint: AA:BB\n",
    )
    .unwrap();
    let store = StateStore::open_in_memory().unwrap();
    sync_consumers_from_config(&store, &config, None).unwrap();
    sync_consumers_from_config(&store, &config, None).unwrap(); // re-sync: no dupes
    let listed = store.list_consumers().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].priority, Some(3));
    // DW-019: the selector is the sha256 of the key (never the
    // plaintext), and the stored hash is the format the
    // authenticator's constant-time verifier expects.
    let selector = dwara_core::config::credentials::credential_selector("secret-key");
    let api = store.lookup_credentials_by_selector(&selector).unwrap();
    assert_eq!(api.len(), 1);
    assert_eq!(api[0].kind, CredentialKind::ApiKey);
    assert_eq!(
        api[0].hash,
        dwara_core::config::credentials::sha256_stored_hash("secret-key")
    );
    // Nothing in the store contains the plaintext key.
    let dumped = format!("{:?}{}", api[0].hash, selector);
    assert!(!dumped.contains("secret-key"));
    assert_eq!(
        store
            .lookup_credentials_by_selector("https://issuer.example")
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store.lookup_credentials_by_selector("AA:BB").unwrap().len(),
        1
    );
}

#[test]
fn revoke_by_source_retires_only_the_linked_rows_of_that_consumer() {
    // The #46 skip-path linkage: `credentials.source_ref` (schema v4)
    // scopes revocation to exactly the rows ONE consumer's config
    // reference seeded. Rows of another consumer (even from the same
    // reference text — each consumer's config slot governs its own
    // row), rows without the linkage (inline keys, operator rows,
    // pre-v4 rows), and other kinds are untouched, keeping the
    // documented upsert-only posture.
    let store = StateStore::open_in_memory().unwrap();
    let acme = store.upsert_consumer("acme", None, &[]).unwrap();
    let globex = store.upsert_consumer("globex", None, &[]).unwrap();
    let reference = "${file:/run/dwara/acme.key}";
    store
        .add_credential_from_reference(
            acme.id,
            CredentialKind::ApiKey,
            "sha256:h1".into(),
            "sel-rotated-out".into(),
            reference,
        )
        .unwrap();
    store
        .add_credential_from_reference(
            acme.id,
            CredentialKind::ApiKey,
            "sha256:h2".into(),
            "sel-live".into(),
            reference,
        )
        .unwrap();
    // Same reference text, DIFFERENT consumer: not this slot's row.
    store
        .add_credential_from_reference(
            globex.id,
            CredentialKind::ApiKey,
            "sha256:h3".into(),
            "sel-globex".into(),
            reference,
        )
        .unwrap();
    // No linkage: an inline-key row of the same consumer+kind.
    store
        .add_credential(
            acme.id,
            CredentialKind::ApiKey,
            "sha256:h4".into(),
            None,
            "sel-inline".into(),
        )
        .unwrap();

    let revoked = store
        .revoke_credentials_by_source(acme.id, CredentialKind::ApiKey, reference)
        .unwrap();
    assert_eq!(revoked, 2, "both rows the reference seeded are retired");
    assert!(store
        .lookup_credentials_by_selector("sel-rotated-out")
        .unwrap()
        .is_empty());
    assert!(
        store
            .lookup_credentials_by_selector("sel-live")
            .unwrap()
            .is_empty(),
        "acme's linked live row is retired"
    );
    assert_eq!(
        store
            .lookup_credentials_by_selector("sel-globex")
            .unwrap()
            .len(),
        1,
        "globex's row from the same reference text survives"
    );
    assert_eq!(
        store
            .lookup_credentials_by_selector("sel-inline")
            .unwrap()
            .len(),
        1,
        "unlinked rows keep the upsert-only posture"
    );
    // No linkage to find: 0 revoked, not an error.
    assert_eq!(
        store
            .revoke_credentials_by_source(acme.id, CredentialKind::ApiKey, "${file:/never/seeded}")
            .unwrap(),
        0
    );
}

#[test]
fn sync_deletes_legacy_config_placeholder_api_key_rows() {
    // Legacy-cleanup rule: a pre-DW-019 build seeded api_key rows with
    // a PLAINTEXT selector and a `config:api_key:<key>` placeholder
    // hash. Sync must delete them (the sha256 seeding never matches
    // them, so without the cleanup they persist forever), while
    // leaving current binding rows (`config:jwt:`/`config:mtls:`) and
    // properly hashed api_key rows untouched.
    let config = parse_gateway(
        "consumers:\n  - name: acme\n    credentials:\n      - type: api_key\n        \
         key: secret-key\n      - type: jwt\n        issuer: https://issuer.example\n",
    )
    .unwrap();
    let store = StateStore::open_in_memory().unwrap();
    // Seed exactly as the pre-DW-019 build did: plaintext selector and
    // placeholder hash (api key), plus a legacy jwt binding row.
    store.upsert_consumer("acme", None, &[]).unwrap();
    let consumer = store.lookup_consumer("acme").unwrap().unwrap();
    store
        .add_credential(
            consumer.id,
            CredentialKind::ApiKey,
            "config:api_key:secret-key".into(),
            None,
            "secret-key".into(),
        )
        .unwrap();
    store
        .add_credential(
            consumer.id,
            CredentialKind::Jwt,
            "config:jwt:https://issuer.example".into(),
            None,
            "https://issuer.example".into(),
        )
        .unwrap();
    // A revoked legacy row is deleted too (the secret must not linger
    // behind a revocation timestamp).
    let revoked = store
        .add_credential(
            consumer.id,
            CredentialKind::ApiKey,
            "config:api_key:old-key".into(),
            None,
            "old-key".into(),
        )
        .unwrap();
    store.revoke_credential(revoked.id).unwrap();

    sync_consumers_from_config(&store, &config, None).unwrap();

    // The plaintext legacy api_key rows are gone...
    assert!(store
        .lookup_credentials_by_selector("secret-key")
        .unwrap()
        .is_empty());
    assert!(store
        .lookup_credentials_by_selector("old-key")
        .unwrap()
        .is_empty());
    // ...the properly re-seeded sha256 api_key row exists...
    let selector = dwara_core::config::credentials::credential_selector("secret-key");
    let api = store.lookup_credentials_by_selector(&selector).unwrap();
    assert_eq!(api.len(), 1);
    assert_eq!(
        api[0].hash,
        dwara_core::config::credentials::sha256_stored_hash("secret-key")
    );
    // ...and the jwt binding row (current format) survives.
    assert_eq!(
        store
            .lookup_credentials_by_selector("https://issuer.example")
            .unwrap()
            .len(),
        1
    );
    // A second sync is a clean no-op cleanup (0 deleted) and still
    // idempotent overall.
    assert_eq!(
        store
            .delete_legacy_config_placeholder_credentials()
            .unwrap(),
        0
    );
}

#[cfg(unix)]
#[test]
fn db_file_is_owner_only_on_unix() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    StateStore::open(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    // Reopen (existing file) leaves it tightened.
    StateStore::open(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn upsert_preserves_created_across_cache_and_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    let store = StateStore::open(&path).unwrap();
    let a = store.upsert_consumer("acme", Some(1), &[]).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let b = store.upsert_consumer("acme", Some(2), &[]).unwrap();
    // Returned record keeps the original creation time.
    assert_eq!(a.created_at, b.created_at);
    assert_eq!(b.priority, Some(2));
    // Cache agrees with disk.
    let cached = store.lookup_consumer("acme").unwrap().unwrap();
    assert_eq!(*cached, b);
    // A fresh handle (cold cache) reads the same row from disk.
    let disk = StateStore::open(&path).unwrap();
    assert_eq!(disk.list_consumers().unwrap(), vec![b]);
}

#[test]
fn quota_for_unknown_consumer_is_typed_error() {
    let store = StateStore::open_in_memory().unwrap();
    let err = store.incr_quota(999, "rpm", 1000, 1, None).unwrap_err();
    assert!(matches!(err, StoreError::UnknownConsumer(_)));
}

#[test]
fn credential_debug_redacts_secrets() {
    let store = seeded_store();
    let consumer = store.lookup_consumer("acme").unwrap().unwrap();
    let cred = store
        .add_credential(
            consumer.id,
            CredentialKind::ApiKey,
            "hash-value-xyz".into(),
            Some("salt-value-abc".into()),
            "selector-value-123".into(),
        )
        .unwrap();
    let debug = format!("{cred:?}");
    assert!(!debug.contains("hash-value-xyz"));
    assert!(!debug.contains("salt-value-abc"));
    assert!(!debug.contains("selector-value-123"));
    // Safe fields remain visible.
    assert!(debug.contains("acme"));
    assert!(debug.contains("ApiKey"));
}

#[test]
fn fresh_db_reaches_latest_version() {
    let dir = tempfile::tempdir().unwrap();
    let store = StateStore::open(&dir.path().join("state.db")).unwrap();
    assert_eq!(store.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    let info = store.schema_info().unwrap();
    assert_eq!(info.current, LATEST_SCHEMA_VERSION);
    assert_eq!(info.latest, LATEST_SCHEMA_VERSION);
    assert_eq!(
        info,
        SchemaInfo {
            current: LATEST_SCHEMA_VERSION,
            latest: LATEST_SCHEMA_VERSION
        }
    );
    // Fresh open on a FRESH file: nothing to migrate, so no backup.
    let mut found = std::fs::read_dir(dir.path()).unwrap().filter_map(|e| {
        let name = e.unwrap().file_name().to_string_lossy().into_owned();
        name.contains(".bak-").then_some(name)
    });
    assert!(
        found.next().is_none(),
        "fresh open must not create a backup"
    );
}

/// Build a database exactly as DW-018 did: the hand-rolled v1 DDL,
/// `PRAGMA user_version = 1`, and rows in every table (including
/// quota data). This is the "v1 gateway data dir" fixture for the
/// migration tests below.
fn build_v1_db(path: &Path) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "BEGIN;
             CREATE TABLE consumers (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT NOT NULL UNIQUE,
                 priority INTEGER,
                 created_at INTEGER NOT NULL
             );
             CREATE TABLE credentials (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 consumer_id INTEGER NOT NULL REFERENCES consumers(id),
                 kind TEXT NOT NULL CHECK (kind IN ('api_key', 'jwt', 'mtls')),
                 hash TEXT NOT NULL,
                 salt TEXT,
                 selector TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 revoked_at INTEGER
             );
             CREATE INDEX idx_credentials_selector ON credentials (selector);
             CREATE TABLE quota_counters (
                 consumer_id INTEGER NOT NULL REFERENCES consumers(id),
                 counter_key TEXT NOT NULL,
                 window_start INTEGER NOT NULL,
                 used INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (consumer_id, counter_key, window_start)
             );
             INSERT INTO consumers (name, priority, created_at) VALUES ('acme', 5, 1000);
             INSERT INTO credentials
                 (consumer_id, kind, hash, salt, selector, created_at, revoked_at)
             VALUES (1, 'api_key', 'h1', NULL, 'key-1', 1001, NULL);
             INSERT INTO credentials
                 (consumer_id, kind, hash, salt, selector, created_at, revoked_at)
             VALUES (1, 'jwt', 'h2', 's2', 'key-2', 1002, 5555);
             INSERT INTO quota_counters (consumer_id, counter_key, window_start, used)
             VALUES (1, 'rpm', 3600, 42);
             PRAGMA user_version = 1;
             COMMIT;",
    )
    .unwrap();
}

#[test]
fn migrating_a_v1_db_takes_a_backup_with_pre_migration_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    build_v1_db(&path);
    StateStore::open(&path).unwrap();

    // Exactly one backup, named for the version migrated FROM.
    let backups: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| {
            let name = e.unwrap().file_name().to_string_lossy().into_owned();
            name.starts_with("state.db.bak-1-").then_some(name)
        })
        .collect();
    assert_eq!(backups.len(), 1, "backups: {backups:?}");

    // The backup is the PRE-migration database: v1 schema, same rows,
    // and no 002 index (that is what migration added).
    let backup = Connection::open(dir.path().join(&backups[0])).unwrap();
    let v: i64 = backup
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, 1);
    let used: i64 = backup
        .query_row(
            "SELECT used FROM quota_counters WHERE consumer_id = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(used, 42);
    let index: i64 = backup
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'idx_quota_counters_window'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(index, 0);
}

#[cfg(unix)]
#[test]
fn backup_failure_aborts_open_without_migrating() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    build_v1_db(&path);
    // Make the directory unwritable so no file can be created — the
    // backup (and, depending on order, the WAL sidecar) cannot be
    // written. Open must REFUSE rather than migrate unbacked.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    let err = StateStore::open(&path).unwrap_err();
    assert!(matches!(err, StoreError::Sqlite(_)));
    // Restore writability (tempdir cleanup needs it) and verify the
    // failed backup left NO partial .bak behind (a truncated snapshot
    // is silent-corruption bait for a restore).
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        all_backups(dir.path()).is_empty(),
        "failed backup must not leave a partial .bak file"
    );
    // and verify the
    // database was left at v1, untouched by the aborted open.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let conn = Connection::open(&path).unwrap();
    let v: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, 1, "aborted open must not migrate");
    let index: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'idx_quota_counters_window'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(index, 0);
}

#[test]
fn reopening_a_current_db_migrates_nothing_and_backs_up_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    StateStore::open(&path).unwrap();
    StateStore::open(&path).unwrap(); // reopen: already latest
    let backups = std::fs::read_dir(dir.path()).unwrap().filter(|e| {
        e.as_ref()
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".bak-")
    });
    assert_eq!(backups.count(), 0);
}

#[test]
fn db_newer_than_this_build_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    build_v1_db(&path);
    {
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", LATEST_SCHEMA_VERSION + 1)
            .unwrap();
    }
    let err = StateStore::open(&path).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("newer than this build"),
        "unexpected error: {msg}"
    );
    // user_version untouched by the refusal.
    let conn = Connection::open(&path).unwrap();
    let v: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, LATEST_SCHEMA_VERSION as i64 + 1);
}

// ---- tester coverage for DW-115 (chain, backup integrity, deep
// fidelity, rapid reopen, foreign version-0 databases, pragmas) ----

/// Dump every row of `table` as formatted text, row order pinned by
/// rowid, so pre/post/backup databases can be compared column for
/// column ("byte-identical" at the value level).
fn dump_table(conn: &Connection, table: &str) -> Vec<Vec<String>> {
    let mut stmt = conn
        .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
        .unwrap();
    let cols = stmt.column_count();
    let mut rows = stmt.query([]).unwrap();
    let mut out = Vec::new();
    while let Some(row) = rows.next().unwrap() {
        let mut cells = Vec::with_capacity(cols);
        for i in 0..cols {
            let cell = match row.get_ref(i).unwrap() {
                rusqlite::types::ValueRef::Null => "NULL".to_string(),
                rusqlite::types::ValueRef::Integer(v) => v.to_string(),
                rusqlite::types::ValueRef::Real(v) => v.to_string(),
                rusqlite::types::ValueRef::Text(v) => {
                    format!("'{}'", String::from_utf8_lossy(v))
                }
                rusqlite::types::ValueRef::Blob(v) => format!("{v:?}"),
            };
            cells.push(cell);
        }
        out.push(cells);
    }
    out
}

/// Richer v1 fixture than [`build_v1_db`]: 2 consumers, 3 credentials
/// (one revoked), and 5 quota rows spanning consumers, keys, and
/// windows. Returns nothing; callers compare state before/after.
fn build_v1_db_rich(path: &Path) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "BEGIN;
             CREATE TABLE consumers (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT NOT NULL UNIQUE,
                 priority INTEGER,
                 created_at INTEGER NOT NULL
             );
             CREATE TABLE credentials (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 consumer_id INTEGER NOT NULL REFERENCES consumers(id),
                 kind TEXT NOT NULL CHECK (kind IN ('api_key', 'jwt', 'mtls')),
                 hash TEXT NOT NULL,
                 salt TEXT,
                 selector TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 revoked_at INTEGER
             );
             CREATE INDEX idx_credentials_selector ON credentials (selector);
             CREATE TABLE quota_counters (
                 consumer_id INTEGER NOT NULL REFERENCES consumers(id),
                 counter_key TEXT NOT NULL,
                 window_start INTEGER NOT NULL,
                 used INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (consumer_id, counter_key, window_start)
             );
             INSERT INTO consumers (name, priority, created_at) VALUES ('acme', 5, 1000);
             INSERT INTO consumers (name, priority, created_at) VALUES ('globex', NULL, 1001);
             INSERT INTO credentials
                 (consumer_id, kind, hash, salt, selector, created_at, revoked_at)
             VALUES (1, 'api_key', 'h1', NULL, 'key-1', 1001, NULL);
             INSERT INTO credentials
                 (consumer_id, kind, hash, salt, selector, created_at, revoked_at)
             VALUES (1, 'jwt', 'h2', 's2', 'key-2', 1002, 5555);
             INSERT INTO credentials
                 (consumer_id, kind, hash, salt, selector, created_at, revoked_at)
             VALUES (2, 'mtls', 'h3', 's3', 'key-3', 1003, NULL);
             INSERT INTO quota_counters (consumer_id, counter_key, window_start, used)
             VALUES (1, 'rpm', 3600, 42);
             INSERT INTO quota_counters (consumer_id, counter_key, window_start, used)
             VALUES (1, 'rpm', 7200, 7);
             INSERT INTO quota_counters (consumer_id, counter_key, window_start, used)
             VALUES (1, 'rpd', 86400, 900);
             INSERT INTO quota_counters (consumer_id, counter_key, window_start, used)
             VALUES (2, 'rpm', 3600, 1);
             INSERT INTO quota_counters (consumer_id, counter_key, window_start, used)
             VALUES (2, 'monthly', 2678400, 123456);
             PRAGMA user_version = 1;
             COMMIT;",
    )
    .unwrap();
}

fn all_backups(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| {
            let name = e.unwrap().file_name().to_string_lossy().into_owned();
            name.contains(".bak-").then_some(name)
        })
        .collect()
}

#[test]
fn v1_upgrade_chain_reopens_at_latest_without_rebacking_up() {
    // CHAIN: v1 -> (open) latest -> (reopen) no-op. Backups accumulate
    // one per ACTUAL migration event: the v1->latest open takes one,
    // the already-latest reopen takes none, forever.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    build_v1_db(&path);

    let first = StateStore::open(&path).unwrap();
    assert_eq!(first.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    drop(first);
    assert_eq!(
        all_backups(dir.path()).len(),
        1,
        "the v1->latest open takes exactly one backup"
    );

    let second = StateStore::open(&path).unwrap();
    assert_eq!(second.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    drop(second);
    let third = StateStore::open(&path).unwrap();
    assert_eq!(third.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    assert_eq!(
        all_backups(dir.path()).len(),
        1,
        "reopens at latest must not add backups"
    );
    // Data survived the whole chain.
    assert_eq!(third.get_quota(1, "rpm", 3600).unwrap(), 42);
}

#[test]
fn backup_file_is_a_valid_pre_migration_v1_database() {
    // BACKUP INTEGRITY: the .bak left by upgrading a rich v1 database
    // is, opened with a raw connection, exactly the pre-migration
    // database: user_version 1, all rows byte-identical at the value
    // level, and the 002 index absent. (It cannot be opened through
    // StateStore for this check because open auto-migrates.)
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    build_v1_db_rich(&path);
    let before = {
        let conn = Connection::open(&path).unwrap();
        (
            dump_table(&conn, "consumers"),
            dump_table(&conn, "credentials"),
            dump_table(&conn, "quota_counters"),
        )
    };
    StateStore::open(&path).unwrap();

    let backups = all_backups(dir.path());
    assert_eq!(backups.len(), 1, "backups: {backups:?}");
    assert!(
        backups[0].starts_with("state.db.bak-1-"),
        "backup name records the version migrated FROM: {}",
        backups[0]
    );
    let bak = Connection::open(dir.path().join(&backups[0])).unwrap();
    let v: i64 = bak
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, 1, "backup must be the v1 pre-migration snapshot");
    let index: i64 = bak
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'idx_quota_counters_window'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(index, 0, "backup must predate the 002 index");
    assert_eq!(dump_table(&bak, "consumers"), before.0);
    assert_eq!(dump_table(&bak, "credentials"), before.1);
    assert_eq!(dump_table(&bak, "quota_counters"), before.2);
    // And the backup's index-free schema still queries (usable file).
    let used: i64 = bak
        .query_row(
            "SELECT used FROM quota_counters WHERE consumer_id = 2 AND counter_key = 'monthly'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(used, 123456);
}
