//! Integration tests for the SQLite state store + hot cache (DW-018).
//!
//! Covers reopen persistence, quota edges and races, negative-cache
//! coherence, selector multi-credentials, seeding drift, corruption/error
//! paths, and warm-cache behavior at volume — the durability and
//! transactional-integrity surface that unit tests in `src/store.rs`
//! (which are largely in-memory) do not pin.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use dwara_core::config::parse_gateway;
use dwara_core::store::{sync_consumers_from_config, CredentialKind, StateStore, StoreError};

fn add_key(store: &StateStore, consumer_id: i64, selector: &str, hash: &str) -> i64 {
    store
        .add_credential(
            consumer_id,
            CredentialKind::ApiKey,
            hash.to_string(),
            None,
            selector.to_string(),
        )
        .unwrap()
        .id
}

// ---------------------------------------------------------------------------
// 1. Reopen persistence
// ---------------------------------------------------------------------------

#[test]
fn state_survives_drop_and_reopen_of_the_same_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    let (consumer_id, cred_id) = {
        let store = StateStore::open(&path).unwrap();
        let c = store.upsert_consumer("acme", Some(7)).unwrap();
        add_key(&store, c.id, "key-1", "h1");
        store.incr_quota(c.id, "rpm", 1000, 4, None).unwrap();
        (
            c.id,
            store.lookup_credential("key-1").unwrap().unwrap()[0].id,
        )
    };
    // Handle dropped cleanly; reopen at the same path.
    let reopened = StateStore::open(&path).unwrap();
    assert_eq!(
        reopened.list_consumers().unwrap(),
        vec![dwara_core::store::ConsumerRecord {
            id: consumer_id,
            name: "acme".into(),
            priority: Some(7),
            created_at: reopened.list_consumers().unwrap()[0].created_at,
        }]
    );
    let creds = reopened.lookup_credential("key-1").unwrap().unwrap();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].id, cred_id);
    assert_eq!(creds[0].hash, "h1");
    assert_eq!(reopened.get_quota(consumer_id, "rpm", 1000).unwrap(), 4);
    // Revocation also persists across reopen.
    assert!(reopened.revoke_credential(cred_id).unwrap());
    drop(reopened);
    let reopened2 = StateStore::open(&path).unwrap();
    assert!(reopened2
        .lookup_credential("key-1")
        .unwrap()
        .unwrap()
        .is_empty());
}

// ---------------------------------------------------------------------------
// 2. Quota edges
// ---------------------------------------------------------------------------

#[test]
fn incr_exactly_to_limit_is_allowed_and_beyond_is_refused_atomically() {
    let store = StateStore::open_in_memory().unwrap();
    let c = store.upsert_consumer("acme", None).unwrap();
    // Exactly to the limit: allowed, used == limit.
    assert_eq!(store.incr_quota(c.id, "rpm", 1, 5, Some(5)).unwrap(), 5);
    assert_eq!(store.get_quota(c.id, "rpm", 1).unwrap(), 5);
    // One over: refused, used unchanged.
    let err = store.incr_quota(c.id, "rpm", 1, 1, Some(5)).unwrap_err();
    assert!(matches!(
        err,
        StoreError::QuotaExceeded {
            used: 5,
            limit: 5,
            requested: 1
        }
    ));
    assert_eq!(store.get_quota(c.id, "rpm", 1).unwrap(), 5);
    // A large amount that would overflow u64 is refused, not wrapped.
    let err = store
        .incr_quota(c.id, "rpm", 1, u64::MAX, Some(u64::MAX))
        .unwrap_err();
    assert!(matches!(err, StoreError::QuotaExceeded { .. }));
    assert_eq!(store.get_quota(c.id, "rpm", 1).unwrap(), 5);
}

#[test]
fn concurrent_increments_never_exceed_the_limit() {
    let store = Arc::new(StateStore::open_in_memory().unwrap());
    let c = store.upsert_consumer("acme", None).unwrap();
    const THREADS: usize = 8;
    const LIMIT: u64 = 5;
    let barrier = Arc::new(Barrier::new(THREADS));
    let accepted = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..THREADS {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let accepted = Arc::clone(&accepted);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            for _ in 0..LIMIT {
                if store.incr_quota(c.id, "rpm", 1, 1, Some(LIMIT)).is_ok() {
                    accepted.fetch_add(1, Ordering::SeqCst);
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let total: u64 = accepted.load(Ordering::SeqCst) as u64;
    assert!(total <= LIMIT, "accepted {total} > limit {LIMIT}");
    assert_eq!(store.get_quota(c.id, "rpm", 1).unwrap(), total);
    assert!(total > 0, "race starved all increments");
}

#[test]
fn window_rollover_starts_an_independent_counter_at_zero() {
    let store = StateStore::open_in_memory().unwrap();
    let c = store.upsert_consumer("acme", None).unwrap();
    store.incr_quota(c.id, "rpm", 1000, 7, Some(10)).unwrap();
    // New window: independent counter, starts at zero, own limit.
    assert_eq!(store.incr_quota(c.id, "rpm", 2000, 3, Some(10)).unwrap(), 3);
    assert_eq!(store.get_quota(c.id, "rpm", 1000).unwrap(), 7);
    assert_eq!(store.get_quota(c.id, "rpm", 2000).unwrap(), 3);
    // Old window at its own limit stays refused; new window still has room.
    assert!(store.incr_quota(c.id, "rpm", 1000, 4, Some(10)).is_err());
    assert_eq!(
        store.incr_quota(c.id, "rpm", 2000, 7, Some(10)).unwrap(),
        10
    );
}

// ---------------------------------------------------------------------------
// 3. Negative-cache coherence
// ---------------------------------------------------------------------------

#[test]
fn negative_cache_is_invalidated_by_add_and_repopulated_by_revoke() {
    let store = StateStore::open_in_memory().unwrap();
    let c = store.upsert_consumer("acme", None).unwrap();
    // Miss: negative result cached, one disk read.
    assert!(store
        .lookup_credential("key-1")
        .unwrap()
        .unwrap()
        .is_empty());
    let after_negative = store.disk_reads();
    assert!(after_negative >= 1);
    for _ in 0..10 {
        assert!(store
            .lookup_credential("key-1")
            .unwrap()
            .unwrap()
            .is_empty());
    }
    assert_eq!(store.disk_reads(), after_negative);

    // add_credential through the same handle invalidates the negative entry.
    let cred_id = add_key(&store, c.id, "key-1", "h1");
    let before = store.disk_reads();
    let entry = store.lookup_credential("key-1").unwrap().unwrap();
    assert_eq!(
        store.disk_reads(),
        before + 1,
        "negative entry was not invalidated"
    );
    assert_eq!(entry.len(), 1);
    assert_eq!(entry[0].hash, "h1");

    // Revoke: lookup returns empty again and the negative result is re-cached.
    assert!(store.revoke_credential(cred_id).unwrap());
    let before = store.disk_reads();
    assert!(store
        .lookup_credential("key-1")
        .unwrap()
        .unwrap()
        .is_empty());
    assert_eq!(store.disk_reads(), before + 1);
    for _ in 0..10 {
        assert!(store
            .lookup_credential("key-1")
            .unwrap()
            .unwrap()
            .is_empty());
    }
    assert_eq!(store.disk_reads(), before + 1);
}

// ---------------------------------------------------------------------------
// 4. Selector multi-credentials (rotation overlap)
// ---------------------------------------------------------------------------

#[test]
fn two_active_credentials_on_one_selector_and_revoking_one_keeps_the_other() {
    let store = StateStore::open_in_memory().unwrap();
    let acme = store.upsert_consumer("acme", None).unwrap();
    let other = store.upsert_consumer("other", None).unwrap();
    let old = add_key(&store, acme.id, "shared-sel", "old-hash");
    let new = add_key(&store, other.id, "shared-sel", "new-hash");

    let entry = store.lookup_credential("shared-sel").unwrap().unwrap();
    assert_eq!(entry.len(), 2);
    let hashes: Vec<&str> = entry.iter().map(|c| c.hash.as_str()).collect();
    assert!(hashes.contains(&"old-hash") && hashes.contains(&"new-hash"));
    let names: Vec<&str> = entry.iter().map(|c| c.consumer_name.as_str()).collect();
    assert!(names.contains(&"acme") && names.contains(&"other"));

    // Revoke the old credential: exactly the new one remains.
    assert!(store.revoke_credential(old).unwrap());
    let entry = store.lookup_credential("shared-sel").unwrap().unwrap();
    assert_eq!(entry.len(), 1);
    assert_eq!(entry[0].id, new);
    assert_eq!(entry[0].hash, "new-hash");
}

// ---------------------------------------------------------------------------
// 5. Seeding idempotence + drift
// ---------------------------------------------------------------------------

fn config_yaml(body: &str) -> dwara_core::config::Gateway {
    parse_gateway(&format!("consumers:\n{body}")).unwrap()
}

#[test]
fn seeding_twice_creates_single_consumer_and_credential_rows() {
    let config =
        config_yaml("  - name: acme\n    credentials:\n      - type: api_key\n        key: k1\n");
    let store = StateStore::open_in_memory().unwrap();
    sync_consumers_from_config(&store, &config).unwrap();
    sync_consumers_from_config(&store, &config).unwrap();
    assert_eq!(store.list_consumers().unwrap().len(), 1);
    assert_eq!(store.lookup_credentials_by_selector("k1").unwrap().len(), 1);
}

#[test]
fn removed_config_consumers_persist_in_the_store_upsert_only_sync() {
    // PIN ACTUAL BEHAVIOR: sync_consumers_from_config is upsert-only; it
    // never deletes. A consumer removed from the config remains in the
    // store after a re-seed with the reduced config. Documented semantics
    // (config is a bootstrap seed, not the source of truth after start) —
    // flagged in the tester report as a semantic to keep documented.
    let full = config_yaml("  - name: acme\n    credentials:\n      - type: api_key\n        key: k1\n  - name: gone\n    credentials:\n      - type: api_key\n        key: k2\n");
    let reduced =
        config_yaml("  - name: acme\n    credentials:\n      - type: api_key\n        key: k1\n");
    let store = StateStore::open_in_memory().unwrap();
    sync_consumers_from_config(&store, &full).unwrap();
    sync_consumers_from_config(&store, &reduced).unwrap();
    let names: Vec<String> = store
        .list_consumers()
        .unwrap()
        .into_iter()
        .map(|c| c.name)
        .collect();
    assert_eq!(names, vec!["acme".to_string(), "gone".to_string()]);
    // The removed consumer's credential is still active in the store.
    assert_eq!(store.lookup_credentials_by_selector("k2").unwrap().len(), 1);
}

#[test]
fn seed_resync_after_revoke_reinserts_the_config_credential() {
    // Drift edge: re-syncing after revocation re-adds the credential,
    // because seeding matches only ACTIVE credentials by consumer+kind.
    let config =
        config_yaml("  - name: acme\n    credentials:\n      - type: api_key\n        key: k1\n");
    let store = StateStore::open_in_memory().unwrap();
    sync_consumers_from_config(&store, &config).unwrap();
    let cred_id = store.lookup_credentials_by_selector("k1").unwrap()[0].id;
    assert!(store.revoke_credential(cred_id).unwrap());
    sync_consumers_from_config(&store, &config).unwrap();
    let active = store.lookup_credentials_by_selector("k1").unwrap();
    assert_eq!(active.len(), 1, "revoked config credential is re-seeded");
}

// ---------------------------------------------------------------------------
// 6. Corruption / error paths / instrumentation
// ---------------------------------------------------------------------------

#[test]
fn opening_a_non_sqlite_file_returns_a_store_error_not_a_panic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("garbage.db");
    std::fs::write(&path, b"this is definitely not a sqlite database file").unwrap();
    let result = StateStore::open(&path);
    match result {
        Err(StoreError::Sqlite(_)) => {}
        Err(other) => panic!("expected Sqlite error, got {other:?}"),
        Ok(_) => panic!("expected error opening a non-SQLite file"),
    }
}

#[test]
fn opening_a_directory_as_db_is_a_typed_error() {
    let dir = tempfile::tempdir().unwrap();
    match StateStore::open(Path::new(dir.path())) {
        Err(StoreError::Sqlite(_)) => {}
        other => panic!("expected Sqlite error, got {:?}", other.err()),
    }
}

#[test]
fn add_credential_for_unknown_consumer_is_the_typed_unknown_consumer_error() {
    let store = StateStore::open_in_memory().unwrap();
    let err = store
        .add_credential(424242, CredentialKind::Jwt, "h".into(), None, "sel".into())
        .unwrap_err();
    match err {
        StoreError::UnknownConsumer(msg) => assert!(msg.contains("424242")),
        other => panic!("expected UnknownConsumer, got {other:?}"),
    }
}

#[test]
fn disk_reads_counter_increments_on_each_cold_miss() {
    let store = StateStore::open_in_memory().unwrap();
    let c = store.upsert_consumer("acme", None).unwrap();
    add_key(&store, c.id, "k1", "h");
    let before = store.disk_reads();
    store.lookup_credential("k1").unwrap();
    store.lookup_credential("unknown-a").unwrap();
    store.lookup_credential("unknown-b").unwrap();
    assert_eq!(store.disk_reads(), before + 3);
    // Warmed: repeated lookups add no disk reads.
    store.lookup_credential("k1").unwrap();
    store.lookup_credential("unknown-a").unwrap();
    assert_eq!(store.disk_reads(), before + 3);
}

// ---------------------------------------------------------------------------
// 7. Volume sanity
// ---------------------------------------------------------------------------

#[test]
fn five_hundred_selectors_warmed_serve_five_thousand_lookups_with_zero_disk() {
    const SELECTORS: u64 = 500;
    const LOOKUPS: u64 = 5000;
    let dir = tempfile::tempdir().unwrap();
    let store = StateStore::open(&dir.path().join("state.db")).unwrap();
    let c = store.upsert_consumer("acme", None).unwrap();
    for i in 0..SELECTORS {
        add_key(&store, c.id, &format!("key-{i}"), &format!("h{i}"));
    }
    // Warm every selector (including some unknown ones).
    for i in 0..SELECTORS {
        store.lookup_credential(&format!("key-{i}")).unwrap();
    }
    for i in 0..10 {
        store.lookup_credential(&format!("nope-{i}")).unwrap();
    }
    let reads_after_warmup = store.disk_reads();
    let mut hits_at_warmup = 0u64;
    for i in 0..LOOKUPS {
        let unknown = i % 50 == 49;
        let selector = if unknown {
            format!("nope-{}", i % 10)
        } else {
            format!("key-{}", i % SELECTORS)
        };
        let entry = store.lookup_credential(&selector).unwrap().unwrap();
        if i == 0 {
            hits_at_warmup = store.cache_hits();
        }
        assert_eq!(entry.is_empty(), unknown);
        if let Some(idx) = selector.strip_prefix("key-") {
            let idx: u64 = idx.parse().unwrap();
            assert_eq!(entry[0].hash, format!("h{idx}"));
        }
    }
    assert_eq!(
        store.disk_reads(),
        reads_after_warmup,
        "disk touched after warmup"
    );
    assert!(store.cache_hits() >= hits_at_warmup + LOOKUPS - 1);
}
