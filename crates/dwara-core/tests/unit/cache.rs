//! Unit tests for `extensions::cache` (relocated from src).

use dwara_core::extensions::cache::*;

#[tokio::test]
async fn set_get_delete_roundtrip() {
    let cache = InMemoryCache::new();
    assert!(cache.get("k").await.unwrap().is_none());
    cache.set("k".into(), b"v".to_vec()).await.unwrap();
    assert_eq!(cache.get("k").await.unwrap(), Some(b"v".to_vec()));
    assert!(cache.delete("k").await.unwrap());
    assert!(cache.get("k").await.unwrap().is_none());
}

#[tokio::test]
async fn delete_of_missing_key_reports_false() {
    let cache = InMemoryCache::new();
    assert!(!cache.delete("never-set").await.unwrap());
}

#[tokio::test]
async fn set_overwrites_previous_value() {
    let cache = InMemoryCache::new();
    cache.set("k".into(), b"old".to_vec()).await.unwrap();
    cache.set("k".into(), b"new".to_vec()).await.unwrap();
    assert_eq!(cache.get("k").await.unwrap(), Some(b"new".to_vec()));
}

#[tokio::test]
async fn values_are_isolated_per_key() {
    let cache = InMemoryCache::new();
    cache.set("a".into(), b"1".to_vec()).await.unwrap();
    cache.set("b".into(), b"2".to_vec()).await.unwrap();
    assert_eq!(cache.get("a").await.unwrap(), Some(b"1".to_vec()));
    assert_eq!(cache.get("b").await.unwrap(), Some(b"2".to_vec()));
}

#[tokio::test]
async fn empty_value_round_trips_as_some() {
    let cache = InMemoryCache::new();
    cache.set("empty".into(), Vec::new()).await.unwrap();
    assert_eq!(cache.get("empty").await.unwrap(), Some(Vec::new()));
}

// --- capacity / LRU eviction (#128) --------------------------------------

#[tokio::test]
async fn insert_over_capacity_evicts_the_oldest_entry() {
    let cache = InMemoryCache::with_capacity(3);
    for (i, k) in ["k1", "k2", "k3"].iter().enumerate() {
        cache.set((*k).into(), vec![i as u8]).await.unwrap();
    }
    // Fourth insert: over capacity, the least-recently-used (k1, only
    // inserted, never touched) is evicted.
    cache.set("k4".into(), b"4".to_vec()).await.unwrap();
    assert_eq!(cache.get("k1").await.unwrap(), None, "oldest evicted");
    for k in ["k2", "k3", "k4"] {
        assert!(cache.get(k).await.unwrap().is_some(), "{k} survives");
    }
}

#[tokio::test]
async fn get_refreshes_recency_lru_not_fifo() {
    // Pins the POLICY as LRU: a get on an old entry rescues it from
    // eviction while an untouched younger one is evicted instead.
    let cache = InMemoryCache::with_capacity(2);
    cache.set("a".into(), b"1".to_vec()).await.unwrap();
    cache.set("b".into(), b"2".to_vec()).await.unwrap();
    assert_eq!(cache.get("a").await.unwrap(), Some(b"1".to_vec())); // a refreshed
    cache.set("c".into(), b"3".to_vec()).await.unwrap();
    assert_eq!(
        cache.get("b").await.unwrap(),
        None,
        "the untouched entry is evicted, not the refreshed old one"
    );
    assert_eq!(cache.get("a").await.unwrap(), Some(b"1".to_vec()));
    assert_eq!(cache.get("c").await.unwrap(), Some(b"3".to_vec()));
}

#[tokio::test]
async fn set_overwrite_refreshes_recency_without_ejecting_peers() {
    let cache = InMemoryCache::with_capacity(2);
    cache.set("a".into(), b"1".to_vec()).await.unwrap();
    cache.set("b".into(), b"2".to_vec()).await.unwrap();
    // Overwrite the OLDEST entry: no growth, no eviction, and a is now
    // the most recent.
    cache.set("a".into(), b"9".to_vec()).await.unwrap();
    assert_eq!(cache.get("a").await.unwrap(), Some(b"9".to_vec()));
    cache.set("c".into(), b"3".to_vec()).await.unwrap();
    assert_eq!(cache.get("b").await.unwrap(), None, "b was least recent");
    assert_eq!(cache.get("a").await.unwrap(), Some(b"9".to_vec()));
    assert_eq!(cache.get("c").await.unwrap(), Some(b"3".to_vec()));
}

#[tokio::test]
async fn eviction_stays_consistent_after_deletions() {
    // Delete keeps the recency index consistent under churn: after
    // removing entries around the capacity, the surviving set is exactly
    // the most-recent capacity-many keys, and a re-inserted key works.
    let cache = InMemoryCache::with_capacity(2);
    cache.set("a".into(), b"1".to_vec()).await.unwrap();
    cache.set("b".into(), b"2".to_vec()).await.unwrap();
    assert!(cache.delete("a").await.unwrap());
    // One slot freed by the delete: c fits WITHOUT an eviction.
    cache.set("c".into(), b"3".to_vec()).await.unwrap();
    assert_eq!(cache.get("b").await.unwrap(), Some(b"2".to_vec()));
    assert_eq!(cache.get("c").await.unwrap(), Some(b"3".to_vec()));
    // Third entry: plain LRU applies among the survivors (b is least
    // recent), NOT the deleted a.
    cache.set("d".into(), b"4".to_vec()).await.unwrap();
    assert_eq!(cache.get("b").await.unwrap(), None, "b was least recent");
    assert_eq!(cache.get("c").await.unwrap(), Some(b"3".to_vec()));
    assert_eq!(cache.get("d").await.unwrap(), Some(b"4".to_vec()));
    // Re-inserting a deleted key starts fresh.
    cache.set("a".into(), b"9".to_vec()).await.unwrap();
    assert_eq!(cache.get("a").await.unwrap(), Some(b"9".to_vec()));
}

#[tokio::test]
async fn capacity_clamps_to_one_and_default_is_bounded() {
    let cache = InMemoryCache::with_capacity(0);
    cache.set("a".into(), b"1".to_vec()).await.unwrap();
    cache.set("b".into(), b"2".to_vec()).await.unwrap();
    assert_eq!(
        cache.get("a").await.unwrap(),
        None,
        "capacity 0 clamps to 1"
    );
    assert_eq!(cache.get("b").await.unwrap(), Some(b"2".to_vec()));
    // The default constant is a sane bounded value (not 0 / unbounded),
    // checked at compile time.
    const _: () = assert!(DEFAULT_CACHE_CAPACITY >= 1);
    let _default = InMemoryCache::default(); // Default == new()
}
