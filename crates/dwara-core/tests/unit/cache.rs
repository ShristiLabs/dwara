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
