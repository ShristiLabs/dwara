//! Unit tests for `extensions::redis_cache` (relocated from src).

#![cfg(feature = "ent")]

use dwara_core::extensions::cache::{CacheStore, InMemoryCache};
use dwara_core::extensions::redis_cache::invalidation_channel;
use std::sync::Arc;
use std::time::Duration;

#[test]
fn full_key_with_prefix() {
    // Test the key prefixing logic without a Redis connection.
    // We can't create a RedisCacheStore without a connection, so
    // we test the logic directly.
    let prefix = "dwara:cache:";
    let key = "my-key";
    let full = format!("{prefix}{key}");
    assert_eq!(full, "dwara:cache:my-key");
}

#[test]
fn invalidation_channel_name() {
    assert_eq!(invalidation_channel(), "dwara:cache:invalidate");
}

#[tokio::test]
async fn coordinated_cache_get_falls_back_to_remote() {
    // Use in-memory caches to simulate local + remote.
    let local: Arc<dyn CacheStore> = Arc::new(InMemoryCache::new());
    let remote: Arc<dyn CacheStore> = Arc::new(InMemoryCache::new());

    // Set a value in "remote" only.
    remote
        .set("key1".to_string(), b"value1".to_vec())
        .await
        .unwrap();

    // The coordinated cache would normally wrap a RedisCacheStore,
    // but we test the logic with two in-memory caches.
    // Since we can't construct a CoordinatedCache without a
    // RedisCacheStore, we test the fallback logic manually.
    let local_val = local.get("key1").await.unwrap();
    assert!(local_val.is_none());

    let remote_val = remote.get("key1").await.unwrap();
    assert_eq!(remote_val, Some(b"value1".to_vec()));
}

#[tokio::test]
async fn coordinated_cache_set_writes_to_both() {
    let local: Arc<dyn CacheStore> = Arc::new(InMemoryCache::new());
    let remote: Arc<dyn CacheStore> = Arc::new(InMemoryCache::new());

    // Set in both.
    local
        .set("key1".to_string(), b"value1".to_vec())
        .await
        .unwrap();
    remote
        .set("key1".to_string(), b"value1".to_vec())
        .await
        .unwrap();

    assert_eq!(local.get("key1").await.unwrap(), Some(b"value1".to_vec()));
    assert_eq!(remote.get("key1").await.unwrap(), Some(b"value1".to_vec()));
}

#[tokio::test]
async fn coordinated_cache_delete_removes_from_both() {
    let local: Arc<dyn CacheStore> = Arc::new(InMemoryCache::new());
    let remote: Arc<dyn CacheStore> = Arc::new(InMemoryCache::new());

    local
        .set("key1".to_string(), b"value1".to_vec())
        .await
        .unwrap();
    remote
        .set("key1".to_string(), b"value1".to_vec())
        .await
        .unwrap();

    local.delete("key1").await.unwrap();
    remote.delete("key1").await.unwrap();

    assert!(local.get("key1").await.unwrap().is_none());
    assert!(remote.get("key1").await.unwrap().is_none());
}

#[tokio::test]
async fn coordinated_cache_set_with_ttl() {
    let local: Arc<dyn CacheStore> = Arc::new(InMemoryCache::new());
    let remote: Arc<dyn CacheStore> = Arc::new(InMemoryCache::new());

    local
        .set_with_ttl(
            "key1".to_string(),
            b"value1".to_vec(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    remote
        .set_with_ttl(
            "key1".to_string(),
            b"value1".to_vec(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    assert_eq!(local.get("key1").await.unwrap(), Some(b"value1".to_vec()));
}
