//! Cache store extension point.
//!
//! # Contract: [`CacheStore`]
//!
//! **Purpose:** opaque byte-level get/set/delete storage for response
//! caching and any hot-path shared state. Keys are strings; values are
//! owned byte vectors so backends can move them without copying.
//!
//! **Semantics:** a best-effort store, not a durable database. `set`
//! overwrites any existing value; `delete` of a missing key is a no-op
//! reporting `false`. There is no TTL parameter in M1 — implementations
//! bound themselves (capacity/eviction) — but signatures were chosen so a
//! TTL can be added later as a new method (`set_with_ttl`) without
//! breaking existing impls or call sites. Operations are individually
//! atomic; ordering across keys is unspecified.
//!
//! **Failure model:** backend failures map to [`ExtensionsError::Backend`];
//! call sites should treat cache errors as a miss (degrade, do not fail the
//! request). No retries.
//!
//! **Editions:** OSS ships [`InMemoryCache`] (process-local `HashMap`; the
//! moka-backed cache lands later behind the same trait). Additional
//! distributed backends may be provided separately in future editions.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use super::ExtensionsError;

/// Swappable key/value cache backend.
#[async_trait]
pub trait CacheStore: Send + Sync {
    /// Fetch the value for `key`, if present.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, ExtensionsError>;
    /// Store `value` under `key`, overwriting any previous value.
    async fn set(&self, key: String, value: Vec<u8>) -> Result<(), ExtensionsError>;
    /// Remove `key`; returns whether a value existed.
    async fn delete(&self, key: &str) -> Result<bool, ExtensionsError>;
}

/// In-memory `HashMap` cache (OSS skeleton).
///
/// Unbounded: capacity/eviction policy is a later concern (moka); this
/// skeleton fixes the trait surface and real storage semantics.
#[derive(Debug, Default)]
pub struct InMemoryCache {
    entries: Mutex<HashMap<String, Vec<u8>>>,
}

impl InMemoryCache {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl CacheStore for InMemoryCache {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, ExtensionsError> {
        Ok(self
            .entries
            .lock()
            .expect("cache state poisoned")
            .get(key)
            .cloned())
    }

    async fn set(&self, key: String, value: Vec<u8>) -> Result<(), ExtensionsError> {
        self.entries
            .lock()
            .expect("cache state poisoned")
            .insert(key, value);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<bool, ExtensionsError> {
        Ok(self
            .entries
            .lock()
            .expect("cache state poisoned")
            .remove(key)
            .is_some())
    }
}
