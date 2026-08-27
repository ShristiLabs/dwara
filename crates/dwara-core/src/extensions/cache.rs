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
//! **Editions:** OSS ships [`InMemoryCache`] (process-local LRU-bounded
//! map; a moka-backed cache may land later behind the same trait).
//! Additional distributed backends may be provided separately in future
//! editions.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use async_trait::async_trait;

use super::ExtensionsError;

/// Default [`InMemoryCache`] capacity (entries, not bytes): enough for a
/// small deployment's hot response set while keeping the store bounded
/// against key-flooding (#128, DW-004 review).
pub const DEFAULT_CACHE_CAPACITY: usize = 1024;

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

/// One entry: its value plus the last-use stamp for LRU ordering.
#[derive(Debug)]
struct Entry {
    value: Vec<u8>,
    last_used: u64,
}

/// Bounded internal state: the entries plus a `last_used -> key` index so
/// eviction finds the least-recently-used entry without a scan.
#[derive(Debug, Default)]
struct Bounded {
    map: HashMap<String, Entry>,
    recency: BTreeMap<u64, String>,
    tick: u64,
}

impl Bounded {
    /// Move `key` (present in `map`) to "just used" under a fresh tick and
    /// keep the recency index in sync. A no-op when the key is absent.
    fn touch(&mut self, key: &str) {
        let Some(last_used) = self.map.get(key).map(|e| e.last_used) else {
            return;
        };
        self.tick += 1;
        self.recency.remove(&last_used);
        if let Some(entry) = self.map.get_mut(key) {
            entry.last_used = self.tick;
        }
        self.recency.insert(self.tick, key.to_string());
    }

    /// Evict least-recently-used entries until the map fits `capacity`.
    fn evict_to(&mut self, capacity: usize) {
        while self.map.len() > capacity {
            let Some((_, victim)) = self.recency.pop_first() else {
                return;
            };
            self.map.remove(&victim);
        }
    }
}

/// In-memory LRU cache (OSS local impl, #128).
///
/// Capacity-bounded with least-recently-used eviction: `get` and `set`
/// refresh recency; once the entry count exceeds the capacity the
/// least-recently-used entry is evicted. The capacity is a constructor
/// parameter ([`InMemoryCache::with_capacity`],
/// [`DEFAULT_CACHE_CAPACITY`] by default, clamped to at least 1) — it
/// bounds ENTRY COUNT, not bytes (values are opaque to the store); a
/// byte- or TTL-bounded backend can slot in behind the same trait later.
#[derive(Debug)]
pub struct InMemoryCache {
    entries: Mutex<Bounded>,
    capacity: usize,
}

impl Default for InMemoryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryCache {
    /// Cache with the default capacity ([`DEFAULT_CACHE_CAPACITY`]
    /// entries).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CACHE_CAPACITY)
    }

    /// Cache bounded to `capacity` entries (values below 1 are clamped
    /// to 1, so the store is always minimally usable).
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(Bounded::default()),
            capacity: capacity.max(1),
        }
    }
}

#[async_trait]
impl CacheStore for InMemoryCache {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, ExtensionsError> {
        let mut state = self.entries.lock().expect("cache state poisoned");
        let value = state.map.get(key).map(|e| e.value.clone());
        // Refresh recency; a no-op when the key is absent (touch checks).
        state.touch(key);
        Ok(value)
    }

    async fn set(&self, key: String, value: Vec<u8>) -> Result<(), ExtensionsError> {
        let mut state = self.entries.lock().expect("cache state poisoned");
        if let Some(old) = state.map.remove(&key) {
            state.recency.remove(&old.last_used);
        }
        state.tick += 1;
        // Copy the tick out: the guard's DerefMut borrows all of `state`
        // for the insert, so the literal cannot read `state.tick` inline.
        let tick = state.tick;
        state.recency.insert(tick, key.clone());
        state.map.insert(
            key,
            Entry {
                value,
                last_used: tick,
            },
        );
        state.evict_to(self.capacity);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<bool, ExtensionsError> {
        let mut state = self.entries.lock().expect("cache state poisoned");
        match state.map.remove(key) {
            Some(entry) => {
                state.recency.remove(&entry.last_used);
                Ok(true)
            }
            None => Ok(false),
        }
    }
}
