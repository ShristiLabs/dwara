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
//! reporting `false`. DW-037 added the optional TTL seam the M1 doc
//! anticipated: [`CacheStore::set_with_ttl`] carries a per-entry
//! lifetime hint, DEFAULTED to plain `set` so every existing
//! implementation keeps compiling and remains a valid backend — the
//! response cache layer stamps expiry into the value envelope and
//! enforces it at READ, so backend TTL is a memory-reclamation
//! optimization, never a correctness dependency.
//!
//! **Failure model:** backend failures map to [`ExtensionsError::Backend`];
//! call sites should treat cache errors as a miss (degrade, do not fail the
//! request). No retries.
//!
//! **Editions:** OSS ships [`InMemoryCache`] (process-local LRU-bounded
//! map) and [`MokaCache`] (the DW-037 response-cache backend:
//! concurrent, byte-weighed, per-entry TTL). Additional distributed
//! backends (DW-068 Redis) may be provided separately in future
//! editions.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;

use super::ExtensionsError;

/// Default [`InMemoryCache`] capacity (entries, not bytes): enough for a
/// small deployment's hot response set while keeping the store bounded
/// against key-flooding (#128, DW-004 review).
pub const DEFAULT_CACHE_CAPACITY: usize = 1024;

/// Default [`MokaCache`] capacity (bytes, DW-037): the weigher counts
/// key + value bytes plus a fixed per-entry overhead, so the bound is a
/// real memory ceiling for the response cache (entries at or under the
/// per-route `max_body_bytes` cap, of which 64 MiB holds hundreds).
pub const DEFAULT_CACHE_STORE_BYTES: u64 = 64 * 1024 * 1024;

/// Swappable key/value cache backend.
#[async_trait]
pub trait CacheStore: Send + Sync {
    /// Fetch the value for `key`, if present.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, ExtensionsError>;
    /// Store `value` under `key`, overwriting any previous value.
    async fn set(&self, key: String, value: Vec<u8>) -> Result<(), ExtensionsError>;
    /// Remove `key`; returns whether a value existed.
    async fn delete(&self, key: &str) -> Result<bool, ExtensionsError>;
    /// Store `value` under `key` with a per-entry lifetime hint
    /// (DW-037). Backends that cannot honor a per-entry TTL implement
    /// the default (store without the hint); every reader re-checks
    /// expiry from the value itself, so correctness never depends on
    /// this. Defaulted, not abstract: existing implementations stay
    /// valid backends without a change (extend, do not break).
    async fn set_with_ttl(
        &self,
        key: String,
        value: Vec<u8>,
        ttl: Duration,
    ) -> Result<(), ExtensionsError> {
        let _ = ttl;
        self.set(key, value).await
    }
    /// Approximate number of live entries, when the backend can report
    /// it cheaply (DW-037 metrics gauge; None = not reportable). An
    /// estimate is acceptable — the consumer renders it as a gauge.
    fn entry_count(&self) -> Option<u64> {
        None
    }
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

/// Byte-weighed TTL cache over `moka` (DW-037 response-cache backend).
///
/// Bounds, honestly stated:
///
/// - **Bytes, not entries**: `max_capacity` is interpreted through a
///   weigher counting key + value bytes plus a fixed per-entry overhead
///   (`ENTRY_OVERHEAD_BYTES`), so the store is bounded by MEMORY, the
///   property a gateway cache actually needs (entry-count bounds let N
///   one-byte-below-the-cap entries allocate N times the cap).
/// - **Time-to-idle** ([`MokaCache::TIME_TO_IDLE`]): entries nobody
///   looks at for an hour are evicted even when still nominally fresh —
///   a cold entry costs memory and a future miss, nothing else.
/// - **Per-entry TTL** via [`CacheStore::set_with_ttl`]: the hint rides
///   the stored pair and drives moka's `Expiry` policy (plus 60 s of
///   slack over the hint, so the envelope's read-side expiry always
///   fires first and the backend only reclaims what the policy already
///   abandoned).
///
/// All eviction (size, idle, TTL) is approximate and concurrent — moka
/// maintains shards internally; no global lock sits on the hot path.
#[derive(Debug)]
pub struct MokaCache {
    inner: moka::sync::Cache<String, (Vec<u8>, Option<Duration>)>,
}

/// Fixed per-entry weigher overhead: moka's own node/bookkeeping bytes
/// charged to the capacity budget so the byte bound is conservative.
const ENTRY_OVERHEAD_BYTES: u64 = 256;

/// Per-entry TTL policy: the duration stored alongside each value (set
/// by `set_with_ttl`, `None` for plain `set`) becomes the entry's
/// post-creation lifetime; updates keep the original expiry clock.
struct TtlExpiry;

impl moka::Expiry<String, (Vec<u8>, Option<Duration>)> for TtlExpiry {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &(Vec<u8>, Option<Duration>),
        _created_at: std::time::Instant,
    ) -> Option<Duration> {
        value.1
    }
}

impl Default for MokaCache {
    fn default() -> Self {
        Self::with_max_bytes(DEFAULT_CACHE_STORE_BYTES)
    }
}

impl MokaCache {
    /// Idle-eviction window (see the type docs).
    pub const TIME_TO_IDLE: Duration = Duration::from_secs(3600);

    /// Slack added to every TTL hint (see the type docs).
    pub const TTL_SLACK: Duration = Duration::from_secs(60);

    /// Cache bounded to `max_bytes` of key+value+overhead bytes.
    pub fn with_max_bytes(max_bytes: u64) -> Self {
        MokaCache {
            inner: moka::sync::Cache::builder()
                .max_capacity(max_bytes)
                .weigher(|k: &String, v: &(Vec<u8>, Option<Duration>)| {
                    (k.len() as u64 + v.0.len() as u64 + ENTRY_OVERHEAD_BYTES) as u32
                })
                .time_to_idle(Self::TIME_TO_IDLE)
                .expire_after(TtlExpiry)
                .build(),
        }
    }
}

#[async_trait]
impl CacheStore for MokaCache {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, ExtensionsError> {
        Ok(self.inner.get(key).map(|(value, _)| value))
    }

    async fn set(&self, key: String, value: Vec<u8>) -> Result<(), ExtensionsError> {
        self.inner.insert(key, (value, None));
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<bool, ExtensionsError> {
        Ok(self.inner.remove(key).is_some())
    }

    async fn set_with_ttl(
        &self,
        key: String,
        value: Vec<u8>,
        ttl: Duration,
    ) -> Result<(), ExtensionsError> {
        // Read-side envelope expiry is the source of truth; the backend
        // TTL only reclaims memory the policy already gave up on.
        self.inner.insert(key, (value, Some(ttl + Self::TTL_SLACK)));
        Ok(())
    }

    fn entry_count(&self) -> Option<u64> {
        Some(self.inner.entry_count())
    }
}
