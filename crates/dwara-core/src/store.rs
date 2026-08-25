//! SQLite-backed state store with an in-memory hot cache (DW-018).
//!
//! # Purpose
//!
//! Durable state for the gateway's control identity layer: consumers,
//! credential records (pre-hashed secrets), and quota counters. The store
//! is the OSS state layer (single-process SQLite); multi-instance
//! deployments would swap the backend behind the same API surface — the
//! schema and method semantics here are deliberately backend-neutral.
//!
//! # Threading model
//!
//! `rusqlite` is synchronous. [`StateStore`] owns ONE writer connection
//! behind a [`std::sync::Mutex`]; every method is a short, non-blocking
//! critical section (SQLite ops here are all primary-key/index lookups or
//! small transactions). Callers on an async runtime should wrap
//! cold-path operations (seeding, quota writes, revocation) in
//! `tokio::task::spawn_blocking`; the HOT path —
//! [`StateStore::lookup_credential`] — takes only an `RwLock` read on the
//! in-memory cache and touches no SQLite after warmup, so it is safe to
//! call inline on any thread.
//!
//! # Cache coherence
//!
//! The in-memory cache is coherent for writes made THROUGH the same
//! [`StateStore`] handle (writes invalidate the affected cache entries).
//! A separate process, or a second handle to the same file, will NOT
//! invalidate this cache: single-process coherence only. Multi-instance
//! deployments need an external shared cache/invalidation layer — that is
//! an edition boundary concern, not a schema concern.
//!
//! # Schema
//!
//! Schema v1 (`PRAGMA user_version = 1`), created by this module. Future
//! schema changes arrive as migrations FROM this baseline. All writes are
//! transactional; WAL journal mode and foreign-key enforcement are on.
//!
//! The store NEVER sees plaintext secrets: credential values arrive
//! pre-hashed with a lookup `selector` (key id/prefix, JWT kid, or
//! certificate fingerprint). Hashing is the authenticator's job (DW-019).
//! See the seeding note on [`sync_consumers_from_config`] for the interim
//! config-based credential story.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use rusqlite::{params, Connection, OptionalExtension};

use crate::config::{Credential, Gateway};

/// Schema version this module creates and expects.
const SCHEMA_VERSION: i64 = 1;

/// Quota-counter retention horizon in seconds: rows whose `window_start`
/// is older than the newest window in the table by more than this are
/// pruned opportunistically on quota writes. Fixed at one year, which
/// comfortably exceeds any realistic rate-limit window (hourly/daily
/// rollover counters turn over thousands of times per year).
const QUOTA_RETENTION_SECS: i64 = 365 * 24 * 60 * 60;

/// Kind of credential record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    ApiKey,
    Jwt,
    Mtls,
}

impl CredentialKind {
    fn as_str(self) -> &'static str {
        match self {
            CredentialKind::ApiKey => "api_key",
            CredentialKind::Jwt => "jwt",
            CredentialKind::Mtls => "mtls",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "api_key" => Some(CredentialKind::ApiKey),
            "jwt" => Some(CredentialKind::Jwt),
            "mtls" => Some(CredentialKind::Mtls),
            _ => None,
        }
    }
}

/// One consumer row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerRecord {
    pub id: i64,
    pub name: String,
    pub priority: Option<u8>,
    /// Unix epoch seconds.
    pub created_at: i64,
}

/// One credential row (already hashed; never contains a plaintext secret).
///
/// Manual `Debug`: `hash`, `salt`, and `selector` are credential
/// material (the selector alone narrows an attacker's search space and
/// the placeholder hash embeds the config value pre-DW-019), so they are
/// redacted from debug output. Use field access when the values are
/// genuinely needed.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialRecord {
    pub id: i64,
    pub consumer_id: i64,
    /// Denormalized consumer name for hot-path convenience.
    pub consumer_name: String,
    pub kind: CredentialKind,
    pub hash: String,
    pub salt: Option<String>,
    /// Lookup key (key id/prefix, JWT issuer/kid, cert fingerprint).
    pub selector: String,
    /// Unix epoch seconds.
    pub created_at: i64,
    /// Unix epoch seconds of revocation, if revoked.
    pub revoked_at: Option<i64>,
}

impl fmt::Debug for CredentialRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialRecord")
            .field("id", &self.id)
            .field("consumer_id", &self.consumer_id)
            .field("consumer_name", &self.consumer_name)
            .field("kind", &self.kind)
            .field("hash", &"[redacted]")
            .field("salt", &self.salt.as_ref().map(|_| "[redacted]"))
            .field("selector", &"[redacted]")
            .field("created_at", &self.created_at)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

/// Typed store error.
#[derive(Debug)]
pub enum StoreError {
    /// Underlying SQLite failure (message string; never carries row data).
    Sqlite(String),
    /// A quota increment would exceed the limit; nothing was written.
    QuotaExceeded {
        used: u64,
        limit: u64,
        requested: u64,
    },
    /// Referenced consumer does not exist (FK-class violation surfaced as
    /// a typed error before SQLite's own FK error).
    UnknownConsumer(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Sqlite(m) => write!(f, "state store error: {m}"),
            StoreError::QuotaExceeded {
                used,
                limit,
                requested,
            } => write!(
                f,
                "quota exceeded: used {used} + requested {requested} > limit {limit}"
            ),
            StoreError::UnknownConsumer(name) => {
                write!(f, "unknown consumer: {name}")
            }
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Sqlite(e.to_string())
    }
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Sqlite(format!("state store io error: {e}"))
    }
}

type Result<T> = std::result::Result<T, StoreError>;

/// In-memory hot cache: selectors and consumer names to shared records.
///
/// Credential entries cache the FULL active-credential list for a selector
/// (an empty list is a cached negative result, so unknown selectors also
/// stop touching disk after their first lookup). Entries are `Arc` so a
/// cache hit clones no records.
#[derive(Default)]
struct HotCache {
    credentials: RwLock<HashMap<String, Arc<Vec<Arc<CredentialRecord>>>>>,
    consumers: RwLock<HashMap<String, Arc<ConsumerRecord>>>,
}

/// SQLite state store with an in-memory hot cache.
///
/// Hot path: [`StateStore::lookup_credential`] reads the cache under an `RwLock` read
/// and performs ZERO SQLite work after warmup (provable via
/// [`disk_reads`][StateStore::disk_reads]). Cold paths (writes, quota,
/// list) take the connection mutex; see the module docs for the
/// threading model.
pub struct StateStore {
    conn: Mutex<Connection>,
    cache: HotCache,
    disk_reads: AtomicU64,
    cache_hits: AtomicU64,
}

impl StateStore {
    /// Open (or create) a store at `path` and ensure schema v1 exists.
    ///
    /// On unix the database file is tightened to mode 0600 after create:
    /// it stores credential hashes/selectors, so group/other read access
    /// granted by the process umask default (0644) is removed. Existing
    /// files are also tightened; a failure to set permissions is a hard
    /// error rather than silently shipping a world-readable secrets file.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path)?.permissions().mode();
            if mode & 0o077 != 0 {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        Self::init(conn)
    }

    /// Open an in-memory store (tests and tooling).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // Contended writers wait up to 5 s instead of failing immediately
        // with SQLITE_BUSY (this store is single-writer, but a second
        // handle/process on the same file is possible in tooling).
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(StoreError::Sqlite(format!(
                "state db schema version {version} is newer than this build supports ({SCHEMA_VERSION})"
            )));
        }
        if version < SCHEMA_VERSION {
            conn.execute_batch(
                "BEGIN;
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
                 PRAGMA user_version = 1;
                 COMMIT;",
            )?;
        }
        Ok(Self {
            conn: Mutex::new(conn),
            cache: HotCache::default(),
            disk_reads: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
        })
    }

    /// Number of disk (SQLite) reads performed by cache-miss lookups.
    /// Test/ops observability for the "no disk on the hot path" contract.
    pub fn disk_reads(&self) -> u64 {
        self.disk_reads.load(Ordering::Relaxed)
    }

    /// Number of cache hits served without touching SQLite.
    pub fn cache_hits(&self) -> u64 {
        self.cache_hits.load(Ordering::Relaxed)
    }

    /// Insert or update a consumer by name; returns the resulting record.
    /// Updating preserves the row id and creation time; only `priority`
    /// changes. The consumer cache entry is refreshed.
    pub fn upsert_consumer(&self, name: &str, priority: Option<u8>) -> Result<ConsumerRecord> {
        let now = now_secs();
        let conn = self.conn.lock().expect("store connection poisoned");
        let tx = conn.unchecked_transaction()?;
        let existing: Option<i64> = tx
            .query_row(
                "SELECT id FROM consumers WHERE name = ?1",
                params![name],
                |r| r.get(0),
            )
            .optional()?;
        let id = match existing {
            Some(id) => {
                tx.execute(
                    "UPDATE consumers SET priority = ?2 WHERE id = ?1",
                    params![id, priority],
                )?;
                id
            }
            None => {
                tx.execute(
                    "INSERT INTO consumers (name, priority, created_at) VALUES (?1, ?2, ?3)",
                    params![name, priority, now],
                )?;
                tx.last_insert_rowid()
            }
        };
        tx.commit()?;
        // Re-read the actual row rather than fabricating one: on update
        // the DB keeps the ORIGINAL created_at, and the returned/cached
        // record must match disk exactly.
        let record = conn.query_row(
            "SELECT id, name, priority, created_at FROM consumers WHERE id = ?1",
            params![id],
            row_to_consumer,
        )?;
        drop(conn);
        self.cache
            .consumers
            .write()
            .expect("consumer cache poisoned")
            .insert(name.to_string(), Arc::new(record.clone()));
        Ok(record)
    }

    /// List all consumers (disk read; cold path).
    pub fn list_consumers(&self) -> Result<Vec<ConsumerRecord>> {
        let conn = self.conn.lock().expect("store connection poisoned");
        let mut stmt =
            conn.prepare("SELECT id, name, priority, created_at FROM consumers ORDER BY name")?;
        let rows = stmt.query_map([], row_to_consumer)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Add a credential with a PRE-HASHED value. The store never sees
    /// plaintext secrets: hashing and selector derivation are the
    /// authenticator's job (DW-019). The selector's cache entry is
    /// invalidated so the next lookup reflects the new credential.
    pub fn add_credential(
        &self,
        consumer_id: i64,
        kind: CredentialKind,
        hash: String,
        salt: Option<String>,
        selector: String,
    ) -> Result<CredentialRecord> {
        let now = now_secs();
        let conn = self.conn.lock().expect("store connection poisoned");
        let consumer_name: Option<String> = conn
            .query_row(
                "SELECT name FROM consumers WHERE id = ?1",
                params![consumer_id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(consumer_name) = consumer_name else {
            return Err(StoreError::UnknownConsumer(format!("id {consumer_id}")));
        };
        conn.execute(
            "INSERT INTO credentials
                 (consumer_id, kind, hash, salt, selector, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![consumer_id, kind.as_str(), hash, salt, selector, now],
        )?;
        let id = conn.last_insert_rowid();
        drop(conn);
        self.invalidate(&selector);
        Ok(CredentialRecord {
            id,
            consumer_id,
            consumer_name,
            kind,
            hash,
            salt,
            selector: selector.clone(),
            created_at: now,
            revoked_at: None,
        })
    }

    /// Revoke a credential by id; returns whether a row was revoked.
    /// Idempotent (revoking a revoked credential returns false). The
    /// selector's cache entry is invalidated so the next lookup reflects
    /// the revocation.
    pub fn revoke_credential(&self, credential_id: i64) -> Result<bool> {
        let now = now_secs();
        let conn = self.conn.lock().expect("store connection poisoned");
        let selector: Option<String> = conn
            .query_row(
                "SELECT selector FROM credentials WHERE id = ?1 AND revoked_at IS NULL",
                params![credential_id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(selector) = selector else {
            return Ok(false);
        };
        conn.execute(
            "UPDATE credentials SET revoked_at = ?2 WHERE id = ?1",
            params![credential_id, now],
        )?;
        drop(conn);
        self.invalidate(&selector);
        Ok(true)
    }

    /// Disk lookup: all ACTIVE credentials for a selector (revoked rows
    /// are ignored). Cold path; feeds the cache.
    pub fn lookup_credentials_by_selector(&self, selector: &str) -> Result<Vec<CredentialRecord>> {
        let conn = self.conn.lock().expect("store connection poisoned");
        let mut stmt = conn.prepare(
            "SELECT c.id, c.consumer_id, k.name, c.kind, c.hash, c.salt,
                    c.selector, c.created_at
             FROM credentials c JOIN consumers k ON k.id = c.consumer_id
             WHERE c.selector = ?1 AND c.revoked_at IS NULL
             ORDER BY c.id",
        )?;
        let rows = stmt.query_map(params![selector], row_to_credential)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// HOT PATH: look up the active credentials for a selector. Cache hit
    /// performs ZERO SQLite work (an `RwLock` read and an `Arc` clone).
    /// Miss reads disk once and fills the cache, including a cached
    /// NEGATIVE result (empty list) for unknown selectors.
    pub fn lookup_credential(
        &self,
        selector: &str,
    ) -> Result<Option<Arc<Vec<Arc<CredentialRecord>>>>> {
        {
            let cache = self.cache.credentials.read().expect("cache poisoned");
            if let Some(entry) = cache.get(selector).map(Arc::clone) {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(Some(entry));
            }
        }
        self.disk_reads.fetch_add(1, Ordering::Relaxed);
        let records = self.lookup_credentials_by_selector(selector)?;
        let entry = Arc::new(
            records
                .into_iter()
                .map(Arc::new)
                .collect::<Vec<Arc<CredentialRecord>>>(),
        );
        self.cache
            .credentials
            .write()
            .expect("cache poisoned")
            .insert(selector.to_string(), Arc::clone(&entry));
        Ok(Some(entry))
    }

    /// Consumer lookup by name. Cached on hit (same counter rules as
    /// [`Self::lookup_credential`]); unlike credentials there is no negative
    /// caching — consumer-by-name lookups are a control-plane path, so an
    /// unknown name re-reads disk.
    pub fn lookup_consumer(&self, name: &str) -> Result<Option<Arc<ConsumerRecord>>> {
        {
            let cache = self.cache.consumers.read().expect("cache poisoned");
            if let Some(entry) = cache.get(name).map(Arc::clone) {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(Some(entry));
            }
        }
        self.disk_reads.fetch_add(1, Ordering::Relaxed);
        let conn = self.conn.lock().expect("store connection poisoned");
        let row: Option<(i64, String, Option<u8>, i64)> = conn
            .query_row(
                "SELECT id, name, priority, created_at FROM consumers WHERE name = ?1",
                params![name],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        drop(conn);
        let record = row.map(|(id, name, priority, created_at)| {
            Arc::new(ConsumerRecord {
                id,
                name,
                priority,
                created_at,
            })
        });
        if let Some(record) = &record {
            self.cache
                .consumers
                .write()
                .expect("cache poisoned")
                .insert(name.to_string(), Arc::clone(record));
        }
        Ok(record)
    }

    /// Invalidate one selector's cache entry (next lookup re-reads disk).
    pub fn invalidate(&self, selector: &str) {
        self.cache
            .credentials
            .write()
            .expect("cache poisoned")
            .remove(selector);
    }

    /// Invalidate every cache entry (next lookup of anything re-reads disk).
    pub fn invalidate_all(&self) {
        self.cache
            .credentials
            .write()
            .expect("cache poisoned")
            .clear();
        self.cache
            .consumers
            .write()
            .expect("cache poisoned")
            .clear();
    }

    /// Atomically add `amount` to a quota counter, refusing the increment
    /// (writing nothing) when it would exceed `limit`. Returns the
    /// used-after value. Window semantics are caller-driven: a new
    /// `window_start` is a NEW counter (rollover = call with the next
    /// window's start).
    pub fn incr_quota(
        &self,
        consumer_id: i64,
        counter_key: &str,
        window_start: i64,
        amount: u64,
        limit: Option<u64>,
    ) -> Result<u64> {
        let conn = self.conn.lock().expect("store connection poisoned");
        // Pre-check the consumer so an unknown id surfaces as a typed
        // error instead of a raw SQLite FK violation on insert below.
        let exists: Option<()> = conn
            .query_row(
                "SELECT 1 FROM consumers WHERE id = ?1",
                params![consumer_id],
                |_| Ok(()),
            )
            .optional()?;
        if exists.is_none() {
            return Err(StoreError::UnknownConsumer(format!("id {consumer_id}")));
        }
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO quota_counters (consumer_id, counter_key, window_start, used)
             VALUES (?1, ?2, ?3, 0)
             ON CONFLICT (consumer_id, counter_key, window_start) DO NOTHING",
            params![consumer_id, counter_key, window_start],
        )?;
        // Opportunistic retention: counter rows accumulate one per
        // (consumer, key, window) forever without pruning. Rows older
        // than the newest window by more than QUOTA_RETENTION_SECS
        // (1 year) can no longer be part of any live window and are
        // deleted here. Pruning against the newest window in the table
        // (not "now") keeps the horizon independent of clock skew and
        // caller window scales; worst case with hourly windows the
        // table holds ~8760 rows per counter key.
        tx.execute(
            "DELETE FROM quota_counters
             WHERE window_start < (SELECT MAX(window_start) FROM quota_counters) - ?1",
            params![QUOTA_RETENTION_SECS],
        )?;
        let used: u64 = tx.query_row(
            "SELECT used FROM quota_counters
             WHERE consumer_id = ?1 AND counter_key = ?2 AND window_start = ?3",
            params![consumer_id, counter_key, window_start],
            |r| r.get(0),
        )?;
        if let Some(limit) = limit {
            let Some(next) = used.checked_add(amount) else {
                return Err(StoreError::QuotaExceeded {
                    used,
                    limit,
                    requested: amount,
                });
            };
            if next > limit {
                return Err(StoreError::QuotaExceeded {
                    used,
                    limit,
                    requested: amount,
                });
            }
        }
        tx.execute(
            "UPDATE quota_counters SET used = used + ?4
             WHERE consumer_id = ?1 AND counter_key = ?2 AND window_start = ?3",
            params![consumer_id, counter_key, window_start, amount],
        )?;
        let used_after: u64 = tx.query_row(
            "SELECT used FROM quota_counters
             WHERE consumer_id = ?1 AND counter_key = ?2 AND window_start = ?3",
            params![consumer_id, counter_key, window_start],
            |r| r.get(0),
        )?;
        tx.commit()?;
        Ok(used_after)
    }

    /// Read the current usage of a quota counter (0 when absent).
    pub fn get_quota(&self, consumer_id: i64, counter_key: &str, window_start: i64) -> Result<u64> {
        let conn = self.conn.lock().expect("store connection poisoned");
        let used: Option<u64> = conn
            .query_row(
                "SELECT used FROM quota_counters
                 WHERE consumer_id = ?1 AND counter_key = ?2 AND window_start = ?3",
                params![consumer_id, counter_key, window_start],
                |r| r.get(0),
            )
            .optional()?;
        Ok(used.unwrap_or(0))
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn row_to_consumer(r: &rusqlite::Row<'_>) -> rusqlite::Result<ConsumerRecord> {
    Ok(ConsumerRecord {
        id: r.get(0)?,
        name: r.get(1)?,
        priority: r.get(2)?,
        created_at: r.get(3)?,
    })
}

fn row_to_credential(r: &rusqlite::Row<'_>) -> rusqlite::Result<CredentialRecord> {
    let kind_str: String = r.get(3)?;
    Ok(CredentialRecord {
        id: r.get(0)?,
        consumer_id: r.get(1)?,
        consumer_name: r.get(2)?,
        kind: CredentialKind::from_str(&kind_str).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Text,
                format!("unknown credential kind {kind_str}").into(),
            )
        })?,
        hash: r.get(4)?,
        salt: r.get(5)?,
        selector: r.get(6)?,
        created_at: r.get(7)?,
        revoked_at: None,
    })
}

/// Bootstrap the store from the gateway config (DW-018 interim seeding).
///
/// Creates/updates every consumer found in the config and inserts a
/// credential row for each config credential that is not already present
/// (matched by consumer + selector, so re-syncing is idempotent).
///
/// HONESTY NOTE on hashes: config credentials today carry plaintext-ish
/// values (`api_key: <value>`); credential HASHING lands with the
/// authenticator (DW-019). Until then, seeded rows store a placeholder
/// hash derived from the config value and the SELECTOR is the config
/// value itself (api key value / JWT issuer / mTLS fingerprint). This
/// means config-based credentials remain CONFIG-authenticated: the store
/// rows exist so the schema, seeding, and cache paths are exercised, not
/// so the dataplane authenticates against them. DW-019 replaces the
/// placeholder with a real hash and the authenticator's selector scheme.
pub fn sync_consumers_from_config(store: &StateStore, gateway: &Gateway) -> Result<()> {
    for consumer in &gateway.consumers {
        let record = store.upsert_consumer(&consumer.name, consumer.priority)?;
        for credential in &consumer.credentials {
            let (kind, selector) = credential_parts(credential);
            let existing = store.lookup_credentials_by_selector(&selector)?;
            if existing
                .iter()
                .any(|c| c.consumer_id == record.id && c.kind == kind)
            {
                continue;
            }
            let placeholder_hash = format!("config:{}:{selector}", kind.as_str());
            store.add_credential(record.id, kind, placeholder_hash, None, selector.clone())?;
        }
    }
    Ok(())
}

fn credential_parts(credential: &Credential) -> (CredentialKind, String) {
    match credential {
        Credential::ApiKey { key } => (CredentialKind::ApiKey, key.clone()),
        Credential::Jwt { issuer, .. } => (CredentialKind::Jwt, issuer.clone()),
        Credential::Mtls { fingerprint } => (CredentialKind::Mtls, fingerprint.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_gateway;

    fn seeded_store() -> StateStore {
        let store = StateStore::open_in_memory().unwrap();
        store.upsert_consumer("acme", Some(7)).unwrap();
        store
    }

    #[test]
    fn consumer_roundtrip_in_memory_and_on_disk() {
        let store = StateStore::open_in_memory().unwrap();
        let a = store.upsert_consumer("acme", Some(7)).unwrap();
        assert_eq!(a.name, "acme");
        assert_eq!(a.priority, Some(7));
        let listed = store.list_consumers().unwrap();
        assert_eq!(listed, vec![a.clone()]);

        let dir = tempfile::tempdir().unwrap();
        let disk = StateStore::open(&dir.path().join("state.db")).unwrap();
        let b = disk.upsert_consumer("acme", None).unwrap();
        assert_eq!(b.name, "acme");
        // Reopen the same file: the row persisted, schema not recreated.
        let disk2 = StateStore::open(&dir.path().join("state.db")).unwrap();
        assert_eq!(disk2.list_consumers().unwrap(), vec![b]);
    }

    #[test]
    fn consumer_name_is_unique_via_upsert() {
        let store = StateStore::open_in_memory().unwrap();
        store.upsert_consumer("acme", None).unwrap();
        store.upsert_consumer("acme", Some(9)).unwrap();
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
    fn seeding_from_config_is_idempotent_and_honest() {
        let config = parse_gateway(
            "consumers:\n  - name: acme\n    priority: 3\n    credentials:\n      - \
             type: api_key\n        key: secret-key\n      - type: jwt\n        issuer: \
             https://issuer.example\n      - type: mtls\n        fingerprint: AA:BB\n",
        )
        .unwrap();
        let store = StateStore::open_in_memory().unwrap();
        sync_consumers_from_config(&store, &config).unwrap();
        sync_consumers_from_config(&store, &config).unwrap(); // re-sync: no dupes
        let listed = store.list_consumers().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].priority, Some(3));
        let api = store.lookup_credentials_by_selector("secret-key").unwrap();
        assert_eq!(api.len(), 1);
        assert_eq!(api[0].kind, CredentialKind::ApiKey);
        // Placeholder hash, not a real digest: documented DW-019 gap.
        assert_eq!(api[0].hash, "config:api_key:secret-key");
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
        let a = store.upsert_consumer("acme", Some(1)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let b = store.upsert_consumer("acme", Some(2)).unwrap();
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
    fn quota_prunes_rows_older_than_retention_horizon() {
        let store = seeded_store();
        let consumer = store.lookup_consumer("acme").unwrap().unwrap();
        let now = now_secs();
        // Seed a stale row (older than the newest window by > 1 year) and
        // a recent one; the next quota write prunes only the stale row.
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO quota_counters VALUES (?1, 'rpm', ?2, 42)",
                params![consumer.id, now - 2 * QUOTA_RETENTION_SECS],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO quota_counters VALUES (?1, 'rpm', ?2, 0)
                 ON CONFLICT (consumer_id, counter_key, window_start) DO NOTHING",
                params![consumer.id, now],
            )
            .unwrap();
        }
        assert_eq!(
            store
                .get_quota(consumer.id, "rpm", now - 2 * QUOTA_RETENTION_SECS)
                .unwrap(),
            42
        );
        store.incr_quota(consumer.id, "rpm", now, 1, None).unwrap();
        assert_eq!(
            store
                .get_quota(consumer.id, "rpm", now - 2 * QUOTA_RETENTION_SECS)
                .unwrap(),
            0
        );
        assert_eq!(store.get_quota(consumer.id, "rpm", now).unwrap(), 1);
    }

    #[test]
    fn schema_is_version_one() {
        let store = StateStore::open_in_memory().unwrap();
        let conn = store.conn.lock().unwrap();
        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 1);
    }
}
