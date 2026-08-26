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
//! # Schema and migrations
//!
//! The schema is created and evolved by the versioned, transactional
//! migration set in [`crate::migrations`] (DW-115): opening a store
//! applies all pending migrations automatically, taking a file backup
//! first (see [`StateStore::open`]). A database whose `user_version` is
//! NEWER than this build supports is refused. All writes are
//! transactional; WAL journal mode and foreign-key enforcement are on.
//!
//! The store NEVER sees plaintext secrets: credential values arrive
//! pre-hashed with a lookup `selector` (a hash for API keys/Basic since
//! DW-019, or a JWT kid/issuer / certificate fingerprint for bindings).
//! Hashing is the authenticator's job (DW-019); config-seeded keys are
//! hashed at seed time (see [`sync_consumers_from_config`]).

use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use rusqlite::{params, Connection, OptionalExtension};

use crate::config::{Credential, Gateway};
use crate::migrations::{migrations, SchemaInfo, LATEST_SCHEMA_VERSION};

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

/// Manual `Debug`: the connection and cache have no meaningful debug
/// output; tests use it only for `unwrap_err` on open (error-side Debug).
impl fmt::Debug for StateStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateStore").finish_non_exhaustive()
    }
}

impl StateStore {
    /// Open (or create) a store at `path`, applying pending migrations.
    ///
    /// ## Backup before migrate (DW-115)
    ///
    /// If the database's schema version is behind this build, a consistent
    /// snapshot is taken via `VACUUM INTO` to
    /// `<path>.bak-<old-version>-<unix-seconds>-<millis>` (millisecond
    /// component disambiguates same-second migrations) BEFORE any
    /// migration runs. Failure to create the backup ABORTS the open: no migration
    /// proceeds without a safety copy. (A brand-new, empty database and
    /// in-memory stores skip this — there is no data to lose.)
    ///
    /// ## Refusal rules
    ///
    /// A database whose `user_version` is NEWER than this build supports
    /// is refused with a clear error (downgrade attempts; the migration
    /// set is forward-only — see [`crate::migrations`] for the rebuild
    /// path).
    ///
    /// ## Permissions
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
        Self::init(conn, Some(path))
    }

    /// Open an in-memory store (tests and tooling).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn, None)
    }

    fn init(conn: Connection, path: Option<&Path>) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // Contended writers wait up to 5 s instead of failing immediately
        // with SQLITE_BUSY (this store is single-writer, but a second
        // handle/process on the same file is possible in tooling).
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > i64::from(LATEST_SCHEMA_VERSION) {
            return Err(StoreError::Sqlite(format!(
                "state db schema version {version} is newer than this build supports ({LATEST_SCHEMA_VERSION})"
            )));
        }
        let mut conn = conn;
        if version < i64::from(LATEST_SCHEMA_VERSION) {
            // version 0 = brand-new (or empty) database: migration 001
            // builds the base schema and there is no data to lose, so no
            // backup is taken. Any database that already HAS a schema
            // (version >= 1) gets a backup before the first change.
            if version > 0 {
                if let Some(path) = path {
                    backup_before_migrate(&conn, path, version)?;
                }
            }
            migrations()
                .to_latest(&mut conn)
                .map_err(|e| StoreError::Sqlite(format!("migration failed: {e}")))?;
        }
        Ok(Self {
            conn: Mutex::new(conn),
            cache: HotCache::default(),
            disk_reads: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
        })
    }

    /// Current schema version of the open database (`PRAGMA user_version`).
    /// After [`Self::open`] this always equals
    /// [`crate::migrations::LATEST_SCHEMA_VERSION`].
    pub fn schema_version(&self) -> Result<u32> {
        let conn = self.conn.lock().expect("store connection poisoned");
        let v: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        u32::try_from(v)
            .map_err(|_| StoreError::Sqlite(format!("schema version {v} out of u32 range")))
    }

    /// Current-vs-latest schema info. Seam for the admin API (DW-022):
    /// `current` is read live, `latest` is what this build can migrate to.
    pub fn schema_info(&self) -> Result<SchemaInfo> {
        Ok(SchemaInfo {
            current: self.schema_version()?,
            latest: LATEST_SCHEMA_VERSION,
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

    /// Legacy-cleanup rule (DW-019 review): databases seeded by the
    /// pre-DW-019 build hold api_key rows whose SELECTOR is the plaintext
    /// config key and whose hash is the placeholder
    /// `config:api_key:<key>` — both embed the secret verbatim, and
    /// without this cleanup they would sit in the store forever (the
    /// post-DW-019 seeding writes a sha256 selector/hash and never
    /// matches them, so the idempotence check skips them). This build
    /// never writes that format, so every matching row is transitional
    /// and is deleted here. A schema migration is overkill for one
    /// build's placeholder rows: a code-level cleanup at sync time is
    /// sufficient, runs everywhere sync runs (deployments with or
    /// without a state DB), and needs no version bump. JWT/mTLS binding
    /// rows (`config:jwt:` / `config:mtls:`) are NOT deleted — those are
    /// the current, non-secret binding-marker format. Returns the number
    /// of rows deleted (0 on a clean or fresh database).
    pub fn delete_legacy_config_placeholder_credentials(&self) -> Result<u64> {
        let conn = self.conn.lock().expect("store connection poisoned");
        let selectors: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT selector FROM credentials WHERE hash LIKE 'config:api_key:%'")?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        if selectors.is_empty() {
            return Ok(0);
        }
        let deleted = u64::try_from(conn.execute(
            "DELETE FROM credentials WHERE hash LIKE 'config:api_key:%'",
            [],
        )?)
        .unwrap_or(u64::MAX);
        drop(conn);
        for selector in selectors {
            self.invalidate(&selector);
        }
        Ok(deleted)
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
            sql_u64_row,
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
            params![
                consumer_id,
                counter_key,
                window_start,
                i64::try_from(amount).unwrap_or(i64::MAX)
            ],
        )?;
        let used_after: u64 = tx.query_row(
            "SELECT used FROM quota_counters
             WHERE consumer_id = ?1 AND counter_key = ?2 AND window_start = ?3",
            params![consumer_id, counter_key, window_start],
            sql_u64_row,
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
                sql_u64_row,
            )
            .optional()?;
        Ok(used.unwrap_or(0))
    }
}

/// Row mapper for `used` counters (SQLite INTEGER -> u64). rusqlite 0.38
/// dropped the u64 FromSql impl, so quota counters convert at the SQL
/// boundary; negative values cannot occur (counters only increment from 0).
fn sql_u64_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<u64> {
    let v: i64 = r.get(0)?;
    u64::try_from(v).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, v))
}

/// Backup file name for a pre-migration snapshot: `<file>.bak-<version>-<unix-seconds>-<millis>`.
/// The millisecond component disambiguates backups taken within the same
/// second (a seconds-only name made a same-second retry collide with the
/// previous attempt's file, making `VACUUM INTO` fail on the existing
/// target and the retry look like a persistent fault).
fn backup_file_name(path: &Path, version: i64, now: std::time::SystemTime) -> String {
    let dur = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!(
        "{}.bak-{version}-{}-{}",
        path.file_name()
            .map(std::ffi::OsStr::to_string_lossy)
            .unwrap_or_else(|| "state.db".into()),
        dur.as_secs(),
        dur.subsec_millis()
    )
}

/// Take a consistent pre-migration snapshot of the database at `path`
/// (schema `version`) into the name built by [`backup_file_name`] using
/// `VACUUM INTO`, which the SQLite backup API backs and which includes
/// all committed WAL content at the moment it runs. Any failure is
/// returned (and any PARTIAL target removed — a truncated snapshot on
/// disk is silent-corruption bait for a restore): the caller aborts the
/// open rather than migrating unbacked.
fn backup_before_migrate(conn: &Connection, path: &Path, version: i64) -> Result<()> {
    let file_name = backup_file_name(path, version, std::time::SystemTime::now());
    let backup_path = path.with_file_name(file_name);
    // Single-quote escaping for the SQL string literal.
    let escaped = backup_path.to_string_lossy().replace('\'', "''");
    conn.execute_batch(&format!("VACUUM INTO '{escaped}';"))
        .map_err(|e| {
            // Best-effort cleanup: VACUUM INTO may leave a partial file
            // when it fails mid-way; restoring a truncated snapshot would
            // silently corrupt the database, so remove it.
            let _ = std::fs::remove_file(&backup_path);
            StoreError::Sqlite(format!(
                "refusing to migrate: backup to {} failed: {e}",
                backup_path.display()
            ))
        })?;
    Ok(())
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

/// Bootstrap the store from the gateway config (DW-018 seeding, hashing
/// per DW-019).
///
/// Creates/updates every consumer found in the config and inserts a
/// credential row for each config credential that is not already present
/// (matched by consumer + selector, so re-syncing is idempotent).
///
/// Hashing (DW-019): config API keys are hashed at seed time — the
/// selector is `hex(sha256(key))` (never the plaintext key; this closes
/// the DW-018 finding that seeded selectors were raw config values) and
/// the stored hash is `sha256:<hex(sha256(key))>`, the format the
/// authenticator's constant-time verifier expects. JWT and mTLS config
/// credentials are BINDINGS, not secrets (tokens are verified
/// cryptographically; client certificates by fingerprint), so their rows
/// keep a binding-marker hash and the issuer/fingerprint selector.
///
/// Legacy cleanup: rows seeded by the pre-DW-019 build (plaintext api-key
/// selector + `config:api_key:` placeholder hash) are deleted on every
/// sync — see
/// [`StateStore::delete_legacy_config_placeholder_credentials`].
pub fn sync_consumers_from_config(store: &StateStore, gateway: &Gateway) -> Result<()> {
    store.delete_legacy_config_placeholder_credentials()?;
    for consumer in &gateway.consumers {
        let record = store.upsert_consumer(&consumer.name, consumer.priority)?;
        for credential in &consumer.credentials {
            let (kind, selector, hash) = credential_parts(credential);
            let existing = store.lookup_credentials_by_selector(&selector)?;
            if existing
                .iter()
                .any(|c| c.consumer_id == record.id && c.kind == kind)
            {
                continue;
            }
            store.add_credential(record.id, kind, hash, None, selector.clone())?;
        }
    }
    Ok(())
}

fn credential_parts(credential: &Credential) -> (CredentialKind, String, String) {
    match credential {
        Credential::ApiKey { key } => (
            CredentialKind::ApiKey,
            crate::authn::credential_selector(key),
            crate::authn::sha256_stored_hash(key),
        ),
        Credential::Jwt { issuer, .. } => (
            CredentialKind::Jwt,
            issuer.clone(),
            format!("config:jwt:{issuer}"),
        ),
        Credential::Mtls { fingerprint } => (
            CredentialKind::Mtls,
            fingerprint.clone(),
            format!("config:mtls:{fingerprint}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn seeded_store() -> StateStore {
        let store = StateStore::open_in_memory().unwrap();
        store.upsert_consumer("acme", Some(7)).unwrap();
        store
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
    fn v1_db_migrates_to_latest_with_zero_data_loss() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        build_v1_db(&path);

        // Opening migrates automatically...
        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
        // ...with every v1 row intact: consumer (and its priority),
        let consumers = store.list_consumers().unwrap();
        assert_eq!(consumers.len(), 1);
        assert_eq!(consumers[0].name, "acme");
        assert_eq!(consumers[0].priority, Some(5));
        assert_eq!(consumers[0].created_at, 1000);
        // active credential,
        let active = store.lookup_credentials_by_selector("key-1").unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].hash, "h1");
        assert_eq!(active[0].kind, CredentialKind::ApiKey);
        // quota data,
        assert_eq!(store.get_quota(1, "rpm", 3600).unwrap(), 42);
        // and the 002 index exists.
        {
            let conn = store.conn.lock().unwrap();
            let n: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index'
                     AND name = 'idx_quota_counters_window'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 1);
        }
        // The store remains writable post-migration (idempotent upsert).
        store.upsert_consumer("acme", Some(6)).unwrap();
        assert_eq!(store.list_consumers().unwrap()[0].priority, Some(6));
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
    fn migration_preserves_every_row_and_the_hot_path_still_works() {
        // DATA FIDELITY (deep): every row of a rich v1 database is
        // value-identical after migration, revoked credentials stay
        // revoked (invisible to lookups), quota counters read back exact,
        // and the migrated store's hot cache behaves: one disk read to
        // warm, then zero-disk hits.
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

        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
        {
            let conn = store.conn.lock().expect("store connection poisoned");
            assert_eq!(dump_table(&conn, "consumers"), before.0);
            assert_eq!(dump_table(&conn, "credentials"), before.1);
            assert_eq!(dump_table(&conn, "quota_counters"), before.2);
        }

        // Both consumers present with their exact fields.
        let consumers = store.list_consumers().unwrap();
        assert_eq!(consumers.len(), 2);
        let globex = store.lookup_consumer("globex").unwrap().unwrap();
        assert_eq!(globex.priority, None);
        assert_eq!(globex.created_at, 1001);

        // Active selectors resolve; the REVOKED selector resolves to
        // nothing (revoked_at 5555 survived and keeps excluding it).
        assert_eq!(
            store.lookup_credentials_by_selector("key-1").unwrap().len(),
            1
        );
        assert_eq!(
            store.lookup_credentials_by_selector("key-3").unwrap().len(),
            1
        );
        assert!(
            store
                .lookup_credentials_by_selector("key-2")
                .unwrap()
                .is_empty(),
            "revoked credential must stay revoked after migration"
        );

        // Every quota counter reads back its exact value.
        assert_eq!(store.get_quota(1, "rpm", 3600).unwrap(), 42);
        assert_eq!(store.get_quota(1, "rpm", 7200).unwrap(), 7);
        assert_eq!(store.get_quota(1, "rpd", 86400).unwrap(), 900);
        assert_eq!(store.get_quota(2, "rpm", 3600).unwrap(), 1);
        assert_eq!(store.get_quota(2, "monthly", 2678400).unwrap(), 123456);

        // Hot path: first lookup costs one disk read, subsequent ones zero.
        let reads_before = store.disk_reads();
        let entry = store.lookup_credential("key-1").unwrap().unwrap();
        assert_eq!(entry.len(), 1);
        assert_eq!(store.disk_reads(), reads_before + 1);
        for _ in 0..3 {
            let again = store.lookup_credential("key-1").unwrap().unwrap();
            assert_eq!(again.len(), 1);
        }
        assert_eq!(
            store.disk_reads(),
            reads_before + 1,
            "warm cache must be disk-free post-migration"
        );
    }

    #[test]
    fn rapid_reopen_and_two_live_handles_on_one_migrated_file() {
        // Single-process concurrency doc: after migration, an immediate
        // second open sees the latest schema without error, and two LIVE
        // handles on the same file coexist (WAL + busy_timeout): a write
        // through one is visible to the other, no corruption.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        build_v1_db(&path);

        let a = StateStore::open(&path).unwrap();
        assert_eq!(a.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
        drop(a); // close, then IMMEDIATELY reopen the same file
        let b = StateStore::open(&path).unwrap();
        assert_eq!(b.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
        assert_eq!(b.get_quota(1, "rpm", 3600).unwrap(), 42);

        // Two handles alive at once: write through the second...
        let c = StateStore::open(&path).unwrap();
        c.upsert_consumer("globex", Some(9)).unwrap();
        c.add_credential(1, CredentialKind::ApiKey, "hx".into(), None, "key-x".into())
            .unwrap();
        // ...read committed state through the first.
        let names: Vec<String> = b
            .list_consumers()
            .unwrap()
            .into_iter()
            .map(|r| r.name)
            .collect();
        assert!(names.contains(&"globex".to_string()), "names: {names:?}");
        assert_eq!(b.lookup_credentials_by_selector("key-x").unwrap().len(), 1);
        // And the file still passes SQLite's own consistency check.
        let check: String = c
            .conn
            .lock()
            .unwrap()
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(check, "ok");
    }

    #[test]
    fn version_zero_database_with_foreign_tables_migrates_without_harming_them() {
        // EDGE: user_version 0 but NOT empty (an older unrelated app left
        // tables). Pinned behavior: 001's IF NOT EXISTS builds our schema
        // alongside the foreign tables (which survive untouched), the
        // database lands at latest, and no backup is taken because
        // version 0 means "no recognized schema to lose".
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE legacy_widgets (
                     id INTEGER PRIMARY KEY,
                     label TEXT NOT NULL
                 );
                 INSERT INTO legacy_widgets (label) VALUES ('keep-me');",
            )
            .unwrap();
        }

        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
        // The foreign table and its row survived verbatim.
        let label: String = store
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT label FROM legacy_widgets WHERE id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(label, "keep-me");
        // Our schema is fully usable next to it.
        store.upsert_consumer("acme", None).unwrap();
        assert_eq!(store.list_consumers().unwrap().len(), 1);
        // version 0 -> no backup (nothing recognized to back up).
        assert!(
            all_backups(dir.path()).is_empty(),
            "version-0 open must not take a backup"
        );
    }

    #[test]
    fn backup_names_are_unique_within_the_same_second() {
        // The name generator carries a millisecond component, so two
        // snapshots in the same wall-clock second get distinct files (a
        // seconds-only name made a same-second retry collide with the
        // previous attempt's file, and VACUUM INTO refuses an existing
        // target).
        let path = Path::new("/data/state.db");
        let t0 = std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_700_000_000_123);
        let a = backup_file_name(path, 1, t0);
        let b = backup_file_name(path, 1, t0 + std::time::Duration::from_millis(1));
        assert_eq!(a, "state.db.bak-1-1700000000-123");
        assert_eq!(b, "state.db.bak-1-1700000000-124");
        assert_ne!(a, b, "same-second backups must not collide");
    }

    #[test]
    fn post_migration_pragmas_stay_configured() {
        // PRAGMA state after a migration open: WAL journaling, FK
        // enforcement, and the 5 s busy_timeout must all still be set
        // (they are applied before migrations and must survive them).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        build_v1_db(&path);
        let store = StateStore::open(&path).unwrap();
        let conn = store.conn.lock().expect("store connection poisoned");
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fk, 1, "foreign_keys must be ON post-migration");
        let timeout_ms: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(timeout_ms, 5000, "busy_timeout must be 5 s post-migration");
    }
}
