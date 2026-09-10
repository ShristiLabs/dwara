//! Distributed nonce store (SEC-06, #210, Enterprise).
//!
//! When the gateway runs as a fleet behind a load balancer, the
//! per-verifier in-process nonce cache (signed_url::NonceCache) only
//! protects against replay within a single instance. A nonce
//! presented to instance A and replayed to instance B is not
//! detected. This module provides a Redis-backed distributed nonce
//! store so replay detection is shared across the fleet.
//!
//! ## Feature gate
//!
//! The `ent` cargo feature must be enabled. Without it, the module
//! is not compiled and the gateway uses the OSS in-process nonce
//! cache.

use async_trait::async_trait;
use redis::aio::ConnectionManager;

use crate::extensions::ExtensionsError;

/// A distributed nonce store: check-and-record a one-time nonce
/// across the gateway fleet.
#[async_trait]
pub trait NonceStore: Send + Sync {
    /// Check and record a nonce. Returns `true` if the nonce is
    /// fresh (not seen before, or the previous entry has expired),
    /// `false` if it is a replay within the validity window. The
    /// `expires` Unix epoch seconds sets the Redis TTL so entries
    /// auto-expire without a sweep.
    async fn check_and_record(&self, nonce: &str, expires: u64) -> Result<bool, ExtensionsError>;
}

/// A Redis-backed distributed nonce store (SEC-06, #210).
///
/// Uses `SET key value NX EX ttl` (atomic check-and-set with TTL) so
/// the check-and-record is atomic: if the key already exists, the
/// `NX` flag causes the SET to fail, indicating a replay. The TTL
/// is set to `expires - now` so the entry auto-expires when the
/// signed URL's validity window ends.
pub struct RedisNonceStore {
    conn: ConnectionManager,
    prefix: String,
}

impl RedisNonceStore {
    /// Create a new Redis nonce store.
    ///
    /// `url` is the Redis connection URL (e.g. "redis://127.0.0.1:6379").
    /// `prefix` is the key prefix (e.g. "dwara:nonce:").
    pub async fn new(url: &str, prefix: &str) -> Result<Self, ExtensionsError> {
        let client = redis::Client::open(url)
            .map_err(|e| ExtensionsError::Backend(format!("redis connect: {e}")))?;
        let conn = ConnectionManager::new(client)
            .await
            .map_err(|e| ExtensionsError::Backend(format!("redis connect: {e}")))?;
        Ok(Self {
            conn,
            prefix: prefix.to_string(),
        })
    }

    /// Create a new Redis nonce store from an existing connection
    /// manager (for testing or sharing a connection pool).
    pub fn with_conn(conn: ConnectionManager, prefix: &str) -> Self {
        Self {
            conn,
            prefix: prefix.to_string(),
        }
    }

    fn full_key(&self, nonce: &str) -> String {
        format!("{}{nonce}", self.prefix)
    }
}

#[async_trait]
impl NonceStore for RedisNonceStore {
    async fn check_and_record(&self, nonce: &str, expires: u64) -> Result<bool, ExtensionsError> {
        let mut conn = self.conn.clone();
        let key = self.full_key(nonce);
        // SET key "1" NX EX <ttl> — atomic check-and-set with TTL.
        // Returns "OK" if the key was set (fresh nonce), nil if the
        // key already exists (replay).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let ttl = expires.saturating_sub(now).max(1) as i64;
        let result: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(ttl)
            .query_async(&mut conn)
            .await
            .map_err(|e| ExtensionsError::Backend(format!("redis set: {e}")))?;
        Ok(result.is_some())
    }
}
