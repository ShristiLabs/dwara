//! Config convergence backend extension point (DW-054, ent feature only).
//!
//! # Contract: [`ConfigConvergenceBackend`]
//!
//! **Purpose:** share config generation state across gateway instances so
//! two or more processes converge to the highest published generation
//! within the configured poll interval, and so drift (instances serving
//! different configs) is detected and reported.
//!
//! **Semantics:** the backend is a read/write store of two things:
//!
//! - per-instance generation records (instance id, generation, config
//!   hash, timestamp), keyed by instance id; and
//! - per-generation config bodies (the normalized YAML), keyed by
//!   generation number.
//!
//! `publish_generation` upserts THIS instance's record and stores the
//! config body for that generation (so a remote instance can load it).
//! `watch_generations` reads every instance's current record (the poll
//! the coordinator runs at `poll_interval_ms`). `load_config` fetches a
//! generation's YAML so a remote change can be re-published locally
//! through `compile_and_publish`. `remove_instance` deletes this
//! instance's record on shutdown so the cluster view does not list a
//! dead instance.
//!
//! **Failure model:** backend failures map to [`ConvergenceError`]. The
//! coordinator applies the configured `fail_open` policy: `true` (the
//! default) keeps serving the local config and pauses convergence until
//! the backend recovers; `false` refuses to start at cold start.
//!
//! **Editions:** v1 ships [`RedisConvergenceBackend`] (the `redis` crate,
//! already an optional dep for DW-031). etcd and Consul backends are
//! deferred -- this trait is the seam they plug into, implementing the
//! same five methods against their native clients. The trait is
//! dyn-compatible (used as `Arc<dyn ConfigConvergenceBackend>`); methods
//! are `async` via `async-trait` for the same dyn-compatibility reason
//! as the other extension traits.
//!
//! # Key format (Redis)
//!
//! Instance records live in a Redis hash at `{prefix}:instances` (one
//! field per instance id, value a `|`-joined `generation|config_hash|
//! timestamp`). Config bodies live at `{prefix}:config:{generation}`.
//! A TTL on the instances hash keeps stale instances from lingering
//! (a graceful shutdown removes the field; a crash leaves it to expire).

use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use redis::aio::ConnectionManager;

use super::ExtensionsError;

/// One instance's currently published config generation (DW-054).
///
/// Returned by [`ConfigConvergenceBackend::watch_generations`] for every
/// instance the backend knows about. The coordinator compares
/// `config_hash` across instances to detect drift and `generation` to
/// pick the highest to converge to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceGeneration {
    /// The instance's unique id (the coordinator generates one per
    /// process).
    pub instance_id: String,
    /// The generation number this instance is currently serving.
    pub generation: u64,
    /// The content hash of the config this instance is serving (the
    /// same `normalized_hash` the snapshot pipeline produces, formatted
    /// as a hex string for transport).
    pub config_hash: String,
    /// Unix-millisecond timestamp of the last publish from this
    /// instance.
    pub timestamp: u64,
}

/// Error produced by a convergence backend operation. Non-exhaustive:
/// a future etcd/Consul backend may surface new failure classes via
/// [`ConvergenceError::Backend`] rather than new variants.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConvergenceError {
    /// The backend itself failed (connection lost, command error, ...).
    Backend(String),
    /// A stored value was malformed (a corrupt instance record or
    /// config body).
    Invalid(String),
    /// The requested generation's config body is not present (it was
    /// never published or has expired).
    NotFound(String),
}

impl std::fmt::Display for ConvergenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConvergenceError::Backend(m) => write!(f, "convergence backend error: {m}"),
            ConvergenceError::Invalid(m) => write!(f, "convergence invalid data: {m}"),
            ConvergenceError::NotFound(m) => write!(f, "convergence not found: {m}"),
        }
    }
}

impl std::error::Error for ConvergenceError {}

impl From<ConvergenceError> for ExtensionsError {
    /// Convergence backend failures map to [`ExtensionsError::Backend`]
    /// so they propagate through the shared extension error type at
    /// boundaries that aggregate the two.
    fn from(e: ConvergenceError) -> Self {
        ExtensionsError::Backend(e.to_string())
    }
}

/// Swappable config convergence backend (DW-054, ent feature only).
///
/// v1 ships [`RedisConvergenceBackend`]; etcd and Consul are deferred
/// behind this trait. Dyn-compatible (used as
/// `Arc<dyn ConfigConvergenceBackend>`); `async` via `async-trait`.
#[async_trait]
pub trait ConfigConvergenceBackend: Send + Sync {
    /// Publish this instance's current generation: upsert the instance
    /// record AND store the config body for this generation, so a
    /// remote instance can load it. Atomicity is best-effort across the
    /// two writes (a remote reader may see the new record before the
    /// body lands; the coordinator retries on the next poll).
    async fn publish_generation(
        &self,
        generation: u64,
        config_hash: &str,
        instance_id: &str,
        config_yaml: &str,
    ) -> Result<(), ConvergenceError>;

    /// Read every instance's current generation record. The coordinator
    /// polls this at `poll_interval_ms` to detect remote changes and at
    /// `drift_check_interval_ms` to report drift.
    async fn watch_generations(&self) -> Result<Vec<InstanceGeneration>, ConvergenceError>;

    /// Load a config generation's normalized YAML body. The coordinator
    /// calls this when a remote instance published a higher generation
    /// with a different config hash, then re-publishes locally through
    /// `compile_and_publish`.
    async fn load_config(&self, generation: u64) -> Result<String, ConvergenceError>;

    /// Remove this instance's record on graceful shutdown so the cluster
    /// view does not list a dead instance. Best-effort: a crash leaves
    /// the record to the instances hash's TTL.
    async fn remove_instance(&self, instance_id: &str) -> Result<(), ConvergenceError>;
}

/// Redis-backed convergence backend (DW-054, ent feature only).
///
/// Uses `redis::aio::ConnectionManager` -- a multiplexed connection
/// that clones cheaply (Arc-based) and reconnects automatically on
/// failure. Instance records live in a hash at `{prefix}:instances`
/// (field = instance id, value = `generation|config_hash|timestamp`);
/// config bodies live at `{prefix}:config:{generation}`. The instances
/// hash carries a TTL so a crashed instance's record auto-expires.
pub struct RedisConvergenceBackend {
    conn: ConnectionManager,
    key_prefix: String,
    /// TTL for the instances hash, in seconds. Long enough that a
    /// healthy instance refreshes it well before expiry; short enough
    /// that a crashed instance's record disappears promptly.
    instances_ttl_s: u64,
    /// TTL for config bodies, in seconds. A generation's body only
    /// needs to live as long as a slow instance might take to converge
    /// to it; the default is generous to cover a paused/polling
    /// instance.
    config_ttl_s: u64,
}

impl std::fmt::Debug for RedisConvergenceBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisConvergenceBackend")
            .field("key_prefix", &self.key_prefix)
            .field("instances_ttl_s", &self.instances_ttl_s)
            .field("config_ttl_s", &self.config_ttl_s)
            .finish()
    }
}

impl RedisConvergenceBackend {
    /// New backend over the provided connection (cloned cheaply,
    /// Arc-based). `key_prefix` is the convergence key namespace
    /// (default `dwara:config`).
    pub fn new(
        conn: ConnectionManager,
        key_prefix: String,
        instances_ttl_s: u64,
        config_ttl_s: u64,
    ) -> Self {
        Self {
            conn,
            key_prefix,
            instances_ttl_s,
            config_ttl_s,
        }
    }

    /// The Redis key for the instances hash.
    fn instances_key(&self) -> String {
        format!("{}:instances", self.key_prefix)
    }

    /// The Redis key for one generation's config body.
    fn config_key(&self, generation: u64) -> String {
        format!("{}:config:{}", self.key_prefix, generation)
    }
}

#[async_trait]
impl ConfigConvergenceBackend for RedisConvergenceBackend {
    async fn publish_generation(
        &self,
        generation: u64,
        config_hash: &str,
        instance_id: &str,
        config_yaml: &str,
    ) -> Result<(), ConvergenceError> {
        let mut conn = self.conn.clone();
        let instances_key = self.instances_key();
        let config_key = self.config_key(generation);
        let now_ms = unix_millis();
        let record = format!("{generation}|{config_hash}|{now_ms}");

        // Upsert the instance record and refresh the hash TTL in one
        // pipeline, then store the config body with its own TTL. The
        // two are not atomic across each other (a remote reader may
        // see the record before the body); the coordinator retries on
        // the next poll if the body is missing.
        redis::pipe()
            .atomic()
            .hset(&instances_key, instance_id, &record)
            .expire(&instances_key, self.instances_ttl_s as i64)
            .set(&config_key, config_yaml)
            .expire(&config_key, self.config_ttl_s as i64)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| ConvergenceError::Backend(format!("redis publish error: {e}")))?;
        Ok(())
    }

    async fn watch_generations(&self) -> Result<Vec<InstanceGeneration>, ConvergenceError> {
        let mut conn = self.conn.clone();
        let map: std::collections::HashMap<String, String> = redis::cmd("HGETALL")
            .arg(self.instances_key())
            .query_async(&mut conn)
            .await
            .map_err(|e| ConvergenceError::Backend(format!("redis watch error: {e}")))?;
        let mut out = Vec::with_capacity(map.len());
        for (instance_id, record) in map {
            let parts: Vec<&str> = record.split('|').collect();
            if parts.len() != 3 {
                return Err(ConvergenceError::Invalid(format!(
                    "instance record for '{instance_id}' is malformed: '{record}'"
                )));
            }
            let generation = parts[0]
                .parse::<u64>()
                .map_err(|e| ConvergenceError::Invalid(format!("generation parse: {e}")))?;
            let config_hash = parts[1].to_string();
            let timestamp = parts[2]
                .parse::<u64>()
                .map_err(|e| ConvergenceError::Invalid(format!("timestamp parse: {e}")))?;
            out.push(InstanceGeneration {
                instance_id,
                generation,
                config_hash,
                timestamp,
            });
        }
        Ok(out)
    }

    async fn load_config(&self, generation: u64) -> Result<String, ConvergenceError> {
        let mut conn = self.conn.clone();
        let res: Option<String> = redis::cmd("GET")
            .arg(self.config_key(generation))
            .query_async(&mut conn)
            .await
            .map_err(|e| ConvergenceError::Backend(format!("redis load_config error: {e}")))?;
        res.ok_or_else(|| {
            ConvergenceError::NotFound(format!(
                "config body for generation {generation} is not present (expired or never \
                 published)"
            ))
        })
    }

    async fn remove_instance(&self, instance_id: &str) -> Result<(), ConvergenceError> {
        let mut conn = self.conn.clone();
        let removed: i64 = redis::cmd("HDEL")
            .arg(self.instances_key())
            .arg(instance_id)
            .query_async(&mut conn)
            .await
            .map_err(|e| ConvergenceError::Backend(format!("redis remove_instance error: {e}")))?;
        if removed == 0 {
            // The instance was already absent (expired or never
            // published); not an error -- the cluster view is correct.
            return Ok(());
        }
        Ok(())
    }
}

/// Current time as Unix milliseconds (the timestamp instance records
/// carry).
fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Establish a Redis connection with a timeout. Used at startup (in
/// dwara-bin) to create the shared [`ConnectionManager`] the convergence
/// backend clones. Mirrors the DW-031 rate-limiter connection helper.
pub async fn connect(
    url: &str,
    timeout: std::time::Duration,
) -> Result<ConnectionManager, ExtensionsError> {
    let client = redis::Client::open(url)
        .map_err(|e| ExtensionsError::Backend(format!("redis client open error: {e}")))?;
    tokio::time::timeout(timeout, ConnectionManager::new(client))
        .await
        .map_err(|_| {
            ExtensionsError::Backend(format!(
                "redis connection timeout after {}ms",
                timeout.as_millis()
            ))
        })?
        .map_err(|e| ExtensionsError::Backend(format!("redis connection error: {e}")))
}
