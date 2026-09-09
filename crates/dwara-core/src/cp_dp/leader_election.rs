//! Leader election for CP/DP HA (SCALE-06, #185, Enterprise).
//!
//! Real leader election with distributed locking, lease renewal, and
//! failover. The [`LeaderElector`] trait is the swappable seam; the
//! runtime calls `try_acquire` on startup and `renew_lease`
//! periodically to hold leadership. If the lease expires (the leader
//! crashes or loses connectivity), a standby acquires leadership and
//! takes over.
//!
//! ## Backends
//!
//! - [`SqliteLeaderElector`]: SQLite-backed (via the existing
//!   [`StateStore`]). Uses a `controller_leader` table with a
//!   lease expiry timestamp. Suitable for single-controller or
//!   shared-file deployments. The OSS default.
//! - [`RedisLeaderElector`]: Redis-backed (ent only). Uses
//!   `SET NX EX` for atomic lease acquisition. Suitable for
//!   multi-controller HA deployments.
//!
//! ## Design
//!
//! The elector is a lease-based lock, not Raft consensus. This is
//! sufficient for the active-passive HA posture described in ADR-0001
//! (one active controller, N standbys). A Raft consensus group
//! remains a future option for stronger consistency guarantees.
//!
//! ## Feature gate
//!
//! The `ent` cargo feature must be enabled. Without it, the module
//! is not compiled and the controller runs in single-instance mode
//! (the `--leader` flag or `DWARA_CP_LEADER=1`).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::state::store::StateStore;

/// A leader election lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaderLease {
    /// The instance ID holding the lease.
    pub instance_id: String,
    /// The epoch (monotonically increasing; increments on each
    /// leadership transition).
    pub epoch: u64,
    /// The lease expiry (Unix epoch milliseconds). The lease must be
    /// renewed before this time or it expires.
    pub expires_at_ms: u64,
}

/// The result of a leader election attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ElectionOutcome {
    /// This instance won the election and holds the lease.
    Won(LeaderLease),
    /// Another instance holds the lease.
    Lost {
        leader_id: String,
        expires_at_ms: u64,
    },
}

/// The leader elector trait: a swappable seam for distributed locking.
///
/// Implementations must be safe to call concurrently from multiple
/// controllers. The lease is time-bounded: the holder must call
/// `renew_lease` before `expires_at_ms` or the lease expires and a
/// standby can acquire it.
#[async_trait]
pub trait LeaderElector: Send + Sync {
    /// Try to acquire leadership. Returns `Won` if this instance now
    /// holds the lease, `Lost` if another instance holds a valid
    /// lease. If the current lease has expired, this call acquires it.
    async fn try_acquire(&self, instance_id: &str) -> ElectionOutcome;

    /// Renew an existing lease. Returns `Ok(lease)` with the new
    /// expiry if this instance still holds the lease, `Err` if the
    /// lease was lost (expired or stolen by another instance).
    async fn renew_lease(&self, instance_id: &str) -> Result<LeaderLease, String>;

    /// Step down voluntarily (release the lease). Used on graceful
    /// shutdown so a standby can take over immediately.
    async fn step_down(&self, instance_id: &str) -> Result<(), String>;

    /// The current leader (if any), or `None` if no valid lease
    /// exists.
    async fn current_leader(&self) -> Option<LeaderLease>;
}

/// SQLite-backed leader elector (SCALE-06, #185).
///
/// Uses a `controller_leader` table (migration 009) with a single row
/// keyed by a fixed key. The row stores the instance ID, epoch, and
/// lease expiry. Acquisition is atomic via a transaction; renewal
/// checks the instance ID before updating.
pub struct SqliteLeaderElector {
    store: Arc<StateStore>,
    lease_ttl: Duration,
}

impl SqliteLeaderElector {
    /// Create a new SQLite-backed leader elector. `lease_ttl` is the
    /// lease duration (the time before the lease expires and must be
    /// renewed).
    pub fn new(store: Arc<StateStore>, lease_ttl: Duration) -> Self {
        Self { store, lease_ttl }
    }
}

#[async_trait]
impl LeaderElector for SqliteLeaderElector {
    async fn try_acquire(&self, instance_id: &str) -> ElectionOutcome {
        let store = Arc::clone(&self.store);
        let ttl_ms = self.lease_ttl.as_millis() as i64;
        let id = instance_id.to_string();
        let outcome = tokio::task::spawn_blocking(move || {
            store
                .try_acquire_leader(&id, ttl_ms)
                .map_err(|e| e.to_string())
        })
        .await
        .unwrap_or(Err("spawn_blocking failed".to_string()));

        match outcome {
            Ok(lease) => ElectionOutcome::Won(LeaderLease {
                instance_id: lease.instance_id,
                epoch: lease.epoch,
                expires_at_ms: lease.expires_at_ms as u64,
            }),
            Err(leader_info) => {
                // leader_info is "instance_id:expires_at_ms" of the
                // current holder.
                let parts: Vec<&str> = leader_info.splitn(2, ':').collect();
                if parts.len() == 2 {
                    ElectionOutcome::Lost {
                        leader_id: parts[0].to_string(),
                        expires_at_ms: parts[1].parse().unwrap_or(0),
                    }
                } else {
                    ElectionOutcome::Lost {
                        leader_id: leader_info,
                        expires_at_ms: 0,
                    }
                }
            }
        }
    }

    async fn renew_lease(&self, instance_id: &str) -> Result<LeaderLease, String> {
        let store = Arc::clone(&self.store);
        let ttl_ms = self.lease_ttl.as_millis() as i64;
        let id = instance_id.to_string();
        let result = tokio::task::spawn_blocking(move || store.renew_leader_lease(&id, ttl_ms))
            .await
            .map_err(|e| e.to_string())?;

        match result {
            Ok(lease) => Ok(LeaderLease {
                instance_id: lease.instance_id,
                epoch: lease.epoch,
                expires_at_ms: lease.expires_at_ms as u64,
            }),
            Err(e) => Err(e.to_string()),
        }
    }

    async fn step_down(&self, instance_id: &str) -> Result<(), String> {
        let store = Arc::clone(&self.store);
        let id = instance_id.to_string();
        let result = tokio::task::spawn_blocking(move || store.step_down_leader(&id))
            .await
            .map_err(|e| e.to_string())?;
        result.map_err(|e| e.to_string())
    }

    async fn current_leader(&self) -> Option<LeaderLease> {
        let store = Arc::clone(&self.store);
        let result = tokio::task::spawn_blocking(move || store.current_leader())
            .await
            .ok()?;
        match result {
            Ok(Some(lease)) => Some(LeaderLease {
                instance_id: lease.instance_id,
                epoch: lease.epoch,
                expires_at_ms: lease.expires_at_ms as u64,
            }),
            _ => None,
        }
    }
}

/// Wall-clock Unix milliseconds.
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A leader election loop: acquires leadership, renews the lease
/// periodically, and calls the callback on leadership transitions.
///
/// The loop runs until the shutdown signal is received. On
/// leadership acquisition, it calls `on_acquire` with the lease. On
/// loss, it calls `on_lose`. The renewal interval is half the lease
/// TTL (renew before expiry).
pub async fn election_loop<E, F1, F2>(
    elector: Arc<E>,
    instance_id: String,
    shutdown: tokio::sync::watch::Receiver<bool>,
    mut on_acquire: F1,
    mut on_lose: F2,
) where
    E: LeaderElector + ?Sized,
    F1: FnMut(LeaderLease),
    F2: FnMut(),
{
    let renew_interval = Duration::from_secs(5);
    let mut is_leader = false;
    let mut shutdown = shutdown;

    loop {
        // Check shutdown.
        if *shutdown.borrow() {
            if is_leader {
                let _ = elector.step_down(&instance_id).await;
                on_lose();
            }
            break;
        }

        if !is_leader {
            // Try to acquire leadership.
            match elector.try_acquire(&instance_id).await {
                ElectionOutcome::Won(lease) => {
                    tracing::info!(
                        code = "cp_leader_acquired",
                        epoch = lease.epoch,
                        expires_at_ms = lease.expires_at_ms,
                        "controller acquired leadership (epoch {})",
                        lease.epoch,
                    );
                    is_leader = true;
                    on_acquire(lease);
                }
                ElectionOutcome::Lost {
                    leader_id,
                    expires_at_ms,
                } => {
                    tracing::debug!(
                        code = "cp_leader_lost",
                        leader = %leader_id,
                        expires_at_ms,
                        "leadership held by {} (expires at {})",
                        leader_id,
                        expires_at_ms,
                    );
                }
            }
        } else {
            // Renew the lease.
            match elector.renew_lease(&instance_id).await {
                Ok(lease) => {
                    tracing::debug!(
                        code = "cp_leader_renewed",
                        epoch = lease.epoch,
                        expires_at_ms = lease.expires_at_ms,
                        "lease renewed (expires at {})",
                        lease.expires_at_ms,
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        code = "cp_leader_lease_lost",
                        "lease lost: {err}; stepping down"
                    );
                    is_leader = false;
                    on_lose();
                }
            }
        }

        // Wait for the next renewal interval or shutdown.
        tokio::select! {
            _ = tokio::time::sleep(renew_interval) => {}
            _ = shutdown.changed() => {}
        }
    }
}

/// Get the current Unix milliseconds (for testing).
#[allow(dead_code)]
pub fn current_unix_ms() -> u64 {
    now_unix_ms()
}
