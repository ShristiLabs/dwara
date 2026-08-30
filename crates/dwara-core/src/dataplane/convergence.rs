//! Config convergence coordinator (DW-054, ent feature only).
//!
//! Runs ALONGSIDE the local file watcher (DW-006): a local file change
//! triggers a local reload plus a publish to the convergence backend; a
//! remote change (detected by polling the backend) triggers a remote
//! reload. Both reloads go through [`ConfigState::compile_and_publish`],
//! so the same validate -> compile -> publish pipeline (and the same
//! rollback-on-failure semantics) applies to both.
//!
//! # The background task
//!
//! [`ConvergenceCoordinator::spawn`] starts one task that:
//!
//! 1. polls the backend at `poll_interval_ms`, re-publishing this
//!    instance's current generation (refreshing the record's TTL) and
//!    checking for a HIGHER generation published by another instance
//!    with a DIFFERENT config hash -- if found, loads that generation's
//!    YAML from the backend and re-publishes it locally
//!    (convergence);
//! 2. at `drift_check_interval_ms`, reads all instances' generations
//!    and reports drift (instances with different config hashes) via a
//!    structured log + the `dwara_config_convergence_drift` metric;
//! 3. on shutdown, removes this instance's record from the backend.
//!
//! The task is cancellable: it selects on a shutdown watch and exits
//! (after the remove-instance best-effort) when the watch fires.
//!
//! # Fail-open
//!
//! When the backend is unreachable, `fail_open: true` (the default)
//! keeps serving the local config and pauses convergence until the
//! backend recovers (the poll loop logs and retries next cycle);
//! `fail_open: false` refuses to start at cold start (dwara-bin exits
//! 1 before the coordinator is constructed). At runtime the coordinator
//! always continues serving local config regardless -- a backend
//! outage mid-run is never fatal (the local file watcher still
//! reloads).
//!
//! # Placement
//!
//! The coordinator orchestrates the snapshot publish pipeline
//! ([`crate::snapshot`]), the convergence backend trait
//! ([`crate::extensions::config_convergence`]), and the observability
//! registry ([`crate::observability`]). It lives in the dataplane
//! (the top of the core dependency graph, which may depend on every
//! other domain) because `snapshot` may not import `extensions`
//! (the dependency direction is strictly downward and enforced by
//! `scripts/check_deps.py`); the dataplane already hosts the
//! comparable long-running background tasks (active health, DNS
//! discovery).

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::{gateway_to_yaml, parse_gateway};
use crate::extensions::config_convergence::{ConfigConvergenceBackend, ConvergenceError};
use crate::observability::Observability;
use crate::snapshot::ConfigState;

/// Config convergence coordinator (DW-054, ent feature only).
///
/// Constructed in dwara-bin when the config carries a
/// `config_convergence` block AND the license grants the
/// `config_convergence` feature claim. The background task is spawned
/// via [`Self::spawn`]; [`Self::publish_local`] is called by the reload
/// path after every successful local reload so the backend carries the
/// new generation.
pub struct ConvergenceCoordinator {
    state: Arc<ConfigState>,
    backend: Arc<dyn ConfigConvergenceBackend>,
    obs: Arc<Observability>,
    instance_id: String,
    poll_interval: Duration,
    drift_check_interval: Duration,
    fail_open: bool,
}

impl std::fmt::Debug for ConvergenceCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConvergenceCoordinator")
            .field("instance_id", &self.instance_id)
            .field("poll_interval", &self.poll_interval)
            .field("drift_check_interval", &self.drift_check_interval)
            .field("fail_open", &self.fail_open)
            .finish()
    }
}

impl ConvergenceCoordinator {
    /// New coordinator over the provided state, backend, and
    /// observability registry. `instance_id` uniquely identifies this
    /// process in the backend (dwara-bin generates one; tests pass
    /// their own). The intervals come from the config block.
    pub fn new(
        state: Arc<ConfigState>,
        backend: Arc<dyn ConfigConvergenceBackend>,
        obs: Arc<Observability>,
        instance_id: String,
        poll_interval_ms: u64,
        drift_check_interval_ms: u64,
        fail_open: bool,
    ) -> Self {
        Self {
            state,
            backend,
            obs,
            instance_id,
            poll_interval: Duration::from_millis(poll_interval_ms),
            drift_check_interval: Duration::from_millis(drift_check_interval_ms),
            fail_open,
        }
    }

    /// Whether the coordinator is configured fail-open (continue
    /// serving local config when the backend is unreachable).
    pub fn fail_open(&self) -> bool {
        self.fail_open
    }

    /// Publish this instance's CURRENT snapshot generation to the
    /// backend (upsert the instance record + store the config body).
    /// Called by the reload path after every successful local reload
    /// and by the background poll loop each cycle (to refresh the
    /// record's TTL). Reads the live snapshot, serializes the gateway
    /// to normalized YAML, and publishes. A publish failure is logged
    /// and counted (never fatal at runtime -- the local config keeps
    /// serving).
    pub async fn publish_local(&self) {
        let snapshot = self.state.snapshot();
        let generation = snapshot.generation();
        let config_hash = format!("{:#x}", snapshot.content_hash());
        let yaml = match gateway_to_yaml(snapshot.gateway()) {
            Ok(yaml) => yaml,
            Err(e) => {
                tracing::warn!(
                    code = "config_convergence_serialize_failed",
                    "config convergence publish skipped: gateway serialization failed ({e})"
                );
                return;
            }
        };
        if let Err(e) = self
            .backend
            .publish_generation(generation, &config_hash, &self.instance_id, &yaml)
            .await
        {
            tracing::warn!(
                code = "config_convergence_publish_failed",
                instance = %self.instance_id,
                "config convergence publish failed ({e}); serving local config"
            );
        }
        self.obs
            .set_config_convergence_generation(&self.instance_id, generation as i64);
    }

    /// Spawn the background poll + drift-check task. The task exits
    /// (after a best-effort `remove_instance`) when `shutdown` fires.
    /// The returned handle is abortable; dwara-bin aborts it on
    /// graceful shutdown (the task also self-exits on the watch).
    pub fn spawn(&self, mut shutdown: watch::Receiver<()>) -> JoinHandle<()> {
        let state = Arc::clone(&self.state);
        let backend = Arc::clone(&self.backend);
        let obs = Arc::clone(&self.obs);
        let instance_id = self.instance_id.clone();
        let poll_interval = self.poll_interval;
        let drift_check_interval = self.drift_check_interval;
        tokio::spawn(async move {
            let mut last_drift_check = Instant::now();
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(poll_interval) => {}
                    _ = shutdown.changed() => break,
                }
                // Each cycle: re-publish our current generation
                // (refreshes the record TTL), then poll for remote
                // changes, then (if the drift timer elapsed) report
                // drift.
                publish_local(&state, &backend, &obs, &instance_id).await;
                obs.record_config_convergence_refresh();
                match backend.watch_generations().await {
                    Ok(instances) => {
                        converge_remote(&state, &backend, &obs, &instance_id, &instances).await;
                        if last_drift_check.elapsed() >= drift_check_interval {
                            report_drift(&obs, &instance_id, &instances);
                            last_drift_check = Instant::now();
                        }
                    }
                    Err(e) => {
                        obs.record_config_convergence_refresh_failure();
                        tracing::warn!(
                            code = "config_convergence_watch_failed",
                            "config convergence watch failed ({e}); retrying next cycle"
                        );
                    }
                }
            }
            // Graceful shutdown: best-effort remove our instance
            // record so the cluster view does not list a dead
            // instance. A crash leaves the record to the backend's
            // TTL.
            if let Err(e) = backend.remove_instance(&instance_id).await {
                tracing::warn!(
                    code = "config_convergence_remove_failed",
                    "config convergence shutdown remove_instance failed ({e})"
                );
            }
        })
    }
}

/// Publish this instance's current snapshot generation (the per-cycle
/// refresh + the post-reload path share this). Reads the live
/// snapshot, serializes, and upserts the record + config body.
async fn publish_local(
    state: &Arc<ConfigState>,
    backend: &Arc<dyn ConfigConvergenceBackend>,
    obs: &Arc<Observability>,
    instance_id: &str,
) {
    let snapshot = state.snapshot();
    let generation = snapshot.generation();
    let config_hash = format!("{:#x}", snapshot.content_hash());
    let yaml = match gateway_to_yaml(snapshot.gateway()) {
        Ok(yaml) => yaml,
        Err(e) => {
            tracing::warn!(
                code = "config_convergence_serialize_failed",
                "config convergence publish skipped: gateway serialization failed ({e})"
            );
            return;
        }
    };
    if let Err(e) = backend
        .publish_generation(generation, &config_hash, instance_id, &yaml)
        .await
    {
        tracing::warn!(
            code = "config_convergence_publish_failed",
            instance = %instance_id,
            "config convergence publish failed ({e}); serving local config"
        );
    }
    obs.set_config_convergence_generation(instance_id, generation as i64);
}

/// Converge to a remote generation if one is higher than ours and
/// carries a different config hash. Loads the remote config body,
/// re-parses and re-publishes it locally through
/// `compile_and_publish` (the same pipeline a local file reload uses,
/// so validation/compile failures keep the running generation). On
/// success, re-publish our new converged generation so the backend
/// reflects it immediately.
async fn converge_remote(
    state: &Arc<ConfigState>,
    backend: &Arc<dyn ConfigConvergenceBackend>,
    obs: &Arc<Observability>,
    instance_id: &str,
    instances: &[crate::extensions::config_convergence::InstanceGeneration],
) {
    let snapshot = state.snapshot();
    let our_generation = snapshot.generation();
    let our_hash = format!("{:#x}", snapshot.content_hash());
    // Pick the highest generation among OTHER instances whose config
    // hash differs from ours (a same-hash higher generation is already
    // our config -- no convergence needed; a lower generation is
    // behind us).
    let target = instances
        .iter()
        .filter(|i| i.instance_id != instance_id)
        .max_by_key(|i| i.generation)
        .filter(|i| i.generation > our_generation && i.config_hash != our_hash);
    let Some(target) = target else {
        return;
    };
    tracing::info!(
        code = "config_convergence_remote_detected",
        remote_instance = %target.instance_id,
        remote_generation = target.generation,
        our_generation,
        "remote config generation detected; converging"
    );
    let yaml = match backend.load_config(target.generation).await {
        Ok(yaml) => yaml,
        Err(ConvergenceError::NotFound(m)) => {
            // The body has not landed yet (the remote upserted the
            // record before the body) or expired. Retry next cycle.
            tracing::debug!(
                code = "config_convergence_body_pending",
                "remote config body not available yet ({m}); retrying next cycle"
            );
            return;
        }
        Err(e) => {
            tracing::warn!(
                code = "config_convergence_load_failed",
                "config convergence load_config failed ({e}); retrying next cycle"
            );
            return;
        }
    };
    let gateway = match parse_gateway(&yaml) {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!(
                code = "config_convergence_parse_failed",
                "remote config body failed to parse ({e}); keeping local generation"
            );
            return;
        }
    };
    match state.compile_and_publish(&gateway) {
        Ok(info) => {
            tracing::info!(
                code = "config_convergence_converged",
                from_generation = our_generation,
                generation = info.generation,
                "converged to remote config generation {}",
                target.generation,
            );
            // Re-publish our converged generation so the backend
            // reflects it immediately (the next cycle's publish_local
            // would too, but this avoids a one-cycle lag).
            publish_local(state, backend, obs, instance_id).await;
        }
        Err(e) => {
            tracing::warn!(
                code = "config_convergence_compile_rejected",
                "remote config generation {} rejected by compile pipeline ({e}); keeping local generation",
                target.generation,
            );
        }
    }
}

/// Report drift: set the instances + drift gauges and emit a
/// structured log when instances diverge. Drift is "one or more
/// instances serve a config hash different from the majority" -- if
/// there is no majority, any divergence counts.
fn report_drift(
    obs: &Arc<Observability>,
    instance_id: &str,
    instances: &[crate::extensions::config_convergence::InstanceGeneration],
) {
    obs.set_config_convergence_instances(instances.len() as i64);
    if instances.len() <= 1 {
        obs.set_config_convergence_drift(false);
        return;
    }
    // Count distinct config hashes. Drift = more than one distinct
    // hash across the cluster.
    let mut hashes: Vec<&str> = instances.iter().map(|i| i.config_hash.as_str()).collect();
    hashes.sort();
    hashes.dedup();
    let drift = hashes.len() > 1;
    obs.set_config_convergence_drift(drift);
    if drift {
        let our_hash = instances
            .iter()
            .find(|i| i.instance_id == instance_id)
            .map(|i| i.config_hash.as_str())
            .unwrap_or("?");
        let divergent: Vec<&str> = instances
            .iter()
            .filter(|i| i.config_hash != our_hash)
            .map(|i| i.instance_id.as_str())
            .collect();
        tracing::warn!(
            code = "config_convergence_drift_detected",
            instance = %instance_id,
            instances = instances.len(),
            divergent_instances = ?divergent,
            "config convergence drift: {} of {} instances serve a different config",
            divergent.len(),
            instances.len(),
        );
    }
}
