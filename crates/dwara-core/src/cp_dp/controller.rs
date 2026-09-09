//! Controller watch loop (DW-066, Enterprise).
//!
//! [`ControllerRuntime`] binds a tonic gRPC server (the
//! [`ControllerServer`]), runs a config-source watch loop (polling file
//! watcher -- mirrors the DW-054 file-watch pattern but kept simple),
//! and on config change compiles the config, publishes a new generation
//! via [`ControllerState::publish_generation`], and broadcasts the
//! [`ConfigUpdate`] to all connected edges.
//!
//! ## Leader election
//!
//! Only the leader serves/publishes. For a single-controller deployment,
//! the controller is leader by default (`--leader` flag or
//! `DWARA_CP_LEADER=1`). Multi-controller leader election composes with
//! [`super::elect_leader`] -- the runtime calls `become_leader` when it
//! wins; standby controllers run the gRPC server but defer publishing.
//!
//! ## Feature gate
//!
//! The `ent` cargo feature must be enabled.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

use super::analytics::AnalyticsCollector;
use super::leader_election::{election_loop, LeaderElector};
use super::transport::{serve_controller, ControllerServer};
use super::{ConfigUpdate, ControllerState};

/// Controller runtime configuration.
#[derive(Clone, Debug)]
pub struct ControllerConfig {
    /// The bind address for the gRPC server.
    pub bind_addr: SocketAddr,
    /// The config source path (file to watch).
    pub config_source: PathBuf,
    /// Whether this controller is the leader (single-instance default:
    /// true). For multi-controller, compose with `elect_leader`.
    pub leader: bool,
    /// The poll interval for the config-source file watch.
    pub poll_interval: Duration,
}

impl ControllerConfig {
    /// Create a controller config from environment variables + explicit
    /// args (mirrors the binary's CLI flags).
    pub fn from_env(bind_addr: SocketAddr, config_source: PathBuf, leader: bool) -> Self {
        let poll_interval = Duration::from_secs(
            std::env::var("DWARA_CP_POLL_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(2),
        );
        Self {
            bind_addr,
            config_source,
            leader,
            poll_interval,
        }
    }
}

/// The controller runtime: runs the gRPC server + config watch loop.
///
/// On `run`, it:
/// 1. Becomes leader (if configured) via `ControllerState::become_leader`.
/// 2. Spawns the gRPC server (serving `ControllerServer`).
/// 3. Polls the config source file; on change, compiles the config,
///    publishes a new generation, and broadcasts to connected edges.
/// 4. Runs until the shutdown signal is received.
pub struct ControllerRuntime {
    config: ControllerConfig,
    state: Arc<ControllerState>,
    server: ControllerServer,
    /// SCALE-06 (#185): optional leader elector for HA. When set,
    /// the runtime uses `election_loop` instead of the static
    /// `--leader` flag.
    elector: Option<Arc<dyn LeaderElector>>,
    /// The instance ID for leader election.
    instance_id: String,
    /// SCALE-07 (#186): optional analytics collector for federated
    /// analytics. When set, the gRPC server forwards edge analytics
    /// batches to this collector.
    analytics_collector: Option<Arc<dyn AnalyticsCollector>>,
}

impl ControllerRuntime {
    /// Create a new controller runtime.
    pub fn new(config: ControllerConfig) -> Self {
        let state = Arc::new(ControllerState::new());
        let server = ControllerServer::new(Arc::clone(&state));
        let instance_id = std::env::var("DWARA_CP_INSTANCE_ID")
            .unwrap_or_else(|_| format!("cp-{}", std::process::id()));
        Self {
            config,
            state,
            server,
            elector: None,
            instance_id,
            analytics_collector: None,
        }
    }

    /// SCALE-06 (#185): attach a leader elector for HA. When set,
    /// the runtime uses `election_loop` for leader election with
    /// lease renewal and failover, instead of the static `--leader`
    /// flag.
    pub fn with_elector(mut self, elector: Arc<dyn LeaderElector>) -> Self {
        self.elector = Some(elector);
        self
    }

    /// SCALE-07 (#186): attach an analytics collector for federated
    /// analytics. When set, the gRPC server forwards edge analytics
    /// batches to this collector, enabling fleet-wide dashboards and
    /// spend reports.
    pub fn with_analytics_collector(mut self, collector: Arc<dyn AnalyticsCollector>) -> Self {
        self.analytics_collector = Some(Arc::clone(&collector));
        self.server = self.server.with_analytics_collector(collector);
        self
    }

    /// The controller state (for inspection / testing).
    pub fn state(&self) -> &Arc<ControllerState> {
        &self.state
    }

    /// The controller server (for publishing updates / testing).
    pub fn server(&self) -> &ControllerServer {
        &self.server
    }

    /// DW-098 (Ent): attach the fleet operations config. When set
    /// and enabled, the controller checks each connecting edge's
    /// version against the skew policy on registration.
    pub fn with_fleet_config(mut self, fleet: crate::config::FleetConfig) -> Self {
        self.server = self.server.with_fleet_config(fleet);
        self
    }

    /// Run the controller: gRPC server + config watch loop.
    ///
    /// Returns when the gRPC server shuts down (or on fatal error).
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        let has_elector = self.elector.is_some();

        if has_elector {
            // SCALE-06 (#185): use the election loop for HA.
            let state = Arc::clone(&self.state);
            let server = self.server.clone();
            let config_source = self.config.config_source.clone();
            let poll_interval = self.config.poll_interval;
            let elector = self.elector.unwrap();
            let instance_id = self.instance_id.clone();

            // Spawn the gRPC server.
            let server_handle = {
                let server = self.server.clone();
                let bind_addr = self.config.bind_addr;
                tokio::spawn(async move {
                    if let Err(e) = serve_controller(server, bind_addr).await {
                        tracing::error!(code = "cp_server_error", "gRPC server error: {e}");
                    }
                })
            };

            // Spawn the config watch loop (it checks is_leader
            // internally, so it runs on all controllers but only
            // publishes when this instance is the leader).
            tokio::spawn(async move {
                config_watch_loop(state, server, config_source, poll_interval).await;
            });

            // Run the election loop. On acquire, become leader; on
            // lose, step down. The config watch loop picks up the
            // is_leader flag.
            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
            let election_state = Arc::clone(&self.state);
            let election_state2 = Arc::clone(&election_state);
            let election_handle = tokio::spawn(async move {
                election_loop(
                    elector,
                    instance_id,
                    shutdown_rx,
                    move |_lease| {
                        election_state.become_leader();
                    },
                    move || {
                        election_state2.step_down();
                    },
                )
                .await;
            });

            // Wait for the gRPC server to shut down, then signal the
            // election loop to stop.
            server_handle.await?;
            let _ = shutdown_tx.send(true);
            let _ = election_handle.await;
        } else {
            // Static leader mode (the pre-#185 behavior).
            if self.config.leader {
                self.state.become_leader();
                tracing::info!(code = "cp_leader_acquired", "controller became leader");
            } else {
                tracing::info!(code = "cp_standby", "controller running as standby");
            }

            let server = self.server.clone();
            let bind_addr = self.config.bind_addr;

            // Spawn the gRPC server.
            let server_handle = tokio::spawn(async move {
                if let Err(e) = serve_controller(server, bind_addr).await {
                    tracing::error!(code = "cp_server_error", "gRPC server error: {e}");
                }
            });

            // Run the config watch loop (only if leader).
            if self.config.leader {
                let state = Arc::clone(&self.state);
                let server = self.server.clone();
                let config_source = self.config.config_source.clone();
                let poll_interval = self.config.poll_interval;

                tokio::spawn(async move {
                    config_watch_loop(state, server, config_source, poll_interval).await;
                });
            }

            // Wait for the server to shut down.
            server_handle.await?;
        }
        Ok(())
    }
}

/// The config-source watch loop: polls the file for changes, compiles
/// the config on change, publishes a new generation, and broadcasts to
/// connected edges.
async fn config_watch_loop(
    state: Arc<ControllerState>,
    server: ControllerServer,
    config_source: PathBuf,
    poll_interval: Duration,
) {
    let mut last_hash: Option<String> = None;

    loop {
        tokio::time::sleep(poll_interval).await;

        if !state.is_leader() {
            continue;
        }

        // Read the config file.
        let Ok(text) = std::fs::read_to_string(&config_source) else {
            tracing::warn!(
                code = "cp_config_read_failed",
                path = %config_source.display(),
                "failed to read config source"
            );
            continue;
        };

        // Hash the content to detect changes.
        let hash = hex_hash(&text);
        if last_hash.as_deref() == Some(hash.as_str()) {
            continue;
        }
        last_hash = Some(hash.clone());

        // Compile the config (reuse the snapshot compile pipeline).
        match compile_config(&text) {
            Ok(compiled_hash) => {
                let generation = state.publish_generation(text.clone(), compiled_hash);
                tracing::info!(
                    code = "cp_generation_published",
                    generation = generation.generation,
                    edges = state.edge_count(),
                    "published config generation {} to {} edges",
                    generation.generation,
                    state.edge_count()
                );

                let update = ConfigUpdate {
                    generation,
                    target_edges: vec![],
                };
                server.publish_update(update);
            }
            Err(err) => {
                tracing::error!(
                    code = "cp_config_compile_failed",
                    "config compile failed: {err}"
                );
            }
        }
    }
}

/// Compile a config YAML string and return its content hash (hex).
/// Reuses the snapshot compile pipeline for validation.
fn compile_config(text: &str) -> Result<String, String> {
    let gateway =
        crate::config::parse_gateway(text).map_err(|e| format!("config parse error: {e}"))?;
    let compiled =
        crate::snapshot::compile(&gateway).map_err(|e| format!("config compile error: {e}"))?;
    Ok(format!("{:x}", compiled.content_hash()))
}

/// SHA-256 hex hash of a string.
fn hex_hash(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in result {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Wall-clock Unix seconds (for log timestamps).
#[allow(dead_code)]
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
