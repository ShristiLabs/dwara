//! Edge watch loop (DW-066, Enterprise).
//!
//! [`EdgeRuntime`] creates an [`EdgeState`], connects to the controller
//! via [`EdgeClient`], registers, receives updates, caches config
//! (`receive_update`), applies the config (writes to a local config file
//! the gateway file-watcher picks up), and sends acks. On CP outage
//! (stream error/disconnect), it marks `set_connected(false)` and
//! continues serving from cache; reconnects with bounded backoff; on
//! reconnect, re-registers and receives any newer generation.
//!
//! ## Feature gate
//!
//! The `ent` cargo feature must be enabled.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use super::analytics::FederatedAnalyticsSink;
use super::transport::{default_backoff, EdgeClient, EdgeClientError};
use super::{ConfigUpdate, EdgeState};
use tokio_stream::StreamExt;

/// Edge runtime configuration.
#[derive(Clone, Debug)]
pub struct EdgeConfig {
    /// The controller gRPC endpoint (e.g. `http://127.0.0.1:50051`).
    pub controller_endpoint: String,
    /// The edge instance ID.
    pub edge_id: String,
    /// The edge version string.
    pub version: String,
    /// The local config output path (the edge writes received configs
    /// here; the gateway's file-watcher picks up changes).
    pub config_output_path: PathBuf,
    /// The reconnect backoff schedule.
    pub backoff: Vec<Duration>,
}

impl EdgeConfig {
    /// Create an edge config from explicit args.
    pub fn new(
        controller_endpoint: &str,
        edge_id: &str,
        version: &str,
        config_output_path: PathBuf,
    ) -> Self {
        Self {
            controller_endpoint: controller_endpoint.to_string(),
            edge_id: edge_id.to_string(),
            version: version.to_string(),
            config_output_path,
            backoff: default_backoff(),
        }
    }
}

/// The edge runtime: connects to the controller, receives config
/// updates, caches them, applies them, and sends acks. Survives CP
/// outage by serving from cache; reconnects with bounded backoff.
pub struct EdgeRuntime {
    config: EdgeConfig,
    state: Arc<EdgeState>,
    /// SCALE-07 (#186): optional federated analytics sink. When set,
    /// the edge ships analytics batches to the controller over gRPC.
    analytics_sink: Option<Arc<FederatedAnalyticsSink>>,
}

impl EdgeRuntime {
    /// Create a new edge runtime.
    pub fn new(config: EdgeConfig) -> Self {
        let state = Arc::new(EdgeState::new(&config.edge_id, &config.version));
        state.set_controller_endpoint(&config.controller_endpoint);
        Self {
            config,
            state,
            analytics_sink: None,
        }
    }

    /// SCALE-07 (#186): attach a federated analytics sink. The sink
    /// batches events and pushes them to the controller over the
    /// `PublishAnalytics` gRPC RPC. The edge's dataplane should use
    /// this sink as its `AnalyticsSink` implementation so all local
    /// analytics are shipped to the controller for fleet-wide
    /// aggregation.
    pub fn with_federated_analytics(
        mut self,
        client: super::transport::EdgeClient,
        batch_size: usize,
        flush_interval_ms: u64,
    ) -> Self {
        let sink = Arc::new(FederatedAnalyticsSink::spawn(
            self.config.edge_id.clone(),
            client,
            batch_size,
            flush_interval_ms,
        ));
        self.analytics_sink = Some(Arc::clone(&sink));
        self
    }

    /// SCALE-07 (#186): the federated analytics sink (if attached).
    /// The dataplane uses this as its `AnalyticsSink` implementation.
    pub fn analytics_sink(&self) -> Option<Arc<FederatedAnalyticsSink>> {
        self.analytics_sink.clone()
    }

    /// The edge state (for inspection / testing).
    pub fn state(&self) -> &Arc<EdgeState> {
        &self.state
    }

    /// Run the edge: connect, register, receive updates, apply, ack.
    /// Reconnects with bounded backoff on disconnect. Runs forever
    /// (until the task is cancelled).
    pub async fn run(&self) {
        loop {
            match self.connect_and_stream().await {
                Ok(()) => {
                    // Stream ended gracefully; reconnect immediately.
                    tracing::info!(
                        code = "edge_stream_ended",
                        edge_id = %self.config.edge_id,
                        "config stream ended; reconnecting"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        code = "edge_stream_error",
                        edge_id = %self.config.edge_id,
                        "config stream error: {e}; reconnecting with backoff"
                    );
                }
            }

            // Mark disconnected; edge serves from cache.
            self.state.set_connected(false);

            // Backoff before reconnecting.
            for &delay in &self.config.backoff {
                tokio::time::sleep(delay).await;
                tracing::info!(
                    code = "edge_reconnect_attempt",
                    edge_id = %self.config.edge_id,
                    "attempting reconnect after {delay:?}"
                );
                match EdgeClient::connect(&self.config.controller_endpoint).await {
                    Ok(client) => {
                        if self.stream_loop(client).await.is_ok() {
                            // Stream ended gracefully; loop back to
                            // reconnect.
                            break;
                        }
                        // Error -- continue backoff.
                    }
                    Err(e) => {
                        tracing::debug!(
                            code = "edge_reconnect_failed",
                            edge_id = %self.config.edge_id,
                            "reconnect failed: {e}"
                        );
                    }
                }
            }
        }
    }

    /// Connect to the controller and start the config stream.
    async fn connect_and_stream(&self) -> Result<(), EdgeClientError> {
        let client = EdgeClient::connect(&self.config.controller_endpoint).await?;
        self.stream_loop(client).await
    }

    /// Register with the controller and process the config update stream.
    /// Returns Ok when the stream ends gracefully, Err on error.
    async fn stream_loop(&self, client: EdgeClient) -> Result<(), EdgeClientError> {
        let registration = self.state.registration();
        let mut stream = client.stream_config_updates(registration).await?;

        self.state.set_connected(true);
        tracing::info!(
            code = "edge_connected",
            edge_id = %self.config.edge_id,
            "connected to controller, receiving config updates"
        );

        while let Some(result) = stream.next().await {
            let pb_update = result?;
            let update: ConfigUpdate = pb_update.try_into().map_err(EdgeClientError::Protocol)?;

            let gen = update.generation.generation;
            match self.state.receive_update(update.clone()) {
                Ok(()) => {
                    tracing::info!(
                        code = "edge_config_received",
                        edge_id = %self.config.edge_id,
                        generation = gen,
                        "received and cached config generation {gen}"
                    );

                    // Apply the config: write to the local config file.
                    if let Err(e) = self.apply_config(&update.generation.config) {
                        tracing::error!(
                            code = "edge_config_apply_failed",
                            edge_id = %self.config.edge_id,
                            generation = gen,
                            "failed to apply config: {e}"
                        );
                        let ack = self.state.ack_current(false, Some(e.to_string()));
                        if let Err(e) = client.ack(ack).await {
                            tracing::warn!(
                                code = "edge_ack_failed",
                                edge_id = %self.config.edge_id,
                                "failed to send ack: {e}"
                            );
                        }
                    } else {
                        tracing::info!(
                            code = "edge_config_applied",
                            edge_id = %self.config.edge_id,
                            generation = gen,
                            "applied config generation {gen}"
                        );
                        let ack = self.state.ack_current(true, None);
                        if let Err(e) = client.ack(ack).await {
                            tracing::warn!(
                                code = "edge_ack_failed",
                                edge_id = %self.config.edge_id,
                                "failed to send ack: {e}"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        code = "edge_config_rejected",
                        edge_id = %self.config.edge_id,
                        generation = gen,
                        "rejected config generation {gen}: {e}"
                    );
                }
            }
        }

        Ok(())
    }

    /// Apply a config by writing it to the local config output file.
    /// The gateway's file-watcher picks up the change and hot-reloads.
    fn apply_config(&self, config: &str) -> std::io::Result<()> {
        std::fs::write(&self.config.config_output_path, config)
    }
}
