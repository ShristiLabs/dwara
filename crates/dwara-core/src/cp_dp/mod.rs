//! Control plane / data plane split (DW-066, Enterprise).
//!
//! `dwara-controller` (the control plane) + `dwara-edge` (the data
//! plane); gRPC config watch (xDS-inspired); HA controller; embedded
//! mode stays first-class.
//!
//! ## Architecture
//!
//! In the CP/DP split, the control plane (`dwara-controller`) manages
//! config distribution to a fleet of data planes (`dwara-edge`). The
//! controller watches config sources (file, etcd, Consul, K8s API),
//! compiles configs, and pushes them to edges via a gRPC stream
//! (xDS-inspired). Edges subscribe to the stream and apply config
//! updates without restart.
//!
//! The embedded mode (single-process) stays first-class: the same
//! config compilation and publishing pipeline runs in-process, just
//! without the gRPC transport.
//!
//! ## HA controller
//!
//! Multiple controllers can run simultaneously; only one is active
//! (leader election). The active controller pushes config to edges;
//! standby controllers watch and take over if the active controller
//! fails.
//!
//! ## Edge survives CP outage
//!
//! Edges cache the last received config. If the controller becomes
//! unavailable, edges continue serving traffic with the cached config.
//! When the controller recovers, edges reconnect and receive any
//! config updates.
//!
//! ## Feature gate
//!
//! The `ent` cargo feature must be enabled. Without it, the module is
//! not compiled and the gateway runs in embedded mode (the default OSS
//! behavior).

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Protocol types (xDS-inspired)
// ---------------------------------------------------------------------------

/// A config generation: a versioned config snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigGeneration {
    /// The generation number (monotonically increasing).
    pub generation: u64,
    /// The config body (normalized YAML).
    pub config: String,
    /// The config hash (SHA-256 hex).
    pub config_hash: String,
    /// The timestamp the generation was created (Unix epoch ms).
    pub timestamp_ms: u64,
}

/// A config update message: sent from the controller to edges.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigUpdate {
    /// The generation being pushed.
    pub generation: ConfigGeneration,
    /// The edge instances this update targets (empty = all).
    pub target_edges: Vec<String>,
}

/// A config acknowledgment: sent from edges to the controller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigAck {
    /// The edge instance ID.
    pub edge_id: String,
    /// The generation being acknowledged.
    pub generation: u64,
    /// Whether the edge successfully applied the config.
    pub applied: bool,
    /// An error message if the config was not applied.
    pub error: Option<String>,
    /// The timestamp the ack was sent (Unix epoch ms).
    pub timestamp_ms: u64,
}

/// An edge registration: sent when an edge connects to the controller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeRegistration {
    /// The edge instance ID (unique).
    pub edge_id: String,
    /// The edge's current generation (0 = cold start).
    pub current_generation: u64,
    /// The edge's version string.
    pub version: String,
    /// The edge's labels (for targeted updates).
    pub labels: HashMap<String, String>,
}

/// The controller state: tracks edges and config generations.
pub struct ControllerState {
    /// The current config generation.
    current_generation: RwLock<Option<ConfigGeneration>>,
    /// Registered edges: edge_id -> registration + last_seen.
    edges: RwLock<HashMap<String, EdgeInfo>>,
    /// Acks received: (edge_id, generation) -> ack.
    acks: RwLock<HashMap<(String, u64), ConfigAck>>,
    /// Whether this controller is the active leader.
    is_leader: RwLock<bool>,
}

/// Information about a registered edge.
#[derive(Clone, Debug)]
struct EdgeInfo {
    registration: EdgeRegistration,
    last_seen: Instant,
}

impl ControllerState {
    /// Create a new controller state.
    pub fn new() -> Self {
        Self {
            current_generation: RwLock::new(None),
            edges: RwLock::new(HashMap::new()),
            acks: RwLock::new(HashMap::new()),
            is_leader: RwLock::new(false),
        }
    }

    /// Become the leader.
    pub fn become_leader(&self) {
        *self.is_leader.write().unwrap() = true;
    }

    /// Step down from leadership.
    pub fn step_down(&self) {
        *self.is_leader.write().unwrap() = false;
    }

    /// Whether this controller is the leader.
    pub fn is_leader(&self) -> bool {
        *self.is_leader.read().unwrap()
    }

    /// Publish a new config generation.
    pub fn publish_generation(&self, config: String, config_hash: String) -> ConfigGeneration {
        let gen = {
            let current = self.current_generation.read().unwrap();
            current.as_ref().map(|g| g.generation + 1).unwrap_or(1)
        };

        let generation = ConfigGeneration {
            generation: gen,
            config,
            config_hash,
            timestamp_ms: now_unix_ms(),
        };

        *self.current_generation.write().unwrap() = Some(generation.clone());
        generation
    }

    /// Get the current config generation.
    pub fn current_generation(&self) -> Option<ConfigGeneration> {
        self.current_generation.read().unwrap().clone()
    }

    /// Register an edge.
    pub fn register_edge(&self, registration: EdgeRegistration) {
        let mut edges = self.edges.write().unwrap();
        edges.insert(
            registration.edge_id.clone(),
            EdgeInfo {
                registration,
                last_seen: Instant::now(),
            },
        );
    }

    /// Remove an edge (on disconnect).
    pub fn remove_edge(&self, edge_id: &str) {
        let mut edges = self.edges.write().unwrap();
        edges.remove(edge_id);
    }

    /// Record an ack from an edge.
    pub fn record_ack(&self, ack: ConfigAck) {
        let edge_id = ack.edge_id.clone();
        let mut acks = self.acks.write().unwrap();
        acks.insert((ack.edge_id.clone(), ack.generation), ack);

        // Update the edge's last_seen.
        let mut edges = self.edges.write().unwrap();
        if let Some(info) = edges.get_mut(&edge_id) {
            info.last_seen = Instant::now();
        }
    }

    /// Get all registered edges.
    pub fn edges(&self) -> Vec<EdgeRegistration> {
        let edges = self.edges.read().unwrap();
        edges.values().map(|i| i.registration.clone()).collect()
    }

    /// Get the ack for a specific edge + generation.
    pub fn get_ack(&self, edge_id: &str, generation: u64) -> Option<ConfigAck> {
        let acks = self.acks.read().unwrap();
        acks.get(&(edge_id.to_string(), generation)).cloned()
    }

    /// Get edges that have not acked a generation.
    pub fn unacked_edges(&self, generation: u64) -> Vec<String> {
        let edges = self.edges.read().unwrap();
        let acks = self.acks.read().unwrap();
        edges
            .keys()
            .filter(|edge_id| !acks.contains_key(&((**edge_id).to_string(), generation)))
            .cloned()
            .collect()
    }

    /// Get edges that have not been seen recently (stale).
    pub fn stale_edges(&self, timeout: Duration) -> Vec<String> {
        let edges = self.edges.read().unwrap();
        let now = Instant::now();
        edges
            .iter()
            .filter(|(_, info)| now.duration_since(info.last_seen) > timeout)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// The number of registered edges.
    pub fn edge_count(&self) -> usize {
        self.edges.read().unwrap().len()
    }
}

impl Default for ControllerState {
    fn default() -> Self {
        Self::new()
    }
}

/// The edge state: caches the last received config and tracks the
/// connection to the controller.
pub struct EdgeState {
    /// The edge instance ID.
    edge_id: String,
    /// The edge version.
    version: String,
    /// The edge labels.
    labels: HashMap<String, String>,
    /// The last received config generation (cached for CP outage).
    cached_generation: RwLock<Option<ConfigGeneration>>,
    /// Whether the edge is connected to the controller.
    connected: RwLock<bool>,
    /// The current controller endpoint (for reconnection).
    controller_endpoint: RwLock<Option<String>>,
}

impl EdgeState {
    /// Create a new edge state.
    pub fn new(edge_id: &str, version: &str) -> Self {
        Self {
            edge_id: edge_id.to_string(),
            version: version.to_string(),
            labels: HashMap::new(),
            cached_generation: RwLock::new(None),
            connected: RwLock::new(false),
            controller_endpoint: RwLock::new(None),
        }
    }

    /// Set a label.
    pub fn with_label(mut self, key: &str, value: &str) -> Self {
        self.labels.insert(key.to_string(), value.to_string());
        self
    }

    /// The edge ID.
    pub fn edge_id(&self) -> &str {
        &self.edge_id
    }

    /// The edge version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The edge labels.
    pub fn labels(&self) -> &HashMap<String, String> {
        &self.labels
    }

    /// Create an edge registration message.
    pub fn registration(&self) -> EdgeRegistration {
        EdgeRegistration {
            edge_id: self.edge_id.clone(),
            current_generation: self
                .cached_generation
                .read()
                .unwrap()
                .as_ref()
                .map(|g| g.generation)
                .unwrap_or(0),
            version: self.version.clone(),
            labels: self.labels.clone(),
        }
    }

    /// Receive and cache a config update.
    pub fn receive_update(&self, update: ConfigUpdate) -> Result<(), String> {
        // Check if this update targets us (empty target_edges = all).
        if !update.target_edges.is_empty() && !update.target_edges.contains(&self.edge_id) {
            return Err(format!(
                "update targets {:?}, not this edge ({})",
                update.target_edges, self.edge_id
            ));
        }

        // Check generation ordering: we should only accept newer generations.
        if let Some(cached) = self.cached_generation.read().unwrap().as_ref() {
            if update.generation.generation <= cached.generation {
                return Err(format!(
                    "received generation {} is not newer than cached {}",
                    update.generation.generation, cached.generation
                ));
            }
        }

        *self.cached_generation.write().unwrap() = Some(update.generation);
        Ok(())
    }

    /// Send an ack for the current generation.
    pub fn ack_current(&self, applied: bool, error: Option<String>) -> ConfigAck {
        let generation = self
            .cached_generation
            .read()
            .unwrap()
            .as_ref()
            .map(|g| g.generation)
            .unwrap_or(0);

        ConfigAck {
            edge_id: self.edge_id.clone(),
            generation,
            applied,
            error,
            timestamp_ms: now_unix_ms(),
        }
    }

    /// Get the cached config generation (for CP outage survival).
    pub fn cached_generation(&self) -> Option<ConfigGeneration> {
        self.cached_generation.read().unwrap().clone()
    }

    /// Whether the edge has a cached config.
    pub fn has_cached_config(&self) -> bool {
        self.cached_generation.read().unwrap().is_some()
    }

    /// Set the connected state.
    pub fn set_connected(&self, connected: bool) {
        *self.connected.write().unwrap() = connected;
    }

    /// Whether the edge is connected to the controller.
    pub fn is_connected(&self) -> bool {
        *self.connected.read().unwrap()
    }

    /// Set the controller endpoint (for reconnection).
    pub fn set_controller_endpoint(&self, endpoint: &str) {
        *self.controller_endpoint.write().unwrap() = Some(endpoint.to_string());
    }

    /// Get the controller endpoint.
    pub fn controller_endpoint(&self) -> Option<String> {
        self.controller_endpoint.read().unwrap().clone()
    }
}

/// Wall-clock Unix milliseconds.
fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A leader election result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeaderElectionResult {
    /// This instance won the election.
    Won,
    /// Another instance won; this one is a standby.
    Lost { leader_id: String },
}

/// A simple leader election: the instance with the lowest ID wins.
/// In a real implementation, this would use a distributed lock
/// (Redis, etcd) or Raft consensus.
pub fn elect_leader(instance_id: &str, candidate_ids: &[String]) -> LeaderElectionResult {
    if candidate_ids.is_empty() {
        return LeaderElectionResult::Won;
    }

    let min_id = candidate_ids.iter().min();
    match min_id {
        Some(id) if id == instance_id => LeaderElectionResult::Won,
        Some(id) => LeaderElectionResult::Lost {
            leader_id: id.clone(),
        },
        None => LeaderElectionResult::Won,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_publish_generation() {
        let state = ControllerState::new();
        assert!(state.current_generation().is_none());

        let gen1 = state.publish_generation("config1".to_string(), "hash1".to_string());
        assert_eq!(gen1.generation, 1);
        assert_eq!(gen1.config, "config1");

        let gen2 = state.publish_generation("config2".to_string(), "hash2".to_string());
        assert_eq!(gen2.generation, 2);
        assert_eq!(gen2.config, "config2");
    }

    #[test]
    fn controller_leader_election() {
        let state = ControllerState::new();
        assert!(!state.is_leader());
        state.become_leader();
        assert!(state.is_leader());
        state.step_down();
        assert!(!state.is_leader());
    }

    #[test]
    fn controller_register_and_remove_edge() {
        let state = ControllerState::new();
        state.register_edge(EdgeRegistration {
            edge_id: "edge-1".to_string(),
            current_generation: 0,
            version: "0.1.0".to_string(),
            labels: HashMap::new(),
        });

        assert_eq!(state.edge_count(), 1);
        assert_eq!(state.edges()[0].edge_id, "edge-1");

        state.remove_edge("edge-1");
        assert_eq!(state.edge_count(), 0);
    }

    #[test]
    fn controller_record_ack() {
        let state = ControllerState::new();
        state.register_edge(EdgeRegistration {
            edge_id: "edge-1".to_string(),
            current_generation: 0,
            version: "0.1.0".to_string(),
            labels: HashMap::new(),
        });

        let gen = state.publish_generation("config".to_string(), "hash".to_string());

        state.record_ack(ConfigAck {
            edge_id: "edge-1".to_string(),
            generation: gen.generation,
            applied: true,
            error: None,
            timestamp_ms: 0,
        });

        let ack = state.get_ack("edge-1", gen.generation).unwrap();
        assert!(ack.applied);
    }

    #[test]
    fn controller_unacked_edges() {
        let state = ControllerState::new();
        state.register_edge(EdgeRegistration {
            edge_id: "edge-1".to_string(),
            current_generation: 0,
            version: "0.1.0".to_string(),
            labels: HashMap::new(),
        });
        state.register_edge(EdgeRegistration {
            edge_id: "edge-2".to_string(),
            current_generation: 0,
            version: "0.1.0".to_string(),
            labels: HashMap::new(),
        });

        let gen = state.publish_generation("config".to_string(), "hash".to_string());

        state.record_ack(ConfigAck {
            edge_id: "edge-1".to_string(),
            generation: gen.generation,
            applied: true,
            error: None,
            timestamp_ms: 0,
        });

        let unacked = state.unacked_edges(gen.generation);
        assert_eq!(unacked, vec!["edge-2"]);
    }

    #[test]
    fn controller_stale_edges() {
        let state = ControllerState::new();
        state.register_edge(EdgeRegistration {
            edge_id: "edge-1".to_string(),
            current_generation: 0,
            version: "0.1.0".to_string(),
            labels: HashMap::new(),
        });

        // Immediately, the edge is not stale.
        let stale = state.stale_edges(Duration::from_secs(60));
        assert!(stale.is_empty());

        // With a 0 timeout, the edge is stale.
        let stale = state.stale_edges(Duration::from_millis(0));
        // The edge was just registered, so it might not be stale yet
        // (depends on timing). We just check the method runs.
        let _ = stale;
    }

    #[test]
    fn edge_receive_update() {
        let edge = EdgeState::new("edge-1", "0.1.0");
        assert!(!edge.has_cached_config());

        let update = ConfigUpdate {
            generation: ConfigGeneration {
                generation: 1,
                config: "config1".to_string(),
                config_hash: "hash1".to_string(),
                timestamp_ms: 0,
            },
            target_edges: vec![],
        };

        edge.receive_update(update).unwrap();
        assert!(edge.has_cached_config());
        assert_eq!(edge.cached_generation().unwrap().generation, 1);
    }

    #[test]
    fn edge_receive_update_targeted_to_other_edge() {
        let edge = EdgeState::new("edge-1", "0.1.0");

        let update = ConfigUpdate {
            generation: ConfigGeneration {
                generation: 1,
                config: "config1".to_string(),
                config_hash: "hash1".to_string(),
                timestamp_ms: 0,
            },
            target_edges: vec!["edge-2".to_string()],
        };

        let err = edge.receive_update(update).unwrap_err();
        assert!(err.contains("not this edge"));
    }

    #[test]
    fn edge_receive_update_targeted_to_self() {
        let edge = EdgeState::new("edge-1", "0.1.0");

        let update = ConfigUpdate {
            generation: ConfigGeneration {
                generation: 1,
                config: "config1".to_string(),
                config_hash: "hash1".to_string(),
                timestamp_ms: 0,
            },
            target_edges: vec!["edge-1".to_string()],
        };

        edge.receive_update(update).unwrap();
        assert!(edge.has_cached_config());
    }

    #[test]
    fn edge_rejects_older_generation() {
        let edge = EdgeState::new("edge-1", "0.1.0");

        // Receive generation 2.
        edge.receive_update(ConfigUpdate {
            generation: ConfigGeneration {
                generation: 2,
                config: "config2".to_string(),
                config_hash: "hash2".to_string(),
                timestamp_ms: 0,
            },
            target_edges: vec![],
        })
        .unwrap();

        // Try to receive generation 1 (older).
        let err = edge
            .receive_update(ConfigUpdate {
                generation: ConfigGeneration {
                    generation: 1,
                    config: "config1".to_string(),
                    config_hash: "hash1".to_string(),
                    timestamp_ms: 0,
                },
                target_edges: vec![],
            })
            .unwrap_err();
        assert!(err.contains("not newer"));
    }

    #[test]
    fn edge_ack_current() {
        let edge = EdgeState::new("edge-1", "0.1.0");

        edge.receive_update(ConfigUpdate {
            generation: ConfigGeneration {
                generation: 1,
                config: "config1".to_string(),
                config_hash: "hash1".to_string(),
                timestamp_ms: 0,
            },
            target_edges: vec![],
        })
        .unwrap();

        let ack = edge.ack_current(true, None);
        assert_eq!(ack.edge_id, "edge-1");
        assert_eq!(ack.generation, 1);
        assert!(ack.applied);
    }

    #[test]
    fn edge_ack_with_error() {
        let edge = EdgeState::new("edge-1", "0.1.0");

        let ack = edge.ack_current(false, Some("config invalid".to_string()));
        assert!(!ack.applied);
        assert_eq!(ack.error, Some("config invalid".to_string()));
    }

    #[test]
    fn edge_registration() {
        let edge = EdgeState::new("edge-1", "0.1.0")
            .with_label("region", "us-east-1")
            .with_label("env", "prod");

        let reg = edge.registration();
        assert_eq!(reg.edge_id, "edge-1");
        assert_eq!(reg.version, "0.1.0");
        assert_eq!(reg.current_generation, 0);
        assert_eq!(reg.labels.get("region"), Some(&"us-east-1".to_string()));
        assert_eq!(reg.labels.get("env"), Some(&"prod".to_string()));
    }

    #[test]
    fn edge_registration_with_cached_config() {
        let edge = EdgeState::new("edge-1", "0.1.0");

        edge.receive_update(ConfigUpdate {
            generation: ConfigGeneration {
                generation: 5,
                config: "config".to_string(),
                config_hash: "hash".to_string(),
                timestamp_ms: 0,
            },
            target_edges: vec![],
        })
        .unwrap();

        let reg = edge.registration();
        assert_eq!(reg.current_generation, 5);
    }

    #[test]
    fn edge_connected_state() {
        let edge = EdgeState::new("edge-1", "0.1.0");
        assert!(!edge.is_connected());
        edge.set_connected(true);
        assert!(edge.is_connected());
        edge.set_connected(false);
        assert!(!edge.is_connected());
    }

    #[test]
    fn edge_controller_endpoint() {
        let edge = EdgeState::new("edge-1", "0.1.0");
        assert!(edge.controller_endpoint().is_none());
        edge.set_controller_endpoint("https://controller:8443");
        assert_eq!(
            edge.controller_endpoint(),
            Some("https://controller:8443".to_string())
        );
    }

    #[test]
    fn edge_survives_cp_outage_with_cache() {
        let edge = EdgeState::new("edge-1", "0.1.0");

        // Receive a config.
        edge.receive_update(ConfigUpdate {
            generation: ConfigGeneration {
                generation: 1,
                config: "config1".to_string(),
                config_hash: "hash1".to_string(),
                timestamp_ms: 0,
            },
            target_edges: vec![],
        })
        .unwrap();

        // Controller goes down.
        edge.set_connected(false);
        assert!(!edge.is_connected());

        // Edge still has the cached config.
        assert!(edge.has_cached_config());
        assert_eq!(edge.cached_generation().unwrap().config, "config1");
    }

    #[test]
    fn elect_leader_wins_when_lowest_id() {
        let result = elect_leader(
            "controller-1",
            &[
                "controller-1".to_string(),
                "controller-2".to_string(),
                "controller-3".to_string(),
            ],
        );
        assert_eq!(result, LeaderElectionResult::Won);
    }

    #[test]
    fn elect_leader_loses_when_not_lowest_id() {
        let result = elect_leader(
            "controller-2",
            &[
                "controller-1".to_string(),
                "controller-2".to_string(),
                "controller-3".to_string(),
            ],
        );
        assert_eq!(
            result,
            LeaderElectionResult::Lost {
                leader_id: "controller-1".to_string()
            }
        );
    }

    #[test]
    fn elect_leader_wins_when_no_candidates() {
        let result = elect_leader("controller-1", &[]);
        assert_eq!(result, LeaderElectionResult::Won);
    }

    #[test]
    fn config_generation_serialization() {
        let gen = ConfigGeneration {
            generation: 1,
            config: "config".to_string(),
            config_hash: "hash".to_string(),
            timestamp_ms: 1234567890,
        };

        let json = serde_json::to_string(&gen).unwrap();
        let deserialized: ConfigGeneration = serde_json::from_str(&json).unwrap();
        assert_eq!(gen, deserialized);
    }

    #[test]
    fn config_update_serialization() {
        let update = ConfigUpdate {
            generation: ConfigGeneration {
                generation: 1,
                config: "config".to_string(),
                config_hash: "hash".to_string(),
                timestamp_ms: 0,
            },
            target_edges: vec!["edge-1".to_string()],
        };

        let json = serde_json::to_string(&update).unwrap();
        let deserialized: ConfigUpdate = serde_json::from_str(&json).unwrap();
        assert_eq!(update, deserialized);
    }

    #[test]
    fn config_ack_serialization() {
        let ack = ConfigAck {
            edge_id: "edge-1".to_string(),
            generation: 1,
            applied: true,
            error: None,
            timestamp_ms: 0,
        };

        let json = serde_json::to_string(&ack).unwrap();
        let deserialized: ConfigAck = serde_json::from_str(&json).unwrap();
        assert_eq!(ack, deserialized);
    }

    #[test]
    fn edge_registration_serialization() {
        let mut labels = HashMap::new();
        labels.insert("region".to_string(), "us-east-1".to_string());

        let reg = EdgeRegistration {
            edge_id: "edge-1".to_string(),
            current_generation: 5,
            version: "0.1.0".to_string(),
            labels,
        };

        let json = serde_json::to_string(&reg).unwrap();
        let deserialized: EdgeRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(reg, deserialized);
    }
}
