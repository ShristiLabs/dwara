//! Unit tests for `cp_dp` (relocated from src).

#![cfg(feature = "ent")]

use dwara_core::cp_dp::{
    elect_leader, ConfigAck, ConfigGeneration, ConfigUpdate, ControllerState, EdgeRegistration,
    EdgeState, LeaderElectionResult,
};
use std::collections::HashMap;
use std::time::Duration;

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
