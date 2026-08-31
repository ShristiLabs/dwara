//! Unit tests for `cp_dp::cluster_sync` (relocated from src).

#![cfg(feature = "ent")]

use dwara_core::cp_dp::cluster_sync::{
    check_version_skew, resolve_conflict, run_chaos_scenario, ChaosScenario, ConflictResolution,
    ConvergenceState, SemVer, SplitBrainDetector, VersionSkewError, VersionSkewPolicy,
};
use dwara_core::cp_dp::ConfigGeneration;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn make_generation(gen: u64) -> ConfigGeneration {
    ConfigGeneration {
        generation: gen,
        config: format!("config-{gen}"),
        config_hash: format!("hash-{gen}"),
        timestamp_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
    }
}

// --- Conflict resolution ---

#[test]
fn conflict_resolution_highest_generation() {
    let a = make_generation(1);
    let b = make_generation(2);
    let winner = resolve_conflict(ConflictResolution::HighestGeneration, &a, &b);
    assert_eq!(winner.generation, 2);
}

#[test]
fn conflict_resolution_highest_generation_tie() {
    let a = make_generation(5);
    let b = make_generation(5);
    let winner = resolve_conflict(ConflictResolution::HighestGeneration, &a, &b);
    assert_eq!(winner.generation, 5);
}

#[test]
fn conflict_resolution_most_recent_timestamp() {
    let a = make_generation(1);
    std::thread::sleep(std::time::Duration::from_millis(10));
    let b = make_generation(2);
    let winner = resolve_conflict(ConflictResolution::MostRecentTimestamp, &a, &b);
    assert_eq!(winner.generation, 2);
}

#[test]
fn conflict_resolution_leader_wins() {
    let a = make_generation(1);
    let b = make_generation(2);
    let winner = resolve_conflict(ConflictResolution::LeaderWins, &a, &b);
    // Leader wins returns `a` (the caller ensures `a` is from the leader).
    assert_eq!(winner.generation, 1);
}

#[test]
fn conflict_resolution_default_is_highest_generation() {
    assert_eq!(
        ConflictResolution::default(),
        ConflictResolution::HighestGeneration
    );
}

// --- Split-brain detection ---

#[test]
fn split_brain_no_controllers() {
    let detector = SplitBrainDetector::new(Duration::from_secs(10));
    assert!(!detector.is_split_brain());
    assert_eq!(detector.active_count(), 0);
}

#[test]
fn split_brain_single_controller() {
    let mut detector = SplitBrainDetector::new(Duration::from_secs(10));
    detector.heartbeat("controller-1");
    assert!(!detector.is_split_brain());
    assert_eq!(detector.active_count(), 1);
}

#[test]
fn split_brain_two_controllers() {
    let mut detector = SplitBrainDetector::new(Duration::from_secs(10));
    detector.heartbeat("controller-1");
    detector.heartbeat("controller-2");
    assert!(detector.is_split_brain());
    assert_eq!(detector.active_count(), 2);
}

#[test]
fn split_brain_stale_controller_not_counted() {
    let mut detector = SplitBrainDetector::new(Duration::from_millis(50));
    detector.heartbeat("controller-1");
    std::thread::sleep(Duration::from_millis(100));
    assert!(!detector.is_split_brain());
    assert_eq!(detector.active_count(), 0);
}

#[test]
fn split_brain_remove_controller() {
    let mut detector = SplitBrainDetector::new(Duration::from_secs(10));
    detector.heartbeat("controller-1");
    detector.heartbeat("controller-2");
    assert!(detector.is_split_brain());
    detector.remove("controller-2");
    assert!(!detector.is_split_brain());
}

#[test]
fn split_brain_cleanup_stale() {
    let mut detector = SplitBrainDetector::new(Duration::from_millis(50));
    detector.heartbeat("controller-1");
    detector.heartbeat("controller-2");
    std::thread::sleep(Duration::from_millis(100));
    detector.cleanup_stale();
    assert_eq!(detector.active_count(), 0);
}

#[test]
fn split_brain_lease_timeout() {
    let detector = SplitBrainDetector::new(Duration::from_secs(30));
    assert_eq!(detector.lease_timeout(), Duration::from_secs(30));
}

// --- Version skew tolerance ---

#[test]
fn version_skew_allow_always_ok() {
    check_version_skew(VersionSkewPolicy::Allow, "1.0.0", "2.0.0").unwrap();
    check_version_skew(VersionSkewPolicy::Allow, "1.0.0", "1.0.0").unwrap();
}

#[test]
fn version_skew_allow_minor_same_version() {
    check_version_skew(VersionSkewPolicy::AllowMinorSkew, "1.2.0", "1.2.0").unwrap();
}

#[test]
fn version_skew_allow_minor_one_minor_apart() {
    check_version_skew(VersionSkewPolicy::AllowMinorSkew, "1.2.0", "1.3.0").unwrap();
    check_version_skew(VersionSkewPolicy::AllowMinorSkew, "1.3.0", "1.2.0").unwrap();
}

#[test]
fn version_skew_allow_minor_major_mismatch() {
    let err = check_version_skew(VersionSkewPolicy::AllowMinorSkew, "1.0.0", "2.0.0").unwrap_err();
    assert!(matches!(err, VersionSkewError::MajorSkew { .. }));
}

#[test]
fn version_skew_allow_minor_too_far_apart() {
    let err = check_version_skew(VersionSkewPolicy::AllowMinorSkew, "1.0.0", "1.5.0").unwrap_err();
    assert!(matches!(
        err,
        VersionSkewError::MinorSkewTooLarge { diff: 5, .. }
    ));
}

#[test]
fn version_skew_require_exact_match() {
    check_version_skew(VersionSkewPolicy::RequireExact, "1.2.3", "1.2.3").unwrap();
}

#[test]
fn version_skew_require_exact_mismatch() {
    let err = check_version_skew(VersionSkewPolicy::RequireExact, "1.2.3", "1.2.4").unwrap_err();
    assert!(matches!(err, VersionSkewError::ExactMismatch { .. }));
}

#[test]
fn version_skew_default_is_allow_minor_skew() {
    assert_eq!(
        VersionSkewPolicy::default(),
        VersionSkewPolicy::AllowMinorSkew
    );
}

#[test]
fn version_skew_invalid_version() {
    let err =
        check_version_skew(VersionSkewPolicy::AllowMinorSkew, "invalid", "1.0.0").unwrap_err();
    assert!(matches!(err, VersionSkewError::InvalidVersion(_)));
}

#[test]
fn version_skew_error_display() {
    let err = VersionSkewError::MajorSkew {
        controller: "1.0.0".to_string(),
        edge: "2.0.0".to_string(),
    };
    assert!(err.to_string().contains("major version skew"));
    assert!(err.to_string().contains("1.0.0"));
    assert!(err.to_string().contains("2.0.0"));
}

// --- SemVer parsing ---

#[test]
fn semver_parse_valid() {
    let v = SemVer::parse("1.2.3").unwrap();
    assert_eq!(
        v,
        SemVer {
            major: 1,
            minor: 2,
            patch: 3
        }
    );
}

#[test]
fn semver_parse_with_pre_release() {
    let v = SemVer::parse("1.2.3-beta.1").unwrap();
    assert_eq!(
        v,
        SemVer {
            major: 1,
            minor: 2,
            patch: 3
        }
    );
}

#[test]
fn semver_parse_invalid() {
    assert!(SemVer::parse("1.2").is_err());
    assert!(SemVer::parse("invalid").is_err());
}

// --- Convergence state ---

#[test]
fn convergence_new_state() {
    let edges = vec![
        "edge-1".to_string(),
        "edge-2".to_string(),
        "edge-3".to_string(),
    ];
    let state = ConvergenceState::new(1, &edges);
    assert_eq!(state.generation, 1);
    assert_eq!(state.total_edges, 3);
    assert_eq!(state.acked_edges.len(), 0);
    assert_eq!(state.pending_edges.len(), 3);
    assert!(!state.converged);
}

#[test]
fn convergence_record_ack() {
    let edges = vec!["edge-1".to_string(), "edge-2".to_string()];
    let mut state = ConvergenceState::new(1, &edges);
    state.record_ack("edge-1");
    assert_eq!(state.acked_edges.len(), 1);
    assert_eq!(state.pending_edges.len(), 1);
    assert!(!state.converged);
}

#[test]
fn convergence_all_acks() {
    let edges = vec!["edge-1".to_string(), "edge-2".to_string()];
    let mut state = ConvergenceState::new(1, &edges);
    state.record_ack("edge-1");
    state.record_ack("edge-2");
    assert!(state.converged);
    assert_eq!(state.acked_percentage(), 100);
}

#[test]
fn convergence_no_edges() {
    let state = ConvergenceState::new(1, &[]);
    assert!(state.converged);
    assert_eq!(state.acked_percentage(), 100);
}

#[test]
fn convergence_partial_acks() {
    let edges = vec![
        "edge-1".to_string(),
        "edge-2".to_string(),
        "edge-3".to_string(),
        "edge-4".to_string(),
    ];
    let mut state = ConvergenceState::new(1, &edges);
    state.record_ack("edge-1");
    state.record_ack("edge-2");
    assert_eq!(state.acked_percentage(), 50);
    assert!(!state.converged);
}

#[test]
fn convergence_remove_edge() {
    let edges = vec![
        "edge-1".to_string(),
        "edge-2".to_string(),
        "edge-3".to_string(),
    ];
    let mut state = ConvergenceState::new(1, &edges);
    state.record_ack("edge-1");
    state.remove_edge("edge-2");
    assert_eq!(state.total_edges, 2);
    assert_eq!(state.acked_edges.len(), 1);
    assert_eq!(state.pending_edges.len(), 1);
    assert!(!state.converged);
}

#[test]
fn convergence_remove_last_pending() {
    let edges = vec!["edge-1".to_string(), "edge-2".to_string()];
    let mut state = ConvergenceState::new(1, &edges);
    state.record_ack("edge-1");
    state.remove_edge("edge-2");
    assert!(state.converged);
}

#[test]
fn convergence_double_ack_ignored() {
    let edges = vec!["edge-1".to_string()];
    let mut state = ConvergenceState::new(1, &edges);
    state.record_ack("edge-1");
    state.record_ack("edge-1"); // should be ignored
    assert_eq!(state.acked_edges.len(), 1);
    assert!(state.converged);
}

// --- Chaos scenarios ---

#[test]
fn chaos_partition_converges() {
    let edges = vec![
        "edge-1".to_string(),
        "edge-2".to_string(),
        "edge-3".to_string(),
    ];
    let state = ConvergenceState::new(1, &edges);
    let scenario = ChaosScenario::Partition {
        partitioned_edges: vec!["edge-2".to_string(), "edge-3".to_string()],
        partition_duration_ms: 5000,
    };
    let final_state = run_chaos_scenario(&scenario, &state);
    // After partition heals, all partitioned edges ack.
    assert!(final_state.converged);
}

#[test]
fn chaos_slow_member_converges() {
    let edges = vec!["edge-1".to_string(), "edge-2".to_string()];
    let mut state = ConvergenceState::new(1, &edges);
    state.record_ack("edge-1");
    let scenario = ChaosScenario::SlowMember {
        edge_id: "edge-2".to_string(),
        ack_delay_ms: 2000,
    };
    let final_state = run_chaos_scenario(&scenario, &state);
    assert!(final_state.converged);
}

#[test]
fn chaos_rollback_converges() {
    let edges = vec!["edge-1".to_string(), "edge-2".to_string()];
    let mut state = ConvergenceState::new(2, &edges);
    state.record_ack("edge-1");
    state.record_ack("edge-2");
    assert!(state.converged);

    let scenario = ChaosScenario::Rollback {
        rollback_to_generation: 1,
    };
    let final_state = run_chaos_scenario(&scenario, &state);
    assert_eq!(final_state.generation, 1);
    assert!(final_state.converged);
}

// --- Done-when: Chaos tests: partition, slow member, rollback all converge ---

#[test]
fn done_when_chaos_tests_all_converge() {
    let edges = vec![
        "edge-1".to_string(),
        "edge-2".to_string(),
        "edge-3".to_string(),
        "edge-4".to_string(),
        "edge-5".to_string(),
    ];

    // 1. Partition: edges 3, 4, 5 are partitioned, then reconnect.
    let state = ConvergenceState::new(1, &edges);
    let partition_scenario = ChaosScenario::Partition {
        partitioned_edges: vec![
            "edge-3".to_string(),
            "edge-4".to_string(),
            "edge-5".to_string(),
        ],
        partition_duration_ms: 5000,
    };
    let after_partition = run_chaos_scenario(&partition_scenario, &state);
    assert!(after_partition.converged, "partition should converge");

    // 2. Slow member: edge-2 is slow to ack.
    let state2 = ConvergenceState::new(2, &edges);
    let slow_scenario = ChaosScenario::SlowMember {
        edge_id: "edge-2".to_string(),
        ack_delay_ms: 3000,
    };
    let after_slow = run_chaos_scenario(&slow_scenario, &state2);
    assert!(after_slow.converged, "slow member should converge");

    // 3. Rollback: roll back to generation 1.
    let rollback_scenario = ChaosScenario::Rollback {
        rollback_to_generation: 1,
    };
    let after_rollback = run_chaos_scenario(&rollback_scenario, &after_slow);
    assert!(after_rollback.converged, "rollback should converge");
    assert_eq!(after_rollback.generation, 1);
}

// --- Serialization ---

#[test]
fn conflict_resolution_serialization() {
    assert_eq!(
        serde_json::to_string(&ConflictResolution::HighestGeneration).unwrap(),
        "\"highest_generation\""
    );
    assert_eq!(
        serde_json::to_string(&ConflictResolution::MostRecentTimestamp).unwrap(),
        "\"most_recent_timestamp\""
    );
    assert_eq!(
        serde_json::to_string(&ConflictResolution::LeaderWins).unwrap(),
        "\"leader_wins\""
    );
}

#[test]
fn version_skew_policy_serialization() {
    assert_eq!(
        serde_json::to_string(&VersionSkewPolicy::Allow).unwrap(),
        "\"allow\""
    );
    assert_eq!(
        serde_json::to_string(&VersionSkewPolicy::AllowMinorSkew).unwrap(),
        "\"allow_minor_skew\""
    );
    assert_eq!(
        serde_json::to_string(&VersionSkewPolicy::RequireExact).unwrap(),
        "\"require_exact\""
    );
}

#[test]
fn convergence_state_serialization() {
    let state = ConvergenceState::new(1, &["edge-1".to_string()]);
    let json = serde_json::to_string(&state).unwrap();
    let deserialized: ConvergenceState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, deserialized);
}

#[test]
fn chaos_scenario_serialization() {
    let scenario = ChaosScenario::Partition {
        partitioned_edges: vec!["edge-1".to_string()],
        partition_duration_ms: 5000,
    };
    let json = serde_json::to_string(&scenario).unwrap();
    let deserialized: ChaosScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(scenario, deserialized);
}
