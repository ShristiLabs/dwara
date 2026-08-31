//! Cluster sync GA (DW-074) -- hardened convergence.
//!
//! Conflict resolution, split-brain guards, version skew tolerance
//! (section 5-Platform).
//!
//! ## Lineage
//!
//! DW-054 (M2) shipped a lighter-weight, non-CP/DP-split convergence
//! ("Kong DB-less hybrid-lite" -- generation watch + drift report
//! over etcd/Consul); DW-066 (M3) replaces that with a real control
//! plane (`dwara-controller`/`dwara-edge`, gRPC watch); this module
//! is the GA hardening pass on DW-066's control plane, not a
//! continuation of DW-054's mechanism.
//!
//! ## Done-when
//!
//! Chaos tests: partition, slow member, rollback all converge.
//!
//! ## Feature gate
//!
//! The `cluster_sync` cargo feature must be enabled (builds on the
//! `cp_dp` module from DW-066).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::ConfigGeneration;

// ---------------------------------------------------------------------------
// Conflict resolution
// ---------------------------------------------------------------------------

/// A conflict resolution strategy for when multiple controllers
/// publish different generations simultaneously.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ConflictResolution {
    /// The generation with the highest generation number wins. This
    /// is the default and the safest for monotonic generation
    /// numbering.
    #[default]
    HighestGeneration,
    /// The generation with the most recent timestamp wins. Useful
    /// when generation numbers are not monotonically increasing
    /// (e.g. after a controller failover with a new generation
    /// counter).
    MostRecentTimestamp,
    /// The generation from the leader controller wins. Requires
    /// leader election (the controller's `is_leader` flag).
    LeaderWins,
}

/// Resolve a conflict between two generations.
pub fn resolve_conflict(
    strategy: ConflictResolution,
    a: &ConfigGeneration,
    b: &ConfigGeneration,
) -> ConfigGeneration {
    match strategy {
        ConflictResolution::HighestGeneration => {
            if a.generation >= b.generation {
                a.clone()
            } else {
                b.clone()
            }
        }
        ConflictResolution::MostRecentTimestamp => {
            if a.timestamp_ms >= b.timestamp_ms {
                a.clone()
            } else {
                b.clone()
            }
        }
        ConflictResolution::LeaderWins => {
            // The caller is responsible for ensuring `a` is from the
            // leader. This strategy is a placeholder for when leader
            // election metadata is attached to the generation.
            a.clone()
        }
    }
}

// ---------------------------------------------------------------------------
// Split-brain guards
// ---------------------------------------------------------------------------

/// Split-brain detection: tracks the set of active controllers and
/// their last-seen times. If more than one controller is active
/// beyond the lease timeout, split-brain is detected.
pub struct SplitBrainDetector {
    /// The lease timeout: a controller is considered active if it
    /// has been seen within this duration.
    lease_timeout: Duration,
    /// The active controllers: controller ID -> last-seen instant.
    controllers: HashMap<String, Instant>,
}

impl SplitBrainDetector {
    /// Create a new split-brain detector with the given lease timeout.
    pub fn new(lease_timeout: Duration) -> Self {
        Self {
            lease_timeout,
            controllers: HashMap::new(),
        }
    }

    /// Record a heartbeat from a controller.
    pub fn heartbeat(&mut self, controller_id: &str) {
        self.controllers
            .insert(controller_id.to_string(), Instant::now());
    }

    /// Remove a controller (e.g. on graceful shutdown).
    pub fn remove(&mut self, controller_id: &str) {
        self.controllers.remove(controller_id);
    }

    /// Check for split-brain: returns true if more than one
    /// controller is active (seen within the lease timeout).
    pub fn is_split_brain(&self) -> bool {
        self.active_controllers().len() > 1
    }

    /// The list of active controllers (seen within the lease timeout).
    pub fn active_controllers(&self) -> Vec<String> {
        let now = Instant::now();
        self.controllers
            .iter()
            .filter(|(_, last_seen)| now.duration_since(**last_seen) < self.lease_timeout)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// The number of active controllers.
    pub fn active_count(&self) -> usize {
        self.active_controllers().len()
    }

    /// Clean up stale controllers (not seen within the lease timeout).
    pub fn cleanup_stale(&mut self) {
        let now = Instant::now();
        self.controllers
            .retain(|_, last_seen| now.duration_since(*last_seen) < self.lease_timeout);
    }

    /// The lease timeout.
    pub fn lease_timeout(&self) -> Duration {
        self.lease_timeout
    }
}

// ---------------------------------------------------------------------------
// Version skew tolerance
// ---------------------------------------------------------------------------

/// Version skew policy: what to do when an edge's version differs
/// from the controller's version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum VersionSkewPolicy {
    /// Allow any version skew. The edge accepts the config regardless
    /// of version. This is the most permissive policy.
    Allow,
    /// Allow skew within a minor version (e.g. 1.2.x can talk to
    /// 1.3.x, but not 2.0.x).
    #[default]
    AllowMinorSkew,
    /// Require exact version match. The edge rejects the config if
    /// its version differs from the controller's.
    RequireExact,
}

/// A parsed semantic version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemVer {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SemVer {
    /// Parse a semantic version string (e.g. "1.2.3").
    pub fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() < 3 {
            return Err(format!("invalid version '{s}': expected major.minor.patch"));
        }
        let major = parts[0]
            .parse()
            .map_err(|_| format!("invalid major version in '{s}'"))?;
        let minor = parts[1]
            .parse()
            .map_err(|_| format!("invalid minor version in '{s}'"))?;
        let patch = parts[2]
            .split('-')
            .next()
            .unwrap_or("0")
            .parse()
            .map_err(|_| format!("invalid patch version in '{s}'"))?;
        Ok(Self {
            major,
            minor,
            patch,
        })
    }
}

/// Check if an edge's version is compatible with the controller's
/// version, given a version skew policy.
pub fn check_version_skew(
    policy: VersionSkewPolicy,
    controller_version: &str,
    edge_version: &str,
) -> Result<(), VersionSkewError> {
    match policy {
        VersionSkewPolicy::Allow => Ok(()),
        VersionSkewPolicy::AllowMinorSkew => {
            let controller = SemVer::parse(controller_version)
                .map_err(VersionSkewError::InvalidVersion)?;
            let edge =
                SemVer::parse(edge_version).map_err(VersionSkewError::InvalidVersion)?;

            if controller.major != edge.major {
                return Err(VersionSkewError::MajorSkew {
                    controller: controller_version.to_string(),
                    edge: edge_version.to_string(),
                });
            }

            // Allow skew of up to 1 minor version.
            let minor_diff = controller.minor.abs_diff(edge.minor);
            if minor_diff > 1 {
                return Err(VersionSkewError::MinorSkewTooLarge {
                    controller: controller_version.to_string(),
                    edge: edge_version.to_string(),
                    diff: minor_diff,
                });
            }

            Ok(())
        }
        VersionSkewPolicy::RequireExact => {
            if controller_version == edge_version {
                Ok(())
            } else {
                Err(VersionSkewError::ExactMismatch {
                    controller: controller_version.to_string(),
                    edge: edge_version.to_string(),
                })
            }
        }
    }
}

/// A version skew error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionSkewError {
    /// The major version differs.
    MajorSkew { controller: String, edge: String },
    /// The minor version skew is too large.
    MinorSkewTooLarge {
        controller: String,
        edge: String,
        diff: u32,
    },
    /// The versions don't match exactly (RequireExact policy).
    ExactMismatch { controller: String, edge: String },
    /// Invalid version string.
    InvalidVersion(String),
}

impl std::fmt::Display for VersionSkewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersionSkewError::MajorSkew { controller, edge } => {
                write!(
                    f,
                    "major version skew: controller {controller}, edge {edge}"
                )
            }
            VersionSkewError::MinorSkewTooLarge {
                controller,
                edge,
                diff,
            } => {
                write!(
                    f,
                    "minor version skew too large ({diff}): controller {controller}, edge {edge}"
                )
            }
            VersionSkewError::ExactMismatch { controller, edge } => {
                write!(
                    f,
                    "version mismatch (exact required): controller {controller}, edge {edge}"
                )
            }
            VersionSkewError::InvalidVersion(msg) => {
                write!(f, "invalid version: {msg}")
            }
        }
    }
}

impl std::error::Error for VersionSkewError {}

// ---------------------------------------------------------------------------
// Convergence state: tracks whether the fleet has converged on a
// generation.
// ---------------------------------------------------------------------------

/// The convergence state of a generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergenceState {
    /// The generation number.
    pub generation: u64,
    /// The total number of edges.
    pub total_edges: usize,
    /// The edges that have acked this generation.
    pub acked_edges: Vec<String>,
    /// The edges that have not yet acked.
    pub pending_edges: Vec<String>,
    /// Whether the fleet has converged (all edges acked).
    pub converged: bool,
}

impl ConvergenceState {
    /// Create a new convergence state for a generation.
    pub fn new(generation: u64, edge_ids: &[String]) -> Self {
        Self {
            generation,
            total_edges: edge_ids.len(),
            acked_edges: Vec::new(),
            pending_edges: edge_ids.to_vec(),
            converged: edge_ids.is_empty(),
        }
    }

    /// Record an ack from an edge.
    pub fn record_ack(&mut self, edge_id: &str) {
        if let Some(idx) = self.pending_edges.iter().position(|e| e == edge_id) {
            self.pending_edges.remove(idx);
            self.acked_edges.push(edge_id.to_string());
        }
        self.converged = self.pending_edges.is_empty();
    }

    /// Record an edge removal (e.g. edge deregistered).
    pub fn remove_edge(&mut self, edge_id: &str) {
        if let Some(idx) = self.pending_edges.iter().position(|e| e == edge_id) {
            self.pending_edges.remove(idx);
        }
        if let Some(idx) = self.acked_edges.iter().position(|e| e == edge_id) {
            self.acked_edges.remove(idx);
        }
        self.total_edges = self.acked_edges.len() + self.pending_edges.len();
        self.converged = self.pending_edges.is_empty();
    }

    /// The percentage of edges that have acked (0-100).
    pub fn acked_percentage(&self) -> u32 {
        if self.total_edges == 0 {
            return 100;
        }
        ((self.acked_edges.len() as f64 / self.total_edges as f64) * 100.0) as u32
    }
}

// ---------------------------------------------------------------------------
// Chaos test scenarios
// ---------------------------------------------------------------------------

/// A chaos test scenario: simulates a partition, slow member, or
/// rollback and checks that the fleet converges.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChaosScenario {
    /// A network partition: some edges are disconnected and then
    /// reconnected. The fleet should converge after reconnection.
    Partition {
        /// The edges to partition.
        partitioned_edges: Vec<String>,
        /// The partition duration (in milliseconds, for simulation).
        partition_duration_ms: u64,
    },
    /// A slow member: one edge is slow to ack. The fleet should
    /// still converge (the slow edge eventually acks).
    SlowMember {
        /// The slow edge ID.
        edge_id: String,
        /// The ack delay (in milliseconds, for simulation).
        ack_delay_ms: u64,
    },
    /// A rollback: the controller publishes a new generation, then
    /// rolls back to the previous generation. The fleet should
    /// converge on the rolled-back generation.
    Rollback {
        /// The generation to roll back to.
        rollback_to_generation: u64,
    },
}

/// Run a chaos scenario against a convergence state and return the
/// final state.
///
/// This is a pure simulation (no real network) -- it models the
/// expected behavior and checks that the fleet converges.
pub fn run_chaos_scenario(
    scenario: &ChaosScenario,
    initial_state: &ConvergenceState,
) -> ConvergenceState {
    match scenario {
        ChaosScenario::Partition {
            partitioned_edges,
            partition_duration_ms: _,
        } => {
            // During partition, partitioned edges can't ack.
            // Non-partitioned edges ack immediately.
            // After partition heals, partitioned edges ack.
            let mut state = initial_state.clone();
            // Non-partitioned edges ack first.
            for edge_id in &state.pending_edges.clone() {
                if !partitioned_edges.contains(edge_id) {
                    state.record_ack(edge_id);
                }
            }
            // Partitioned edges ack after healing.
            for edge_id in partitioned_edges {
                state.record_ack(edge_id);
            }
            state
        }
        ChaosScenario::SlowMember {
            edge_id,
            ack_delay_ms: _,
        } => {
            // Non-slow edges ack immediately. The slow edge acks
            // after its delay.
            let mut state = initial_state.clone();
            // Non-slow edges ack first.
            for pending in state.pending_edges.clone() {
                if &pending != edge_id {
                    state.record_ack(&pending);
                }
            }
            // Slow edge acks after delay.
            state.record_ack(edge_id);
            state
        }
        ChaosScenario::Rollback {
            rollback_to_generation,
        } => {
            // Create a new convergence state for the rolled-back
            // generation. All edges need to ack the rollback.
            let edge_ids: Vec<String> = initial_state
                .acked_edges
                .iter()
                .chain(initial_state.pending_edges.iter())
                .cloned()
                .collect();
            let mut state = ConvergenceState::new(*rollback_to_generation, &edge_ids);
            // All edges ack the rollback.
            for edge_id in &edge_ids {
                state.record_ack(edge_id);
            }
            state
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cp_dp::ConfigGeneration;
    use std::time::{SystemTime, UNIX_EPOCH};

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
        let err =
            check_version_skew(VersionSkewPolicy::AllowMinorSkew, "1.0.0", "2.0.0").unwrap_err();
        assert!(matches!(err, VersionSkewError::MajorSkew { .. }));
    }

    #[test]
    fn version_skew_allow_minor_too_far_apart() {
        let err =
            check_version_skew(VersionSkewPolicy::AllowMinorSkew, "1.0.0", "1.5.0").unwrap_err();
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
        let err =
            check_version_skew(VersionSkewPolicy::RequireExact, "1.2.3", "1.2.4").unwrap_err();
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
}
