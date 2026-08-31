# Cluster Sync GA (Ent) (DW-074)

## Overview

Hardened convergence for the CP/DP split control plane: conflict
resolution, split-brain guards, and version skew tolerance
(section 5-Platform).

## Lineage

DW-054 (M2) shipped a lighter-weight, non-CP/DP-split convergence
("Kong DB-less hybrid-lite" -- generation watch + drift report over
etcd/Consul); DW-066 (M3) replaces that with a real control plane
(`dwara-controller`/`dwara-edge`, gRPC watch); this module is the GA
hardening pass on DW-066's control plane.

## Enabling

Build with the `ent` feature (which enables the `cp_dp` module):

```sh
cargo build --features ent
```

## Conflict resolution

When multiple controllers publish different generations simultaneously,
the conflict is resolved using a configurable strategy:

- `HighestGeneration` (default): the generation with the highest
  generation number wins.
- `MostRecentTimestamp`: the generation with the most recent timestamp
  wins.
- `LeaderWins`: the generation from the leader controller wins.

```rust
use dwara_core::cp_dp::cluster_sync::{ConflictResolution, resolve_conflict};
use dwara_core::cp_dp::ConfigGeneration;

let winner = resolve_conflict(ConflictResolution::HighestGeneration, &gen_a, &gen_b);
```

## Split-brain guards

The `SplitBrainDetector` tracks active controllers and their
last-seen times. If more than one controller is active beyond the
lease timeout, split-brain is detected.

```rust
use dwara_core::cp_dp::cluster_sync::SplitBrainDetector;
use std::time::Duration;

let mut detector = SplitBrainDetector::new(Duration::from_secs(10));
detector.heartbeat("controller-1");
assert!(!detector.is_split_brain());

detector.heartbeat("controller-2");
assert!(detector.is_split_brain());
```

## Version skew tolerance

The `VersionSkewPolicy` controls what happens when an edge's version
differs from the controller's version:

- `Allow`: allow any version skew.
- `AllowMinorSkew` (default): allow skew within a minor version
  (e.g. 1.2.x can talk to 1.3.x, but not 2.0.x).
- `RequireExact`: require exact version match.

```rust
use dwara_core::cp_dp::cluster_sync::{VersionSkewPolicy, check_version_skew};

check_version_skew(VersionSkewPolicy::AllowMinorSkew, "1.2.0", "1.3.0").unwrap();
```

## Convergence state

The `ConvergenceState` tracks whether the fleet has converged on a
generation: total/acked/pending edges, converged flag, and acked
percentage.

```rust
use dwara_core::cp_dp::cluster_sync::ConvergenceState;

let edges = vec!["edge-1".to_string(), "edge-2".to_string()];
let mut state = ConvergenceState::new(1, &edges);
state.record_ack("edge-1");
state.record_ack("edge-2");
assert!(state.converged);
```

## Chaos scenarios

The `ChaosScenario` enum models chaos test scenarios:

- `Partition`: some edges are disconnected and then reconnected.
- `SlowMember`: one edge is slow to ack.
- `Rollback`: the controller rolls back to a previous generation.

```rust
use dwara_core::cp_dp::cluster_sync::{ChaosScenario, run_chaos_scenario, ConvergenceState};

let state = ConvergenceState::new(1, &["edge-1".to_string(), "edge-2".to_string()]);
let scenario = ChaosScenario::Partition {
    partitioned_edges: vec!["edge-2".to_string()],
    partition_duration_ms: 5000,
};
let final_state = run_chaos_scenario(&scenario, &state);
assert!(final_state.converged);
```

## Done-when

Chaos tests: partition, slow member, rollback all converge -- tested
in `done_when_chaos_tests_all_converge`.

## Feature gate

The `ent` cargo feature must be enabled (builds on the `cp_dp` module
from DW-066).
