# CP/DP Split (DW-066, Enterprise)

## Overview

dwara Enterprise supports a control plane / data plane split
architecture: `dwara-controller` (the control plane) manages config
distribution to a fleet of `dwara-edge` (data planes) via a gRPC
config watch (xDS-inspired). The embedded mode (single-process) stays
first-class.

## Enabling

Build with the `ent` feature:

```sh
cargo build --features ent
```

## Architecture

In the CP/DP split:
- The **control plane** (`dwara-controller`) watches config sources
  (file, etcd, Consul, K8s API), compiles configs, and pushes them to
  edges via a gRPC stream (xDS-inspired).
- The **data plane** (`dwara-edge`) subscribes to the stream and
  applies config updates without restart.
- The **embedded mode** (single-process) runs the same config
  compilation and publishing pipeline in-process, just without the
  gRPC transport.

## HA controller

Multiple controllers can run simultaneously; only one is active
(leader election). The active controller pushes config to edges;
standby controllers watch and take over if the active controller
fails.

```rust
use dwara_core::cp_dp::{ControllerState, elect_leader, LeaderElectionResult};

let state = ControllerState::new();

// Simple leader election: lowest ID wins.
let result = elect_leader("controller-1", &[
    "controller-1".to_string(),
    "controller-2".to_string(),
]);

if result == LeaderElectionResult::Won {
    state.become_leader();
}
```

## Edge survives CP outage

Edges cache the last received config. If the controller becomes
unavailable, edges continue serving traffic with the cached config.
When the controller recovers, edges reconnect and receive any config
updates.

```rust
use dwara_core::cp_dp::{EdgeState, ConfigUpdate, ConfigGeneration};

let edge = EdgeState::new("edge-1", "0.1.0");

// Receive a config update.
edge.receive_update(ConfigUpdate {
    generation: ConfigGeneration {
        generation: 1,
        config: "config".to_string(),
        config_hash: "hash".to_string(),
        timestamp_ms: 0,
    },
    target_edges: vec![],
}).unwrap();

// Controller goes down.
edge.set_connected(false);

// Edge still has the cached config.
assert!(edge.has_cached_config());
```

## API

### ControllerState

The control plane state: tracks edges, config generations, acks, and
leader election.

### EdgeState

The data plane state: caches the last received config, tracks
controller connection, and creates registration/ack messages.

### Protocol types

- `ConfigGeneration`: a versioned config snapshot (generation number,
  config body, config hash, timestamp).
- `ConfigUpdate`: a config push from controller to edges (generation +
  target edges).
- `ConfigAck`: an acknowledgment from edges to controller (edge ID,
  generation, applied, error).
- `EdgeRegistration`: sent when an edge connects (edge ID, current
  generation, version, labels).

## Feature gate

The `ent` cargo feature must be enabled. Without it, the module is
not compiled and the gateway runs in embedded mode (the default OSS
behavior).

## Not yet implemented

- The actual gRPC transport (tonic-based streaming)
- The controller's watch loop (file/etcd/Consul/K8s API watching)
- The edge's reconnect logic
- Production leader election (Redis/etcd distributed lock or Raft)
- DW-074 (Cluster sync GA): conflict resolution, split-brain, version
  skew hardening
