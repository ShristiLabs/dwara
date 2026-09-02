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

## gRPC transport (DW-066)

The CP/DP split uses a tonic-based gRPC transport with hand-written
prost wire messages (no protoc/build-script dependency). The transport
layer lives in `crates/dwara-core/src/cp_dp/transport.rs` and provides:

- `ControllerServer`: implements the `DwaraControlPlane` gRPC service.
  Edges register via `stream_config_updates` (server-streaming) and
  receive config updates; edges ack applied generations via `ack`
  (unary). A broadcast channel fans out updates to all connected edges;
  each edge's stream filters by `target_edges`.
- `EdgeClient`: connects to the controller, registers, receives
  updates, and sends acks. Reconnects with bounded backoff on
  disconnect.
- `ProstCodec`: a custom tonic `Codec` that uses the workspace prost
  0.14 (avoids tonic's prost 0.13 duplicate-version dependency).

### Running the controller

```sh
cargo run -p dwara-cli --bin dwara-controller --features ent -- \
    --bind 127.0.0.1:50051 \
    --config-source ./dwara.yaml \
    --leader
```

Environment variables: `DWARA_CP_BIND`, `DWARA_CP_CONFIG_SOURCE`,
`DWARA_CP_LEADER`, `DWARA_CP_POLL_INTERVAL_SECS`.

### Running an edge

```sh
cargo run -p dwara-cli --bin dwara-edge --features ent -- \
    --controller-endpoint http://127.0.0.1:50051 \
    --edge-id edge-1 \
    --config-output /etc/dwara/dwara.yaml
```

Environment variables: `DWARA_CP_CONTROLLER_ENDPOINT`,
`DWARA_CP_EDGE_ID`, `DWARA_CP_EDGE_VERSION`, `DWARA_CP_CONFIG_OUTPUT`.

### Wire protocol

The gRPC service `dwara.ControlPlane` has two methods:

- `StreamConfigUpdates` (server-streaming): the edge sends an
  `EdgeRegistration`, the controller streams `ConfigUpdate` messages.
- `Ack` (unary): the edge sends a `ConfigAck`, the controller responds
  with an empty `AckResponse`.

All wire messages are hand-written prost structs in `transport.rs`
that mirror the domain types 1:1. Conversions happen in the
transport layer; the domain types are unchanged.

### TLS

The current implementation uses plaintext gRPC (suitable for
development and trusted-network deployments). mTLS support is a
documented follow-up; the tonic transport layer supports it via
`ServerTlsConfig` / `ClientTlsConfig` when the `tls` features are
enabled.

## Global load balancing and data residency (DW-094, Enterprise)

DW-094 adds locality-aware load balancing and data-residency
enforcement to the CP/DP split. Endpoints declare a `region` and
optional `zone`; the dataplane's balancer prefers same-region
endpoints (falling back to same-zone, then any) so traffic stays
close to its origin. A `LocalityContext` is propagated from the
controller to edges via the config stream, so every edge sees the
same locality topology without per-edge configuration.

Data residency: a route can declare `allowed_regions` — a list of
regions whose endpoints are eligible to receive that route's traffic.
The proxy enforces the constraint at pick time: a request is only
forwarded to an endpoint whose region is in the allowed set. This
lets an operator keep EU-personal-data traffic on EU endpoints
without a separate gateway per region.

Code: `crates/dwara-core/src/config/locality.rs` (the locality schema
and `LocalityContext`), `crates/dwara-core/src/dataplane/balance.rs`
(locality-aware pick), `crates/dwara-core/src/dataplane/proxy.rs`
(residency enforcement at dispatch).

## Fleet operations (DW-098, Enterprise)

DW-098 adds fleet-wide operational controls to the CP/DP split:

- **Version skew policy**: each edge registers with its build version
  on connect. The controller checks the version against the
  configured skew policy (`allow`, `allow_minor_skew`, or
  `require_exact`) and rejects an edge that violates it — so a
  rolling upgrade cannot silently mix incompatible versions. The
  check lives in `check_edge_version_skew`.
- **Fleet status API**: two admin endpoints expose the fleet's
  health: `GET /fleet/skew` returns the version-skew status of every
  connected edge (version, policy, compliant/flagged), and
  `GET /fleet/status` returns each edge's connection state, last-ack
  generation, and cached-config status.
- **Rolling upgrade orchestration**: the controller can drive a
  rolling upgrade by label-selector waves — targeting a subset of
  edges (by label) for a config push, waiting for acks, then
  proceeding to the next wave. This bounds the blast radius of a bad
  config to one wave.

Code: `crates/dwara-core/src/cp_dp/mod.rs`
(`check_edge_version_skew`, `edge_skew_status`),
`crates/dwara-core/src/cp_dp/transport.rs` (fleet status RPCs),
`crates/dwara-admin/src/lib.rs` (the `/fleet/*` admin endpoints).

## Not yet implemented

- Production leader election (Redis/etcd distributed lock or Raft)
- mTLS for the gRPC transport
- Additional config sources (etcd, Consul, K8s API) beyond file
  watching
