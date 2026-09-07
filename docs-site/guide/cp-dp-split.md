# CP/DP split (Enterprise)

## Overview

Dwara Enterprise supports a control plane / data plane split
architecture: `dwara-controller` (the control plane) manages config
distribution to a fleet of `dwara-edge` (data planes) via a gRPC
config watch (xDS-inspired). The embedded mode (single-process) stays
first-class.

This is an Enterprise feature, gated behind the `ent` cargo feature.

## Enabling

Build with the `ent` feature:

```sh
cargo build --features ent
```

## Architecture

In the CP/DP split:

- The **control plane** (`dwara-controller`) watches config sources
  (file), compiles configs, and pushes them to edges via a gRPC stream
  (xDS-inspired).
- The **data plane** (`dwara-edge`) subscribes to the stream and
  applies config updates without restart.
- The **embedded mode** (single-process) runs the same config
  compilation and publishing pipeline in-process, just without the
  gRPC transport.

## Running the controller

```sh
cargo run -p dwara-cli --bin dwara-controller --features ent -- \
    --bind 127.0.0.1:50051 \
    --config-source ./dwara.yaml \
    --leader
```

Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `DWARA_CP_BIND` | `127.0.0.1:50051` | gRPC bind address |
| `DWARA_CP_CONFIG_SOURCE` | `./dwara.yaml` | config source file to watch |
| `DWARA_CP_LEADER` | `true` | whether this controller is the leader |
| `DWARA_CP_POLL_INTERVAL_SECS` | `2` | config source poll interval |
| `DWARA_LOG` | `dwara=info,dwara_core=info` | tracing filter; the controller's own events (leader election, generation publishes, compile failures) log as JSON, same pipeline as the gateway |

## Running an edge

```sh
cargo run -p dwara-cli --bin dwara-edge --features ent -- \
    --controller-endpoint http://127.0.0.1:50051 \
    --edge-id edge-1 \
    --config-output /etc/dwara/dwara.yaml
```

Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `DWARA_CP_CONTROLLER_ENDPOINT` | `http://127.0.0.1:50051` | controller gRPC endpoint |
| `DWARA_CP_EDGE_ID` | `edge-1` | edge instance ID |
| `DWARA_CP_EDGE_VERSION` | `0.1.0` | edge version string |
| `DWARA_CP_CONFIG_OUTPUT` | `/etc/dwara/dwara.yaml` | local config output path |
| `DWARA_LOG` | `dwara=info,dwara_core=info` | tracing filter; the edge's own events (connect, receive, apply, ack, reconnect) log as JSON, same pipeline as the gateway |

## Edge survives CP outage

Edges cache the last received config. If the controller becomes
unavailable, edges continue serving traffic with the cached config.
When the controller recovers, edges reconnect and receive any config
updates.

## HA controller

Multiple controllers can run simultaneously; only one is active
(leader election). The active controller pushes config to edges;
standby controllers watch and take over if the active controller
fails.

## Wire protocol

The gRPC service `dwara.ControlPlane` has two methods:

- `StreamConfigUpdates` (server-streaming): the edge sends an
  `EdgeRegistration`, the controller streams `ConfigUpdate` messages.
- `Ack` (unary): the edge sends a `ConfigAck`, the controller responds
  with an empty `AckResponse`.

All wire messages are hand-written prost structs that mirror the
domain types 1:1. The transport uses a custom `ProstCodec` (no
protoc/build-script dependency).

## TLS

The CP-DP transport supports both plaintext and mTLS modes.

**Plaintext** (default, for development and trusted-network
deployments): the existing `EdgeClient::connect` and
`serve_controller` methods use plaintext gRPC.

**mTLS** (opt-in, for deployments that need end-to-end encryption on
the CP-DP transport): the controller presents its server certificate,
requires client authentication, and validates peer certificates against
a configured CA. The edge presents its client certificate and validates
the controller's certificate against the same CA.

The TLS configuration is passed programmatically to the edge/controller
builders:

```
CpDpTlsConfig {
    cert_pem: "/path/to/edge.crt",
    key_pem: "/path/to/edge.key",
    ca_pem: "/path/to/ca.crt",
}
```

- `EdgeClient::connect_tls(endpoint, tls)`: the edge connects to the
  controller over TLS, presenting its client certificate and validating
  the controller's certificate against the CA.
- `serve_controller_tls(server, addr, tls)`: the controller serves over
  TLS, requiring client authentication and validating peer certificates
  against the CA.

The TLS-enabled methods require the tonic `tls` feature (enabled in the
workspace dependency). The existing plaintext methods remain available
for compatibility.

## Not yet implemented

- Production leader election (Redis/etcd distributed lock or Raft)
- Additional config sources (etcd, Consul, K8s API) beyond file
  watching

## Try it

The repository ships a runnable CP/DP topology under
[quickstart/enterprise/](https://github.com/shristilabs/dwara/tree/main/quickstart/enterprise):
one controller and a fleet of two edges/gateways on a docker network,
with a documented walkthrough of fleet convergence (edit one file,
watch every data plane reload) and controller-outage survival.
