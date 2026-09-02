# Web console

The web console is a single-page application served from the gateway's
mTLS admin listener. It provides a browser-based dashboard for
inspecting the running gateway -- routes, services, upstreams, health,
metrics, and recent requests -- without any external dependencies.

The console ships in two modes:

- **Read-only (OSS)**: the default build serves a view-only dashboard.
  You can inspect routes, services, health, metrics, and recent requests
  but cannot modify any state.
- **CRUD (Enterprise)**: the v2 console (see
  [Console v2 (Enterprise)](#console-v2-enterprise)) adds full create,
  read, update, and delete operations, fleet views, a config editor, and
  a workspace switcher. Build with `--features ent` and present a valid
  license.

## When to use this

Use the web console when:

- You want a quick visual overview of the gateway state without
  running `curl` against the admin API.
- You are in a debugging session and want to see routes, health, and
  metrics in one place.
- You don't have a separate observability dashboard set up yet.

The console is **read-only** in the OSS build: it cannot modify config,
purge cache, or change any state. All mutations go through the admin API
or CLI. The enterprise v2 console (below) adds CRUD operations.

## Enabling

The web console is served from the admin listener. Enable the admin
listener with mTLS (see [Admin API](./admin-api)):

```yaml
admin:
  bind: 127.0.0.1:2019
  tls:
    cert_file: /etc/dwara/admin.crt.pem
    key_file: /etc/dwara/admin.key.pem
    client_ca_file: /etc/dwara/admin-clients.ca.pem
```

The console is available at `/console/` on the admin listener:

```
https://127.0.0.1:2019/console/
```

The console is embedded in the gateway binary at compile time
(`include_str!`/`include_bytes!`) -- there is no runtime file system
dependency and no external crate needed.

## Authentication

The console inherits the admin listener's mTLS authentication. Your
browser must present a client certificate chaining to
`client_ca_file`. There is no separate login or token -- the mTLS
handshake is the authentication.

::: tip
To access the console from a browser, you need a client certificate
installed in your browser's certificate store. See your browser's
documentation for installing client certificates.
:::

## Views

The console provides the following views:

### Overview

Gateway version, uptime, listener count, route count, active
requests, and a health summary.

### Routes

All configured routes with their match conditions, services, and
actions. Click a route to see its full config (transforms, rate
limits, policies, plugins).

### Services and upstreams

All services and upstreams with their endpoints, load balancer
strategy, and health state per endpoint.

### Health

Per-upstream health: passive health state, active probe results,
circuit breaker state.

### Metrics

Key metrics from the `/metrics` endpoint rendered as gauges and
counters: requests/sec, error rate, latency p50/p95/p99, cache hit
rate, active requests.

### Recent requests

The last N requests from the analytics store (if analytics is
enabled): timestamp, method, path, status, latency, consumer, route.

## Console v2 (Enterprise)

The v2 console is an enterprise feature: build with `--features ent`
and present a valid license (see [Enterprise licensing](./licensing)).
It includes all of the v1 read-only views above plus CRUD operations,
fleet views, a config editor, and a workspace switcher.

```sh
cargo build --release --features ent
```

### CRUD views

Routes, services, policies, and consumers can be created, edited, and
deleted directly from the console. Each CRUD view is backed by the
admin API mutation endpoints -- `POST` to create, `PATCH` to update,
and `DELETE` to remove -- so the console is a UI over the same
mTLS-authenticated admin API described in [Admin API](./admin-api).
The v1 read-only views remain available; the CRUD views layer
edit/delete affordances on top of them.

### Fleet views

For CP/DP split fleets (see [CP/DP split](./cp-dp-split)), the v2
console adds two fleet views:

- **Version skew status** -- `GET /fleet/skew` returns per-edge version
  compatibility against the controller, flagging edges that are behind
  or ahead of the configured skew policy.
- **Fleet status** -- `GET /fleet/status` returns the full fleet
  configuration and every registered edge's version, so you can see the
  whole fleet in one place.

### Config editor

A built-in YAML editor lets you edit the gateway config in-browser. The
editor offers two actions:

- **Validate** -- `POST /config/validate` checks the edited config
  against the schema and returns validation issues without publishing
  anything. Use this to preview whether a change is safe before it goes
  live.
- **Publish** -- `PATCH /config` applies the edited config as a new
  generation. The publish path is the same hot-reload pipeline used by
  file watch and SIGHUP, so a published config converges immediately on
  a single instance and across the fleet in a CP/DP split (see
  [Cluster sync](./cluster-sync)).

### Workspace switcher

For multi-tenant deployments (see
[Workspaces, RBAC, and audit](./workspaces-rbac-audit)), the v2 console
adds a workspace switcher. `GET /workspaces` lists the workspaces the
authenticated admin principal can access; selecting one scopes every
view and CRUD operation to that workspace.

## Limitations

- **Read-only (OSS)**: the default build's console cannot modify any
  state. Use the admin API or CLI for mutations. CRUD operations
  (create, edit, delete) require the enterprise edition -- build with
  `--features ent` and a valid license to enable the v2 console.
- **No historical data**: the console shows the current state and
  recent requests only. For historical analysis, use the analytics
  API or an external dashboard.
- **No separate auth**: the console has no login or token of its own
  -- it is exactly as accessible as the admin listener serving it.
  In production that means mTLS; on a developer machine,
  `DWARA_ADMIN_DEV=1` (loopback-only plaintext admin, see
  [Admin API](./admin-api#dev-fallback-never-in-production)) also
  serves the console in plaintext.
