# Web console

The web console is a single-page application served from the gateway's
mTLS admin listener. It provides a browser-based dashboard for
inspecting the running gateway -- routes, services, upstreams, health,
metrics, and recent requests -- plus create/edit/delete flows and a
config editor, all without external dependencies. Every console
operation is a call to the same mTLS-authenticated admin API the CLI
uses, so the console's powers are exactly the admin API's powers
(including your RBAC role).

The enterprise edition adds fleet-scale surfaces on top (see
[Enterprise surfaces](#enterprise-surfaces)): workspace switching for
multi-tenant deployments and fleet views for CP/DP split topologies.

## When to use this

Use the web console when:

- You want a quick visual overview of the gateway state without
  running `curl` against the admin API.
- You are in a debugging session and want to see routes, health, and
  metrics in one place.
- You don't have a separate observability dashboard set up yet.

The console can modify state (create, edit, and delete routes,
upstreams, and other entities; validate and publish config) in every
build -- subject to your admin RBAC role. A `readonly`-role principal
sees the same views without mutation affordances.

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

## Config editor

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

## Enterprise surfaces

Two console surfaces require the enterprise edition (build with
`--features ent` and a valid license; see
[Enterprise licensing](./licensing)) because the endpoints behind them
are enterprise features:

- **Workspace switcher** (multi-tenant deployments; see
  [Workspaces](./workspaces), [RBAC](./rbac), and [audit
  log](./audit-log)): `GET /workspaces` lists the workspaces the
  authenticated admin principal can access; selecting one scopes every
  view and CRUD operation to that workspace.
- **Fleet views** (CP/DP split fleets; see [CP/DP split](./cp-dp-split)):
  - **Version skew status** -- `GET /fleet/skew` returns per-edge version
    compatibility against the controller, flagging edges that are behind
    or ahead of the configured skew policy.
  - **Fleet status** -- `GET /fleet/status` returns the full fleet
    configuration and every registered edge's version, so you can see
    the whole fleet in one place.

## Limitations

- **Mutations are admin-API mutations**: the console is exactly as
  powerful as the admin API and your RBAC role allow -- there is no
  separate console permission model.
- **No historical data**: the console shows the current state and
  recent requests only. For historical analysis, use the analytics
  API or an external dashboard.
- **No separate auth**: the console has no login or token of its own
  -- it is exactly as accessible as the admin listener serving it.
  In production that means mTLS; on a developer machine,
  `DWARA_ADMIN_DEV=1` (loopback-only plaintext admin, see
  [Admin API](./admin-api#dev-fallback-never-in-production)) also
  serves the console in plaintext.

## Live charts, CRUD flows, AI ops

The console additionally ships:

- **Live dashboard**: a "Live" view with real-time stat cards (active
  requests, RPS, p50/p95/p99 latency, error rate) and a canvas-based
  latency sparkline chart showing trends over a 60-point rolling
  window. A per-route live table shows RPS and latency per route.
- **CRUD flows**: the Routes and Upstreams views now support
  create, edit, and delete via modal dialogs. Click "Create" to open
  a JSON editor for a new entity, "Edit" to modify an existing one,
  or "Delete" to remove it. Changes are sent via `POST`, `PUT`, and
  `DELETE` to the entity CRUD endpoints.
- **AI ops view**: an "AI Ops" view showing AI credential pool
  health (active/exhausted/cooldown), MCP sessions and tools, and
  experiment prompt overrides.

## Runnable demo

Run this feature against a live gateway: [`demos/09-operations/`](https://github.com/shristilabs/dwara/tree/main/demos/09-operations) (test
script: `test-06-web-console.sh`) in the repository.
The category README covers prerequisites and teardown.
