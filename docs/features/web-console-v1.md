# Web Console (DW-117, DW-118)

## Overview

dwara ships a read-only web console -- a static SPA served from the
mTLS admin listener. The operator can diagnose an outage entirely
from the console; no dataplane deps (SPA is static).

## Architecture

The console is a static SPA (HTML + CSS + vanilla JS, no build step,
no dependencies) embedded at compile time via `include_str!`/
`include_bytes!`. No runtime file system dependency, no external
crate needed.

The SPA fetches from the admin API endpoints on the same origin:

- `GET /health` -- gateway health
- `GET /stats` -- gateway stats (active requests, upstreams)
- `GET /config` -- current config (routes, services)
- `GET /config_dump` -- current config as YAML
- `GET /analytics/top` -- analytics Top-N

## Serving

The console is served at `/console/` from the admin listener. The
admin handler checks for `/console` paths (via
`dwara_console::is_console_path`) before dispatching to the admin API
handlers.

## Views

### Overview

Gateway status, active requests, uptime, config epoch, route/listener
counts. Auto-refreshes every 5 seconds.

### Routes

Route table: name, path, service, methods.

### Upstreams

Upstream/service health table: service, address, health, requests,
errors.

### Health

Raw health JSON.

### Analytics

Top-N analytics.

### Config

Current config YAML dump.

## Read-only

The v1 console is read-only: no PATCH/POST/PUT/DELETE. The SPA only
fetches data from the admin API. The v2 upgrade (below) adds full
CRUD; the v1 read-only views remain.

## Web Console v2 (DW-118, Enterprise)

DW-118 upgrades the console from read-only to full CRUD, adds fleet
and workspace views, and a config editor with validation preview —
all still a static SPA (HTML + CSS + vanilla JS, no build step, no
dependencies), embedded at compile time via `include_str!`/
`include_bytes!`.

- **Full CRUD**: routes, services, policies, and consumers can be
  created, edited, and deleted via the admin API
  (`PATCH /config` publishes; the editor builds the patch in the
  browser). The v1 read-only views remain; v2 adds the editor views
  alongside them.
- **Fleet views**: version skew status (`GET /fleet/skew`) and fleet
  status (`GET /fleet/status`) surface the CP/DP split's edge health
  in the console — see
  [CP/DP split: fleet operations](./cp-dp-split.md#fleet-operations-dw-098-enterprise).
- **Config editor with validation preview**: `POST /config/validate`
  validates a candidate config without publishing it, so the operator
  sees errors before pressing publish (`PATCH /config`).
- **Workspace switcher**: `GET /workspaces` lists available
  workspaces; the operator switches context in the console.

## Web Console v3 (#226)

Console v3 adds live charts, per-entity CRUD flows, and an AI ops
view — all still a static SPA with no build step or dependencies.

- **Live charts**: a "Live" view fetches `/analytics/dashboard`,
  `/analytics/live`, and `/stats` in parallel, displaying stat cards
  (active requests, RPS, p50/p95/p99, error rate) and a canvas-based
  latency sparkline chart with a 60-point rolling history. A
  per-route live table shows RPS, p50, p95, and error counts.
- **CRUD flows**: the Routes and Upstreams views now use
  `renderCrudEntity()` — a generic CRUD view with a table, "Create"
  button (opens a modal with a JSON textarea), "Edit" button (opens
  a modal pre-filled with the entity JSON), and "Delete" button
  (confirms then calls `DELETE /<entity>/<name>`). Create calls
  `POST /<entity>`, Edit calls `PUT /<entity>/<name>`.
- **AI ops view**: an "AI Ops" view fetches `/ai/credential-pools`,
  `/mcp/sessions`, `/mcp/tools`, and `/experiments/prompt-overrides`
  in parallel, displaying credential pool health, MCP sessions and
  tools, and experiment prompt overrides.

Code: `crates/dwara-console/static/{index.html,style.css,app.js}`
(the SPA), `crates/dwara-console/src/lib.rs` (embedding + path
resolution).

## API

### resolve(path)

Resolve a console path to a `StaticFile` (body + content-type).
Returns `None` if the path is not a console path.

### is_console_path(path)

Check if a path is a console path (starts with `/console`).

### file_paths()

List all embedded file paths.

### FILE_COUNT

The number of static files embedded in the console.
