# Web Console v1 (Read-Only, OSS) (DW-117)

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

The console is read-only: no PATCH/POST/PUT/DELETE. The SPA only
fetches data from the admin API. A v2 (full CRUD + fleet/workspace
views, Enterprise) is a follow-on (DW-118).

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
