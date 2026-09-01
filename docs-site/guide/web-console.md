# Web console

The web console is a read-only single-page application served from
the gateway's mTLS admin listener. It provides a browser-based
dashboard for inspecting the running gateway -- routes, services,
upstreams, health, metrics, and recent requests -- without any
external dependencies.

## When to use this

Use the web console when:

- You want a quick visual overview of the gateway state without
  running `curl` against the admin API.
- You are in a debugging session and want to see routes, health, and
  metrics in one place.
- You don't have a separate observability dashboard set up yet.

The console is **read-only**: it cannot modify config, purge cache,
or change any state. All mutations go through the admin API or CLI.

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

## Limitations

- **Read-only**: the console cannot modify any state. Use the admin
  API or CLI for mutations.
- **No historical data**: the console shows the current state and
  recent requests only. For historical analysis, use the analytics
  API or an external dashboard.
- **No separate auth**: the console has no login or token of its own
  -- it is exactly as accessible as the admin listener serving it.
  In production that means mTLS; on a developer machine,
  `DWARA_ADMIN_DEV=1` (loopback-only plaintext admin, see
  [Admin API](./admin-api#dev-fallback-never-in-production)) also
  serves the console in plaintext.
