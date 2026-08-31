# Deployment and operations

Everything you need to run Dwara in production and keep it running:
getting the binary into place, reloading config without restarts,
swapping the binary under load, and the operator surfaces for
inspecting and patching a live gateway.

If you are new, start with [Getting started](./getting-started) and
[Installation](./installation) first; this section assumes the gateway
is already built or downloaded.

## In this section

- [Deployment](./deployment) - the one-command TLS demo and production
  topology notes.
- [Operations](./operations) - config reload (file watcher + SIGHUP),
  graceful shutdown, and the day-to-day knobs.
- [Zero-downtime upgrade](./zero-downtime-upgrade) - swap the gateway
  binary under load with no failed requests or reset connections.
- [CLI](./cli) - the `dwara-cli` operator tool for validating, formatting,
  diffing, and linting configs without standing up a gateway.
- [Admin API](./admin-api) - the mTLS-only operator surface for live
  config inspection and patching.
