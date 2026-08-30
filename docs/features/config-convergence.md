# Config Convergence (DW-054)

## Overview

Config convergence shares config generation state across gateway
instances via a backend (Redis in v1; etcd and Consul are deferred
behind the `ConfigConvergenceBackend` trait). Each instance publishes
its current generation to the backend and polls for generations
published by other instances, converging to the highest generation
within the configured poll interval. A drift report is emitted when
instances diverge.

This is an enterprise feature, gated behind the `ent` cargo feature and
the `config_convergence` license claim.

## Architecture

```
Local file watcher (DW-006) -----> compile_and_publish
                                        |
                                        v
                                  ConfigState (Snapshot)
                                        |
                                   ConvergenceCoordinator
                                        |
                          +-------------+-------------+
                          |                           |
                          v                           v
                   publish_generation            watch_generations
                   (upsert record + body)        (poll every poll_interval_ms)
                          |                           |
                          |                           v
                          |                  converge_remote?
                          |                  (higher gen, diff hash)
                          |                           |
                          |                           v
                          |                  load_config -> compile_and_publish
                          |                  (same pipeline as local reload)
                          v
                   ConfigConvergenceBackend (Redis)
```

### ConfigConvergenceBackend trait

`extensions/config_convergence.rs::ConfigConvergenceBackend` is the
swappable backend seam (async, dyn-compatible via `async-trait`). Four
methods:

- `publish_generation`: upsert this instance's record + store the
  config body for the generation.
- `watch_generations`: read every instance's current record (the poll).
- `load_config`: fetch a generation's config body (for remote
  convergence).
- `remove_instance`: delete this instance's record on shutdown.

v1 ships `RedisConvergenceBackend`. etcd and Consul implementations are
deferred and will implement the same trait against their native
clients.

### Redis key format

Instance records live in a Redis hash at `{prefix}:instances` (one
field per instance id, value `generation|config_hash|timestamp`). Config
bodies live at `{prefix}:config:{generation}`. The instances hash
carries a TTL (3x the poll interval) so a crashed instance's record
auto-expires; a graceful shutdown removes the field explicitly.

### ConvergenceCoordinator

`dataplane/convergence.rs::ConvergenceCoordinator` orchestrates the
snapshot publish pipeline, the backend trait, and the observability
registry. It lives in the dataplane (the top of the core dependency
graph) because `snapshot` may not import `extensions` (the dependency
direction is strictly downward and enforced by
`scripts/check_deps.py`); the dataplane already hosts the comparable
long-running background tasks (active health, DNS discovery).

The coordinator's background task:

1. polls the backend at `poll_interval_ms`, re-publishing this
   instance's current generation (refreshing the record's TTL) and
   checking for a higher generation with a different config hash;
2. at `drift_check_interval_ms`, reads all instances' generations and
   reports drift (instances with different config hashes) via a
   structured log + the `dwara_config_convergence_drift` metric;
3. on shutdown, removes this instance's record from the backend.

The task is cancellable: it selects on a shutdown watch and exits
(after the remove-instance best-effort) when the watch fires.

### Fail-open

When the backend is unreachable, `fail_open: true` (the default) keeps
serving the local config and pauses convergence until the backend
recovers; `fail_open: false` refuses to start at cold start. At runtime
the coordinator always continues serving local config regardless -- a
backend outage mid-run is never fatal (the local file watcher still
reloads).

## Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `dwara_config_convergence_generation` | gauge | `instance` | This instance's current convergence generation. |
| `dwara_config_convergence_instances` | gauge | none | Total instances the backend reports. |
| `dwara_config_convergence_drift` | gauge | none | Drift flag: 1 when instances diverge, 0 when converged. |
| `dwara_config_convergence_refresh_total` | counter | none | Convergence refresh attempts. |
| `dwara_config_convergence_refresh_failures_total` | counter | none | Convergence refresh failures. |

## License gating

The feature is activated only when ALL three conditions hold:

1. The `ent` cargo feature is compiled in.
2. The config carries an enabled `config_convergence` block.
3. The loaded license grants the `config_convergence` feature claim.

When any condition fails, the block is accepted but inert and the local
file watcher runs alone. A one-line notice is logged at startup. The
license check runs at startup in `dwara-bin` (where a missing claim
logs a warning and falls back to local-only mode), NOT in the compile
pipeline -- a license's validity is a runtime property that can change
between reloads without a config-schema change.

## Testing

`crates/dwara-core/tests/config_convergence.rs` (ent-gated) covers the
four scenarios from the story using an in-memory `MemoryBackend`
(deterministic, no Redis required):

1. Two instances converge within the poll interval.
2. Drift is detected and reported.
3. Fail-open when the backend is unreachable.
4. Instance removal on shutdown.

A real-Redis smoke test is gated on the `REDIS_URL` env var (skipped
when unset).
