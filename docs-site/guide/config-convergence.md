# Config convergence

By default each gateway instance serves only its local config
generation: the file watcher reloads on a local file change,
and the new generation is published to the in-process snapshot. Two or
more instances behind a load balancer do not share config state -- a
reload on one is invisible to the others until each independently
reloads.

Config convergence (an enterprise feature) shares config
generation state across instances via a backend ([Redis](https://en.wikipedia.org/wiki/Redis_(software)) (an in-memory data store) in v1; [etcd](https://en.wikipedia.org/wiki/Etcd) (a distributed key-value store) and
[Consul](https://en.wikipedia.org/wiki/Consul_(software)) (a service-mesh and key-value store) are deferred behind the `ConfigConvergenceBackend` trait). Each
instance publishes its current generation to the backend and polls for
generations published by other instances, converging (all instances reaching the same config generation) to the highest
generation within the configured poll interval. A drift (instances serving different configs) report is
emitted when instances diverge.

## When to use this

Config convergence is for a fleet of two or more gateway instances that
must share config state, so a reload on one converges to all within the
poll interval — instead of each instance reloading independently. For a
single instance, the local file watcher is sufficient.

## Requirements

All three conditions must hold for convergence to activate:

1. The `ent` cargo feature is compiled in
   (`cargo build --features ent`).
2. The config carries an enabled `config_convergence` block.
3. The loaded license grants the `config_convergence` feature claim.

When any condition is missing, the block is accepted but inert and the
local file watcher runs alone. A one-line notice is logged at startup.

## Configuration

Add a `config_convergence` block to your gateway config:

```yaml
gateway:
  config_convergence:
    enabled: true
    backend: redis
    redis_url: redis://127.0.0.1:6379
    key_prefix: "dwara:config"            # optional, default "dwara:config"
    poll_interval_ms: 1000                # optional, default 1000, range 100..=60000
    drift_check_interval_ms: 5000         # optional, default 5000, range 1000..=300000
    fail_open: true                       # optional, default true
```

| Field | Default | Range | Description |
|---|---|---|---|
| `enabled` | `false` | bool | Master switch. `false`: convergence is inert (local file watcher only). `true` (and licensed): the coordinator publishes and polls. |
| `backend` | required | `"redis"` | Convergence backend type. v1 ships `redis`; etcd and Consul are deferred. |
| `redis_url` | required (redis) | non-empty URL | Redis connection URL (e.g. `redis://host:6379`). Required when `backend = "redis"`. |
| `key_prefix` | `dwara:config` | non-empty string | Prefix for convergence keys in Redis. Instance records live under `{prefix}:instances`; config bodies under `{prefix}:config:{generation}`. |
| `poll_interval_ms` | `1000` | 100..=60000 | How often to poll the backend for remote generations. Lower values converge faster at the cost of backend load. |
| `drift_check_interval_ms` | `5000` | 1000..=300000 | How often to read all instances and report drift. |
| `fail_open` | `true` | bool | When the backend is unreachable: `true` keeps serving the local config (convergence pauses); `false` refuses to start at cold start. |

## How it works

The convergence coordinator runs alongside the local file watcher. The
flow for a config change is:

1. **Local reload.** A file change (or SIGHUP) triggers the normal
   reload pipeline: validate, compile, and atomically publish a new
   generation via `compile_and_publish`.
2. **Publish.** After a successful local reload, the coordinator
   publishes the new generation to the backend: it upserts this
   instance's record (instance id, generation, config hash, timestamp)
   and stores the config body (normalized YAML) for that generation.
3. **Poll.** Every `poll_interval_ms`, the coordinator re-publishes its
   current generation (refreshing the record's [TTL](https://en.wikipedia.org/wiki/Time_to_live) (how long a record lives before expiring)) and reads every
   other instance's record. If another instance published a higher
   generation with a different config hash, the coordinator loads that
   generation's config body from the backend.
4. **Converge.** The loaded config is re-parsed and re-published
   locally through `compile_and_publish` -- the same pipeline a local
   reload uses, so validation/compile failures keep the running
   generation. On success, the coordinator re-publishes its converged
   generation so the backend reflects it immediately.
5. **Drift check.** Every `drift_check_interval_ms`, the coordinator
   reads all instances' generations and reports drift: if one or more
   instances serve a different config hash than the majority, a
   structured warning is logged and the `dwara_config_convergence_drift`
   gauge flips to 1.

The done-when target is sub-second convergence: with
`poll_interval_ms = 100`, an instance detects and converges to a remote
change within 100 ms plus one Redis round-trip (one request and its response).

## Fail-open behavior

When the convergence backend is unreachable, `fail_open: true` (the
default) keeps serving the local config generation -- convergence
pauses until the backend recovers, but the gateway stays available.
The local file watcher still reloads on a local file change.

`fail_open: false` refuses to start at cold start when the backend
cannot be reached (the gateway exits 1). At runtime the coordinator
always continues serving local config regardless of the setting -- a
backend outage mid-run is never fatal.

## Instance identity

Each instance identifies itself in the backend by an instance id. The
id defaults to `{pid}-{startup_timestamp_ms}` (unique per process per
host); set the `DWARA_INSTANCE_ID` environment variable to override
(e.g. to a stable hostname or pod name for readability in drift
reports).

On graceful shutdown, the coordinator removes its instance record from
the backend so the cluster view does not list a dead instance. A
crashed instance's record auto-expires via the instances hash's TTL
(3x the poll interval).

## Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `dwara_config_convergence_generation` | gauge | `instance` | This instance's current convergence generation. |
| `dwara_config_convergence_instances` | gauge | none | Total instances the backend reports (cluster view). |
| `dwara_config_convergence_drift` | gauge | none | Drift flag: 1 when instances diverge, 0 when converged. |
| `dwara_config_convergence_refresh_total` | counter | none | Convergence refresh attempts (backend polls). |
| `dwara_config_convergence_refresh_failures_total` | counter | none | Convergence refresh failures (backend unreachable or malformed). |

## Backends

v1 ships a Redis backend (`RedisConvergenceBackend`). The
`ConfigConvergenceBackend` trait is the seam for alternative backends
-- etcd and Consul implementations are deferred and will plug into the
same `backend` config field when available.
