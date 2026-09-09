# Category 11: Enterprise Features

This demo documents dwara's enterprise feature surface and verifies the
OSS-equivalent behavior the gateway provides today. The enterprise edition
adds a control plane / data plane split, distributed cache, Redis-backed
rate limiters, Vault/KMS secrets, workspace RBAC, federated analytics,
credential pools, service mesh, and licensing -- all built on top of the
same extension-trait boundary (RateLimiter, CacheStore, SecretSource,
AnalyticsSink, ConfigSource) that the OSS edition ships local
implementations for.

> **Important:** This demo uses the **OSS edition** image (`dwara:demo`,
> built from `Dockerfile.scratch` at the repo root). Enterprise features are
> **documented but not fully demonstrated** -- the `ent` cargo feature is
> not compiled in, so enterprise-only config blocks are accepted but inert
> at runtime. The gateway logs a notice for each inert block and falls back
> to the OSS equivalent. To run the full enterprise topology, see the
> [enterprise quickstart](../../quickstart/enterprise/).

## Enterprise features overview

| Feature | Config block | OSS status | Enterprise edition |
|---------|-------------|------------|-------------------|
| CP/DP split | (separate binaries) | Not available | `dwara-controller` + `dwara-edge` binaries, gRPC config broadcast |
| Config convergence | `gateway.config_convergence` | Accepted, inert (local file watcher only) | Redis-backed peer-to-peer convergence |
| Distributed cache | (no config block; CacheStore trait) | Local in-memory (moka) cache | Redis-backed cache with Pub/Sub invalidation |
| Redis rate limiters | `gateway.redis_rate_limiter` | Accepted, inert (local GCRA limiter) | Redis-backed GCRA, fleet-shared limits |
| Redis quotas | `gateway.redis_quotas` | Accepted, inert (local SQLite quotas) | Redis-backed quotas, fleet-shared counters |
| Vault secrets | (no config block; SecretSource trait) | File/env secret resolution (`${...}` grammar) | Vault KV v2 with TTL caching |
| KMS secrets | (no config block; SecretSource trait) | File/env secret resolution (`${...}` grammar); `secret_sources:` rejected at validation | Envelope encryption: `key_id:ciphertext` refs decrypted by aws-kms/gcp-kms/azure-kv |
| Workspace RBAC | (enterprise management plane) | Not available | Multi-workspace isolation + RBAC bindings |
| Audit log | `admin.audit` (SEC-01 shape) | Accepted, inert (no runtime consumer) | Append-only workspace audit log via `GET /workspaces/<name>/audit` |
| Federated analytics | (no config block; AnalyticsSink trait) | Embedded local SQLite analytics store | Edge-to-controller gRPC streaming (DW-095) |
| Credential pools | `ai.providers[].credential_pool` | Rejected at validation (ent-gated) | Multi-key rotation with 429 quarantine (DW-080) |
| Service mesh | `gateway.mesh` | Accepted, inert (validation warns) | Sidecar mode with SPIFFE/SPIRE mTLS (DW-107) |
| Cluster sync GA | `gateway.fleet` (skew/waves) | Accepted, inert | Conflict resolution + split-brain guards + version skew (DW-074) |
| Fleet operations | `gateway.fleet` | Accepted, inert | Version-skew policy + fleet status endpoints (DW-098) |
| Licensing | `gateway.license` | Accepted, inert (LicenseGate::none()) | License verification + feature-claim gating (DW-032) |
| Controller persistence | (controller flags/env, no YAML block) | Not available (single-node SQLite state) | PostgreSQL store: snapshots, license, membership, analytics |

### CP/DP split (control plane / data plane)

The enterprise edition's flagship topology: a `dwara-controller` watches a
config file, compiles changes, publishes generations, and broadcasts them
over gRPC to `dwara-edge` data planes. Each edge writes the received config
to a local file, and its gateway hot-reloads. One config file reconfigures
the whole fleet.

The OSS image does not include the `dwara-controller` or `dwara-edge`
binaries -- those require the `ent` cargo feature. This demo runs a
single-node OSS gateway instead.

**Reference:** `quickstart/enterprise/docker-compose.yml` (controller +
edge-1 + edge-2 + gateway-1 + gateway-2 + upstream, built from
`Dockerfile.ent`).

### Config convergence (DW-054)

Peer-to-peer config convergence: the gateway publishes its config generation
to a shared Redis backend and polls for generations published by other
instances, converging to the highest generation. This lets a fleet share
one config without a controller.

The config block is accepted but inert in OSS: the gateway logs a notice and
falls back to the local file watcher. The enterprise quickstart demonstrates
convergence via the CP/DP split (controller broadcasts to edges).

### Distributed cache (DW-068)

A Redis-backed `CacheStore` with coordinated invalidation via Redis Pub/Sub.
When one instance purges a cache entry, the purge propagates to all others.
There is no config-level block -- the `CacheStore` implementation is selected
at startup based on compiled features and license.

The OSS edition ships a local in-memory (moka) cache behind the same
`CacheStore` trait. The route-level `cache` block (DW-037) works in both
editions; only the backing store differs.

### Redis-backed rate limiters (DW-031)

The GCRA bucket state lives in Redis and is updated atomically via a Lua
script, so a fleet of N instances shares one rate limit. The config block
(`gateway.redis_rate_limiter`) is accepted but inert in OSS: the local
in-memory GCRA limiter is used instead.

### Redis-backed quotas (DW-155)

Distributed consumer request quotas: the counters live in Redis and are
updated atomically, so a fleet enforces the configured cap (not N x the cap).
The config block (`gateway.redis_quotas`) is accepted but inert in OSS.

### Vault/KMS secrets (DW-069)

Reads secrets from a Vault KV v2 engine or a KMS provider, with TTL-based
caching for rotation without restart. There is no config-level block -- the
`SecretSource` implementation is selected at startup. The OSS edition ships
file/env-based secret resolution via the `${...}` grammar (DW-045).

### KMS secrets (envelope encryption)

The KMS secret source stores secrets encrypted in the config (or a file)
and decrypts them at resolve time: a reference looks like
`kms:alias/dwara-secrets:<base64 ciphertext>`, and the provider
(`aws-kms`, `gcp-kms`, `azure-kv`, or a `mock` for tests) decrypts the
ciphertext with the named key. This keeps secrets encrypted at rest
without a live dependency on a secret server. Like Vault, the source
fails closed: an unresolvable secret prevents startup (or reload), never
a silent fallback.

The `secret_sources:` block from the guide is not part of the OSS config
schema -- a config carrying it is **rejected at validation** (unknown
field), mirroring the runtime fail-closed contract: the OSS build never
accepts a KMS source it cannot decrypt from. `test-11` verifies exactly
that rejection plus the healthy OSS secret path. See
[the KMS secrets guide](../../docs-site/guide/kms-secrets.md).

### Audit log (workspace audit, ent-gated)

The enterprise audit log is an append-only record of administrative
activity: every admin action is recorded with `seq` (monotonic,
gap-free), `timestamp`, `principal` (mTLS cert subject), `action`,
`workspace`, `before`/`after` state, and `request_id`. Entries cannot
be edited or deleted after the fact. It completes the multi-tenant
story: workspaces isolate, RBAC decides who may act, the audit log
records what they actually did. It is queried via the admin API
(`GET /workspaces/<name>/audit`).

The OSS-adjacent surface is the `admin.audit` block (SEC-01): when
present, mutating admin actions (PATCH /config, purge) are specified to
be recorded in an append-only audit table in the state store with the
actor (cert fingerprint or token hash), action, before/after config
hash, and timestamp. In the OSS build the block is **accepted but
inert** -- no runtime consumer records entries. The demo config ships
`admin.audit: {enabled: true}`; `test-12` verifies the gateway accepts
it and serves the admin API normally. See
[the audit log guide](../../docs-site/guide/audit-log.md).

### Workspace RBAC

Multi-workspace isolation with role-based access control for API management.
Workspaces partition consumers, routes, and policies into isolated namespaces.
The OSS edition does not have workspace isolation but does support admin API
RBAC (SEC-01): mTLS client cert fingerprints mapped to roles.

### Federated analytics (DW-095)

Edge-to-controller gRPC streaming: each edge gateway streams access records
to a central controller for fleet-wide aggregation. The OSS edition ships the
embedded local analytics store (DW-043): a separate SQLite file with
1m/5m/1h/1d additive rollups and per-granularity retention.

### Credential pools (DW-080)

Multi-key rotation for AI provider credentials with 429 quarantine,
round-robin or weighted pick, and pool-exhaustion graceful degradation. The
`credential_pool` block on AI providers is rejected at validation in OSS
(ent-gated). The OSS edition supports single-credential API key auth.

### Service mesh (DW-107)

Sidecar mode: dwara runs as a sidecar in each pod, intercepting traffic via
iptables/TPROXY redirect, with mTLS identity from SPIFFE/SPIRE X.509 SVIDs.
The config block (`gateway.mesh`) is accepted but inert in OSS (validation
warns). The OSS gateway functions as a regular reverse proxy.

### Licensing (DW-032)

The enterprise edition verifies a license file at startup and gates
enterprise features behind the license's feature claims. The public key
comes from the `DWARA_LICENSE_PUBLIC_KEY` env var (or the compiled-in
development key), never user-configurable. The config block
(`gateway.license`) is accepted but inert in OSS: the gate is always
`LicenseGate::none()`.

The enterprise edition uses a private `licensing-core` dependency (stubbed
out in OSS builds). The `vendor-licensing.sh` script in the enterprise
quickstart vendors the private dependency for Docker builds.

### Cluster sync GA (DW-074)

The GA-hardened convergence layer for the CP/DP split control plane,
adding production-grade convergence guarantees to the M3 gRPC
controller/edge design:

- **Conflict resolution:** when multiple controllers publish
  simultaneously (e.g. during a leader-election transition), the fleet
  resolves by `highest_generation` (default), `most_recent_timestamp`,
  or `leader_wins`.
- **Split-brain guards:** a controller is active if it heartbeated
  within the lease timeout. When more than one is active, the
  controller logs the active set, **edges refuse new generations** and
  keep serving their cached config until one controller remains -- two
  controllers can never push conflicting configs at once.
- **Version skew tolerance:** during rolling upgrades, edges may run
  different versions than the controller. The policy is `allow`,
  `allow_minor_skew` (default: same major, within one minor), or
  `require_exact`; an incompatible edge rejects the generation with a
  `VersionSkewError` and keeps serving cached config.
- **Chaos-validated:** partition, slow-member, and rollback scenarios
  must all converge for the GA gate.

The OSS gateway-side config surface is the `fleet` block (DW-098): the
skew policy, the rolling-upgrade wave order (`upgrade.order[]` entries
selected by `labels`, with a `max_concurrent` cap and
`halt_on_failure`), the controller reference version, and the
stale-edge timeout. It is **accepted but inert** in OSS. Note the
naming split: the gateway schema uses `fleet.upgrade.order[]`
(name + labels), while the `controller:` YAML in the guide
(`conflict_resolution`, `lease_timeout_seconds`) is the ent controller
binary's own config surface. `test-13` verifies the accepted block and
its schema shape. See
[the cluster sync guide](../../docs-site/guide/cluster-sync.md).

### Ent controller persistence (PostgreSQL)

The enterprise controller stores its durable state in PostgreSQL,
chosen by ADR: the controller is a multi-writer service (config
publishes, heartbeat updates, and analytics ingestion overlap), which
rules out SQLite's single-writer model; the query patterns (fleet
membership lookups, rollup aggregation, snapshot history) are
relational, which rules out an object store. Four categories of state
are persisted:

1. **Config snapshots** -- every published config version, immutable,
   with version, author, publish time, and the full YAML (served to
   data planes over cluster sync; retained for audit and rollback).
2. **License state** -- the license, its entitlements, and fleet-wide
   consumption counters, so entitlements survive a restart.
3. **Fleet membership** -- registered data-plane instances, their
   last-seen heartbeat, reported version, and health.
4. **Federated analytics** -- aggregated analytics streamed up from the
   data planes, persisted in rollup tables.

The store is accessed **only by the controller**; data planes receive
config and report heartbeats over the cluster-sync protocol and never
touch the database directly. There is no OSS-validate YAML surface for
the DSN (the controller launches via flags/env vars, documented in
`fixtures/ent-controller-launch.env`), and this demo deliberately ships no
postgres container -- `test-14` verifies the documented decision plus
the OSS single-node SQLite state store. See
[the ent controller persistence guide](../../docs-site/guide/ent-controller-persistence.md).

## Prerequisites

1. **Shared images built.** The demo upstream images and the gateway image
   must already exist:
   ```
   docker images | grep -E 'dwara:demo|dwara-demo/(echo|static)'
   ```
   If missing, build them from the `demos/_shared/upstreams/` Dockerfiles
   and the repo-root `Dockerfile.scratch` (tagged `dwara:demo`).

2. **Certs generated.** The shared certs at `demos/_shared/certs/` must
   exist (used for the admin API's mTLS and the config mount):
   ```
   ls demos/_shared/certs/server.crt demos/_shared/certs/server.key \
      demos/_shared/certs/client-ca.crt demos/_shared/certs/client.crt \
      demos/_shared/certs/client.key
   ```

3. **Docker Compose.** Docker and Docker Compose must be installed.

## How to run

### 1. Start the stack

```sh
cd demos/11-enterprise
docker compose up -d
```

This starts three containers on a shared bridge network:
- `dwara` -- the gateway on port 8080 (HTTP) + 2019 (mTLS admin API)
- `echo` -- the echo upstream (reflects requests as JSON)
- `static` -- the static upstream (serves demo files)

### 2. Wait for the gateway

```sh
curl -sf http://localhost:8080/healthz
# -> ok
```

### 3. Run the test scripts

Each test script sources `../_shared/helpers.sh`, waits for the gateway,
runs its assertions, and prints a pass/fail summary.

```sh
./test-01-cp-dp-split.sh
./test-02-convergence.sh
./test-03-distributed-cache.sh
./test-04-redis-limiters.sh
./test-05-vault-secrets.sh
./test-06-workspace-rb.sh
./test-07-federated-analytics.sh
./test-08-credential-pools.sh
./test-09-service-mesh.sh
./test-10-licensing.sh
./test-11-kms-secrets.sh
./test-12-audit-log.sh
./test-13-cluster-sync.sh
./test-14-ent-controller-persistence.sh
```

Or run them all at once:

```sh
for t in test-*.sh; do echo "--- $t ---"; ./"$t"; done
```

### 4. Tear down

```sh
docker compose down -v
```

## Expected results

| Test | What it verifies | Expected |
|------|-----------------|----------|
| test-01-cp-dp-split | Single-node gateway proxies (CP/DP baseline) | 200 on echo, static, healthz |
| test-02-convergence | Hot reload via local file watcher | Gateway still serves after config touch |
| test-03-distributed-cache | Proxy path (cache is transparent) | 200 on echo, static; consistent responses |
| test-04-redis-limiters | Local limiter path (proxy works) | 200 on 5 consecutive requests |
| test-05-vault-secrets | OSS secret resolution (gateway starts) | 200 on healthz, echo, static |
| test-06-workspace-rb | Admin API mTLS (OSS admin RBAC surface) | 200 on admin /health and /stats |
| test-07-federated-analytics | Local analytics store active | 200 on admin /stats, contains request data |
| test-08-credential-pools | Basic auth path healthy | 200 on echo, static, healthz |
| test-09-service-mesh | Reverse proxy baseline | 200 on echo, static; stripped path visible |
| test-10-licensing | OSS licensing stub (inert block) | 200 on healthz, echo, static, admin /health |
| test-11-kms-secrets | OSS secret path + KMS fail-closed rejection | 200 on healthz/echo/static; `secret_sources:` rejected (unknown field) |
| test-12-audit-log | `admin.audit` block accepted-but-inert | 200 on healthz/echo, admin /health + /config; audit shape validates |
| test-13-cluster-sync | `fleet` block accepted-but-inert | 200 on healthz/echo/static, admin /health; fleet shape validates |
| test-14-ent-controller-persistence | Documented PostgreSQL store (no DB container) | 200 on healthz/echo/static; reference snippet + no-postgres guard |

All tests should pass with zero failures. Tests 11-13 additionally use
the **host** operator CLI (`dwara-cli`, at `target/debug/dwara-cli` or
`target/release/dwara-cli` after `cargo build -p dwara-cli`) for their
config-shape probes; the container image ships only the gateway server.

## Enterprise quickstart reference

The full enterprise topology (CP/DP split with controller + edges +
gateways) is at `quickstart/enterprise/`. To run it:

```sh
cd quickstart/enterprise
./vendor-licensing.sh          # vendor the private licensing-core
mkdir -p edge-1 edge-2
cp dwara.yaml edge-1/dwara.yaml
cp dwara.yaml edge-2/dwara.yaml
docker compose up               # builds Dockerfile.ent
curl --cacert ../certs/server.crt https://localhost:9443/
curl --cacert ../certs/server.crt https://localhost:9444/
```

The enterprise quickstart runs without a license for the CP/DP split
itself (compiled in by the `ent` build). Only the Redis-backed features
(distributed rate limiting, config convergence) need license claims.

## Config notes

The `dwara.yaml` in this demo includes five enterprise-adjacent config
blocks that are **accepted but inert** in the OSS build:

- `redis_rate_limiter` -- the URL and parameters are valid; the gateway
  logs a notice and uses the local in-memory GCRA limiter.
- `config_convergence` -- `enabled: false` with a Redis backend; the
  gateway logs a notice and uses the local file watcher only.
- `license` -- the file path is valid; the gateway does not read it
  (the OSS stub is always `LicenseGate::none()`).
- `admin.audit` (SEC-01 shape) -- the block round-trips through the
  running gateway, but no OSS runtime consumer records audit entries.
- `fleet` (DW-098 / DW-074) -- the skew policy and upgrade waves are
  valid; the gateway runs single-node (no controller, no fleet status
  endpoints).

These blocks are included to show the config shape an enterprise
deployment would use. Swapping the image to `Dockerfile.ent` + providing
a license file activates them.

Validate the config with:

```sh
cargo run -q -p dwara-cli --bin dwara-cli -- validate demos/11-enterprise/dwara.yaml
# -> ok: 3 routes
```

## Files

```
11-enterprise/
  docker-compose.yml           stack definition (gateway + echo + static)
  dwara.yaml                   gateway config (routes, admin, analytics, inert enterprise blocks)
  test-01-cp-dp-split.sh       CP/DP split architecture documentation + baseline
  test-02-convergence.sh       config convergence + hot reload verification
  test-03-distributed-cache.sh distributed cache documentation + proxy verification
  test-04-redis-limiters.sh    Redis rate limiters documentation + local limiter verification
  test-05-vault-secrets.sh     Vault/KMS secrets documentation + OSS secret path
  test-06-workspace-rb.sh      workspace RBAC documentation + admin mTLS verification
  test-07-federated-analytics.sh federated analytics documentation + local analytics
  test-08-credential-pools.sh  credential pools documentation + basic auth verification
  test-09-service-mesh.sh      service mesh documentation + reverse proxy baseline
  test-10-licensing.sh         licensing documentation + OSS stub verification
  test-11-kms-secrets.sh       KMS secrets documentation + fail-closed rejection
  test-12-audit-log.sh         audit log documentation + admin.audit inert block
  test-13-cluster-sync.sh      cluster sync documentation + fleet inert block
  test-14-ent-controller-persistence.sh controller persistence documentation
  fixtures/ent-controller-launch.env  controller launch-surface + PostgreSQL reference
  README.md                    this file
```
