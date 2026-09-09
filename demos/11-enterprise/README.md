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
| Vault/KMS secrets | (no config block; SecretSource trait) | File/env secret resolution (`${...}` grammar) | Vault KV v2 + KMS providers with TTL caching |
| Workspace RBAC | (enterprise management plane) | Not available | Multi-workspace isolation + RBAC bindings |
| Federated analytics | (no config block; AnalyticsSink trait) | Embedded local SQLite analytics store | Edge-to-controller gRPC streaming (DW-095) |
| Credential pools | `ai.providers[].credential_pool` | Rejected at validation (ent-gated) | Multi-key rotation with 429 quarantine (DW-080) |
| Service mesh | `gateway.mesh` | Accepted, inert (validation warns) | Sidecar mode with SPIFFE/SPIRE mTLS (DW-107) |
| Fleet operations | `gateway.fleet` | Accepted, inert | Version-skew policy + fleet status endpoints (DW-098) |
| Licensing | `gateway.license` | Accepted, inert (LicenseGate::none()) | License verification + feature-claim gating (DW-032) |

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

All tests should pass with zero failures.

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

The `dwara.yaml` in this demo includes three enterprise-adjacent config
blocks that are **accepted but inert** in the OSS build:

- `redis_rate_limiter` -- the URL and parameters are valid; the gateway
  logs a notice and uses the local in-memory GCRA limiter.
- `config_convergence` -- `enabled: false` with a Redis backend; the
  gateway logs a notice and uses the local file watcher only.
- `license` -- the file path is valid; the gateway does not read it
  (the OSS stub is always `LicenseGate::none()`).

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
  README.md                    this file
```
