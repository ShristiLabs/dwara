# Editions: OSS vs Enterprise

Dwara is [open-core](https://en.wikipedia.org/wiki/Open-core_model): one
codebase, two editions. The **OSS edition** (the default build,
Apache-2.0) is a complete, production-grade API gateway with every
dataplane capability compiled in. The **Enterprise edition** adds the
features that span multiple gateway instances or require external
infrastructure — fleet coordination, shared state, multi-tenant
management, and integrations — behind a commercial license.

The split is deliberate: everything a *single* gateway needs to serve
production traffic is OSS. Enterprise features are the ones that only
make sense once you are operating *many* gateways as one system.

## How the editions differ

| | OSS | Enterprise |
|---|---|---|
| Build | `cargo build --release` | `cargo build --release --features ent` |
| License | Apache-2.0 | Apache-2.0 core + BSL-1.1 `licensing-core` |
| Activation | None | Signed license file (Ed25519-verified) |
| External dependencies | None required (SQLite is embedded) | Redis for shared state; Vault/KMS optional |
| Topology | Independent instances | Control plane + coordinated data-plane fleet |
| Degradation | N/A | Expired license degrades gracefully to the OSS feature set |

In an OSS build, every enterprise feature is **inert but accepted**: a
config block for one parses, is validated, and is then ignored — the
gateway runs in OSS mode regardless. An enterprise build verifies the
license at startup and activates features per license claim. See
[Enterprise licensing](./licensing) for the license mechanics, grace
period, and the `dwara_license_status` metric.

## Software components by edition

| Component | OSS | Enterprise | Purpose |
|---|---|---|---|
| `dwara` gateway binary | yes | yes | Data plane + embedded admin listener + optional SQLite state and analytics |
| `dwara` CLI | yes | yes | `validate`, `fmt`, `diff`, `lint`, `schema`, `import`, `upgrade` |
| `dwara-loadgen` | yes | yes | Load-generator rig for benchmarking |
| `dwara-controller` | no | yes | Control plane: compiles config generations, pushes them to edges over gRPC (leader-elected, HA) |
| `dwara-edge` | no | yes | Data-plane instance fed by the controller; caches the last generation so it survives controller outages |
| License gate | no | yes | Runtime activation of enterprise features from license claims |

## Feature comparison

Legend: **OSS** — in the default build. **Ent** — enterprise edition,
requires the `ent` build and a license.

### Core gateway (proxying and routing)

| Feature | OSS | Enterprise |
|---|---|---|
| Reverse proxy (HTTP/1.1, h2, h2c) | OSS | — |
| TLS termination (multi-SNI certificates) and SNI passthrough | OSS | — |
| Routing: exact, path-parameter, regex, prefix | OSS | — |
| Path/query rewrites and redirects | OSS | — |
| Load balancing (round robin, least-requests, ip-hash, random, slow start) | OSS | — |
| Traffic splitting (canary, blue-green) and sticky sessions | OSS | — |
| Request/response transforms, security headers | OSS | — |
| Response field masking | OSS | — |
| API versioning (path/header/query/Accept, Deprecation/Sunset) | OSS | — |
| gRPC and WebSocket proxying | OSS | — |
| CORS, compression, request limits | OSS | — |
| Dynamic upstream discovery (DNS) | OSS | — |
| API aggregation (multi-upstream composition) | OSS | — |
| OpenAPI import, mock mode, response validation | OSS | — |
| Kubernetes Gateway API / Ingress translation | OSS | — |
| HTTP/3 (QUIC) ingress and upstream | OSS | — |
| L4 TCP/UDP proxying with SNI routing reuse | OSS | — |

### Traffic policy and resilience

| Feature | OSS | Enterprise |
|---|---|---|
| Passive and active health checks | OSS | — |
| Retries with budgets, timeouts | OSS | — |
| Circuit breaking | OSS | — |
| Load shedding and priority-aware admission | OSS | — |
| Admission queues with backpressure | OSS | — |
| WAF-lite heuristic filtering (SQLi/XSS/traversal) | OSS | — |
| Maintenance mode and policy dry-run | OSS | — |
| Request hedging | OSS | — |
| Mirroring and fault injection | OSS | — |
| Rate limiting (local GCRA, stacked windows) | OSS | — |
| Distributed rate limiting (shared Redis buckets) | — | Ent |
| Response caching (local, TTL/ETag/stale-while-revalidate) | OSS | — |
| Distributed cache (two-tier, shared Redis) | — | Ent |

### Security and authentication

| Feature | OSS | Enterprise |
|---|---|---|
| API key, Basic, JWT via JWKS, mTLS client-cert, HMAC request signing | OSS | — |
| OAuth2 client-credentials, mTLS consumer mapping | OSS | — |
| OpenID Connect | OSS | — |
| Authorization chain (consumer/route/service/listener/global, IP ACL) | OSS | — |
| Secrets via `${...}` references (env, file, static) | OSS | — |
| HashiCorp Vault and KMS secret resolution | — | Ent |
| Cedar policy / OPA authorization | OSS | — |
| CEL expressions in policies | OSS | — |
| FIPS 140-3 mode (cipher-suite restriction, primitive allowlist) | — | Ent |
| Post-quantum TLS hybrid key exchange (X25519 + ML-KEM) | OSS | — |
| Workspaces (multi-tenant config partitioning) | — | Ent |
| Admin RBAC (roles, permissions scoped to workspaces) | — | Ent |
| Append-only audit log of admin changes | — | Ent |

### Config management and operations

| Feature | OSS | Enterprise |
|---|---|---|
| Single strict YAML config, hot reload (file watch / SIGHUP) | OSS | — |
| mTLS admin API (`GET`/`PATCH /config`, `/health`, `/stats`) | OSS | — |
| CLI tooling (`validate`, `fmt`, `diff`, `lint`, `schema`) | OSS | — |
| Config import (NGINX, Kong, Envoy) | OSS | — |
| Zero-downtime binary upgrade | OSS | — |
| Config convergence across instances (Redis-backed) | — | Ent |
| Cluster sync GA (conflict resolution, split-brain guards, version skew) | — | Ent |
| CP/DP split (`dwara-controller` / `dwara-edge` fleet) | — | Ent |
| Web console v2 (CRUD + fleet) | — | Ent |
| Fleet operations (version skew, rolling upgrades) | — | Ent |
| tokio-console diagnostics integration | OSS | — |

### Observability and analytics

| Feature | OSS | Enterprise |
|---|---|---|
| Structured logs, access logs, spans, `/metrics` | OSS | — |
| OTel metrics export | OSS | — |
| Embedded analytics (request records, rollups, bounded disk) | OSS | — |
| Analytics stream (NDJSON firehose to external sinks) | OSS | — |
| Alert and event webhooks | OSS | — |
| Synthetic monitoring (built-in probes feeding analytics) | OSS | — |
| Usage reports and exports, quotas and metering | OSS | — |
| ML insights (forecast, anomaly detection) | OSS | — |
| Business metrics dimensions | OSS | — |
| Federated analytics (cross-edge aggregation) | — | Ent |

### Traffic and routing

| Feature | OSS | Enterprise |
|---|---|---|
| Global load balancing (locality-aware) | — | Ent |
| Data residency (region-restricted routing) | — | Ent |
| Adaptive limits (origin-driven) | OSS | — |
| Anomaly scoring + latency-aware LB | OSS | — |
| Auto-canary analysis | OSS | — |

### AI gateway

| Feature | OSS | Enterprise |
|---|---|---|
| AI provider adapters (OpenAI/Anthropic/Gemini) | OSS | — |
| AI routing, failover, canary | OSS | — |
| Token rate limiting & budgets | OSS | — |
| Cost attribution & metering | OSS | — |
| Provider credential pools | — | Ent |
| Prompt/response logging | OSS | — |
| Guardrails pack | OSS | — |
| Semantic caching | OSS | — |
| Model governance | OSS | — |
| Fallback chains & routing policy | OSS | — |
| Prompt experimentation | OSS | — |
| MCP gateway | OSS | — |
| Agent principals & governance | OSS | — |
| A2A (agent-to-agent) protocol support | OSS | — |

### Extensibility

| Feature | OSS | Enterprise |
|---|---|---|
| proxy-wasm host (community Kong/Envoy filters) | OSS | — |
| Native Rust filter chain | OSS | — |
| Extension traits (RateLimiter, ConfigSource, CacheStore, AnalyticsSink, SecretSource) | OSS | — |
| Agent-operable administration (MCP) | OSS | — |

The extension traits are OSS in both editions — enterprise backends
(Redis, Vault) are simply additional implementations of the same seams.

## How gating works

There are two gates, and every enterprise feature passes both:

1. **Compile time.** The `ent` cargo feature compiles in the
   enterprise modules (`dwara-controller`, `dwara-edge`, workspaces,
   the Redis/Vault extensions, the license verifier, FIPS enforcement).
   OSS builds do not contain this code at all.
2. **Runtime.** The license gate (`LicenseGate`) verifies the signed
   license at startup and checks each feature's claim before the
   feature engages. A missing block, an OSS build, or an expired
   license past the grace period leaves the feature inert — never
   half-active.

The result is a single degradation story: an expired license degrades
the gateway to the OSS feature set (traffic keeps flowing; fleet
coordination pauses), and the `dwara_license_status` metric tells you
which state you are in. See [Enterprise licensing](./licensing).

### Compile-time feature packs

Separate from the edition question, some advanced surfaces ship as
optional compile-time capabilities — `wasm` (the proxy-wasm host),
`plugins` (native filters), `cel`, `aggregation`, `mcp`. They are
default-OFF and not included in the published binaries: their library
components are complete in the source tree, and a build that carries
one enables its config block. A config block for a capability the
build lacks is rejected at validation — unlike an enterprise feature
in an OSS build, which parses and validates but stays inert. Status
notes on the individual guide pages say where each capability stands
today.

## Choosing an edition

- **One gateway, or a few independent gateways** behind a load
  balancer with the same config: the OSS edition is complete for this.
  Nothing about production readiness — TLS, authn/authz, rate limiting,
  resilience, observability — is held back.
- **A fleet that must behave as one system**: shared rate-limit
  budgets, config that converges everywhere on reload, a control plane
  pushing generations to edges — that coordination layer is the
  enterprise edition.
- **Multi-tenant operations**: teams or tenants that own isolated
  slices of gateway config with per-workspace RBAC and an audit trail
  — enterprise.
- **Enterprise secret infrastructure** (Vault, KMS) — enterprise.
- **FIPS 140-3 compliance** — enterprise (the enforcement layer is
  `ent`-gated; the aws-lc-rs FIPS provider is installed in every build).
