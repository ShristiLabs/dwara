# Feature reference

Dwara has two editions: **OSS** (the default build) and **Enterprise**
(built with `--features ent`). Every dataplane capability is compiled
into the OSS build — there are no optional capabilities to enable.
This page is the complete reference for what each edition includes,
build commands, and feature maturity.

For the high-level OSS vs Enterprise comparison, see
[Editions](./editions). For the license verification mechanics, see
[Enterprise licensing](./licensing).

## How features are gated

There are two layers of gating:

1. **Compile time.** The `ent` cargo feature compiles in the
   enterprise modules (`dwara-controller`, `dwara-edge`, workspaces,
   the Redis/Vault extensions, the license verifier, FIPS enforcement).
   OSS builds do not contain this code at all. Every other capability
   — H3, L4, OTLP, WASM, CEL, Cedar, GraphQL, gRPC-Web, protocol
   translation, semantic cache, plugins, PQ, etc. — is compiled into
   the default OSS build.

2. **Runtime license gate (`LicenseGate`).** When `ent` is compiled
   in, the gateway verifies a signed license file at startup and
   checks feature claims before activating enterprise features. A
   missing license, an expired license past the grace period, or a
   missing claim leaves the feature inert.

The result is a single degradation story: an expired license degrades
to the OSS feature set, and the `dwara_license_status` metric reports
the state.

## Build commands

### OSS (default)

```sh
cargo build --release
```

Every dataplane capability is included. This is the published OSS
binary.

### Enterprise

```sh
# Enterprise build (license required at runtime)
cargo build --release --features ent
```

### Diagnostics

```sh
# tokio-console diagnostics server (development)
DWARA_CONSOLE=1 cargo run -- -p dwara-bin --config config.yaml
```

### Loom (concurrency model checking, test-only)

```sh
cargo test -p dwara-core --features loom --test loom
```

## Enterprise-only features

These require the `ent` cargo feature at build time AND a valid
license with the matching claim at runtime. Without `ent`, the code is
not compiled in. With `ent` but no license (or an expired license past
grace), the config is accepted but the feature is inert.

| Feature | What it adds | License claim |
|---|---|---|
| `ent` | Enterprise edition: license verification, Redis rate limiter/cache/convergence, CP/DP gRPC, workspaces, Vault/KMS, federated analytics, AI credential pools | (enables the license gate itself) |
| FIPS 140-3 mode | aws-lc-rs FIPS provider enforcement, self-test, restricted cipher suites, primitive allowlist | `fips` claim required |
| Service mesh | Sidecar controller + SPIFFE/SPIRE mTLS identity | `mesh` claim; validation warns when configured without `ent` |

The `ent` feature pulls in these enterprise-only modules (all
`#[cfg(feature = "ent")]`):

| Module | Purpose |
|---|---|
| `extensions::redis_rate_limiter` | Distributed Redis-backed GCRA rate limiter |
| `extensions::redis_cache` | Redis-backed distributed response cache |
| `extensions::config_convergence` | Config convergence backend (Redis) |
| `extensions::vault_secrets` | HashiCorp Vault and KMS secret resolution |
| `extensions::licensing` | Ed25519 license file verification + `LicenseGate` |
| `workspace` | Multi-tenant config partitioning + RBAC + audit |
| `cp_dp` | Control plane / data plane split (controller + edge) |
| `dataplane::convergence` | Runtime convergence coordinator |

## Enterprise-only config blocks

These config fields are present in the schema in both OSS and
Enterprise builds (so configs round-trip), but require `ent` + a
valid license to activate. In an OSS build they are accepted and
inert, with two exceptions noted below.

| Config path | What it controls | OSS behavior |
|---|---|---|
| `gateway.license` | Signed license file path + grace period | Accepted, ignored |
| `gateway.redis_rate_limiter` | Distributed Redis rate limiter | Accepted, inert |
| `gateway.config_convergence` | Shared config convergence (Redis) | Accepted, inert |
| `gateway.fleet` | Version-skew policy for CP/DP fleet | Accepted, inert |
| `gateway.mesh` | Service mesh sidecar + SPIFFE mTLS | Accepted, **validation warns** |
| `ai.providers[].credential_pool` | Multi-key AI provider credential rotation | **Validation rejects** |
| `upstreams[].locality` | Locality-aware routing / data residency | Accepted, inert |

### Validation behavior in OSS builds

Two enterprise config blocks are explicitly rejected or warned in OSS
builds (the rest are silently accepted and inert):

- **`ai.providers[].credential_pool`** -- validation emits an error:
  "credential pools require the enterprise edition (build with
  --features ent)". The config is rejected at publish time.
- **`gateway.mesh`** -- validation emits a warning:
  "the mesh block is configured but the `ent` cargo feature is not
  compiled in". The config is accepted but the mesh is inert.

All other enterprise config blocks parse and validate normally in OSS
builds. This lets operators stage enterprise configs before obtaining
a license.

## Runtime license claims

When built with `ent`, the `LicenseGate` checks feature claims from
the signed license file before activating enterprise features:

| Claim string | Feature activated |
|---|---|
| `redis_rate_limiter` | Distributed Redis rate limiter |
| `config_convergence` | Config convergence across instances |
| `fips` | FIPS 140-3 mode enforcement |

If a claim is missing, the feature logs a `*_not_licensed` warning and
falls back to OSS behavior. The gateway never crashes on a missing
claim.

The FIPS claim has an additional rule: if the license claims `fips`
but the binary was not built with the `ent` cargo feature, the gateway
**refuses to start** (exit 1). This prevents an operator from
accidentally running a non-FIPS binary in an environment that expects
FIPS compliance.

## Incompatible feature combinations

| Combination | Status |
|---|---|
| FIPS + PQ | **Incompatible.** FIPS mode restricts cipher suites to FIPS-approved primitives; post-quantum hybrid key exchange (ML-KEM) is not FIPS-approved. Do not combine. |

## Feature maturity

Some capabilities ship as library-complete components with their
gateway wiring still landing. Each capability's guide page carries a
status note saying exactly what is wired today.

| Status | Capabilities |
|---|---|
| Wired end to end | OTLP export, console diagnostics, Kubernetes Gateway API, proxy-wasm host, native filter chain, CEL expressions, Cedar policies, OpenAPI validation, API aggregation, HTTP/3, gRPC-Web, protocol translation, semantic cache, nano-services, post-quantum TLS |
| Config-accepted, runtime partially wired | L4 TCP/UDP proxying, GraphQL awareness, API lifecycle, A2A protocol, certificate pinning, SOAP translation |
| Config-accepted, runtime stubbed | MCP gateway, service mesh, Extism PDK, signed URL auth, ACME automation |
