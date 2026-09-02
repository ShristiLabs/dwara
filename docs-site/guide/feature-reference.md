# Feature reference

Every optional capability in dwara is a cargo feature flag that is
**default-OFF**. The default `cargo build` produces the OSS edition with
no optional packs. This page is the complete reference for all 28
feature flags, their edition gating, build commands, and what each
enables.

For the high-level OSS vs Enterprise comparison, see
[Editions](./editions). For the license verification mechanics, see
[Enterprise licensing](./licensing).

## How features are gated

There are three layers of gating, and every feature passes through the
ones that apply to it:

1. **Compile time (cargo feature).** Every optional pack is a cargo
   feature on `dwara-core` (and sometimes forwarded by `dwara-bin` or
   `dwara-cli`). The feature must be listed in `--features` at build
   time or the code is not compiled in.

2. **Enterprise compile gate (`ent`).** The `ent` cargo feature is a
   superset that pulls in the enterprise modules and dependencies
   (`licensing-core`, `redis`, `tonic`, `prost`, `tokio-stream`).
   Without `ent`, enterprise modules are absent from the binary.

3. **Runtime license gate (`LicenseGate`).** When `ent` is compiled
   in, the gateway verifies a signed license file at startup and
   checks feature claims before activating enterprise features. A
   missing license, an expired license past the grace period, or a
   missing claim leaves the feature inert.

The result is a single degradation story: an expired license degrades
to the OSS feature set, and the `dwara_license_status` metric reports
the state.

## All feature flags

### OSS feature packs

These packs are open-source (Apache-2.0, no license required) but
default-OFF because each adds binary size or a heavy dependency. Enable
them per build with `--features <name>`.

| Flag | Crate | What it adds | Why default OFF |
|---|---|---|---|
| `wasm` | dwara-core | proxy-wasm host runtime (wasmtime) | wasmtime + cranelift are a large binary-size cost |
| `nano_services` | dwara-core | WASM route handlers (implies `wasm`) | wasmtime dependency; opt-in extension model |
| `plugins` | dwara-core | Native Rust filter trait + unified dispatch chain | compile-in extension path, opt-in by design |
| `cel` | dwara-core | CEL expression evaluation in policies | cel-interpreter adds binary size |
| `cedar` | dwara-core | Cedar policy engine + OPA HTTP callout for authorization | cedar-policy adds binary size |
| `openapi_validation` | dwara-core | Upstream response validation against OpenAPI schemas; also used by AI guardrails schema enforcement | jsonschema adds binary size |
| `k8s` | dwara-core, dwara-cli | Kubernetes Gateway API / Ingress translation + controller | kube-rs + k8s-openapi add significant binary size |
| `aggregation` | dwara-core | Multi-upstream response composition (KrakenD-style) | aggregation buffers bodies (size-capped), kept off the default zero-buffering build |
| `mcp` | dwara-core | Agent-operable administration via MCP server/tools | opt-in attack-surface reduction |
| `semantic_cache` | dwara-core | Embedding-similarity cache for AI prompts (HNSW ANN) | hnsw_rs adds binary size; external embedding service required |
| `h3` | dwara-core, dwara-bin | HTTP/3 (QUIC) ingress listener + upstream transport | quinn + h3 add binary size |
| `a2a` | dwara-core | A2A (agent-to-agent) protocol support | opt-in; task lifecycle currently stubbed |
| `graphql` | dwara-core | GraphQL awareness: query depth/complexity limits, persisted-query enforcement | opt-in; only relevant for GraphQL traffic |
| `grpc_web` | dwara-core | gRPC-Web framing + JSON-to-gRPC transcoding | prost dependency; opt-in protocol support |
| `protocol_translation` | dwara-core | General protocol translation (REST to gRPC to GraphQL); implies `grpc_web` | prost dependency; opt-in protocol support |
| `soap` | dwara-core | SOAP/XML translation; implies `protocol_translation` | protocol_translation dependency; opt-in legacy protocol support |
| `pq` | dwara-core, dwara-bin | Post-quantum TLS hybrid key exchange (X25519 + ML-KEM) | experimental; must not be combined with `fips` |
| `l4` | dwara-core, dwara-bin | L4 TCP/UDP proxying with SNI routing reuse | opt-in; TCP splicing implemented, UDP stubbed |
| `api_lifecycle` | dwara-core | API lifecycle management: dev portal, environment profiles, journey recorder | opt-in; config-accepted, runtime partially wired |
| `extism` | dwara-core | Extism PDK plugin runtime | opt-in; config-accepted, runtime stubbed |
| `cert_pinning` | dwara-core | Upstream TLS certificate pinning by SPKI hash | opt-in; scaffolded |
| `signed_url` | dwara-core | Signed URL request authentication (HMAC-SHA256) | opt-in; scaffolded |
| `otlp` | dwara-bin | OTLP trace/metrics export to a collector | opentelemetry stack adds ~405 KiB |
| `console` | dwara-bin | tokio-console diagnostics server | console-subscriber adds binary size |

### Enterprise features

These require the `ent` cargo feature at build time AND a valid
license with the matching claim at runtime. Without `ent`, the code is
not compiled in. With `ent` but no license (or an expired license past
grace), the config is accepted but the feature is inert.

| Flag | Crate | What it adds | License claim |
|---|---|---|---|
| `ent` | dwara-core, dwara-bin, dwara-cli | Enterprise edition: license verification, Redis rate limiter/cache/convergence, CP/DP gRPC, workspaces, Vault/KMS, federated analytics, AI credential pools | (enables the license gate itself) |
| `fips` | dwara-core, dwara-bin | FIPS 140-3 mode: aws-lc-rs FIPS provider, self-test, restricted cipher suites | `fips` claim required; binary refuses to start if the claim is present but the `fips` feature is not compiled |

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

## Feature dependency chains

Some features imply others. Cargo resolves these automatically when
you list the top-level feature:

```
soap -> protocol_translation -> grpc_web -> prost
nano_services -> wasm
```

For example, `--features soap` enables `protocol_translation` and
`grpc_web` transitively. You do not need to list them explicitly.

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
but the binary was not built with the `fips` cargo feature, the gateway
**refuses to start** (exit 1). This prevents an operator from
accidentally running a non-FIPS binary in an environment that expects
FIPS compliance.

## Build recipes

### OSS (default)

```sh
cargo build --release
```

No optional packs. This is the published OSS binary.

### OSS with common packs

```sh
# Add proxy-wasm filters and OpenAPI validation
cargo build --release --features wasm,openapi_validation

# Add HTTP/3 ingress and OTLP export
cargo build --release --features h3,otlp -p dwara-bin

# Add protocol translation (gRPC-Web, REST-to-gRPC, SOAP)
cargo build --release --features soap

# Add post-quantum TLS
cargo build --release --features pq -p dwara-bin

# Add L4 TCP/UDP proxying
cargo build --release --features l4 -p dwara-bin
```

### Enterprise

```sh
# Enterprise build (license required at runtime)
cargo build --release --features ent

# Enterprise + FIPS 140-3 mode
cargo build --release --features ent,fips

# Enterprise + proxy-wasm + HTTP/3
cargo build --release --features ent,wasm,h3 -p dwara-bin

# Enterprise + all protocol packs
cargo build --release --features ent,soap,h3,l4,pq -p dwara-bin
```

### Diagnostics

```sh
# tokio-console diagnostics server (development)
cargo build --features console -p dwara-bin
DWARA_CONSOLE=1 ./target/debug/dwara run --config config.yaml
```

### Loom (concurrency model checking, test-only)

```sh
cargo test -p dwara-core --features loom --test loom
```

## Incompatible feature combinations

| Combination | Status |
|---|---|
| `fips` + `pq` | **Incompatible.** FIPS mode restricts cipher suites to FIPS-approved primitives; post-quantum hybrid key exchange (ML-KEM) is not FIPS-approved. Do not combine. |

## Feature maturity

Some feature packs ship as library-complete components with their
gateway wiring still landing. Each pack's guide page carries a status
note saying exactly what is wired today.

| Status | Features |
|---|---|
| Wired end to end | `ent`, `otlp`, `k8s`, `wasm`, `plugins`, `cel`, `cedar`, `openapi_validation`, `aggregation`, `h3`, `grpc_web`, `protocol_translation`, `semantic_cache` |
| Config-accepted, runtime partially wired | `l4`, `graphql`, `api_lifecycle`, `mcp`, `a2a` |
| Config-accepted, runtime stubbed | `soap`, `extism`, `cert_pinning`, `signed_url`, `nano_services` |

The published OSS binaries and images are built with no packs enabled.
