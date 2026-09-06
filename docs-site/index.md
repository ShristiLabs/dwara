---
layout: home

hero:
  name: Dwara
  text: API gateway
  tagline: Predictable latency, defense-in-depth traffic policy, and one declarative YAML config for the edge in front of your APIs.
  image:
    src: /mark-color.svg
    alt: Dwara mark
  actions:
    - theme: brand
      text: Get started
      link: /guide/getting-started
    - theme: alt
      text: Installation
      link: /guide/installation
    - theme: alt
      text: Architecture overview
      link: /architecture/overview
    - theme: alt
      text: View on GitHub
      link: https://github.com/shristilabs/dwara

features:
  - title: Streaming dataplane
    details: "HTTP/1.1 and HTTP/2 proxying with no buffering by default -- SSE and large bodies pass through under frame-based backpressure. TLS termination (multi-SNI) and SNI passthrough, gRPC over h2, and managed WebSocket tunnels."
    link: /guide/grpc-websockets
    linkText: Protocols
  - title: Routing and rewrites
    details: "Exact (with path parameters), regex, and prefix matching with fixed precedence; host, method, header, query, and cookie criteria; strip/replace/regex rewrites, redirects, and direct responses."
    link: /guide/routing
    linkText: Routing
  - title: Resilience
    details: "Retries with bounded attempts and timeout budgets, circuit breaking, passive and active health checks with endpoint ejection, load shedding, admission queues, and request hedging."
    link: /guide/traffic-policy
    linkText: Traffic policy
  - title: Rate limiting and quotas
    details: "GCRA and stacked-window rate limits at global, listener, service, route, or consumer scope -- plus per-consumer daily and monthly request budgets over the durable state store."
    link: /guide/quotas
    linkText: Quotas
  - title: Authentication
    details: "API keys, Basic, JWT via JWKS, mTLS client certificates, and HMAC request signing. Secret references resolve at compile time with exhaustive redaction -- secrets never appear in logs or admin output."
    link: /guide/security
    linkText: Security
  - title: Authorization
    details: "Consumer and group allow/deny lists, JWT scopes and claims, IP ACLs, and GeoIP gates, attached at five precedence levels with deny-anywhere-wins semantics and a monitor-only dry-run mode."
    link: /guide/authorization
    linkText: Authorization
  - title: Observability
    details: "Structured JSON logs with request IDs, Prometheus /metrics on every listener, a uniform JSON error envelope, and optional OTLP trace and metrics export."
    link: /guide/observability
    linkText: Observability
  - title: Analytics
    details: "An embedded analytics store with rollups and retention, a closed-grammar query API, an NDJSON firehose to external sinks, and scheduled per-consumer usage reports for billing pipelines."
    link: /guide/analytics
    linkText: Analytics
  - title: Web console
    details: "A read-only, dependency-free dashboard served from the admin listener: routes, upstreams, health, metrics, and recent requests in one place."
    link: /guide/web-console
    linkText: Console
  - title: Admin API and CLI
    details: "An mTLS-only admin surface for live config inspection, patching, credential rotation, and cache purge -- and dwara-cli for validate, fmt, lint, diff, config imports, and Terraform-style state round-trips."
    link: /guide/admin-api
    linkText: Admin API
  - title: Operations
    details: "Hot config reload (debounced file watch or SIGHUP) with atomic publish-and-swap, zero-downtime binary upgrade over SO_REUSEPORT, and graceful drain on shutdown."
    link: /guide/operations
    linkText: Operations
  - title: Kubernetes Gateway API
    details: "Translate Gateway, HTTPRoute, and Ingress resources into dwara config and run the controller beside your cluster (a compile-time feature pack)."
    link: /guide/kubernetes-gateway-api
    linkText: Kubernetes
---

## Run it in under a minute

Start any HTTP server to proxy to, run the gateway against the sample
config (it forwards everything under `/v1` to `127.0.0.1:9000`), and
send a request through:

```sh
python3 -m http.server 9000
DWARA_CONFIG=crates/dwara-bin/dwara.yaml cargo run -p dwara-bin
curl http://127.0.0.1:8080/v1/
```

The request streams to the backend unbuffered and the response streams
back the same way. A path with no matching route returns `404`; a dead
backend returns `502`. Stop with `Ctrl-C` -- in-flight requests drain
before the process exits.

A released binary works the same way: point `DWARA_CONFIG` at your
YAML. [Getting started](/guide/getting-started) walks through a first
config, and [Installation](/guide/installation) covers binaries,
Docker images, and systemd.

## One gateway, two editions

The OSS core -- proxying, TLS, routing, resilience, security,
observability, analytics -- is complete and production-shaped, and
everything in the cards above ships in it. Heavier capabilities
(Proxy-Wasm plugins, CEL expressions, Cedar/OPA authorization,
aggregation) are compile-time feature packs, and fleet-scale features
(CP/DP split, Redis-backed rate limiting and convergence, Vault/KMS
secrets, workspaces) make up the enterprise edition. The
[editions guide](/guide/editions) has the full comparison matrix.

## Feature flags

Every optional capability is a cargo feature flag, **default-OFF**. The
default `cargo build` produces the complete OSS gateway with no optional
packs -- each pack adds binary size or a heavy dependency, so you opt in
per build. See the [feature reference](/guide/feature-reference) for
build commands, dependency chains, license claims, and maturity status.

### Protocol and transport

| Flag | What it adds | Guide |
|---|---|---|
| `h3` | HTTP/3 (QUIC) ingress listener and upstream transport | [HTTP/3](/guide/http3) |
| `grpc_web` | gRPC-Web framing and JSON-to-gRPC transcoding | [gRPC-Web](/guide/grpc-web) |
| `protocol_translation` | General protocol translation (REST, gRPC, GraphQL); implies `grpc_web` | [Protocol translation](/guide/protocol-translation) |
| `soap` | SOAP/XML envelope translation; implies `protocol_translation` | [Protocol translation](/guide/protocol-translation) |
| `l4` | L4 TCP/UDP proxying with SNI routing reuse | [L4 proxying](/guide/l4-proxying) |
| `pq` | Post-quantum TLS hybrid key exchange (X25519 + ML-KEM); experimental | [Post-quantum TLS](/guide/post-quantum-tls) |

### Extensibility

| Flag | What it adds | Guide |
|---|---|---|
| `wasm` | proxy-wasm host runtime (community Kong/Envoy filters run unmodified) | [proxy-wasm plugins](/guide/proxy-wasm-plugins) |
| `nano_services` | WASM route handlers -- a route action that runs a WASM module to generate the response (implies `wasm`) | [Nano-services](/guide/nano-services) |
| `plugins` | Native Rust filter trait and unified dispatch chain alongside proxy-wasm | [Native plugins](/guide/native-plugins) |
| `cel` | CEL (Common Expression Language) expression evaluation in policies | [CEL expressions](/guide/cel-expressions) |
| `extism` | Extism PDK plugin runtime alongside native and WASM plugins | [Extism PDK](/guide/extism-pdk) |

### Authorization and security

| Flag | What it adds | Guide |
|---|---|---|
| `cedar` | Cedar policy engine and OPA HTTP callout for fine-grained authorization | [Cedar/OPA authz](/guide/cedar-opa-authz) |
| `openapi_validation` | Upstream response validation against OpenAPI schemas; also used by AI guardrails | [OpenAPI response validation](/guide/openapi-response-validation) |
| `cert_pinning` | Upstream TLS certificate pinning by SPKI hash | [Feature reference](/guide/feature-reference) |
| `signed_url` | Signed URL request authentication (HMAC-SHA256 over canonical request) | [Feature reference](/guide/feature-reference) |
| `fips` | FIPS 140-3 mode (Enterprise): aws-lc-rs FIPS provider, self-test, restricted cipher suites | [FIPS mode](/guide/fips-mode) |
| `mesh` | Service mesh mode (Enterprise): sidecar controller, SPIFFE/SPIRE mTLS identity | [Service mesh](/guide/service-mesh) |

### API management

| Flag | What it adds | Guide |
|---|---|---|
| `k8s` | Kubernetes Gateway API / Ingress resource translation and controller | [Kubernetes Gateway API](/guide/kubernetes-gateway-api) |
| `aggregation` | Multi-upstream response composition (KrakenD-style) with JSONPath fragment shaping | [API aggregation](/guide/api-aggregation) |
| `graphql` | GraphQL awareness: query depth/complexity limits, persisted-query enforcement | [GraphQL](/guide/graphql) |
| `api_lifecycle` | API lifecycle management: developer portal, environment profiles, journey recorder | [API lifecycle](/guide/api-lifecycle) |

### AI gateway

| Flag | What it adds | Guide |
|---|---|---|
| `semantic_cache` | Embedding-similarity cache for AI prompts (HNSW ANN, external embedding service) | [Semantic caching](/guide/ai-semantic-caching) |
| `mcp` | Agent-operable administration via MCP server with RBAC-scoped tools | [Agent-operable admin](/guide/agent-operable-admin) |
| `a2a` | A2A (agent-to-agent) protocol support with Agent Card parsing | [A2A protocol](/guide/a2a-protocol) |

### Observability and diagnostics

| Flag | What it adds | Guide |
|---|---|---|
| `otlp` | OTLP trace and metrics export to a collector (build with `-p dwara-bin`) | [OTel metrics export](/guide/otel-metrics-export) |
| `console` | tokio-console diagnostics server for async task inspection (build with `-p dwara-bin`) | [Feature reference](/guide/feature-reference) |

### Enterprise edition

| Flag | What it adds | Guide |
|---|---|---|
| `ent` | Enterprise edition: license verification, Redis distributed rate limiter/cache/convergence, CP/DP split over gRPC, workspaces with RBAC and audit, Vault/KMS secrets, federated analytics, AI provider credential pools | [Enterprise](/guide/enterprise) |

### Test-only

| Flag | What it adds |
|---|---|
| `loom` | Concurrency model checking -- swaps synchronization primitives for loom's model-checked equivalents (never in production builds) |

### Feature maturity at a glance

| Status | Features |
|---|---|
| Wired end to end | `ent`, `otlp`, `k8s`, `wasm`, `plugins`, `cel`, `cedar`, `openapi_validation`, `aggregation`, `h3`, `grpc_web`, `protocol_translation`, `semantic_cache` |
| Config-accepted, runtime partially wired | `l4`, `graphql`, `api_lifecycle`, `mcp`, `a2a`, `mesh` |
| Config-accepted, runtime stubbed | `soap`, `extism`, `cert_pinning`, `signed_url`, `nano_services` |

The published OSS binaries and images are built with no packs enabled.
