---
layout: home

hero:
  name: Dwara
  text: API gateway
  tagline: Predictable latency, defense-in-depth traffic policy, and one declarative YAML config for the edge in front of your APIs.
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
  - icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M13 2 4.5 13.5H11L10 22l8.5-11.5H12L13 2Z'/></svg>"
    title: Streaming dataplane
    details: "HTTP/1.1 and HTTP/2 proxying with no buffering by default -- SSE and large bodies pass through under frame-based backpressure. TLS termination (multi-SNI) and SNI passthrough, gRPC over h2, and managed WebSocket tunnels."
    link: /guide/grpc-websockets
    linkText: Protocols
  - icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><circle cx='5' cy='6' r='2'/><circle cx='19' cy='6' r='2'/><circle cx='12' cy='19' r='2'/><path d='M12 17v-3.5L6.4 7.4M12 13.5l5.6-6.1'/></svg>"
    title: Routing and rewrites
    details: "Exact (with path parameters), regex, and prefix matching with fixed precedence; host, method, header, query, and cookie criteria; strip/replace/regex rewrites, redirects, and direct responses."
    link: /guide/routing
    linkText: Routing
  - icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M12 3 5 5.8v5.4c0 4.4 2.9 7.4 7 8.8 4.1-1.4 7-4.4 7-8.8V5.8L12 3Z'/><path d='M7.8 12h2l1.3-2.6 1.7 4.6 1.3-2h2.1'/></svg>"
    title: Resilience
    details: "Retries with bounded attempts and timeout budgets, circuit breaking, passive and active health checks with endpoint ejection, load shedding, admission queues, and request hedging."
    link: /guide/traffic-policy
    linkText: Traffic policy
  - icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M5.5 18.5a6.5 6.5 0 1 1 13 0'/><path d='m12 18.5 3.6-5'/><circle cx='12' cy='18.5' r='1.4'/></svg>"
    title: Rate limiting and quotas
    details: "GCRA and stacked-window rate limits at global, listener, service, route, or consumer scope -- plus per-consumer daily and monthly request budgets over the durable state store."
    link: /guide/quotas
    linkText: Quotas
  - icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><circle cx='7.5' cy='15.5' r='4'/><path d='m10.6 12.4 8.9-8.9'/><path d='m14.8 5.2 3 3'/><path d='m12.2 8 2 2'/></svg>"
    title: Authentication
    details: "API keys, Basic, JWT via JWKS, mTLS client certificates, and HMAC request signing. Secret references resolve at compile time with exhaustive redaction -- secrets never appear in logs or admin output."
    link: /guide/security
    linkText: Security
  - icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M12 3 5 5.8v5.4c0 4.4 2.9 7.4 7 8.8 4.1-1.4 7-4.4 7-8.8V5.8L12 3Z'/><path d='m9 12 2.1 2.1 4-4.2'/></svg>"
    title: Authorization
    details: "Consumer and group allow/deny lists, JWT scopes and claims, IP ACLs, and GeoIP gates, attached at five precedence levels with deny-anywhere-wins semantics and a monitor-only dry-run mode."
    link: /guide/authorization
    linkText: Authorization
  - icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M3 12h4l2-6 4 12 2-6h6'/></svg>"
    title: Observability
    details: "Structured JSON logs with request IDs, Prometheus /metrics on every listener, a uniform JSON error envelope, and optional OTLP trace and metrics export."
    link: /guide/observability
    linkText: Observability
  - icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M5 20v-5'/><path d='M11 20V6'/><path d='M17 20v-9'/><path d='M3 20h18'/></svg>"
    title: Analytics
    details: "An embedded analytics store with rollups and retention, a closed-grammar query API, an NDJSON firehose to external sinks, and scheduled per-consumer usage reports for billing pipelines."
    link: /guide/analytics
    linkText: Analytics
  - icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><rect x='3' y='4.5' width='18' height='15' rx='2.5'/><path d='M3 9h18'/><path d='M6 6.8h.01'/><path d='M8.8 6.8h.01'/></svg>"
    title: Web console
    details: "A read-only, dependency-free dashboard served from the admin listener: routes, upstreams, health, metrics, and recent requests in one place."
    link: /guide/web-console
    linkText: Console
  - icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><rect x='2.5' y='4' width='19' height='16' rx='2.5'/><path d='m7 9 3.5 3L7 15'/><path d='M12.5 15H17'/></svg>"
    title: Admin API and CLI
    details: "An mTLS-only admin surface for live config inspection, patching, credential rotation, and cache purge -- and dwara-cli for validate, fmt, lint, diff, config imports, and Terraform-style state round-trips."
    link: /guide/admin-api
    linkText: Admin API
  - icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M21 12a9 9 0 1 1-2.64-6.36'/><path d='M21 3v5h-5'/></svg>"
    title: Operations
    details: "Hot config reload (debounced file watch or SIGHUP) with atomic publish-and-swap, zero-downtime binary upgrade over SO_REUSEPORT, and graceful drain on shutdown."
    link: /guide/operations
    linkText: Operations
  - icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M12 2.5 20.2 7.2v9.6L12 21.5 3.8 16.8V7.2L12 2.5Z'/><circle cx='12' cy='12' r='2.2'/><path d='M12 7v2.8'/><path d='m8.2 14.6 2.4-1.4'/><path d='m15.8 14.6-2.4-1.4'/></svg>"
    title: Kubernetes Gateway API
    details: "Translate Gateway, HTTPRoute, and Ingress resources into Dwara config and run the controller beside your cluster (a compile-time feature pack)."
    link: /guide/kubernetes-gateway-api
    linkText: Kubernetes

editions:
  - title: Open source core
    tagline: "The default build: a complete, production-shaped gateway in a single static binary."
    points:
      - Proxying, TLS termination, and routing
      - Resilience and traffic policy
      - Security, observability, and analytics
    link: /guide/getting-started
    linkText: Get started
    highlight: true
  - title: Compile-time feature packs
    tagline: "Heavier capabilities you opt into per build -- every pack is default-OFF."
    points:
      - Proxy-Wasm plugins and native filters
      - CEL expressions and Cedar/OPA authorization
      - Aggregation, protocol translation, HTTP/3
    link: /guide/feature-reference
    linkText: Feature flags
  - title: Enterprise edition
    tagline: "Fleet-scale operation across many gateway instances."
    points:
      - CP/DP split and workspaces with RBAC
      - Redis-backed rate limiting and convergence
      - Vault/KMS secrets and federated analytics
    link: /guide/editions
    linkText: Editions comparison

flagGroups:
  - group: Protocol and transport
    items:
      - { flag: h3, desc: "HTTP/3 (QUIC) ingress listener and upstream transport", link: /guide/http3 }
      - { flag: grpc_web, desc: "gRPC-Web framing and JSON-to-gRPC transcoding", link: /guide/grpc-web }
      - { flag: protocol_translation, desc: "General protocol translation (REST, gRPC, GraphQL); implies grpc_web", link: /guide/protocol-translation }
      - { flag: soap, desc: "SOAP/XML envelope translation; implies protocol_translation", link: /guide/protocol-translation, status: partial }
      - { flag: l4, desc: "L4 TCP/UDP proxying with SNI routing reuse", link: /guide/l4-proxying, status: partial }
      - { flag: pq, desc: "Post-quantum TLS hybrid key exchange (X25519 + ML-KEM); experimental", link: /guide/post-quantum-tls }
  - group: Extensibility
    items:
      - { flag: wasm, desc: "proxy-wasm host runtime -- community Kong/Envoy filters run unmodified", link: /guide/proxy-wasm-plugins }
      - { flag: nano_services, desc: "WASM route handlers -- a route action that runs a WASM module (implies wasm)", link: /guide/nano-services }
      - { flag: plugins, desc: "Native Rust filter trait and unified dispatch chain alongside proxy-wasm", link: /guide/native-plugins }
      - { flag: cel, desc: "CEL (Common Expression Language) expression evaluation in policies", link: /guide/cel-expressions }
      - { flag: extism, desc: "Extism PDK plugin runtime alongside native and WASM plugins", link: /guide/extism-pdk, status: stubbed }
  - group: Authorization and security
    items:
      - { flag: cedar, desc: "Cedar policy engine and OPA HTTP callout for fine-grained authorization", link: /guide/cedar-opa-authz }
      - { flag: openapi_validation, desc: "Upstream response validation against OpenAPI schemas; also used by AI guardrails", link: /guide/openapi-response-validation }
      - { flag: cert_pinning, desc: "Upstream TLS certificate pinning by SPKI hash", link: /guide/feature-reference, status: partial }
      - { flag: signed_url, desc: "Signed URL request authentication (HMAC-SHA256 over canonical request)", link: /guide/feature-reference, status: stubbed }
      - { flag: fips, desc: "FIPS 140-3 mode (Enterprise): aws-lc-rs FIPS provider, self-test, restricted cipher suites", link: /guide/fips-mode }
      - { flag: mesh, desc: "Service mesh mode (Enterprise): sidecar controller, SPIFFE/SPIRE mTLS identity", link: /guide/service-mesh, status: stubbed }
  - group: API management
    items:
      - { flag: k8s, desc: "Kubernetes Gateway API / Ingress resource translation and controller", link: /guide/kubernetes-gateway-api }
      - { flag: aggregation, desc: "Multi-upstream response composition (KrakenD-style) with JSONPath fragment shaping", link: /guide/api-aggregation }
      - { flag: graphql, desc: "GraphQL awareness: query depth/complexity limits, persisted-query enforcement", link: /guide/graphql, status: partial }
      - { flag: api_lifecycle, desc: "API lifecycle management: developer portal, environment profiles, journey recorder", link: /guide/api-lifecycle, status: partial }
  - group: AI gateway
    items:
      - { flag: semantic_cache, desc: "Embedding-similarity cache for AI prompts (HNSW ANN, external embedding service)", link: /guide/ai-semantic-caching }
      - { flag: mcp, desc: "Agent-operable administration via MCP server with RBAC-scoped tools", link: /guide/agent-operable-admin, status: stubbed }
      - { flag: a2a, desc: "A2A (agent-to-agent) protocol support with Agent Card parsing", link: /guide/a2a-protocol, status: partial }
  - group: Observability and diagnostics
    items:
      - { flag: otlp, desc: "OTLP trace and metrics export to a collector (build with -p dwara-bin)", link: /guide/otel-metrics-export }
      - { flag: console, desc: "tokio-console diagnostics server for async task inspection (build with -p dwara-bin)", link: /guide/feature-reference }
  - group: Enterprise edition
    items:
      - { flag: ent, desc: "License verification, Redis rate limiter/cache/convergence, CP/DP split, workspaces, Vault/KMS secrets, federated analytics, AI provider credential pools", link: /guide/enterprise }
  - group: Test-only
    items:
      - { flag: loom, desc: "Concurrency model checking -- swaps synchronization primitives for loom's model-checked equivalents (never in production builds)", link: /guide/feature-reference }
---

## Run it in under a minute

Start any HTTP server to proxy to, run the gateway against the sample
config (it forwards everything under `/v1` to `127.0.0.1:9000`), and
send a request through:

```sh[terminal: dwara -- quickstart]
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

## One gateway, from single binary to fleet

The OSS core -- proxying, TLS, routing, resilience, security,
observability, analytics -- is complete and production-shaped, and
everything in the cards above ships in it. Heavier capabilities
(Proxy-Wasm plugins, CEL expressions, Cedar/OPA authorization,
aggregation) are compile-time feature packs, and fleet-scale features
(CP/DP split, Redis-backed rate limiting and convergence, Vault/KMS
secrets, workspaces) make up the enterprise edition. The
[editions guide](/guide/editions) has the full comparison matrix.

<HomeEditions />

## Feature flags

Every optional capability is a cargo feature flag, **default-OFF**. The
default `cargo build` produces the complete OSS gateway with no optional
packs -- each pack adds binary size or a heavy dependency, so you opt in
per build. The chips below show every flag and its runtime maturity; the
[feature reference](/guide/feature-reference) has build commands,
dependency chains, license claims, and the full maturity table.

<HomeFlags />

The published OSS binaries and images are built with no packs enabled.
