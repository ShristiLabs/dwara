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
