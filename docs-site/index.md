---
layout: home

hero:
  name: Dwara
  text: API gateway
  tagline: One Rust binary. One YAML file. Every protocol, every policy, every provider -- from a single edge to a fleet.
  actions:
    - theme: brand
      text: Get started
      link: /guide/getting-started
    - theme: alt
      text: First scenarios
      link: /guide/first-scenarios
    - theme: alt
      text: Installation
      link: /guide/installation
    - theme: alt
      text: View on GitHub
      link: https://github.com/shristilabs/dwara

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
  - title: Complete capability set
    tagline: "Every dataplane capability compiled into the default OSS build."
    points:
      - Proxy-Wasm plugins and native filters
      - CEL expressions and Cedar/OPA authorization
      - Aggregation, protocol translation, HTTP/3
    link: /guide/feature-reference
    linkText: Feature reference
  - title: Enterprise edition
    tagline: "Fleet-scale operation across many gateway instances."
    points:
      - CP/DP split and workspaces with RBAC
      - Redis-backed rate limiting and convergence
      - Vault/KMS secrets and federated analytics
    link: /guide/editions
    linkText: Editions comparison

domains:
  - title: Proxying and transport
    link: /guide/proxying-transport
    visual: proxying
    blurb: "The wire level: how a connection is accepted, which protocols are spoken, and how traffic reaches the upstream."
    icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M13 2 4.5 13.5H11L10 22l8.5-11.5H12L13 2Z'/></svg>"
    items:
      - { name: Streaming proxying, desc: "HTTP/1.1 + HTTP/2, no buffering, SSE-safe", link: /guide/proxying-transport }
      - { name: TLS termination, desc: "Multi-SNI certificates or SNI passthrough", link: /guide/deployment }
      - { name: Routing and matching, desc: "Exact, regex, prefix -- fixed precedence", link: /guide/routing }
      - { name: Rewrites and redirects, desc: "Strip/replace/regex, direct responses", link: /guide/routing }
      - { name: Load balancing and splitting, desc: "Canary, blue-green, sticky sessions", link: /guide/traffic-splitting }
      - { name: Dynamic discovery, desc: "DNS A/SRV pools, TTL refresh", link: /guide/dynamic-discovery }
      - { name: gRPC and WebSockets, desc: "Trailers, timeouts, managed tunnels", link: /guide/grpc-websockets }
      - { name: HTTP/3 ingress, desc: "QUIC listeners with Alt-Svc", link: /guide/http3 }
      - { name: H3/QUIC upstream, desc: "Gateway-to-upstream over QUIC", link: /guide/h3-quic-upstream }
      - { name: L4 TCP/UDP proxying, desc: "Raw listeners with SNI routing", link: /guide/l4-proxying, badge: partial }
      - { name: Post-quantum TLS, desc: "X25519 + ML-KEM hybrid key exchange", link: /guide/post-quantum-tls }
  - title: Request and response control
    link: /guide/request-response-control
    visual: reqresp
    blurb: "Application-level shaping once a route has matched -- each of these is a small optional block on the route itself."
    icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M4 7h16M4 15h16'/><circle cx='14' cy='7' r='2.2'/><circle cx='9' cy='15' r='2.2'/></svg>"
    items:
      - { name: CORS, desc: "Cross-origin policy with preflights", link: /guide/edge-policies }
      - { name: Compression, desc: "Response compression at the edge", link: /guide/edge-policies }
      - { name: Request limits and validation, desc: "Size caps + JSON Schema bodies", link: /guide/edge-policies }
      - { name: Transforms, desc: "Header, query, and JSON-body rewrites", link: /guide/transforms }
      - { name: Security headers, desc: "HSTS, nosniff, CSP", link: /guide/transforms }
      - { name: Response field masking, desc: "Per-consumer redaction, fail-closed", link: /guide/masking }
      - { name: Response caching, desc: "TTL, SWR, coalescing, tag purge", link: /guide/caching }
      - { name: API versioning, desc: "Path/header/Accept + Deprecation/Sunset", link: /guide/api-versioning }
  - title: Protocol translation and API management
    link: /guide/protocol-translation
    visual: translation
    blurb: "Speak the client's protocol on the way in and compose many backends on the way out."
    icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M4 5h8M8 3v2c0 4-2 7-4.5 8.5M6 8c1.5 3 4 5 7 6'/><path d='m13 21 4-9 4 9M14.5 18h5'/></svg>"
    items:
      - { name: gRPC-Web and transcoding, desc: "gRPC-Web framing, JSON transcoding", link: /guide/grpc-web }
      - { name: Protocol translation, desc: "REST, gRPC, GraphQL, SOAP/XML", link: /guide/protocol-translation }
      - { name: GraphQL awareness, desc: "Depth/complexity limits, persisted queries", link: /guide/graphql, badge: partial }
      - { name: API aggregation, desc: "Multi-upstream JSONPath composition", link: /guide/api-aggregation }
      - { name: OpenAPI import and mocks, desc: "Scaffold config; mock routes", link: /guide/openapi-import }
      - { name: OpenAPI response validation, desc: "Validate upstream responses, dry-run", link: /guide/openapi-response-validation }
      - { name: API lifecycle and dev portal, desc: "Catalog, env profiles, journeys", link: /guide/api-lifecycle, badge: partial }
  - title: Traffic policy and resilience
    link: /guide/traffic-policy
    visual: traffic
    blurb: "Bounded failure and predictable load under stress -- retries, breaking, shedding, and budgets."
    icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M5.5 18.5a6.5 6.5 0 1 1 13 0'/><path d='m12 18.5 3.6-5'/><circle cx='12' cy='18.5' r='1.4'/></svg>"
    items:
      - { name: Retries and timeout budgets, desc: "Bounded attempts, timeout budgets", link: /guide/traffic-policy }
      - { name: Circuit breaking and health, desc: "Passive + active checks, ejection", link: /guide/traffic-policy }
      - { name: Rate limiting, desc: "GCRA and stacked windows, five scopes", link: /guide/traffic-policy }
      - { name: Request hedging, desc: "Speculative duplicates, race-and-cancel", link: /guide/request-hedging }
      - { name: Admission queues, desc: "Bounded queues, per-priority", link: /guide/admission-queue }
      - { name: Consumer quotas, desc: "Daily/monthly request budgets", link: /guide/quotas }
      - { name: WAF-lite filtering, desc: "SQLi/XSS/traversal heuristics, dry-run", link: /guide/waf-lite }
      - { name: Maintenance and dry-run, desc: "Per-route 503; policy monitor mode", link: /guide/maintenance }
      - { name: Mirroring and fault injection, desc: "Shadow traffic, abort/delay", link: /guide/mirroring-fault-injection }
  - title: Security and identity
    link: /guide/security
    visual: security
    blurb: "How callers prove who they are, what they are allowed to do, and how secrets stay out of everything."
    icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M12 3 5 5.8v5.4c0 4.4 2.9 7.4 7 8.8 4.1-1.4 7-4.4 7-8.8V5.8L12 3Z'/><path d='m9 12 2.1 2.1 4-4.2'/></svg>"
    items:
      - { name: Authentication methods, desc: "API keys, Basic, JWT, mTLS, HMAC", link: /guide/authentication-methods }
      - { name: HMAC request signing, desc: "HMAC-SHA256, replay protection", link: /guide/hmac-signing }
      - { name: OAuth2 and mTLS, desc: "Client credentials, upstream mTLS", link: /guide/oauth2-mtls }
      - { name: OpenID Connect, desc: "Introspection, PKCE, token exchange", link: /guide/oidc }
      - { name: Authorization rules, desc: "ACLs, JWT claims, IP, GeoIP; monitor mode", link: /guide/authorization }
      - { name: Cedar and OPA authz, desc: "In-process Cedar or OPA callout", link: /guide/cedar-opa-authz }
      - { name: CEL expressions, desc: "Sandboxed policy expressions", link: /guide/cel-expressions }
      - { name: Secrets, desc: "Reference resolution, redaction", link: /guide/secrets }
      - { name: ACME certificates, desc: "Let's Encrypt over TLS-ALPN-01", link: /guide/acme, badge: experimental }
      - { name: FIPS 140-3 mode, desc: "aws-lc-rs provider, restricted ciphers", link: /guide/fips-mode, badge: ent }
  - title: AI gateway
    link: /guide/ai-gateway
    visual: ai
    blurb: "One OpenAI-shaped endpoint in front of every model provider, with budgets, guardrails, and governance."
    icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M12 3l1.9 4.6L18.5 9.5l-4.6 1.9L12 16l-1.9-4.6L5.5 9.5l4.6-1.9L12 3Z'/><path d='m18.5 15.5.9 2.1 2.1.9-2.1.9-.9 2.1-.9-2.1-2.1-.9 2.1-.9.9-2.1Z'/></svg>"
    items:
      - { name: Provider adapters and aliases, desc: "OpenAI, Anthropic, Gemini, Azure, Bedrock", link: /guide/ai-gateway }
      - { name: Routing policies, desc: "Cheap-first escalation, cost/latency", link: /guide/ai-routing-policies }
      - { name: Token budgets, desc: "Token + cost budgets, billing exports", link: /guide/ai-token-budgets }
      - { name: Prompt experimentation, desc: "Versioning, A/B splits, evals", link: /guide/ai-prompt-experimentation }
      - { name: Prompt logging, desc: "PII redaction, sampling, retention", link: /guide/ai-prompt-logging }
      - { name: Governance and agents, desc: "Model allowlists, agent principals", link: /guide/ai-governance }
      - { name: Guardrails, desc: "Injection, PII, schema rules", link: /guide/ai-guardrails }
      - { name: Semantic caching, desc: "Embedding-similarity prompt cache", link: /guide/ai-semantic-caching }
      - { name: MCP gateway, desc: "HTTP services as MCP tools", link: /guide/ai-mcp-gateway, badge: experimental }
      - { name: A2A protocol, desc: "Agent Card discovery and routing", link: /guide/a2a-protocol, badge: partial }
  - title: Extensibility and plugins
    link: /guide/extensibility-overview
    visual: extensibility
    blurb: "Three plugin families -- proxy-wasm, native Rust filters, and Extism -- unified under one dispatch chain."
    icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M9 3v5m6-5v5M6.5 8h11v4a5.5 5.5 0 0 1-11 0V8ZM12 17.5V21'/></svg>"
    items:
      - { name: Proxy-Wasm plugins, desc: "Kong/Envoy filters run unmodified", link: /guide/proxy-wasm-plugins }
      - { name: Native plugin filters, desc: "Rust filters, same dispatch chain", link: /guide/native-plugins }
      - { name: Extension traits, desc: "Swap whole subsystems via traits", link: /guide/extension-traits }
      - { name: Nano-services, desc: "WASM route handlers, no upstream", link: /guide/nano-services }
      - { name: Extism PDK, desc: "Multi-language plugin runtime", link: /guide/extism-pdk, badge: experimental }
      - { name: Plugin lifecycle, desc: "Hot-swap, health, failure isolation", link: /guide/plugin-lifecycle }
      - { name: Plugin SDK, desc: "dwara-cli scaffolding", link: /guide/plugin-sdk }
  - title: Observability and analytics
    link: /guide/observability-analytics
    visual: observability
    blurb: "Every request leaves a trace: logs, metrics, traces, and an embedded analytics store with rollups."
    icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M3 12h4l2-6 4 12 2-6h6'/></svg>"
    items:
      - { name: Structured logs, desc: "JSON logs with request IDs", link: /guide/observability }
      - { name: Prometheus metrics, desc: "/metrics on every listener", link: /guide/observability }
      - { name: OTLP export, desc: "Traces + metrics to any collector", link: /guide/otel-metrics-export }
      - { name: SLOs and error budgets, desc: "SLOs from request outcomes", link: /guide/observability }
      - { name: Embedded analytics, desc: "Rollups, retention, forecasts", link: /guide/analytics }
      - { name: Analytics stream, desc: "NDJSON firehose to a sink", link: /guide/analytics-stream }
      - { name: Alert and event webhooks, desc: "Breaker/endpoint/config events", link: /guide/webhooks }
      - { name: Synthetic monitoring, desc: "Per-route probes, alerting", link: /guide/synthetic-monitoring }
      - { name: Replay debugging, desc: "Record routing, replay offline", link: /guide/replay-debugging }
  - title: Operations and platform
    link: /guide/deployment-operations
    visual: operations
    blurb: "Run it, upgrade it without downtime, and automate it from the CLI, admin API, or Kubernetes."
    icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M21 12a9 9 0 1 1-2.64-6.36'/><path d='M21 3v5h-5'/></svg>"
    items:
      - { name: Hot config reload, desc: "File watch/SIGHUP, atomic swap", link: /guide/operations }
      - { name: Zero-downtime upgrade, desc: "SO_REUSEPORT hand-off, drain", link: /guide/zero-downtime-upgrade }
      - { name: Admin API, desc: "mTLS config + credential surface", link: /guide/admin-api }
      - { name: Web console, desc: "Embedded read-only dashboard", link: /guide/web-console }
      - { name: CLI, desc: "validate, fmt, lint, diff, loadgen", link: /guide/cli }
      - { name: Terraform state, desc: "Export, plan, apply", link: /guide/terraform-state }
      - { name: Config import, desc: "NGINX, Kong, Envoy, OpenAPI", link: /guide/config-import }
      - { name: Kubernetes Gateway API, desc: "Gateway/HTTPRoute/Ingress controller", link: /guide/kubernetes-gateway-api }
      - { name: Agent-operable admin, desc: "MCP tools for AI operators", link: /guide/agent-operable-admin, badge: experimental }
  - title: Fleet scale
    link: /guide/enterprise
    visual: fleet
    blurb: "Many gateways, one brain -- the enterprise edition."
    badge: ent
    icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><circle cx='5' cy='12' r='2.5'/><circle cx='19' cy='5' r='2.5'/><circle cx='19' cy='19' r='2.5'/><path d='m7.3 11 9.4-5M7.3 13l9.4 5'/></svg>"
    items:
      - { name: CP/DP split, desc: "Controller pushes config to edges", link: /guide/cp-dp-split }
      - { name: Cluster sync, desc: "Redis convergence, split-brain guards", link: /guide/cluster-sync }
      - { name: Distributed rate limiting, desc: "Shared GCRA buckets in Redis", link: /guide/redis-rate-limiter }
      - { name: Distributed cache, desc: "Two-tier cache, fleet invalidation", link: /guide/distributed-cache }
      - { name: Vault and KMS secrets, desc: "External sources, fail-closed", link: /guide/vault-kms-secrets }
      - { name: Workspaces and RBAC, desc: "Multi-tenant isolation, audit log", link: /guide/workspaces-rbac-audit }
      - { name: Federated analytics, desc: "Per-edge analytics, rolled up", link: /guide/analytics }
      - { name: Controller persistence, desc: "PostgreSQL controller state", link: /guide/ent-controller-persistence }
      - { name: Service mesh, desc: "Sidecars, SPIFFE/SPIRE identity", link: /guide/service-mesh, badge: experimental }
      - { name: Licensing, desc: "Ed25519 license files, grace period", link: /guide/licensing }

personas:
  - title: Platform engineers
    icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M3 9 12 4l9 5-9 5-9-5Z'/><path d='M3 9v6l9 5 9-5V9'/><path d='M12 14v6'/></svg>"
    blurb: "One declarative YAML for routing, policy, and identity. Validate before publish, hot-reload without restart, and diff configs like Terraform state."
    links:
      - { text: Configuration, link: /guide/configuration }
      - { text: CLI, link: /guide/cli }
      - { text: Config import, link: /guide/config-import }
  - title: SREs and operations
    icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M21 12a9 9 0 1 1-2.64-6.36'/><path d='M21 3v5h-5'/></svg>"
    blurb: "Retries, circuit breaking, health checks, admission queues, and zero-downtime binary upgrades. Prometheus metrics on every listener and an embedded analytics store."
    links:
      - { text: Operations, link: /guide/operations }
      - { text: Traffic policy, link: /guide/traffic-policy }
      - { text: Observability, link: /guide/observability }
  - title: Security teams
    icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M12 3 5 5.8v5.4c0 4.4 2.9 7.4 7 8.8 4.1-1.4 7-4.4 7-8.8V5.8L12 3Z'/><path d='m9 12 2.1 2.1 4-4.2'/></svg>"
    blurb: "Five authn methods, a deny-anywhere-wins authorization chain, Cedar/OPA policy engines, secret redaction, WAF-lite, and FIPS 140-3 mode."
    links:
      - { text: Security, link: /guide/security }
      - { text: Authorization, link: /guide/authorization }
      - { text: Secrets, link: /guide/secrets }
  - title: AI and ML teams
    icon: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M12 3l1.9 4.6L18.5 9.5l-4.6 1.9L12 16l-1.9-4.6L5.5 9.5l4.6-1.9L12 3Z'/><path d='m18.5 15.5.9 2.1 2.1.9-2.1.9-.9 2.1-.9-2.1-2.1-.9 2.1-.9.9-2.1Z'/></svg>"
    blurb: "One OpenAI-shaped endpoint in front of every provider. Token budgets, cost attribution, guardrails, semantic caching, and the MCP gateway."
    links:
      - { text: AI gateway, link: /guide/ai-gateway }
      - { text: Token budgets, link: /guide/ai-token-budgets }
      - { text: Guardrails, link: /guide/ai-guardrails }

faq:
  - q: "What is Dwara?"
    a: "Dwara is a high-performance, streaming reverse-proxy API gateway written in Rust. It terminates TLS, routes traffic, enforces policy, authenticates callers, and observes everything -- from a single static binary configured by one YAML file."
  - q: "What does the OSS edition include?"
    a: "Every dataplane capability: proxying (HTTP/1.1, HTTP/2, HTTP/3, gRPC, WebSocket, L4), TLS termination, routing, load balancing, traffic policy and resilience, security and authentication, AI gateway, plugins and extensibility, observability and analytics, and operations. There are no optional packs to enable."
  - q: "What does the enterprise edition add?"
    a: "Features that span multiple gateway instances or require external infrastructure: CP/DP split with a leader-elected control plane, Redis-backed distributed rate limiting and cache, config convergence, workspaces with RBAC and audit, Vault/KMS secrets, federated analytics, FIPS 140-3 enforcement, and service mesh mode."
  - q: "Do I need to change my application to use Dwara?"
    a: "No. Dwara is a reverse proxy -- point it at your backends and send traffic to it. For AI gateway usage, change only the base URL and credential in your OpenAI-compatible SDK; Dwara translates the request to whichever provider serves it."
  - q: "Where does Dwara run?"
    a: "Anywhere a single static binary runs: bare metal, Docker, systemd, or Kubernetes. The OSS edition is a standalone binary; the enterprise edition adds a controller and edge binaries for fleet operation. See the deployment guide."
  - q: "How does config work?"
    a: "One strict YAML file declares the entire gateway: listeners, routes, services, upstreams, consumers, policies, and observability. The config pipeline (parse, validate, compile, publish) runs on every change -- file watch, SIGHUP, admin API, or controller stream -- and swaps atomically behind an ArcSwap. A failure at any stage never replaces the running snapshot."
  - q: "Can I migrate from NGINX, Kong, or Envoy?"
    a: "Yes. The dwara CLI has an import command that reads NGINX, Kong, or Envoy config and emits a Dwara YAML draft. Use dwara diff to compare it against a hand-tuned config before cutover."
  - q: "Is Dwara production-ready?"
    a: "The OSS core (proxying, TLS, routing, resilience, security, observability, analytics) is stable and production-shaped. Some advanced capabilities (L4 proxying, GraphQL awareness, API lifecycle, MCP gateway, service mesh, Extism PDK) are partially wired or experimental; each guide page carries a status note. See the feature reference for the maturity matrix."
---

## Why dwara

A streaming reverse proxy written in Rust, built for operators who need
predictable latency, defense-in-depth traffic policy, and a single
declarative config for the edge in front of their APIs.

<div class="home-value-props">

- **Single static binary** -- no runtime, no garbage collector, no
  shared-library dependencies. Ship one file, run it anywhere.
- **Streaming by default** -- HTTP/1.1, HTTP/2, SSE, and large bodies
  pass through under frame-based backpressure with zero buffering.
- **One declarative YAML** -- the routing chain, identity, policy, and
  observability in a single strict config that validates before it
  goes live.
- **Defense in depth** -- rate limiting, circuit breaking, WAF-lite,
  authn/authz, and secret redaction composed at five scopes with
  deny-anywhere-wins semantics.
- **Open core** -- every dataplane capability is in the Apache-2.0
  build. Enterprise adds fleet coordination, not paywalled features.

</div>

## Get started in under a minute

Three commands. Start any HTTP server, run the gateway against the
sample config, and send a request through.

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

## By scenario

New to Dwara and not sure where to start? These task-oriented guides
walk through the common goals an operator has on day one:

- **Protect a public API** -- rate limiting, WAF-lite, and JWT
  authentication in one config: [Traffic policy](/guide/traffic-policy)
  + [Security](/guide/security).
- **Proxy to LLM providers** -- one OpenAI-shaped endpoint that
  translates to OpenAI, Anthropic, or Gemini with token budgets and
  guardrails: [AI gateway](/guide/ai-gateway).
- **Migrate from NGINX, Kong, or Envoy** -- import an existing config
  and diff against a native Dwara config:
  [Config import](/guide/config-import).
- **Run on Kubernetes** -- translate Gateway, HTTPRoute, and Ingress
  resources and run the controller beside your cluster:
  [Kubernetes Gateway API](/guide/kubernetes-gateway-api).
- **Operate a fleet** -- a control plane pushing config generations to
  edges, shared rate-limit budgets, and workspaces with RBAC:
  [Enterprise and fleet](/guide/enterprise).

For more, see [First scenarios](/guide/first-scenarios).

## Built for your team

One gateway, four audiences. Each gets the controls it needs without
the noise of the others.

<HomePersonas />

## Works with your stack

Keep your existing providers, SDKs, and infrastructure. Dwara speaks
every protocol your clients use and translates between them.

| Layer | What it speaks |
|---|---|
| **Protocols** | HTTP/1.1, HTTP/2, HTTP/3 (QUIC), gRPC, gRPC-Web, WebSocket, L4 TCP/UDP |
| **AI providers** | OpenAI, Anthropic, Google Gemini, Azure OpenAI, AWS Bedrock, any OpenAI-compatible endpoint |
| **Import from** | NGINX, Kong, Envoy, OpenAPI specs |
| **Run on** | Bare metal, Docker, systemd, Kubernetes (Gateway API controller) |
| **Observe via** | Prometheus `/metrics`, OTLP traces and metrics, NDJSON analytics firehose, alert webhooks |
| **Extend with** | Proxy-Wasm (Kong/Envoy filters), native Rust filters, Extism PDK, WASM nano-services |

## Explore the capabilities

Everything below ships in the default OSS build unless marked
otherwise. Badges match the guides: **partial** means config-accepted
and partially wired, **experimental** means runtime-stubbed, and
**enterprise** marks fleet-scale features of the enterprise edition.

<HomeBands />

## One gateway, from single binary to fleet

The OSS core -- proxying, TLS, routing, resilience, security,
observability, analytics -- is complete and production-shaped, and
everything in the cards above ships in it. Every dataplane capability
(Proxy-Wasm plugins, CEL expressions, Cedar/OPA authorization,
aggregation, HTTP/3, protocol translation) is compiled into the
default OSS build, and fleet-scale features (CP/DP split, Redis-backed
rate limiting and convergence, Vault/KMS secrets, workspaces, FIPS
enforcement) make up the enterprise edition. The
[editions guide](/guide/editions) has the full comparison matrix.

<HomeEditions />

## Feature reference

Every dataplane capability is compiled into the default OSS build --
there are no optional packs to enable. The
[feature reference](/guide/feature-reference) carries the maturity
matrix showing which capabilities are wired end to end and which are
still landing, plus build commands and enterprise-only config blocks.

## Questions teams ask before they deploy

<HomeFAQ />
