<p align="center">
  <img src="./branding/png/logo-horizontal.png" alt="Dwara" width="360">
</p>

---

A high-performance, streaming reverse-proxy API gateway written in Rust.
Built for operators who need predictable latency, defense-in-depth traffic
policy, and a single declarative YAML config to run an edge for internal and
external APIs.

Dwara is licensed under the [Apache License 2.0](./LICENSE) and developed
in the open at [shristilabs/dwara](https://github.com/shristilabs/dwara).

> **Status:** pre-1.0. The OSS core (proxying, TLS, routing, resilience,
> security, observability, AI gateway, analytics) is stable and
> production-shaped. Enterprise and extension features (CP/DP split, Wasm
> plugins, CEL, aggregation, MCP, K8s translator, fleet operations, global
> load balancing, FIPS mode, post-quantum TLS, service mesh, protocol
> translation, nano-services, API lifecycle, A2A protocol) are
> feature-gated and shipping iteratively. See the
> [changelog](./CHANGELOG.md) for what shipped.

## Documentation

The complete operator documentation is published at
**<https://shristilabs.github.io/dwara/>**. This README is a quick
orientation; treat the docs site as the source of truth.

| Topic | Link |
| --- | --- |
| Getting started | <https://shristilabs.github.io/dwara/guide/getting-started> |
| Installation | <https://shristilabs.github.io/dwara/guide/installation> |
| Configuration | <https://shristilabs.github.io/dwara/guide/configuration> |
| Deployment and operations | <https://shristilabs.github.io/dwara/guide/deployment-operations> |
| Routing | <https://shristilabs.github.io/dwara/guide/routing> |
| Traffic policy and resilience | <https://shristilabs.github.io/dwara/guide/traffic-policy> |
| Security and authentication | <https://shristilabs.github.io/dwara/guide/security> |
| Observability and analytics | <https://shristilabs.github.io/dwara/guide/observability-analytics> |
| Admin API | <https://shristilabs.github.io/dwara/guide/admin-api> |
| CLI reference | <https://shristilabs.github.io/dwara/guide/cli> |
| Web console | <https://shristilabs.github.io/dwara/guide/web-console> |
| AI gateway | <https://shristilabs.github.io/dwara/guide/ai-gateway> |
| HTTP/3 ingress | <https://shristilabs.github.io/dwara/guide/http3> |
| GraphQL awareness | <https://shristilabs.github.io/dwara/guide/graphql> |
| gRPC-Web and transcoding | <https://shristilabs.github.io/dwara/guide/grpc-web> |
| Protocol translation | <https://shristilabs.github.io/dwara/guide/protocol-translation> |
| L4 TCP/UDP proxying | <https://shristilabs.github.io/dwara/guide/l4-proxying> |
| Nano-services (WASM) | <https://shristilabs.github.io/dwara/guide/nano-services> |
| Service mesh mode | <https://shristilabs.github.io/dwara/guide/service-mesh> |
| Post-quantum TLS | <https://shristilabs.github.io/dwara/guide/post-quantum-tls> |
| FIPS 140-3 mode | <https://shristilabs.github.io/dwara/guide/fips-mode> |
| API lifecycle and dev portal | <https://shristilabs.github.io/dwara/guide/api-lifecycle> |
| Enterprise features | <https://shristilabs.github.io/dwara/guide/enterprise> |
| Environment variables | <https://shristilabs.github.io/dwara/reference/environment-variables> |
| Configuration schema | <https://shristilabs.github.io/dwara/reference/configuration-schema> |
| Architecture overview | <https://shristilabs.github.io/dwara/architecture/overview> |

## Capabilities

**Proxying**
- Streaming HTTP/1.1 and HTTP/2 (no buffering by default; SSE and large
  bodies pass through with frame-based backpressure).
- HTTP/3 (h3 over QUIC) ingress with 0-RTT early data policy and Alt-Svc
  advertisement (feature-gated).
- H3/QUIC upstream transport: dial upstreams over QUIC for reduced
  connection latency and head-of-line blocking avoidance (feature-gated).
- TLS termination with multi-SNI certificate selection, plus SNI passthrough.
- L4 TCP/UDP proxying with SNI-based routing reuse for non-HTTP protocols
  (feature-gated).
- gRPC over H2 and managed WebSocket tunnels (origin allowlist, frame-rate
  policing).
- gRPC-Web framing and JSON-to-gRPC transcoding for browser clients
  (feature-gated).
- Protocol translation: REST-to-gRPC, REST-to-GraphQL, and SOAP-to-REST
  bridging (feature-gated).

**Routing**
- `exact` (with path parameters), `regex`, and `prefix` matching with fixed
  precedence (exact > regex > prefix).
- Non-path criteria: host, methods, headers, query, cookies.
- Path rewrites (`strip_prefix`, `replace_prefix`, `regex`) and
  `redirect` / `respond` direct actions.
- GraphQL awareness: depth and complexity limits, persisted-query
  enforcement, and query parsing (feature-gated).

**Load balancing**
- `round_robin`, `least_requests`, `random`, `ip_hash`, `peak_ewma`
  (latency-aware), with slow start.
- Locality-aware endpoint selection (region/zone preference) for global
  load balancing (enterprise).
- Auto-canary analysis: metrics-driven promotion and rollback of canary
  split weights.

**Resilience**
- Passive and active health checks, endpoint ejection.
- Retries with bounded attempts and timeout budgets.
- Circuit breaking and per-upstream capacity limits.
- Load shedding with priority-aware admission.
- Local rate limiting (GCRA, stacked windows) at global, listener, service,
  route, or consumer scope.
- Adaptive rate-limit tuning: EWMA of upstream error rate and latency
  dynamically scales quotas; origin-driven `Retry-After` honored.
- Anomaly scoring: statistical request-shape scoring (header entropy, path
  depth, body size) with configurable block or dry-run.
- Distributed rate limiting via Redis (enterprise).
- Per-consumer request budgets (quotas) over durable state-store counters.

**Security**
- Authentication: API key, Basic, JWT via JWKS, mTLS client certificates,
  and HMAC request signing.
- Authorization and IP ACLs with deny-anywhere-wins precedence
  (consumer > route > service > listener > global).
- Request/response transforms, security headers, and fail-closed response
  field masking (per-consumer-group redaction).
- mTLS-only admin API for live config inspection and patching.
- Secret references resolved at compile time with exhaustive redaction;
  secrets are never logged or included in Debug output.
- FIPS 140-3 mode: aws-lc-rs FIPS provider with self-test attestation
  and primitive allowlist (enterprise, feature-gated).
- Post-quantum TLS: X25519+ML-KEM hybrid key exchange for
  quantum-resistant transport (experimental, feature-gated).
- Upstream TLS certificate pinning by SPKI hash (fail-closed).
- Signed-URL verification for pre-authenticated request routing.
- Bot detection hooks for automated traffic classification.

**Operability**
- Hot config reload (file change, debounced, or SIGHUP) with atomic
  publish-and-swap.
- Zero-downtime binary upgrade (SIGUSR2 / `dwara upgrade`): SO_REUSEPORT
  hand-off with zero failed requests and zero reset connections.
- Structured JSON logs, request IDs, Prometheus `/metrics`, and a uniform
  JSON error envelope.
- Embedded analytics store with rollups, a real-time analytics stream,
  live sketches (sub-second freshness), ML insights (capacity forecasting,
  anomaly detection), and custom business metrics dimensions.
- Alert and event webhooks off an in-process event bus.
- API versioning (path / header / query / Accept media type) with
  Deprecation/Sunset/Link automation.
- Response caching, CORS, and per-route compression.
- Web console at `/console/`: read-only inspection (OSS) or full CRUD with
  fleet views, config editor, and workspace switcher (enterprise v2).
- Synthetic probes with alert firing/recovery and per-route failure
  thresholds.
- tokio-console integration for live async task diagnostics (feature-gated).
- Replay time-travel debugging: capture request inputs and reconstruct
  routing decisions offline with modified config (CLI-driven).
- API lifecycle: developer portal scaffold, environment profiles
  (dev/staging/prod), and journey recorder for request tracing
  (feature-gated).

**Extensions (feature-gated)**
- Proxy-Wasm plugin lifecycle: loading, hot-swap on reload, failure
  isolation. Plugin SDK scaffolding via `dwara plugin new`.
- CEL expressions across route conditions, header transforms, rate-limit
  key derivation, and policy conditions.
- Cedar + OPA authorization with decision cache.
- OpenAPI response validation (drift detection, optional 502).
- API aggregation: KrakenD-style multi-upstream response composition with
  JSONPath fragment shaping and per-fragment fail-open/closed policies.
- Kubernetes Gateway API translator (Gateway, HTTPRoute, GatewayClass).
- MCP gateway: dwara as an MCP server/router over JSON-RPC 2.0 with
  per-tool authz, session management, and tool-call analytics.
- Vault/KMS secret sources (enterprise): Vault KV v2, KMS-backed
  decryption, lease management.
- Control-plane / data-plane split with cluster sync, conflict resolution,
  split-brain detection, version skew tolerance, fleet operations, and
  federated analytics (enterprise).
- Nano-services: WASM route handlers via wasmtime with fuel-based
  execution limits and memory caps (feature-gated).
- Extism PDK scaffold for cross-language plugin development (feature-gated).
- Service mesh mode: sidecar deployment with SPIFFE/SPIRE mTLS identity
  and iptables/TPROXY traffic capture (feature-gated).
- A2A (Agent-to-Agent) protocol scaffold: Agent Card discovery and
  routing for inter-agent communication (feature-gated).
- eBPF hooks research spike: aya-rs scaffold for ambient mesh redirect
  and connection-identity enrichment (research stage).

**AI gateway**
- One client dialect (OpenAI chat-completions) in, three provider
  dialects (OpenAI, Anthropic, Gemini) out -- any OpenAI-compatible SDK
  works unchanged.
- Provider failover chains (up to 4 alternates) and weighted canary splits
  (2-8 versions) with deterministic per-request-id hashing.
- Routing policies: fallback-chain (cheap-first escalation via a
  classifier) and latency-vs-cost static selection.
- Streaming excellence: zero-buffered SSE translation with provider-reported
  usage, mid-stream budget cutoff, and uniform `[DONE]` termination.
- Token rate limiting and budgets (per-minute tokens, per-day cost) with
  pre-check rejection and mid-stream enforcement.
- Cost attribution and metering: pricing tables in micro-USD, per-consumer
  spend tracking, billing exports.
- Provider credential pools with 429 quarantine and automatic key rotation
  (enterprise).
- Prompt/response logging with PII redaction, sampling, and retention.
- Guardrails pack: injection, PII, banned-content, and schema-conformance
  checks with block/redact/log actions.
- Semantic caching: embedding-similarity cache for paraphrased prompts
  (feature-gated).
- Model governance: per-team model allowlists with shadow audit.
- Prompt experimentation: prompt versioning, A/B model comparison,
  regression evals, and feedback ingestion.
- Agent principals and governance: typed consumer identities (user/agent),
  per-agent tool allowlists, and per-agent token budgets.

**Packaging**
- Fully static musl binary (bundled SQLite, aws-lc-rs compiled in).
- Scratch (17.6 MB) and distroless (65.2 MB) images; multi-arch GHCR
  images built from verified, checksummed release artifacts.
- Hardened systemd unit.

## Quickstart

Requires Rust 1.94+ (pinned in `rust-toolchain.toml`) or a released binary
(see [Installation](https://shristilabs.github.io/dwara/guide/installation)).

Start any HTTP server to proxy to, then run the gateway with the sample
config that forwards everything under `/v1` to `127.0.0.1:9000`:

```sh
python3 -m http.server 9000
DWARA_CONFIG=crates/dwara-bin/dwara.yaml cargo run -p dwara-bin
```

Send a request through the gateway (it binds `http://127.0.0.1:8080`):

```sh
curl http://127.0.0.1:8080/v1/
```

The request streams to the backend unbuffered and the response streams
back the same way. A path with no matching route returns `404`; a dead
backend returns `502` (or `504` on connect timeout). Stop with `Ctrl-C` --
the gateway drains in-flight requests before exiting.

An invalid or missing config makes the process exit with code 1, printing
every validation issue at once (not just the first).

For the full path with TLS, Docker, and a demo upstream, see the
[deployment guide](https://shristilabs.github.io/dwara/guide/deployment).

## Contributing

Contributors should read [`AGENTS.md`](./AGENTS.md) for build commands,
code organization, conventions, and the verification gate. Developer
documentation (internals, rationale, diagrams) lives in [`docs/`](./docs).

## License

Licensed under the [Apache License 2.0](./LICENSE).
