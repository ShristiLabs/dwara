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
> security, observability) is stable and production-shaped. Enterprise and
> extension features (CP/DP split, Wasm plugins, CEL, aggregation, MCP, K8s
> translator) are feature-gated and shipping iteratively. See the
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
| Enterprise features | <https://shristilabs.github.io/dwara/guide/enterprise> |
| Environment variables | <https://shristilabs.github.io/dwara/reference/environment-variables> |
| Configuration schema | <https://shristilabs.github.io/dwara/reference/configuration-schema> |
| Architecture overview | <https://shristilabs.github.io/dwara/architecture/overview> |

## Capabilities

**Proxying**
- Streaming HTTP/1.1 and HTTP/2 (no buffering by default; SSE and large
  bodies pass through with frame-based backpressure).
- TLS termination with multi-SNI certificate selection, plus SNI passthrough.
- gRPC over H2 and managed WebSocket tunnels (origin allowlist, frame-rate
  policing).

**Routing**
- `exact` (with path parameters), `regex`, and `prefix` matching with fixed
  precedence (exact > regex > prefix).
- Non-path criteria: host, methods, headers, query, cookies.
- Path rewrites (`strip_prefix`, `replace_prefix`, `regex`) and
  `redirect` / `respond` direct actions.

**Load balancing**
- `round_robin`, `least_requests`, `random`, `ip_hash`, with slow start.

**Resilience**
- Passive and active health checks, endpoint ejection.
- Retries with bounded attempts and timeout budgets.
- Circuit breaking and per-upstream capacity limits.
- Load shedding with priority-aware admission.
- Local rate limiting (GCRA, stacked windows) at global, listener, service,
  route, or consumer scope.
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

**Operability**
- Hot config reload (file change, debounced, or SIGHUP) with atomic
  publish-and-swap.
- Zero-downtime binary upgrade (SIGUSR2 / `dwara upgrade`): SO_REUSEPORT
  hand-off with zero failed requests and zero reset connections.
- Structured JSON logs, request IDs, Prometheus `/metrics`, and a uniform
  JSON error envelope.
- Embedded analytics store with rollups and a real-time analytics stream.
- Alert and event webhooks off an in-process event bus.
- API versioning (path / header / query / Accept media type) with
  Deprecation/Sunset/Link automation.
- Response caching, CORS, and per-route compression.
- Read-only web console at `/console/` for live route, upstream, health,
  analytics, and config inspection.
- Synthetic probes with alert firing/recovery and per-route failure
  thresholds.

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
- MCP server for AI agent administration with RBAC-scoped tools.
- Vault/KMS secret sources (enterprise): Vault KV v2, KMS-backed
  decryption, lease management.
- Control-plane / data-plane split with cluster sync, conflict resolution,
  split-brain detection, and version skew tolerance (enterprise).

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
