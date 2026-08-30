# Dwara

<p align="center">
  <img src="./branding/png/logo-horizontal.png" alt="Dwara" width="360">
</p>

A high-performance, streaming reverse-proxy API gateway written in Rust.
Built for operators who need predictable latency, defense-in-depth traffic
policy, and a single declarative YAML config to run an edge for internal and
external APIs.

Dwara is Apache-2.0 licensed and developed in the open at
[shristilabs/dwara](https://github.com/shristilabs/dwara).

> **Status:** milestone M1 ("It proxies") is complete. The gateway is
> production-shaped but pre-1.0: the config schema is still additive-only and
> may churn before the first stable release. See the
> [changelog](./CHANGELOG.md) for what shipped.

## Documentation

The complete operator documentation is published at
**<https://shristilabs.github.io/dwara/>** and covers every feature in depth.
This README is a quick orientation; treat the docs site as the source of truth.

| Where to look | Link |
| --- | --- |
| Getting started guide | <https://shristilabs.github.io/dwara/guide/getting-started> |
| Configuration | <https://shristilabs.github.io/dwara/guide/configuration> |
| Deployment (TLS, Docker, systemd) | <https://shristilabs.github.io/dwara/guide/deployment> |
| Operations | <https://shristilabs.github.io/dwara/guide/operations> |
| Observability | <https://shristilabs.github.io/dwara/guide/observability> |
| Admin API | <https://shristilabs.github.io/dwara/guide/admin-api> |
| CLI reference | <https://shristilabs.github.io/dwara/guide/cli> |
| Environment variables | <https://shristilabs.github.io/dwara/reference/environment-variables> |
| Configuration schema (JSON Schema) | <https://shristilabs.github.io/dwara/reference/configuration-schema> |
| Architecture overview | <https://shristilabs.github.io/dwara/architecture/overview> |

Contributors and integrators should also read [`AGENTS.md`](./AGENTS.md)
(practical build/test/conventions) and the developer docs in
[`docs/`](./docs) (internals, rationale, diagrams).

## Capabilities

A single Dwara process fronts many upstreams with a layered traffic policy.
Each capability is documented in its own guide page on the docs site.

**Dataplane**
- Streaming HTTP/1.1 and HTTP/2 proxying (no buffering by default; SSE and
  large bodies pass through with frame-based backpressure).
- TLS termination with multi-SNI certificate selection, plus SNI passthrough.
- Routing: `exact` (with path parameters), `regex`, and `prefix` matching with
  a fixed precedence (exact > regex > prefix); non-path criteria (host,
  methods, headers, query, cookies).
- Path rewrites (`strip_prefix`, `replace_prefix`, `regex`) and `redirect` /
  `respond` direct actions.
- Load balancing: `round_robin`, `least_requests`, `random`, `ip_hash`, with
  slow start.
- gRPC over H2 and managed WebSocket tunnels (origin allowlist, frame-rate
  policing).

**Resilience**
- Passive and active health checks, endpoint ejection.
- Retries with bounded attempts and timeout budgets.
- Circuit breaking and per-upstream capacity limits.
- Load shedding with priority-aware admission (`max_concurrent_requests`).
- Local rate limiting (GCRA, stacked windows) at global, listener, service,
  route, or consumer scope.
- Distributed rate limiting via Redis (enterprise) so multiple gateway
  instances share one limit.
- Per-consumer request budgets (quotas) over durable state-store counters.

**Security**
- Authentication: API key, Basic, JWT via JWKS, mTLS client certificates, and
  HMAC request signing.
- Authorization and IP ACLs with deny-anywhere-wins precedence
  (consumer > route > service > listener > global).
- Request/response transforms, security headers, and fail-closed response
  field masking (per-consumer-group redaction).
- mTLS-only admin API for live config inspection and patching.
- Secret references (`${...}`) resolved at compile time with exhaustive
  redaction; secrets are never logged or included in Debug output.

**Operability**
- Hot config reload (file change, debounced, or SIGHUP) with atomic
  publish-and-swap; a rejected reload keeps the previous generation serving.
- Structured JSON logs, request IDs, Prometheus `/metrics`, and a uniform
  JSON error envelope.
- Embedded analytics store with rollups and a real-time analytics stream.
- Alert and event webhooks off an in-process event bus.
- API versioning (path / header / query / Accept media type) with
  Deprecation/Sunset/Link automation.
- Response caching, CORS, and per-route compression.

**Packaging**
- Fully static musl binary (bundled SQLite, aws-lc-rs compiled in).
- Scratch (17.6 MB) and distroless (65.2 MB) images; multi-arch GHCR images
  built from verified, checksummed release artifacts.
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

The request streams to the backend unbuffered and the response streams back
the same way. A path with no matching route returns `404`; a dead backend
returns `502` (or `504` on connect timeout). Stop with `Ctrl-C` — the gateway
drains in-flight requests before exiting.

An invalid or missing config makes the process exit with code 1, printing
every validation issue at once (not just the first).

For the full path with TLS, Docker, and a demo upstream, see the
[one-command TLS demo](https://shristilabs.github.io/dwara/guide/deployment).

## Configuration

Dwara is configured from a single YAML file, parsed strictly (unknown fields
are rejected; errors carry the path of the offending node). Config passes
through a fixed pipeline before the gateway serves it: **parse** (strict) ->
**validate** (semantic, all issues at once) -> **compile** (route lookup
structures) -> **publish** (atomic; a failure anywhere keeps the previous
generation serving).

A minimal valid configuration:

```yaml
listeners:
  - name: main
    address: 0.0.0.0
    port: 8080
routes:
  - name: all
    service: echo
    match:
      path:
        type: prefix
        value: /
    action:
      type: proxy
services:
  - name: echo
    upstream: echo-upstream
upstreams:
  - name: echo-upstream
    endpoints:
      - address: 127.0.0.1
        port: 9000
```

The machine-readable JSON Schema of the full config is committed at
[`config-reference.json`](./config-reference.json) and regenerated with:

```sh
cargo run -q -p dwara-cli -- schema > config-reference.json
```

CI gates freshness: a pull request whose committed `config-reference.json`
differs from what `dwara-cli schema` emits fails, so the reference never
drifts from the code.

For the complete configuration model (routing precedence, rewrites, upstreams,
TLS, policies, authn/authz, transforms, masking, caching, versioning,
webhooks, analytics), see the
[Configuration guide](https://shristilabs.github.io/dwara/guide/configuration)
and the topic-specific guide pages.

## Environment variables

Operational knobs are environment variables (`DWARA_*`); topology is YAML.
The full list with defaults is in the
[Environment variables reference](https://shristilabs.github.io/dwara/reference/environment-variables).
The most common ones:

| Variable | Default | Purpose |
| --- | --- | --- |
| `DWARA_CONFIG` | `./dwara.yaml` | config file path (watched for changes) |
| `DWARA_BIND` | unset | override with a single cleartext listener (dev escape hatch) |
| `DWARA_STATE_DB` | unset | path to the SQLite state store (unset = no store) |
| `DWARA_CREDENTIAL_PEPPER` | unset | per-deployment secret peppering stored credential hashes |
| `DWARA_LOG` | `dwara=info` | log filter in `RUST_LOG` syntax |
| `DWARA_ACCESS_LOG_SAMPLE` | `1.0` | fraction of non-error access-log lines emitted |
| `DWARA_SHUTDOWN_TIMEOUT_SECS` | `10` | graceful-drain budget on SIGTERM/SIGINT |
| `DWARA_ADMIN_DEV` | unset | `1` = plaintext loopback admin API (DEV ONLY) |
| `DWARA_OTLP_ENDPOINT` | unset | OTLP trace export (`http://` endpoint; `otlp` feature build only) |

Reload: file change (debounced) or SIGHUP. Shutdown: SIGTERM/SIGINT with
backlog flush and drain. A `POST`/`PATCH` to the admin API is live-published.

## Repository layout

| Path | Contents |
| --- | --- |
| `crates/dwara-core` | The library: config, snapshot pipeline, extensions, observability, events, state, analytics, security, resilience, dataplane |
| `crates/dwara-bin` | The `dwara` gateway binary: entry/shutdown, listeners, reload, OTLP export |
| `crates/dwara-admin` | mTLS-only admin API (config, health, stats) |
| `crates/dwara-cli` | Operator CLI (`run`/`validate`/`fmt`/`diff`/`lint`/`schema`); load-generator rig |
| `fuzz/` | cargo-fuzz targets (separate workspace) |
| `quickstart/` | One-command docker-compose TLS demo |
| `packaging/` | systemd unit and packaging notes |
| `grafana/` | Starter dashboard for the `/metrics` families |
| `scripts/` | Macro bench rig, baseline gate, dependency-direction guard |
| `config-reference.json` | Generated JSON Schema of the config (freshness-gated in CI) |
| `docs/` | Developer-facing documentation (internals, rationale, diagrams) |
| `docs-site/` | Published end-user (operator) documentation site (VitePress) |

## Extension points

State-holding subsystems are defined as swappable, dyn-compatible traits in
`dwara-core::extensions`: `RateLimiter`, `ConfigSource`, `CacheStore`,
`AnalyticsSink`, and `SecretSource`. Each trait's rustdoc states its contract
(purpose, semantics, failure model). Local in-memory, file, and
environment-variable implementations ship in-tree; alternative backends plug
in by implementing the same traits without touching call sites. See the
[Extension points](./docs/features/extension-points.md) developer doc.

## Development

Requires Rust via rustup (the pinned toolchain installs automatically on
first cargo invocation). Optional: Docker, `actionlint` (brew) for workflow
linting, a nightly toolchain for `cargo fuzz`, python3 for bench scripts.

```sh
cargo build --workspace
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check advisories licenses bans
cargo doc --no-deps --workspace   # must be zero-warning
```

CI runs on pushes and pull requests to `main`. Blocking gates: `cargo fmt
--check`, clippy with `-D warnings`, build, tests, and cargo-deny checks
(advisories, licenses, bans; policy in `deny.toml`). A CycloneDX SBOM is
generated and uploaded as an artifact on each run. Every `uses:` reference in
the workflows is pinned to a full commit SHA; Dependabot keeps the pins fresh.

See [`AGENTS.md`](./AGENTS.md) for the full contributor guide (code
organization, conventions, the verification gate, the test map).

## Branding

The Dwara logo, mark, and favicon set live in [`./branding`](./branding)
(`svg/`, `png/`, `favicon/`). They share the ShristiLabs identity DNA — an
indigo base with a teal `#12B5A5` accent and a torana-arch symbol evoking a
gateway (द्वार). The docs site consumes the favicons and logos from
[`./docs-site/public`](./docs-site/public); see
[`branding/README.md`](./branding/README.md) for the asset inventory and
usage notes.

## License

Apache-2.0
