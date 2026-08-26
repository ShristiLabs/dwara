# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project

dwara is a Rust API gateway (Apache-2.0, OSS edition). Cargo workspace with a
pinned toolchain (`rust-toolchain.toml`, Rust 1.94.0). Public GitHub repo:
`shristilabs/dwara`.

**Status:** milestone M1 ("It proxies") is complete — reverse proxying with
TLS (multi-SNI terminate + SNI passthrough, h2/h2c), routing and rewrites,
load balancing, passive/active health, retries and timeouts, circuit
breaking, load shedding, rate limiting, authn (API key / Basic / JWT via
JWKS), authz + IP ACL, SQLite state + migrations, observability, mTLS admin
API, CLI, protocol hardening, fuzzing/benchmarks, and packaging. Later
milestones (management plane, extensions, AI/LLM features) are not yet
implemented.

## Layout

| Path | Contents |
|---|---|
| `crates/dwara-core` | The library: config schema (`config.rs`), snapshot compile pipeline (`snapshot.rs`), reverse-proxy dataplane (`proxy.rs`), TLS terminate/passthrough (`tls.rs`), upstream client (`upstream.rs`), load balancing (`balance.rs`), passive/active health (`health.rs`, `active.rs`), retries (`retries.rs`), circuit breaker (`breaker.rs`), rate limiting (`extensions/rate_limiter.rs`), authn/authz (`authn.rs`, `authz.rs`), SQLite state store + migrations (`store.rs`, `migrations.rs`), observability (`observability.rs`), protocol hardening (`hardening.rs`), extension traits (`extensions/`) |
| `crates/dwara-bin` | The `dwara` gateway binary: listeners, hot reload, graceful shutdown, admin spawn |
| `crates/dwara-admin` | mTLS-only admin API (GET/PATCH /config, /health, /stats) |
| `crates/dwara-cli` | Operator CLI (`run`/`validate`/`fmt`/`diff`/`lint`/`schema`) and the `dwara-loadgen` load generator |
| `fuzz/` | cargo-fuzz crate (its own workspace, not a member) |
| `quickstart/` | One-command docker-compose TLS demo |
| `packaging/` | systemd unit + packaging notes |
| `grafana/` | Starter dashboard for the /metrics families |
| `scripts/` | Macro bench rig + baseline gate |
| `config-reference.json` | Generated JSON Schema (repo root; see freshness gate) |

## Development environment

- Rust via rustup; the pinned toolchain installs automatically on first
  cargo invocation.
- Optional: Docker (quickstart/images; colima works on macOS),
  `actionlint` (brew) for workflow linting, a nightly toolchain for
  `cargo fuzz`, python3 for `scripts/bench-baseline.py`.
- The musl/aws-lc-rs build needs cmake + a C compiler; the release
  Dockerfiles carry these in their builder stages.

## Running locally

```sh
cargo run -p dwara-bin                        # uses crates/dwara-bin/dwara.yaml
DWARA_CONFIG=path/to/conf.yaml cargo run -p dwara-bin
```

The binary requires a config at startup (exit 1 with all validation issues
if invalid). Main environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `DWARA_CONFIG` | `./dwara.yaml` | config file path (watched for changes) |
| `DWARA_BIND` | `127.0.0.1:8080` | override for a single cleartext listener |
| `DWARA_STATE_DB` | unset | enable the SQLite state store |
| `DWARA_ADMIN_DEV` | unset | `1` = plaintext loopback admin (dev only) |
| `DWARA_LOG` / `DWARA_ACCESS_LOG_SAMPLE` | `dwara=info` / `1.0` | log filter / access-line sampling |
| `DWARA_HTTP1_*`, `DWARA_H2_*`, `DWARA_REQUEST_BODY_TIMEOUT_MS` | see README | protocol hardening knobs |
| `DWARA_SHUTDOWN_TIMEOUT_SECS` | `10` | graceful drain bound |

Reload: file change (debounced) or SIGHUP. Shutdown: SIGTERM/SIGINT with
backlog flush + drain. `POST` to the admin API is live-published.

## Commands

```sh
cargo build --workspace
cargo test --workspace            # ~720 tests; suites spawn real servers/binaries
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check advisories licenses bans
cargo doc --no-deps --workspace   # must be zero-warning
cargo run -q -p dwara-cli --bin dwara-cli -- schema   # config reference (diff vs config-reference.json)
```

Extras when touching those areas: `cargo test -p dwara-core --features loom --test loom`,
`cargo bench --workspace --bench micro`, `actionlint .github/workflows/<file>`,
`scripts/bench-macro.sh` (macro rig), `cargo fuzz run <target>` (from `fuzz/`).

## Verification gate

Before declaring any change done, the full set above must pass in order with
zero warnings and zero failures. Never weaken a command to make it pass (no
`--no-verify`, no scoped subsets for final checks, no clippy allows).

## Hard rules

1. **Never commit `docs-internal/`.** It holds private planning material and is
   intentionally untracked. Never reference it from committed files.
2. **Never push or create PRs** without an explicit user instruction.
3. No new dependencies without checking licenses against `deny.toml` and
   flagging the addition in your report.
4. No emoji in code, comments, docs, or commit messages.
5. `.sdlc/` is internal pipeline state; leave it untracked unless told
   otherwise.

## Conventions

- **Commits:** conventional style (`feat:`, `fix:`, `ci:`, `test:`, ...),
  subject ≤72 chars, body explains why; reference issues with `Refs #N`
  (PR descriptions carry `Closes`).
- **Config schema:** strict serde — `deny_unknown_fields` on every struct.
  Changes are additive only. Parse-level checks live in `config.rs`;
  semantic validation (refs, bounds, cross-field rules) lives in
  `snapshot.rs::validate` and must produce `ValidationIssue`s naming the
  offending field. Invalid regexes fail at compile in `snapshot.rs`.
  After schema changes, regenerate `config-reference.json`
  (`dwara-cli schema > config-reference.json`) — CI fails on drift.
- **Ops knobs are env vars** (`DWARA_*`), topology is YAML. Do not add
  operational settings to the schema without discussion.
- **Vocabulary is frozen:** Listener/Route/Service/Upstream/Endpoint/
  Consumer/Credential/Policy/Plugin/Workspace/Snapshot. Policy precedence:
  consumer > route > service > listener > global (deny-anywhere-wins).
- **Request-path order** (do not reorder casually): reserved paths
  (/healthz, /readyz, /metrics) → route resolution → authn → authz →
  rate limit → gateway cap admission (priority-aware) → breaker →
  endpoint pick → pending cap → connect.
- **Gateway-generated responses** use the JSON error envelope
  `{error:{code,message,request_id}}`; never leak upstream internals.
- **Secrets:** never logged, never in Debug output, redaction is exhaustive
  (query strings excluded from logs/spans; `X-Consumer-*` stripped inbound).
- **Metrics:** label cardinality must stay config-bounded (no consumer-name
  labels). Counters survive reloads; hot paths use atomics only.
- **Tests:** integration tests spawn real servers or the real binary
  (`CARGO_BIN_EXE_*`), use unique ports and bounded readiness polls.
  Zero tolerance for flakes: re-run new timing-sensitive suites 5x.
  Timing tests use tiny windows with generous margins; never sleeps as
  synchronization.
- **Streaming:** the dataplane buffers nothing by default. Any change that
  introduces buffering must be opt-in and size-capped.

## Extension points

Swappable subsystem traits live in `dwara-core::extensions`:
`RateLimiter`, `ConfigSource`, `CacheStore`, `AnalyticsSink`,
`SecretSource` (async, dyn-compatible). Local in-memory/file/env
implementations ship in-tree; additional backends may be provided
separately. The traits are the intended seam for plugging in alternative
implementations without touching call sites — extend, do not break them.

## Test map

| Area | Suites |
|---|---|
| Config schema / validation | `config_schema`, `config_schema_extended`, `snapshot_pipeline` |
| Routing | `router_golden` (golden files), `proxy_coverage` |
| Proxy behavior | `proxy`, `proxy_coverage` |
| TLS | `tls_validation`, `tls_listener`, `tls_edges` |
| Upstreams / LB | `upstream_client`, `balancing` |
| Health | `passive_health`, `active_health` |
| Resilience | `retries_timeouts`, `breaker_caps`, `load_shedding`, `rate_limit` |
| State | `store` |
| Auth | `authn`, `authz` |
| Ops | `reload_edges`, `reload_shutdown`, `healthz_readyz`, `observability`, `protocol_hardening`, `admin_reload_coherence` |
| Tooling | `cli` (+ `loadgen_e2e`), `swap_stress`, `loom` (feature-gated) |

## Notable implementation facts

- hyper 1.x does **not** reject CL+TE requests; the pre-parse sniff in
  `hardening.rs` is the real smuggling defense (first head only; the proxy
  rebuilds every forwarded request from parsed parts, so framing cannot
  desync through the gateway).
- Hot reload swaps an atomic `Snapshot` (+ upstream registry, TLS material,
  auth state) — in-flight requests keep their old generation. The listener
  bind set is restart-only.
- The state store (opt-in via `DWARA_STATE_DB`) auto-migrates on open and
  writes a `.bak-*` backup before migrating; schema changes go through
  `migrations.rs` (forward-only).
- API keys are stored as `sha256:<hex>` with sha256 selectors
  (constant-time compare); store-managed Basic credentials should use
  argon2id PHC hashes.
- arc-swap has no loom support; swap paths are covered by real-thread
  stress tests in `tests/swap_stress.rs`.

## CI posture (compute-conscious)

- `ci.yml`: verify (fmt/clippy/build/test + config-reference freshness) and
  supply-chain (cargo-deny + SBOM) on pushes/PRs to main, path-filtered,
  concurrency-cancelled.
- `bench.yml` / `fuzz.yml`: scheduled weekly + manual dispatch only —
  never on PRs.
- `release-artifacts.yml`: tag-only (`v*`), musl binaries with a 25 MB bar
  and GHCR multi-arch images.

## Quickstart sanity check

`quickstart/` boots the gateway + a demo upstream over TLS:
`gen-certs.sh && docker compose up`, then
`curl --cacert certs/server.crt https://localhost:8443/`.
Linux hosts need `sudo chown -R 65532:65532 certs` (see quickstart/README).
