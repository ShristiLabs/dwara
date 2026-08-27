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
JWKS / mTLS client-cert), authz + IP ACL, SQLite state + migrations,
observability, mTLS admin
API, CLI, protocol hardening, fuzzing/benchmarks, and packaging. Later
milestones (management plane, extensions, AI/LLM features) are not yet
implemented.

## Layout

| Path | Contents |
|---|---|
| `crates/dwara-core` | The library, organized as bounded-context domain directories behind a facade `lib.rs` (see Code organization below) |
| `crates/dwara-bin` | The `dwara` gateway binary: `main.rs` (entry/shutdown), `listeners.rs` (bind/serve/TLS modes), `reload.rs` (watcher/reload/TLS refresh) |
| `crates/dwara-admin` | mTLS-only admin API (GET/PATCH /config, /health, /stats) |
| `crates/dwara-cli` | Operator CLI (`run`/`validate`/`fmt`/`diff`/`lint`/`schema`); the load-generator rig lives in the lib (`dwara_cli::loadgen`) behind the thin `dwara-loadgen` bin |
| `fuzz/` | cargo-fuzz crate (its own workspace, not a member) |
| `quickstart/` | One-command docker-compose TLS demo |
| `packaging/` | systemd unit + packaging notes |
| `grafana/` | Starter dashboard for the /metrics families |
| `scripts/` | Macro bench rig + baseline gate + dependency-direction guard |
| `config-reference.json` | Generated JSON Schema (repo root; see freshness gate) |

## Code organization

The codebase follows an enterprise bounded-context layout. `dwara-core`
is the domain library; its `src/` tree groups modules by domain with a
facade `lib.rs` as the only intended public surface:

```
crates/dwara-core/src/
  lib.rs              facade: declares the domain modules and the
                      aggregate error type, re-exports #[doc(hidden)]
                      legacy top-level aliases, documents the
                      dependency direction
  error.rs            facade-level Error enum over the eight domain
                      error types (boundary propagation; domains keep
                      their typed errors for recoverable matches)
  config/             schema types, YAML parsing, and the shared
                      grammar everything validates against: net.rs
                      (IP/CIDR utilities), limits.rs (schema
                      validation bounds), credentials.rs (credential
                      selector/hash formats)
  snapshot/           validate -> compile -> publish pipeline; the
                      immutable Snapshot behind ArcSwap
  extensions/         the five swappable subsystem traits
                      (RateLimiter, ConfigSource, CacheStore,
                      AnalyticsSink, SecretSource) + local impls
  observability.rs    spans, access logs, metrics registry, envelope;
                      exposes plain setters only, depends on nothing
  state/              SQLite store + migrations
  security/           tls, authn, authz
  resilience/         health, retries, breaker (passive observation)
  dataplane/          proxy, upstream, balance, hardening, and
                      active.rs (probe loops drive the registry —
                      dataplane lifecycle)
```

Dependency direction is strictly downward and **enforced in CI** by
`scripts/check_deps.py` (the verify job fails on any upward import):

```
config          <- everything
extensions      <- config
snapshot        <- config
observability   <- (none)
state           <- config
security        <- config, state, observability
resilience      <- config, snapshot, extensions, observability
dataplane       <- all of the above
bin/admin/cli   <- dwara-core (presentation layer)
```

Rules for new code:

- **Pick the domain first.** New behavior goes into the domain
  directory that owns it; if it spans two domains, it belongs in the
  lower one and is consumed by the higher one.
- **Never import upward.** `config` imports nothing from sibling
  domains; `dataplane` may import anything. A change that forces an
  upward import is a design smell — restructure instead. The guard
  (`python3 scripts/check_deps.py`, wired into CI) fails the build on
  violations; if a genuinely new dependency is needed, move the shared
  item DOWN into the lowest consuming domain (the precedent: IP/CIDR
  grammar, validation limits, and credential hash formats all live in
  `config`).
- **The facade is the API.** Public items are reachable via the domain
  modules; the root also re-exports legacy flat aliases
  (`dwara_core::proxy`, `dwara_core::tls`, ...) — `#[doc(hidden)]`,
  kept for compatibility. New external code should use the canonical
  domain paths (`dwara_core::dataplane::proxy`). For error
  propagation across boundaries, `dwara_core::error::Error` aggregates
  the eight domain error types via `From`.
- **Domain promotion path.** When a domain grows an independent release
  cadence or a heavy dependency tree (e.g. `state` pulling rusqlite),
  promote `src/<domain>/` to `crates/dwara-<domain>` and re-export it
  from the facade. The directory structure is the extraction seam —
  keep domains self-contained so promotion is a `git mv` plus Cargo
  manifest work, not a rewrite.
- **Tests live in `tests/`, not `src/`.** `crates/dwara-core/tests/`
  holds integration suites (`<domain>.rs`, process-level where
  possible), the relocated unit tests (`tests/unit/`, one mod file
  per source module behind a single `main.rs` binary to bound CI link
  time), and `tests/support/mod.rs` — the shared fixture module
  (config builders, gateway/backend spawn helpers, HTTP client
  helpers). New suites `mod support;` instead of re-declaring
  fixtures; suite-specific variants stay local. The ONLY tests allowed
  in `src/` are white-box tests of private internals that cannot be
  expressed through the public API — each carries a comment saying why
  it stays (e.g. raw-SQL introspection of the store's connection).
  Current residuals: `state/store.rs`,
  `dataplane/{balance,upstream,proxy}.rs`, and `dwara-bin`'s
  `listeners.rs` (panic supervisor). New suites must be
  deterministic under load: bounded polls, unique ports, generous
  margins; see the Test map below.
- **Feature flags** are declared in the owning crate's `Cargo.toml`
  with a comment stating why they exist (see `loom`). No default-on
  features beyond the standard set.

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
| `DWARA_CREDENTIAL_PEPPER` | unset | per-deployment secret peppering stored credential hashes (#124); unset = legacy-only mode |
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
  endpoint pick → pending cap → connect. Unrouted traffic stops at
  route resolution: listener- and global-attached policies rate-limit
  the request before the 404; authn/authz never run pre-route.
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
| Unit (relocated from src) | `tests/unit/*` (one file per source module; white-box residuals stay in `src/` with justification comments) |
| Config schema / validation | `config_schema`, `config_schema_extended`, `snapshot_pipeline` |
| Routing | `router_golden` (golden files), `proxy_coverage` |
| Proxy behavior | `proxy`, `proxy_coverage` |
| TLS | `tls_validation`, `tls_listener`, `tls_edges`, `trusted_ca` |
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
- API keys are stored as `sha256:<hex>` (legacy) or, when
  `DWARA_CREDENTIAL_PEPPER` is set, `hmac-sha256:<hex>` (#124), with
  sha256 selectors and constant-time compare in both modes. Legacy
  rows re-hash to the peppered format in place on successful
  verification; peppered rows fail closed without a pepper (401 + one
  ERROR log). Store-managed Basic credentials should use argon2id PHC
  hashes (pepper-independent).
- arc-swap has no loom support; swap paths are covered by real-thread
  stress tests in `tests/swap_stress.rs`.
- Listener accept tasks are panic-supervised (`listeners.rs`): a
  panicked accept loop is respawned on the SAME bound socket (cap 8 per
  listener, process lifetime), then the listener is given up on with an
  ERROR log — the process never aborts for a dead listener. The socket
  stays behind a shared `Arc`, so the shutdown flush polls `poll_accept`
  with a no-op waker instead of `into_std` (re-binding would race the
  port away).
- The passthrough SNI parser reassembles ClientHellos fragmented across
  TLS records, bounded at 64 KiB (`MAX_HELLO_BYTES` in `tls.rs`); the
  peek never consumes bytes, so the original hello is replayed to the
  upstream by the splice.
- Outbound https trust is per entity (#121): a `trusted_ca_file` PEM
  bundle on an upstream or JWT provider REPLACES the webpki public roots
  for that entity only (additive trust exists solely for the
  programmatic `with_root_certificates` API), and active https health
  probes inherit their upstream's roots (kept on the upstream handle).
  Validation owns PEM-level rejection — `check_trusted_ca_file` in
  snapshot/mod.rs parses the bundle (rustls-pki-types) and rejects
  missing, unreadable, or certificate-free files naming the field; the
  runtime fail-closed paths (empty root store plus ERROR log for the
  upstream, provider disabled for a JWT provider) are only a
  microsecond validate-vs-build race backstop, never a fallback to the
  public roots. Bundle paths are NOT file-watched (only the config file
  and terminate cert/key files are): a rotation needs SIGHUP or a
  config change to apply.

## CI posture (compute-conscious)

- `ci.yml`: verify (fmt/clippy/build/test + config-reference freshness) and
  supply-chain (cargo-deny + SBOM) on pushes/PRs to main, path-filtered,
  concurrency-cancelled.
- `bench.yml` / `fuzz.yml`: scheduled weekly + manual dispatch only —
  never on PRs.
- `release-artifacts.yml`: tag-only (`v*`), musl binaries with a 25 MB bar
  and GHCR multi-arch images.
- Every action ref across `.github/workflows/` is pinned to a full commit
  SHA (with a `# pinned: <tag> @ <sha>` comment naming the source tag);
  Dependabot (`github-actions`, weekly, `.github/dependabot.yml`) keeps
  the pins fresh — reviewers should not accept unpinned third-party
  actions.

## Quickstart sanity check

`quickstart/` boots the gateway + a demo upstream over TLS:
`gen-certs.sh && docker compose up`, then
`curl --cacert certs/server.crt https://localhost:8443/`.
Linux hosts need `sudo chown -R 65532:65532 certs` (see quickstart/README).
