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
JWKS / mTLS client-cert / HMAC request signing), authz + IP ACL,
SQLite state + migrations,
observability, mTLS admin API, CLI, protocol hardening, fuzzing/benchmarks,
and packaging. Later milestones (management plane, extensions, AI/LLM
features) are not yet implemented.

## Hard rules

1. **Never commit `docs-internal/`.** It holds private planning material and
   is intentionally untracked. Never reference it from committed files.
2. **Never push or create PRs** without an explicit user instruction.
3. No new dependencies without checking licenses against `deny.toml` and
   flagging the addition in your report.
4. No emoji in code, comments, docs, or commit messages.
5. `.sdlc/` is internal pipeline state; leave it untracked unless told
   otherwise.

## Commands

```sh
cargo build --workspace
cargo test --workspace            # ~1188 tests; suites spawn real servers/binaries
cargo test -p dwara-bin --features otlp  # +24 feature-gated on top of the default suite
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check advisories licenses bans
cargo doc --no-deps --workspace   # must be zero-warning
cargo run -q -p dwara-cli --bin dwara-cli -- schema   # config reference (diff vs config-reference.json)
```

Extras when touching those areas: `cargo test -p dwara-core --features loom --test loom`,
`cargo test -p dwara-bin --features otlp --test otlp_export`,
`cargo bench --workspace --bench micro`, `actionlint .github/workflows/<file>`,
`scripts/bench-macro.sh` (macro rig), `cargo fuzz run <target>` (from `fuzz/`).

## Verification gate

Before declaring any change done, the full set above must pass in order with
zero warnings and zero failures. Never weaken a command to make it pass (no
`--no-verify`, no scoped subsets for final checks, no clippy allows).

## Layout

| Path | Contents |
|---|---|
| `crates/dwara-core` | The library, organized as bounded-context domain directories behind a facade `lib.rs` (see Code organization below) |
| `crates/dwara-bin` | The `dwara` gateway binary: `main.rs` (entry/shutdown), `listeners.rs` (bind/serve/TLS modes), `reload.rs` (watcher/reload/TLS refresh), `otlp.rs` (feature-gated OTLP trace export) |
| `crates/dwara-admin` | mTLS-only admin API (GET/PATCH /config, /health, /stats) |
| `crates/dwara-cli` | Operator CLI (`run`/`validate`/`fmt`/`diff`/`lint`/`schema`); the load-generator rig lives in the lib (`dwara_cli::loadgen`) behind the thin `dwara-loadgen` bin |
| `fuzz/` | cargo-fuzz crate (its own workspace, not a member) |
| `quickstart/` | One-command docker-compose TLS demo |
| `packaging/` | systemd unit + packaging notes |
| `grafana/` | Starter dashboard for the /metrics families |
| `scripts/` | Macro bench rig + baseline gate + dependency-direction guard |
| `config-reference.json` | Generated JSON Schema (repo root; see freshness gate) |
| `docs/` | Contributor-facing developer documentation (internals, rationale, diagrams) — see Documentation below |
| `docs-site/` | Published end-user (operator) documentation site, VitePress — see Documentation below |

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
                      selector/hash formats), transforms.rs (RFC 6901
                      JSON pointers + the transforms/security-headers
                      shapes, DW-028), versioning.rs (HTTP-date and
                      media-type grammar, DW-048)
  snapshot/           validate -> compile -> publish pipeline; the
                      immutable Snapshot behind ArcSwap
  extensions/         the five swappable subsystem traits
                      (RateLimiter, ConfigSource, CacheStore,
                      AnalyticsSink, SecretSource) + local impls
  observability.rs    spans, access logs, metrics registry, envelope;
                      exposes plain setters only, depends on nothing
  events/             the in-process event bus (DW-044) and the
                      budget-bounded webhook deliverer; sits BELOW
                      snapshot because the config publish pipeline and
                      the resilience state machines both emit onto it
  state/              SQLite store + migrations
  analytics/          the embedded analytics store (DW-043): its own
                      SQLite file (raw access records + 1m/5m/1h/1d
                      additive rollups, cursor-guarded cascade,
                      per-granularity retention, incremental vacuum);
                      implements extensions::analytics::AnalyticsSink;
                      the fire-and-forget channel writer must never
                      block the request path (drop and count on full)
  security/           tls, authn, authz
  resilience/         health, retries, breaker (passive observation)
  dataplane/          proxy, upstream, balance, hardening, cors,
                      compression, and active.rs (probe loops drive
                      the registry — dataplane lifecycle)
```

Dependency direction is strictly downward and **enforced in CI** by
`scripts/check_deps.py` (the verify job fails on any upward import):

```
config          <- everything
extensions      <- config
observability   <- (none)
events          <- config, observability
snapshot        <- config, events
state           <- config
analytics       <- config, observability, extensions
security        <- config, state, observability
resilience      <- config, snapshot, extensions, observability, events
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
  `dataplane/{balance,upstream,proxy}.rs`, `dwara-bin`'s
  `listeners.rs` (panic supervisor), and `dwara-bin`'s `otlp.rs`
  (private-helper white-box tests; justification comment in source).
  New suites must be deterministic under load: bounded polls, unique
  ports, generous margins; see the Test map below.
- **Feature flags** are declared in the owning crate's `Cargo.toml`
  with a comment stating why they exist (see `loom` on dwara-core,
  `otlp` on dwara-bin). No default-on features beyond the standard set.

## Conventions

- **Commits:** conventional style (`feat:`, `fix:`, `ci:`, `test:`, ...),
  subject ≤72 chars, body explains why; reference issues with `Refs #N`
  (PR descriptions carry `Closes`).
- **Config schema:** strict serde — `deny_unknown_fields` on every struct.
  Changes are additive only. Parse-level checks live in `config.rs`;
  semantic validation (refs, bounds, cross-field rules) lives in
  `snapshot.rs::validate` and must produce `ValidationIssue`s naming the
  offending field. Invalid regexes fail at compile in `snapshot.rs`.
  Zero-route configs are guarded (#129): validation rejects an empty
  `routes` list unless the additive top-level `allow_empty_routes:
  true` flag is set — test configs that legitimately declare no routes
  (admin-only, SNI-passthrough-only fixtures) must carry the flag.
  After schema changes, regenerate `config-reference.json`
  (`dwara-cli schema > config-reference.json`) — CI fails on drift.
- **Ops knobs are env vars** (`DWARA_*`), topology is YAML. Do not add
  operational settings to the schema without discussion.
- **Vocabulary is frozen:** Listener/Route/Service/Upstream/Endpoint/
  Consumer/Credential/Policy/Plugin/Workspace/Snapshot. Policy precedence:
  consumer > route > service > listener > global (deny-anywhere-wins).
- **Request-path order** (do not reorder casually): reserved paths
  (/healthz, /readyz, /metrics) → route resolution → route maintenance
  (503 + Retry-After, preflight-exempt, DW-041) → route method allowlist
  (405 + Allow, preflight-exempt like maintenance, DW-030) → route
  limits (413/431) → CORS preflight short-circuit (204, pre-authn) →
  authn → authz → rate limit → gateway cap admission (priority-aware) →
  breaker → endpoint pick → pending cap → connect (request transforms
  run on the forward path inside the proxy action, DW-028: query ops
  after the DW-010 path rewrite, header ops after the trusted-header
  injection, the JSON body transform before retry buffering — matching
  and every policy above evaluated the ORIGINAL request); responses
  then gain field masking (DW-029: proxy actions only, union of the
  route floor and the consumer's groups, fail-closed 502 on
  encoded/non-JSON/over-cap/unparseable/unresolved-pointer bodies —
  the sentinel replaces secrets before any later stage reads the
  body) → body/header transforms (DW-028) → route compression
  (DW-027) → versioning stamps (Vary: Accept fold +
  Deprecation/Sunset/Link, DW-048) → CORS decoration (DW-027) →
  security headers (DW-028, every route-matched response including
  short-circuits) → rate headers. Unrouted traffic
  stops at route resolution: listener- and global-attached policies
  rate-limit the request before the 404; authn/authz never run
  pre-route. Dry-run (DW-041) does not reorder anything: a phase with
  a `dry_run` attachment evaluates in place and reports instead of
  rejecting (route limits, authz, rate limits, load shedding).
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
| `DWARA_OTLP_ENDPOINT` | unset | OTLP trace export; live only in an `otlp`-feature build (`http://` endpoint), reserved-but-inert otherwise |
| `DWARA_HTTP1_*`, `DWARA_H2_*`, `DWARA_REQUEST_BODY_TIMEOUT_MS` | see README | protocol hardening knobs |
| `DWARA_SHUTDOWN_TIMEOUT_SECS` | `10` | graceful drain bound |

Reload: file change (debounced) or SIGHUP. Shutdown: SIGTERM/SIGINT with
backlog flush + drain. `POST` to the admin API is live-published.

## Development environment

- Rust via rustup; the pinned toolchain installs automatically on first
  cargo invocation.
- Optional: Docker (quickstart/images; colima works on macOS),
  `actionlint` (brew) for workflow linting, a nightly toolchain for
  `cargo fuzz`, python3 for `scripts/bench-baseline.py`.
- The musl/aws-lc-rs build needs cmake + a C compiler; the release
  Dockerfiles carry these in their builder stages.
- **Disk out of space:** this workspace's `target/` grows large (multiple
  crates, LTO release builds, fuzz corpora). If a build/test/lint command
  fails with a "No space left on device" (`ENOSPC`) error, run
  `cargo clean` first (drops `target/`, forcing a full rebuild) and retry
  before troubleshooting further. If space is still tight, `cargo clean -p
  <crate>` targets just one crate's artifacts, and `du -sh target/*` finds
  what's largest. Re-run the full verification gate after cleaning, since a
  clean forces every check to rebuild from scratch.

## Test map

Suites live in each crate's `tests/` directory. Run a single suite with
`cargo test -p <crate> --test <name>`.

| Area | Crate | Suites |
|---|---|---|
| Unit (relocated from src) | dwara-core | `tests/unit/*` (one file per source module; white-box residuals stay in `src/` with justification comments) |
| Config schema / validation | dwara-core | `config_schema`, `config_schema_extended`, `snapshot_pipeline` |
| Routing | dwara-core | `router_golden` (golden files), `proxy_coverage` |
| Proxy behavior | dwara-core | `proxy`, `proxy_coverage` |
| TLS | dwara-core / dwara-bin | `tls_validation`, `trusted_ca` / `tls_listener`, `tls_edges` |
| Upstreams / LB | dwara-core | `upstream_client`, `balancing` |
| Health | dwara-core | `passive_health`, `active_health` |
| Resilience | dwara-core | `retries_timeouts`, `breaker_caps`, `load_shedding`, `rate_limit` |
| Edge policies (CORS/compression/limits) | dwara-core | `cors_compression_limits` |
| Transforms + security headers (DW-028) | dwara-core | `transforms` (end to end), `tests/unit/transforms.rs` |
| Response field masking (DW-029) | dwara-core | `masking` (end to end), `tests/unit/transforms.rs` (union + miss-is-the-leak cases) |
| Response caching (DW-037) + request coalescing (DW-038) | dwara-core / dwara-admin | `caching` (end to end: headers, consumer isolation, SWR, ETag, vetoes, invalidation; coalescing single-flight, fail-open fallbacks, saturation, SWR no-deadlock), `tests/unit/response_cache.rs` (envelope/key/validator grammar), `admin_api` purge cases |
| Maintenance + policy dry-run (DW-041) | dwara-core | `maintenance_dry_run` |
| Embedded analytics (DW-043) | dwara-core / dwara-admin | `analytics` (e2e record path incl. custom dims), `tests/unit/analytics_store.rs` (schema, percentile math, rollup cascade exactness/idempotence/cursor-restart, retention, drop-on-full, writer drain, query layer), `admin_api` analytics cases (dashboard/top/query endpoints, closed grammar, 404 without store) |
| Protocol hardening pass 2: PROXY protocol, method allowlist, happy eyeballs (DW-030) | dwara-core / dwara-bin | `method_allowlist` (405+Allow matrix incl. preflight), `upstream_client` (happy-eyeballs dual-stack e2e), `tests/unit/proxy_proto.rs` (header policy), `tests/unit/upstream.rs` (race/order), `protocol_hardening` (real-binary PROXY v1/v2 + fail-closed) |
| Alert/event webhooks (DW-044) | dwara-core | `webhooks` (end to end), `tests/unit/webhooks.rs` |
| State | dwara-core | `store` |
| Auth | dwara-core | `authn`, `authz`, `hmac_signing` |
| Ops | dwara-bin | `reload_edges`, `reload_shutdown`, `healthz_readyz`, `observability`, `protocol_hardening`, `admin_reload_coherence`, `otlp_export` (feature-gated), `otlp_inert`, `hello_listener` |
| Admin API | dwara-admin | `admin_api` |
| Tooling | dwara-core / dwara-cli | `swap_stress`, `loom` (feature-gated) / `cli`, `loadgen_e2e`, `loadgen_unit` |

## Reference: implementation facts

Context that constrains how code is written. Read the entries for any area
you are about to change.

- **Hot reload** swaps an atomic `Snapshot` (+ upstream registry, TLS
  material, auth state) — in-flight requests keep their old generation.
  The listener bind set is restart-only. Counters/gauges survive reloads.
- **State store** (opt-in via `DWARA_STATE_DB`) auto-migrates on open and
  writes a `.bak-*` backup before migrating; schema changes go through
  `migrations.rs` (forward-only, transactional, tracked in
  `PRAGMA user_version`).
- **Credential hashing.** API keys are stored as `sha256:<hex>` (legacy)
  or, when `DWARA_CREDENTIAL_PEPPER` is set, `hmac-sha256:<hex>` (#124),
  with sha256 selectors and constant-time compare in both modes. Legacy
  rows re-hash to the peppered format in place on successful
  verification; peppered rows fail closed without a pepper (401 + one
  ERROR log). Store-managed Basic credentials should use argon2id PHC
  hashes (pepper-independent).
- **Request smuggling.** hyper 1.x does not reject CL+TE requests; the
  pre-parse sniff in `hardening.rs` is the real defense (first head
  only; the proxy rebuilds every forwarded request from parsed parts, so
  framing cannot desync through the gateway).
- **Outbound TLS trust** is per entity (#121): a `trusted_ca_file` PEM
  bundle on an upstream or JWT provider REPLACES the webpki public roots
  for that entity only. Active https health probes inherit their
  upstream's roots. Validation owns PEM-level rejection
  (`check_trusted_ca_file` in `snapshot/mod.rs`); the runtime fail-closed
  paths are only a validate-vs-build race backstop, never a fallback to
  public roots. Bundle paths are NOT file-watched (only the config file
  and terminate cert/key files are): a rotation needs SIGHUP or a config
  change to apply.
- **Listener supervision** (`listeners.rs`): panicked accept loops are
  respawned on the SAME bound socket (cap 8 per listener, process
  lifetime), then given up on with an ERROR log — the process never
  aborts for a dead listener. The socket stays behind a shared `Arc`, so
  shutdown flush polls `poll_accept` with a no-op waker instead of
  `into_std` (re-binding would race the port away).
- **SNI passthrough** (`tls.rs`): the parser reassembles ClientHellos
  fragmented across TLS records, bounded at 64 KiB (`MAX_HELLO_BYTES`);
  the peek never consumes bytes, so the original hello is replayed to the
  upstream by the splice.
- **Concurrency testing.** arc-swap has no loom support; swap paths are
  covered by real-thread stress tests in `tests/swap_stress.rs`. The
  `loom` feature covers the rest of the hot paths.

## CI posture (compute-conscious)

- `ci.yml`: verify (fmt/clippy/build/test + config-reference freshness) and
  supply-chain (cargo-deny + SBOM) on pushes/PRs to main, path-filtered,
  concurrency-cancelled.
- `bench.yml` / `fuzz.yml`: scheduled weekly + manual dispatch only —
  never on PRs. `bench.yml` dispatches take a `job` input (`gate`
  default, `baseline-refresh` to (re)capture the CI micro-bench
  baseline: `gh workflow run bench.yml --ref main -f
  job=baseline-refresh`, and `soak`); `fuzz.yml` builds on a dated
  nightly pin (bump procedure in the workflow).
- `release-artifacts.yml`: tag-only (`v*`), musl binaries with a 25 MB bar
  and GHCR multi-arch images.
- Every action ref across `.github/workflows/` is pinned to a full commit
  SHA (with a `# pinned: <tag> @ <sha>` comment naming the source tag);
  Dependabot (`github-actions`, weekly, `.github/dependabot.yml`) keeps
  the pins fresh — reviewers should not accept unpinned third-party
  actions. Dependabot also has an `npm` lane scoped to `docs-site/`
  (separate from the Rust workspace's `deny.toml` gate).
- `docs-site.yml`: builds and publishes `docs-site/` to GitHub Pages on
  every push to `main` that touches `docs-site/**`.

## Documentation

Two documentation trees, for two different audiences — do not mix their
content:

| Tree | Audience | Content |
|---|---|---|
| `docs/` | dwara contributors (this repo's agents and humans) | In-depth internals: how a feature is implemented, the rationale behind non-obvious choices, mermaid diagrams of flows/state machines. Plain markdown, browsed on GitHub — not built or published separately. |
| `docs-site/` | OSS and enterprise operators | Task-oriented guides (install, configure, deploy, operate) and high-level architecture diagrams — never internals or rationale. A VitePress site, versioned, published to GitHub Pages. |

If a change adds or materially changes a feature covered in either
tree, update the corresponding page(s) as part of the same change —
don't let `docs/` or `docs-site/` drift from the code the way a stale
comment would.

### `docs/` (contributor docs)

- Entry point: [`docs/README.md`](docs/README.md), which tracks what's
  written vs. scaffolded (`docs/features/*.md` stubs marked
  `> **Status: scaffold.**`).
- When writing a page: state what the feature does, why it's built
  that way (cite `DW-xxx`/`#nnn` markers and the module's `//!` doc
  comment — most rationale already lives there), a mermaid diagram if
  it clarifies a flow or state machine, and links to the owning source
  files and test suites. Follow the pattern in the already-written
  pages (`docs/architecture.md`, `docs/features/{tls,dataplane-proxy,
  resilience,authn-authz}.md`).
- No build step; verify by reading rendered markdown/mermaid on GitHub
  (or any local markdown+mermaid previewer) and by re-checking cited
  facts still match the source before merging.

### `docs-site/` (published end-user site)

- Local dev: `cd docs-site && npm install && npm run docs:dev`. Build
  with `npm run docs:build` (must succeed with zero dead-link errors —
  VitePress fails the build on a broken internal link by default).
- Structure: `guide/` (task-oriented), `architecture/` (high-level
  mermaid diagrams only, no internals), `reference/` (generated/
  exhaustive material, e.g. links to `config-reference.json`). See
  [`docs-site/README.md`](docs-site/README.md) for the full layout.
- Links between pages must be relative (versioning plugin requirement)
  — never `/guide/foo`, always `./foo` or `../guide/foo`.
- **Versioning** (`vitepress-versioning-plugin`): the root content
  always tracks `main` and is labeled `unstable`. Before tagging a
  release, run `npm run docs:freeze -- <version>` (no leading `v`) from
  `docs-site/` to snapshot the current root into `versions/<version>/`,
  commit that snapshot, *then* cut the tag — the frozen snapshot must
  land before the tag it documents. Never hand-edit files under
  `versions/`; regenerate by re-running the freeze step against a
  corrected root if a past snapshot needs fixing.
- Publishing is automatic: `.github/workflows/docs-site.yml` builds and
  deploys to GitHub Pages on every push to `main` touching
  `docs-site/**`. There is no separate per-tag deploy — a frozen
  version only appears on the published site once its snapshot is
  committed to `main`.

## Quickstart sanity check

`quickstart/` boots the gateway + a demo upstream over TLS:
`gen-certs.sh && docker compose up`, then
`curl --cacert certs/server.crt https://localhost:8443/`.
Linux hosts need `sudo chown -R 65532:65532 certs` (see quickstart/README).
