# AGENTS.md

Guidance for AI coding agents. Detailed reference material lives in
[`docs/agent-guide/`](docs/agent-guide/).

---

## 1. Project overview and code organization

**dwara** is a streaming reverse-proxy API gateway in Rust (Apache-2.0).
Cargo workspace, pinned toolchain (Rust 1.94.0, `rust-toolchain.toml`).
Repo: `shristilabs/dwara`. Pre-1.0, milestones M1-M6 complete.

Two editions: **OSS** (`cargo build`) and **Enterprise** (`cargo build
--features ent`). Only two cargo features exist: `ent` and `loom`
(test-only). Everything else compiles unconditionally into OSS.

### Workspace crates

| Crate | Role |
|---|---|
| `dwara-core` | Library. Bounded-context domains behind facade `lib.rs`. |
| `dwara-bin` | Gateway binary (`main.rs`, `listeners.rs`, `reload.rs`, `otlp.rs`, `h3.rs`, `upgrade.rs`). |
| `dwara-admin` | mTLS admin API + web console. |
| `dwara-cli` | Operator CLI (`run`/`validate`/`fmt`/`diff`/`lint`/`schema`/`import`/`tf`/`upgrade`/`plugin`/`replay`/`k8s`). |
| `dwara-console` | Read-only web console SPA (no deps, `publish = false`). |
| `dwara-ebpf` | eBPF research spike. **Excluded** from workspace. See `docs/adr/0002-ebpf-hooks-research-spike.md`. |
| `dwara-uring` | io_uring experiment. **Excluded** from workspace. See `docs/adr/0003-io-uring-engine.md`. |

Other paths: `fuzz/` (cargo-fuzz, own workspace), `quickstart/`,
`packaging/`, `grafana/`, `scripts/`, `tools/config-studio/`,
`config-reference.json`, `docs/`, `docs-site/`.

### Domain modules (`dwara-core/src/`)

```
config/          schema types, YAML parsing, shared grammar
snapshot/        validate -> compile -> publish; immutable Snapshot (ArcSwap)
extensions/      swappable traits (RateLimiter, ConfigSource, CacheStore,
                 AnalyticsSink, SecretSource) + LicenseGate + Redis/Vault (ent)
observability.rs spans, metrics, access logs, SLO/error budgets
events/          event bus, webhook delivery, event stream
state/           SQLite store + migrations
analytics/       embedded analytics (SQLite), live sketches, ML insights
security/        tls, authn, authz, geoip, oauth2, oidc, cedar, fips, pq, acme
resilience/      health, retries, breaker, adaptive rate-limit tuning
plugins/         native filter chain + WasmDispatch bridge
wasm/            proxy-wasm host (wasmtime/cranelift)
ai/              provider adapters, routing, streaming, budgets, cost,
                 governance, guardrails, semantic cache, experiments, MCP, A2A
cel/             CEL expression engine
openapi/         OpenAPI response validation
aggregation/     API aggregation
mcp/             agent-operable admin via MCP
synthetic/       synthetic monitoring probes
lifecycle/       developer portal, environment profiles, API journey
mesh/            service mesh (scaffolded no-ops, intended ent-only)
k8s_gateway/     Kubernetes Gateway API translator
cp_dp/           CP/DP split (ent)
workspace/       workspaces + RBAC + audit (ent)
dataplane/       reverse-proxy request path, upstreams, balancers, transforms,
                 caching, waf, anomaly, canary, discovery, l4, graphql, grpc_web,
                 protocol translation, nano-service, hedging, split, replay
error.rs         facade-level aggregate Error
supervision.rs   panic-respawn supervision (no domain imports)
```

### Dependency direction

Enforced by `scripts/check_deps.py` (CI fails on violations). Authoritative
source is the `ALLOWED` dict in that script.

```
config          <- (nothing)
extensions      <- config
observability   <- (nothing)
events          <- config, observability
snapshot        <- config, events, security
state           <- config
analytics       <- config, observability, extensions
mesh            <- config
security        <- config, state, observability, mesh
resilience      <- config, snapshot, extensions, observability, events
plugins         <- config
wasm            <- config, plugins
k8s_gateway     <- config
cp_dp           <- config, snapshot, extensions        (ent)
ai              <- config
dataplane       <- all of the above
supervision     <- (nothing)
```

Domains not yet in `ALLOWED` (`cel`, `openapi`, `aggregation`, `mcp`,
`synthetic`, `lifecycle`) have no cross-domain imports. Add to `ALLOWED` in
the same change if one gains a dependency.

**Key rules:**
- New code goes into the domain that owns it. If it spans two, put it in the lower one.
- Never import upward. Move shared items DOWN into the lowest consumer.
- Use canonical domain paths (`dwara_core::dataplane::proxy`), not legacy aliases.
- When a domain outgrows its directory, promote to `crates/dwara-<domain>`.

---

## 2. Build and test commands

```sh
cargo build --workspace
cargo build --workspace --features ent
cargo test --workspace                  # ~2700 tests
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check advisories licenses bans
cargo doc --no-deps --workspace         # zero-warning required
cargo run -q -p dwara-cli --bin dwara-cli -- schema
python3 tools/config-studio/build.py    # after schema changes
```

Area-specific: `cargo test -p dwara-core --features loom --test loom`,
`cargo bench --workspace --bench micro`, `cargo bench --workspace --bench cel`,
`actionlint .github/workflows/<file>`, `scripts/bench-macro.sh`,
`cargo fuzz run <target>` (from `fuzz/`).

**Verification gate:** all commands above must pass with zero warnings/failures
before declaring any change done. Never weaken a command to make it pass.

CI workflow details: [`docs/agent-guide/ci.md`](docs/agent-guide/ci.md).

---

## 3. Code style guidelines

- **No emoji** in code, comments, docs, or commit messages.
- **Strict serde:** `deny_unknown_fields` on every config struct. Changes additive only.
- **Ops knobs are env vars** (`DWARA_*`), topology is YAML.
- **Frozen vocabulary:** Listener / Route / Service / Upstream / Endpoint /
  Consumer / Credential / Policy / Plugin / Workspace / Snapshot.
  Policy precedence: consumer > route > service > listener > global (deny-anywhere-wins).
- **Error envelope:** gateway-generated responses use
  `{error:{code,message,request_id}}`. Never leak upstream internals.
- **Streaming:** dataplane buffers nothing by default. Buffering must be opt-in and size-capped.
- **Metrics:** label cardinality must stay config-bounded (no consumer-name labels).
  Counters survive reloads. Hot paths use atomics only.
- **Feature flags** declared in owning crate's `Cargo.toml` with a comment.
  Only `ent` and `loom` exist.
- Config schema changes require regenerating `config-reference.json`
  (`dwara-cli schema > config-reference.json`) AND rebuilding config-studio
  (`python3 tools/config-studio/build.py`). CI fails on drift.

Request pipeline order: [`docs/agent-guide/request-pipeline.md`](docs/agent-guide/request-pipeline.md).
Config studio rules: [`docs/agent-guide/config-studio.md`](docs/agent-guide/config-studio.md).

---

## 4. Testing instructions

- Tests live in `tests/`, not `src/`. `crates/dwara-core/tests/` has ~90
  integration suites + `tests/unit/` (relocated unit tests, one file per
  source module behind `main.rs`). Shared fixtures in `tests/support/mod.rs`.
- White-box tests in `src/` are allowed ONLY for private internals that
  cannot be tested through the public API. Each carries a justification
  comment. Current residuals: `state/store.rs`,
  `dataplane/{balance,upstream,proxy}.rs`, `dwara-bin`'s `listeners.rs`
  and `otlp.rs`.
- Integration tests spawn real servers or the real binary (`CARGO_BIN_EXE_*`).
  Use unique ports and bounded readiness polls.
- Zero tolerance for flakes. Re-run new timing-sensitive suites 5x.
  Use tiny windows with generous margins. Never use sleeps as synchronization.
- Zero-route test configs must carry `allow_empty_routes: true`.

Full test map: [`docs/agent-guide/test-map.md`](docs/agent-guide/test-map.md).

---

## 5. Security considerations

- **Secrets:** never logged, never in `Debug` output. Redaction is exhaustive.
  Query strings excluded from logs/spans. `X-Consumer-*` stripped inbound.
- **Dependencies:** no new deps without checking licenses against `deny.toml`
  and flagging the addition.
- **Credentials:** constant-time compare, peppered hashes, argon2id for
  store-managed passwords. See [`docs/agent-guide/implementation-notes.md`](docs/agent-guide/implementation-notes.md).
- **Request smuggling:** `hardening.rs` sniffs CL+TE; proxy rebuilds every
  forwarded request from parsed parts.
- **TLS trust:** per-entity trust roots, not global fallback. Never fall back
  to public roots at runtime.
- **Never commit** `docs-internal/` or `.sdlc/`.
- **No issue IDs** (`DW-###`, `#123`) in end-user-facing content: root README,
  user-facing READMEs (`quickstart/`, `packaging/`, `tools/`), `docs-site/`,
  or operator-facing sample files. Allowed in: `CHANGELOG.md`, `docs/`,
  `AGENTS.md`, commit messages, source comments.

---

## 6. Architecture decision records

ADRs live in `docs/adr/`:

| ADR | Topic |
|---|---|
| [`0001-controller-persistence.md`](docs/adr/0001-controller-persistence.md) | Ent controller persistence |
| [`0002-ebpf-hooks-research-spike.md`](docs/adr/0002-ebpf-hooks-research-spike.md) | eBPF hooks research spike |
| [`0003-io-uring-engine.md`](docs/adr/0003-io-uring-engine.md) | io_uring engine experiment |

Implementation notes (hot reload, credential hashing, TLS trust, listener
supervision, SNI passthrough, zero-downtime upgrade, concurrency testing,
extension points): [`docs/agent-guide/implementation-notes.md`](docs/agent-guide/implementation-notes.md).

---

## 7. End-user documentation style

End-user docs live in `docs-site/` (VitePress, published to GitHub Pages).

- **Audience:** OSS and enterprise operators.
- **Content:** task-oriented guides (install, configure, deploy, operate) and
  high-level architecture diagrams. Never internals or rationale.
- **Structure:** `guide/` (task-oriented), `architecture/` (high-level
  mermaid only), `reference/` (generated/exhaustive).
- **Links:** always relative (`./foo`, `../guide/foo`), never absolute.
- **Versioning:** `vitepress-versioning-plugin`. Root tracks `main`
  (labeled `unstable`). Before tagging a release: `npm run docs:freeze --
  <version>` from `docs-site/`, commit snapshot, then cut tag. Never
  hand-edit `versions/`.
- **Build:** `cd docs-site && npm install && npm run docs:build` (must
  succeed with zero dead-link errors).
- Publishing is automatic via `docs-site.yml` on push to `main`.
- **Update:** Update end-user documentation as necessary after every change. 

---

## 8. Developer documentation guidelines

Contributor docs live in `docs/` (plain markdown, browsed on GitHub).

- **Audience:** dwara contributors (agents and humans).
- **Content:** how a feature is implemented, rationale behind non-obvious
  choices, mermaid diagrams of flows/state machines.
- **Entry point:** [`docs/README.md`](docs/README.md) tracks what's
  written vs scaffolded.
- **When writing:** state what the feature does, why it's built that way
  (cite `DW-xxx`/`#nnn` and the module's `//!` doc comment), include a
  mermaid diagram if it clarifies a flow, link to owning source files and
  test suites.
- **Follow the pattern** in existing pages (`docs/architecture.md`,
  `docs/features/`).
- No build step. Verify by reading rendered markdown on GitHub.
- If a change adds or materially changes a feature, update the corresponding
  page(s) in the same change.

---

## 9. Code commit guidelines

- **Never push or create PRs** without explicit user instruction.
- **Conventional commits:** `feat:`, `fix:`, `ci:`, `test:`, etc.
  Subject <=72 chars, body explains why. Reference issues with `Refs #N`
  (PR descriptions carry `Closes`).
- **No emoji** in commit messages.
- **Verification before commit** The full verification gate must pass before committing.
- **No Co-Authored by** Attributions necessary.

---

## 10. Local development guidelines

```sh
cargo run -p dwara-bin                        # uses crates/dwara-bin/dwara.yaml
DWARA_CONFIG=path/to/conf.yaml cargo run -p dwara-bin
```

- Rust via rustup; pinned toolchain installs automatically.
- Optional: Docker (colima on macOS), `actionlint` (brew), nightly toolchain
  for `cargo fuzz`, python3 for bench scripts.
- musl/aws-lc-rs build needs cmake + C compiler.
- **Disk space:** `target/` grows large. On `ENOSPC`, run `cargo clean` and
  retry. `cargo clean -p <crate>` for targeted cleanup.

Full environment variable reference: [`docs/agent-guide/env-vars.md`](docs/agent-guide/env-vars.md).
Quickstart instructions: [`docs/agent-guide/config-studio.md`](docs/agent-guide/config-studio.md).
