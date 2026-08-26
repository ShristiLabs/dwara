# Changelog

All notable changes to dwara are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
the project follows semantic versioning once 1.0 is reached.

## [Unreleased]

### Added

- Cargo workspace scaffold: `dwara-core`, `dwara-bin`, `dwara-admin`,
  `dwara-cli`; pinned toolchain; strict fmt/clippy gates; runnable
  hello-listener (DW-001).
- CI pipeline: fmt/clippy/build/test verification and cargo-deny
  supply-chain gates (advisories, licenses, bans) with a CycloneDX SBOM
  artifact, path-filtered and concurrency-cancelled (DW-002).
- Strict YAML configuration schema for the frozen gateway vocabulary
  (Gateway/Listener/Route/Service/Upstream/Endpoint/Consumer/Credential/
  Policy) with `deny_unknown_fields` everywhere, path-precise parse
  errors, and a JSON Schema export (`dwara-cli schema`; committed as
  `config-reference.json` with a CI freshness gate) (DW-003).
- Swappable subsystem traits — `RateLimiter`, `ConfigSource`,
  `CacheStore`, `AnalyticsSink`, `SecretSource` — dyn-compatible, with
  local in-memory/file/env implementations (DW-004).
- Config compile pipeline: validate (all semantic issues at once) ->
  compile (exact/regex/prefix route tables, content hash) -> publish
  (immutable Snapshot behind ArcSwap, atomic generations). Bad config
  never replaces the running snapshot (DW-005).
- Hot config reload (directory file watch + SIGHUP) and graceful
  shutdown (SIGTERM/SIGINT with backlog flush and bounded drain);
  zero dropped requests through reloads (DW-006).
- TLS listeners: terminate with multi-SNI certificate selection and
  live certificate hot-reload (torn cert/key pairs rejected), TLS 1.2/1.3,
  ALPN h2 + HTTP/1.1, h2c prior-knowledge on cleartext listeners, and
  SNI-routed TLS passthrough (DW-007).
- Pooled upstream clients with per-upstream connection caps (active +
  idle), connect timeouts over dial+TLS, and upstream TLS verification
  against public CA roots (DW-008).
- Reverse-proxy dataplane: route resolution, proxy/redirect/respond
  actions, full-duplex zero-buffer streaming (SSE, multi-GiB bodies,
  HTTP/1.1 protocol-upgrade tunnels), hop-by-hop header hygiene,
  X-Forwarded-For/X-Real-IP with a trusted-proxy chain, and classified
  upstream errors (DW-009).
- Router: query and cookie matchers, path rewrites (`strip_prefix`,
  `replace_prefix`, regex with capture substitution), canonical
  precedence (exact > regex > prefix) documented and golden-file pinned
  (DW-010).
- Upstream load balancing: smooth weighted round-robin,
  least-connections, two-choices random, and ketama consistent hashing
  (sticky by client IP); slow-start ramp; endpoint sets and weights
  hot-swap without restart (property-tested) (DW-011).
- Passive health / outlier ejection: consecutive-failure and windowed
  5xx-ratio rules with volume gates, half-open probe recovery,
  fail-open when every endpoint of a pool is ejected (DW-012).
- Active health checks: HTTP/TCP probes with full jitter feeding the
  ejection machinery; reserved `/healthz` and `/readyz` endpoints
  served before routing (DW-013).
- Upstream timeouts (per-attempt header deadline, response-body
  inactivity) and bounded retries: idempotency rules (POST strictly
  opt-in; DELETE/PATCH never), full-jitter exponential backoff, retry
  budget over all proxied traffic, opt-in size-capped body replay
  (DW-014).
- Circuit breaking and capacity caps: per-upstream breaker (consecutive
  + rolling error-ratio, half-open probes, 503 + Retry-After), per-
  upstream pending-connection rejection, gateway-wide concurrency cap
  with body-lifetime permits; admission rejections never masquerade as
  upstream failures (DW-015).
- Priority-aware load shedding: route/consumer priority with a reserved
  high-priority bucket; per-priority admit/shed counters (DW-016).
- Local rate limiting: GCRA behind the `RateLimiter` trait, selector
  combos (ip/credential/route), stacked windows, 429 + `Retry-After`
  (max across binding rules) + `X-RateLimit-*` headers (DW-017).
- Optional SQLite state store (`DWARA_STATE_DB`, off by default):
  consumers, hashed credential records, quota counters; in-memory hot
  cache (auth lookups never touch disk after warmup); owner-only file
  permissions and redacted debug output (DW-018).
- Automatic, forward-only SQLite schema migrations with a pre-migration
  timestamped backup; startup aborts if the backup fails; databases
  newer than the build are refused (DW-115).
- Authentication: API keys (sha256 selectors, constant-time compare,
  optional argon2id), Basic, and JWT Bearer via JWKS providers with
  rotation (unknown-kid refresh throttled, stale-refresh-before-use,
  failed-refresh backoff); routes gain `auth_required`; consumer
  identity drives rate limiting, policy precedence, and shedding
  priority; `X-Consumer-*` spoof prevention (DW-019).
- Authorization and IP access control: route-level consumer/group
  allow-deny, JWT scope and exact-claim requirements, and CIDR ACLs on
  the trusted-chain effective client IP; the precedence chain
  (consumer > route > service > listener > global, deny-anywhere-wins)
  with the route link live (DW-020).
- Observability: per-phase tracing spans, structured JSON access logs
  with exhaustive redaction and sampling, request IDs, Prometheus
  `/metrics` endpoint (12 metric families), a uniform JSON error
  envelope, and a starter Grafana dashboard (DW-021).
- mTLS-only admin API (default-off): GET/PATCH `/config` (full-YAML
  dry-run, atomic file write, live publish), `/health`, `/stats`;
  `dwara-cli` with `run`/`validate`/`fmt`/`diff`/`lint` subcommands
  (DW-022).
- Protocol hardening: HTTP/1 parser bounds and slowloris header
  timeout, HTTP/2 stream/window caps, pre-parse CL+TE smuggling
  rejection (hyper 1.x does not reject the pair itself), request-body
  inter-frame inactivity timeout (DW-023).
- Performance verification harness: criterion micro benchmarks with a
  machine-guarded baseline regression gate, a paced load generator
  (`dwara-loadgen`), a macro bench rig, and schedule-only CI
  (DW-024).
- Fuzzing and concurrency verification: six libFuzzer targets (1M
  executions each, zero panics), loom model tests behind a `loom`
  cargo feature, and real-thread snapshot/balancer stress tests
  (DW-025).
- Packaging and quickstart: static musl scratch (17.6 MB) and
  distroless images, a one-command docker-compose TLS quickstart, a
  hardened systemd unit, and a tag-only release workflow with a 25 MB
  size bar and GHCR multi-arch images (DW-026).

### Fixed

- Linux config-watcher reload loop: each reload's own read bumped the
  config file's atime, re-firing the inotify watcher forever at the
  debounce cadence. Watch events are now limited to create/modify-data/
  remove/rename, and file-watch reloads of unchanged content are no-ops
  (SIGHUP remains a forced reload).
- SNI ClientHello parser panicked on truncated length fields (found by
  fuzzing); every length read is now bounds-gated.
- TLS certificate hot-reload accepted a torn cert/key pair (new cert
  with old key); reloads now verify the key matches the leaf
  certificate and otherwise keep the previous material.

### Changed

- `PATCH /config` no longer double-bumps the generation: the file
  watcher's reload of identical content is a no-op.
- Gateway-generated responses use a uniform JSON error envelope
  (`{error:{code,message,request_id}}`).

### Security

- All GitHub Actions references pinned to full commit SHAs (first- and
  third-party) with weekly Dependabot updates keeping the pins fresh
  (DW-002 follow-up).
