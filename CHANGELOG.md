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
- Per-entity private-CA trust: `trusted_ca_file` on upstreams and JWT
  providers — a PEM CA bundle (multi-cert supported) that REPLACES the
  webpki public roots for that upstream's TLS connections AND its https
  active-health probes, and for that provider's https JWKS fetches.
  Unset keeps the public roots; validation rejects a bundle that is
  missing, unreadable, or PEM-unparseable (zero certificates), so one
  that goes bad after publish is caught at reload and the old
  generation keeps serving — the runtime fail-closed paths (upstream
  TLS dials refused / provider disabled) remain only as a
  validate-vs-build race backstop, never a silent fallback (#121).
- Policy attachment and authorization at every precedence level
  (#123): gateway-level `global_policies` and `authorization`,
  listener `policies` and `authorization`, and consumer/service
  `authorization` join the existing route/service policy links and
  route authorization, so both frozen chains (consumer > route >
  service > listener > global) run end-to-end from config. Rate-limit
  rules at all attached levels AND together, with the most specific
  denying rule binding the 429 headers; an authorization deny at any
  level wins. Unrouted 404 traffic no longer bypasses rate limiting:
  listener- and global-attached policies apply before the 404 (429
  when denied, else 404 with `X-RateLimit-*`), the reserved paths
  stay exempt, and authn/authz still never run pre-route. A policy
  attached at multiple levels is evaluated once per request (its most
  specific occurrence binds the 429 headers), and
  `RateLimitEngine::check` widened from three to five policy lists —
  listener and global added (public surface).
- Credential pepper (#124): `DWARA_CREDENTIAL_PEPPER` (a per-deployment
  secret resolved through the SecretSource seam, never logged) moves
  every NEW stored credential hash to `hmac-sha256:<hex>` (HMAC-SHA256
  keyed by the pepper), so a state-DB leak alone cannot verify guesses.
  Legacy `sha256:<hex>` entries keep verifying; without a pepper the
  gateway runs legacy-only and peppered entries fail closed with an
  ERROR log (a set-but-unreadable value refuses startup).
- mTLS client-certificate authentication (#124): a terminate listener
  with `tls.client_ca_file` (a PEM CA bundle; rejected in passthrough
  mode) verifies presented client certificates during the handshake
  (unverified = handshake failure) and maps the verified certificate to
  a consumer via its `mtls` credential — by subject CommonName or
  SHA-256 fingerprint (exactly one must be set). A verified certificate
  matching no credential is a 401; header credentials (API key, Basic,
  Bearer) take precedence over the ambient certificate; a connection
  without one is still accepted.
- Store-managed consumer groups (#124): SQLite schema v3 adds
  `consumers.groups` (a JSON array; existing rows default to none) via
  the automatic forward-only migration with the pre-migration backup,
  so group-based authorization (`allowed_groups`/`denied_groups`) now
  applies to store-managed consumers exactly as to config consumers —
  previously they could never satisfy a group rule.
- OTLP trace export behind a default-off `otlp` cargo feature (#126):
  built with the feature and `DWARA_OTLP_ENDPOINT` set (an `http://`
  collector base endpoint; `/v1/traces` is appended), the gateway
  exports its existing request root/phase spans over OTLP http/protobuf
  to any collector receiver, flushed bounded by the shutdown drain
  budget; the default build is unchanged (the variable stays
  reserved-but-inert).
- Rate-limiter eviction and key-count metrics (#132):
  `dwara_rate_limiter_evictions_total` (cells dropped by eviction
  sweeps, aggregated over every compiled rule; resets when a reload
  rebuilds the engine) and `dwara_rate_limiter_live_keys` (live
  per-key cells, bounded by the sharded store cap) — both scrape-time
  snapshot gauges on `/metrics`, aggregate and unlabeled so metric
  cardinality is never per key.
- Route-scoped edge policies (#28): three additive optional Route
  fields. `cors` — the gateway answers browser preflights itself
  (204 right after route resolution and BEFORE authentication,
  because browsers send preflights without credentials; never proxied;
  a policy-rejected preflight is still 204 but carries no CORS
  headers) and decorates actual responses with the policy headers +
  `Vary: Origin`; origins are an exact allowlist matched in
  normalized form (case-insensitive scheme/host, default port
  dropped) or the single entry `*`, which validation never allows
  together with `allow_credentials`; routes must list `OPTIONS` in
  `match.methods` for preflights to resolve. `compression` — opt-in
  per route; gzip/brotli/zstd negotiated against `Accept-Encoding`
  (config preference order, `q=0` refusal, `*`), never applied to
  204/304/101 or already-encoded bodies, `min_size` and
  content-type include/exclude lists, one `level` clamped per
  algorithm; the body streams through the codec chunk-by-chunk with a
  per-chunk flush (SSE-safe, never buffered whole), and every
  non-encoded response on the route carries `Vary: Accept-Encoding`.
  `limits` — per-route request caps enforced right after route
  resolution: declared `Content-Length` over `max_body_bytes` is a
  413 before any upstream contact, unknown-length bodies abort 413
  the moment they cross the cap, and `max_header_count` /
  `max_header_bytes` answer 431 — all in the JSON error envelope.
  Codec dependencies flate2/brotli/zstd added (tower-http
  deliberately not); `config-reference.json` regenerated.
- Secret references in config (#46): `consumers[].credentials[].api_key.key`
  accepts the value inline (unchanged) or as a `${...}` reference —
  `${ENV_NAME}` (an environment variable of the gateway process) or
  `${file:/path}` (read at config-compile time; ONE trailing newline
  trimmed per the mounted-secret convention; must be non-empty; the
  read is bounded at 1 MiB and an oversized file fails closed naming
  the path and the limit).
  References resolve when a generation is built — cold start and every
  hot reload / admin publish, never per request — and are re-read on
  each reload, so rotating a secret file needs a SIGHUP, config change,
  or PATCH to apply; the resolved bytes are hashed into selectors and
  stored hashes and the plaintext dropped. Unresolvable (unset/empty
  env var, missing/empty/oversized file) or malformed — including
  never-closed — `${`-shaped values fail
  validation closed naming the field — a typo'd reference is never
  installed as a literal key. With `DWARA_STATE_DB`, a re-seed whose
  reference no longer resolves also revokes the row previously seeded
  from that reference (SQLite schema v4 adds `credentials.source_ref`
  for the linkage), so a store-backed old key fails closed instead of
  lingering. OPERATOR-VISIBLE BEHAVIOR CHANGE: admin
  `GET /config` no longer returns credential material — inline api_key
  values are served redacted as `${redacted:sha256:<8 hex>}`
  fingerprints (same key = same fingerprint, so which key a generation
  carries can be confirmed without seeing it) and references echo
  verbatim; `Credential` `Debug` is redacted so the whole config tree
  is Debug-safe. The placeholder is unresolvable by design: a
  GET-then-PATCH round trip carrying it back is rejected with 400
  naming the field instead of installing placeholder bytes as a live
  key (re-enter the key or switch the field to a reference). New
  `FileSecretSource` extension impl (re-reads per resolve, no caching;
  a missing file is a fail-closed error naming the path);
  `config-reference.json` regenerated.
- HMAC request signing (#37): a fifth credential family. Consumers
  declare `credentials: [{type: hmac, key_id, secret}]` (the secret
  inline — redacted in every config echo like api keys — or a
  `${...}` reference); a signed request carries five headers
  (`X-Dwara-Key-Id/-Timestamp/-Nonce/-Body-Sha256/-Signature`) and the
  gateway verifies HMAC-SHA256 over a canonical string of a version
  tag plus seven signed elements
  (key id, method, raw path, raw query, timestamp, nonce,
  body digest — the grammar is pinned in the `security::authn` module
  docs and re-implemented independently by the integration suite as
  the interop contract). Timestamps outside a gateway-wide
  clock-skew window (`hmac_auth.max_clock_skew_secs`, default 300s,
  validated 1..=3600) are 401 before any MAC work; nonces are
  remembered for twice the window in a sharded per-instance in-memory
  cache (single-instance boundary documented; a shared store is the
  enterprise seam) and a replay inside the window is 401; the MAC
  compares in constant time over the full digest, with a dummy
  computation on unknown key ids so key existence is not
  timing-readable. The signed body digest is enforced while STREAMING:
  nothing is buffered, any body size, the digesting wrapper sits inside
  the route's body-limit wrapper (413 still wins), and a body that
  does not match its signed digest aborts the upstream send mid-stream
  and answers 401 — a tampered body never completes upstream. The
  secret never becomes a stored hash (an HMAC needs the raw key bytes),
  so the credential is config-served only, held zeroized in memory, and
  the credential pepper deliberately does not apply;
  `config-reference.json` regenerated.
- API versioning aids (DW-048): a new `match.accept` route criterion
  for media-type version selection — a bare `type/subtype` (e.g.
  `application/vnd.acme.v2+json`) that the request's `Accept` header
  must NAME explicitly (any list entry matches case-insensitively;
  q-values/parameters ignored; wildcards and a missing header never
  match, so unconstrained clients fall to the unversioned default
  route; the configured spelling is normalized — padding and case —
  once at snapshot compile, so padded values match exactly like
  trimmed ones), and a per-route `deprecation` block automating the RFC
  signal headers on every action response (proxy/redirect/respond):
  `Deprecation: @<unix-seconds>` (the RFC 9745 structured-date form),
  `Sunset: <HTTP-date>` verbatim (RFC 8594), and the RFC 9745
  companion `Link: <uri>; rel="deprecation"` (appended beside upstream
  links; configured `Deprecation`/`Sunset` replace upstream values,
  unconfigured routes pass them through). Dates are validated as
  IMF-fixdate HTTP-dates (the only generator form; the grammar lives
  in `config::versioning` with no new dependencies), a `sunset` in the
  past or before `since` is rejected, and accept-selected routes gain
  `Vary: Accept` for cache correctness, folding with the CORS and
  compression Vary tokens. Path-segment versioning (`/v1/`, `/v2/`,
  rewrite) and exact header criteria (`X-API-Version`) were already
  expressible via DW-010 and are documented in the module docs rather
  than duplicated; same-path multi-version selection remains a
  documented v1 limitation (criteria misses 404 — no candidate
  fallthrough in the frozen router model). Headers are NOT stamped on
  gateway short-circuits (413/431, preflights, authn/authz/rate-limit
  rejections, sheds; the action-path HMAC digest 401 carries them);
  `config-reference.json` regenerated.

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
- SNI passthrough closed ClientHellos fragmented across TLS records as
  no-SNI; such hellos (larger than one 16 KiB record) are now
  reassembled, bounded at 64 KiB, and routed by their server name, with
  the original bytes replayed to the upstream unchanged.
- A panicked listener accept task killed its listener silently; accept
  loops are now respawned on the same bound socket up to 8 times per
  listener, after which the listener is given up on with an ERROR log
  while the process and other listeners keep serving.
- Rate-limiter per-key GCRA state was never evicted, so rules keyed by
  `ip` (or any high-cardinality selector) grew state for the process
  lifetime under key spray. Each window's keyed state is now a
  size-capped sharded store (16 shards of 4,096 keys — 65,536 per
  window at worst): keys idle past one full bucket refill are dropped
  first (indistinguishable from fresh state), and a shard full of
  fresh keys evicts its idlest half, resetting those keys' buckets —
  a fresh budget for the evicted keys, the fail-open trade for the
  memory bound (#122).
- A JWT provider without a configured `audience` rejected tokens that
  carry an `aud` claim (jsonwebtoken validates `aud` whenever present),
  contradicting the documented "absent: any audience accepted". The
  audience is now validated ONLY when configured: a provider without
  `audience` accepts tokens carrying any (or no) `aud` claim (#124).
- `dwara-cli diff` compared only entity name sets, so a route, upstream,
  or consumer kept under the same name but with changed content
  (endpoints, timeouts, ...) was reported as "no route/upstream/consumer
  differences". Same-name entities are now compared by per-entity
  content hash of the normalized serialization (source key order never
  surfaces as a change) and reported as `~ kind name` lines (#125).
- Paced-mode starve-sleep in `dwara-loadgen` re-anchored to its own
  clock: a starved worker slept `now + 50ms` and drifted off the
  dispenser's tick grid, occasionally landing just before a
  dispensation and paying a second slice of wait for the same permit.
  Both sides of pacing now share one epoch — the dispenser's interval
  and every starve-sleep land on the same 50 ms grid (#127).
- The bench workflow piped `cargo bench` through `tee` (and the baseline
  refresh through its writer script) without pipefail, so a failing
  `cargo bench` hid behind the pipeline's exit 0 and the regression gate
  compared (or the refresh committed) output truncated at the failure
  point; both pipelines now fail at the source (#127).
- Smooth-WRR `current_weight` was copied at rebuild, so a pick in flight
  against the old generation while a reload published a new one stranded
  its phase step (a one-off distribution glitch). The accumulator is now
  a shared cell carried across rebuilds exactly like the inflight
  counters, so WRR phase continuity survives reloads (#128).
- Duplicate-endpoint detection compared untrimmed address strings while
  the neighboring endpoint checks trim, so ` 127.0.0.1` and `127.0.0.1`
  passed validation as two endpoints against one shared balancer state
  (the identical spelling was already rejected). The duplicate target is
  now compared trimmed, like the empty-address check (#128).
- The admin API's accept loop had no panic supervision: a panicked
  accept task killed the admin listener silently for the rest of the
  process lifetime. The admin accept loop now runs under the same
  bounded supervision as the data-plane listeners — the supervisor is
  shared in `dwara-core`, respawns a panicked incarnation on the same
  bound socket up to 8 times, then gives up with an ERROR log while
  the gateway keeps serving (#130).
- A JWT provider that failed to build left Bearer tokens passing
  through UNVERIFIED (proxied 200 with no consumer identity; a
  misleading 401 on auth_required routes) because the empty-verifier
  branch treated "disabled" the same as "not configured". The two
  states now split: with no provider configured Bearer stays
  deliberate pass-through, but providers configured yet disabled fail
  closed — a presented Bearer token answers 500
  `authentication_unavailable` (reachable only via the
  validate-vs-build race; #121 rejects broken bundles at validation)
  (#131).
- The OTLP exporter client dropped a span batch permanently on any
  retryable collector answer (429/503) or transport failure — nothing
  behind it re-queues, so a briefly unavailable collector lost traces.
  The client now retries transient answers (429/502/503/504) and
  transport failures inside one export: up to three attempts with
  exponential backoff honoring a seconds-form `Retry-After`, every
  attempt sharing the export's one total deadline. The same change
  bounds request writes: a 64 KiB-chunked, deadline-rechecked write
  loop replaces single `write_all`s, so a peer making steady minimal
  TCP-window progress inside one write can no longer stretch the
  exchange past the deadline. Delivery is at-least-once — a retry
  after a lost response may duplicate spans (#133).

### Changed

- Legacy `sha256:<hex>` stored credentials are transparently re-hashed
  to the peppered `hmac-sha256:<hex>` format in place on successful
  verification when a pepper is configured — the transition completes
  lazily, without credential re-issue (#124).
- `PATCH /config` no longer double-bumps the generation: the file
  watcher's reload of identical content is a no-op.
- Gateway-generated responses use a uniform JSON error envelope
  (`{error:{code,message,request_id}}`).
- rustls is built with an explicit feature set (`aws-lc-rs`, `logging`,
  `std`, `tls12`; default features off), mirroring the tokio-rustls
  declaration. No binary-size win resulted: at 0.23.43 the ring
  provider was never in rustls's default features (ring enters via
  rcgen and jsonwebtoken), so the pin is supply-chain hygiene; the one
  behavioral delta is dropping rustls's `prefer-post-quantum` default,
  with interop unchanged.
- Paced mode in `dwara-loadgen` caps catch-up (#127): the permit
  dispenser's top-up is bounded by what workers have actually consumed
  plus one 50 ms slice, so a worker (or the whole rig) that falls
  behind can no longer discharge the accumulated permit backlog as one
  burst — bursts contaminate paced latency percentiles. The sustained
  schedule is unchanged.
- Release images are assembled from the size-bar-verified musl
  artifacts instead of recompiling both architectures (#127): the
  release workflow's images job downloads the checksummed tarballs,
  re-verifies the sha256s, and COPYs the binaries into
  `Dockerfile.release-{scratch,distroless}`, so published images are
  byte-for-byte the published tarball binaries (and the image build no
  longer needs QEMU emulation).
- The fuzz workflow builds on a dated nightly pin (`nightly-2026-08-25`,
  bump procedure documented in `fuzz.yml`) instead of a floating
  `nightly`, keeping the weekly fuzz matrix reproducible and immune to
  unrelated nightly regressions (#127).
- `InMemoryCache` (the in-tree `CacheStore` impl) is bounded instead of
  the previously documented-unbounded map: capacity 1024 entries by
  default (`InMemoryCache::with_capacity` for another bound; the count
  bounds entries, not bytes), evicting the least-recently-used entry
  past it with `get`/`set` refreshing recency. It still sits behind the
  trait seam, wired into no request path (#128).
- Zero-route configs are no longer published: an empty `routes` list
  fails validation unless the new additive top-level
  `allow_empty_routes: true` opt-in is set — at cold start (exit 1)
  and on reload or admin `PATCH /config` (rejected; the previous
  generation keeps serving). A truncated or torn config write is
  schema-valid and previously published an empty gateway, silently
  dropping all routing (#129).

### Security

- All GitHub Actions references pinned to full commit SHAs (first- and
  third-party) with weekly Dependabot updates keeping the pins fresh
  (DW-002 follow-up).
- TLS private keys are zeroized after loading: PEM file bodies and
  parsed key values (terminate listeners and the admin mTLS key) are
  wiped on drop via the `zeroize` crate instead of lingering in heap
  memory (DW-007 follow-up).
