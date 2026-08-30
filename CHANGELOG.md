# Changelog

All notable changes to dwara are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
the project follows semantic versioning once 1.0 is reached.

## [Unreleased]

### Added

- Enterprise licensing gate (DW-032): a `LicenseGate` runtime value
  that holds an optional verified license and gates enterprise features
  behind feature-claim flags. The gate is the edition boundary as a
  type boundary (per AGENTS.md): OSS builds (the default, no `ent`
  cargo feature) compile a stub gate that is always `none()` and never
  pull in the `licensing-core` dependency (BSL-1.1, allow-listed in
  `deny.toml`); enterprise builds (`cargo build --features ent`) link
  `licensing-core` and verify a license file at startup. The public key
  is NEVER in the YAML config — it comes from the
  `DWARA_LICENSE_PUBLIC_KEY` env var (or the compiled-in development
  key when unset), so an operator cannot substitute their own key to
  forge a license. The product ID is pinned to `"dwara"` so a license
  issued for another ShristiLabs product cannot be replayed. A
  configurable grace period (default 7 days, 0..=30) after expiry keeps
  enterprise features working while the operator renews; after the
  grace window the gate degrades to OSS gracefully (the done-when:
  "Invalid/expired license degrades to OSS feature set gracefully"). A
  new optional `gateway.license` config block carries the license file
  path and grace period; when the `ent` feature is not compiled in the
  block is accepted but inert. Startup behavior: no license = OSS mode
  (log); valid = enterprise mode (log customer/plan/features); expired
  within grace = enterprise mode with warning; expired past grace =
  degrade to OSS with warning; invalid signature or file not found =
  refuse to start (exit 1). A new `dwara_license_status` metric (gauge:
  0 = no license, 1 = valid, 2 = expired within grace, 3 = expired past
  grace) is exported on `/metrics`. The current enterprise features
  (DW-031 Redis rate limiter, DW-054 config convergence) are not yet
  implemented; the gate provides the check mechanism they will call.
  New `ent` cargo feature on dwara-core and dwara-bin (forwards to
  dwara-core/ent). New `chrono` workspace dependency (MIT OR
  Apache-2.0, already in the tree via jsonwebtoken) for license
  expiry/grace-period arithmetic.

- Distributed Redis rate limiter (DW-031): a `RedisRateLimiter` that
  implements the `RateLimiter` trait with the same GCRA algorithm as
  the local limiter, but stores per-key TAT (theoretical arrival time)
  state in Redis and updates it atomically via a Lua script in a
  single round-trip. Multiple gateway instances share one rate limit
  so the effective limit is not multiplied by the instance count.
  Activated only when the `ent` cargo feature is compiled in, the
  config carries a `gateway.redis_rate_limiter` block, and the loaded
  license grants the `redis_rate_limiter` feature claim; when any
  condition is missing the block is accepted but inert (the local
  in-memory GCRA limiter is used). Configurable fail-open (default
  true: Redis outage does not take down the gateway) or fail-closed
  (reject with 429) behavior when Redis is unreachable. Uses
  `redis::aio::ConnectionManager` (multiplexed, auto-reconnecting,
  Arc-based cheap clones) established once at startup. The
  `RateLimitEngine`'s `check` and `evaluate` methods are now async
  (the local limiter path is sync-in-async with no overhead). New
  `redis` workspace dependency (BSD-3-Clause, allow-listed in
  `deny.toml`, optional via `ent` feature) on dwara-core and dwara-bin.
  New `redis_rate_limiter` config block: `url`, `fail_open`,
  `key_prefix`, `connection_timeout_ms` (100..=30000), `key_ttl_s`
  (60..=86400).

- OAuth2 client-credentials proxying and mTLS consumer mapping (DW-035):
  the gateway can obtain an access token from an external OAuth2 token
  endpoint using the client-credentials grant (RFC 6749 section 4.4)
  and forward it to an upstream as `Authorization: Bearer <token>`,
  replacing any client-supplied `Authorization` header. Configured per
  upstream via `oauth2_client_credentials` (token endpoint URL,
  client_id, client_secret as inline or `${...}` reference, optional
  scopes, optional `token_cache_ttl_s` override, optional `mtls` block
  for RFC 8705 `tls_client_auth` to the token endpoint). Tokens are
  cached per upstream (keyed by token endpoint URL) with a TTL of
  `min(expires_in - 60s, token_cache_ttl_s)` clamped to 1s; refresh is
  lazy (on the first request after expiry, no background task);
  concurrent fetches coalesce into one token-endpoint POST (per-upstream
  fetch lock). The token cache persists across config reloads. A
  token-endpoint failure (network, non-2xx, malformed body) surfaces as
  502 `oauth2_token_unavailable` (never proxying unauthenticated; the
  error envelope never leaks the token endpoint's response). A new
  gateway-level `mtls_consumer_mapping` block maps verified client
  certificates to consumers by SHA-256 fingerprint (colon-separated hex)
  or subject CommonName, independent of the per-consumer `mtls`
  credential registry; when enabled with entries, an unmapped certificate
  is rejected 401 `mtls_consumer_not_mapped` (the mapping is
  authoritative, not falling through to the credential registry). A new
  `mtls_forward_headers` block adds `X-Client-Cert-{Fingerprint,
  Subject-CN, Issuer-CN, Not-After}` headers to the upstream request
  from the verified client certificate, with inbound spoofing prevention
  (any inbound headers with the configured prefix are stripped before
  the gateway injects its own; prefix is configurable, default
  `X-Client-Cert`). Certificate metadata extraction (subject CN, issuer
  CN, not-after, fingerprint) is hand-rolled DER walking with no X.509
  parser dependency. Zero new dependencies. New config structs:
  `OAuth2ClientCredentials`, `OAuth2Mtls`, `MtlsConsumerMapping`,
  `MtlsFingerprintMapping`, `MtlsForwardHeaders` (all
  `deny_unknown_fields`).

- Bounded admission queues and backpressure (DW-053): an optional
  `gateway.admission_queue` block makes the gateway concurrency cap
  degrade gracefully instead of the DW-016 cliff. When the cap is
  saturated and the queue is enabled, requests WAIT for a permit up to
  `queue_timeout_ms` (1..=10000) instead of being immediately shed —
  latency rises before shedding begins. The queue is bounded by
  `max_queue_size` (1..=10000); once full, further requests are shed
  immediately with 503 (the `queue_full` outcome). Per-priority
  splitting (`per_priority: true`, the default) reserves half the
  queue capacity for high-priority requests (>= 8) so they are not
  starved by a low-priority queue fill. Queue-timeout and queue-full
  sheds carry a `Retry-After` header (a small fixed value derived from
  the queue timeout). The queue is opt-in (`enabled: false` by
  default) and requires `max_concurrent_requests` (validation rejects
  an enabled queue on an uncapped gateway, the same rule as
  `load_shed_dry_run`). Dry-run interaction: `load_shed_dry_run: true`
  + `admission_queue.enabled: true` admits over the cap on would-shed
  (the queue timeout still fires, but no 503 is sent). Zero new
  dependencies (hand-rolled with tokio semaphore + timeout). New
  metrics: `dwara_admission_queued_total{outcome}` (admitted, timeout,
  queue_full) and `dwara_admission_queue_depth` (gauge).

- WAF-lite heuristic filtering (DW-051): per-route opt-in pattern
  matching for SQL injection, XSS, and path traversal signatures on
  the request path, query string, selected headers (User-Agent,
  Referer, Cookie, X-Forwarded-For), and body (JSON, form-urlencoded,
  or text/plain, up to `max_body_inspect_bytes`, default 128 KiB). A
  match returns 403 `waf_blocked`; dry-run mode (`dry_run: true`)
  evaluates and logs matches without blocking (the same DW-041
  monitor-mode pattern as route limits, authz, rate limits, and load
  shedding). Filter selection via `filters: [sqli, xss,
  path_traversal]` (default: all three); custom regex patterns via
  `custom_patterns`. The WAF runs after the route method allowlist and
  before the route limits — a content filter that rejects malicious
  requests before any resource is spent on auth or rate limiting, on
  the ORIGINAL request (before path rewrite / transforms). Body
  inspection buffers up to `max_body_inspect_bytes` (the one explicitly
  buffering piece the WAF introduces, bounded by the cap) and replays
  the buffered prefix plus the remaining stream to the rest of the
  request path. New metric: `dwara_waf_total{route,filter,outcome}`
  (blocked, logged, passed). Zero new dependencies (regex is already a
  dependency).

- Traffic splitting and sticky sessions (DW-040): a service can
  dispatch across several upstreams by a weighted split
  (`services[].split.targets`, 2..=8 targets naming existing
  upstreams, no duplicates, positive total at most 100000) instead of
  a single `upstream` — validation requires exactly one of the two.
  The pick is a stateless weighted hash (`hash % total_weight` over
  the same FNV-1a the balancer's consistent-hash ring uses): with no
  sticky cookie the key is the request id (per-request distribution
  whose ratios converge on the weights statistically), and a weight of
  0 parks a target (the blue-green side) without serving traffic. The
  blue-green switch is a republish that flips the weights — the pick
  is stateless, so the next request dispatches by the new generation,
  no restart, no drain. Displacement is bounded by an INVARIANT total:
  a same-total change (95/5 -> 90/10, or the 100/0 -> 0/100 flip)
  moves only the changed share; a total-changing bump reshuffles every
  session, so ramp a canary by re-balancing the pair, never by growing
  one side alone. An optional `services[].sticky` block
  (`cookie`: an RFC 6265 token name; `ttl_s` default 3600, 1..=2592000)
  pins a session to its branch: the gateway mints an opaque affinity
  handle (hex time + counter — not a secret, carrying no identity) as
  the cookie value on the FIRST response (before the pick, so the
  branch picked IS the cookie-pinned branch; `Set-Cookie` appended,
  never replacing upstream cookies, never re-set when presented) and
  the value consistently selects the same upstream. Stickiness is
  layered: the cookie guarantees BRANCH affinity, and when the branch
  upstream runs `ip_hash` the value becomes the ring key so the
  session pins one endpoint through the existing ketama machinery;
  with other balancers the endpoint floats (documented). One edge: a
  session whose first request is a response cache HIT mints no cookie
  until its first miss (no dispatch, nothing to pin while hits last).
  Zero new dependencies. New metrics:
  `dwara_split_picks_total{service,upstream}` (both labels
  config-declared — canary share is the upstream's share of the
  service) and `dwara_sticky_sessions_total` (affinity cookies set).

- gRPC and WebSocket polish (DW-039): gRPC over H2 now works
  end to end through the gateway with protocol semantics honored —
  the spec's `TE: trailers` request header is forwarded (previously
  stripped as hop-by-hop; still stripped for non-gRPC traffic), and
  `grpc-timeout` (1..=8 digits + H/M/S/m/u/n, case-exact; overflow
  saturates at a day; garbage ignored) is enforced as the RPC's TOTAL
  budget: each upstream attempt runs inside the remaining slice (a
  retry that cannot fit is cut, not started) and the response BODY
  carries the same absolute deadline (a server that answers headers
  then starves the stream is cut at the same instant); expiry answers
  504 with `grpc-status: 4` (DEADLINE_EXCEEDED) in the headers — the
  trailers-only shape — plus the JSON envelope for non-gRPC tooling.
  Response trailers (`grpc-status`/`grpc-message`) pass through
  untouched (body frames forward verbatim; pinned end to end against
  a TLS-h2 upstream). New `routes[].websocket` block makes the
  generic 101 tunnel managed for browser traffic: `origins` is an
  exact-match allowlist evaluated before ANY upstream contact (a
  non-empty list denies non-matches AND missing `Origin` — browsers
  always send one — with 403 `websocket_origin_denied`; absent/empty
  list = every origin, the transparent default) and
  `max_frames_per_sec` (1..=100000) polices the UPGRADED connection
  client-to-upstream: a token bucket (sustained rate, one-second
  burst) over DATA frames only (ping/pong/close free), closing an
  abusive client with close code 1008 and disconnecting. Policing is
  keyed off the UPSTREAM's actual 101 upgrade (a mixed-token request
  whose backend upgrades something else tunnels unpoliced — no WS
  frame is parsed into a non-WS stream) and is one-directional
  (protects upstreams, not clients). Zero new dependencies: the RFC
  6455 frame-boundary scanner reads 2..=14 header bytes (mask folded
  into the skip, no unmasking, no allocation on hostile input) and
  the 1008 close frame is four fixed bytes. New metric
  `dwara_websocket_policy_total{route,outcome}` with the closed set
  origin_denied/rate_closed.

- Real-time analytics stream (DW-121): an `analytics_stream` block
  streams every completed request's access record — one per request,
  not rollups, not the discrete DW-044 ops events; unrouted 404s
  included — to an external sink as ordered NDJSON batches: one JSON
  object per line (`application/x-ndjson`, redacted-by-construction
  fields: no query strings, no headers, no credentials; config-declared
  custom dimensions ride along), one POST per flushed batch
  (`batch_max` records default 512, a 2 MiB byte cap, or `flush_ms`
  default 1 s — whichever comes first). The one shipped sink is
  `type: webhook`, compiled through the SAME URL/`${...}`-header/retry
  grammar as alert webhooks and delivered by the same budget-bounded
  engine extracted for both (one total `timeout_ms` per batch shared
  by every retry attempt, exponential backoff, Retry-After honored,
  429/502/503/504 the retry set); a Kafka producer is the documented
  second sink slot, deferred by the lean-deps rule (the Parquet/DW-156
  precedent). Batches deliver strictly in order; the pipeline is
  fire-and-forget end to end (bounded `buffer` channel, default 8192,
  drop-and-count on full — a dead or slow collector degrades the
  stream's completeness counters, never gateway latency). Reloads are
  live: sink URL, cadence, batch bound, and enabled/disabled state are
  per-generation (the refresh arms the offer path only after the
  flusher has the new sink set, so arming loses nothing; a disable
  with a queued tail counts the tail as dropped — `offered ==
  delivered + failed + dropped` always holds). New metrics:
  `dwara_access_records_streamed_total{outcome}` (closed set
  delivered/failed/dropped), `dwara_access_records_offered_total`,
  `dwara_access_records_dropped_total` (scrape-time gauges; the offer
  path stays registry-free). Independent of the embedded analytics
  store — run either, both, or neither.

- Scheduled usage reports & exports (DW-120): an `analytics.exports`
  block (requires the DW-043 analytics store) turns the store into a
  scheduled reporter — a background worker (30 s tick, config read
  live each tick, so reloads add/remove exports without a restart)
  closes each UTC calendar window of the configured kind
  (`window: hourly|daily|monthly`, default daily) once it has settled
  (5 min after close, for writer flush + rollup grace) and writes the
  per-consumer usage statement — requests, errors, error rate,
  rate-limited/shed counts, average latency, plus DW-033 quota budget
  figures — as one deterministic file per format into
  `analytics.exports.directory` (created on demand; atomic
  temp+rename write; a re-export overwrites, so output is idempotent).
  `formats` is a duplicate-free subset of `csv`/`json` — omitted or
  empty means both (default both; Parquet deferred to the DW-156
  backlog). CSV is RFC
  4180 (CRLF, quoting rules; absent quota cells are EMPTY — zero means
  configured-and-zero-used); JSON is pretty and self-describing
  (window bounds, generated_at, partial flag, totals, per-consumer
  rows). The statement's numbers ARE the query API's numbers BY
  CONSTRUCTION (the export calls the same `structured` aggregation
  `POST /analytics/query` uses, grouped by consumer plus a totals row;
  pinned by test) — the acceptance contract of the issue. A restart
  backfills missed windows oldest-first (max 64/tick); the scheduler
  never auto-exports past the queried granularity's retention, and
  windows older than it are flagged `partial: true` (possible
  undercount, real data). Quota columns appear only when the budget's
  window FULLY CONTAINS the export window (daily export: same-day
  daily counter + month-to-date monthly; monthly export: monthly
  only) and are read by the dataplane from the state store's
  `quota_counters` — never fabricated zeros. New `export_runs` ledger
  (analytics schema v2, forward-only migration): one upserted row per
  (kind, window) with status ok/failed, partial flag, and counts.
  Admin endpoints: `GET /analytics/exports?limit=` (ledger, newest
  first, limit 1..=100 default 25) and `POST /analytics/exports/run`
  (manual trigger; optional `window`/`window_start_ms` default to the
  configured kind and most recent closed window; 400s on unconfigured
  exports, misspelled window, unaligned/not-closed window_start_ms).
  Two analytics query fixes found by the totals row: ungrouped totals
  over empty ranges are NULL-tolerant (zeros, not an error), and a
  literal `GROUP BY 1` on the ungrouped path (which resolved
  positionally to a SUM aggregate) was removed.

- Quotas and metering (DW-033): per-consumer request BUDGETS, a
  mechanism distinct from rate limiting — a rate limit replenishes
  inside seconds or minutes, a budget caps total volume across a fixed
  UTC calendar window and never replenishes mid-window; both apply when
  both are configured. Config: `consumers[].quotas` with
  `daily_requests` (midnight-to-midnight UTC) and/or `monthly_requests`
  (the UTC calendar month), each > 0, at least one present (validation
  rejects zero values and an explicit empty block). Enforcement uses
  the state store's `quota_counters` rows (the seam DW-018 shipped):
  counters are durable across restarts (a reopened store resumes at the
  exact cap), reloads apply live (budgets are read from the current
  generation, no engine to rebuild), and an over-budget request answers
  429 with `Retry-After` (whole seconds to the window boundary —
  month-scale for a monthly wall; when both budgets are exhausted the
  LATER wall is reported) plus the binding budget's
  `X-RateLimit-Limit`/`-Remaining`/`-Reset` (epoch seconds of the
  window boundary) — budget headers appear on denials only, so
  admitted responses' rate headers stay the rate limiter's. Evaluation
  is decide-and-reserve, stops at the first denial, and consumes
  NOTHING for a refused request (later budgets are peeked read-only to
  stretch `Retry-After` past an also-exhausted later wall — the DW-017
  max-wait rule without reservation; a request denied by the monthly
  budget has already spent its daily unit, the documented stacking
  trade). Failure model: without `DWARA_STATE_DB` the block is INERT
  (warned once per process, traffic passes — no counters to enforce);
  an unsynced consumer row fails open the same way; a store ERROR
  mid-check answers 500 (`quota_store_unavailable`), the authN
  "unavailable" posture. Usage is queryable four ways: `GET
  /quotas/usage` on the admin API (per-consumer current-window
  used/limit/remaining/reset, optional `?consumer=` filter; a consumer
  with no store row reports `synced: false` with no fabricated zeros),
  the `dwara_quota_denied_total{consumer,budget}` counter plus
  `dwara_quota_used`/`dwara_quota_limit` scrape-time gauges, the
  analytics store's per-consumer axis (a refused request completes with
  its consumer name and the rate-limited flag), and the new
  `quota_near_limit` webhook event (edge-triggered once per consumer,
  budget, and window at 80% of the cap; its `consumer` payload field is
  a config-declared label — the same trust class as `upstream` names —
  which refines the events payload contract, documented in
  `events/mod.rs`). Cost note: each request of a quota-configured
  consumer performs one or two synchronous SQLite writes on the single
  state-store connection (fsync per commit at the store's default
  `synchronous=FULL`) — the accepted OSS per-instance shape; a
  distributed shared-counter variant (fleet-wide consistency) is the
  Ent follow-up (DW-155).

- GeoIP ACL (DW-050): country/ASN authorization predicates backed by a
  MaxMind-format database. `gateway.geoip: {path}` names the .mmdb file
  (GeoLite2-Country, GeoLite2-ASN, or a combined DB — whichever
  subtrees it carries are the ones rules can use); any authorization
  block (gateway/listener/service/route/consumer) can carry
  `geoip: {allowed_countries, denied_countries, allowed_asns,
  denied_asns}` evaluated against the EFFECTIVE client IP (the same
  XFF-resolved address ip_acl uses). Semantics frozen: a denied match
  rejects (403); a non-empty allow list admits only matches; UNKNOWN
  addresses (private ranges, not-in-DB, no database loaded) match
  NEITHER side — deny-lists pass unknowns (geo blocking must not fail
  closed on infrastructure addresses), allow-lists reject them (an
  allow-list admitting unknowns would filter nothing). Country codes
  compare case-insensitively (ISO 3166-1 alpha-2, validated);
  `country` is preferred over `registered_country`. A geo-only
  authorization block ADMITS anonymous traffic (the ip_acl-only shape
  generalized), and geoip rules count as rules for the empty-block
  validator. Validation rejects geo rules without a `gateway.geoip`
  database. The database HOT-RELOADS: dwara-bin opens it at startup
  (fail loud, serve geo-UNKNOWN without it) and a watcher swaps the
  reader when the file changes — atomic ArcSwap; in-flight lookups
  keep the reader they loaded; no restart. New deps: maxminddb
  (Apache-2.0 OR MIT, allow-listed) and mmdb-writer (DEV-ONLY: tests
  generate their own .mmdb fixtures at runtime — no binary test data
  in the repo).

- Key rotation workflows (DW-046): dual-validity windows for API keys
  and JWKS, admin lifecycle endpoints, and a zero-failure rotation
  runbook. API keys: the state store gains `credentials.retire_at`
  (schema v5, additive) — SCHEDULED retirement, the far edge of the
  dual-validity window. Issue a new key, both keys authenticate
  simultaneously, retire the old one now or at a chosen instant;
  retirement is enforced lazily (SQL filter at lookup PLUS a
  registry-side time check so a CACHED row expires exactly on time
  with no background sweeper), can only move EARLIER (a scheduled stop
  cannot be postponed — issue a new credential instead), and is
  distinct from revocation in the row's record. New admin endpoints on
  the mTLS listener: GET /consumers/{name}/credentials (lifecycle
  stamps only — selector/hash material never leaves the store module),
  POST /consumers/{name}/credentials (issue an api key hashed with the
  dataplane's own pepper state — 16..=512-byte keys enforced), and
  POST /credentials/{id}/retire (empty body = immediate;
  {"at_ms"} = scheduled). All 404 with a named envelope without a
  DWARA_STATE_DB deployment. JWKS: `retired_key_grace_secs` per JWT
  provider (default 86400 = 24 h, 0 disables, capped at 7 days) — when
  a successful JWKS fetch delivers a set whose kids CHANGED, the
  superseded set is retained and tokens carrying a kid the fresh set
  dropped keep verifying through the grace (the rotation race:
  issuers remove the old key while previously-issued tokens still use
  it); an identical-kid re-fetch does not re-stamp the grace. The
  retired-set consult happens BEFORE the forced-refresh throttle (a
  dropped kid needs no fetch). Two behavior pins updated to the new
  frozen semantics (retired kids now verify within the grace by
  default; the grace-0 immediate-cutoff shape is pinned separately).

- SLO & error-budget export (DW-052): routes can declare service-level
  objectives (`routes[].slo`: `availability` percentage, optional
  `latency_ms` threshold + `latency_target` percentage, validated),
  exported as `dwara_slo_burn_rate{route,objective,window}` and
  `dwara_slo_target{route,objective}` metrics for multiwindow
  burn-rate alerting. Burn rate is the standard error-budget
  consumption signal: the bad-request fraction over a process-local
  sliding window (5m and 1h, 15-second buckets) divided by the allowed
  fraction — 1.0 consumes the budget at exactly the allowed rate, 14.4
  over 1h is the classic fast-burn page. Availability counts a request
  bad only when the GATEWAY answers 5xx (client errors are the
  caller's policy); latency counts bad when the end-to-end duration
  exceeds the threshold. Values are computed from windowed counters by
  a custom Prometheus COLLECTOR at scrape time — always fresh, never a
  stale sampled gauge, no background task — with empty windows
  reporting 0.0 (never NaN, which would break alerting comparisons)
  and unconfigured features exporting no series at all (empty families
  are dropped: the text encoder would panic on them). Routes whose
  `slo` block disappears on reload lose their series. The starter
  Grafana dashboard gains an "SLO burn rate by route and objective"
  panel with the 6x/14.4x alert thresholds drawn.

- Embedded analytics store (DW-043): an optional `analytics` block on
  the gateway config opens a SEPARATE SQLite database (never the state
  store's file) that records every completed request and answers
  traffic-history queries from the mTLS admin API. The write path is
  fire-and-forget by construction: the request-completion seam hands
  the redacted access record to a bounded channel (`try_send`; a full
  channel DROPS and counts — analytics can never slow or block the
  dataplane), and a background writer batches raw rows in
  transactions, then a maintenance worker rolls them through a fixed
  cascade — raw → 1m → 5m → 1h → 1d — where every stage aggregates
  the previous stage's COMPLETED windows (a 60 s grace absorbs writer
  lag), each granularity keeps a cursor advanced in the same
  transaction as the rows it covers (a crash never double-counts),
  and every aggregation is a wholesale window RECOMPUTE, so re-running
  any range — after a crash, a restored backup, or a cursor reset —
  reproduces identical rows. Rollup rows are fully additive (request/
  error/rate-limit/shed counters, duration sum/max, and a 13-bucket
  latency histogram whose bounds are fixed, so any set of windows
  merges by summation and percentiles estimate without per-request
  samples). Retention is per-granularity (defaults: raw 24 h, 1m 48 h,
  5m 7 d, 1h 30 d, 1d 365 d; validated monotone and capped) with
  incremental vacuum returning pages to the filesystem — bounded disk
  is the point. The read side serves three admin endpoints:
  `GET /analytics/dashboard` (per-window requests, error rate,
  p50/p95/p99, rate-limit and shed counts, with drill-down group_by
  and equality filters), `GET /analytics/top` (the five frozen
  reports: top consumers, top routes, slowest, most error-prone,
  rate-limit offenders), and `POST /analytics/query` — a structured
  query over a CLOSED grammar translated to parameterized SQL (six
  groupable dimension columns; never SQL text from the caller).
  Custom dimensions (`analytics.dimensions[]`) tag requests from
  configured request headers (e.g. `x-plan` as dimension `plan`) at
  completion-time capture — analytics-only, deliberately never added
  to the redacted access log — and aggregate into their own rollup
  table. The store implements the M1 `extensions::analytics`
  `AnalyticsSink` contract (extended additively with the per-request
  fields), making it the OSS implementation of the seam the federated
  analytics (DW-095) and raw-record firehose (DW-121) pipelines will
  share. All endpoints 404 with a named envelope when no store is
  configured; the database open failure is loud but non-fatal (serve
  without analytics).
- Protocol hardening pass 2 (DW-030), three features. **PROXY protocol
  acceptance** (`listeners[].proxy_protocol`, opt-in, default false):
  a listener behind an L4 load balancer reads a PROXY protocol v1 or
  v2 header as the first bytes of every connection — before the TLS
  handshake in terminate mode — and the header's source address
  replaces the accepted socket peer everywhere it is consumed (authz
  IP ACL base, rate-limit keying, `X-Forwarded-For`/`X-Real-IP`).
  The spoofing boundary is the config: a listener without the flag
  never interprets first bytes as a PROXY line. A malformed header
  (bad signature, bad lengths, Unix family, datagram protocol,
  over-ceiling) is answered with a 400 error envelope and closed —
  never handed to HTTP parsing; a stalled or dropped header read
  closes silently, bounded by the slowloris header timeout. A v2
  `LOCAL` command, a v1 `UNKNOWN` line, and AF_UNSPEC keep the real
  peer (the specification's fallbacks). Parsing is delegated to the
  `ppp` crate (Apache-2.0); the framing read, bounds (107 B v1 /
  16+65535 B v2), and fail-closed policy live in dwara-core. The
  flag is part of the restart-only bind set and cannot combine with
  `tls.mode passthrough` (validation rejects it). **Per-route method
  allowlist** (`routes[].methods`): when non-empty, a request that
  resolved the route with a method outside the list is answered
  `405` with an `Allow` header echoing the configured methods
  verbatim (RFC 9110 10.2.1). Placement mirrors the maintenance 503:
  after route resolution, before route limits and authentication;
  a CORS preflight is exempt (the preflight asks about the gateway's
  cross-origin policy, not the resource — failing it would hide the
  CORS answer from the browser), and the 405 itself is
  CORS-decorated and security-stamped. Matching is case-insensitive;
  HEAD is not implicitly granted by GET; entries are validated as
  HTTP method tokens without case-insensitive duplicates. **Happy
  eyeballs dialing** (`upstreams[].timeouts.happy_eyeballs_ms`,
  default 250, `0` disables racing, bounded to 10 minutes): dials
  race across a multi-address resolution per RFC 8305 — first
  address immediately, each subsequent address one delay after the
  previous start, address families alternating after the resolver's
  first, failure fast-forward when nothing is in flight, first
  success cancels the losers. The upstream's `connect_ms` still
  bounds the whole dial (resolution, every interleaved attempt, and
  the TLS handshake), and exactly one outcome per dial reaches
  breaker and passive-health accounting — a losing arm is never
  counted as an endpoint failure. Active health probes dial with
  the same discipline. IP-literal IPv6 authorities are handled
  correctly (`[::1]` brackets stripped before resolution and SNI).
- Request coalescing for cache misses (DW-038): an optional
  `coalescing` block on a route's `cache` policy collapses concurrent
  identical cacheable GETs into one upstream call — the first miss
  leads while followers wait (bounded by `wait_ms`, default 5 s,
  validated) and replay the leader's stored answer exactly like a
  cache hit. The coalescing key is the full cache key (route epoch,
  consumer, path, query, vary), so followers can only receive an
  outcome computed for an identical request of their own consumer;
  every failure mode fails open to an independent fetch (unstorable
  leader outcome, mid-flight purge/config change, wait expiry, leader
  map saturation at 256 keys) — a client is never errored because
  coalescing gave up, and a leader's failure is never inherited. New
  closed-set `dwara_coalescing_*` metric families report leaders,
  follower outcomes, upstream calls saved, and parked waiters.
- Route-scoped response caching (DW-037): a local cache behind the
  `CacheStore` extension seam (moka-backed, byte-weighed, per-entry
  TTL) with per-consumer keys folding the effective vary set
  (configured + `Accept`/`Origin` policy folds), TTL freshness,
  stale-while-revalidate with bounded single-flight background
  revalidation, ETag/If-None-Match 304 semantics, `x-cache` hit/stale/
  miss/bypass/revalidated stamps, closed-label metrics, an O(1)
  epoch-based purge endpoint on the admin API (<100 ms at any store
  size), and automatic invalidation on any config change to a route.
  Stored bodies are the post-masking/post-transform identity bytes;
  the decoration tail re-runs on every replay.
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
- Alert and event webhooks (DW-044): `gateway.webhooks` POSTs gateway
  state changes to operator-configured HTTP endpoints as one stable
  JSON envelope (`id`, `kind`, RFC 3339 `timestamp`, `gateway`
  instance id, `payload` of bounded labels/numbers only). Emitted
  events: circuit-breaker transitions (`breaker_opened` with the rule
  that tripped, `breaker_half_open`, `breaker_closed`), endpoint
  ejection and recovery (`endpoint_ejected`, `endpoint_recovered`),
  and config lifecycle (`config_published` with generation/hash/routes,
  `config_rejected` with the validation issue count — every publish
  path, startup/reload/admin, emits). Emission rides a bounded
  in-process event bus (new `events` domain, below `snapshot` so the
  publish pipeline and the resilience state machines share one queue):
  a full queue drops and counts (`dwara_events_dropped_total`), never
  blocks the dataplane. Delivery runs on a background task with
  bounded-concurrency per-delivery tasks, retries for transport
  failures and 429/502/503/504 (honoring seconds-form `Retry-After`),
  exponential backoff, and ONE total `timeout_ms` budget per delivery
  shared by every attempt — a slow, hung, or dead target can never
  affect the gateway. Outcomes land in
  `dwara_webhook_events_total{kind,outcome}` (delivered/failed/dropped;
  both labels closed sets). Webhook header values accept `${...}`
  secret references (DW-045 grammar, resolved at config-compile time)
  and inline values are redacted in config echoes; validation checks
  URL shape, known event kinds (quota events arrive with quotas,
  DW-033), header legality, duplicate URLs, and retry-knob bounds.
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

- Request/response transforms and security headers (DW-028): a
  per-route `transforms` block (`request.headers` / `request.query` /
  `request.body` / `response.headers` / `response.body`) and a sibling
  `security_headers` block. Header ops (`set`, `add`, `remove`,
  `rename`) apply in one frozen order — set, add, rename, remove —
  with BTreeMap iteration keeping multi-entry application
  deterministic; request-side ops run on the forward path after the
  DW-010 path rewrite, hop-by-hop stripping, and the trusted-header
  injection (ops see — and may shape — the near-final forwarded
  request, including removing `X-Consumer-*`/`X-Forwarded-*`: the
  operator owns the upstream's contract); query ops carry untouched
  pairs VERBATIM (no decode/re-encode round trip — a client's exact
  percent-encoding survives) and percent-encode only the pairs a named
  op touches; framing and hop-by-hop header names are REJECTED by
  validation in both directions (request smuggling and
  body-corruption guards; `host` additionally request-side,
  `content-encoding` response-side — the compression pipeline owns
  it). The JSON body transform (`body.json`, RFC 6901 pointers, `set`
  any value / `remove`) is the transforms surface's ONE explicitly
  buffering piece, preserving the streaming dataplane elsewhere: it
  applies only to JSON-typed bodies (`application/json` and
  `application/*+json`, parameters ignored), enforces a hard
  `max_bytes` cap against both a declared `Content-Length` and the
  live stream, rewrites the forwarded `Content-Length` to the
  transformed length, runs BEFORE retry buffering so retries replay
  the transformed bytes, and reads THROUGH the route-limit and
  HMAC-digest wrappers (enforcement stays on the client's original
  bytes; policy shapes what the upstream receives). It fails CLOSED:
  over-cap 413 (request) / 502 (response), unparseable JSON 400 /
  502, and an unresolved pointer 400 / 502 — a silent skip would be
  fail-open in exactly the masking direction DW-029 builds on this
  machinery; non-JSON, already-encoded, and empty bodies pass
  through untouched (SSE and streamed downloads keep streaming).
  Pointers parse once at snapshot compile into the route table (the
  same lockstep precompute contract as the CORS/compression/
  deprecation tables); header/query ops carry no grammar and
  deliberately have no compiled form. Response-side transforms run in
  the decoration tail BEFORE compression (the codec encodes the
  transformed bytes and eligibility sees the final content type) and
  apply to action responses only, like deprecation stamps.
  `security_headers` injects HSTS (`max-age` + optional
  `includeSubDomains`/`preload`, composition validated), `X-Content-Type-Options:
  nosniff`, `Content-Security-Policy`, and `X-Frame-Options`
  (`deny`/`sameorigin`; obsolete `ALLOW-FROM` deliberately absent) on
  EVERY route-matched response — action responses AND gateway
  short-circuits (401/403/413/429/503, CORS preflights: a browser
  parsing an error page deserves the same edge guarantees, the
  deliberate asymmetry with deprecation stamps — but not the pre-route
  framing 400 or unrouted 404s, which have no route to consult) —
  REPLACING any upstream-sent values (the gateway is the source of
  truth at its edge, the deprecation/rate-header rule); it stamps last
  in the tail, after operator transforms, so the edge policy has the
  final word. Zero new dependencies (hand-rolled RFC 6901 grammar in
  `config::transforms`); `config-reference.json` regenerated.
- Response field masking (DW-029): a per-route `masking` block
  (`max_bytes`, `fields`, `groups`) that redacts RFC 6901 pointers
  from the route's PROXIED responses — replaced with the FIXED
  sentinel `"***"` (a JSON string; not configurable, so clients and
  audit tooling can rely on the exact shape — a literal `"***"` in
  source data is documented as indistinguishable) — before any other
  body-handling stage runs. The effective pointer set is the UNION of
  `fields` (the floor, every consumer on the route) and every `groups`
  entry the authenticated consumer belongs to, deduplicated: groups
  only ADD pointers, and there is deliberately no mechanism by which a
  group is exempted from the floor (an exemption would be an
  allow-anywhere escape hatch on a redaction policy, the
  deny-anywhere-wins analog). Every DW-028 body-transform
  pass-through gate is INVERTED into a fail-closed 502: a
  content-encoded body (the gateway does not decode, and cannot prove
  fields absent from bytes it cannot read — the flagged DW-028 review
  surface), a non-JSON content type, a declared or streamed length
  over `max_bytes`, JSON that does not parse, and a configured pointer
  that does not resolve (schema drift — a silent miss IS the leak)
  each answer a generic `response_mask_failed` 502 envelope, with the
  refusal class named server-side only; bodiless statuses (1xx/101/
  204/304) and empty bodies pass (nothing to leak), and
  gateway-authored `respond`/`redirect` bodies never face the gates
  (operator config bytes, no upstream data). Masking runs FIRST in the
  response decoration tail — before the DW-028 body/header transforms
  and before DW-027 compression — so no later stage can resurrect a
  redacted value, while the gateway's OWN compression (which runs
  later) never trips the encoding gate; only upstream-pre-encoded
  responses are refused. `Content-Length` is rewritten to the masked
  length; upstream trailers are dropped when buffering. Audit trail:
  one `dwara::policy` info event per masked response
  (`response_masked`: route, consumer, distinct-pointer count,
  request-id) and one warn per refusal (`response_mask_failed`: the
  refusal class) — labels and counts only, masked VALUES never appear
  in events. Validation is fail-closed at publish: the block must mask
  something, `max_bytes > 0`, every pointer parses as RFC 6901 and is
  not the root, group entries non-empty, and every group name must
  match some configured consumer's groups membership (a typo'd name
  silently never masks — fail-open — with the same store-managed-
  consumers caveat as authorization group rules). Pointers parse once
  at snapshot compile into the route table (`CompiledMasking`; the
  per-request group union resolves at apply time); zero new
  dependencies; `config-reference.json` regenerated; new
  `docs/features/masking.md` and docs-site `guide/masking.md`.

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
- Maintenance mode and policy dry-run (DW-041): a per-route
  `maintenance` block (optional `retry_after_secs`, default 60, and
  `message`) makes the gateway answer every matched request with
  `503` + `Retry-After` + the `maintenance` JSON envelope — checked
  immediately after route resolution, BEFORE the route's request
  limits (maintenance is a statement about the route's availability,
  not the request's shape, so an over-limit request is told "we're
  down" rather than handed a 431 it cannot fix) and before every
  action (redirect/respond never run; the upstream is never
  contacted). CORS preflights are the one exemption — they keep their
  204 (the Fetch handshake is about the gateway's cross-origin
  policy; failing it would surface in browsers as an opaque CORS
  error and hide the 503), while the actual request's 503 carries the
  policy's CORS actual-response headers so browser clients can read
  the envelope. Reserved paths answer before routing and stay live
  through maintenance; unrouted traffic still 404s. Toggled by
  ordinary config reload (file watch/SIGHUP/admin PATCH publish).
  Validation rejects `retry_after_secs: 0` (a retry stampede against
  a route just taken down) and an empty `message`. Alongside it,
  monitor-mode `dry_run` flags on every policy phase that can reject:
  `routes[].limits.dry_run` (413/431; the streaming body guard stays
  unarmed — only the up-front checks are observable), a `dry_run` on
  any of the five `authorization` attachment levels (401/403), a
  `dry_run` on a named rate-limit policy bundle (429 — the bundle
  still evaluates, its GCRA buckets advance exactly as if enforcing,
  and it contributes no `X-RateLimit-*` headers), and
  `gateway.load_shed_dry_run` (the concurrency cap's 503; a would-shed
  is admitted over the cap — the documented trade of previewing a
  cap). A dry attachment evaluates, logs one structured
  `dwara::policy` warn event (phase, would-be status, reason, route,
  consumer, request id), increments the new
  `dwara_policy_dry_run_total{phase,route}` counter, and lets the
  request proceed; the invariant throughout is that dry run never
  makes enforcement more permissive — the authz resolver walks past a
  dry deny and stops only at a live one, and live rate-limit bundles
  429 regardless of dry siblings on the same request. The metric and
  the log events ARE the dry-run report (no endpoint; scrape and
  grep). Unrouted traffic reports dry global/listener policies under
  the `unrouted` route label. `config-reference.json` regenerated.
