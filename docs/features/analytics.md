# Embedded analytics

Source: `crates/dwara-core/src/analytics/` (DW-043). Tests:
`analytics` (dwara-core, end-to-end record path),
`tests/unit/analytics_store.rs` (schema, math, cascade, retention,
queries), `admin_api` analytics cases (dwara-admin). Served by the
admin API's `/analytics/*` endpoints.

Observability answers "is it healthy right now"; analytics answers
"what happened over time, to whom, and why". This page is the
implementation-focused version: the write path and why it can never
slow a request, the rollup cascade and why it is crash-idempotent, the
bounded-disk story, and the query surface. The operator-facing knob
reference lives in
[docs-site: Analytics](../../docs-site/guide/analytics.md).

## The write path (never blocks the dataplane)

The request-completion seam (`dataplane::proxy::handle`, right where
the Prometheus families and the sampled access log record) offers the
redacted `AccessRecord` to the store: a `try_send` onto a bounded
channel (capacity 4096). The call NEVER blocks and NEVER fails the
request — a full channel drops the record and counts it
(`analytics_channel_full` logs throttled; `dropped_records()` is the
honest counter). A background writer drains the channel in batched
transactions (flush tick `analytics.flush_ms`, default 1 s, or 1024
records). On shutdown the writer drains what is queued, takes a final
flush and a final rollup/retention pass, and stops — a clean restart
loses nothing.

Custom dimensions (`analytics.dimensions[]`: name + source) are
captured at three points in the request path, and the list is read
from the CURRENT generation (reload adds/renames dimensions live).
They are analytics-only — the access log's redacted field list stays
exactly what it was.

- **Header** (`source: header`, the default when `source` is absent):
  read from the request header named by the `header` field, while the
  request head is still in hand. First value of a repeated header
  wins; non-UTF-8 and over-128-byte values are skipped. This is the
  original DW-043 shape.
- **Claim** (`source: claim`, DW-093): read from the verified JWT's
  claims map (the `claim` field names the claim). Only string- and
  number-valued top-level claims are available (the same subset authn
  exposes); absent claims and over-128-byte values are skipped.
  Extracted after authn resolves Identity.
- **Body path** (`source: body_path`, DW-093): read from the request
  body via an RFC 6901 JSON pointer (the `body_path` field). Only
  works when the body is buffered (retries, hedging, request
  transforms, or request validation); the zero-buffering default
  skips body-path dimensions silently — the gateway never buffers just
  for analytics. The body must be valid JSON; non-JSON bodies and
  unresolved pointers are skipped. Extracted after the body is
  collected for replay.

A **correlation ID** (DW-093) is resolved per request from the
`X-Correlation-Id` header (falling back to the request ID) and stored
on the raw record. The response echoes it as `X-Correlation-Id`. The
`raw` table's `correlation_id` column (indexed) drives the
journey/funnel query.

## Storage: a separate SQLite file, additive rollups

The analytics database is a SEPARATE file from the state store's:
different lifecycle (retention deletes vs identity upserts), different
write pattern (high-churn batched appends), and an independent
bounded-disk story. It owns its own `user_version` namespace, so the
state store's forward-only migration contract is untouched.

Four tables:

- `raw` — one row per completed request (the `AccessRecord` field set
  plus a JSON column of custom dimensions). Short retention (default
  24 h): raw seeds rollups and answers custom-dimension ad hoc
  queries; the durable history is the rollups.
- `rollup_fixed` — pre-aggregated counters per (granularity, window,
  fixed dimension tuple: listener/route/upstream/consumer/method/
  status_class). Latency is a 13-bucket histogram (fixed inclusive
  bounds 1 ms…5 s + overflow) stored as NON-cumulative counts, so any
  set of windows merges by summation and percentiles are estimated
  without per-request samples.
- `rollup_dim` — the custom-dimension twin, one row per (granularity,
  window, dimension name, value); aggregated in Rust because the
  source is a JSON column (no JSON1 build-flag dependency).
- `meta` — the rollup cursors.

## The cascade (crash-idempotent by construction)

raw → 1m → 5m → 1h → 1d, each stage aggregating the PREVIOUS stage's
completed windows (never raw twice):

- A window is COMPLETE once its end plus a 60 s grace is in the past —
  the grace absorbs writer lag, so a straggler still lands in its own
  window. Records later than the grace are documented rollup-lost
  (they remain in `raw` until raw retention expires).
- Each granularity keeps a CURSOR (exclusive frontier) advanced in the
  SAME transaction as the rows it covers: a crash mid-cascade never
  double-counts.
- Every aggregation is a wholesale window RECOMPUTE (`INSERT OR
  REPLACE` over the window's full source range): re-running any range
  — crash, restored backup, reset cursor — reproduces identical rows.
  Idempotence comes from determinism, not from merge arithmetic.

## Retention (bounded disk)

Per-granularity retention (defaults raw 24 h, 1m 48 h, 5m 7 d, 1h 30 d,
1d 365 d) swept by the same maintenance worker; validation enforces
each floor, monotonicity (no coarser table expires before the finer
table it cascades from), and caps. `auto_vacuum = INCREMENTAL` plus a
bounded `incremental_vacuum` per sweep returns pages to the filesystem
without ever blocking the writer with a full VACUUM.

## The query surface (closed grammar, parameterized SQL)

Five admin endpoints, all 404 with a named envelope when no store is
configured:

- `GET /analytics/dashboard?from_ms&to_ms&gran&group_by&<filters>` —
  per-window series (requests, errors, error rate, rate-limited, shed,
  avg, p50/p95/p99) with drill-down by one dimension and equality
  filters.
- `GET /analytics/top?kind&from_ms&to_ms&n` — the five frozen reports:
  consumers, routes, slowest, error_prone, rate_limited.
- `POST /analytics/query` — a structured query over a closed grammar:
  `group_by` accepts exactly the six dimension columns, values bind as
  SQL parameters, and SQL TEXT from the caller is never executed.
- `POST /analytics/dimensions` (DW-093) — a custom-dimension query
  over the `rollup_dim` table: aggregate per (window, dimension name,
  value) at a granularity, filtered by dimension name and optional
  value. Closed JSON grammar; SQL TEXT from the caller is never
  executed.
- `GET /analytics/journey?correlation_id&from_ms&to_ms` (DW-093) —
  the journey/funnel query: all raw records matching a correlation
  ID, ordered by time ascending. The `correlation_id` index keeps the
  scan bounded; optional `from_ms`/`to_ms` narrow the window.

The scheduled usage-report exports (DW-120) build their per-consumer
statement by calling this same `structured` aggregation — see
[Usage reports and exports](./usage-reports.md).

## The seam

The store implements the M1 `extensions::analytics::AnalyticsSink`
contract (extended additively with the per-request fields DW-043
needed). That trait is the OSS/Ent seam: the federated analytics
pipeline (DW-095) and the raw-record firehose (DW-121) are future
sibling implementations of the same contract.
