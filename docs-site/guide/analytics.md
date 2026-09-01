# Analytics

Observability answers *"is it healthy right now"* (see
[Operations](./operations)); analytics answers *"what happened over
time, to whom, and why"*. The embedded analytics store gives
a single-instance gateway a durable, queryable traffic history with
zero external dependencies and bounded disk usage.

## When to use this

The embedded analytics store gives a single-instance gateway a durable,
queryable traffic history with zero external dependencies — useful for
usage reporting, billing, and post-incident review. For multi-instance
fleets or warehouses that want the raw firehose, use the
[analytics stream](./analytics-stream) instead.

## Enabling

Add an `analytics` block to the gateway config and restart (the
database opens at startup, like the listener bind set):

```yaml
analytics:
  path: /var/lib/dwara/analytics.db
  flush_ms: 1000              # optional, default 1s, 100..=60000
  retention:                  # optional; defaults shown
    raw_ms: 86400000          # raw records: 24h
    m1_ms: 172800000          # 1-minute rollups: 48h
    m5_ms: 604800000          # 5-minute rollups: 7d
    h1_ms: 2592000000         # 1-hour rollups: 30d
    d1_ms: 31536000000        # 1-day rollups: 365d
  dimensions:                 # optional custom dimensions
    - name: plan
      header: x-plan
```

The database is a separate [SQLite](https://en.wikipedia.org/wiki/SQLite) file (an embedded SQL database stored as a single file) from the state store
(`DWARA_STATE_DB`) on purpose: retention deletes and vacuum churn
never touch the identity store. Without the block, the gateway runs
exactly as before — the admin analytics endpoints answer 404, and
request recording is a no-op.

Every completed request is recorded fire-and-forget: the gateway never
waits on analytics (a saturated analytics pipeline drops and counts
records rather than adding so much as a lock to the request path).

## Custom dimensions

`dimensions[]` tags requests with values from request headers —
`x-plan: pro` becomes the analytics dimension `plan=pro` — which then
group and aggregate like the built-in dimensions (listener, route,
upstream, consumer, method, status class). The first value of a
repeated header wins; non-UTF-8 and over-128-byte values are skipped.
Dimensions never appear in the access log.

## The rollup model

Raw records live briefly (default 24 h) and feed a fixed cascade of
pre-aggregated rollups (pre-aggregated summaries at fixed time granularities) — 1 minute, 5 minutes, 1 hour, 1 day — each
holding request/error/rate-limit/shed counts, duration sum/max, and a
13-bucket latency histogram (counts observations into buckets for percentile estimation) per dimension tuple. Because every stored
number is additive, any time range at any granularity merges exactly,
and [percentiles](https://en.wikipedia.org/wiki/Percentile) (e.g. p95 = the latency 95% of requests are under) are estimated from the merged histogram. Retention is
enforced per granularity with incremental vacuum (SQLite's space-reclaim operation), so disk usage is
bounded by configuration, not by traffic.

## Querying

All endpoints live on the [admin API](./admin-api) (mTLS; the dev
fallback works too) and answer 404 when analytics is not configured.

**Dashboard series** — per-window metrics with drill-down and filters:

```
GET /analytics/dashboard?from_ms=1690000000000&to_ms=1690086400000&gran=2
    &group_by=consumer&route=checkout
```

`gran` is 0..=3 (1m/5m/1h/1d); `group_by` and the equality filters
(`listener`, `route`, `upstream`, `consumer`, `method`,
`status_class`) are optional. Each point carries `requests`, `errors`,
`error_rate`, `rate_limited`, `shed`, `avg_ms`, `p50_ms`, `p95_ms`,
`p99_ms`.

**Top-N reports** — the five built-in rankings:

```
GET /analytics/top?kind=slowest&from_ms=...&to_ms=...&n=10
```

`kind` is one of `consumers`, `routes`, `slowest`, `error_prone`,
`rate_limited`.

**Structured query** — a closed JSON grammar translated to
[parameterized SQL](https://en.wikipedia.org/wiki/Prepared_statement) (SQL with placeholders, never string-interpolated — injection-safe) (SQL text is never accepted):

```json
POST /analytics/query
{
  "from_ms": 1690000000000,
  "to_ms": 1690086400000,
  "gran": 1,
  "group_by": ["consumer", "status_class"],
  "filters": { "route": "checkout" },
  "limit": 100
}
```

`group_by` accepts exactly the six dimension columns. A week of
traffic answers in well under 100 ms — the query reads rollup tables,
never raw records.

## Usage reports and exports

An `exports` block inside `analytics` turns the store into a scheduled
reporter: once per configured window the gateway writes a per-consumer
usage statement — requests, errors, error rate, rate-limited and shed
counts, average latency, and quota budget figures — as one
deterministic file per format. Durable input for a billing pipeline,
distinct from the ad hoc query API. The quota figures come from
consumer budgets (see [Consumer quotas](./quotas)); live per-window
counters are also readable via `GET /quotas/usage` on the
[admin API](./admin-api).

```yaml
analytics:
  path: /var/lib/dwara/analytics.db
  exports:
    directory: /var/lib/dwara/usage-reports
    window: daily            # hourly | daily | monthly; default daily (UTC)
    formats: [csv, json]     # default both
```

The directory is created on demand. Files are named
`dwara-usage-{window}-{utc-stamp}.{ext}` — for example
`dwara-usage-daily-2026-08-29.json` — and a re-export of the same
window simply overwrites the file, so output is idempotent and safe to
re-run. A background worker checks every 30 seconds and exports each
closed window about 5 minutes after it closes (so rollups settle);
after a restart it backfills missed windows oldest-first. Reloads
apply live. Validation rejects an empty directory and duplicated
formats — an omitted or empty format list simply means both; [Parquet](https://en.wikipedia.org/wiki/Apache_Parquet) (a columnar storage format for analytics)
is not offered yet.

The statement's numbers are the query API's numbers: the export runs
the same aggregation as `POST /analytics/query` (grouped by consumer,
plus a totals row), so a statement always reconciles with an ad hoc
query for the same period.

Quota columns follow a strict alignment rule: a budget's
used/limit figures appear only when its quota window fully contains
the export window — a daily report carries the same-day daily counter
plus the month-to-date monthly counter, a monthly report carries only
the monthly counter. Monthly figures are month-to-date as of
generation time (the store's live counter, so a re-exported window can
differ from the original run); each budget's `window_start_epoch_s`
and `reset_epoch_s` bound what `used` covers. Empty cells mean "no
applicable budget", never zero.

Two [admin API](./admin-api) endpoints (they answer 404 when analytics
is not configured):

```
GET /analytics/exports?limit=25
POST /analytics/exports/run   {"window": "daily", "window_start_ms": 1770000000000}
```

`GET /analytics/exports` returns the run ledger, newest first
(`limit` 1..=100, default 25): one record per exported window with
status (`ok`/`failed`), the `partial` flag, formats, and
consumer/request counts. `POST /analytics/exports/run` triggers one
export by hand; both body fields are optional (defaults: the configured
window kind and its most recent closed window), and the endpoint
rejects a misspelled `window` or a `window_start_ms` that is unaligned
or not yet closed.

A window older than the rollup retention may undercount without the
store being able to know; such statements carry `"partial": true` so a
billing consumer can reject them, and the scheduler never auto-exports
past that horizon — only a manual trigger can, still flagged. Windows
with no traffic are not loss: counts are exact whenever `partial` is
false.
