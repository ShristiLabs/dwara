# Analytics

Observability answers *"is it healthy right now"* (see
[Operations](./operations)); analytics answers *"what happened over
time, to whom, and why"*. The embedded analytics store (DW-043) gives
a single-instance gateway a durable, queryable traffic history with
zero external dependencies and bounded disk usage.

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

The database is a separate SQLite file from the state store
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
pre-aggregated rollups — 1 minute, 5 minutes, 1 hour, 1 day — each
holding request/error/rate-limit/shed counts, duration sum/max, and a
13-bucket latency histogram per dimension tuple. Because every stored
number is additive, any time range at any granularity merges exactly,
and percentiles are estimated from the merged histogram. Retention is
enforced per granularity with incremental vacuum, so disk usage is
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
parameterized SQL (SQL text is never accepted):

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
