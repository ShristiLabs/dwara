# Quotas and metering

Source: `crates/dwara-core/src/state/quotas.rs` (DW-033), the request
phase in `dataplane/proxy.rs`, the admin read in `dwara-admin`. Tests:
`quotas` (dwara-core), `state::quotas` unit tests (dwara-core), quota
cases in `admin_api` (dwara-admin). Metrics: `dwara_quota_denied_total`,
`dwara_quota_used`, `dwara_quota_limit`.

## Budgets, not rates

Rate limiting (DW-017) shapes traffic INSIDE seconds or minutes: GCRA
buckets that replenish continuously. A quota is a different mechanism —
a BUDGET: the total number of requests one consumer may make inside a
fixed UTC calendar window, with no replenishment until the window rolls
over whole. The two run independently and compose (both apply when both
are configured; the rate limiter is consulted first because an
in-memory 429 is cheaper than a store-backed one).

The distinction shows up in the failure surface too: a rate-limit 429
counts in `rate_limited_total{route}`; a budget 429 counts in
`dwara_quota_denied_total{consumer,budget}` and never touches the
rate-limit family.

## Configuration

Budgets attach to CONFIG consumers (`consumers[].quotas`) — one or both
of `daily_requests` and `monthly_requests`, each > 0, at least one
present (validation rejects an explicit empty block and zero values).
Windows are UTC calendar aligned: a daily budget is midnight-to-midnight
UTC, a monthly budget the first through the last instant of the UTC
month.

```yaml
consumers:
  - name: acme
    credentials:
      - type: api_key
        key: ${ACME_KEY}
    quotas:
      daily_requests: 50000
      monthly_requests: 1000000
```

Enforcement needs the state store (`DWARA_STATE_DB`): counters are rows
of the store's `quota_counters` table (the seam DW-018 shipped with
`incr_quota`'s atomic increment-or-refuse). Without a store the block is
INERT — the dataplane warns once per process (`quota_store_missing`)
and traffic passes: there are no counters to enforce, and 429-ing (or
500-ing) every request of a misconfigured deployment would turn a
wiring gap into an outage. The same fail-open applies to a consumer
whose store row is missing (`quota_consumer_unsynced` — consumer sync
runs at startup). A store that ERRORS mid-check is different: the
gateway cannot vouch for the budget either way, so the request answers
500 (`quota_store_unavailable`), the same posture as an authN backend
failure.

Anonymous traffic and store-managed consumers have no budgets: quotas
are config-consumer-only in this edition. A distributed shared-counter
variant (fleet-wide consistency) is the Ent follow-up (DW-155).

## Evaluation semantics

Every authenticated request of a quota-configured consumer checks each
budget shortest-window-first (daily, then monthly); all configured
budgets apply (AND). `check` is decide-and-reserve like the rate
limiter: an allowed request's unit is already spent.

- **Denial.** The first denying budget answers `429` with `Retry-After`
  (whole seconds to the window boundary, rounded up, minimum 1) and
  `X-RateLimit-Limit` / `-Remaining` / `-Reset` from that budget — the
  same client-facing header contract DW-017 set. `X-RateLimit-Reset`
  is the UTC window boundary as Unix epoch seconds; a monthly denial
  advertises a month-scale `Retry-After`.
- **Denials only.** Budget headers appear on 429s only: on admitted
  responses the `X-RateLimit-*` family belongs to the rate limiter
  when it applies (two mechanisms racing to write the same header
  names on every success would be noise, not information).
- **Fail-fast, consume nothing.** Evaluation stops at the first denial
  and a refused request consumes NO budget — later budgets are peeked
  read-only, never incremented for a request that will not run.
- **Max-wait across walls.** When a later budget is ALSO exhausted,
  `Retry-After` stretches to the later reset (a month boundary is a
  midnight at or after the day boundary): a client honoring the hint
  never retries out of the daily wall straight into the monthly one —
  the DW-017 max-wait rule, implemented without reservation.
- **Documented stacking trade.** The mirror image of the GCRA stacking
  trade: a request denied by the MONTHLY budget has already spent its
  daily unit (the daily window evaluated first). One unit of waste in
  the faster-resetting window; never more permissive; bounded.

## Durability and cost

Counters are synchronous point writes committed before the request
proceeds — not fire-and-forget like the analytics pipeline — so a
crash can lose at most the request that was in flight, never a
committed counter, and a restart resumes at the exact budget (pinned by
test: a store reopened from the same file keeps refusing at the same
cap). Reloads are live: budgets are read from the current generation's
consumer config, so publishing a larger cap immediately admits against
the same persisted counter.

Cost note for operators: each request of a quota-configured consumer
performs one or two synchronous SQLite write transactions on the single
mutex-guarded state-store connection, and that store keeps SQLite's
default `synchronous=FULL` (an fsync per commit) — unlike the analytics
store, which pins `NORMAL`. Budgets therefore add a per-request fsync
and serialize quota'd traffic through one connection. That is the
accepted OSS per-instance shape; scaling quota enforcement across a
fleet is the DW-155 Ent follow-up.

## Metering: where usage is visible

- **Admin API**: `GET /quotas/usage` (optional `?consumer=` filter) —
  per quota-configured consumer, each budget's current-window
  `used`/`limit`/`remaining`, `window_start_epoch_s`, and
  `reset_epoch_s` (the same instant a 429's `X-RateLimit-Reset`
  advertises). 404 `state_store_not_configured` without a store; a
  consumer with no store row reports `synced: false` and an empty
  budgets list rather than fabricated zeros.
- **Metrics** (DW-021 conventions): `dwara_quota_denied_total{consumer,
  budget}` (counter), `dwara_quota_used{consumer,budget}` and
  `dwara_quota_limit{consumer,budget}` (scrape-time snapshot gauges —
  the same model as the rate-limiter live-keys gauge; a consumer
  removed by reload keeps its last series until restart, and the
  used/limit ratio of a stale pair stays correct because both series
  freeze together).
- **Analytics**: a quota-denied request completes with
  `rate_limited = true` and its consumer name, so the existing
  per-consumer axis (raw rows and the `rollup_fixed` consumer
  dimension, DW-043) answers "how much did this consumer send and how
  much was refused" over history — `/analytics/dashboard?consumer=`
  and the consumers Top-N.
- **Events**: `quota_near_limit` (webhook-subscribable, DW-044) fires
  when a budget crosses 80% of its cap — edge-triggered ONCE per
  (consumer, budget, window), so the second and later crossings in one
  window are not noise. Payload: `consumer` (a config-declared label,
  the same trust class as `upstream` names), `detail` (the budget:
  `daily`/`monthly`), `used`, `limit`.

## Where it sits in the request pipeline

The quota phase runs after rate limiting and before gateway-cap
admission (a budget wall never holds a concurrency slot), on routed,
authenticated traffic only — authentication identifies the consumer,
and unrouted requests 404 before any budget could apply. The phase
span is `quota` in the request trace.
