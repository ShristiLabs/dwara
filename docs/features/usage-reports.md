# Usage reports and exports (DW-120)

> Implements issue DW-120 (M2, `edition/oss`, effort M), over the
> analytics store shipped by DW-043. Sources:
> `crates/dwara-core/src/analytics/exports.rs` (the engine — its module
> docs carry the full rationale), the `export_runs` schema-v2 migration
> in `analytics/schema.rs`, the worker and quota-figure handoff in
> `dataplane/proxy.rs`, config types in `config/mod.rs`, validation in
> `snapshot/mod.rs`, the endpoints in `dwara-admin/src/lib.rs`, the
> spawn in `dwara-bin/src/main.rs`. Tests:
> `crates/dwara-core/tests/exports.rs` (end to end: statement==query
> equality, CSV escaping, idempotent re-export, partial flagging,
> failed-directory run, backfill, settle delay, empty period) and
> `crates/dwara-core/tests/unit/exports.rs` (window alignment, closed
> sets, defaults, `last_closed_window`, ledger table). Operator docs:
> [docs-site analytics guide](../../docs-site/guide/analytics.md).

DW-043 made the analytics store QUERYABLE live; DW-120 makes it
REPORTABLE durably. A background worker closes each UTC calendar
window of the configured kind (hourly/daily/monthly) and writes the
per-consumer usage statement — requests, errors, error rate,
rate-limited and shed counts, average latency, plus the quota budget
figures a billing pipeline consumes — as one deterministic file per
configured format into a configured directory. Distinct from the query
API on purpose: this is scheduled durable OUTPUT, not an ad hoc query
(the §5-Analytics line "feeds billing" is the requirement).

## Configuration

`analytics.exports` sits inside the `analytics` block (a store must
exist for exports to run; without the block the worker no-ops and the
admin endpoints answer that exports are not configured):

```yaml
analytics:
  path: /var/lib/dwara/analytics.db
  exports:
    directory: /var/lib/dwara/usage-reports
    window: daily            # hourly | daily | monthly; default daily
    formats: [csv, json]     # no duplicates; omitted/empty = both
```

Defaults: `window` daily (midnight-to-midnight UTC — aligned with the
quota daily budget's window, so a daily statement's quota column is
exactly that day's counter), `formats` both (an omitted or empty list
MEANS both). Validation rejects an empty `directory` and duplicate
formats (each format writes exactly one file per window; a duplicate
would promise two). Parquet is deliberately NOT a v1 format — the
arrow/parquet dependency weight is deferred to the DW-156 backlog.

The worker reads the CURRENT config generation every tick, so a reload
adds, removes, or re-aims exports without a restart. An unwritable
directory fails the run LOUD (failed run record + `analytics_export_failed`
log), never the dataplane — the export path never touches a request.

## Scheduling: due windows, backfill, and the horizon

`DataPlane::spawn_export_worker` (spawned by `dwara-bin` on the shared
shutdown watch) ticks every 30 s (`EXPORT_TICK_MS`) and calls `run_due`,
which exports every closed window of the configured kind that has no
`ok` run record yet:

- **Settle delay.** A window is due once its close is at least 5
  minutes in the past (`EXPORT_DELAY_MS`: writer flush + rollup grace +
  cascade headroom) — the statement reads settled windows, so it is as
  complete as the store can make it. Not a correctness knob; a manual
  trigger bypasses it.
- **Backfill, oldest first.** A restart (or any downtime) backfills
  missed windows oldest-first, bounded at 64 windows per tick
  (`MAX_CATCHUP_WINDOWS` — one query plus file writes each, so a single
  tick's work stays bounded while a long downtime drains over
  successive ticks). Failed runs are retried on later ticks, at most
  once per 10 minutes (`FAILURE_RETRY_MS`; only `ok` records count as
  done).
- **Retention horizon.** The scheduler never AUTO-exports a window
  older than the queried granularity's retention (it would undercount
  without the store being able to know); only a manual trigger can
  force one, and the output is flagged (below).
- **Settling per run.** `run_export` forces one `maintain()` pass
  first — idempotent and cursor-guarded — so even a manual trigger
  reads complete windows.

Granularity choice: hourly and daily statements read the 1-hour rollup
table (short settle lag, well inside its default 30-day retention); a
monthly statement reads the 1-day table, because a month of 1-hour
windows would outrun the 1h table's default retention.

## The statement IS the query API's answer

The acceptance contract ("a per-consumer usage statement for a period
matches the analytics query API's own numbers for that period") holds
BY CONSTRUCTION: `run_export` builds the statement by calling
`query::structured` itself — grouped by `consumer` (limit 10,000) plus
one ungrouped totals row — over the same `rollup_fixed` tables through
the same aggregation helpers, with the same period bounds. There is no
second arithmetic to drift. The integration suite pins it anyway: the
`statement_matches_the_query_api_exactly` test parses the written JSON
file and compares it against an independent `structured()` call.

Two real bugs in `analytics/query.rs` surfaced by the totals row and
fixed in this change: `read_agg` is now NULL-tolerant (an UNGROUPED
aggregate over an empty range yields one all-NULL row — the documented
totals shape is zeros, not a type error), and a literal `GROUP BY 1`
was removed from the ungrouped path (it resolved positionally to a SUM
aggregate instead of eliminating rows — harmless by accident, wrong by
construction).

## Output files

One deterministic file per (window, format), written atomically (temp
file + rename in the destination directory — a crash mid-write leaves
only a stray temp, never a torn export; concurrent exports of the same
window race to last-writer-wins):

| Kind | Stamp | Filename |
| --- | --- | --- |
| hourly | `YYYY-MM-DDThhZ` | `dwara-usage-hourly-2026-08-29T14Z.csv` |
| daily | `YYYY-MM-DD` | `dwara-usage-daily-2026-08-29.json` |
| monthly | `YYYY-MM` | `dwara-usage-monthly-2026-08.csv` |

A re-export of the same window simply overwrites — idempotent output,
the rollup recompute philosophy. The directory is created on demand; a
write failure fails the run (files that did land stay on disk — the run
record says which formats ran).

**CSV** is RFC 4180: CRLF terminators, fields quoted when they contain
a comma, quote, CR, or LF (quotes doubled) — hostile consumer names
cannot smuggle a column break. Fixed columns, one row per consumer:
`consumer, requests, errors, error_rate, rate_limited, shed, avg_ms,
quota_daily_used, quota_daily_limit, quota_monthly_used,
quota_monthly_limit`. Absent quota cells are EMPTY strings — zero
means configured-and-zero-used, and the distinction is load-bearing
for billing.

**JSON** is pretty and self-describing: `kind: "usage_statement"`,
`window`, `from_ms`/`to_ms` bounds, `generated_at_ms`, `partial`,
`windows_nonempty` (informational), a `totals` object, and
`consumers[]` rows carrying the same fields as the CSV plus each
budget's `window_start_epoch_s`/`reset_epoch_s` (the denominator's
bounds, so a billing consumer knows exactly what `used` covers).

## Quota columns (DW-033)

The quota figures come from the STATE store's `quota_counters`, a
domain the analytics module cannot import (`scripts/check_deps.py`) —
so the callers above both domains (the export worker, the admin
trigger) read the counters and hand them in as plain `QuotaFigures`
per consumer name. Consumers without a quotas block, without a store,
or not yet synced into the store carry no figures — never fabricated
zeros.

Alignment rule: a budget's figures appear only when its quota window
FULLY CONTAINS the export window — a daily export carries the
same-UTC-day `daily` counter (exact period consumption) plus the
month-to-date `monthly` counter; a monthly export carries only the
`monthly` counter (the daily budget's per-day rows do not sum to the
month by construction, so they are omitted rather than approximated).
Monthly figures are month-to-date as of generation time — the column
reads the store's live counter, so a backfilled or re-exported window
can carry a different `quota_monthly_used` than the original run; each
budget's `window_start_epoch_s`/`reset_epoch_s` bound what `used`
covers.
See [Quotas and metering](./quotas.md) for the counter machinery.

## The run ledger and the admin surface

Schema v2 of the analytics database (forward-only migration, same rule
as the state store) adds the `export_runs` ledger: one row per
(kind, window_start_ms) — a re-export REPLACES the row, matching the
idempotent file output. Columns: `status` (`ok`/`failed`), `partial`,
`formats`, `directory`, `consumers`, `requests`, `windows_nonempty`,
`error`, `generated_at_ms`.

`partial: true` flags a window whose start is older than the queried
granularity's retention: real data, flagged, so a billing consumer can
reject the statement instead of trusting an undercount. Quiet windows
are NOT loss — `windows_nonempty` counts the range's rollup windows
that carry any data, and the statement's counts are exact whenever
`partial` is false.

Two admin endpoints (mTLS, like every analytics endpoint; both 404 with
the shared `analytics_absent` envelope when no store is configured):

- `GET /analytics/exports?limit=` — the ledger, newest first. `limit`
  defaults to 25 and is clamped to 1..=100. The response is
  `{"runs": [...]}`.
- `POST /analytics/exports/run` — the scheduled worker's manual twin
  (same engine, same reconciliation contract). Optional JSON body
  `{"window": "hourly|daily|monthly", "window_start_ms": <aligned,
  closed>}`; absent fields default to the configured kind and its most
  recent CLOSED window. 400s (`analytics_export_run_invalid` /
  `analytics_exports_not_configured`): no `analytics.exports` block in
  the config (the directory is where outputs land — an ad hoc directory
  in a request body would be a write-anywhere footgun), a misspelled
  `window`, or a `window_start_ms` that is unaligned or not yet closed.
  A failed run answers 500 `analytics_export_failed` with the error
  string; success returns the run record.

The [embedded analytics](./analytics.md) page covers the store, the
rollup cascade, and the query surface this feature builds on.
