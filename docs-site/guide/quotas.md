# Consumer quotas

A quota is a **budget**, not a rate: it caps the total number of
requests one consumer may make inside a fixed UTC calendar window --
a day (midnight to midnight UTC) or a month (the first through the
last instant of the UTC month). The rate limiter shapes traffic
inside seconds or minutes; a budget bounds total volume. The two are
separate by design and compose: when both are configured, both apply
(rate limiting is covered in [Configuration](./configuration)).

A quota never replenishes inside its window. It resets whole at the
boundary -- the daily budget is full again at UTC midnight.

Quotas count REQUESTS. AI routes have their own budget family that
counts provider-reported TOKENS per minute (and spend per day) per
consumer or team -- see
[Token budgets](./ai-gateway#token-budgets) in the AI gateway guide.

## When to use this

Use quotas when the unit of control is total volume per billing
period rather than bursts per second:

- Per-tenant request allowances (10k/day on the free tier).
- Monthly API commitments with automated enforcement.
- Hard spend ceilings for batch/CI consumers that legitimately burst.

Use rate limits (not quotas) when the concern is protecting upstreams
from load spikes.

## Configuration

Budgets are declared on config consumers:

```yaml
consumers:
  - name: acme-prod
    credentials:
      - type: api_key
        key: ${ACME_PROD_KEY}
    quotas:
      daily_requests: 1000000
      monthly_requests: 20000000
```

| Field | Type | Description |
| --- | --- | --- |
| `daily_requests` | `u64` | Max requests per UTC calendar day (midnight to midnight). |
| `monthly_requests` | `u64` | Max requests per UTC calendar month. |

At least one budget must be set, and every set budget must be greater
than zero -- a budget of 0 would deny the consumer's first request,
so "no budget" is expressed by omitting the field (validation
enforces both).

## The state store is required

Enforcement needs the durable state store for its counters: start the
gateway with `DWARA_STATE_DB` pointing at the SQLite file (see
[environment variables](../reference/environment-variables)). Without
a store, quota config is inert and the request path logs that
enforcement is off.

Scope of this implementation: counters are **per instance** (local
SQLite truth), and budgets apply to config-declared consumers -- a
fleet-wide shared counter is the enterprise follow-up. If you run
several gateway instances behind one load balancer, each instance
counts its own share of a consumer's traffic; take that into account
or enforce budgets at a single choke point.

## Enforcement

When a consumer's request would exceed a budget, the gateway answers
`429` with the same header family rate-limit 429s carry:

- `Retry-After` -- seconds until the window resets (rounded up,
  minimum 1).
- `X-RateLimit-Limit` / `X-RateLimit-Remaining` / `X-RateLimit-Reset`
  -- the binding budget's size, what is left of it, and the Unix
  epoch second at which it resets.

The gateway is the source of truth for the `X-RateLimit-*` family:
any upstream values are silently stripped, so the client always sees
the gateway's own accounting.

### Durability and cost

Every accepted request of a quota-configured consumer performs one or
two synchronous state-store writes (a daily and/or monthly counter
increment), committed before the request proceeds -- so a crash can
lose at most the request that was in flight, never a committed
counter. The store runs SQLite's default `synchronous=FULL` (an
fsync per commit): budgets are billed-grade durable, and the
per-request fsync on the single store connection is the documented
price. For consumers that do not need second-grade ceilings,
prefer rate limits (in-memory) and keep budgets for the volumes
where the durability trade is worth it.

## Reading usage

`GET /quotas/usage` on the admin API reports every quota-configured
consumer's current-window counters (or the one named by the optional
`?consumer=` parameter):

```sh
curl --cert operator.crt --key operator.key \
  https://127.0.0.1:2019/quotas/usage
```

```json
{
  "now_epoch_s": 1770000000,
  "consumers": [
    {
      "consumer": "acme-prod",
      "synced": true,
      "budgets": [
        {
          "budget": "daily",
          "limit": 1000000,
          "used": 482113,
          "remaining": 517887,
          "window_start_epoch_s": 1769961600,
          "reset_epoch_s": 1770048000
        }
      ]
    }
  ]
}
```

`reset_epoch_s` is the same instant a budget 429's
`X-RateLimit-Reset` advertises. A consumer whose store row is
missing reports `synced: false` with no budgets -- no counters exist
for it yet, and reporting zero usage would be a lie.

Errors: `404 state_store_not_configured` when the gateway runs
without `DWARA_STATE_DB`, and `400 quota_bad_consumer` when
`?consumer=` names a consumer that declares no `quotas` block.

## Usage reports

Scheduled usage statements carry the quota figures a billing pipeline
consumes: the exports' `quota_daily_used` / `quota_daily_limit` /
`quota_monthly_used` / `quota_monthly_limit` columns come from these
same state-store counters (absent -- never zero -- when the consumer
has no budgets). See
[Usage reports and exports](./analytics#usage-reports-and-exports)
for the windowing, formats, and the manual trigger.
