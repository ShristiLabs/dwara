# AI token budgets and cost attribution

Token budgets cap the total AI consumption of one consumer (or one shared
team): provider-reported tokens per minute and/or spend per UTC day. Cost
attribution maps each provider model to its per-1k-token price so the
gateway can track spend per consumer, team, and model and export it for
billing reconciliation. The two work together -- a cost-per-day budget is
only enforced once a pricing table is configured.

## When to use this

- One consumer or team must not burn unbounded tokens or spend --
  per-minute token caps and per-day cost caps answer before the
  provider call.
- You need per-consumer, per-team, and per-model cost accounting, and
  billing exports to reconcile it against provider invoices.

## Token budgets

A token budget caps the total AI consumption of one consumer (or one
shared team): provider-reported TOKENS per minute, and/or spend per
UTC day. It is a budget, not a rate -- where rate limits count
requests and [consumer quotas](./quotas) count requests per day or
month, a token budget counts what the provider reports back, so the
three compose when all are configured.

Cost-per-day budgets are fully enforced once a pricing table is
configured (see [Cost attribution](#cost-attribution-and-metering)
below). The gateway never estimates a price -- it multiplies the
provider-reported token counts by the configured per-model rates.

Budgets are declared on a policy, and the policy is attached to the
consumers (or routes) it should govern:

```yaml
policies:
  - name: acme-ai-budget
    token_budget:
      tokens_per_min: 500000        # provider-reported tokens / minute
      cost_per_day_micros: 5000000  # $5.00/day, integer micro-USD
      # scope: policy              # one SHARED team budget instead
                                    # of one window per consumer

consumers:
  - name: acme
    credentials:
      - type: api_key
        key: ${ACME_KEY}
    policies: [acme-ai-budget]
```

| Field | Default | Description |
|---|---|---|
| `tokens_per_min` | none | Max provider-reported tokens per fixed 60-second window. |
| `cost_per_day_micros` | none | Max spend per UTC day, in integer micro-USD (1,000,000 = $1.00). Requires a [pricing table](#cost-attribution-and-metering) to be effective. |
| `scope` | `consumer` | `consumer`: every consumer attaching the policy gets its own window. `policy`: one shared (team) budget -- all attaching consumers spend from the same window. |

At least one of `tokens_per_min` / `cost_per_day_micros` must be set,
and a set value must be greater than zero (validation rejects an
empty or zero budget).

### How enforcement behaves

- **A spent window rejects before the provider is called.** A request
  from a holder whose window is already exhausted gets `429` with a
  `Retry-After` header (seconds until the window resets) and the
  OpenAI error shape, `code: ai_budget_exceeded`. No provider tokens
  are spent on a rejected request.
- **A local estimate pre-check rejects oversized requests before the
  provider is called.** After request parsing, the gateway estimates
  the prompt token count using a lightweight heuristic (approximately
  4 characters per token plus per-message overhead). If the estimated
  total (prompt estimate + requested `max_tokens`) exceeds the
  remaining budget, the request is rejected with `429` before any
  provider contact -- avoiding unnecessary provider calls and token
  spend. The estimate is conservative (it tends to over-estimate
  slightly), so a request near the boundary may be rejected even if
  the provider would have reported fewer tokens. Provider-reported
  usage remains authoritative for post-call accounting.
- **The gateway spends what the provider reports, never an
  estimate.** Usage is recorded after the provider answers, so a
  holder sitting exactly at its limit can always complete one more
  request; the next one is rejected. Overrun is bounded by that one
  request's usage.
- **A stream that crosses its budget is cut off mid-stream.** Usage
  is spent as the provider reports it during the stream; on a
  crossing, forwarding stops, the client receives this event and then
  `[DONE]` (already-streamed content stands, the connection is not
  reset), and the provider request is cancelled -- no further
  provider tokens are consumed:

  ```
  data: {"error":{"code":"ai_budget_exceeded_midstream","message":"the token budget for this window is exhausted; the stream was cut off","request_id":"req-...","type":"rate_limit_error"}}

  data: [DONE]
  ```

  Only providers that report usage during the stream (Anthropic does)
  can be cut off mid-stream; providers that report usage only at the
  end are enforced on the next request's pre-check.
- **Spend survives config reloads.** Changing limits (or anything
  else) by reload never resets a live window -- a minute window rolls
  at the minute boundary, the day window at UTC midnight, regardless
  of reloads.
- **Counters are in-memory and per instance.** No state store is
  required; a fleet of gateway instances each count their own share
  (fleet-wide shared budgets are the enterprise edition's follow-up).

If several policies in the attachment chain (consumer > route >
service > listener > global) declare a budget, the most specific one
governs. Consumers with no budget attached are unlimited.

Denials are counted in `dwara_ai_budget_denied_total{kind}` (see
[Metrics](#metrics)); the consumer name appears in the access log,
never as a metric label.

## Cost attribution and metering

A pricing table maps each provider model to its per-1k-token cost
(integer micro-USD), so the gateway can attribute spend per consumer,
team, and model -- and export it for billing reconciliation.

### Pricing tables

```yaml
ai:
  pricing:
    gpt-4o-mini-2024-07-18:
      input_per_1k_micros: 150     # $0.15 / 1k input tokens
      output_per_1k_micros: 600    # $0.60 / 1k output tokens
    claude-sonnet-4-5:
      input_per_1k_micros: 300
      output_per_1k_micros: 1500
```

The key is the PROVIDER MODEL (the `provider_model` from the alias
table), not the client-facing alias -- that is what the provider
charges for. Spend for one call is:

```
cost = prompt_tokens * input_per_1k_micros / 1000
     + completion_tokens * output_per_1k_micros / 1000
```

All arithmetic is integer micro-USD (no floating-point money). A
model not in the pricing table costs 0 -- the call is tracked but
not priced (fail-open: the request is never blocked, a warning is
logged). This means a new model release works immediately without
waiting for a pricing-table update. Pricing changes take effect on
the next request after a config reload -- no restart.

| Field | Default | Description |
|---|---|---|
| `input_per_1k_micros` | (required) | Cost per 1,000 prompt tokens, in micro-USD. |
| `output_per_1k_micros` | (required) | Cost per 1,000 completion tokens, in micro-USD. |

### Spend tracking

Every AI request (streaming and non-streaming) records a spend row
into the analytics store with: consumer, team (the policy name when
a `scope: policy` budget is attached, empty otherwise), provider,
model, version, prompt/completion/total tokens, and cost in micro-USD.
Rows are written fire-and-forget (drop-and-count on a full channel --
never blocks the request path).

Spend is queryable through the admin API:

```
POST /analytics/spend
{
  "from_ms": 1693526400000,
  "to_ms": 1693612800000,
  "group_by": ["consumer", "model"]
}
```

The response is one row per group with token totals, cost, and
request count.

### Billing exports

The scheduled usage-report export carries spend columns in
both CSV and JSON output: `prompt_tokens`, `completion_tokens`,
`total_tokens`, and `cost_micros` per consumer. The JSON statement
additionally includes a `spend_by_model` array breaking down tokens
and cost per model for the window. CSV is RFC 4180 compliant;
Parquet is deferred to a future release (the seam is documented for
billing pipelines that need columnar output).

## Runnable demo

The [`demos/07-ai-gateway/`](https://github.com/shristilabs/dwara/tree/main/demos/07-ai-gateway) stack in the repository configures
per-consumer and per-policy token budgets and per-model pricing in
its `dwara.yaml` (consumer `demo-user`, policy `ai-budget`); there
is no dedicated test script. The category README covers the config,
prerequisites, and teardown.

## See also

- [AI gateway](./ai-gateway)
