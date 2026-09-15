# Routing policies, budgets, pricing

## `ai.routing_policies.<name>`

Evaluated per request for aliases that declare `routing_policy: <name>`.

### `fallback_chain` - cheap-first escalation

```yaml
ai:
  routing_policies:
    complexity-escalation:
      kind: fallback_chain
      cheap: gpt-4o-mini          # alias served when score < threshold
      escalate_to: gpt-4o         # alias served when score >= threshold
      classifier_url: http://classifier:9090/classify
      classifier_model: complexity
      threshold: 0.5
      timeout_ms: 1000
```

Classifier contract: `POST {"model","input"}` ->
`{"data":[{"score": 0.0..1.0}]}`. Classifier failure or timeout **fails
open to the cheap model** - a dead classifier never blocks traffic.

### `latency_cost` - preference-driven selection

```yaml
ai:
  routing_policies:
    balanced-selection:
      kind: latency_cost
      preference: balanced        # cost | latency | balanced
      candidates:
        - model: gpt-4o-mini
          cost: 1
          latency: 1
        - model: gpt-4o
          cost: 5
          latency: 3
      # live: true                # live latency observations override the
      # live_window: 10           # static `latency` scores (no effect when
      #                           # preference is `cost`)
```

## `token_budget` - tokens and dollars

Two places to set one, checked in this order:

1. **Consumer-direct**: `consumers[].token_budget` (anonymous callers cannot
   bind one).
2. **Policy**: `policies[].token_budget` attached at any level (consumer >
   route > service > listener > global); the **most specific** policy in the
   chain wins; no budget anywhere = unlimited.

```yaml
policies:
  - name: ai-token-budget
    token_budget:
      tokens_per_min: 200000        # fixed 60s sliding window
      cost_per_day_micros: 5000000  # UTC calendar day
      scope: policy                 # consumer (default) | policy
```

- `scope: consumer` = per-consumer window; `scope: policy` = one shared
  window for everyone the policy covers (team budget).
- Exceed -> `429` + `ai_budget_exceeded` + `Retry-After`, **before** any
  provider contact (phase 1 of the pipeline).
- Pre-parse estimate (~4 chars/token + per-message overhead, conservative -
  over-estimates) + requested `max_tokens` are compared against remaining
  budget; oversized prompts are rejected without spending a call.
- Mid-stream cutoff `ai_budget_exceeded_midstream`: only for providers that
  report usage during the stream (Anthropic). Streamed-so-far content
  stands; the provider request is cancelled.
- Counters are in-memory per instance (fleet-shared budgets are an
  enterprise concern) and **survive reloads**.

## `ai.pricing` - cost attribution

```yaml
ai:
  pricing:
    gpt-4o:
      input_per_1k_micros: 250
      output_per_1k_micros: 1000
    gpt-4o-mini:
      input_per_1k_micros: 15
      output_per_1k_micros: 60
```

Micro-USD per 1K tokens, keyed by **alias**. Provider-reported usage x this
table = recorded spend. A model without a pricing entry costs 0 - tracked,
warned about in logs, never blocked. If `cost_per_day_micros` matters, price
every alias the budget can reach (including failover/canary targets -
**price the underlying aliases referenced by policies/canaries too**).

## Spend observability

- `POST /analytics/spend` (`from_ms`, `to_ms`, `group_by`) - spend queries.
- Budget denials are distinguishable from rate-limit denials by the error
  `code` field (`ai_budget_exceeded`); the 429 troubleshooting page on the
  docs site disambiguates the whole family.

## Choosing a shape

| Need | Use |
| --- | --- |
| Survive one provider outage | alias `failover` chain (<= 4) |
| Gradually shift traffic to a new model | alias `canary` (2..=8 weighted versions) |
| Cut cost on easy requests | `fallback_chain` + classifier |
| Trade cost vs latency statically (or with live signals) | `latency_cost` |
| Hard cap a team | `token_budget` policy with `scope: policy` + pricing entries |
