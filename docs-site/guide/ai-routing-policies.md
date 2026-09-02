# AI routing policies

Routing policies are within-request escalation and latency-vs-cost
selection, composed over the AI gateway's routing foundation. Unlike
failover (which retries across providers on failure), a routing policy
chooses which model to call based on the prompt's complexity or a
cost/latency tradeoff.

A model alias with a `routing_policy` cannot also declare `failover`
or `canary` (mutual exclusivity). The policy is evaluated per request
and returns the candidate list to walk.

## When to use this

Use routing policies when:

- You want simple prompts routed to a cheap model and complex prompts
  escalated to a costlier one, decided per request by an external
  classifier.
- You want static, operator-declared cost/latency tradeoffs picked at
  compile time without runtime metrics.
- You need deterministic selection that composes over the gateway's
  existing model alias and provider machinery.

## Fallback chain (cheap-first escalation)

Calls an external classifier service to estimate prompt complexity.
Simple prompts (score < threshold) route to the cheap model; complex
prompts (score >= threshold) escalate to the costlier model. Fails
open to the cheap model on classifier error.

```yaml
ai:
  routing_policies:
    cheap-first:
      kind: fallback_chain
      cheap: gpt-4o-mini
      escalate_to: gpt-4o
      classifier_url: http://localhost:11434/v1/classify
      classifier_model: complexity
      threshold: 0.5
      timeout_ms: 1000
      api_key: ${CLASSIFIER_API_KEY}
  models:
    smart-router:
      routing_policy: cheap-first
```

The classifier service must accept a POST with
`{"model": "...", "input": "..."}` and return
`{"data": [{"score": 0.0-1.0}]}` (OpenAI-embeddings-compatible shape
with a `score` field instead of `embedding`).

## Latency-vs-cost routing

Static config-based selection. The operator declares cost/latency
scores per candidate (1-10, where 1 = cheapest/fastest) and a
preference. The policy picks deterministically at compile time -- no
runtime metrics needed.

```yaml
ai:
  routing_policies:
    balanced:
      kind: latency_cost
      preference: balanced
      candidates:
        - model: gpt-4o-mini
          cost: 1
          latency: 3
        - model: gpt-4o
          cost: 5
          latency: 2
  models:
    smart-router:
      routing_policy: balanced
```

| Preference | Selection |
|---|---|
| `cost` | Lowest `cost` score (cheapest) |
| `latency` | Lowest `latency` score (fastest) |
| `balanced` | Lowest `cost + latency` sum |

## Metrics

- `dwara_ai_routing_policy_escalations_total{policy}` -- FallbackChain
  escalations (complex prompt -> expensive model).
- `dwara_ai_routing_policy_cheap_total{policy}` -- FallbackChain
  cheap-model selections.
- `dwara_ai_routing_policy_latency_cost_selections_total{policy}` --
  LatencyCost selections.

## See also

- [AI gateway](./ai-gateway)
