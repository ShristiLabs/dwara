# AI prompt experimentation

Prompt experimentation adds prompt versioning, A/B model comparison,
regression evals, and feedback ingestion to the AI gateway. All four
live under the `ai.experiments` config block and are OFF by default
(no `ai.experiments` block = no experimentation surface).

## When to use this

Use prompt experimentation when:

- You want to version system prompts and switch the active version at
  runtime without a config reload.
- You want to split traffic for one alias across two or more variants
  (model + prompt version) and compare outcomes.
- You want regression evals against a golden set to score model or
  prompt changes before rollout.
- You want to collect human feedback (thumbs up/down, labels) and
  correlate it with the original request.

## Prompt versioning

Each prompt declares one or more versions (each with a system
message) and an active version. When a variant or eval references a
prompt version, that version's system message is prepended to the
request's messages BEFORE any existing system message.

```yaml
ai:
  experiments:
    prompts:
      greeting:
        versions:
          v1:
            system: "You are a helpful assistant."
          v2:
            system: "You are a concise assistant. Answer in one sentence."
        active: v1
```

The active version can be overridden at runtime via the admin API
without a config reload. The override is stored in the state store
and takes effect on the next request:

```
PUT /experiments/prompt-overrides
{"prompt_name": "greeting", "version": "v2"}
```

List current overrides:

```
GET /experiments/prompt-overrides
```

Clear an override (revert to the config-declared `active` version):

```
DELETE /experiments/prompt-overrides
{"prompt_name": "greeting"}
```

## A/B model comparison

An A/B test splits traffic for one alias across two or more variants,
each naming a model alias (plain chain/canary alias), an optional
prompt version, and a weight. The split is deterministic by request
id: the same request id always lands on the same variant, and the
configured ratios hold over many requests (the same slot semantics as
canary splits).

```yaml
ai:
  experiments:
    prompts:
      greeting:
        versions:
          v1:
            system: "You are a helpful assistant."
          v2:
            system: "You are a concise assistant."
        active: v1
    ab_tests:
      prompt-test:
        variants:
          - name: control
            model: gpt-4o-mini
            prompt: greeting/v1
            weight: 5
          - name: treatment
            model: gpt-4o-mini
            prompt: greeting/v2
            weight: 5
  models:
    gpt-4o-mini:
      provider: openai
      provider_model: gpt-4o-mini-2024-07-18
    chat:
      provider: openai
      provider_model: placeholder
      ab_test: prompt-test
```

A model alias with `ab_test` cannot also declare `failover`, `canary`,
or `routing_policy` (mutual exclusivity): an experiment alias composes
over other aliases' routing plans, so it has no provider/model pair of
its own. A variant's `model` must reference a plain chain/canary alias
that is NOT itself an experiment or policy alias (no nested
experiments).

Each request served by an experiment alias records an assignment row
in the `ai_experiment_assignments` analytics table with: request id,
experiment name, variant name, model, and consumer. The assignment is
written fire-and-forget (never blocks the request path).

## Regression evals

An eval declares a golden set of input/expected pairs and an optional
prompt version. The admin API runs it against a model alias (or an
A/B test's variants) by making direct provider calls and scoring each
response.

```yaml
ai:
  experiments:
    evals:
      greeting-eval:
        prompt: greeting/v1
        golden_set:
          - input: "Say hello"
            expected: "hello"
            scorer: exact_match
          - input: "Tell me about foxes"
            expected: "brown fox"
            scorer: contains
          - input: "Confirm order"
            expected: "Order #\\d+"
            scorer: regex
```

Supported scorers:

| Scorer | Description |
|---|---|
| `exact_match` | The output must exactly match `expected` (after trimming whitespace). Default when `scorer` is omitted. |
| `contains` | The output must contain `expected` as a substring. |
| `regex` | The output must match `expected` as a regex pattern. The pattern is compiled at publish time; an invalid regex is rejected by validation. |

Each eval case result is stored in the `ai_eval_results` analytics
table with: eval name, model, variant, prompt version, case index,
input, expected, actual, passed flag, scorer name, and latency.

## Feedback ingestion

The admin API accepts feedback records (thumbs up/down, labels,
comments) correlated by request id. Feedback is stored in the
`ai_feedback` analytics table alongside the request id for
correlation with the original request.

```
POST /experiments/feedback
{
  "request_id": "req-abc123",
  "label": "thumbs_up",
  "comment": "great response",
  "consumer": "acme",
  "model": "chat"
}
```

The `request_id` and `label` fields are required and must be
non-empty. Feedback ingestion is enabled by default; set
`ai.experiments.feedback.enabled: false` to reject feedback with a
403.

## Verdict computation

The admin API computes a verdict for an A/B test from stored eval
results. The variant with the highest pass rate wins; on a tie, the
lowest average latency wins (the cost tiebreaker); on a full tie
(same pass rate AND same latency), the verdict is a tie (no winner).

```
POST /experiments/verdict
{"experiment": "prompt-test"}
```

The response includes the winner, per-variant pass rates, and
per-variant average latencies:

```json
{
  "experiment": "prompt-test",
  "winner": "treatment",
  "pass_rates": [["control", 0.8], ["treatment", 0.9]],
  "avg_latencies": [["control", 120.5], ["treatment", 95.0]]
}
```

## Metrics

- `dwara_ai_experiment_variant_selections_total{experiment,variant}` --
  A/B test variant selections. `experiment` is the A/B test
  name; `variant` is the selected variant name. Both labels are
  config-bounded. No consumer label (cardinality rule).

## See also

- [AI gateway](./ai-gateway)
