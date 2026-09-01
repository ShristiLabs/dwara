# AI gateway

The AI gateway lets clients send one request shape -- the OpenAI
chat-completions format -- to dwara, and dwara translates the call to
whichever provider actually serves it: OpenAI, Anthropic, or Google
Gemini. Responses (and errors) are translated back to the OpenAI
shape, so any OpenAI-compatible client or SDK works unchanged.

Your model names stay yours: clients ask for the alias you publish
(`gpt-4o-mini`, `claude-sonnet`, or your own names like `prod-chat`),
and the provider's real model identifier never leaves the gateway.
Rotate providers by editing the alias table -- no client changes.

## When to use this

Use the AI gateway when:

- You want to switch or combine LLM providers without changing client
  code.
- Provider credentials should live in one place (the gateway) instead
  of in every client.
- You want gateway metrics for AI traffic (requests per provider,
  token usage) alongside your other routing metrics.
- You want to cap how many tokens (or how much spend) one consumer
  or team may burn -- see [Token budgets](#token-budgets).

## Configuration

Three pieces: an upstream per provider (the transport), an `ai:`
block mapping providers and model aliases, and a route with the `ai`
action.

```yaml
upstreams:
  - name: openai-pool
    endpoints:
      - address: api.openai.com
        port: 443
    # TLS is negotiated toward the endpoint; the provider path
    # (/v1/chat/completions, /v1/messages, ...) is added by the adapter
  - name: anthropic-pool
    endpoints:
      - address: api.anthropic.com
        port: 443

ai:
  providers:
    - name: openai
      kind: openai
      upstream: openai-pool
      auth:
        header: Authorization
        # the reference must span the WHOLE value, so the "Bearer "
        # prefix belongs to the variable: OPENAI_API_KEY_BEARER
        # should be set to "Bearer sk-..."
        value: ${OPENAI_API_KEY_BEARER}
    - name: anthropic
      kind: anthropic
      upstream: anthropic-pool
      auth:
        header: x-api-key
        value: ${ANTHROPIC_API_KEY}
  models:
    gpt-4o-mini:
      provider: openai
      provider_model: gpt-4o-mini-2024-07-18
    claude-sonnet:
      provider: anthropic
      provider_model: claude-sonnet-4-5

routes:
  - name: chat
    service: ai-svc
    match:
      path:
        type: prefix
        value: /v1
    action:
      type: ai

services:
  - name: ai-svc
    upstream: openai-pool
```

### Providers

| Field | Default | Description |
|---|---|---|
| `name` | (required) | Provider name, referenced by model aliases. Unique within the `ai:` block. |
| `kind` | (required) | Wire dialect: `openai`, `anthropic`, or `gemini`. |
| `upstream` | (required) | Name of the upstream that carries this provider's transport (endpoints, TLS, timeouts, connection pooling, circuit breaking). |
| `auth.header` | (required with `auth`) | Header name the provider expects (`Authorization`, `x-api-key`, `x-goog-api-key`). |
| `auth.value` | (required with `auth`) | Header value, verbatim. Use a `${...}` [secret reference](./secrets) (env var or file); inline values are redacted in every config echo. Omit `auth` entirely for providers that need none (for example a local OpenAI-compatible endpoint on an internal network). |

Notes on providers:

- Because a provider names a standard upstream, everything upstreams
  get applies: multiple endpoints with load balancing, per-upstream
  TLS trust, timeouts, and circuit breaking.
- The `openai` kind also speaks to OpenAI-COMPATIBLE servers (vLLM,
  Ollama's compatibility endpoint, and others): point the upstream at
  one of those and no other change is needed.

### Models

The `models` map is the alias table your clients see. The key is the
`model` value clients put in their request body; `provider` names an
`ai.providers` entry; `provider_model` is what dwara sends to that
provider instead of the alias.

Changing an alias (or adding one) is a config reload -- the next
request uses the new mapping, with no restart.

### The route

A route with `action: { type: ai }` accepts OpenAI chat-completions
POST bodies. The request's `model` field selects the provider through
the alias table. The route's `service` is required by the schema but
is not dialed for `ai` routes.

## Pointing clients at the gateway

Any OpenAI SDK works: set the base URL to the gateway route and use
your alias as the model name.

```sh
curl http://gateway:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{
        "model": "claude-sonnet",
        "messages": [{"role": "user", "content": "hello"}],
        "max_tokens": 64
      }'
```

The response is the OpenAI response shape regardless of the provider
that served it:

```json
{
  "id": "msg_01X...",
  "object": "chat.completion",
  "model": "claude-sonnet",
  "choices": [
    {
      "index": 0,
      "message": {"role": "assistant", "content": "Hi! How can I help?"},
      "finish_reason": "stop"
    }
  ],
  "usage": {"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14}
}
```

Tool calling works end to end: tool definitions, tool calls in
assistant replies, and tool results are translated to each provider's
native form. Requests may also carry images as `data:` URIs (as the
OpenAI SDKs send them); remote image URLs are supported for OpenAI
only.

Request parameters specific to one provider's API (for example
OpenAI's `seed` or `response_format`) pass through when the serving
provider is OpenAI or an OpenAI-compatible server, and are dropped
for Anthropic and Gemini.

## Streaming

Send `"stream": true` and the response streams back as
`text/event-stream`: each provider chunk is translated to the OpenAI
chunk shape and forwarded as it arrives — the gateway does not wait
for the provider to finish, so the first tokens reach your client at
the provider's own pace.

What clients receive, regardless of which provider served the call:

- `chat.completion.chunk` frames with your model alias, in order.
- A terminal usage frame (`"choices": []` with a `usage` object) when
  the provider reported token usage. Token counts are
  PROVIDER-REPORTED ONLY — the gateway never estimates. Usage
  reporting is requested from the provider even when the client did
  not ask, so the counts are always available for metrics.
- A final `data: [DONE]` frame. The gateway writes this terminator
  itself for every provider, so the stream shape is identical across
  OpenAI, Anthropic, and Gemini.

If the provider dies mid-stream, already-received content stands and
the stream ends cleanly with an error chunk
(`provider_stream_aborted`) followed by `data: [DONE]` — the
connection is not reset. Failover (see below) applies only BEFORE the
stream starts; once chunks are flowing, the serving provider is
committed.

Streaming metrics (per provider):

- `dwara_ai_stream_chunks_total` — forwarded chunks.
- `dwara_ai_first_token_seconds` — time from request to the first
  forwarded chunk (the number streaming consumers feel).
- `dwara_ai_stream_duration_seconds` — total stream duration.
- `dwara_ai_tokens_total` — the stream's provider-reported usage,
  attributed to the serving provider (and canary version).

## Failover and canary

A model alias can do more than name one provider. Two optional
additions control availability and rollout — but not both on the same
alias.

### Failover chains

```yaml
ai:
  models:
    chat:
      provider: openai
      provider_model: gpt-4o-mini-2024-07-18
      failover:
        - provider: anthropic
          provider_model: claude-sonnet-4-5
```

When the serving provider answers 429 or a 5xx, is unreachable, or
rejects the conversation in its dialect, the gateway retries the next
entry in the chain — up to 4 alternates. The client sees one response
and nothing about a failed attempt: providers are only answered after
the gateway has their full response. Deterministic provider errors
(a 400, an invalid key, an unknown model) are NOT retried on another
provider — another provider would only re-diagnose them. If every
entry fails, the client receives the LAST provider's answer.

Use failover when one logical model must stay up across provider
outages. Note that every extra entry adds a full provider round-trip
to a failing request's latency — that is why the bound is 4.

### Canary splits

```yaml
ai:
  models:
    summarize:
      provider: openai
      provider_model: placeholder    # unused when canary is present
      canary:
        - version: stable            # the attribution label
          weight: 9
          provider: openai
          provider_model: gpt-4o-mini-2024-07-18
        - version: canary
          weight: 1
          provider: anthropic
          provider_model: claude-haiku-4-5
```

Traffic for the alias splits across 2..=8 versions by a deterministic
weighted hash of the request id: the same request id always lands on
the same version, and the split follows the configured ratios over
many requests. Versions may live on different providers.

To ramp a canary, RE-BALANCE the weights (90/10 to 95/5, keeping the
total constant) and reload the config — the next requests use the new
split, no restart needed. Growing one side alone also works but
reshuffles which ids land where; re-balancing moves the fewest
requests between versions.

### What you observe

- `dwara_ai_requests_total{provider,route,outcome,version}` — one
  outcome per provider ATTEMPT: a failed-over request shows
  `provider_error` on the failing provider and `success` on the one
  that served. The `version` label is the canary version name, or
  `default` for aliases without a split.
- `dwara_ai_tokens_total{provider,kind,version}` — token usage
  attributed to the provider and version that actually served.
- The access log's `attempts` field is the candidate number that
  succeeded (1 = the primary answered).

An alias cannot declare both `failover` and `canary`: failover would
retry a canary request onto the stable version and silently undo the
experiment. Run the failover chain and the canary split on separate
aliases.

## Routing policies

Routing policies (DW-085) are within-request escalation and
latency-vs-cost selection, composed over the DW-076 routing
foundation. Unlike failover (which retries across providers on
failure), a routing policy chooses which model to call based on the
prompt's complexity or a cost/latency tradeoff.

A model alias with a `routing_policy` cannot also declare `failover`
or `canary` (mutual exclusivity). The policy is evaluated per request
and returns the candidate list to walk.

### Fallback chain (cheap-first escalation)

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

### Latency-vs-cost routing

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

### Metrics

- `dwara_ai_routing_policy_escalations_total{policy}` -- FallbackChain
  escalations (complex prompt -> expensive model).
- `dwara_ai_routing_policy_cheap_total{policy}` -- FallbackChain
  cheap-model selections.
- `dwara_ai_routing_policy_latency_cost_selections_total{policy}` --
  LatencyCost selections.

## Prompt experimentation

Prompt experimentation (DW-086) adds prompt versioning, A/B model
comparison, regression evals, and feedback ingestion to the AI
gateway. All four live under the `ai.experiments` config block and
are OFF by default (no `ai.experiments` block = no experimentation
surface).

### Prompt versioning

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

### A/B model comparison

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

### Regression evals

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

### Feedback ingestion

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

### Verdict computation

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

### Metrics

- `dwara_ai_experiment_variant_selections_total{experiment,variant}` --
  A/B test variant selections (DW-086). `experiment` is the A/B test
  name; `variant` is the selected variant name. Both labels are
  config-bounded. No consumer label (cardinality rule).

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
  data: {"error":{"code":"ai_budget_exceeded","message":"the token budget for this window is exhausted; the stream was cut off","request_id":"req-...","type":"rate_limit_error"}}

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
not priced (fail-open, never a crash). Pricing changes take effect on
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

The scheduled usage-report export (DW-120) carries spend columns in
both CSV and JSON output: `prompt_tokens`, `completion_tokens`,
`total_tokens`, and `cost_micros` per consumer. The JSON statement
additionally includes a `spend_by_model` array breaking down tokens
and cost per model for the window. CSV is RFC 4180 compliant;
Parquet is deferred to a future release (the seam is documented for
billing pipelines that need columnar output).

## Prompt and response logging

Opt-in capture of AI prompts and responses with PII redaction,
sampling, and retention. Capture is OFF by default (privacy-first);
when on, a redaction pass scrubs PII and secrets before storage,
sampling controls volume, and retention ages records out.

### Configuration

```yaml
ai:
  logging:
    enabled: true
    sample_rate: 0.01          # capture 1% of requests
    retention_secs: 604800     # 7 days
    redaction:
      patterns:                # custom patterns beyond the built-ins
        - "ACME-\\d{6}"
      replacement: "[REDACTED]"
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Master switch. Off by default (privacy-first). |
| `sample_rate` | `1.0` | Fraction of requests to capture (0.0 to 1.0). Sampling is deterministic by request id -- the same request id always captures or skips. |
| `retention_secs` | `604800` (7 days) | Records older than this are deleted by the analytics maintenance tick. |
| `redaction.patterns` | (empty) | Additional regex patterns to scrub beyond the built-in PII patterns. |
| `redaction.replacement` | `[REDACTED]` | String that replaces redacted content. |

### Per-consumer toggle

A consumer can override the global setting:

```yaml
consumers:
  - name: acme
    credentials:
      - type: api_key
        key: ${ACME_KEY}
    ai_logging: false          # disable even if global is on
```

`ai_logging: false` disables capture for that consumer even when the
global `ai.logging.enabled` is true. `ai_logging: true` enables it
even when the global is off. Omit the field to inherit the global
setting.

### PII redaction

Built-in patterns (always active when logging is on):
- Email addresses
- Phone numbers (US and international)
- API keys (OpenAI `sk-`, Anthropic, GitHub, Slack, AWS AKIA, Bearer tokens)
- Credit card numbers

Custom patterns from config are applied alongside the built-ins. The
redaction pass runs on all string values in the serialized prompt and
response JSON before storage -- no PII reaches the log store.

### Querying logs

Prompt logs are queryable via the admin API:

```
POST /analytics/prompt-logs
{
  "from_ms": 1693526400000,
  "to_ms": 1693612800000,
  "consumer": "acme",
  "limit": 100
}
```

The response is one row per captured request with: request id,
consumer, route, provider, model, version, redacted prompt JSON,
redacted response JSON, and a stream flag.

### Streaming

For streaming responses, the prompt is captured and redacted in full.
The response is marked as `{"streamed": true}` -- the full streamed
content is not reassembled for logging (that would require buffering
the entire stream, contradicting the zero-buffer design).

## Model governance

Per-team model allowlists control which model aliases each team may
call, and a shadow audit records every model usage (allowed and
denied) for review.

### Configuration

```yaml
ai:
  governance:
    team_allowlists:
      acme-ai-budget: [gpt-4o-mini, claude-haiku]  # low-cost only
      enterprise-team: [gpt-4o, claude-sonnet, gpt-4o-mini]
    audit: true
```

The key in `team_allowlists` is a POLICY name -- the same policy that
attaches to consumers via `policies: [...]`. A consumer attaching a
policy with an allowlist may only call the listed model aliases. When
multiple policies with allowlists attach to a consumer, the model
must be in ALL of them (deny-wins, the same principle as AuthZ).

| Field | Default | Description |
|---|---|---|
| `team_allowlists` | (empty) | Map of policy name to allowed model aliases. |
| `audit` | `false` | When true, record every model usage (allowed and denied) for shadow audit. |

### Enforcement

The governance check runs AFTER the request body is parsed (the model
alias is in the body) and BEFORE the provider is called. A denied
request returns `403` with the OpenAI error shape:

```json
{
  "error": {
    "code": "model_denied_by_policy",
    "message": "model 'gpt-4o' is not allowed for this team",
    "request_id": "req-..."
  }
}
```

No provider tokens are spent on a denied request. Consumers with no
allowlist policy attached are allowed (fail-open).

### Audit

When `audit: true`, every AI request (allowed and denied) is recorded
in the governance audit log with: consumer, team (policy name), model
alias, verdict (allow/deny), and reason. Audit events are queryable
via the admin API:

```
POST /analytics/governance-audit
{
  "from_ms": 1693526400000,
  "to_ms": 1693612800000
}
```

Denials are counted in `dwara_ai_governance_denied_total{reason}`.

## Guardrails

Guardrails (DW-082) are pattern-based checks that inspect prompts and
responses for prompt-injection attempts, PII, banned content, and
output-schema conformance. They run as a middleware chain on the AI
proxy action, AFTER governance and BEFORE the provider call (prompt
phase) and AFTER the provider response is parsed (response phase).

Guardrails are OFF by default (no `ai.guardrails` block). When enabled,
each rule is compiled once at dataplane refresh and swapped atomically
on reload -- a guardrail change applies to the next request with no
restart.

### Configuration

```yaml
ai:
  guardrails:
    rules:
      - name: block-injection
        kind: injection
        action: block
        phase: prompt
      - name: redact-pii
        kind: pii
        action: redact
        phase: prompt
      - name: block-banned
        kind: banned
        action: block
        phase: response
        patterns:
          - '(?i)forbidden_word'
          - '(?i)another_banned_phrase'
      - name: enforce-schema
        kind: schema
        action: block
        phase: response
        schema:
          type: object
          properties:
            result:
              type: string
          required: [result]
```

| Field | Values | Notes |
|---|---|---|
| `kind` | `injection` / `pii` / `banned` / `schema` | What the rule checks |
| `action` | `block` / `redact` / `log` | `redact` is prompt-phase only; `log` is dry-run (records and continues) |
| `phase` | `prompt` / `response` / `both` (default) | When the rule runs |
| `patterns` | list of regex strings | Custom patterns; `injection` and `pii` also have built-in patterns |
| `schema` | JSON Schema object | Required for `kind: schema`; validated with the `openapi_validation` feature |
| `policies` | list of policy names | Empty = applies to all consumers; non-empty = only consumers with a matching policy |

### Kinds

- **Injection**: built-in patterns target explicit instruction-override
  phrases ("ignore previous instructions", "disregard the above", role-
  injection `"role":"system"`). Custom patterns extend the set. The
  built-in set is deliberately conservative (phrase-level, not keyword-
  level) to keep the benign-traffic false-positive rate near zero.
- **PII**: built-in patterns match structured PII (email, phone, API
  key, credit card). The `redact` action scrubs matches using the
  DW-081 Redactor (consistent PII scrubbing across logging and
  guardrails). Custom patterns extend the detection set.
- **Banned**: entirely deployment-defined (no built-in patterns). The
  operator supplies the regex set. Runs on both prompt and response
  text; for streaming responses, banned-content checks run per-chunk
  and cut the stream off on a match.
- **Schema**: validates the response text as JSON against a JSON
  Schema. Non-JSON responses are treated as violations. Requires the
  `openapi_validation` feature; without it, schema rules are inert
  (always allow). Response-phase only (partial streaming content
  cannot be validated).

### Actions

- **block**: returns a 400 `guardrail_blocked` (or
  `response_schema_violation` for schema kind). The request never
  reaches the provider (prompt phase) or the response never reaches
  the client (response phase).
- **redact**: scrubs the matched content from the prompt and continues
  (prompt-phase only). PII uses the DW-081 Redactor; other kinds use
  a generic regex replace with `[REDACTED]`.
- **log**: dry-run mode. Records the match via structured logging and
  continues. Use this to measure the false-positive rate on benign
  traffic before switching to `block`.

### Policy scoping

A rule with an empty `policies` list applies to ALL consumers. A rule
with a non-empty list applies only to consumers whose attached policies
(consumer > route > service > listener > global) include at least one
listed name -- the same vocabulary the budgets and governance use.

### False-positive guidance

The guardrails are PATTERN-BASED heuristics, not ML classifiers.
Operators should tune the pattern sets per deployment and use the `log`
action to measure the false-positive rate on benign traffic before
switching to `block`. See the `ai::guardrails` module docs for the
false-positive profile of each kind and recommended thresholds.

## Semantic caching

Semantic caching (DW-083) caches AI responses by prompt embedding
similarity: a paraphrased prompt within the similarity threshold
returns the cached response with no provider call and no token spend.
This is a significant cost saver for workloads with repeated or
paraphrased prompts.

Semantic caching is OFF by default and feature-gated behind the
`semantic_cache` cargo feature (the `hnsw_rs` HNSW ANN index adds
binary size). Build with `cargo build --features semantic_cache` to
enable it. Without the feature, the config is accepted but the cache
is inert (all requests hit the provider).

### Configuration

```yaml
ai:
  semantic_cache:
    enabled: true
    embedding_url: http://localhost:11434/v1/embeddings
    embedding_model: all-MiniLM-L6-v2
    embedding_dim: 384
    threshold: 0.85
    ttl_secs: 3600
    max_entries: 10000
    embedding_timeout_ms: 5000
    embedding_api_key: ${EMBEDDING_API_KEY}
```

| Field | Default | Notes |
|---|---|---|
| `enabled` | `false` | Must be true to activate the cache |
| `embedding_url` | (required) | URL of an OpenAI-compatible `/v1/embeddings` API |
| `embedding_model` | (required) | Model name passed to the embedding service |
| `embedding_dim` | (required) | Vector dimension; must match the embedding service's output |
| `threshold` | `0.85` | Cosine similarity threshold (0.0 to 1.0); higher = stricter |
| `ttl_secs` | `3600` | Entry TTL in seconds; stale entries are not returned |
| `max_entries` | `10000` | Max cached entries; when full, the cache resets (all evicted) |
| `embedding_timeout_ms` | `5000` | Timeout for the embedding service HTTP call |
| `embedding_api_key` | (optional) | Sent as `Authorization: Bearer <key>`; supports `${...}` refs |

### How it works

1. On a non-streaming AI request, AFTER guardrails and BEFORE the
   provider call, the gateway sends the prompt text to the configured
   embedding service and receives a vector embedding.
2. The embedding is searched against the HNSW ANN index for the
   nearest cached entry (k=1).
3. If the nearest entry's cosine similarity is >= the threshold, the
   entry is within TTL, and the model alias matches, the cached
   response is returned immediately (no provider call, no token
   spend).
4. On a cache miss, the request proceeds to the provider. After a
   successful response, the prompt embedding and response are stored
   in the cache (fire-and-forget -- the store never blocks the
   response path).

### Limitations

- **Non-streaming only**: streaming responses cannot be cached (the
  zero-buffer design precludes full content reassembly).
- **External dependency**: the embedding service must be reachable
  and responsive. If the embedding call fails or times out, the cache
  fails open (the request proceeds to the provider as a miss).
- **Per-model**: the cache is keyed by model alias; the same prompt
  with different models does not cross-hit.
- **No persistence**: the HNSW index and cached entries are in-memory
  only; they are lost on restart. The cache persists across config
  reloads (the index and entries survive; config updates in place).
- **Eviction**: when the cache reaches `max_entries`, the entire
  index is reset (all entries evicted). This is a simple full-reset
  policy; LRU eviction is a follow-up.

### Cost savings

The primary value of semantic caching is provider-call avoidance. For
a workload with N requests and M cache hits, the provider is called
N - M times. The cost savings are:

- **Token cost**: zero tokens spent on cache hits (the response is
  served from cache, not from the provider).
- **Latency**: cache hits skip the provider round-trip (the embedding
  call is typically faster than a full LLM completion).
- **Embedding cost**: each cache lookup and store makes one embedding
  API call. The embedding cost should be significantly cheaper than
  the LLM completion cost for the savings to be positive.

The `dwara_ai_semantic_cache_hits_total{model}` and
`dwara_ai_semantic_cache_misses_total{model}` metrics quantify the
hit rate; combine with `dwara_ai_cost_micros_total` to measure the
dollar savings.

## Errors

Errors come back in the OpenAI error shape, so SDK error handling
works unchanged:

```json
{
  "error": {
    "message": "the model 'gpt-5' does not exist",
    "type": "invalid_request_error",
    "code": "model_not_found",
    "request_id": "req-..."
  }
}
```

| Situation | Status | `code` |
|---|---|---|
| Over the [token budget](#token-budgets) (checked before the body is read) | 429 | `ai_budget_exceeded` |
| Model denied by [governance](#model-governance) policy | 403 | `model_denied_by_policy` |
| Prompt blocked by a [guardrail](#guardrails) rule | 400 | `guardrail_blocked` |
| Response blocked by a [guardrail](#guardrails) rule | 400 | `guardrail_blocked` or `response_schema_violation` |
| Unknown model alias | 404 | `model_not_found` |
| Malformed body or request | 400 | `invalid_json` / others |
| Request body over 16 MiB | 413 | `body_too_large` |
| Provider returned an error | the provider's status | the provider's code, when sent |
| Provider unreachable | 502 | `provider_unreachable` |
| Provider response could not be translated | 502 | `provider_malformed_response` and similar |

Provider errors pass through with the provider's own status code and
message (in the OpenAI error envelope), so client retry logic sees
the real 429/5xx. The budget 429 additionally carries a `Retry-After`
header (seconds until the denying window resets).

## Metrics

Metric families exported on `/metrics`:

- `dwara_ai_requests_total{provider,route,outcome,version}` --
  outcomes are `success`, `provider_error`, `transport_error`, and
  `translation_error`; `version` is the canary version that served,
  or `default` for aliases without a split.
- `dwara_ai_tokens_total{provider,kind,version}` -- token usage as
  REPORTED BY THE PROVIDER (`kind` is `prompt` or `completion`). The
  gateway does not estimate token counts.
- `dwara_ai_budget_denied_total{kind}` -- token-budget pre-check
  rejections and mid-stream cutoffs. A pre-check records the kind of
  the window that denied (`tokens` or `cost`); a mid-stream cutoff
  records `tokens`.
- `dwara_ai_cost_micros_total{provider,model}` -- total AI spend in
  micro-USD, attributed to the serving provider and provider model.
  No consumer label (cardinality stays config-bounded).
- `dwara_ai_governance_denied_total{reason}` -- model-governance
  denials (DW-084). `reason` is the denial reason string
  (config-bounded).
- `dwara_ai_guardrail_blocked_total{rule,kind}` -- AI guardrail
  blocks (DW-082). `rule` is the rule name; `kind` is the phase/kind
  label (`prompt`, `response`, `schema`, or `banned` for mid-stream
  banned-content cutoffs). Both labels are config-bounded.
- `dwara_ai_semantic_cache_hits_total{model}` -- semantic cache hits
  (DW-083). `model` is the model alias (config-bounded).
- `dwara_ai_semantic_cache_misses_total{model}` -- semantic cache
  misses (DW-083). `model` is the model alias (config-bounded).
- `dwara_ai_routing_policy_escalations_total{policy}` -- FallbackChain
  policy escalations (DW-085). `policy` is the policy name
  (config-bounded).
- `dwara_ai_routing_policy_cheap_total{policy}` -- FallbackChain
  cheap-model selections (DW-085).
- `dwara_ai_routing_policy_latency_cost_selections_total{policy}` --
  LatencyCost policy selections (DW-085).
- `dwara_ai_experiment_variant_selections_total{experiment,variant}` --
  A/B test variant selections (DW-086). `experiment` is the A/B test
  name; `variant` is the selected variant name. Both labels are
  config-bounded. No consumer label (cardinality rule).

## Validation and secrets

Configuration is checked at publish time. A config is rejected when:
an `ai` route action has no `ai:` block; a provider names an upstream
that does not exist; a model alias names a provider that does not
exist; or a provider's `auth.value` is a `${...}` reference that does
not resolve (the referenced environment variable or file must exist
in the gateway's environment). Rejected configs never interrupt the
running generation.

Inline auth values are replaced by a redaction placeholder in every
config echo (admin API, config dumps). Prefer `${...}` references so
the secret never appears in the config file at all; see
[Secrets](./secrets).
