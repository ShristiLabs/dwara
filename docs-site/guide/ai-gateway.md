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

::: info Status
Non-streaming chat completions are fully supported. Streaming
(`"stream": true`) is answered with HTTP 400
`streaming_not_supported` for now; the streaming pipeline is a
planned feature and this page will be updated when it lands.
:::

## When to use this

Use the AI gateway when:

- You want to switch or combine LLM providers without changing client
  code.
- Provider credentials should live in one place (the gateway) instead
  of in every client.
- You want gateway metrics for AI traffic (requests per provider,
  token usage) alongside your other routing metrics.

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
| Unknown model alias | 404 | `model_not_found` |
| Malformed body or request | 400 | `invalid_json` / others |
| `stream: true` | 400 | `streaming_not_supported` |
| Request body over 16 MiB | 413 | `body_too_large` |
| Provider returned an error | the provider's status | the provider's code, when sent |
| Provider unreachable | 502 | `provider_unreachable` |
| Provider response could not be translated | 502 | `provider_malformed_response` and similar |

Provider errors pass through with the provider's own status code and
message (in the OpenAI error envelope), so client retry logic sees
the real 429/5xx.

## Metrics

Two metric families are exported on `/metrics`:

- `dwara_ai_requests_total{provider,route,outcome}` -- outcomes are
  `success`, `provider_error`, `transport_error`, and
  `translation_error`.
- `dwara_ai_tokens_total{provider,kind}` -- token usage as REPORTED
  BY THE PROVIDER (`kind` is `prompt` or `completion`). The gateway
  does not estimate token counts.

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
