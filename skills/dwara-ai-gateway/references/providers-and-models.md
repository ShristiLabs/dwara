# Providers and model aliases

## `ai.providers[]`

```yaml
ai:
  providers:
    - name: openai                 # your handle, referenced by aliases
      kind: openai                 # adapter: openai | anthropic | gemini |
      upstream: openai-upstream    #   azure_openai | bedrock | a2a
      # path: /api/coding/paas/v4/chat/completions   # optional full request-path
      #        override (needed for OpenAI-compatible endpoints hosted at a
      #        subpath; applies to translated and passthrough traffic)
      auth:
        header: Authorization      # header name the provider expects
        value: ${OPENAI_AUTH_HEADER}  # WHOLE-value env ref; env contains
                                      # "Bearer sk-..." including the prefix
```

- `kind: openai` also covers vLLM/Ollama-style OpenAI-compatible endpoints
  (point `upstreams` at them; use `path` if they live under a subpath).
- Auth values are secret references (`${ENV}` / `${file:...}`); inline
  literals work but are redacted in `GET /config` echoes. Unresolved
  references reject the publish.
- Enterprise `credential_pool` (>= 2 credentials, `strategy:
  round_robin|weighted`, `quarantine_secs`, provider `Retry-After`
  honored): mutually exclusive with `auth`; **rejected at publish in OSS
  builds**. Check pool/quarantine status via `GET /ai/credential-pools`.

## `ai.models` - the alias table

Clients send `"model": <alias>`. Four mutually exclusive shapes:

```yaml
ai:
  models:
    # 1. Direct alias
    gpt-4o-mini:
      provider: openai
      provider_model: gpt-4o-mini

    # 2. Failover chain (max 4 alternates)
    gpt-4o:
      provider: openai
      provider_model: gpt-4o
      failover:
        - provider: anthropic
          provider_model: claude-sonnet-4-5

    # 3. Weighted canary (2..=8 versions; deterministic per request id)
    gpt-4o-canary:
      provider: openai
      provider_model: gpt-4o
      canary:
        - version: stable
          weight: 90
          provider: openai
          provider_model: gpt-4o
        - version: canary
          weight: 10
          provider: openai
          provider_model: gpt-4o-mini

    # 4. Routing policy (see routing-and-budgets.md)
    smart-router:
      provider: openai
      provider_model: gpt-4o-mini
      routing_policy: complexity-escalation
```

Rules:

- `failover` XOR `canary` XOR `routing_policy`; A/B tests (under
  `experiments`) reference plain aliases only and exclude all three.
- Failover triggers on 429/5xx-class errors, **not** deterministic failures
  (invalid key, unknown model, malformed request) - retrying those against
  another provider would just fail differently.
- If every tier fails, the client receives the last provider's response.
- Canary ramping = re-balancing weights (keep the campaign intent explicit);
  splits are deterministic by request id.

## Request surface details

- Accepted dialects at ingress: OpenAI chat-completions, Anthropic
  Messages, Gemini `generateContent`. Non-chat OpenAI endpoints can be
  passed through verbatim (`endpoint: embeddings|images|audio|moderation`
  on the route action; governance still checks `model`).
- `response_format` is translated per provider: passthrough on OpenAI,
  forced tool calls on Anthropic, `generationConfig.responseMimeType` /
  `responseSchema` on Gemini. Values: `text | json_object | json_schema`.
- Extra request fields: `prompt` + `prompt_variables` resolve server-side
  prompt templates (see `experiments.prompts` in
  guardrails-cache-logging.md).
- The gateway always requests usage from the provider even when the client
  didn't ask - budgets and spend accounting need it.

## Upstream transport notes

- One `upstreams[]` entry can be shared by several providers (the quickstart
  points openai + anthropic at the same transport upstream), but per-host
  timeouts should match the slowest use.
- `read_ms: 120000` floor for chat; streaming responses hold the read open.
- OAuth2 client-credentials toward the provider (token fetched + cached +
  forwarded as Bearer) is configured on the *upstream* via
  `oauth2_client_credentials` - useful for gateway-mediated IdPs, not for
  typical provider API keys.
