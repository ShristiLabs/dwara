# AI request failures

AI request failures cover errors specific to the AI gateway:
provider errors, translation errors, budget exhaustion, and
guardrail rejections.

## Symptoms

- Client receives an OpenAI-shaped error envelope with
  `error.code` indicating the failure type.
- Metrics show `dwara_ai_requests_total{outcome="..."}` increasing.
- The access log shows the AI route and provider.

## Likely causes

### Provider error (5xx from provider)

The upstream provider returned an error. The error code is
`provider_error`.

**Diagnose:**

```sh
# Check AI request metrics by outcome
curl -k https://127.0.0.1:2019/metrics | grep dwara_ai_requests_total
```

**Fix:** Check the provider's status page. If the provider is
rate-limiting, configure failover to another provider:

```yaml
ai:
  models:
    gpt-4o-mini:
      provider: openai
      provider_model: gpt-4o-mini-2024-07-18
      failover:
        - provider: azure
          provider_model: gpt-4o-deployment
```

### Translation error

The gateway could not translate the request or response between
the OpenAI facade and the provider's dialect. The error code is
`translation_error`.

**Diagnose:**

```sh
# Check AI request metrics for translation errors
curl -k https://127.0.0.1:2019/metrics | grep dwara_ai_requests_total | grep translation
```

**Fix:** This usually indicates a bug in the adapter or an
unsupported feature in the provider's dialect. Check the gateway
logs for the specific translation error. If the request uses
features the provider does not support (e.g., tool calls to a
provider that does not support them), switch to a provider that
does.

### Unknown model alias

The client requested a model alias that is not configured. The
error code is `unknown_model` (HTTP 404).

**Diagnose:**

```sh
# Check the configured model aliases
curl -k https://127.0.0.1:2019/config | jq '.ai.models | keys'
```

**Fix:** Add the missing model alias to the `ai.models` block, or
use a configured alias.

### Model denied by governance

The consumer's team is not allowed to use the requested model. The
error code is `model_denied_by_policy` (HTTP 403).

**Diagnose:**

```sh
# Check governance audit log
curl -k https://127.0.0.1:2019/analytics/governance-audit -X POST \
  -H 'Content-Type: application/json' \
  -d '{"from_ms": 0, "to_ms": 9999999999999}'
```

**Fix:** Add the model to the team's allowlist in the governance
config:

```yaml
ai:
  governance:
    team_allowlists:
      my-team: [gpt-4o-mini, gpt-4o]
```

### Guardrail rejection

The request was rejected by a guardrail rule. The error code is
`guardrail_blocked` (HTTP 400).

**Diagnose:**

```sh
# Check guardrail metrics
curl -k https://127.0.0.1:2019/metrics | grep dwara_guardrail
```

**Fix:** Check the guardrail configuration. If the guardrail is too
aggressive, use `action: log` (dry-run mode) to measure the
false-positive rate before switching to `block`:

```yaml
ai:
  guardrails:
    rules:
      - name: my-rule
        action: log  # dry-run: log but do not block
```

### AI budget exhausted

The consumer has exhausted its AI token or cost budget. The error
code is `ai_budget_exceeded` (HTTP 429).

**Diagnose:**

```sh
# Check AI budget metrics
curl -k https://127.0.0.1:2019/metrics | grep dwara_ai_budget
```

**Fix:** Increase the token budget or wait for the budget window
to reset. See [AI token budgets](../ai-token-budgets).

## See also

- [AI gateway](../ai-gateway)
- [AI guardrails](../ai-guardrails)
- [AI governance](../ai-governance)
- [AI token budgets](../ai-token-budgets)
