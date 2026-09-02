# AI governance and agent principals

The AI gateway enforces two layers of governance over model usage. Model
governance controls which model aliases each team may call through
per-team allowlists, with a shadow audit recording every usage (allowed
and denied) for review. Agent principals extend the consumer model with
typed identities -- bot principals that carry their own tool allowlists
and per-agent token budgets, with typed analytics attribution so agent
traffic is identifiable, governable, and billable separately from user
traffic.

## Agent principals & governance

Agent principals extend the consumer model with typed identities,
per-agent tool allowlists, per-agent token budgets, and typed analytics
attribution. An `agent` consumer is a bot principal with its own
governance rules; a `user` consumer (the default) is a human or
application caller.

### Consumer type

Each consumer declares a `type` field (`user` or `agent`, defaults
`user`). The type threads through the authenticated `Identity` into
analytics records (`ai_spend.consumer_type`, `mcp_tool_calls.
consumer_type`) so agent traffic is identifiable, governable, and
billable separately from user traffic.

```yaml
consumers:
  - name: agent-bot
    type: agent
    credentials:
      - type: api_key
        key: agent-key
    tool_allowlist: [search, fetch]
    token_budget:
      tokens_per_min: 1000
      scope: consumer
  - name: human-user
    type: user
    credentials:
      - type: api_key
        key: user-key
```

### Tool allowlist

A consumer with a non-empty `tool_allowlist` may only call the named
tools through the MCP gateway. `tools/call` for a non-allowlisted tool
is denied with `tool_not_in_agent_allowlist`; `tools/list` is filtered
to show only allowlisted tools. A consumer with an empty allowlist
(the default) has no restriction. Validation checks that every name
references a configured `ai.mcp.tools` entry and rejects an allowlist
when no `ai.mcp` block is configured.

### Per-agent token budget

A consumer with a `token_budget` gets its own direct token budget,
checked FIRST in the budget engine -- before the policy chain (the
most-specific budget wins). The budget is consumer-scoped by
definition; an anonymous caller cannot bind one. A consumer without a
`token_budget` falls through to the policy chain (route, service,
listener, global). Validation checks the same shape as a policy
`token_budget` (at least one window, positive values).

### Analytics

Analytics schema v8 adds a `consumer_type` column to `ai_spend` and
`mcp_tool_calls` (defaults `'user'`, additive ALTER TABLE migration).
Every spend record and tool-call record carries the consumer type for
typed attribution.

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
must be in ALL of them (deny-win, the same principle as AuthZ).

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

## See also

- [AI gateway](./ai-gateway)
