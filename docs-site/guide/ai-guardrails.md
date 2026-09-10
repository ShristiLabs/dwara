# AI guardrails

Guardrails are pattern-based checks that inspect prompts and responses
for prompt-injection attempts, PII, banned content, and output-schema
conformance. They run as a middleware chain on the AI proxy action,
after governance and before the provider call (prompt phase) and after
the provider response is parsed (response phase).

Guardrails are OFF by default (no `ai.guardrails` block). When enabled,
each rule is compiled once at dataplane refresh and swapped atomically
on reload -- a guardrail change applies to the next request with no
restart.

A `dry_run` field on the guardrails block evaluates all rules and logs
would-be blocks without rejecting requests -- see
[Dry-run mode](#dry-run-mode) below.

## Configuration

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
| `schema` | JSON Schema object | Required for `kind: schema`; validated unconditionally |
| `policies` | list of policy names | Empty = applies to all consumers; non-empty = only consumers with a matching policy |

## Kinds

- **Injection**: built-in patterns target explicit instruction-override
  phrases ("ignore previous instructions", "disregard the above", role-
  injection `"role":"system"`). Custom patterns extend the set. The
  built-in set is deliberately conservative (phrase-level, not keyword-
  level) to keep the benign-traffic false-positive rate near zero.
- **PII**: built-in patterns match structured PII (email, phone, API
  key, credit card). The `redact` action scrubs matches using the
  prompt-logging Redactor (consistent PII scrubbing across logging and
  guardrails). Custom patterns extend the detection set.
- **Banned**: entirely deployment-defined (no built-in patterns). The
  operator supplies the regex set. Runs on both prompt and response
  text; for streaming responses, banned-content checks run per-chunk
  and cut the stream off on a match.
- **Schema**: validates the response text as JSON against a JSON
  Schema. Non-JSON responses are treated as violations. Schema
  validation runs unconditionally (no feature flag required).
  Response-phase only (partial streaming content cannot be validated).

### Streaming redaction

PII redaction applies to streaming responses as well as buffered
ones. Each streamed chunk is scrubbed before it reaches the client,
using the same Redactor as the prompt phase. This ensures PII in
streamed content is caught in real time without buffering the entire
response.

### MCP tool-call output inspection

When the MCP gateway returns tool-call results to the caller, the
guardrails engine inspects the output against configured schema rules
before returning it. A tool-call result that violates a schema rule
is rejected with an MCP JSON-RPC error, preventing malformed tool
output from reaching the agent.

## Actions

- **block**: returns a 400 `guardrail_blocked` (or
  `response_schema_violation` for schema kind). The request never
  reaches the provider (prompt phase) or the response never reaches
  the client (response phase).
- **redact**: scrubs the matched content from the prompt and continues
  (prompt-phase only). PII uses the prompt-logging Redactor; other
  kinds use a generic regex replace with `[REDACTED]`.
- **log**: dry-run mode. Records the match via structured logging and
  continues. Use this to measure the false-positive rate on benign
  traffic before switching to `block`.

## Policy scoping

A rule with an empty `policies` list applies to ALL consumers. A rule
with a non-empty list applies only to consumers whose attached policies
(consumer > route > service > listener > global) include at least one
listed name -- the same vocabulary the budgets and governance use.

## False-positive guidance

The guardrails are PATTERN-BASED heuristics, not ML classifiers.
Operators should tune the pattern sets per deployment and use the `log`
action to measure the false-positive rate on benign traffic before
switching to `block`. See the `ai::guardrails` module docs for the
false-positive profile of each kind and recommended thresholds.

## Dry-run mode

Set `dry_run: true` on the `ai.guardrails` block to evaluate all rules
and log would-be blocks without rejecting requests:

```yaml
ai:
  guardrails:
    dry_run: true
    rules:
      - name: block-injection
        kind: injection
        action: block
        phase: prompt
```

In dry-run mode, would-be blocks are:
- Counted in `dwara_policy_dry_run_total{phase="ai_guardrails",route}`.
- Logged with `code = "policy_dry_run"` and the rule that would have
  blocked.
- NOT returned to the client -- the request proceeds to the provider
  (prompt phase) or the response proceeds to the client (response
  phase).

This is separate from the per-rule `action: log` (which is a per-rule
dry-run). The block-level `dry_run` overrides all rules: even rules
with `action: block` are logged-only when the block-level dry-run is
on. Use the block-level dry-run to test the entire guardrails
configuration; use per-rule `action: log` to dry-run individual rules
while others enforce.

## Runnable demo

Run guardrails against a live gateway: `demos/07-ai-gateway/` in the
repository (test script: `test-07-guardrails.sh` -- an injection
prompt is blocked with 400, a benign one passes). The category README
covers prerequisites and teardown.

## See also

- [AI gateway](./ai-gateway)
