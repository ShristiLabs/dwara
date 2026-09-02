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
| `schema` | JSON Schema object | Required for `kind: schema`; validated with the `openapi_validation` feature |
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
  Schema. Non-JSON responses are treated as violations. Requires the
  `openapi_validation` feature; without it, schema rules are inert
  (always allow). Response-phase only (partial streaming content
  cannot be validated).

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

## See also

- [AI gateway](./ai-gateway)
