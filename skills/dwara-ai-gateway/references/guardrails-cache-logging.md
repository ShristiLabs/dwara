# Guardrails, semantic cache, logging, governance, experiments

## `ai.guardrails` - prompt/response inspection

```yaml
ai:
  guardrails:
    # dry_run: true               # logs-only mode for the whole block
    rules:
      - name: block-injection
        kind: injection           # injection | pii | banned | schema
        action: block             # block | redact | log
        phase: prompt             # prompt | response | both (default)
        patterns:                 # regexes added to the built-ins
          - "(?i)ignore.*instructions"
        # policies: [mobile-quota]  # scope rule to consumers carrying these
        #                           # policies; empty/omitted = all consumers
      - name: response-shape
        kind: schema              # response-phase only; requires `schema`
        schema:                   # JSON Schema; non-JSON text = violation
          type: object
```

- `kind`: `injection`, `pii` (built-in detector + Redactor), `banned`
  (pattern-driven), `schema` (JSON-Schema validation of the response text;
  validated unconditionally when present).
- `action`: `block` (reject), `redact` (prompt-phase only; PII uses the
  logging Redactor, others regex-replace `[REDACTED]`), `log` (per-rule
  dry-run).
- Streaming: banned-content checks run per-chunk and can cut the stream;
  PII redaction scrubs chunks in real time.
- MCP tool outputs are inspected against schema rules too (JSON-RPC error on
  violation).
- Dry-run observability: `dwara_policy_dry_run_total{phase="ai_guardrails"}`
  alongside `dwara::policy` warn logs.

## `ai.semantic_cache`

```yaml
ai:
  semantic_cache:
    enabled: true
    embedding_url: http://embeddings:8080/v1/embeddings  # OpenAI-compatible
    embedding_model: text-embedding-3-small
    embedding_dim: 1536
    threshold: 0.85              # cosine similarity to treat as a hit
    ttl_secs: 3600
    max_entries: 10000           # LRU bound
    embedding_timeout_ms: 5000
    embedding_api_key: ${EMBED_API_KEY}   # optional Bearer for the embedder
```

Behavior: two-tier lookup - exact prompt-hash tier first (no embedding
call), then vector (HNSW, k=1) cosine match >= `threshold`. Keyed per model
alias; chat-only. Fail-open: embedding-service errors never block a
request, they just skip the cache. Cached streams are replayed as SSE via a
1 MiB tee buffer - streams larger than 1 MiB are served but not cached.
In-memory: survives reloads, not restarts.

## `ai.logging` - prompt/response capture (opt-in)

```yaml
ai:
  logging:
    enabled: true
    sample_rate: 0.1
    retention_secs: 604800
    redaction:
      patterns: ["[0-9]{16}"]
      replacement: "[REDACTED]"
```

Streamed responses log the prompt fully but the response only as
`{"streamed": true}` (zero-buffer design). Query via
`POST /analytics/prompt-logs` (`from_ms`, `to_ms`, `consumer`, `limit`).
Per-consumer opt-out/in: `consumers[].ai_logging`.

## `ai.governance` - who may use which model

```yaml
ai:
  governance:
    audit: true
    team_allowlists:
      mobile-quota: [gpt-4o-mini, gpt-4o]   # keyed by consumer POLICY name
      bot-quota:      [gpt-4o-mini]
```

A request whose resolved alias is not allowed for any policy the consumer
carries -> `403 model_denied_by_policy` (pipeline phase 3, before any
provider call). Audit trail queryable via `POST /analytics/governance-audit`.
Remember to allowlist the *targets* of failover/canary/policy aliases, not
just the entry alias.

## `ai.experiments` - prompts, A/B, evals

```yaml
ai:
  experiments:
    prompts:
      customer-support:
        active: v1
        versions:
          v1: { system: "You are a helpful customer support agent." }
          v2: { system: "You are concise. Keep answers under 3 sentences." }
    ab_tests:
      support-model-test:
        variants:
          - { name: control,   model: gpt-4o-mini, weight: 50 }
          - { name: treatment, model: gpt-4o,      weight: 50, prompt: customer-support/v2 }
    evals:
      support-quality:
        prompt: customer-support/v1
        golden_set:
          - { input: "How do I reset my password?", expected: "reset", scorer: contains }
    feedback: { enabled: true }
```

Clients select a prompt version server-side with request fields `prompt:
<prompt-name>` + `prompt_variables: {...}`. A/B variants must reference
plain (non-policy, non-experiment) aliases. Runtime levers via admin API:
`PUT/GET/DELETE /experiments/prompt-overrides`, `POST
/experiments/feedback`, `POST /experiments/verdict`.
