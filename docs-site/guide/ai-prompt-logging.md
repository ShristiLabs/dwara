# AI prompt and response logging

Opt-in capture of AI prompts and responses with PII redaction,
sampling, and retention. Capture is OFF by default (privacy-first);
when on, a redaction pass scrubs PII and secrets before storage,
sampling controls volume, and retention ages records out.

## Configuration

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

## Per-consumer toggle

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

## PII redaction

Built-in patterns (always active when logging is on):
- Email addresses
- Phone numbers (US and international)
- API keys (OpenAI `sk-`, Anthropic, GitHub, Slack, AWS AKIA, Bearer tokens)
- Credit card numbers

Custom patterns from config are applied alongside the built-ins. The
redaction pass runs on all string values in the serialized prompt and
response JSON before storage -- no PII reaches the log store.

## Querying logs

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

## Streaming

For streaming responses, the prompt is captured and redacted in full.
The response is marked as `{"streamed": true}` -- the full streamed
content is not reassembled for logging (that would require buffering
the entire stream, contradicting the zero-buffer design).

## See also

- [AI gateway](./ai-gateway)
