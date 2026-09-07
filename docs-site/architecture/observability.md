# Observability architecture

How Dwara emits signals that let operators see what the gateway is
doing. For operator-facing configuration, see
[Observability](../guide/observability). This page covers the runtime
architecture: the request ID, the access log, the metric families,
the trace spans, and how they correlate.

Observability is a cross-cutting substrate. Every request, every
upstream attempt, every error, and every AI call emits into it. The
unifying key is the request ID.

## The request ID

Every request gets a request ID, resolved at the very start of the
request pipeline:

```mermaid
flowchart LR
    A[Incoming request] --> B{X-Request-Id header?}
    B -->|present, valid| C[Use inbound value]
    B -->|absent or invalid| D[Generate:\nreq-{wallclock_ns:016x}-{counter:06x}]
    C --> E[Stamp on response\nX-Request-Id]
    D --> E
    E --> F[Stamp on error envelope\nerror.request_id]
    E --> G[Stamp on access log\nrequest_id]
    E --> H[Stamp on trace spans]
    E --> I[Stamp on analytics record]
```

### Resolution rules

- An inbound `X-Request-Id` is accepted if it is printable ASCII and
  at most 128 bytes.
- Otherwise a new ID is generated as
  `req-{wallclock_ns:016x}-{counter:06x}`.
- The resolved ID is stamped on the response (`X-Request-Id`), the
  error envelope, the access log, the trace spans, and the analytics
  record.

A separate `X-Correlation-Id` is resolved the same way (falling back
to the request ID) and stamped on the response. The correlation ID
lets a caller trace a request across multiple hops; the request ID
identifies this specific hop.

## The access log

Every request emits one structured JSON access log line at completion:

```json
{
  "request_id": "req-...",
  "method": "POST",
  "path": "/v1/chat/completions",
  "status": 200,
  "duration_ms": 142,
  "route": "ai-chat",
  "consumer": "team-a",
  "upstream": "openai-primary",
  "endpoint": "api.openai.com:443",
  "attempts": 1,
  "rate_limited": false,
  "broken": false,
  "shed": false
}
```

The fields are the minimum needed to reconstruct a request's outcome:
what was called, who called it, where it went, how many attempts it
took, and whether it was rate-limited, circuit-broken, or
load-shedded. The `target` is `dwara::access` for log filtering.

## Metric families

Dwara exposes Prometheus metrics at `/metrics`. The families are
grouped by subsystem:

### Request metrics

| Metric | Type | Labels |
|---|---|---|
| `requests_total` | counter | route, listener, status_class |
| `request_duration_seconds` | histogram | route |
| `active_requests` | gauge | (none) |

### Upstream / resilience metrics

| Metric | Type | Labels |
|---|---|---|
| `upstream_attempts_total` | counter | upstream, endpoint, status_class |
| `retries_total` | counter | upstream |
| `breaker_state` | gauge | upstream (0=closed, 1=open, 2=half-open) |
| `endpoint_health` | gauge | upstream, endpoint |
| `upstream_fail_open_picks` | gauge | upstream |

### Rate limiting / quotas

| Metric | Type | Labels |
|---|---|---|
| `rate_limited_total` | counter | route |
| `dwara_quota_denied_total` | counter | consumer, budget |
| `dwara_quota_used` | gauge | consumer, budget |
| `dwara_quota_limit` | gauge | consumer, budget |
| `dwara_rate_limiter_adaptive_factor` | gauge | policy |

### Policy / auth

| Metric | Type | Labels |
|---|---|---|
| `dwara_policy_dry_run_total` | counter | phase, route |
| `jwks_refresh_total` | counter | provider |

### AI metrics

| Metric | Type | Labels |
|---|---|---|
| `dwara_ai_requests_total` | counter | provider, route, outcome, version |
| `dwara_ai_tokens_total` | counter | provider, kind, version |
| `dwara_ai_cost_micros_total` | counter | provider, model |
| `dwara_ai_request_duration_seconds` | histogram | provider, route |
| `dwara_ai_tokens_per_request` | histogram | provider, model, kind |

### MCP / A2A

| Metric | Type | Labels |
|---|---|---|
| `dwara_mcp_tool_calls_total` | counter | tool, status |
| `dwara_mcp_tool_duration_seconds` | histogram | tool |
| `dwara_a2a_requests_total` | counter | agent, outcome |

### Config

| Metric | Type | Labels |
|---|---|---|
| `config_generation` | gauge | (none) |

### Cardinality

Metric labels are bounded to keep cardinality predictable:

- `route` and `listener` are config-defined, not request-derived.
- `upstream` and `endpoint` are config-defined.
- `consumer` is the resolved consumer name, not a free-form value.
- `status_class` is the class (`1xx`, `2xx`, ...), not the exact
  status code.
- AI `model` is the provider-side model id from the alias table, not
  the client-supplied alias.

This keeps the metrics registry bounded by config size, not by
traffic diversity.

## Tracing

Dwara emits tracing spans for the request path. Spans carry the
request ID and correlation ID, so a trace can be correlated to the
access log and error envelope.

```mermaid
flowchart TD
    A[request span\nrequest_id, correlation_id] --> B[authn span]
    A --> C[authz span]
    A --> D[rate_limit span]
    A --> E[upstream span\nupstream, endpoint, attempt]
    A --> F[ai span\nprovider, model] -- if AI route
    E --> G[retry span] -- if retried
```

### OTLP export

When built with the `otlp` feature, spans are exported via OTLP to a
collector endpoint. The export is asynchronous and bounded — a slow
or unavailable collector does not block the request path. See
[OTLP export](../guide/observability#otlp-export) for configuration.

## The error envelope

Every gateway-generated error response uses a unified JSON envelope:

```json
{
  "error": {
    "code": "rate_limited",
    "message": "rate limit exceeded",
    "request_id": "req-..."
  }
}
```

The `request_id` ties the error back to the access log, the trace
spans, and the analytics record. A client that receives an error can
report the `request_id` to the operator, who can then find the
single access log line, the trace, and the analytics record for that
request.

See [Error handling](./error-handling) for the full error code
catalog and the upstream error classification.

## The analytics store

The analytics store is a separate SQLite file from the state store.
It receives one record per request (the same fields as the access
log, plus resolved consumer, route, and AI token/cost data) and
maintains additive rollups at 1m, 5m, 1h, and 1d granularities with
per-granularity retention.

The analytics writer is fire-and-forget: if the write channel is
full, the record is dropped and counted, never blocking the request
path. This trades a small data-loss window under extreme load for
request-path isolation.

On Enterprise, the analytics store can be replaced by the federated
analytics sink, which streams records from edge data planes to the
controller via gRPC for fleet-wide aggregation. See
[Config, state, and extensions](./config-and-state) for the
`AnalyticsSink` extension trait.

## Per-DataPlane isolation

Each `DataPlane` instance owns its own metric registry. This means a
fleet of gateway instances does not share metric state — each
instance reports its own metrics, and an aggregator (Prometheus,
VictoriaMetrics, etc.) combines them. This keeps the registry
lock-free and bounded by the single instance's config.

## Redaction

Sensitive data is redacted at the observability boundary:

- Secrets are never logged; redacted placeholders are used.
- AI prompt logs (when enabled) run through a PII scrubber before
  storage.
- Access logs do not include request bodies or headers beyond what is
  needed for routing.
- Error envelopes do not include secret-derived values.

See [AI prompt logging](../guide/ai-prompt-logging) for the PII
scrubbing configuration.

## See also

- [Observability](../guide/observability) — operator configuration
  for metrics, logs, and traces.
- [Error handling](./error-handling) — the error envelope and code
  catalog.
- [Request pipeline](./request-pipeline) — where signals are emitted
  in the request path.
- [Config, state, and extensions](./config-and-state) — the
  `AnalyticsSink` extension trait.
- [AI gateway](./ai-gateway) — the AI-specific metric families.
