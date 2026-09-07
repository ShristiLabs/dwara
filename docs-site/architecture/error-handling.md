# Error handling

How Dwara formats errors for clients and classifies upstream failures.

## Unified error envelope

All gateway-generated error responses use a unified JSON envelope so
clients can parse errors programmatically without guessing the body
shape:

```json
{
  "error": {
    "code": "<machine-code>",
    "message": "<human-readable>",
    "request_id": "<request-id>"
  }
}
```

The `code` field is a stable machine-readable string; the `message` is
classification-only text that never leaks upstream internals. The
`request_id` matches the `X-Request-Id` response header and the access
log entry, so an operator can trace any error end-to-end.

## Gateway-generated errors

| Status | Code | When |
|---|---|---|
| 400 | `bad_request` | Framing ambiguity, GraphQL rejection, request validation failure |
| 401 | `unauthorized` | No valid credential found; includes `WWW-Authenticate` |
| 403 | `forbidden` | Authorization denial, WAF filter, anomaly score, WebSocket origin |
| 404 | `no_route` | No route matched (after listener/global rate limiting) |
| 405 | `method_not_allowed` | Method not in the route's `methods` allowlist |
| 413 | `request_too_large` | Route body cap exceeded |
| 429 | `rate_limit_exceeded` | Rate limit or consumer quota; includes `Retry-After` and `X-RateLimit-*` |
| 431 | `request_header_fields_too_large` | Route header count/bytes cap exceeded |
| 502 | `upstream_unavailable` | Endpoint refused, pool failure, no endpoints, pending cap |
| 503 | `upstream_circuit_open` | Circuit breaker open; includes `Retry-After` |
| 503 | `service_unavailable` | Gateway concurrency cap / load shedding |
| 504 | `upstream_timeout` | Connect or per-attempt read timeout |

## Upstream error classification

Upstream failure details are logged server-side only; the client sees
a classified status with no upstream internals:

| Cause | Status |
|---|---|
| Connect timeout / per-attempt read timeout | 504 |
| Endpoint refused / pool failure / no endpoints | 502 |
| Invalid upstream TLS configuration | 500 |

A **mid-body abort** (the upstream connection dies partway through a
response body already streaming to the client) is different: the
attempt already resolved its headers, so it is final — not retryable —
and any bytes already forwarded to the client end abruptly with no
synthesized tail (HTTP/1.1 truncation semantics). It is still reported
as a passive-health failure for the endpoint, so a chronically
flaky-mid-stream endpoint still gets ejected.

## See also

- [Request pipeline](./request-pipeline) — where each error status
  is produced in the pipeline.
- [Observability](../guide/observability) — access logs, metrics, and
  tracing for error diagnosis.
- [Traffic policy](../guide/traffic-policy) — retries, circuit
  breaking, and load shedding that produce 502/503/504.
