# Observability

Logs, request IDs, metrics, and error bodies share one goal: an operator
can correlate any client complaint to exactly one gateway request.

## Logs

The binary emits structured JSON on stdout, filtered by `DWARA_LOG`
(`RUST_LOG` syntax, default `dwara=info`). One access-log line per
completed request carries: timestamp, `request_id`, `method`, `path`,
`status`, `duration_ms`, `route`, `consumer`, `upstream`, `endpoint`,
`attempts`, and `rate_limited`/`broken`/`shed` flags. `route` is
`unrouted` for 404s and reserved paths; `consumer` is `anonymous`
without authentication.

`DWARA_ACCESS_LOG_SAMPLE` (0.0–1.0, default 1.0) sets the fraction of
**non-error** lines emitted — responses with status ≥ 500 are always
logged regardless of sampling, and an invalid value falls back to 1.0
so a broken knob can never silence error visibility.

**Redaction is exhaustive:** logged paths never include the query
string, and no credential material (`Authorization`,
`Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key` values, keys,
JWKS bodies) is ever logged.

## Request IDs

An inbound `X-Request-Id` is respected when it's printable ASCII of at
most 128 bytes; otherwise dwara generates one
(`req-<hex nanoseconds>-<counter>`). The resolved ID is echoed on every
response as `X-Request-Id` and appears in every log line, span, and
error body — use it as the single correlation key across client
reports, gateway logs, and (if enabled) traces.

## Metrics

`/metrics` serves Prometheus text format, reserved on every terminate
and cleartext listener just like `/healthz` (see
[Operations](./operations#health-endpoints)).

| Metric | Type | Labels |
| --- | --- | --- |
| `requests_total` | counter | `route`, `listener`, `status_class` |
| `request_duration_seconds` | histogram | `route` |
| `upstream_attempts_total` | counter | `upstream`, `endpoint`, `status_class` |
| `retries_total` | counter | `upstream` |
| `rate_limited_total` | counter | `route` |
| `shed_total` | counter | `priority` |
| `dwara_policy_dry_run_total` | counter | `phase`, `route` |
| `breaker_state` | gauge (0/1/2 = closed/open/half-open) | `upstream` |
| `endpoint_health` | gauge (1/0 = available/ejected) | `upstream`, `endpoint` |
| `upstream_fail_open_picks` | gauge | `upstream` |
| `active_requests` | gauge | — |
| `config_generation` | gauge | — |
| `jwks_refresh_total` | counter | `provider` |
| `dwara_rate_limiter_evictions_total` | gauge | — |
| `dwara_rate_limiter_live_keys` | gauge | — |

Label cardinality is deliberately config-bounded — there is no
consumer-name label anywhere, and the rate-limiter series are
aggregate/unlabeled even though the engine tracks many per-key cells
internally. `dwara_policy_dry_run_total` counts requests a
[dry-run policy](./maintenance#dry-run-preview-a-policy-before-enforcing-it)
would have rejected, by phase (`route_limits`, `authz`,
`rate_limit`, `load_shed`) and route — its log counterpart is the
`dwara::policy` warn event. A starter dashboard ships at
`grafana/dwara-overview.json`; import it in Grafana via
Dashboards → New → Import and point it at a Prometheus instance
scraping the gateway's `/metrics`.

## Error envelope

Every gateway-generated non-success response body (including the
reserved `/healthz`/`/readyz` paths) uses one shape:

```json
{"error":{"code":"no_route","message":"no route","request_id":"req-..."}}
```

`code` is a stable machine token, `message` is a human string that
never leaks upstream internals, and `request_id` ties the response to
logs and traces.

## Distributed tracing (OTLP)

Trace export over OTLP requires a build with the `otlp` cargo feature
(off by default to keep the release binary small):

```sh
cargo build -p dwara-bin --features otlp
```

Point it at a collector with `DWARA_OTLP_ENDPOINT` (e.g.
`http://collector:4318` — `/v1/traces` is appended, or a full
`.../v1/traces` URL is accepted as-is). In a default build, this
environment variable is reserved but inert — setting it has no effect
unless the binary was built with the feature.
