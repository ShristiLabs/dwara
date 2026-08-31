# Alert and event webhooks

Dwara can POST a small JSON notification to your HTTP endpoints when
gateway state changes: circuit breakers trip, endpoints leave and
re-enter rotation, and config generations publish or get rejected.
Point one at your incident tool, a chat relay, or your own collector.

## When to use this

Webhooks push a small JSON notification to your endpoints when gateway
state changes (a breaker trips, an endpoint is ejected, a config is
published or rejected) — point one at an incident tool, a chat relay,
or your own collector for real-time alerting.

```yaml
webhooks:
  - url: https://hooks.example.com/alerts
    events: [breaker_opened, endpoint_ejected, config_rejected]
    headers:
      X-Hook-Token: ${file:/run/secrets/hook-token}
    timeout_ms: 2000
    max_attempts: 3
    backoff_base_ms: 100
    backoff_cap_ms: 1000
```

## Events

| Kind | When | Payload fields |
| --- | --- | --- |
| `breaker_opened` | an upstream's [circuit breaker](https://en.wikipedia.org/wiki/Circuit_breaker_design_pattern) trips (a resilience pattern that stops sending traffic to a failing upstream) | `upstream`, `detail` (the rule: `consecutive_failures`, `error_ratio`, or `half_open_probe_failed`) |
| `breaker_half_open` | the cooling-off elapsed; the next request becomes a probe | `upstream` |
| `breaker_closed` | a half-open probe succeeded | `upstream`, `detail` (`half_open_probe_succeeded`) |
| `endpoint_ejected` | passive or active health removed an endpoint from rotation | `upstream`, `endpoint` |
| `endpoint_recovered` | an ejected endpoint is back in rotation | `upstream`, `endpoint` |
| `config_published` | a config generation was validated and published (startup, reload, admin API) | `generation`, `content_hash`, `route_count` |
| `config_rejected` | a config candidate was rejected; the running generation keeps serving | `issue_count`, `generation` (the one still running) |

The `events` list accepts exactly these spellings; an unknown kind is a
validation error (so is `quota_near_limit` — quota events arrive with
quota support, not yet in this milestone).

## The envelope

Every delivery is one POST with `Content-Type: application/json` and a
[`User-Agent`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent): `dwara-webhook` header:

```json
{
  "id": "evt-18f3c2a1b9d0-00000a",
  "kind": "breaker_opened",
  "timestamp": "2026-08-27T09:00:00.123Z",
  "gateway": "dwara-8213-18f3c2910b07",
  "payload": { "upstream": "billing", "detail": "error_ratio" }
}
```

- `id` is unique per gateway process and monotonically increasing — use
  it to deduplicate (delivery is [at-least-once](https://en.wikipedia.org/wiki/Reliability_(computer_networking)#Delivery_guarantees): a delivery may be retried, so a target can see the same event twice — deduplicate by id; a target that accepts a
  POST but drops the connection is retried).
- `timestamp` is [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339) UTC with millisecond precision.
- `gateway` identifies the emitting process (`dwara-<pid>-<boot time>`)
  so a fleet can tell instances apart.
- `payload` carries only bounded labels and numbers — never request
  data, never credentials.

The path and query of the configured URL are preserved, so
`https://hooks.example.com/alerts?source=dwara` delivers to
`/alerts?source=dwara`.

## Delivery behavior

- **Retries.** Transport failures and the statuses 429, 502, 503, and
  504 are retried up to `max_attempts` total attempts with [exponential backoff](https://en.wikipedia.org/wiki/Exponential_backoff) (waiting longer between each retry) (`backoff_base_ms`, doubling, capped at `backoff_cap_ms`). A
  seconds-form `Retry-After` header replaces the computed backoff for
  that wait. Any other non-2xx answer (4xx, 500, redirects — they are
  not followed) fails the delivery immediately.
- **One budget per delivery.** `timeout_ms` bounds the WHOLE delivery —
  connect, write, response, and every retry wait — so a slow or hung
  target can never occupy the gateway longer than that.
- **Never blocks the gateway.** Events are emitted onto a bounded
  in-process queue; a full queue drops the event (and counts the drop
  in `dwara_events_dropped_total`) rather than slowing a single
  request. At most 32 deliveries run concurrently; beyond that, events
  are dropped and counted, not queued.
- **Targets follow the config.** Targets are recompiled on every config
  generation — including re-resolving `${...}` header references — and
  apply to the next event after a reload.

Config changes to a webhook list validate like everything else: the URL
must be absolute `http(s)`, `events` must be non-empty and known, header
names/values must be legal, duplicate URLs are rejected, and the retry
knobs must be in bounds (`timeout_ms` 1-60000, `max_attempts` 1-10,
`backoff_cap_ms >= backoff_base_ms`).

## Secrets in headers

Header values follow the same [secret-reference
grammar](./secrets.md) as credentials: `${ENV_NAME}` and
`${file:/path}` resolve at config-compile time (every reload re-reads
them), and inline values are redacted in every config echo (the admin
API's `GET /config`). Prefer a reference for bearer tokens and signing
secrets — the config file then never holds the bytes.

## Egress posture

Webhook URLs are operator configuration, like upstream endpoints: the
gateway dials exactly what the config names, and there is no
private-address egress (outbound network traffic from the gateway) filter (an internal alerting listener on
`127.0.0.1` or `10/8` is a normal shape). `https://` targets verify
against the public CA root set; private-CA webhook targets are not
supported in this milestone.

## Metrics

| Metric | Type | Labels |
| --- | --- | --- |
| `dwara_webhook_events_total` | counter | `kind`, `outcome` |
| `dwara_events_dropped_total` | gauge | — |
| `dwara_events_emitted_total` | gauge | — |

`outcome` is `delivered` (2xx on some attempt), `failed` (retries
exhausted, non-retryable answer, or budget spent), or `dropped` (never
tried: envelope over the byte cap, or delivery concurrency saturated).
`dwara_events_dropped_total` counts events dropped at EMIT time — a
full queue or no deliverer running. See
[Observability: metrics](./observability#metrics).
