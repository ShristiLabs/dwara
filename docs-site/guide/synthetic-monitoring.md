# Synthetic monitoring

Synthetic monitoring runs built-in probes per route that measure
latency and uptime from the gateway's perspective. Probe results feed
into analytics and can trigger webhooks for alerting.

## When to use this

Use synthetic monitoring when:

- You want to know a route is broken before users report it.
- You need uptime and latency SLOs measured from the gateway's
  vantage point.
- You want to alert on consecutive failures (edge-triggered) rather
  than scraping metrics.

## Configuration

Configure probes per route in the top-level `synthetic` block:

```yaml
synthetic:
  probes:
    - route_name: api
      interval_ms: 5000
      timeout_ms: 2000
      failure_threshold: 3
    - route_name: health
      interval_ms: 10000
      timeout_ms: 1000
      failure_threshold: 2
```

| Field | Default | Description |
|---|---|---|
| `route_name` | (required) | The route to probe. The probe sends a request to this route's matched path. |
| `interval_ms` | `5000` | Milliseconds between probes. |
| `timeout_ms` | `2000` | Per-probe timeout in milliseconds. |
| `failure_threshold` | `1` | Consecutive failures before an alert fires. |

## How alerts work

Alerts are **edge-triggered**: a webhook fires once when the
consecutive failure count reaches `failure_threshold`, and again when
the route recovers. You will not get a webhook per failure -- only
the state transition.

The webhook payload includes:

```json
{
  "event": "probe_alert",
  "route": "api",
  "state": "alerting",
  "consecutive_failures": 3,
  "last_error": "timeout after 2000ms",
  "timestamp": 1718000000000
}
```

On recovery:

```json
{
  "event": "probe_recovered",
  "route": "api",
  "state": "healthy",
  "timestamp": 1718000005000
}
```

## Probe results in analytics

Probe results are written to the analytics store alongside real
traffic. You can query them via the analytics API with a filter on
the `synthetic` flag to distinguish probe traffic from user traffic.

## Interaction with health checks

Synthetic monitoring is distinct from active health checks:

- **Active health checks** probe upstream endpoints and feed the
  load balancer's health state (used for endpoint selection).
- **Synthetic monitoring** probes routes end-to-end (through the
  gateway) and feeds alerting/analytics.

Both can run simultaneously; they serve different purposes.
