# Synthetic Monitoring (DW-071)

## Overview

dwara includes built-in synthetic probes per route that measure
latency and uptime, feeding results into analytics and webhooks. This
is the proactive/synthetic side of SLO tracking -- it pairs with
DW-052 (SLO & error-budget export, M2), which derives SLO/burn-rate
metrics from real traffic. Synthetic monitoring lets an SLO be
tracked even on routes with little real traffic.

"The gateway measures the SLOs it exports." (section 6-Traffic
Intelligence)

## API

### ProbeSpec

A synthetic probe specification for a route:

```rust
use dwara_core::synthetic::ProbeSpec;
use std::time::Duration;

let spec = ProbeSpec {
    route_name: "api-v1".to_string(),
    url: Some("http://localhost:8080/api/v1/health".to_string()),
    method: "GET".to_string(),
    interval: Duration::from_secs(10),
    timeout: Duration::from_secs(5),
    expected_status: 200,
    headers: vec![],
    body: None,
    failure_threshold: 3,
};
```

### ProbeRunner

The coordinator that processes probe results and manages edge-
triggered alerting:

```rust
use dwara_core::synthetic::{ProbeRunner, ProbeResult, ProbeOutcome};

let mut runner = ProbeRunner::new(vec![spec]);

// Process a successful probe.
let result = ProbeResult {
    route_name: "api-v1".to_string(),
    started_at_ms: 1000,
    latency_ms: 50,
    status: 200,
    success: true,
    error: None,
};
match runner.process_result(&result) {
    ProbeOutcome::Success => { /* probe succeeded */ }
    ProbeOutcome::AlertFired => { /* alert! notify webhooks */ }
    ProbeOutcome::Recovered => { /* probe recovered from alert */ }
    ProbeOutcome::Failure(n) => { /* probe failed (n consecutive) */ }
}
```

## Probe lifecycle

1. At config publish time, the probe configuration is compiled into a
   `ProbeSpec` per route.
2. A background task runs each probe on its configured interval.
3. Each probe result is:
   - Recorded in the analytics store (as a synthetic access record).
   - Emitted as an event if the probe failed (for webhook delivery).
   - Used to update the route's SLO metrics.

## Alerting

Alerts are edge-triggered: the first failure that crosses the
`failure_threshold` fires an alert. Subsequent consecutive failures
do not re-fire until the probe recovers (a successful probe resets the
failure counter and clears the alerting state).

When a probe fails and crosses the threshold:
1. The `ProbeRunner::process_result` returns `ProbeOutcome::AlertFired`.
2. The caller emits an event on the event bus.
3. If a webhook is configured for the `probe_failed` event kind, the
   webhook deliverer sends a notification.

When a probe recovers:
1. `ProbeRunner::process_result` returns `ProbeOutcome::Recovered`.
2. The caller emits a recovery event.
3. If a webhook is configured, the webhook deliverer sends a
   recovery notification.

## Fields

### ProbeSpec

| Field | Type | Default | Description |
|---|---|---|---|
| `route_name` | string | -- | The route name this probe is attached to |
| `url` | Option<string> | None (use route URL) | The URL to probe |
| `method` | string | "GET" | The HTTP method |
| `interval` | Duration | -- | How often to run the probe |
| `timeout` | Duration | -- | How long to wait for a response |
| `expected_status` | u16 | 200 | The expected status code |
| `headers` | Vec<(string, string)> | empty | Headers to send |
| `body` | Option<string> | None | Request body |
| `failure_threshold` | u32 | 1 | Consecutive failures before alerting |

### ProbeResult

| Field | Type | Description |
|---|---|---|
| `route_name` | string | The route name |
| `started_at_ms` | u64 | When the probe was initiated (Unix ms) |
| `latency_ms` | u64 | Round-trip latency in ms |
| `status` | u16 | HTTP status code (0 if request failed) |
| `success` | bool | Whether the probe was successful |
| `error` | Option<string> | Error message if failed |

## Design (section 6-Traffic Intelligence)

The probe system is a coordinator, not a background thread. The
caller (the gateway's background task pool) is responsible for
scheduling probe runs (e.g. via `tokio::spawn` with a sleep loop per
probe). This keeps the probe system testable and runtime-agnostic.
