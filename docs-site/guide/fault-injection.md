# Fault injection

Fault injection deliberately aborts or delays a percentage of
requests for testing. The abort fault immediately returns a fixed
HTTP status code instead of forwarding the request; the delay fault
pauses for a fixed duration before forwarding it.

Because the faults are injected at the gateway, you control the
failure rate precisely and only on the routes you configure --
injected failures do not depend on the upstream actually being
unhealthy.

## When to use this

Use fault injection to test client-side resilience. Inject 503s or
delays to verify your clients retry, fall back, or degrade
gracefully.

Fault injection is also a natural companion to the gateway's own
resilience features -- [timeouts](./timeouts),
[retries](./retries), [circuit breaking](./circuit-breaking),
[health checks](./health-checks), and
[rate limiting](./rate-limiting). Inject a controlled failure rate
and observe how the full stack behaves under failure.

## Configuration

Configure `fault_injection` on a route to abort or delay a
percentage of requests:

```yaml
routes:
  - name: api
    service: api-service
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy }
    fault_injection:
      abort:
        percentage: 10
        status: 503
      delay:
        percentage: 20
        fixed_ms: 5000
```

### Abort

The abort fault immediately returns the specified HTTP status code
instead of forwarding the request:

| Field | Default | Description |
|---|---|---|
| `percentage` | (required) | Percentage of requests to abort (0-100). |
| `status` | `503` | HTTP status code to return. |

### Delay

The delay fault pauses for a fixed duration before forwarding the
request:

| Field | Default | Description |
|---|---|---|
| `percentage` | (required) | Percentage of requests to delay (0-100). |
| `fixed_ms` | (required) | Fixed delay in milliseconds. |

## How it works

Abort and delay are independent -- both can be configured on the
same route. A request that is both aborted and delayed is aborted
(the delay is moot).

## Combining with mirroring

Fault injection can be combined with [mirroring](./mirroring) on
the same route. Mirroring happens before fault injection, so the
mirror upstream receives the request regardless of whether the
primary is faulted.

## Runnable demo

Feel an injected fault: `demos/03-resilience/` (test script:
`test-10-fault-injection.sh`) in the repository calls a route with
a 100 ms delay fault and asserts the 200 arrives late. The category
README covers prerequisites and teardown.
