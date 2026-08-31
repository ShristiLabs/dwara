# Mirroring and fault injection

Mirroring sends a fire-and-forget duplicate of each request to a
separate mirror upstream -- the mirror response is discarded and
never impacts the client. Fault injection deliberately aborts or
delays a percentage of requests for testing.

## When to use this

- **Mirroring**: test a new upstream with real traffic before cutting
  over. Send a copy of every request (or a sample) to the new
  upstream and watch for errors without affecting users.
- **Fault injection**: test client-side resilience. Inject 503s or
  delays to verify your clients retry, fall back, or degrade
  gracefully.

## Mirroring

Configure `mirror` on a route to send a percentage of requests to a
mirror upstream:

```yaml
routes:
  - name: api
    service: api-service
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy }
    mirror:
      upstream: api-canary
      percentage: 100
```

| Field | Default | Description |
|---|---|---|
| `upstream` | (required) | Name of the upstream to receive mirrored (shadow) requests. |
| `percentage` | `0` | Percentage of requests to mirror (0-100). `0` mirrors nothing; `100` mirrors every request. |

The mirror upstream is separate from the route's service upstream.
The mirror request is sent in parallel with the primary; the mirror
response is discarded. The primary response is what the client
receives.

::: tip
Mirroring does not buffer the request body by default. The mirror
copy is sent with an empty body. If you need the body mirrored,
configure body buffering on the route.
:::

## Fault injection

Configure `fault_injection` on a route to abort or delay a percentage
of requests:

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

Abort and delay are independent -- both can be configured on the same
route. A request that is both aborted and delayed is aborted (the
delay is moot).

## Combining mirroring and fault injection

Both can be configured on the same route. Mirroring happens before
fault injection, so the mirror upstream receives the request
regardless of whether the primary is faulted.
