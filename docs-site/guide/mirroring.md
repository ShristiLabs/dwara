# Mirroring

Mirroring sends a fire-and-forget duplicate of each request to a
separate mirror upstream -- the mirror response is discarded and
never impacts the client. The primary response is what the client
receives, so mirroring is safe to run against live traffic.

Because the mirror sees real production requests, it is the most
realistic way to validate a candidate upstream before you shift any
traffic to it.

## When to use this

Use mirroring to test a new upstream with real traffic before
cutting over. Send a copy of every request (or a sample) to the new
upstream and watch for errors without affecting users. Once the
mirror looks healthy, shift live traffic over gradually with
[traffic splitting](./traffic-splitting).

## Configuration

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
| `timeout_ms` | `2000` | Hard timeout for the mirror request in milliseconds. If the mirror upstream does not respond within this duration, the mirror request is abandoned. The mirror is fire-and-forget, so this timeout never affects the primary request. |

## How it works

The mirror upstream is separate from the route's service upstream.
The mirror request is sent in parallel with the primary; the mirror
response is discarded. The primary response is what the client
receives.

::: tip
Mirroring does not buffer the request body by default. The mirror
copy is sent with an empty body. If you need the body mirrored,
configure body buffering on the route.
:::

## Combining with fault injection

Mirroring can be combined with [fault injection](./fault-injection)
on the same route. Fault injection is evaluated first; if an abort
fires, the request is short-circuited and no mirror request is sent.
If the fault injection does not abort (e.g. a delay only), the
mirror request is sent in parallel with the (delayed) primary.

## Runnable demo

Shadow traffic on a live gateway: `demos/03-resilience/` (test
script: `test-11-mirroring.sh`) in the repository mirrors 100% of a
test route to a shadow upstream and asserts the primary still
answers 200. The category README covers prerequisites and teardown.
