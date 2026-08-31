# Request hedging

Request hedging sends a speculative duplicate request after a timeout
and races the primary against the hedge. Whichever response arrives
first wins; the loser is cancelled. This cuts tail latency at the
99th percentile without increasing average load -- the hedge only
fires on requests that are already slow.

## When to use this

Use hedging when a small fraction of requests are slow due to
upstream variability (a slow replica, a hot shard, a GC pause). The
hedge gives you a second chance at a fast response from a different
endpoint, without paying the cost on requests that are already fast.

## Configuration

Hedging is configured per-upstream, inside the `retries` block:

```yaml
upstreams:
  - name: api
    load_balancer: round_robin
    endpoints:
      - { address: 10.0.0.1, port: 8080 }
      - { address: 10.0.0.2, port: 8080 }
    retries:
      buffer_max_bytes: 16384
      hedge:
        hedge_after_ms: 200
        hedge_max: 1
        retry_post: false
```

| Field | Default | Description |
|---|---|---|
| `hedge_after_ms` | `0` (disabled) | Milliseconds to wait before sending a hedge copy. `0` disables hedging. |
| `hedge_max` | `1` | Maximum number of speculative hedge copies. At most this many duplicates are in flight at once. |
| `retry_post` | `false` | Whether to hedge `POST` requests. By default only idempotent methods (GET, HEAD, OPTIONS, TRACE, PUT) are hedged. |

## Requirements

Hedging requires:

- **`buffer_max_bytes > 0`**: the request body must be replayable to
  send a hedge copy. Set `buffer_max_bytes` on the `retries` block to
  enable body buffering (up to the configured cap).
- **Idempotent semantics**: by default only idempotent methods are
  hedged. Enable `retry_post: true` only if your upstream handles
  duplicate POSTs safely.

## How it works

1. The primary request is sent to the first endpoint.
2. If no response arrives within `hedge_after_ms`, a hedge copy is
   sent to a different endpoint.
3. Whichever response arrives first wins. The other request is
   cancelled.
4. Up to `hedge_max` hedge copies may be sent (each to a different
   endpoint), spaced `hedge_after_ms` apart.

The hedge copy goes to a **different** endpoint than the primary --
this is what makes hedging effective against per-endpoint tail
latency.

## Interaction with retries

Hedging is orthogonal to retries. Retries fire on errors; hedging
fires on slowness. Both can be configured on the same upstream:

```yaml
upstreams:
  - name: api
    retries:
      attempts: 2
      buffer_max_bytes: 16384
      hedge:
        hedge_after_ms: 200
        hedge_max: 1
```

A request that times out the hedge may still be retried if the final
response is an error.
