# Distributed Redis rate limiter

The default rate limiter is local and in-memory: each gateway instance
keeps its own per-key GCRA buckets. This is correct for a single
instance, but two or more instances behind a load balancer each get
their own independent budget, so the effective limit is multiplied by
the instance count.

The distributed Redis rate limiter (DW-031, enterprise feature) moves
the bucket state to Redis so every instance shares one limit. The same
GCRA algorithm runs, but the theoretical arrival time (TAT) for each
key lives in Redis and is updated atomically via a Lua script in a
single round-trip.

## Requirements

All three conditions must hold for the Redis limiter to activate:

1. The `ent` cargo feature is compiled in
   (`cargo build --features ent`).
2. The config carries a `redis_rate_limiter` block.
3. The loaded license grants the `redis_rate_limiter` feature claim.

When any condition is missing, the block is accepted but inert and the
local in-memory limiter is used. A one-line notice is logged at
startup.

## Configuration

Add a `redis_rate_limiter` block to your gateway config:

```yaml
gateway:
  redis_rate_limiter:
    url: redis://127.0.0.1:6379
    fail_open: true           # optional, default true
    key_prefix: "dwara:rl:"   # optional, default "dwara:rl:"
    connection_timeout_ms: 1000  # optional, default 1000, range 100..=30000
    key_ttl_s: 3600           # optional, default 3600, range 60..=86400
```

| Field | Default | Range | Description |
|---|---|---|---|
| `url` | required | n/a | Redis connection URL (e.g. `redis://host:6379`). |
| `fail_open` | `true` | bool | When Redis is unreachable: `true` lets requests through (no rate limiting); `false` rejects with 429. |
| `key_prefix` | `dwara:rl:` | non-empty string | Prefix for rate-limit keys in Redis. |
| `connection_timeout_ms` | `1000` | 100..=30000 | Timeout for the initial connection at startup. |
| `key_ttl_s` | `3600` | 60..=86400 | Minimum TTL for rate-limit keys in Redis (stale keys auto-expire). |

## How it works

The limiter uses the same GCRA (Generic Cell Rate Algorithm) as the
local limiter. For each rate-limit check:

1. The key is built from the policy's selectors (e.g. `ip`,
   `ip+route`, `consumer+route`) exactly as the local limiter does.
2. A Lua script runs atomically in Redis: it reads the key's TAT,
   computes the new TAT, and writes it back in a single round-trip.
3. The script returns whether the request is allowed, the remaining
   budget, and the retry-after duration.

The Lua script is atomic (Redis executes it as a single command), so
two gateway instances checking the same key at the same time will
serialize correctly through Redis.

## Fail-open vs fail-closed

When Redis is unreachable (network error, timeout, Redis down):

- **`fail_open: true`** (default) -- the request is allowed with no
  rate limiting. This is the safer default for availability: a Redis
  outage should not take down the gateway. The limiter logs a warning
  and falls back to allowing all traffic.
- **`fail_open: false`** -- the request is rejected with 429. Use this
  when hard limits matter more than availability (e.g. compliance
  requirements).

At startup, if the Redis connection cannot be established:

- `fail_open: true` -- the gateway starts with the local rate limiter
  and logs a warning.
- `fail_open: false` -- the gateway refuses to start (exit 1).

## Key expiry

Each rate-limit key in Redis carries a TTL so stale keys
auto-expire. The Lua script sets an EXPIRE based on the burst
tolerance (the time it takes a fully-spent bucket to refill); the
`key_ttl_s` config value is a floor that ensures cleanup even for
long-burst windows.

## Connection pooling

The limiter uses `redis::aio::ConnectionManager` -- a multiplexed
connection that clones cheaply (Arc-based) and reconnects
automatically on failure. The connection is established once at
startup and cloned per-rule at engine compile time. Reloads recompile
the rate-limit engine with the same connection.
