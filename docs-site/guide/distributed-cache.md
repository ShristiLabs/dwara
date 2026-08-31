# Distributed cache

The distributed cache extends the built-in response cache with a
shared Redis backend, so all gateway instances share one cache. This
is an enterprise feature.

## When to use this

Use the distributed cache when:

- You run multiple gateway instances behind a load balancer and want
  cache hits to be shared across instances.
- You want cache entries to survive instance restarts.
- You want to invalidate cache entries across the fleet from one
  place.

## Enabling

Build with the `ent` feature:

```sh
cargo build --features ent
```

Configure the Redis cache store:

```yaml
cache:
  redis:
    url: redis://redis:6379
    key_prefix: dwara
    ttl_seconds: 300
```

| Field | Default | Description |
|---|---|---|
| `url` | (required) | Redis connection URL (`redis://host:port`). |
| `key_prefix` | `dwara` | Prefix for all cache keys (for namespace isolation). |
| `ttl_seconds` | `300` | Default TTL for cache entries. |

## Two-tier caching

The distributed cache uses a two-tier architecture:

1. **Local tier**: an in-process LRU cache on each instance (same as
   the built-in OSS cache). Hits are served from memory with no
   network round-trip.
2. **Remote tier**: the shared Redis cache. On a local miss, the
   gateway checks Redis before going to the upstream.

The read path:

```
request -> local cache (hit? return)
                -> Redis cache (hit? write to local, return)
                    -> upstream (write to local + Redis, return)
```

Writes go to both tiers: a cache write sets the entry in the local
cache and in Redis. A cache delete removes it from both.

## Consistency

The distributed cache is **eventually consistent**: after a write or
delete, other instances may serve stale data from their local cache
until the local TTL expires. This is acceptable for most response
caching use cases.

For strong consistency, use cache invalidation via the admin API
(see below) -- a `DELETE /cache` call propagates to Redis, and other
instances will miss their local cache on the next request (if the
local TTL is short).

## Invalidation

Invalidate cache entries via the admin API:

```sh
# Invalidate all cache entries
curl -X DELETE --cert admin.crt --key admin.key \
  https://127.0.0.1:2019/cache

# Invalidate entries for a specific route
curl -X DELETE --cert admin.crt --key admin.key \
  https://127.0.0.1:2019/cache?route=api
```

Invalidation removes entries from Redis. Local caches on other
instances expire based on their local TTL.

## Interaction with the OSS cache

The distributed cache is a superset of the OSS cache. In an OSS
build (without `ent`), only the local in-memory cache is used. In
an enterprise build with Redis configured, both tiers are active.

If Redis is unavailable, the cache degrades gracefully to
local-only mode (the local tier continues to work; Redis reads/writes
fail silently with a log warning).
