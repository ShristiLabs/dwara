# Distributed Cache (DW-068, Enterprise)

## Overview

dwara Enterprise supports a Redis-backed distributed cache with
coordinated invalidation across instances. This implements the same
`CacheStore` trait DW-037's OSS moka implementation defines -- no
dataplane fork.

## Enabling

Build with the `ent` feature:

```sh
cargo build --features ent
```

## API

### RedisCacheStore

A `CacheStore` implementation backed by Redis with key prefixing and
Pub/Sub invalidation:

```rust
use dwara_core::extensions::redis_cache::RedisCacheStore;

let store = RedisCacheStore::new(
    "redis://127.0.0.1:6379",
    "dwara:cache:",
).await?;
```

### CoordinatedCache

A two-tier cache: local (fast) + Redis (shared), with read-through
and write-through:

```rust
use dwara_core::extensions::redis_cache::{RedisCacheStore, CoordinatedCache};
use dwara_core::extensions::cache::MokaCache;
use std::sync::Arc;

let local = Arc::new(MokaCache::new());
let remote = Arc::new(RedisCacheStore::new(
    "redis://127.0.0.1:6379",
    "dwara:cache:",
).await?);

let cache = CoordinatedCache::new(local, remote);
```

### InvalidationListener

Subscribes to the Redis Pub/Sub invalidation channel for cross-
instance purge propagation:

```rust
use dwara_core::extensions::redis_cache::InvalidationListener;

let listener = InvalidationListener::new(conn);
listener.run(|key| {
    println!("invalidated: {key}");
}).await;
```

## Coordinated invalidation

When one gateway instance purges a cache entry, the purge must
propagate to all other instances in the fleet. This is done via
Redis Pub/Sub:

1. When a key is deleted via `RedisCacheStore::delete`, an
   invalidation message is published to the
   `dwara:cache:invalidate` channel.
2. Each instance subscribes to this channel via
   `InvalidationListener`.
3. When an invalidation message is received, the instance evicts
   the key from its local cache.

The invalidation publication is best-effort: if it fails, the entry
will still expire via TTL or be overwritten on the next write.

## Design

- `RedisCacheStore` implements the `CacheStore` trait (the same
  trait DW-037's OSS moka implementation defines).
- `CoordinatedCache` wraps a local cache + Redis cache, providing
  read-through (try local first, fall back to Redis, populate local)
  and write-through (write to both local and Redis).
- All keys are stored with a configurable prefix (e.g.
  `dwara:cache:`) to avoid collisions with other Redis users.
- Per-entry TTL is supported via `set_with_ttl` (uses Redis
  `SET EX`).

## Feature gate

The `ent` cargo feature must be enabled. Without it, the module is
not compiled and the gateway uses the OSS in-memory/moka cache.
