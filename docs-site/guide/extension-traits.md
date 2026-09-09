# Extension traits

Dwara defines five swappable subsystem seams as traits. The default
OSS build ships a local implementation for each; the enterprise edition
adds Redis- and Vault-backed implementations of the same traits. You
can also write your own implementation and wire it in -- the gateway
calls the trait, not the concrete backend.

The traits are the extraction boundary for promoting a subsystem to
its own crate later (see [Code organization](../architecture/overview)):
each is self-contained behind its trait, so a backend swap is a
config change, not a code change.

## The five traits

| Trait | What it owns | Default impl | Enterprise impl |
|---|---|---|---|
| `RateLimiter` | rate-limit decisions per scope | local GCRA, stacked windows | Redis-backed distributed GCRA |
| `ConfigSource` | where config generations come from | file watch / SIGHUP / admin API | controller gRPC stream (CP/DP) |
| `CacheStore` | response cache get/set/invalidate | local in-memory, TTL/ETag | Redis-backed two-tier distributed cache |
| `AnalyticsSink` | where completed-request records go | embedded SQLite analytics store | federated gRPC stream to controller |
| `SecretSource` | how `${...}` secret references resolve | env, file, static inline | HashiCorp Vault and KMS |

## How they fit together

Each trait is consumed by exactly one domain:

- `RateLimiter` is called from the traffic-policy stage of the request
  pipeline.
- `ConfigSource` feeds the snapshot publish pipeline (parse, validate,
  compile, publish).
- `CacheStore` is consulted by the response-caching stage after a
  route matches.
- `AnalyticsSink` receives the fire-and-forget record for every
  completed request.
- `SecretSource` resolves references at compile time, before the
  snapshot is published.

The local implementations are always available. Enterprise backends
are compiled in with the `ent` cargo feature and activated by a license
claim; in an OSS build the enterprise config blocks are accepted and
inert. See [Feature reference](./feature-reference) for the gating
mechanics.

## Where to go next

- [Enterprise and fleet](./enterprise) - the enterprise backends for
  each trait.
- [Architecture: config, state, and extensions](../architecture/config-and-state)
  - the internal design of the extension boundaries.
- [Plugins](./extensibility-overview) - the per-route filter chain,
  which is a separate extensibility layer from the extension traits.
