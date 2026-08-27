# Extension points

Source: `crates/dwara-core/src/extensions/{mod,rate_limiter,cache,
config_source,analytics,secrets}.rs` (DW-004 and the trait-specific
tickets noted per trait below).

## The OSS/Ent boundary as a type boundary

dwara is open-core, and these five traits are where that boundary is
actually drawn in code: `RateLimiter`, `ConfigSource`, `CacheStore`,
`AnalyticsSink`, `SecretSource`. The OSS edition ships a local
in-memory/file/env implementation next to each trait; the design intent
is that additional backends (a distributed rate limiter, a
control-plane config source, a warehouse-backed analytics sink) can be
provided separately later and slot in via `dyn` injection **without
changing trait signatures or call sites**. Whether that promise holds
is exactly what a change to one of these traits should be checked
against: if a change requires touching a dataplane call site to keep
working, the seam has been broken.

## Why these five, specifically

What the five traits have in common is that each one wraps an
**external system integration point that legitimately varies by
deployment** — a rate-limiter backend, a config source, a cache, an
analytics destination, a secret store — as opposed to core
routing/proxy/policy logic, which is not swappable and is not exposed
as a trait anywhere. That's a deliberate line: dwara's routing
semantics, TLS handling, and auth precedence chain are not things a
deployment should be able to silently replace with different
behavior, but *where the rate limiter's state lives* or *where secrets
come from* legitimately differs between a single-instance OSS
deployment and a larger operation.

## Why `async-trait`, not native `async fn` in traits

Every trait is used as `Arc<dyn Trait>` at runtime, so dyn-compatibility
(object safety) is the load-bearing requirement — and that's exactly
what native `async fn`-in-traits (RPITIT) doesn't yet give you on
stable Rust. `async-trait`'s boxing approach trades a small per-call
allocation for dyn-compatibility today; if/when RPITIT closes that gap
this is the module to revisit, but it's not a mistake to fix now — it's
a real constraint being worked around deliberately.

## One shared error type, error classes not per-trait taxonomies

All five traits return `ExtensionsError`, a single non-exhaustive enum
carrying a human-readable message. The variants map to **failure
classes** (I/O, invalid data, backend failure) rather than to five
separate per-trait error taxonomies, specifically so a brand-new
backend implementation can express its failures honestly without
requiring a breaking change to a shared enum every trait depends on —
adding a backend should never mean widening `ExtensionsError` in a way
that breaks the other four traits' callers.

## Each trait's contract

### `RateLimiter`

Full write-up: [Rate limiting](./rate-limiting.md). Contract summary:
`check` is the hot path, must be non-blocking beyond a backend
round-trip, and must be atomic per key (concurrent calls for the same
key linearize). It both decides and reserves in one call — no separate
commit, no refund in v1. OSS ships `InMemoryRateLimiter` (fixed
window, kept mostly for reference) and `GcraRateLimiter` (the real
sharded GCRA limiter actually used in production configs).

### `ConfigSource`

**Purpose:** produce the current `Gateway` configuration on demand.
`load` is a full read of the current generation — implementations
should be cheap to call repeatedly but need not cache, and `load` is
not expected to run on the request hot path (it backs startup and
reload, not per-request work). The trait is deliberately **pull-only**:
watch mechanics (a `tokio::sync::watch` channel, the `notify` crate)
are layered by the consumer, not baked into the trait, specifically so
a future `subscribe` method could be added later with a default no-op
implementation — backward compatible for every existing implementation
— rather than requiring every `ConfigSource` implementor to have
handled push notifications from day one. Failure maps to
`ExtensionsError::Io` for an unreadable source, or
`ExtensionsError::Invalid` (wrapping the path-precise `ConfigError`
message from [the config pipeline](../architecture.md#the-config-lifecycle))
for malformed content. OSS ships `FileConfigSource` (single YAML
file) — the one actually driving the file-watch reload described in
[Operations](../../docs-site/guide/operations.md#reload).

### `CacheStore`

**Purpose:** opaque byte-level get/set/delete for response caching or
any other hot-path shared state a future feature might need. Keys are
strings, values are owned byte vectors (so a backend can move them
without copying). It's explicitly a **best-effort** store, not a
durable database: `set` overwrites unconditionally, deleting a missing
key is a no-op reporting `false`, and there's no TTL parameter in v1 —
implementations bound themselves via capacity/eviction instead. The
signature was chosen so a TTL could be added later as a new method
(`set_with_ttl`) without breaking existing implementations or call
sites, the same forward-compatibility pattern as `ConfigSource`'s
`subscribe`. Backend failures map to `Backend` and should be treated
by callers as a cache **miss** — degrade, never fail the request over
a cache problem. OSS ships `InMemoryCache` (a process-local,
LRU-bounded map).

### `AnalyticsSink`

**Purpose:** accept request/flow events emitted by the dataplane,
fire-and-forget from the caller's side. `record` must not block beyond
a bounded enqueue — an analytics backend having a bad day must never
be able to stall the dataplane, which is why implementations are
expected to bound themselves (ring buffer, batching, drop-oldest)
rather than apply unbounded backpressure. `record` returning `Ok`
means "accepted," explicitly not "durably persisted" — events may be
coalesced or dropped under pressure, and ordering is best-effort only.
**Events must never contain secret material** — this sits alongside
the redaction rules in [Observability](./observability.md#redaction-implementation-not-just-policy)
as another place the same "never let a credential leak into a sink"
invariant has to hold. OSS ships `InMemoryAnalyticsSink` (a bounded
ring buffer).

### `SecretSource`

**Purpose:** resolve named secrets (TLS key passphrases, upstream
credentials, plugin tokens) at runtime without baking values into the
YAML config file — the same "config declares references, something
else resolves values" pattern used for credential hashes in
[Authentication and authorization](./authn-authz.md). `resolve`
returns `None` for "this source doesn't know this secret" (so callers
can chain multiple sources), distinct from an error, which means "this
source knows *where* the secret should be but couldn't read it"
(sealed backend, unreadable file) — that distinction is what lets a
caller decide "try the next source" vs. "something is actually
broken" without guessing. Resolution isn't on the request hot path in
v1, and implementations must never log a resolved value. The `Secret`
newtype wraps values with a redacted `Debug` impl specifically so a
resolved secret can't leak into a stray `{:?}` log line by accident;
true zeroization-on-drop is flagged as a future hardening step (would
change the wrapper's internals via the `secrecy` crate, not the
trait's public shape). OSS ships `EnvSecretSource` (environment
variables) and `StaticSecretSource` (an in-process map, for tests).

## Implementing a new backend

1. Pick the trait matching the integration point you're replacing —
   don't reach for a new trait; if what you need doesn't fit one of
   the five, that's a signal the seam needs a design discussion, not a
   sixth trait added quietly.
2. Implement the trait for your type. Because everything is used as
   `Arc<dyn Trait>`, your type needs no other integration — no
   registry to update, no enum variant to add.
3. Wire your implementation in at construction time (wherever the OSS
   local implementation is currently constructed) — call sites consume
   the trait object, not a concrete type, so this is the only place
   that needs to change.
4. Respect the failure-model notes above for your trait (what should
   map to `Backend` vs. `Io` vs. `Invalid`, and what callers will do
   with each) — getting this wrong doesn't break compilation, only
   behavior under failure, so it's worth checking against the relevant
   trait's contract deliberately rather than by analogy to a different
   trait.
