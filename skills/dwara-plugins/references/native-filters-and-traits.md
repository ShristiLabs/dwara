# Native filters and extension traits

## Native Rust filters

For maximum performance and direct access to dwara-core types, compile the
filter into the gateway instead of loading WASM.

1. Implement the `NativeFilter` trait in dwara-core's plugins domain.
   Return `FilterOutcome`:
   - `Continue` - pass through to the next filter,
   - `LocalResponse` - short-circuit with a gateway-built response,
   - `Error` - fail (route-level failure semantics).
2. Register at startup: `NativeRegistry::register(...)` under a name.
3. Load via config - a plugin entry with `native:` instead of `wasm:`
   (mutually exclusive), same `phases`/`config` fields:

```yaml
plugins:
  - name: my-native-filter
    native: my-filter          # the registered name
    phases: [request_headers, response_headers]
    config: ...
```

Choose native when: the filter is on the critical path of every request,
needs dwara-core types (snapshot, consumer, pool internals), or needs
first-class observability integration. Choose wasm when: you don't want to
rebuild the gateway, want hot reload, or plan to run community filters.

## Extension traits (embedding dwara-core)

The five seams the gateway calls out to. OSS ships local implementations;
the enterprise edition adds Redis/Vault backends **as additional
implementations of the same traits** - your custom impl sits in the same
slot.

| Trait | Called from | Implement to |
| --- | --- | --- |
| `RateLimiter` | Traffic-policy stage, per scope | Plug in a shared/remote limiter with custom keying or semantics |
| `ConfigSource` | The snapshot publish pipeline | Source config generations from etcd/database/anything instead of the file watcher |
| `CacheStore` | Response-caching stage (after route match) | Back the response cache with a custom store (custom eviction, persistence) |
| `AnalyticsSink` | Fire-and-forget after every completed request | Stream request records to your warehouse instead of embedded SQLite |
| `SecretSource` | Config build, before snapshot publish | Resolve `${...}` from your secret manager |

Contract notes:

- `AnalyticsSink` is fire-and-forget: slow sinks must not stall the
  dataplane - buffer/queue internally.
- `SecretSource` runs at config-build time only: failures fail the publish
  (fail closed), they never serve a partial config.
- `ConfigSource` feeds generations - keep the Parse->Validate->Compile->
  Publish discipline; a bad generation must never publish (same rule as
  file reloads).
- `RateLimiter`/`CacheStore` see hot-path traffic: implement with lock-free
  or sharded state (the built-ins shard; `DWARA_POOL_SHARDS` sizes pools).

## Filter chain ordering

Built-in stages in fixed order:

```
acl -> rate_limit -> authn -> authz -> validate -> transform -> cache -> route
```

Customize with:

```yaml
filter_chain:
  order: [acl, rate_limit, authn, authz, validate, transform, cache, route]
  # must be a PERMUTATION of all eight stages
  dry_run: [authz]        # stages running in observe-only mode
```

Gateway-level by default; per-route `filter_chain` overrides. Consequences
worth internalizing:

- `authn`/`authz` run **before** route match - plugins and transforms see
  an authenticated context on `auth_required` routes (consumer resolved),
  and authorization decisions cannot be dodged by route selection.
- `rate_limit` before `authn`: IP-selector windows admit/deny anonymous
  traffic pre-authn (credential selectors fall back to IP pre-auth).
- `transform` after `authz` means authz sees original headers - a set/add/
  remove cannot smuggle a consumer past `allowed_consumers`.
- `cache` last-before-route: cache hits skip everything after `cache` for
  already-stored responses (coalescing waits happen there).

## When NOT to write a plugin

Audit the built-ins first - the majority of "we need a plugin" requests are
config: `transforms` (header surgery), `authorization` (allow/deny rules),
`waf` (pattern blocking), `policies[].anomaly` (behavioral signals),
`masking` (field redaction), `request_validation` (body schemas),
`cel`-style expressions (not yet wired - check schema), or a
`respond`/`mock` action. A plugin is for logic the config grammar cannot
express.
