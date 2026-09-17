# Demo 06: embedding dwara-core with a custom AnalyticsSink

The
[custom-backends recipe](../../../docs-site/guide/use-cases/custom-backends-traits.md):
when decisions or state must live in YOUR infrastructure, you embed
dwara-core in a binary you own and register extension-trait
implementations at startup. `AnalyticsSink` is the easiest seam, so
that is what this demo swaps.

## The pattern

`src/main.rs` embeds dwara-core exactly the way
`crates/dwara-core/tests/proxy_plugins.rs` (and its shared harness)
constructs a gateway:

1. `parse_gateway(YAML)` -> `ConfigState::compile_and_publish` ->
   `DataPlane::new`
2. a plain hyper accept loop calling `proxy::handle` per request
   (h1 + upgrades) -- no dwara-bin involved
3. `StdoutSink` implements `extensions::analytics::AnalyticsSink` the
   way the contract demands: `record` is a bounded-channel `try_send`
   (never blocks the dataplane; a full channel drops and reports),
   with one background task rendering each event
4. the embedder owns the completion seam: it wraps `proxy::handle`,
   and when a request completes it builds one `Event` (method, path,
   status, duration) and records it into the sink -- the same
   boundary dwara-bin uses to attach the embedded SQLite store

The same shape swaps any of the five traits (`RateLimiter`,
`ConfigSource`, `CacheStore`, `SecretSource`): implement, register at
startup, run your own front end.

## What test.sh asserts (from the binary's output)

1. the embedded gateway served the fired requests (3x 200, 1x 404)
2. the sink rendered a record for EVERY completed request, including
   the unrouted 404
3. records carry `kind`, `listener`, `method`, `path`, `status`,
   `duration_ms`
4. the binary exits 0 (its own bounded sink-drain self-check passed)

## Run

```sh
./test.sh          # builds this crate, runs it, asserts on its output
```

Ports: 18251 (the embedded gateway).

## Notes

- This crate is EXCLUDED from the cargo workspace (see the root
  `Cargo.toml`, mirroring the `plugins/examples` exclusion): it must
  not sit on every `cargo build --workspace`. It therefore builds its
  OWN dependency tree -- the first build compiles all of dwara-core's
  dependencies and is slow; later runs are incremental.
- Build-time integration means no hot loading: swapping the sink is a
  rebuild, which is exactly the tradeoff the recipe documents.
