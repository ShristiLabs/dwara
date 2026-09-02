# Nano-services: WASM route handlers (DW-106)

> Implements issue DW-106 (M2, `edition/oss`, effort M). Sources:
> `crates/dwara-core/src/dataplane/nano_service.rs` (the `NanoService`
> compiled config, the `NanoServiceHandler` with its process-wide
> wasmtime `Engine` and the `dwara` host-import `Linker`, the
> `run_handle_sync` core, the `allocate` helper, the
> `serialize_request` / `deserialize_request` wire format, the
> `NanoContext` `ResourceLimiter`, the `shared_handler` `OnceLock`
> cache, the `NanoServiceError` enum), the config schema in
> `crates/dwara-core/src/config/mod.rs` (`RouteAction::NanoService`,
> `NanoServiceAction` with `module`, `memory_limit`,
> `execution_timeout_ms`), validation in `src/snapshot/mod.rs` (the
> module-existence check, the bound enforcement, the inert-feature
> warning), and the route-action wiring in `dataplane/proxy.rs`. Tests:
> the request wire-format round trip, the empty-request round trip, and
> the truncated-buffer rejection in `dataplane/nano_service.rs`'s
> inline `tests` module (the length-prefixed serializer is private to
> the module). Operator docs: [docs-site native-plugins
> guide](../../docs-site/guide/native-plugins.md).

A nano-service is a route action that runs a WebAssembly module to
generate the response directly, instead of proxying to an upstream.
This is the "function-as-a-route" path: a self-contained WASM module
owns the whole response for a route -- status, headers, and body -- with
no backend contact. The module implements a simple request-to-response
handler ABI over the existing wasmtime runtime (the `wasm` cargo
feature, brought in by `nano_services`). The route's `service` is still
required by the schema (the frozen vocabulary) but never dialed -- the
whole point is serving without a backend.

## The PDK contract

The module exports:

- `memory` -- the linear memory the host and module share.
- `alloc(size: i32) -> i32` -- allocate `size` bytes in linear memory
  and return a pointer (a simple bump allocator is fine; the host uses
  it to place the serialized request).
- `handle(req_ptr: i32, req_len: i32) -> i32` -- handle the request
  whose serialized form lives at `[req_ptr, req_ptr+req_len)` in linear
  memory. Returns 0 on success (the response is communicated back via
  the host imports) and non-zero on error (the route answers 502).

The host provides these imports under the module name `dwara`:

- `response_status(status: i32)` -- set the HTTP response status
  (clamped to 1..=599; defaults to 200 when never called).
- `response_header(k_ptr, k_len, v_ptr, v_len)` -- add a response
  header (reads the key and value from linear memory).
- `response_body(ptr, len)` -- set the response body.
- `log(ptr, len)` -- emit a log line (`tracing::debug`).

The request is serialized into linear memory in a length-prefixed
binary format (all lengths `u32` big-endian): `method`, `path`, a
header count followed by `(key, value)` pairs, then the body. The
module parses this to read the request, calls the host imports to build
the response, and returns 0 from `handle`. `serialize_request` and
`deserialize_request` are the paired codec; the round trip and the
truncated-buffer rejection are pinned by inline tests.

## Resource limits

Three independent caps bound a nano-service module:

- **Fuel.** `NANO_FUEL` (1,000,000) is the wasmtime fuel budget for one
  `handle` call. The engine is constructed with `consume_fuel(true)`,
  and `store.set_fuel(NANO_FUEL)` arms it before instantiation. A
  module that loops forever traps with an out-of-fuel error (detected
  by `store.get_fuel() == 0` after a trap) and the route answers 502.
  Generous enough for typical request inspection and response building.
- **Memory.** `memory_limit` caps the linear memory the module may
  allocate, enforced via wasmtime's `ResourceLimiter` on the
  `NanoContext` (`memory_growing` returns `Ok(desired <= memory_cap)`).
  The config default is 1 MiB; the validation ceiling is 64 MiB
  (`NANO_MAX_MEMORY`). A grow past the cap traps and the route answers
  502 (`MemoryLimitExceeded`). The table grow is capped at 10,000
  entries.
- **Time.** `execution_timeout_ms` caps the wall-clock time the
  `handle` call may run. The call runs on a blocking-pool thread
  (`tokio::task::spawn_blocking`) wrapped in a `tokio::time::timeout`,
  so a module that exceeds it is interrupted and the route answers 504
  (`NanoServiceError::Timeout`). The config default is 100 ms; the
  validation ceiling is 5000 ms.

`NanoServiceError` maps to HTTP responses: `ModuleLoadFailed` -> 502,
`ExecutionFailed` -> 502, `Timeout` -> 504, `MemoryLimitExceeded` ->
502. The blocking task keeps the async caller never blocked on wasm
compilation or execution.

## The handler and the shared engine

`NanoServiceHandler` holds a process-wide wasmtime `Engine` and the
`Linker` wired with the `dwara` host imports. wasmtime recommends a
single `Engine` per process (compiled modules are cached and shared
across threads), so the dataplane reuses one handler for every
nano-service route via `shared_handler` (a `OnceLock` that lazily
initializes on first use; a construction failure is reported once and
cached as an error so every subsequent request answers 502 without
retrying). The handler is stateless beyond the immutable engine +
linker (both `Arc`-held), so sharing it across requests and tests is
safe. `handle` clones the engine and linker, reads and compiles the
module from `service.module_path` on the blocking thread, instantiates
it, writes the serialized request into linear memory via the module's
`alloc` export (falling back to growing the memory by one page when
`alloc` is absent), calls `handle`, and returns the response the module
produced.

## Configuration

```yaml
routes:
  - name: health
    service: unused
    match:
      path: { type: exact, value: /healthz }
    action:
      type: nano_service
      module: /etc/dwara/nano/health.wasm
      memory_limit: 1048576
      execution_timeout_ms: 100
```

The `nano_service` action is additive to the `RouteAction` enum. The
config schema (`NanoServiceAction`) is always present, so configs
round-trip without the feature; when the `nano_services` cargo feature
is off the action is accepted but inert (validation warns, the route
returns 502). `module` must exist and be readable at config publish
time. `memory_limit` must be positive and at most 67,108,864 (64 MiB).
`execution_timeout_ms` must be positive and at most 5000. Both default
when omitted (1 MiB and 100 ms).

The [proxy-wasm](./proxy-wasm.md) page covers the filter ABI for
in-line request/response mutation; nano-services are the
whole-response sibling -- a module that owns the route rather than
filtering through it. The [native-plugins](./native-plugins.md) page
covers the unified dispatch chain both plug into.
