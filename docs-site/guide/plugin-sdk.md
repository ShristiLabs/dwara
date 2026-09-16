# Plugin SDK

The Plugin SDK is the developer workflow for writing proxy-wasm
plugins: `dwara-cli plugin new` scaffolds a ready-to-build Rust crate
against the [proxy-wasm](https://proxy-wasm.spec.vec.io/) ABI, and the
gateway runs the compiled `.wasm` on the live request path of every
default build — there is no cargo feature to enable.

This page is the developer home for that workflow: the quickstart, the
hostcall support matrix, resource limits and failure semantics, and
troubleshooting. Operators configuring existing plugins should read
[Proxy-Wasm plugins](./proxy-wasm-plugins) and
[Plugin lifecycle](./plugin-lifecycle) instead.

## Fifteen-minute quickstart

Every command below is verified against a default build
(`cargo build -p dwara-bin -p dwara-cli`). It mirrors the
`test-02-proxy-wasm.sh` and `test-07-plugin-sdk.sh` scripts in the
[`demos/08-extensibility/`](https://github.com/shristilabs/dwara/tree/main/demos/08-extensibility)
directory.

### 1. Scaffold the plugin

```sh
dwara-cli plugin new my-plugin
cd my-plugin
```

This creates `Cargo.toml` (a `cdylib` depending on `proxy-wasm`),
`src/lib.rs` (a minimal filter with the request/response headers
callbacks), `dwara.yaml` (a manifest wiring the plugin into a gateway
config), `README.md`, and `.gitignore`.

To start from a working example instead of the hello-world filter,
pass `--template` with one of `static-auth`, `header-guard`,
`response-body-redact`, or `request-tagger` — the example's source is
scaffolded under your crate name, its host-runnable tests included:

```sh
dwara-cli plugin new my-plugin --template static-auth
```

### 2. Implement your logic

Edit the phase callbacks in `src/lib.rs`. The scaffold logs the
request path; the smallest useful change is stamping a header. In
`on_http_response_headers`:

```rust
fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
    self.add_http_response_header("x-my-plugin", "active");
    Action::Continue
}
```

A plugin can hook any subset of the four phases (see
[the phase contract](./proxy-wasm-plugins#phase-contract)) and can
short-circuit a request with `send_http_response` from any of them.

### 3. Build the .wasm

The `wasm32-wasip1` target must be installed (idempotent):

```sh
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1
```

The artifact lands at `target/wasm32-wasip1/release/my_plugin.wasm`.

### 4. Load it into the gateway

Reference the `.wasm` in your gateway config and attach it to a route.
The scaffold's `dwara.yaml` is a complete, valid gateway config —
`dwara-cli validate dwara.yaml` passes as generated (validation does
not check that the `.wasm` exists yet; the path resolves against the
gateway process's working directory when it loads). A minimal working
config:

```yaml
listeners:
  - name: http
    address: 127.0.0.1
    port: 8080
    protocol: http

routes:
  - name: api
    service: backend
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy }
    plugins:
      - my-plugin

services:
  - name: backend
    upstream: backend-upstream

upstreams:
  - name: backend-upstream
    load_balancer: round_robin
    protocol: http1
    endpoints:
      - address: 127.0.0.1
        port: 9000

plugins:
  - name: my-plugin
    wasm: ./my-plugin/target/wasm32-wasip1/release/my_plugin.wasm
    phases:
      - request_headers
      - response_headers
```

The `wasm:` path is resolved relative to the gateway process's working
directory — prefer an absolute path outside throwaway setups.

### 5. Run and verify

```sh
DWARA_CONFIG=dwara.yaml dwara
curl -i http://127.0.0.1:8080/api/hello
```

The response carries `x-my-plugin: active` — your plugin ran on the
live path. (From a source checkout: `DWARA_CONFIG=dwara.yaml cargo run
-p dwara-bin`.)

## How the gateway calls your plugin

The host implements the proxy-wasm HTTP filter subset and the standard
module lifecycle. The four phase hook points and where they sit in
the request pipeline are diagrammed in
[Proxy-Wasm plugins](./proxy-wasm-plugins#phase-contract). For every
request on a route referencing your plugin, the gateway:

1. instantiates a fresh module instance (fuel and memory limits from
   the plugin's `limits` block);
2. calls `_start`, `proxy_on_context_create(1, 0)`,
   `proxy_on_vm_start`, then `proxy_on_configure` (SDK modules need
   this sequence; minimal ABI modules without those exports skip
   them);
3. calls `proxy_on_context_create(2, 1)` before the first phase
   callback, then the phase exports for the phases your plugin
   declares, in pipeline order;
4. always calls `proxy_on_done` / `proxy_on_log` /
   `proxy_on_delete` at the end of the request, on every exit path
   (short-circuits and failures included).

The header maps your plugin sees follow the proxy-wasm convention:
the request map carries `:method` and `:path` (the path **including
the query string**) ahead of the real headers; the response map
carries `:status`. A changed `:path`, `:method`, or `:authority` at
`request_headers` rewrites the FORWARDED request — `:path` is the
final upstream target (see
[Proxy-Wasm plugins: pseudo-header writes](./proxy-wasm-plugins#pseudo-header-writes));
`:status` writes are ignored. The write-back applies only the headers
the chain changed: headers no plugin touched keep their original
bytes, non-UTF-8 (obs-text) values included.

## Hostcall support matrix

Audited against the host implementation (`crates/dwara-core/src/wasm/`).
"Per-instance" state lives inside one request's module instance: it
does not survive the request and is not shared across plugins.

### HTTP headers and bodies

| Hostcall | Status | Notes |
|---|---|---|
| `proxy_get_header_map_value` | Supported | Case-insensitive lookup; a missing key reads as empty (the Rust SDK maps that to `None`). |
| `proxy_add_header_map_value` | Supported | Appends (duplicate names possible). |
| `proxy_replace_header_map_value` | Supported | Replaces the first case-insensitive match, or appends. |
| `proxy_remove_header_map_value` | Supported | Removes every case-insensitive match. |
| `proxy_get_header_map_pairs` | Supported | Request/response header maps in the spec wire format (LE entry count, LE length table, NUL-terminated strings — the layout the Rust SDK's `get_map` parses). Trailer maps read as empty. |
| `proxy_set_header_map_pairs` | Partial | Replaces the **whole** map, parsing the same spec wire format (`set_map` output). Values are UTF-8 strings; a whole-map set cannot carry non-UTF-8 values (untouched headers keep theirs — see above). Trailer stores are accepted and discarded. |
| `proxy_get_buffer_bytes` | Supported | Request body, response body, plugin configuration, VM configuration. |
| `proxy_get_buffer_status` | Supported | Lengths for the same four buffers. |
| `proxy_set_buffer_bytes` | Partial | Request and response bodies only. The write **replaces the buffer from the offset to the end** (spec-range in-place edits are not supported). Configuration buffers are read-only. |
| `proxy_send_local_response` | Supported | Short-circuits the request: status, headers (spec wire format, exactly what the Rust SDK's `send_http_response` serializes), and body are honored verbatim, the upstream is never dialed. Status-code details and the gRPC status parameter are ignored. A non-empty body without a content-type defaults to `application/json`. |
| `proxy_log` | Partial | Lines are captured in the per-instance buffer, capped at **64 KiB per instance** (past the cap, the head of the overflowing line plus a truncation marker is kept and further lines are dropped); they are **not surfaced to the gateway log today**. No level filtering. |
| `proxy_get_log_level` | Partial | Always reports `Info`. |
| `proxy_get_current_time_nanoseconds` | Supported | Nanoseconds since the Unix epoch. |

### Shared state, metrics, and callouts

| Hostcall | Status | Notes |
|---|---|---|
| `proxy_get_shared_data` / `proxy_set_shared_data` | Partial | A per-**instance** key/value map with CAS. Not shared across requests or plugins — every request starts with an empty map. Treat it as request-local scratch space, not cross-request state. |
| `proxy_define_metric` / `proxy_record_metric` / `proxy_increment_metric` / `proxy_get_metric` | Partial | Per-instance metric maps; **not exported** to the gateway's `/metrics` surface and reset every request. Emit gateway-visible signals from your plugin config or headers instead. |
| `proxy_http_call` | Stub | Returns `InternalFailure`. The Rust SDK surfaces this as `Err(Status::InternalFailure)` from `dispatch_http_call`. |
| `proxy_grpc_call` / `proxy_grpc_stream` | Stub | Return `InternalFailure`; the SDK's `dispatch_grpc_call` / `open_grpc_stream` surface that as `Err`. No gRPC callouts. |
| `proxy_grpc_send` / `proxy_grpc_cancel` / `proxy_grpc_close` | Stub | Return `InternalFailure`. The SDK wrappers for these (`send_grpc_stream_message`, `cancel_grpc_call`/`cancel_grpc_stream`) only map `BadArgument`/`NotFound` to `Err` — they **panic** on `InternalFailure`, which traps the module and fails closed as 500 `plugin_failed`. Host-safe, but the plugin dies rather than handling the error. |
| `proxy_get_status` | Partial | Returns Ok with code `0` and no message: no gRPC callout is ever in flight, so there is no status to report. The SDK's `get_grpc_status` reads that as `(0, None)` (it panics on any non-Ok status, so the host must answer Ok). |
| `proxy_register_shared_queue` / `proxy_resolve_shared_queue` / `proxy_dequeue_shared_queue` / `proxy_enqueue_shared_queue` | Stub | Return `InternalFailure`; no shared queues. |
| `proxy_set_tick_period_milliseconds` | Stub | Returns `InternalFailure`; there is no tick loop. `on_tick` never fires. |
| `proxy_call_foreign_function` | Stub | Returns `InternalFailure`. |

### Properties, contexts, streams

| Hostcall | Status | Notes |
|---|---|---|
| `proxy_get_property` | Stub | Returns an empty value for every path — no properties resolve. |
| `proxy_set_property` | Stub | No-op (reports success, changes nothing). |
| `proxy_set_effective_context` | Partial | The ID is recorded; cross-context callbacks are not re-dispatched. |
| `proxy_continue_stream` | Partial | No-op (reports success). |
| `proxy_close_stream` | Partial | Ends the stream (same as returning `EndStream`). |
| `proxy_done` | Supported | Marks the context done. |

### The WASI subset (`wasm32-wasip1`)

A plugin compiled for `wasm32-wasip1` emits a small
`wasi_snapshot_preview1` import set. The host provides minimal stubs
for exactly that set:

| Import | Behavior |
|---|---|
| `environ_get` / `environ_sizes_get` | Empty environment. |
| `fd_write` | Routed into the per-instance log buffer (panic output included), under the same 64 KiB per-instance cap as `proxy_log` (a plugin spewing through stderr cannot grow host memory without bound). Like `proxy_log`, that buffer is not surfaced to the gateway log today. |
| `proc_exit` | Traps the instance — reported like any plugin failure. |
| `random_get` | Non-cryptographic. Do not use it for key material. |
| `clock_time_get` | Wall-clock nanoseconds. |
| `sched_yield` | No-op. |

A module importing any **other** WASI function (files, sockets, more)
fails to instantiate, and routes referencing it fail closed. Keep
plugins to the subset above.

## Plugin configuration

The gateway config's `config` string on a plugin entry is delivered as
raw bytes: your `on_configure` implementation reads it with
`get_plugin_configuration()` and parses it (JSON and YAML are
typical). The VM-level configuration buffer is empty today — deliver
everything through the plugin-level `config` field.

```rust
impl RootContext for MyPluginRoot {
    fn on_configure(&mut self, _config_size: usize) -> bool {
        let bytes = self.get_plugin_configuration().unwrap_or_default();
        // parse `bytes`...
        true // returning false fails the plugin load (routes fail closed)
    }
}
```

## Resource limits and failure semantics

Limits come from the plugin's `limits` block (defaults: `fuel:
1000000`, `memory_mb: 32`, `timeout_ms: 100`). Every limit violation
fails closed — the request does not silently skip the plugin:

| Limit | Enforcement | Client-visible result |
|---|---|---|
| `fuel` | wasmtime fuel consumed per module instance; exhaustion traps | 500 `plugin_failed` |
| `memory_mb` | linear-memory growth beyond the cap fails the allocation (a trap) | 500 `plugin_failed` |
| `timeout_ms` | An epoch deadline is armed, but **no epoch ticker runs by default** — the deadline never fires on its own. Fuel is the effective execution bound today; size `fuel` accordingly (a busy-loop plugin dies on fuel, not on `timeout_ms`). | — |

Other request-path failures, all fail-closed on the referencing route
only:

- **Over-cap body**: a route whose plugins declare a body phase
  buffers the body up to the route's `limits.max_body_bytes` (default
  1 MiB). A larger body answers 500 `plugin_body_too_large`.
- **Streaming and encoded responses skip `response_body`**: SSE
  (`text/event-stream`), un-framed (no content-length) bodies, and
  content-encoded bodies pass through untouched — the skip is logged
  once (`plugin_response_body_skipped`), never silently. Never write
  a `response_body` plugin that must run for SSE routes.
- **Crashed, disabled, or unloadable plugin**: 500
  `plugin_unavailable` (see below).

Every failure increments
`dwara_plugin_failures_total{name,reason}` (reasons include
`instantiate_failed`, `trap`, `crashed`, `body_too_large`,
`response_stream_ended`) and a request answered by a plugin
(short-circuit **or** failure) sets the access log's
`plugin_short_circuit` flag.

## Caching and signature interactions

- **Response cache**: changing a plugin definition (its `config`
  bytes or the `.wasm` checksum) bumps the response-cache epoch of
  every route referencing that plugin on reload — cached
  pre-old-plugin response bytes are never replayed against the new
  plugin.
- **HMAC-signed routes**: a `request_body` plugin that modifies the
  body on a route with HMAC request signing will fail the signature
  check — the digest is computed over the original bytes, so the
  signed route answers 401 `signature_body_mismatch`. Do not put
  body-rewriting plugins on HMAC-signed routes.
- **Duplicate references**: a route naming the same plugin twice is a
  config validation error (the double execution would otherwise be
  literal). Reference each plugin at most once per route.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Config rejected: unknown `wasm`/`native` combination or empty `phases` | Schema validation | A plugin needs exactly one of `wasm:`/`native:` and a non-empty `phases` list. |
| Config rejected: route references an undefined plugin | Snapshot validation | Every name in a route's `plugins` list must match a top-level plugin entry, with no duplicates. |
| `plugin_load_failed` in the gateway log, route answers 500 `plugin_unavailable` | The `.wasm` could not be read (path wrong, permissions) — the plugin is marked Crashed at publish; the rest of the config loads | Fix the path and reload. |
| `plugin_compile_failed`, same 500 | The module failed to compile or failed ABI validation (missing `proxy_on_vm_start`, no exported memory, unknown host imports) | Rebuild against the scaffold's SDK version; check the WASI subset above. |
| 500 `plugin_unavailable` with `instantiate_failed` | Per-request instantiation failed — most commonly a WASI import outside the stub set, `on_configure` returning false, or a trap inside `_start` (the error names `_start`) | Same as above. |
| 500 `plugin_failed` with reason `trap` | The plugin trapped: fuel exhaustion (the usual), a memory-cap allocation failure, or a Rust panic inside the plugin | Raise `fuel`/`memory_mb` if legitimate; panics print through `fd_write` into the per-instance buffer, which is not surfaced today — reproduce the plugin logic outside the gateway (or in a [test harness](./plugin-testing)) to find the panic. |
| 500 `plugin_body_too_large` | A body-phase plugin saw a body over the route's cap | Raise `limits.max_body_bytes` on the route or narrow the phases the plugin declares. |
| Plugin changes not taking effect | Hot swap is checksum-keyed: identical `.wasm` bytes and `config` reuse the loaded module | Change the bytes (rebuild) or the config string, then reload. |

## Nano-services are live today

If you need WASM that *generates* responses at the edge (rather than
filtering proxied traffic), nano-services are live on every default
build today: a route action `type: nano_service` runs a `.wasm`
module's handler directly with no upstream. See
[Nano-services](./nano-services). Plugin filters and nano-services
share the same sandbox model; pick the one that matches the job.

## Testing plugins

For running plugins against a live gateway during development (the
verified scaffold/build/load/curl loop, plus the harness patterns the
demo scripts use), see [Plugin testing](./plugin-testing).

## Compatibility and versioning

Which proxy-wasm ABI level the host implements, the `proxy-wasm` crate
version the scaffold pins, the wasm target matrix, and the
breaking-change policy for the hostcall surface:
[Plugin compatibility](./plugin-compat).

## Runnable demo

Run the verified round-trip end to end:
[`demos/08-extensibility/`](https://github.com/shristilabs/dwara/tree/main/demos/08-extensibility)
(test scripts: `test-02-proxy-wasm.sh`, `test-07-plugin-sdk.sh`). Both
build a plugin from `dwara-cli plugin new` output, load it into a
default-build gateway, and assert the header effect with curl; the
category README covers prerequisites (prebuilt host binaries, the
`wasm32-wasip1` rustup target) and teardown.
