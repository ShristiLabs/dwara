# Nano-services

Dwara can run a route handler inside the gateway process itself, as a
[WebAssembly](https://webassembly.org/) (a portable, sandboxed bytecode
format) module, instead of proxying to an upstream. A nano-service is a
small `.wasm` module that receives the request, produces a response, and
returns — no upstream hop, no separate process, no network call. The
module runs in the gateway's Wasmtime runtime, sandboxed, with the
request handed to it and the response read back.

::: info Status
Live in every build: the `nano_service` route action and its runtime
compile unconditionally — there is no cargo feature to enable. It is a
route action, not a plugin: nano-services do not hook the plugin filter
phases (see [Proxy-Wasm plugins](./proxy-wasm-plugins)); they own the
whole response for their route.
:::

## When to use this

Use a nano-service when a route's logic is small enough that standing
up an upstream service is overkill — a request validator that returns
`400` on a bad shape, a feature-flag check that returns a canned
response, a request-shaped echo for smoke testing. Because the module
runs in process, latency is the cost of the WASM call alone, with no
network hop. For logic that needs a database, a large dependency tree,
or a long-running process, keep a real upstream — the sandbox is not a
substitute for a service.

## Configuration

Add a route with `action.type: nano_service` and point it at the
`.wasm` module:

```yaml
routes:
  - name: feature-flag
    match:
      path: { type: exact, value: /flags/new-ui }
    action:
      type: nano_service
      module: /etc/dwara/modules/feature-flag.wasm
      memory_limit: 1048576
      execution_timeout_ms: 100
```

| Field | Default | Description |
|---|---|---|
| `module` | (required) | Path to the `.wasm` module. Must exist and be readable at config publish time. |
| `memory_limit` | `1048576` (1 MiB) | Maximum linear memory the module may allocate, in bytes. Max 64 MiB. |
| `execution_timeout_ms` | `100` | Maximum wall-clock time for one `handle` call. Max 5000. |

The module is compiled when the gateway builds the route handler for a
config generation; a broken module is reported there, and the route
answers `502` (`nano_service_unavailable`) rather than serving from a
half-loaded handler.

## Writing a module

A nano-service module implements a small dedicated handler ABI — it is
not the proxy-wasm ABI. The module exports:

| Export | Purpose |
|---|---|
| `memory` | The linear memory the host and module share. |
| `alloc(size) -> ptr` | Allocate `size` bytes in linear memory; the host uses it to place the serialized request. |
| `handle(req_ptr, req_len) -> i32` | Handle the request serialized at `[req_ptr, req_ptr+req_len)`. Returns `0` on success, non-zero on error (the route answers `502`). |

The host provides four imports under the module name `dwara`:

| Import | Purpose |
|---|---|
| `dwara.response_status(status)` | Set the HTTP response status (defaults to 200). |
| `dwara.response_header(k_ptr, k_len, v_ptr, v_len)` | Add a response header. |
| `dwara.response_body(ptr, len)` | Set the response body. |
| `dwara.log(ptr, len)` | Emit a debug log line. |

The request is serialized into linear memory as a length-prefixed
binary blob (all lengths `u32` big-endian): `method`, `path`,
`headers` (count, then key/value pairs), `body`. The module parses it,
builds the response through the host imports, and returns `0` from
`handle`. A minimal Rust sketch (no helper crate is required; compile
with `--target wasm32-unknown-unknown`):

```rust
#[link(wasm_import_module = "dwara")]
extern "C" {
    fn response_status(status: i32);
    fn response_body(ptr: i32, len: i32);
}

#[no_mangle]
pub extern "C" fn alloc(size: i32) -> i32 {
    // bump allocator over the module's static heap
    // ...
}

#[no_mangle]
pub extern "C" fn handle(req_ptr: i32, req_len: i32) -> i32 {
    // parse the serialized request at req_ptr..req_ptr+req_len
    let body = b"{\"flag\":true}";
    unsafe {
        response_status(200);
        response_body(body.as_ptr() as i32, body.len() as i32);
    }
    0
}
```

Any language that can export plain WASM functions and skip runtime
preludes works (`#![no_std]` Rust, C, AssemblyScript). A module
importing WASI functions does not instantiate — the host provides only
the four `dwara` imports.

## Sandboxing and failure semantics

A nano-service module has no host capabilities beyond the four imports
above: no network, no filesystem, no environment, no access to the
gateway's config, secrets, or other routes. The sandbox is the
security boundary. Every failure mode fails closed:

| Condition | Client sees |
|---|---|
| Module missing or broken at handler construction | 502 `nano_service_unavailable` |
| `handle` returns non-zero, traps, or exhausts its fuel budget | 502 `nano_service_error` |
| `handle` exceeds `execution_timeout_ms` | 504 `nano_service_timeout` |
| Request body over 1 MiB (the module receives the body whole) | 413 `nano_service_body_too_large` |

The `handle` call runs on a blocking-pool thread under a timeout, so a
busy-looping module is interrupted rather than left hanging a worker.

## Observability

Nano-service execution surfaces in [`/metrics`](./observability) as
`dwara_nano_service_requests_total{route,outcome}` with outcomes
`success`, `error`, and `timeout`, and
`dwara_nano_service_duration_seconds{route}` for the in-process call
latency.

## Runnable demo

Run the demo stack: [`demos/08-extensibility/`](https://github.com/shristilabs/dwara/tree/main/demos/08-extensibility) in the repository (test
script: `test-04-nano-services.sh`). The script documents the
`nano_service` action and verifies the composition pattern using echo
and static upstream services as a stand-in; the README covers
prerequisites and teardown.
