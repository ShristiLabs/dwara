# Nano-services

Dwara can run a route handler inside the gateway process itself, as a
[WebAssembly](https://webassembly.org/) (a portable, sandboxed bytecode
format) module, instead of proxying to an upstream. A nano-service is a small
`.wasm` module that receives the request, produces a response, and returns --
no upstream hop, no separate process, no network call. The module runs in the
gateway's WASM runtime, sandboxed, with the request handed to it and the
response read back.

## When to use this

Use a nano-service when a route's logic is small enough that standing up an
upstream service is overkill -- a request validator that returns `400` on a
bad shape, a feature-flag check that returns a canned response, a
request-shaped echo for smoke testing, an edge-side composition that fans out
to two other routes and merges the results. Because the module runs in
process, latency is the cost of the WASM call alone, with no network hop. For
logic that needs a database, a large dependency tree, or a long-running
process, keep a real upstream -- the sandbox is not a substitute for a
service.

## Configuration

Add a route with `action.type: nano_service` and point it at the `.wasm`
module. The module is loaded at config publish and reloaded on config change.

```yaml
routes:
  - name: feature-flag
    match:
      path: { type: exact, value: /flags/new-ui }
    action:
      type: nano_service
      module: /etc/dwara/modules/feature-flag.wasm
      config:
        flag: new-ui
        enabled: true
        rollout_pct: 25
```

The `config` map is passed to the module as its initialization payload -- a
free-form JSON object the module reads at load time. Use it for per-route
parameters the module needs (flag names, allowlists, canned response bodies)
so the same `.wasm` can drive many routes with different config.

## Writing a module

A nano-service module implements the gateway's handler ABI: an `init` entry
point that receives the `config` JSON, and a `handle` entry point that
receives the request (method, path, headers, body) and returns a response
(status, headers, body). The ABI is small and stable -- a module compiled
against it keeps working across gateway versions.

The module can be written in any language that compiles to WASI
([WebAssembly System Interface](https://wasi.dev/) -- the standard WASI
subset for sandboxed modules): Rust (with `wasm32-wasi` target), Go with
TinyGo, AssemblyScript, or C. A typical Rust module looks like:

```rust
// your module's lib.rs -- compile with: cargo build --target wasm32-wasi --release
use dwara_nano::{init, handle, Request, Response};

#[init]
fn init(config: Config) {
    // read config.flag, config.enabled, config.rollout_pct
}

#[handle]
fn handle(req: Request) -> Response {
    if enabled && rollout(req) {
        Response::ok().json(&flag_json())
    } else {
        Response::new(404).body("not enrolled")
    }
}
```

The module's `handle` runs synchronously per request, on the gateway's
worker pool. The sandbox caps memory and CPU: a module that exceeds its
memory budget or runs past its deadline is terminated and the request
returns `503` -- the gateway never lets a nano-service hang a worker.

## Sandboxing

A nano-service module runs with no host capabilities by default: no network,
no filesystem, no environment. The sandbox is the security boundary -- a
module cannot reach the gateway's config, secrets, or other routes. If a
module needs a host capability (a clock, a shared KV cache), it must be
granted explicitly in the route config via a `capabilities` block; the
gateway denies any call the module did not declare. This is the same
[proxy-wasm](./proxy-wasm-plugins) capability model, scoped to the
nano-service route action.

## Observability

Nano-service execution surfaces in [`/metrics`](./observability) as
`dwara_nano_service_total{route,outcome}` with outcomes `ok`,
`module_error`, and `sandbox_killed`, and `dwara_nano_service_duration_seconds`
for the in-process call latency. A module that returns an invalid response
(missing status, oversized body) is logged as `module_error` and the client
receives `502` -- the gateway treats a broken module like a broken upstream.
