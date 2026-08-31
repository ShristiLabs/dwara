# Native Plugin Filters (DW-119)

## Overview

dwara supports two plugin implementation paths, both selected by config
and both occupying the same phase slot on a route with no
dataplane-visible difference in attachment semantics:

1. **proxy-wasm plugins** (DW-055) -- portable `.wasm` modules loaded
   into a sandboxed wasmtime host at startup. The portability/ABI path.
2. **native plugin filters** (DW-119) -- Rust filters compiled into the
   gateway binary at build time and linked in directly. The
   convenience/performance path.

A native filter and a WASM plugin attach identically from config's
point of view: both are entries in the top-level `plugins` list,
referenced by name from routes, and both declare the same phase
contract. Only the implementation differs -- compiled-in vs
sandboxed-and-hot-loaded.

## Enabling

Native filters are feature-gated behind the `plugins` cargo feature
(default OFF):

```sh
cargo build --features plugins
```

Combine with `wasm` for both paths:

```sh
cargo build --features plugins,wasm
```

When `plugins` is on but `wasm` is off, only native filters work. When
both are on, both work and share the unified dispatch chain.

## The NativeFilter trait

A native filter is a Rust type implementing
`dwara_core::plugins::NativeFilter` -- a dyn-compatible trait mirroring
the proxy-wasm host's phase callbacks. Each method receives the current
headers/body by value and returns a `FilterOutcome`:

```rust
use dwara_core::plugins::{NativeFilter, FilterOutcome};

pub struct AddHeaderFilter {
    name: String,
    value: String,
}

impl NativeFilter for AddHeaderFilter {
    fn on_request_headers(
        &mut self,
        mut headers: Vec<(String, String)>,
    ) -> FilterOutcome {
        headers.push((self.name.clone(), self.value.clone()));
        FilterOutcome::Continue { headers, body: Vec::new() }
    }
}
```

The methods are synchronous, matching the WASM runner's synchronous
phase methods -- the proxy calls them synchronously per phase. A filter
that does not hook a phase returns `Continue` with the input unchanged
(the default trait method does this).

### FilterOutcome

`FilterOutcome` mirrors `wasm::runner::PhaseOutcome` so a native filter
and a WASM plugin are interchangeable in the unified chain:

- `Continue { headers, body }` -- proceed to the next plugin/phase. The
  (possibly modified) headers/body are threaded through.
- `LocalResponse(LocalResponse)` -- short-circuit with a local response;
  the proxy returns it immediately.
- `Error(String)` -- the filter failed (the proxy returns a 500,
  mirroring a WASM trap). The message is logged and never leaked to the
  client.

## Registration

Compiled-in filters register themselves at startup via
`NativeRegistry::register` -- a simple function the binary calls (no
inventory/linkme, dependency-free):

```rust
use dwara_core::plugins::{NativeRegistry, NativeFilterFactory};

let registry = NativeRegistry::new();
registry.register("add-header", Box::new(|_cfg| {
    Ok(Box::new(AddHeaderFilter {
        name: "x-native".into(),
        value: "dwara".into(),
    }))
})).unwrap();
```

The factory receives the plugin's opaque `config` string (the same blob
a WASM plugin gets via `proxy_on_configure`); a native filter parses it
itself (typically JSON or YAML).

## Configuration

A plugin is either `wasm:` or `native:` (exactly one must be set):

```yaml
plugins:
  - name: my-native
    native: add-header
    phases:
      - request_headers
      - response_headers
    config: '{"key": "value"}'

routes:
  - name: api
    service: backend
    match:
      path:
        type: exact
        value: /api
    action:
      type: proxy
    plugins:
      - my-native
```

### Plugin fields

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Unique plugin name; referenced by routes |
| `wasm` | string | one of wasm/native | Path to the .wasm module file (WASM plugins) |
| `native` | string | one of wasm/native | Registered native filter implementation name (native plugins) |
| `phases` | list | yes (non-empty) | Phases to hook: `request_headers`, `request_body`, `response_headers`, `response_body` |
| `config` | string | no | Plugin-specific config (passed to the factory / `proxy_on_configure`) |
| `limits` | object | no | Resource limits (WASM only; fuel, memory, time) |

Validation enforces: exactly one of `wasm`/`native`, non-empty
`phases`, no duplicate plugin names, and route `plugins` references
must name a defined plugin.

## Phase contract (section 9.3)

The phases and their outcome semantics mirror the proxy-wasm host
exactly. The four HTTP filter phases are:

1. `request_headers` -- after route resolution, before authn.
2. `request_body` -- after authn/authz/rate-limit, before upstream.
3. `response_headers` -- after the upstream responds, before masking.
4. `response_body` -- after masking, before compression.

A native filter can short-circuit with a `LocalResponse` at any phase,
exactly as a WASM plugin can via `proxy_send_http_response`.

## Unified dispatch chain

`PluginChain` is the single integration seam the dataplane calls. Given
a route's plugin names, the gateway's plugin configs, the native
registry, and an optional WASM dispatch adapter, it builds the
per-request execution list combining native filters and WASM instances
IN PHASE ORDER (deterministic, using the same ordering logic as
`wasm::lifecycle::PluginLifecycle::phase_order`). It exposes the same
phase methods and dispatches to each plugin in order, threading
headers/body through and short-circuiting on `LocalResponse`/`Error`.

The chain is generic over a `WasmDispatch` adapter so the `plugins`
domain never imports `wasm` (dependency direction stays downward). The
`wasm` domain provides `WasmChainAdapter` (gated behind both `wasm` and
`plugins` features) that bridges its `PluginInstances` into the unified
chain. When the `wasm` feature is off, the chain uses `NoWasm`.

## Relationship to proxy-wasm plugins

| Aspect | Native filter (DW-119) | WASM plugin (DW-055) |
|---|---|---|
| Implementation | Rust, compiled in | .wasm module, sandboxed |
| Selection | `native: <name>` | `wasm: <path>` |
| Phase contract | identical | identical |
| Outcome semantics | `FilterOutcome` | `PhaseOutcome` |
| Sandbox | none (in-process) | wasmtime (fuel, memory, time) |
| Hot-load | no (build-time) | yes (startup/reload) |
| Portability | no (Rust + dwara-core) | yes (community Kong/Envoy filters) |

Both share the same phase slot on a route, selected by config, with no
dataplane-visible difference in attachment semantics.

## Architecture

- `plugins::NativeFilter` -- the dyn-compatible trait.
- `plugins::FilterOutcome` / `plugins::LocalResponse` -- the shared
  outcome/response types (canonical in the lower `plugins` domain).
- `plugins::NativeRegistry` -- implementation name -> factory registry
  (dependency-free, `Send + Sync`).
- `plugins::PluginChain` -- the unified per-request dispatch chain
  (generic over `WasmDispatch`).
- `plugins::WasmDispatch` / `plugins::NoWasm` -- the WASM adapter
  interface and the no-op default.
- `wasm::adapter::WasmChainAdapter` -- the `wasm` domain's bridge from
  `PluginInstances` to `WasmDispatch` (gated behind `wasm` + `plugins`).

## Dependency direction

`plugins` depends on `config` only. It does NOT depend on `wasm`: the
unified chain is generic over `WasmDispatch` so `wasm` (which may
depend on `plugins`) can bridge its instances in without an upward
import. This keeps the dependency direction strictly downward (enforced
by `scripts/check_deps.py`).
