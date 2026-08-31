# Native plugin filters

Dwara supports two plugin implementation paths, both selected by config
and both occupying the same phase slot on a route with no
dataplane-visible difference in attachment semantics:

- **Proxy-Wasm plugins** -- portable `.wasm` modules loaded into a
  sandboxed runtime at startup. The portability/ABI path (see
  [Proxy-Wasm plugins](./proxy-wasm-plugins)).
- **Native plugin filters** -- Rust filters compiled into the gateway
  binary at build time and linked in directly. The
  convenience/performance path.

A native filter and a WASM plugin attach identically from config's
point of view: both are entries in the top-level `plugins` list,
referenced by name from routes, and both declare the same phase
contract. Only the implementation differs -- compiled-in vs
sandboxed-and-hot-loaded.

## When to use this

Use native plugin filters when you need:

- Maximum performance (no sandbox overhead, no ABI marshalling).
- Direct access to Rust types and the dwara-core library.
- A filter that does not need to be portable across proxy-wasm hosts.

Use proxy-wasm plugins when you need portability (community Kong/Envoy
filters run unmodified) or hot-loading without a rebuild.

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
| `name` | string | yes | Unique plugin name (referenced by routes). |
| `wasm` | string | one of `wasm`/`native` | Path to the `.wasm` module (WASM plugins). |
| `native` | string | one of `wasm`/`native` | Registered native filter implementation name (native plugins). |
| `phases` | list | yes (non-empty) | Phases the plugin hooks. |
| `config` | string | no | Plugin-specific config (passed to the factory). |
| `limits` | object | no | Resource limits (WASM only: fuel, memory, time). |

Validation enforces: exactly one of `wasm`/`native`, non-empty
`phases`, no duplicate plugin names, and route `plugins` references
must name a defined plugin.

### Phase contract

Plugins hook into the request lifecycle at defined phases:

| Phase | Description |
|---|---|
| `request_headers` | After route resolution, before authn. |
| `request_body` | After authn/authz/rate-limit, before upstream. |
| `response_headers` | After upstream response headers arrive, before masking. |
| `response_body` | After masking, before compression. |

A plugin can hook multiple phases. A native filter can short-circuit
with a local response at any phase, exactly as a WASM plugin can via
`proxy_send_http_response`.

## Writing a native filter

A native filter is a Rust type implementing the `NativeFilter` trait.
Each method receives the current headers/body by value and returns a
`FilterOutcome`:

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
phase methods. A filter that does not hook a phase returns `Continue`
with the input unchanged (the default trait method does this).

### FilterOutcome

- **Continue** -- proceed to the next plugin/phase. The (possibly
  modified) headers/body are threaded through.
- **LocalResponse** -- short-circuit with a local response; the proxy
  returns it immediately.
- **Error** -- the filter failed (the proxy returns a 500, mirroring a
  WASM trap). The message is logged and never leaked to the client.

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

## Relationship to proxy-wasm plugins

| Aspect | Native filter | WASM plugin |
|---|---|---|
| Implementation | Rust, compiled in | `.wasm` module, sandboxed |
| Selection | `native: <name>` | `wasm: <path>` |
| Phase contract | identical | identical |
| Sandbox | none (in-process) | wasmtime (fuel, memory, time) |
| Hot-load | no (build-time) | yes (startup/reload) |
| Portability | no (Rust + dwara-core) | yes (community filters) |

Both share the same phase slot on a route, selected by config, with no
dataplane-visible difference in attachment semantics.
