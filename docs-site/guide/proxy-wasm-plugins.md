# Proxy-Wasm plugins

Dwara supports [Proxy-Wasm](https://proxy-wasm.spec.vec.io/) plugins
-- WebAssembly modules that run inside the gateway and intercept
requests and responses at defined phases. This is the primary
extension mechanism for custom logic that the built-in config cannot
express.

## When to use this

Use proxy-wasm plugins when you need:

- Custom request/response header manipulation logic.
- Request body inspection or transformation.
- Custom authentication or authorization checks.
- Rate limiting with custom key derivation.
- Logging or metrics with custom labels.

Plugins run in a sandboxed WebAssembly runtime (wasmtime) with
configurable resource limits (fuel, memory, timeout).

## Enabling

Proxy-wasm support is feature-gated. Build with the `wasm` feature:

```sh
cargo build --features wasm
```

Without the feature, plugin config blocks are accepted but inert
(plugins are not loaded or executed).

## Configuration

Define plugins at the top level and reference them from routes:

```yaml
plugins:
  - name: rate-limiter
    wasm: ./plugins/rate-limiter.wasm
    phases:
      - request_headers
    limits:
      fuel: 1000000
      memory_mb: 32
      timeout_ms: 100
    config: |
      { "limit": 100, "window": "1m" }

routes:
  - name: api
    service: api-service
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy }
    plugins:
      - rate-limiter
```

### Plugin fields

| Field | Default | Description |
|---|---|---|
| `name` | (required) | Plugin name (referenced by routes). |
| `wasm` | (required) | Path to the `.wasm` module. |
| `phases` | (required) | Phases the plugin hooks. Must be non-empty. |
| `limits` | see below | Resource limits for the plugin. |
| `config` | (none) | Plugin-specific config (passed as bytes to the module). |

### Phase contract

Plugins hook into the request lifecycle at defined phases:

| Phase | Description |
|---|---|
| `request_headers` | After route resolution, before authn. |
| `request_body` | After the request body is received. |
| `response_headers` | After upstream response headers arrive. |
| `response_body` | After the upstream response body is received. |

A plugin can hook multiple phases. The `phases` list determines
which callbacks the gateway invokes.

### Resource limits

| Field | Default | Description |
|---|---|---|
| `fuel` | `1000000` | Wasmtime fuel (CPU budget). The plugin is interrupted when fuel is exhausted. |
| `memory_mb` | `32` | Maximum linear memory in MB. |
| `timeout_ms` | `100` | Maximum wall-clock time per invocation. |

### Plugin return actions

A plugin can return one of:

- **Continue** (`0`): proceed to the next phase or plugin.
- **End stream** (`1`): short-circuit the request (e.g. return a 403).
- **Pause** (`2`): pause the stream (for async operations).

When a plugin short-circuits, the gateway returns the response the
plugin set via `proxy_send_http_response`.

## Failure isolation

A plugin that panics, exhausts fuel, or times out is isolated: the
gateway logs the error and continues processing the request without
that plugin. One broken plugin does not break the request path.

## Creating a plugin

See [Plugin SDK](./plugin-sdk) for scaffolding a new plugin project
with the `dwara plugin new` command.
