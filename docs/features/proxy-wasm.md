# proxy-wasm Host (DW-055)

## Overview

dwara includes a proxy-wasm ABI host built on wasmtime, allowing
community Kong/Envoy proxy-wasm filters to run unmodified. The host is
feature-gated behind the `wasm` cargo feature (default OFF) because
wasmtime + cranelift are significant binary size against the DW-026
25MB budget.

## Enabling

Build with the `wasm` feature:

```sh
cargo build --features wasm
```

Without the feature, the `plugins` config block is accepted but inert
(plugins are not loaded or executed).

## Configuration

Plugins are defined in the top-level `plugins` list and attached to
routes via the `plugins` field:

```yaml
plugins:
  - name: my-filter
    wasm: /opt/plugins/my-filter.wasm
    phases:
      - request_headers
      - response_headers
    config: '{"key": "value"}'
    limits:
      fuel: 500000
      memory_mb: 16
      timeout_ms: 50

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
      - my-filter
```

### Plugin fields

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Unique plugin name; referenced by routes |
| `wasm` | string | yes | Path to the .wasm module file |
| `phases` | list | no | Phases to hook: `request_headers`, `request_body`, `response_headers`, `response_body` |
| `config` | string | no | Plugin-specific config (passed to `proxy_on_configure` as bytes) |
| `limits` | object | no | Resource limits (see below) |

### Resource limits

| Field | Default | Description |
|---|---|---|
| `fuel` | 1,000,000 | Maximum wasmtime operations (fuel) |
| `memory_mb` | 32 | Maximum linear memory in MB |
| `timeout_ms` | 100 | Maximum execution time in milliseconds |

When a plugin exhausts its fuel budget, it traps and the host returns a
500. When a plugin exceeds its memory cap, the allocation fails and the
plugin traps. Time caps use wasmtime's epoch interruption.

## Phase contract (section 9.3)

dwara's request pipeline calls plugin phase callbacks at defined points.
The phases relevant to HTTP filters are:

1. **request_headers** — after route resolution, before authn. The
   plugin can inspect and modify request headers, or short-circuit with
   a local response.
2. **request_body** — after authn/authz/rate-limit, before upstream.
   The plugin can read and modify the request body.
3. **response_headers** — after the upstream responds, before masking.
   The plugin can inspect and modify response headers.
4. **response_body** — after masking, before compression. The plugin
   can read and modify the response body.

A plugin can short-circuit the request at any phase by calling
`proxy_send_http_response`. The host catches this and returns the
stored response immediately, skipping all subsequent phases.

## ABI surface

The host implements the HTTP filter subset of the proxy-wasm ABI:

- `proxy_log` — emit a log line at trace/debug/info/warn/error/critical
- `proxy_get_buffer_bytes` / `proxy_set_buffer_bytes` — read/write
  request/response bodies and config buffers
- `proxy_get_buffer_status` — get buffer size
- `proxy_get_header_map_pairs` / `proxy_set_header_map_pairs` —
  read/write the full header map
- `proxy_get_header_map_value` / `proxy_add_header_map_value` /
  `proxy_replace_header_map_value` / `proxy_remove_header_map_value` —
  individual header operations
- `proxy_send_http_response` — short-circuit with a local response
- `proxy_continue_stream` / `proxy_close_stream` — stream control
- `proxy_get_shared_data` / `proxy_set_shared_data` — cross-instance
  shared data with CAS
- `proxy_set_effective_context` / `proxy_done` — context management
- `proxy_get_property` / `proxy_set_property` — property access
  (minimal: returns empty for unknown properties)
- `proxy_define_metric` / `proxy_record_metric` /
  `proxy_increment_metric` / `proxy_get_metric` — plugin metrics
- `proxy_get_current_time` — current time in nanoseconds
- `proxy_on_memory_allocate` — the standard proxy-wasm allocation
  pattern (the plugin exports this; the host calls it to allocate
  space for returned data)

The following ABI functions are stubbed (return error): shared queues,
HTTP/gRPC calls, foreign function calls, and tick periods. These are
not needed for the HTTP filter subset and will be added in future
stories.

## Architecture

- `WasmEngine` — process-wide wasmtime engine + linker, compiled once
  at startup. Holds the compiled modules keyed by config name.
- `PluginModule` — a compiled wasmtime module for one plugin config
  entry. Created once at config publish time.
- `PluginInstance` — a per-request plugin instance (store + instance +
  context). Created for each request that passes through a route with
  plugins.
- `PluginContext` — the per-instance state the host imports read from
  and write to: request/response headers, body, the action returned by
  the plugin, etc.
- `PluginRunner` — the integration layer between the proxy pipeline and
  the host. Holds compiled modules and provides per-request methods to
  run each phase.

## Security

- Each plugin runs in a sandboxed wasmtime instance with fuel
  consumption and epoch interruption enabled.
- Memory is capped via wasmtime's `ResourceLimiter`.
- Plugins cannot access the filesystem, network, or environment
  variables (no WASI imports are provided).
- A plugin that traps (out of fuel, memory error, or panic) does not
  crash the gateway; the request gets a 500 and the gateway continues.
