# proxy-wasm Host (DW-055)

## Overview

dwara includes a proxy-wasm ABI host built on wasmtime, allowing
community Kong/Envoy proxy-wasm filters to run unmodified. The host is
compiled into the OSS build; wasmtime + cranelift are a significant
binary-size cost.

## Enabling

The proxy-wasm host is compiled into the default build:

```sh
cargo build
```

The `plugins` config block activates proxy-wasm filters when present.
Without a `plugins` block, the host is inert (no filters are loaded).

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
- `proxy_get_shared_data` / `proxy_set_shared_data` — VM-scoped
  shared data with CAS (one map per compiled module, shared by every
  per-request instance of that plugin — DW-167; what a callout
  plugin's TTL cache is built on). Capped per module at 1024 entries
  and 1 MiB of key+value bytes: an over-cap set fails with an error
  status (the SDK surfaces `Err(Status::CasMismatch)`), never evicts
- `proxy_set_effective_context` / `proxy_done` — context management
- `proxy_get_property` / `proxy_set_property` — property access
  (minimal: returns empty for unknown properties)
- `proxy_define_metric` / `proxy_record_metric` /
  `proxy_increment_metric` / `proxy_get_metric` — plugin metrics
- `proxy_get_current_time` — current time in nanoseconds
- `proxy_http_call` — HTTP callouts to http/https targets (DW-167):
  registers the exchange, the phase pauses, and the dispatch driver
  in `dataplane::plugin_dispatch` performs it off-thread and delivers
  `proxy_on_http_call_response` (see below)
- `proxy_on_memory_allocate` — the standard proxy-wasm allocation
  pattern (the plugin exports this; the host calls it to allocate
  space for returned data)

The following ABI functions are stubbed (return error): shared queues,
gRPC calls, foreign function calls, and tick periods. These are
not needed for the HTTP filter subset and will be added in future
stories.

## HTTP callouts (DW-167)

`proxy_http_call` follows the proxy-wasm pause/resume contract with
the wasm runner kept fully synchronous:

1. the phase callback dispatches (URI string, spec-serialized
   header/trailer maps, optional body, timeout in MILLISECONDS — the
   Rust SDK's `dispatch_http_call` encoding) and the host registers a
   token-tagged pending callout on the instance;
2. the chain reports `ChainOutcome::CalloutPending` and stops at the
   paused entry (a new outcome variant; native filters never produce
   it);
3. the ASYNC boundary — `plugin_dispatch::RequestPlugins::
   resolve_callouts` — performs each exchange on `spawn_blocking`
   around the synchronous client in `wasm::callout` (the registry
   fetcher's transport with `http://` and arbitrary methods added),
   records `dwara_plugin_callouts_total{name,outcome}`, and delivers
   the response with a synchronous wasmtime re-entry (the SDK's
   5-parameter `proxy_on_http_call_response(context_id, token,
   num_headers, body_size, num_trailers)` export; `:status` rides the
   MapType-6 header map, the body the BufferType-4 buffer);
4. on resume the chain continues from the entry AFTER the paused one
   with the plugin's post-callback payload (`PluginChain::resume_*`).

Guardrails (hard caps, no config surface): timeout clamped to
[1ms, 5s] as a whole-exchange wall clock; 8 callout rounds per phase
per request (the loop guard — exceeding fails closed, metric reason
`callout_loop`); 4 MiB response-body cap; 16 KiB head cap; the request
head validated fail-closed at the hostcall (`:method` and header
names must be HTTP tokens; names, values, and `:path` must be
CR/LF/NUL-free — violations answer BadArgument with no connection
attempted, the request-splitting posture); redirects refused (a 3xx is
delivered as data); the gateway SSRF egress filter applied at connect
time against every resolved IP.

Failure semantics (a deliberate deviation from Envoy's empty-callback
delivery): any COMPLETED response is delivered — non-2xx included —
but a callout that cannot complete (timeout, refused, over-cap, SSRF)
fails the route closed (500 `plugin_failed`, metric reason
`callout_failed`): a plugin must not resume as though its decision
input had arrived. Recipes wanting fail-open behavior scope it
without depending on the callout answering.

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
