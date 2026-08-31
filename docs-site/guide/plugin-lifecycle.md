# Plugin lifecycle

Plugin lifecycle management covers how plugins are loaded, validated,
hot-reloaded, and monitored at runtime. This is the operator-facing
companion to [Proxy-Wasm plugins](./proxy-wasm-plugins).

## Loading

On gateway startup, the plugin loader:

1. Reads each plugin's `.wasm` file from the configured path.
2. Computes a SHA-256 checksum of the module.
3. Compiles the module with wasmtime.
4. Validates the module exports the required proxy-wasm entry points
   (`proxy_on_vm_start`, `proxy_on_request_headers`, etc.).
5. Instantiates the module with the configured resource limits.

Plugins that fail to compile or validate are **skipped** (with a log
warning) -- the gateway starts even if a plugin is broken. A broken
plugin does not block startup.

## Validation

Each plugin module is validated against the proxy-wasm ABI:

- Required exports must be present (`proxy_on_vm_start` at minimum).
- The module must export a linear `memory`.
- The module must not import unknown host functions.

Validation failures are logged with the plugin name and the specific
error. The plugin is not loaded.

## Hot reload

When the config is reloaded (via file watch or admin API), plugins
are re-evaluated:

- **New plugin**: loaded and compiled on first appearance.
- **Removed plugin**: its module is dropped; no new instances are
  created.
- **Changed plugin** (different `.wasm` path or checksum): the old
  module is replaced with the new one. In-flight requests finish
  with the old module; new requests use the new module.

## Health monitoring

The plugin runner tracks per-plugin health:

| State | Description |
|---|---|
| `Healthy` | Plugin loaded and running normally. |
| `Degraded` | Plugin has had failures (panics, timeouts) but is still loaded. |
| `Failed` | Plugin failed to load or has been disabled. |

Plugin health is exposed via the admin API:

```sh
curl --cert admin.crt --key admin.key https://127.0.0.1:2019/plugins
```

```json
{
  "plugins": [
    {
      "name": "rate-limiter",
      "state": "healthy",
      "checksum": "sha256:abc123...",
      "instances": 4,
      "failures": 0
    }
  ]
}
```

## Failure isolation

When a plugin invocation fails (panic, fuel exhaustion, timeout):

1. The failure is logged with the plugin name and request id.
2. The plugin is marked degraded (failure count incremented).
3. The request continues without that plugin's contribution.
4. The plugin is NOT disabled -- subsequent requests still invoke it.

This means a transient failure (e.g. a single timeout) does not
permanently disable a plugin. The plugin recovers automatically on
the next successful invocation.

## Phase ordering

When multiple plugins hook the same phase, they execute in a
deterministic order:

1. By phase (request_headers before request_body, etc.).
2. Within a phase, by the order plugins are listed on the route.

The order is **not** load-order-dependent -- it is determined by the
route's `plugins` list, so reordering the list changes execution
order.
