# Plugin lifecycle

Plugin lifecycle management covers how plugins are loaded, validated,
hot-swapped, and health-tracked at runtime. This is the operator-facing
companion to [Proxy-Wasm plugins](./proxy-wasm-plugins) and [Native
plugin filters](./native-plugins).

::: info Status
The plugin runtime is live: plugins load, run on the request path,
hot-swap on reload, and are health-tracked in every build — there are
no `wasm`/`plugins` cargo features. Health is observable through the
admin API's plugin status surface (`GET /plugins`), the
`dwara_plugin_failures_total{name,reason}` /
`dwara_plugin_total{state}` metrics, and the load-failure log lines.
:::

## When to use this

- You deploy plugins (proxy-wasm or native) and need to know what
  happens on config reload -- which instances are hot-swapped versus
  restarted, and what happens to in-flight requests.
- A plugin is crashing or misbehaving and you need to understand the
  health tracking and failure isolation before you disable it.

## Loading

On every config publish (startup and reload), the plugin lifecycle
manager, for each configured plugin:

1. Reads the plugin's `.wasm` file from the configured path.
2. Computes a checksum of the module (hot-swap keying).
3. Compiles the module with wasmtime and validates the proxy-wasm ABI
   (`proxy_on_vm_start` export at minimum, an exported linear
   `memory`, no unknown host imports) via the plugin runner.
4. Tracks the plugin's health from the outcome.

A plugin whose file cannot be read or whose module fails to compile is
marked **Crashed at publish time** and logged (`plugin_load_failed` /
`plugin_compile_failed`) -- the rest of the config still loads, and
routes referencing the crashed plugin fail closed with 500
`plugin_unavailable` from the first request of the new generation.
The operator is expected to know, not discover it later from silently
missing behavior. (Native filters do not go through this path: they
are registered in the
[`NativeRegistry`](./native-plugins#registration) at startup and
dispatched by the unified chain.)

## Hot swap on reload

When config is reloaded, plugins are re-evaluated by comparing the
module checksum:

- **Unchanged plugin** (same checksum): the previously loaded instance
  and its health state are kept -- nothing is recompiled.
- **Changed plugin** (different checksum): the old module is replaced
  and the plugin's health resets to `Healthy`.
- **Removed plugin**: its entry is dropped; no new instances are
  created for it.

The swap is atomic from the lifecycle manager's point of view: the new
plugin table and runner are built first, then swapped in.

## Health tracking

The runtime tracks per-plugin health:

| State | Description |
| --- | --- |
| `Healthy` | Loaded and serving normally. |
| `Crashed { error, crash_count }` | The plugin cannot serve: its `.wasm` could not be read or compiled at publish time. `crash_count` grows across reloads of the same broken file. Routes referencing a crashed plugin fail closed with `500`. |
| `Disabled { reason }` | The plugin was disabled through the lifecycle API. |

Transitions:

- A read or compile failure at publish marks the plugin `Crashed`
  (logged as `plugin_load_failed` / `plugin_compile_failed`); the
  crash counter accumulates while the file stays broken.
- A reload that fixes the file (the checksum changes, or the plugin
  re-publishes clean) resets the plugin to `Healthy`.
- `mark_crashed` / `mark_healthy` / `disable` are lifecycle APIs for
  embedders; the stock gateway sets health at publish time only.

One honest caveat: a **runtime** trap (fuel exhaustion, panic) answers
500 `plugin_failed` on the affected requests but does not flip the
stored health state -- the plugin still reads `Healthy`, and fixing it
means shipping new bytes (a checksum change) and reloading. Watch
`dwara_plugin_failures_total{name,reason="trap"}` for runtime traps.

Health state lives in the lifecycle manager and is served through the
admin API's plugin status surface: `GET /plugins` returns one entry
per declared plugin with its state, checksum, and the routes
referencing it (see [Admin API](./admin-api)).

## Failure isolation

The manager keeps a route-to-plugins mapping so that a crash is
isolated to the routes that actually use the plugin:

1. The failure is recorded on the plugin (`Crashed`), with the error.
2. Requests on routes referencing the crashed plugin fail closed with
   `500` `plugin_unavailable` -- a broken plugin must not silently
   turn into an open pipe.
3. Requests on routes that do not reference it are unaffected, and the
   plugin-less fast path never touches the plugin machinery at all.

A crash does not disable the plugin permanently: a reload that fixes
the file publishes the plugin `Healthy` again. Every request-path
failure also increments `dwara_plugin_failures_total{name,reason}` and
sets the access log's `plugin_short_circuit` flag.

## Phase ordering

When multiple plugins hook the same phase, the unified
[`PluginChain`](./native-plugins) executes them in a deterministic
order: by phase first (`request_headers` before `request_body`, etc.),
then by the order plugins are listed on the route. The order is not
load-order-dependent -- reordering the route's `plugins` list changes
execution order.

## Runnable demo

Run this feature against a live gateway: [`demos/08-extensibility/`](https://github.com/shristilabs/dwara/tree/main/demos/08-extensibility) in the repository.
`test-06-plugin-lifecycle.sh` verifies the lifecycle config shape and
the live hot-reload flow; `test-02-proxy-wasm.sh` additionally asserts
the crashed-plugin fail-closed behavior live. See the category README
for prerequisites and teardown.
