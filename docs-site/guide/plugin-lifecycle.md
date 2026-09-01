# Plugin lifecycle

Plugin lifecycle management covers how plugins are loaded, validated,
hot-swapped, and health-tracked at runtime. This is the operator-facing
companion to [Proxy-Wasm plugins](./proxy-wasm-plugins) and [Native
plugin filters](./native-plugins).

::: info Status
The plugin runtime is a compile-time feature pack (`wasm` for the
proxy-wasm host, `plugins` for native filters; both default OFF -- see
[Editions](./editions#compile-time-feature-packs)) and is not included
in the published OSS binaries. The lifecycle manager, runner, and
unified dispatch chain are complete and test-covered as library
components; wiring them into the gateway's request path is landing
iteratively (see the [changelog](https://github.com/shristilabs/dwara/blob/main/CHANGELOG.md)).
This page documents the lifecycle behavior the runtime implements.
:::

## Loading

On load, the plugin lifecycle manager, for each configured plugin:

1. Reads the plugin's `.wasm` file from the configured path.
2. Computes a SHA-256 checksum of the module.
3. Compiles the module with wasmtime (via the plugin runner).
4. Validates the module against the proxy-wasm ABI: required exports
   (`proxy_on_vm_start` at minimum), an exported linear `memory`, and
   no unknown host-function imports.
5. Instantiates the module with the configured resource limits
   (fuel, memory, timeout).

A plugin whose file cannot be read or whose module fails to compile
**fails the load** -- the operator is expected to know, not discover
it later from silently missing behavior. (Native filters do not go
through this path: they are registered in the
[`NativeRegistry`](./native-plugins#registration) at startup and
dispatched by the unified chain.)

## Hot swap on reload

When config is reloaded, plugins are re-evaluated by comparing
checksums:

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
| `Crashed { error, crash_count }` | The plugin failed at runtime (e.g. a trap); `crash_count` increments per crash. Routes referencing a crashed plugin fail closed with `500`. |
| `Disabled { reason }` | The plugin was disabled -- manually or by the circuit breaker. |

Transitions:

- A runtime failure calls `mark_crashed` with the error; the counter
  accumulates across crashes.
- A successful invocation (or a changed checksum on reload) calls
  `mark_healthy`, resetting to `Healthy`.
- The circuit breaker can `disable` a plugin with a reason; a disabled
  plugin is not invoked.

Health state currently lives in the lifecycle manager. Exposing plugin
health through the admin API is a documented follow-up -- there is no
`/plugins` admin endpoint yet.

## Failure isolation

The manager keeps a route-to-plugins mapping so that a crash is
isolated to the routes that actually use the plugin:

1. The failure is recorded on the plugin (`Crashed`), with the error.
2. Requests on routes referencing the crashed plugin fail closed with
   `500` -- a broken plugin must not silently turn into an open pipe.
3. Requests on routes that do not reference it are unaffected.

A crash does not disable the plugin permanently: the next successful
invocation marks it healthy again (and a reload that changes the
module resets health outright).

## Phase ordering

When multiple plugins hook the same phase, the unified
[`PluginChain`](./native-plugins) executes them in a deterministic
order: by phase first (`request_headers` before `request_body`, etc.),
then by the order plugins are listed on the route. The order is not
load-order-dependent -- reordering the route's `plugins` list changes
execution order.
