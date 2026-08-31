# Plugin Lifecycle (DW-056)

## Overview

dwara supports plugin lifecycle management: loading from config (path
+ checksums), hot-swap on reload, config schema validation, and
failure isolation. This builds on the DW-055 proxy-wasm host.

## Enabling

Build with the `wasm` feature:

```sh
cargo build --features wasm
```

## Failure isolation

A crashed plugin returns 500 on affected routes only, never
gateway-wide. The plugin lifecycle manager tracks which plugins are
healthy and which routes use them. When a plugin crashes, only the
routes that reference that plugin are affected.

```rust
use dwara_core::wasm::{PluginLifecycle, PluginHealth};

let lifecycle = PluginLifecycle::new();

// Register which plugins a route uses.
lifecycle.register_route("route-1", &["my-plugin".to_string()]);

// A plugin crashes.
lifecycle.mark_crashed("my-plugin", "out of fuel");

// Only route-1 is affected; other routes continue normally.
assert!(lifecycle.route_should_500("route-1"));
assert!(!lifecycle.route_should_500("route-2"));
```

## Hot-swap on reload

When the config is reloaded, the lifecycle manager recompiles plugins
that changed (by checksum) and swaps them in atomically. Plugins that
did not change are reused (no recompilation).

## Config validation

```rust
use dwara_core::wasm::{PluginLifecycle, ValidationError};
use dwara_core::config::PluginConfig;

let config = PluginConfig { /* ... */ };
match PluginLifecycle::validate_config(&config) {
    Ok(()) => { /* valid */ }
    Err(ValidationError::NoPhases { plugin }) => { /* ... */ }
    Err(ValidationError::WasmNotFound { plugin, path }) => { /* ... */ }
    // ...
}
```

Validation checks:
- The .wasm path is non-empty
- The .wasm file exists
- Phases are non-empty
- Limits (fuel, memory, timeout) are non-zero

## Phase ordering

A route's plugin chain is deterministic from its config, not
load-order-dependent. The `phase_order` function returns plugins
grouped by phase in the defined order:

```rust
use dwara_core::wasm::PluginLifecycle;
use dwara_core::config::PluginPhase;

let order = PluginLifecycle::phase_order(
    &["plugin-a".to_string(), "plugin-b".to_string()],
    &plugins,
);

// order = [
//   (RequestHeaders, ["plugin-a", "plugin-b"]),
//   (RequestBody, ["plugin-b"]),
//   (ResponseBody, ["plugin-a"]),
// ]
```

## API

### PluginLifecycle

The lifecycle manager: tracks loaded plugins, their health, and
which routes use them.

### PluginHealth

- `Healthy`: the plugin is ready to serve
- `Crashed { error, crash_count }`: the plugin has crashed
- `Disabled { reason }`: the plugin is disabled

### LoadedPlugin

A loaded plugin: its config, checksum, and health.

### LoadError / ValidationError

Typed errors for loading and validation failures.

## Feature gate

The `wasm` cargo feature must be enabled. Without it, the module is
not compiled and the gateway runs without plugin support.
