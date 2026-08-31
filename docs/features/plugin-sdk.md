# Plugin SDK + Scaffolding (DW-057)

## Overview

dwara provides a plugin SDK and scaffolding tool for authoring
proxy-wasm plugins in Rust. The `dwara plugin new` command generates
a new plugin project from a template, targeting `wasm32-wasip1`.

## Quick start: new plugin in < 30 min

### 1. Scaffold the plugin

```sh
dwara plugin new my-plugin
```

This creates a `my-plugin/` directory with:
- `Cargo.toml` -- targets `wasm32-wasip1`, depends on `proxy-wasm`
- `src/lib.rs` -- a minimal proxy-wasm filter with phase callbacks
- `dwara.yaml` -- a minimal gateway config that loads the plugin
- `README.md` -- build + run instructions
- `.gitignore` -- ignores `target/`

### 2. Build the plugin

```sh
cd my-plugin
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1
```

The compiled `.wasm` file is at
`target/wasm32-wasip1/release/my-plugin.wasm`.

### 3. Run the gateway

```sh
dwara run --config dwara.yaml
```

The gateway listens on `127.0.0.1:8080` and forwards requests to
`127.0.0.1:9000`. The plugin logs the request path at the
`request_headers` phase.

### 4. Edit the plugin

Edit `src/lib.rs` to implement your custom logic at any of the four
phases:

- `on_http_request_headers` -- after route resolution, before authn
- `on_http_request_body` -- after authn/authz/rate-limit, before upstream
- `on_http_response_headers` -- after the upstream responds, before masking
- `on_http_response_body` -- after masking, before compression

A plugin can short-circuit the request by calling `send_http_response`
(returns a local response instead of forwarding to the upstream).

## Phase contract (section 9.3)

dwara's request pipeline calls plugin phase callbacks at defined
points. Each plugin declares which phase(s) it hooks. The phases
relevant to HTTP filters are:

1. `request_headers` -- after route resolution, before authn.
2. `request_body` -- after authn/authz/rate-limit, before upstream.
3. `response_headers` -- after the upstream responds, before masking.
4. `response_body` -- after masking, before compression.

A plugin's phase chain is deterministic from its config, not
load-order-dependent (see DW-056).

## Plugin config

The plugin's `config` field in `dwara.yaml` is passed to the plugin's
`on_configure` callback as a byte string. Parse it as JSON or YAML in
your plugin:

```rust
fn on_configure(&mut self, _config_size: usize) -> bool {
    let config = self.get_configuration();
    // Parse config as JSON or YAML...
    true
}
```

## Resource limits

Each plugin gets resource limits (fuel, memory, time) configured in
`dwara.yaml`:

```yaml
plugins:
  - name: my-plugin
    wasm: target/wasm32-wasip1/release/my-plugin.wasm
    phases:
      - request_headers
    limits:
      fuel: 1000000        # wasmtime operations (default: 1M)
      memory_mb: 32        # linear memory in MB (default: 32)
      timeout_ms: 100      # execution time in ms (default: 100)
```

Fuel exhaustion traps the plugin, which the host converts to a 500.
Memory is capped via wasmtime's `ResourceLimiter`. Time caps use
epoch interruption.

## Failure isolation

A crashed plugin returns 500 on affected routes only, never
gateway-wide (see DW-056). The plugin lifecycle manager tracks which
plugins are healthy and which routes use them.

## Testing

The scaffold includes a minimal proxy-wasm filter that exercises the
core ABI surface (header inspection, response short-circuit, body
modification). See the dwara documentation for the plugin test harness
and the phase contract conformance suite.

## `dwara plugin new` options

```
dwara plugin new <name> [--dir <dir>]

  name    The plugin name (used for the crate name and directory).
          Must start with a letter or underscore, and contain only
          letters, digits, underscores, and hyphens.
  --dir   The parent directory; the scaffold is created in <dir>/<name>/.
          Defaults to the current directory.
```
