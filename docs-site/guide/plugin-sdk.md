# Plugin SDK

The Plugin SDK provides scaffolding for new proxy-wasm plugin
projects. The `dwara plugin new` command generates a ready-to-build
plugin crate with the proxy-wasm ABI, a `dwara.yaml` manifest, and a
README.

## When to use this

Use the SDK when you are writing a new plugin from scratch. The
scaffold gives you:

- A Cargo crate configured for the `wasm32-wasip1` target.
- The `proxy-wasm` dependency wired up.
- A minimal plugin implementation with the four phase callbacks
  stubbed out.
- A `dwara.yaml` manifest for loading the plugin into the gateway.
- A README with build and test instructions.

## Scaffolding a plugin

```sh
dwara plugin new my-plugin
```

This creates a `my-plugin/` directory:

```
my-plugin/
  Cargo.toml      # crate-type = ["cdylib"], proxy-wasm dep
  src/
    lib.rs        # minimal plugin: on_http_request_headers, etc.
  dwara.yaml      # plugin manifest (name, wasm path, phases)
  README.md       # build and test instructions
```

## Building the plugin

Plugins target `wasm32-wasip1`. Install the target if you haven't:

```sh
rustup target add wasm32-wasip1
```

Build the plugin:

```sh
cd my-plugin
cargo build --release --target wasm32-wasip1
```

The compiled `.wasm` file is at
`target/wasm32-wasip1/release/my_plugin.wasm`.

## Loading the plugin

Copy or symlink the `.wasm` file to a path the gateway can read, then
reference it in your gateway config:

```yaml
plugins:
  - name: my-plugin
    wasm: ./my-plugin/target/wasm32-wasip1/release/my_plugin.wasm
    phases:
      - request_headers
      - response_headers
    config: |
      { "key": "value" }
```

See [Proxy-Wasm plugins](./proxy-wasm-plugins) for the full plugin
configuration reference.

## The generated plugin

The scaffolded `src/lib.rs` implements the four proxy-wasm phase
callbacks:

```rust
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

#[no_mangle]
pub struct MyPlugin;

impl Context for MyPlugin {}

impl HttpContext for MyPlugin {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // Add a request header
        self.set_http_request_header("x-my-plugin", Some("active"));
        Action::Continue
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        Action::Continue
    }

    fn on_http_request_body(&mut self, _body_size: usize, _end_of_stream: bool) -> Action {
        Action::Continue
    }

    fn on_http_response_body(&mut self, _body_size: usize, _end_of_stream: bool) -> Action {
        Action::Continue
    }
}
```

Customize the callbacks to implement your plugin's logic.

## Plugin config

The `config` field in the gateway config is passed to the plugin as
raw bytes via `proxy_on_vm_start`. The plugin is responsible for
parsing it (typically as JSON or YAML):

```rust
impl PluginConfig for MyPlugin {
    fn on_configure(&mut self, config_size: usize) -> bool {
        let config = self.get_plugin_configuration();
        // Parse config bytes...
        true
    }
}
```

## Testing

The scaffolded plugin can be tested with the gateway's integration
test suite. See [Plugin lifecycle](./plugin-lifecycle) for how
plugins are loaded and validated.
