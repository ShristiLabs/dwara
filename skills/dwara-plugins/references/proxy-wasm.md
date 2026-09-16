# proxy-wasm development walkthrough

> Status: the scaffold, toolchain, registry, and `plugins:` config are
> live; dispatching plugins on the live request path is the remaining
> wiring (the dataplane currently runs a no-wasm placeholder). Build and
> publish plugins today; verify dispatch in your build before depending
> on it in production.

## Scaffold and build

```sh
dwara-cli plugin new my-plugin
cd my-plugin
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1
```

Scaffold contents:

```
my-plugin/
├── Cargo.toml     # crate-type = ["cdylib"], proxy-wasm dependency
├── src/lib.rs     # the four proxy-wasm callbacks, stubbed
├── dwara.yaml     # plugin manifest (name, wasm path, phases)
└── README.md
```

The four phases your callbacks can serve: `request_headers`,
`request_body`, `response_headers`, `response_body` - declare them on the
plugin entry (and mirror in the manifest) so the host calls you at the
right points.

## Loading in config

(The block parses and validates today; request-path execution follows the
dispatch status above.)

```yaml
plugins:
  - name: my-plugin
    wasm: /etc/dwara/plugins/my_plugin.wasm
    phases: [request_headers, response_headers]
    limits:
      fuel: 1000000       # execution-fuel bound: loops die here, not at the
                          # request timeout
      memory_mb: 32
      timeout_ms: 100
    config:               # raw bytes handed to proxy_on_vm_start - conventionally
      ...                 # JSON the plugin parses itself

routes:
  - name: tagged
    # ...
    plugins: [my-plugin]  # opt-in per route
```

Load pipeline per plugin: read `.wasm` -> SHA-256 checksum -> wasmtime
compile -> export validation (`proxy_on_vm_start` minimum, exported memory,
no unknown imports) -> instantiate. A changed checksum hot-swaps the
instance on reload.

## Lifecycle states

| State | Meaning |
| --- | --- |
| `Healthy` | Serving |
| `Crashed { error, crash_count }` | Failed fuel/export/instantiation bounds. Routes referencing it fail **closed** with 500 - by design |
| `Disabled { reason }` | Deliberately off |

Plugin status is observable via `GET /plugins` on the admin API (and
`dwara-cli status`): name, kind/source, SHA-256 digest, lifecycle
state with error and crash_count, limits, phases, and the routes
referencing each plugin. Remove the config entry (reload) to disable.

## Registry distribution

```yaml
plugin_registry:
  base_url: https://shristilabs.github.io/dwara-plugins   # default (registry.dwara.dev will CNAME)
  public_keys: [...]                             # Ed25519 verification keys
  cache_dir: ...                                 # local cache

plugins:
  - name: some-plugin
    source:
      url: https://shristilabs.github.io/dwara-plugins/some-plugin.wasm
      digest: <sha256>             # REQUIRED - pin it
      signature: ...               # optional Ed25519
      public_key: ...
      cache_path: ...
```

CLI:

```sh
dwara-cli plugin search [query] [--registry URL]
dwara-cli plugin install <name> [--registry URL] [--digest HASH] [-o DIR]
# env: DWARA_PLUGIN_REGISTRY (default https://shristilabs.github.io/dwara-plugins)
# requires curl
```

Always pin `digest` in config - a registry compromise then cannot change
what runs in your gateway; `signature`/`public_key` add provenance on top.

## Testing pattern

1. Unit-test the callback logic as plain Rust (the proxy-wasm host
   context is mockable in the scaffold's test setup).
2. Integration: minimal gateway config with a `respond` route + the plugin
   attached - assert the response the plugin rewrites/blocks.
3. Fuel/memory behavior: write the pathological loop test once; confirm it
   dies at the bound and the route fails closed rather than hanging.
4. Roll out: attach to one canary route first (see dwara-traffic skill's
   splits), watch crash_count, then widen.
