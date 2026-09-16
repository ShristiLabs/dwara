# header-guard

Allow or deny requests by the value of one header. The simplest
access-control plugin: requests carrying the configured header with
the configured value are forwarded; everything else is answered `403`
by the plugin itself (`proxy_send_http_response`) and the upstream is
never dialed.

| Request | Result |
|---|---|
| no `x-guard-key` header | `403` `{"error":"forbidden by header-guard"}` |
| `x-guard-key: wrong` | `403` |
| `x-guard-key: open-sesame` | forwarded to the upstream |

## Gateway config

The top-level `plugins:` entry (this is the entry used by
`plugins/examples/gateway.yaml`):

```yaml
plugins:
  - name: header-guard
    wasm: plugins/examples/header-guard/target/wasm32-wasip1/release/header_guard.wasm
    phases:
      - request_headers
    config: '{"header":"x-guard-key","value":"open-sesame"}'
```

The route that references it:

```yaml
routes:
  - name: header-guard
    service: echo-service
    match:
      path:
        type: prefix
        value: /guard/
    action:
      type: proxy
    auth_required: false
    plugins:
      - header-guard
```

`config` is handed to the plugin's `proxy_on_configure` as raw bytes
and parsed as flat JSON (`{"header": ..., "value": ...}`, both
required). A missing or unparsable config fails closed: the plugin
refuses to activate and the gateway answers `500 plugin_unavailable`
for the route instead of running unguarded.

## Build

```sh
rustup target add wasm32-wasip1   # once, idempotent
cargo build --release --target wasm32-wasip1
```

The gateway loads `target/wasm32-wasip1/release/header_guard.wasm`.

## Test

```sh
# Level 1: plain-Rust unit tests (no gateway, no wasm)
cargo test

# Level 2: integration through a real gateway (from the repo root)
bash plugins/examples/run-all.sh
# or, with the harness gateway already up:
bash plugins/examples/header-guard/assert.sh http://127.0.0.1:18101
```

## Notes

- Phase contract: `request_headers` only (after route resolution,
  before authn).
- The header name is matched case-insensitively by the host; the
  value must match exactly.
- Layout: `src/lib.rs` is the plugin (RootContext holds the parsed
  config; the `proxy_on_*` exports are thin shims around the pure
  `evaluate`), `src/abi.rs` is the copyable proxy-wasm binding layer,
  `src/json.rs` the flat-JSON config reader. See the plugin testing
  guide in the documentation for the methodology.
