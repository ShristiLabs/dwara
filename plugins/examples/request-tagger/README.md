# request-tagger

The "hello plugin+" of the gallery: stamp `x-plugin-*` correlation
headers on both directions. At `request_headers` the plugin reads the
inbound `x-request-id` and stamps `x-plugin-name` +
`x-plugin-request-id` onto the request (visible at the upstream); at
`response_headers` it stamps the same pair onto the response (visible
at the client), echoing the request id captured earlier. When the
inbound request carries no `x-request-id`, the value is the literal
`unset`. No config.

| Direction | Header | Value |
|---|---|---|
| request | `x-plugin-name` | `request-tagger` |
| request | `x-plugin-request-id` | inbound `x-request-id`, or `unset` |
| response | `x-plugin-name` | `request-tagger` |
| response | `x-plugin-request-id` | the id captured at the request phase |

## Gateway config

The top-level `plugins:` entry (this is the entry used by
`plugins/examples/gateway.yaml`):

```yaml
plugins:
  - name: request-tagger
    wasm: plugins/examples/request-tagger/target/wasm32-wasip1/release/request_tagger.wasm
    phases:
      - request_headers
      - response_headers
```

The route that references it:

```yaml
routes:
  - name: request-tagger
    service: echo-service
    match:
      path:
        type: prefix
        value: /tag/
    action:
      type: proxy
    auth_required: false
    plugins:
      - request-tagger
```

## Build

```sh
rustup target add wasm32-wasip1   # once, idempotent
cargo build --release --target wasm32-wasip1
```

The gateway loads `target/wasm32-wasip1/release/request_tagger.wasm`.

## Test

```sh
# Level 1: plain-Rust unit tests (no gateway, no wasm). Includes
# tests/callbacks.rs, which drives the real proxy_on_* exports
# against the fake host from src/abi.rs.
cargo test

# Level 2: integration through a real gateway (from the repo root)
bash plugins/examples/run-all.sh
# or, with the harness gateway already up:
bash plugins/examples/request-tagger/assert.sh http://127.0.0.1:18101
```

## Notes

- Phase contract: `request_headers` and `response_headers`. Header
  phases apply diffs only: names the plugin never touched keep their
  original bytes downstream.
- Layout: `src/lib.rs` is the plugin (HttpContext holds the captured
  request id across the two phases; the `proxy_on_*` exports are thin
  shims), `src/abi.rs` is the copyable proxy-wasm binding layer. See
  the plugin testing guide in the documentation for the methodology.
