# response-body-redact

Scrub sensitive patterns from response bodies before they reach the
client. Two pattern classes, both length-preserving so framing never
shifts:

- **Card numbers**: a run of 13-19 digits (single `-` or ` `
  separators between groups allowed) that passes the Luhn checksum is
  masked to `*` except the last four digits, separators kept:
  `4111-1111-1111-1111` becomes `****-****-****-1111`. The checksum
  gate keeps ordinary 16-digit ids (order numbers, tracking codes)
  readable.
- **Configured literals**: each occurrence of a configured string is
  replaced with `*` repeated to the same length
  (`sk-live-12345` becomes `*************`).

Card masking is always on; `literals` is optional.

| Response body contains | Client sees |
|---|---|
| `4111-1111-1111-1111` | `****-****-****-1111` |
| `5555 5555 5555 4444` | `**** **** **** 4444` |
| `1234567812345678` (invalid checksum) | unchanged |
| `sk-live-12345` (configured literal) | `*************` |

## Gateway config

The top-level `plugins:` entry (this is the entry used by
`plugins/examples/gateway.yaml`):

```yaml
plugins:
  - name: response-body-redact
    wasm: plugins/examples/response-body-redact/target/wasm32-wasip1/release/response_body_redact.wasm
    phases:
      - response_body
    config: '{"literals":["sk-live-12345"]}'
```

The route that references it:

```yaml
routes:
  - name: response-body-redact
    service: echo-service
    match:
      path:
        type: prefix
        value: /statement
    action:
      type: proxy
    auth_required: false
    plugins:
      - response-body-redact
```

`config` is handed to the plugin's `proxy_on_configure` as raw bytes
and parsed as flat JSON (`{"literals": [...]}`, an array of strings).
An unparsable config fails closed: the plugin refuses to activate and
the gateway answers `500 plugin_unavailable` for the route instead of
serving unredacted bytes.

## Build

```sh
rustup target add wasm32-wasip1   # once, idempotent
cargo build --release --target wasm32-wasip1
```

The gateway loads
`target/wasm32-wasip1/release/response_body_redact.wasm`.

## Test

```sh
# Level 1: plain-Rust unit tests (no gateway, no wasm). Includes
# tests/callbacks.rs, which drives the real proxy_on_response_body
# export against the fake host from src/abi.rs.
cargo test

# Level 2: integration through a real gateway (from the repo root)
bash plugins/examples/run-all.sh
# or, with the harness gateway already up:
bash plugins/examples/response-body-redact/assert.sh http://127.0.0.1:18101
```

## Notes

- Phase contract: `response_body` only. The phase applies to
  **buffered, non-encoded** response bodies: dwara buffers the body
  for the phase (capped by the route's `limits.max_body_bytes`,
  default 1 MiB) and rewrites `Content-Length` when the plugin
  changes the bytes. Streaming bodies (`text/event-stream`, un-framed
  chunked) and content-encoded bodies skip the phase and stream
  through untouched.
- Layout: `src/lib.rs` is the plugin (RootContext holds the parsed
  config; the `proxy_on_response_body` export is a thin shim around
  the pure `redact`/`mask_card_numbers`/`luhn_valid`), `src/abi.rs`
  is the copyable proxy-wasm binding layer, `src/json.rs` the
  flat-JSON config reader. See the plugin testing guide in the
  documentation for the methodology.
