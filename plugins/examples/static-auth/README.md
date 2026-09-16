# static-auth

Gate a route behind a configured token. Requests presenting the
configured token in the configured header are forwarded; everything
else is answered `401` with a `WWW-Authenticate: Bearer realm="dwara"`
challenge by the plugin itself (`proxy_send_http_response`) and the
upstream is never dialed. Token comparison is constant-time.

| Request | Result |
|---|---|
| no `authorization` header | `401` + challenge, body `missing credential` |
| `authorization: Basic ...` | `401` + challenge |
| `authorization: Bearer wrong` | `401` + challenge, body `invalid credential` |
| `authorization: Bearer dwara-example-token` | forwarded to the upstream |

## Gateway config

The top-level `plugins:` entry (this is the entry used by
`plugins/examples/gateway.yaml`):

```yaml
plugins:
  - name: static-auth
    wasm: plugins/examples/static-auth/target/wasm32-wasip1/release/static_auth.wasm
    phases:
      - request_headers
    config: '{"header":"authorization","scheme":"Bearer","token":"dwara-example-token"}'
```

The route that references it:

```yaml
routes:
  - name: static-auth
    service: echo-service
    match:
      path:
        type: prefix
        value: /auth/
    action:
      type: proxy
    auth_required: false
    plugins:
      - static-auth
```

`config` is handed to the plugin's `proxy_on_configure` as raw bytes
and parsed as flat JSON: `header` and `token` are required; `scheme`
is optional (`"Bearer"` yields the standard `Bearer <token>` shape,
matched ASCII case-insensitively per RFC 7235; without it the raw
header value is compared). A missing or unparsable config fails
closed: the plugin refuses to activate and the gateway answers `500
plugin_unavailable` for the route instead of running unauthenticated.

This is a demonstration plugin: a static token in config is
appropriate for demos and internal edges. For real deployments prefer
the gateway's built-in authentication (API keys, OIDC, mTLS) and use
a plugin for custom schemes only.

## Build

```sh
rustup target add wasm32-wasip1   # once, idempotent
cargo build --release --target wasm32-wasip1
```

The gateway loads `target/wasm32-wasip1/release/static_auth.wasm`.

## Test

```sh
# Level 1: plain-Rust unit tests (no gateway, no wasm). Includes
# tests/callbacks.rs, which drives the real proxy_on_* exports
# against the fake host from src/abi.rs.
cargo test

# Level 2: integration through a real gateway (from the repo root)
bash plugins/examples/run-all.sh
# or, with the harness gateway already up:
bash plugins/examples/static-auth/assert.sh http://127.0.0.1:18101
```

## Notes

- Phase contract: `request_headers` only (after route resolution,
  before authn).
- Layout: `src/lib.rs` is the plugin (RootContext holds the parsed
  config; the `proxy_on_*` exports are thin shims around the pure
  `evaluate`/`constant_time_eq`), `src/abi.rs` is the copyable
  proxy-wasm binding layer, `src/json.rs` the flat-JSON config
  reader. See the plugin testing guide in the documentation for the
  methodology.
