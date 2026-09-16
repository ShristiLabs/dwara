# dwara example plugin gallery

Four complete, building, tested proxy-wasm plugins to copy from.
Each directory is a self-contained Rust crate (no dependencies): copy
the directory, rename, and edit `src/lib.rs`.

| Example | Phases | Behavior |
|---|---|---|
| [header-guard](header-guard/) | `request_headers` | allow/deny by request header value; deny = plugin-answered 403 |
| [static-auth](static-auth/) | `request_headers` | configured-token gate; deny = 401 + `WWW-Authenticate` challenge |
| [response-body-redact](response-body-redact/) | `response_body` | mask Luhn-valid card numbers and configured literals in response bodies |
| [request-tagger](request-tagger/) | `request_headers`, `response_headers` | stamp `x-plugin-*` correlation headers on both directions |

## Run everything

From the repository root:

```sh
bash plugins/examples/run-all.sh
```

The harness:

1. builds every example (host `cargo test` + wasm32-wasip1 release
   artifact),
2. starts a real dwara gateway with
   [gateway.yaml](gateway.yaml) plus a minimal echo upstream
   ([echo-upstream.py](echo-upstream.py), port 18102),
3. runs each example's `assert.sh` against the live gateway
   (port 18101),
4. tears everything down.

Each `assert.sh` also runs standalone against any gateway that has
the plugin wired:

```sh
bash plugins/examples/header-guard/assert.sh http://127.0.0.1:18101
```

## Layout of an example

```
header-guard/
  Cargo.toml      cdylib (wasm) + rlib (host tests), zero dependencies
  src/lib.rs      the plugin: RootContext/HttpContext-shaped state,
                  thin proxy_on_* shims over pure, unit-tested logic
  src/abi.rs      the proxy-wasm binding layer (copy verbatim; it
                  also compiles a fake host on non-wasm targets so
                  `cargo test` can drive the real callbacks)
  src/json.rs     flat-JSON plugin-config reader (config-driven
                  examples only)
  tests/          plain-Rust tests: logic + callbacks
  assert.sh       curl assertions against a live gateway
  README.md       behavior + exact gateway config snippet
```

## Why no proxy-wasm SDK dependency

The examples bind the dwara proxy-wasm host directly instead of using
the `proxy-wasm` Rust SDK: each `src/abi.rs` is ~150 lines of
`extern "C"` bindings to exactly the hostcalls the dwara host links,
so every example is a zero-dependency crate that builds offline and —
because the bindings compile an in-memory fake host on non-wasm
targets — has its callbacks unit-testable with plain `cargo test` on
a laptop. The phases dwara drives (`proxy_on_vm_start`,
`proxy_on_configure`, the four `proxy_on_http_*` filters, cleanup)
are exactly the ones these bindings export.

These are dwara-host bindings, not a portability promise. The buffer
and map constants match the proxy-wasm spec's numbers (request body
0, response body 1, request headers 0, response headers 2, plugin
configuration 7), but two parts of the binding are dwara's own: the
local-response hostcall is imported as `proxy_send_http_response`
with dwara's argument order (the spec hostcall is
`proxy_send_local_response` with a different parameter list; dwara
links both spellings), and the `ACTION_END_STREAM = 2` phase return
is a dwara extension (the spec's action enum is Continue=0/Pause=1
only). A `.wasm` built from these examples is a dwara plugin; do not
assume it runs unchanged on another proxy-wasm host. SDK
compatibility is the mirror question — modules built with the Rust
`proxy-wasm` SDK do run on dwara — and both directions are covered
in the proxy-wasm plugins guide
(`docs-site/guide/proxy-wasm-plugins.md` in this repository) along
with the host contract.

## Testing methodology

See the plugin testing guide on the documentation site for the full
three-level methodology these examples follow: plain-Rust unit tests
of the callbacks, integration through a real gateway (this harness),
and replay-based regression for config changes.
