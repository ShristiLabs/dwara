# Extism plugin development kit

Dwara supports a third plugin implementation path alongside
[Proxy-Wasm](./proxy-wasm-plugins) and [native filters](./native-plugins):
plugins written against the [Extism](https://extism.org/) Plugin Development
Kit (PDK). Extism plugins are WebAssembly modules that use a higher-level
host-function ABI than proxy-wasm -- the PDK provides language SDKs for
Rust, Go, Python, JavaScript, and others, so a plugin can be written in
whichever language the team is comfortable with. Like the other two paths,
an Extism plugin is an entry in the top-level `plugins` list, referenced by
name from routes, and hooks the same request lifecycle phases. Only the
implementation and the host sandbox differ.

## When to use this

Use the Extism PDK when you want a plugin in a language other than Rust
(the PDK has first-class SDKs for several languages, where proxy-wasm SDK
coverage is narrower), a higher-level ABI than proxy-wasm's raw host
functions (the PDK abstracts memory management and provides typed
input/output buffers, JSON config parsing, and HTTP calls from inside the
plugin), or portability across any Extism host. Use proxy-wasm when you
need to run community Kong/Envoy filters unmodified. Use native filters
when you need maximum performance and are willing to compile into the
gateway binary.

## Enabling

Extism plugins are feature-gated behind the `extism` cargo feature
(default OFF), which pulls in the Extism host runtime. Combine with
`plugins` so the unified dispatch chain can route to an Extism plugin:

```sh
cargo build -p dwara-core --features plugins,extism
```

When `extism` is on but `plugins` is off, the host runtime is present but
no dispatch occurs. When both are on, an Extism plugin attaches through
the same `PluginChain` as a native or WASM plugin.

## Configuration

An Extism plugin is declared with `extism:` instead of `wasm:` or
`native:`. Exactly one of the three must be set per plugin. The `config`
string is passed to the plugin as raw bytes; the PDK parses it (typically
as JSON). The phase contract is identical to the other two paths
(`request_headers`, `request_body`, `response_headers`, `response_body`),
and an Extism plugin can short-circuit with a local response at any phase.

## Bot detection hooks

A common Extism plugin use case is bot detection at the `request_headers`
phase -- inspecting the User-Agent, request rate, and JA3/JA4 TLS
fingerprint to classify a client before authn runs:

```yaml
plugins:
  - name: bot-detect
    extism: ./plugins/bot_detect.wasm
    phases:
      - request_headers
    config: |
      {
        "allowed_bots": ["googlebot", "bingbot"],
        "challenge_suspicious": true,
        "ja4_blocklist": ["t13d1516h2_8daaf6152771_b0da82dd1658"]
      }

routes:
  - name: api
    service: backend
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy }
    plugins:
      - bot-detect
```

A plugin that classifies the client as a disallowed bot returns a
`LocalResponse` (a 403 or a challenge page) and the request never reaches
the upstream. Allowed bots proceed; the plugin can also tag the request
with a header (`X-Bot-Class: googlebot`) for downstream observability.

## Signed-URL verification

An Extism plugin can verify signed URLs at the `request_headers` phase --
checking an HMAC or token in the query string against a shared secret
before the request is proxied:

```yaml
plugins:
  - name: signed-url
    extism: ./plugins/signed_url.wasm
    phases:
      - request_headers
    config: |
      { "secret_env": "SIGNED_URL_SECRET", "max_age_s": 300 }
```

The plugin reads the secret from the environment variable named in
`secret_env`, recomputes the signature over the path and query, compares
it to the token in the request, and rejects expired or mismatched
signatures with a 403. The secret is never passed through `config` --
only the environment variable name is, so the secret stays out of the
gateway config file.

## Certificate pinning

An Extism plugin can enforce upstream certificate pinning at the
`request_headers` phase by recording the expected SPKI hashes and
rejecting requests to upstreams whose presented certificate does not
match:

```yaml
plugins:
  - name: cert-pin
    extism: ./plugins/cert_pin.wasm
    phases:
      - request_headers
    config: |
      {
        "pins": { "payments.example.com": ["sha256/abc123...", "sha256/def456..."] },
        "mode": "strict"
      }
```

In `strict` mode a certificate that matches no pinned SPKI causes the
plugin to return a `LocalResponse` 502 and the request is not forwarded.
In `report` mode the mismatch is logged and the request proceeds, useful
for validating a pin set before enforcing it. The plugin reads the
upstream's presented certificate from the gateway's TLS context (exposed
to the PDK as a host function) and hashes the SubjectPublicKeyInfo.

## Relationship to the other plugin paths

| Aspect | Native filter | Proxy-Wasm | Extism |
|---|---|---|---|
| Implementation | Rust, compiled in | `.wasm`, proxy-wasm ABI | `.wasm`, Extism PDK |
| Selection | `native: <name>` | `wasm: <path>` | `extism: <path>` |
| Phase contract | identical | identical | identical |
| Sandbox | none (in-process) | wasmtime | extism host |
| Language SDKs | Rust only | several | many (Rust, Go, Python, JS, ...) |
| Hot-load | no (build-time) | yes (startup/reload) | yes (startup/reload) |
| Portability | no | proxy-wasm hosts | any Extism host |

All three share the same phase slot on a route, selected by config, with
no dataplane-visible difference in attachment semantics.
