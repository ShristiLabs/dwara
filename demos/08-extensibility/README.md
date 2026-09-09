# Category 08: Extensibility

This demo documents dwara's extensibility surface: native plugin filters,
Proxy-Wasm (WebAssembly) plugins, CEL (Common Expression Language) expressions,
and the nano-services pattern. It verifies the gateway starts and proxies
correctly with the default build, and documents how to enable each
extensibility mechanism via custom builds.

## What the demo covers

### Native plugin filters (NativeFilter trait, DW-119)

dwara supports compile-in Rust filters via the `NativeFilter` trait,
feature-gated behind the `plugins` cargo feature (default OFF). A native
filter is a Rust type implementing `NativeFilter`, registered with
`NativeRegistry` at startup under a name. Routes reference native filters
by name via their `plugins` field, exactly as they reference WASM plugins.

The four HTTP filter phases (mirroring the proxy-wasm host):

1. `request_headers` - after route resolution, before authn
2. `request_body` - after authn/authz/rate-limit, before upstream
3. `response_headers` - after the upstream responds, before masking
4. `response_body` - after masking, before compression

A native filter can short-circuit with a `LocalResponse` at any phase.

**Config:** top-level `plugins` list with `native: <name>`, `phases`,
and optional `config`. Routes reference plugins via `plugins: [name]`.

**Build:** `cargo build --release --features plugins`

### Proxy-Wasm (WebAssembly) plugins (DW-055)

dwara supports Proxy-Wasm (WebAssembly) plugins via the `wasm` cargo
feature (default OFF). Each plugin is a `.wasm` module loaded at startup
and run on the request pipeline phases it declares. The host uses
wasmtime as the WebAssembly engine. Community Kong/Envoy proxy-wasm
filters run unmodified.

**Config:** top-level `plugins` list with `wasm: <path>`, `phases`,
optional `config` and `limits` (fuel, memory_mb, timeout_ms). Routes
reference plugins via `plugins: [name]`.

**Build:** `cargo build --release --features wasm`

### CEL (Common Expression Language) expressions (DW-058 / DW-059)

dwara supports CEL for request/response matching and transforms via the
`cel` cargo feature (default OFF). The "CEL everywhere" design (DW-059)
provides one CEL surface across four use-sites:

1. **Expression matchers in routes** - a CEL expression that evaluates
   to a bool; if true, the route matches.
2. **Header/transform logic** - a CEL expression that evaluates to a
   string; the result is used as the header value.
3. **Rate-limit key derivation** - a CEL expression that evaluates to a
   string; the result is used as the rate-limit key.
4. **Policy conditions** - a CEL expression that evaluates to a bool;
   if true, the policy applies.

All four use-sites share the same request context: a `request` variable
with `path`, `method`, `headers`, `query`, `host` fields. CEL
expressions are compiled once at config publish time (never on the
request path) for hot-path performance.

**Status:** The CEL engine module (`crates/dwara-core/src/cel/`) is fully
implemented, but CEL expression fields are not yet wired into the
declarative config schema (`RouteMatch`, transforms, rate-limit
selectors, policy conditions do not expose CEL fields in the current
config). The feature is available for custom builds that wire CEL
fields programmatically.

**Build:** `cargo build --release --features cel`

### Nano-services pattern (DW-106)

Nano-services are small WASM modules that generate responses directly
instead of proxying to an upstream. A route with `action: nano_service`
loads a `.wasm` module, calls its `handle` export with the serialized
request (method, path, headers, body), and returns the response the
module produces (status, headers, body). No upstream is contacted.

The nano-services pattern enables composing small, self-contained
services at the gateway layer: each nano-service is a single `.wasm`
module that handles one route, and the gateway routes between them.
This is the "functions at the edge" pattern without a separate
functions runtime.

**Config:** route action `type: nano_service` with `module` (path to
`.wasm`), `memory_limit` (bytes, default 1 MiB), and
`execution_timeout_ms` (default 100).

**Build:** `cargo build --release --features nano_services`
(nano_services pulls in `wasm`)

### Feature availability

| Feature | Cargo feature | Default build | Config accepted | Runtime effect |
|---------|---------------|---------------|-----------------|----------------|
| Native filters | `plugins` | OFF | Yes (inert) | None without feature |
| Proxy-Wasm | `wasm` | OFF | Yes (inert) | None without feature |
| CEL | `cel` | OFF | Fields not in schema | None without feature |
| Nano-services | `nano_services` | OFF | Yes (inert, 502) | None without feature |

The default `dwara:demo` image (built from `Dockerfile.scratch`) uses
`cargo build --release` with NO features enabled. This keeps the binary
within the 25MB budget (wasmtime + cranelift alone add significant size).
The config schema ACCEPTS the `plugins` top-level block and the
`nano_service` route action regardless of features (so configs
round-trip without the features), but they are inert without the
features compiled in.

To build a feature-enabled image, modify `Dockerfile.scratch` to add
the desired features to the `cargo build` line, e.g.:

```sh
RUN cargo build --release --target "$(cat /target.triple)" --bin dwara \
    -p dwara-bin --features "plugins,wasm,nano_services,cel"
```

## Prerequisites

1. **Shared images built.** The demo upstream images and the gateway
   image must already exist:
   ```
   docker images | grep -E 'dwara:demo|dwara-demo/(echo|static)'
   ```
   If missing, build them from the `demos/_shared/upstreams/` Dockerfiles
   and the repo-root `Dockerfile.scratch` (tagged `dwara:demo`).

2. **Certs generated.** The shared certs at `demos/_shared/certs/` must
   exist (used for the admin API's mTLS):
   ```
   ls demos/_shared/certs/server.crt demos/_shared/certs/server.key \
      demos/_shared/certs/client-ca.crt demos/_shared/certs/client.crt
   ```

3. **Docker Compose.** Docker and Docker Compose must be installed.

## How to run

### 1. Start the stack

```sh
cd demos/08-extensibility
docker compose up -d
```

This starts three containers on a shared bridge network:
- `dwara` - the gateway on port 8080 (HTTP), admin API on 2019 (mTLS)
- `echo` - the echo upstream (reflects requests as JSON)
- `static` - the static upstream (nginx serving demo files)

### 2. Wait for the gateway

```sh
curl -sf http://localhost:8080/healthz
# -> ok
```

### 3. Run the test scripts

Each test script sources `../_shared/helpers.sh`, waits for the gateway,
documents an extensibility mechanism, runs assertions, and prints a
pass/fail summary.

```sh
./test-01-native-plugins.sh
./test-02-proxy-wasm.sh
./test-03-cel-expressions.sh
./test-04-nano-services.sh
```

Or run them all at once:

```sh
for t in test-*.sh; do echo "--- $t ---"; ./"$t"; done
```

### 4. Tear down

```sh
docker compose down -v
```

## Expected results

All four test scripts should pass with zero failures. Each test
verifies that the gateway starts and proxies correctly with the default
build, while documenting the extensibility mechanism it covers:

| Test | Verifies | Expected |
|------|----------|----------|
| test-01-native-plugins | gateway starts, /healthz 200, /v1/echo/test 200 | All pass |
| test-02-proxy-wasm | gateway starts, /healthz 200, /v1/echo/test 200 | All pass |
| test-03-cel-expressions | gateway starts, /healthz 200, /v1/echo/test 200, / 200 | All pass |
| test-04-nano-services | gateway starts, echo + static composed services work | All pass |

## Files

```
08-extensibility/
  docker-compose.yml              stack definition (gateway + echo + static)
  dwara.yaml                      gateway config (listeners, routes, services,
                                  upstreams, admin, documented plugins block)
  test-01-native-plugins.sh       native plugin filters (NativeFilter, DW-119)
  test-02-proxy-wasm.sh           proxy-wasm (WebAssembly) plugins (DW-055)
  test-03-cel-expressions.sh      CEL expressions (DW-058/059)
  test-04-nano-services.sh        nano-services pattern (DW-106)
  README.md                       this file
  data/                           SQLite state DB (mounted volume)
```

## Extensibility config reference

### Top-level `plugins` block

```yaml
plugins:
  - name: my-native-filter
    native: request_id_injector     # registered factory name
    phases:
      - request_headers
      - response_headers
    config: '{"header_name": "X-Request-Id"}'

  - name: my-wasm-plugin
    wasm: /etc/dwara/plugins/filter.wasm
    phases:
      - request_headers
      - request_body
      - response_headers
      - response_body
    config: '{"mode": "observe"}'
    limits:
      fuel: 1000000
      memory_mb: 32
      timeout_ms: 100
```

### Route plugin attachment

```yaml
routes:
  - name: my-route
    service: my-service
    match:
      path:
        type: prefix
        value: /v1/
    action:
      type: proxy
    plugins:
      - my-native-filter
      - my-wasm-plugin
```

### Nano-service route action

```yaml
routes:
  - name: nano-hello
    service: echo-service          # required by schema, never dialed
    match:
      path:
        type: exact
        value: /nano/hello
    action:
      type: nano_service
      module: /etc/dwara/plugins/hello.wasm
      memory_limit: 1048576         # 1 MiB (default)
      execution_timeout_ms: 100     # default
```
