# Category 08: Extensibility

This demo documents dwara's extensibility surface: native plugin filters,
Proxy-Wasm (WebAssembly) plugins, CEL (Common Expression Language) expressions,
the nano-services pattern, the Extism PDK plugin runtime, plugin lifecycle
management, and the plugin SDK scaffolding CLI. Proxy-wasm plugins run on
the live request path of every default build; the remaining mechanisms are
either embedder seams (native filters) or feature-gated custom builds
(CEL, nano-services, Extism).

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

### Proxy-Wasm (WebAssembly) plugins (DW-055 / DW-157)

Proxy-Wasm plugins run on the live request path in every DEFAULT
build — there is no `wasm` cargo feature to enable. Each plugin is a
`.wasm` module loaded at config publish time (checksum-tracked across
hot reloads) and run at the phases it declares. The host uses wasmtime
as the WebAssembly engine and registers the proxy-wasm spec ABI names,
so plugins built with the Rust `proxy-wasm` SDK (what
`dwara-cli plugin new` scaffolds) run as-is.

**Config:** top-level `plugins` list with `wasm: <path>`, `phases`,
optional `config` and `limits` (fuel, memory_mb, timeout_ms). Routes
reference plugins via `plugins: [name]`.

**Dispatch contract (DW-157):** `request_headers` runs after route
resolution before authn; `request_body` runs before the upstream (the
body is buffered up to the route's `limits.max_body_bytes`, else 1
MiB — an over-cap body answers 500 `plugin_body_too_large`);
`response_headers` runs after the upstream responds;
`response_body` runs after masking (skipped, and logged, for
streaming/SSE and content-encoded bodies). A plugin's
`send_http_response` short-circuits without dialing the upstream.
Everything fails closed on the referencing route only: a
crashed/disabled/unloadable plugin answers 500 `plugin_unavailable`, a
WASM trap answers 500 `plugin_failed`. `test-02` proves the whole
scaffold-to-running path live.

**Build:** none beyond `cargo build` — the host is always compiled in.

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

### Extism PDK plugin runtime (DW-109, STUBBED)

Extism is the third plugin implementation path alongside Proxy-Wasm
and native filters: plugins written against the [Extism](https://extism.org/)
Plugin Development Kit. The PDK provides language SDKs for Rust, Go,
Python, JavaScript, and others, plus a higher-level host-function ABI
than proxy-wasm's raw stream contract (typed input/output buffers,
JSON config parsing, HTTP calls from inside the plugin). An Extism
plugin is designed to be an entry in the top-level `plugins` list,
referenced by name from routes, hooking the same four phase slots with
the same short-circuit semantics.

**Status: STUBBED.** The runtime scaffold lives at
`crates/dwara-core/src/plugins/extism.rs` behind the `extism` cargo
feature (default OFF). The actual `extism` crate is NOT a dependency
yet -- the host's runtime calls are documented no-ops returning
`FilterOutcome::Continue` with the input unchanged. The config schema
does not accept the `extism:` selector either: `PluginConfig` accepts
`wasm`/`native` only, so an `extism:` block is **rejected by
validation** as an unknown field (fail-closed, not silently ignored).
The schema, validation, and dispatch trait were designed so the real
wiring lands without touching the rest of the gateway. Until then, the
`extism:` examples in the guide (bot detection, signed-URL
verification, certificate pinning) do not validate. `test-05` verifies
exactly this state: the `wasm:` plugins-block shape validates, the
`extism:` selector is rejected with an unknown-field error, and the
default gateway is unaffected.

**Build (when it lands):** `cargo build --release --features extism,plugins`

### Plugin lifecycle (DW-056)

The plugin lifecycle manager owns how plugins are loaded, hot-swapped,
and health-tracked (see `crates/dwara-core/src/wasm/lifecycle.rs` and
the [plugin lifecycle guide](../../docs-site/guide/plugin-lifecycle.md)):

- **Loading:** read the `.wasm` file, compute a checksum, compile with
  wasmtime, validate the proxy-wasm ABI (`proxy_on_vm_start` export at
  minimum, exported linear memory, no unknown host imports), register
  the module with the per-request runner. A module that cannot be read
  or compiled marks that plugin `Crashed` at publish time (the load
  itself succeeds; routes referencing the plugin fail closed with 500).
- **Hot swap on reload:** plugins are re-evaluated by comparing
  checksums. Unchanged: the loaded instance and health state are kept
  (no recompilation). Changed: the old module is replaced and health
  resets to `Healthy`. Removed: the entry is dropped. The swap is
  atomic (new table and runner are built first, then swapped in).
- **Health tracking:** `Healthy` / `Crashed { error, crash_count }` /
  `Disabled { reason }`. Crashes call `mark_crashed` (the counter
  accumulates); successful invocations and checksum changes call
  `mark_healthy`; the circuit breaker can disable a plugin. Health
  lives in the lifecycle manager -- there is **no `/plugins` admin
  endpoint yet** (documented follow-up).
- **Failure isolation:** the manager keeps a route-to-plugins map;
  routes referencing a crashed plugin **fail closed with 500**, other
  routes are unaffected. Phase ordering across multiple plugins is
  deterministic (phase first, then the route's plugin-list order).

The lifecycle manager runs on every DEFAULT build (no cargo feature).
An unreadable or uncompilable `.wasm` marks THAT plugin `Crashed` at
publish time — the rest of the config loads, and routes referencing
the crashed plugin fail closed with 500 from the first request of the
new generation. `test-06` verifies the config schema the lifecycle
manager consumes (plugins block + route attachment) and the live
config hot-reload flow (DW-006) that triggers checksum re-evaluation;
`test-02` asserts the crashed-plugin fail-closed behavior live.

### Plugin SDK: host CLI scaffolding (DW-057)

The operator CLI scaffolds new proxy-wasm plugin projects:

```sh
dwara-cli plugin new my-plugin
```

This creates `my-plugin/` with a `Cargo.toml` (cdylib targeting
`wasm32-wasip1`, `proxy-wasm` dependency), `src/lib.rs` (the
request/response headers phase callbacks stubbed out), a `dwara.yaml`
manifest, a README, and a `.gitignore`. The generated manifest is a
complete, valid gateway config — `dwara-cli validate dwara.yaml`
passes as generated (the `.wasm` path is not checked for existence
until the gateway loads it). Build with `cargo build --release
--target wasm32-wasip1`, then load the `.wasm` via the gateway's
top-level `plugins` block. See the
[plugin SDK guide](../../docs-site/guide/plugin-sdk.md).

The scratch demo image ships only the gateway server binary, so the
scaffold runs on the **host CLI**; `test-07` additionally drives the
full SDK round-trip against the prebuilt host gateway (scaffold ->
implement a header effect -> build -> load -> curl asserts the
effect) — plugins run on every default build, no cargo feature
needed.

### Extension traits (developer-facing)

Separate from the per-route plugin chain, dwara defines five swappable
subsystem seams as traits -- the extension-trait boundary the gateway
calls instead of any concrete backend:

| Trait | What it owns | Default (OSS) impl | Enterprise impl |
|---|---|---|---|
| `RateLimiter` | rate-limit decisions per scope | local GCRA, stacked windows | Redis-backed distributed GCRA |
| `ConfigSource` | where config generations come from | file watch / SIGHUP / admin API | controller gRPC stream (CP/DP) |
| `CacheStore` | response cache get/set/invalidate | local in-memory, TTL/ETag | Redis-backed two-tier distributed cache |
| `AnalyticsSink` | where completed-request records go | embedded SQLite analytics store | federated gRPC stream to controller |
| `SecretSource` | how `${...}` secret references resolve | env, file, static inline | HashiCorp Vault and KMS |

Each trait is consumed by exactly one domain (traffic policy, snapshot
publish, response caching, analytics, config compile), so a backend
swap is a config/build change, not a code change. This surface is
developer-facing: there is **no gateway config block and no test
script** for it in this demo -- writing an implementation means
implementing the trait and wiring it in at startup. See the
[extension traits guide](../../docs-site/guide/extension-traits.md)
and `crates/dwara-core/src/extensions/`; the 11-enterprise demo
documents the enterprise backends behind the same traits.

### Feature availability

| Feature | Cargo feature | Default build | Config accepted | Runtime effect |
|---------|---------------|---------------|-----------------|----------------|
| Native filters | none | ON (dispatch live; registration is an embedder seam) | Yes | Unified chain dispatches registered filters; no built-in filters ship |
| Proxy-Wasm | none | ON (live on the request path) | Yes | Four dispatch phases, fail-closed 500s, short-circuit |
| CEL | `cel` | OFF | Fields not in schema | None without feature |
| Nano-services | `nano_services` | OFF | Yes (inert, 502) | None without feature |
| Extism PDK | `extism` | OFF | No (`extism:` selector rejected) | Stubbed no-ops |
| Plugin lifecycle | none | ON (loads, hot-swaps, health-tracks) | Yes | Checksum hot-swap; Crashed plugins fail closed |
| Plugin SDK | (host CLI) | CLI on host | n/a (scaffolds files) | Scaffold builds and runs on a default gateway |
| Extension traits | (developer-facing) | n/a | No config surface | n/a (trait swap) |

The default `dwara:demo` image (built from `Dockerfile.scratch`) uses
a plain `cargo build --release`. The proxy-wasm host, the unified
dispatch chain, and the plugin lifecycle are always compiled in — a
`.wasm` placed at a readable path in the container loads and runs.
The remaining feature-gated surfaces (CEL, nano-services, Extism) are
inert without their features; to enable them in an image, modify
`Dockerfile.scratch` to add the features to the `cargo build` line,
e.g.:

```sh
RUN cargo build --release --target "$(cat /target.triple)" --bin dwara \
    -p dwara-bin --features "nano_services,cel"
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
./test-05-extism-pdk.sh
./test-06-plugin-lifecycle.sh
./test-07-plugin-sdk.sh
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

All seven test scripts should pass with zero failures. Each test
verifies that the gateway starts and proxies correctly with the default
build, while documenting the extensibility mechanism it covers:

| Test | Verifies | Expected |
|------|----------|----------|
| test-01-native-plugins | gateway starts, /healthz 200, /v1/echo/test 200 | All pass |
| test-02-proxy-wasm | scaffold -> build -> load -> curl asserts the plugin's header effect; plugin-less fast path intact; broken plugin fails closed 500; blast radius isolated (host-based) | All pass |
| test-03-cel-expressions | gateway starts, /healthz 200, /v1/echo/test 200, / 200 | All pass |
| test-04-nano-services | gateway starts, echo + static composed services work | All pass |
| test-05-extism-pdk | plugins-block shape validates; `extism:` selector rejected (documented limitation); gateway proxies | All pass |
| test-06-plugin-lifecycle | lifecycle config shape validates; reload-nudge flow keeps serving | All pass |
| test-07-plugin-sdk | `dwara-cli plugin new` scaffolds the 5 files; manifest quirk documented + fixed manifest validates; SDK round-trip (build + load + curl) passes | All pass |

Tests 05-07 use the **host** operator CLI (`dwara-cli`, at
`target/debug/dwara-cli` or `target/release/dwara-cli` after
`cargo build -p dwara-cli`) for config-shape validation and the plugin
scaffold; the container image ships only the gateway server. Tests 02
and 07 are **host-based end-to-end** (like `09-operations`' test-09):
they additionally use the prebuilt host gateway
(`target/{debug,release}/dwara` after `cargo build -p dwara-bin`) and
skip their round-trip sections with a message when it is missing. The
plugin builds need the `wasm32-wasip1` rustup target (installed
idempotently by the scripts) and network access for the first
`proxy-wasm` crate fetch.

## Files

```
08-extensibility/
  docker-compose.yml              stack definition (gateway + echo + static)
  dwara.yaml                      gateway config (listeners, routes, services,
                                  upstreams, admin, documented plugins block)
  test-01-native-plugins.sh       native plugin filters (NativeFilter, DW-119)
  test-02-proxy-wasm.sh           proxy-wasm plugins live: scaffold -> build -> load -> curl (DW-055/DW-157/DW-159)
  test-03-cel-expressions.sh      CEL expressions (DW-058/059)
  test-04-nano-services.sh        nano-services pattern (DW-106)
  test-05-extism-pdk.sh           Extism PDK runtime (DW-109, stubbed + config-shape)
  test-06-plugin-lifecycle.sh     plugin lifecycle (DW-056, config shape + reload flow)
  test-07-plugin-sdk.sh           plugin SDK scaffold + SDK round-trip on a default build (DW-057/DW-159)
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
