# Category 13: Extension use cases (runnable recipes)

One runnable demo per recipe from the docs-site guide
[Extension use cases and recipes](../../docs-site/guide/extensibility-use-cases.md).
Where the other demo categories exercise shipped features end to end,
this category proves the RECIPES -- the documented combinations that
map a real problem to the right extension surface -- exactly as the
guide describes them.

| Demo | Guide recipe | Surface | What it proves |
| --- | --- | --- | --- |
| `01-user-subset-migration/` | Use case 1: user-subset migration (Option A) | SDK-style proxy-wasm plugin + config-includes hot reload + mock entitlement microservice | Per-user /v1 -> /v2 path rewrites from a published allow-list; publish-on-change flips verdicts on the NEXT request; empty list = safe default; plugin-less routes untouched |
| `02-response-pii-redaction/` | Response PII redaction | shipped `response-body-redact` plugin, built by path | Luhn-gated keep-last-4 card masking; innocent numbers untouched; the SSE streaming carve-out skips the phase |
| `03-custom-auth/` | Custom request authentication | shipped `static-auth` plugin, built by path | 401 + WWW-Authenticate short-circuit (no upstream dial); correct token reaches the backend; sibling route unaffected |
| `04-feature-flag-nano/` | Zero-upstream endpoints | hand-written no_std WASM nano-service module | The route's action IS a WASM module: canned `{"flag":bool}` verdicts parsed from the path, no upstream configured |
| `05-tenant-routing/` | Tenant-aware routing and tagging | SDK-style proxy-wasm plugin, two phases | Tenant decoded from a header grammar; request tagged + path rewritten per tenant; response header stamped |
| `06-embedding-analytics-sink/` | Your own analytics/config/cache/... backend | embedding binary (dwara-core path dep) | A custom `AnalyticsSink` registered at startup sees every completed request, 200s and 404s alike |
| `07-per-request-decision/` | Per-request external decisions (entitlements, experiments, fraud) | SDK-style proxy-wasm plugin with `proxy_http_call` | Pause -> decision-service callout -> response callback -> resume; the verdict rides the request; a 2s in-plugin cache suppresses repeat hits; non-2xx verdicts short-circuit; a callout slower than the plugin's timeout fails the route closed |

## How these differ from category 08

`08-extensibility` demos the extension MECHANISMS (plugin dispatch
contract, lifecycle, nano-service ABI shape, scaffolding CLI) against
shared container upstreams. This category runs the RECIPES from the
use-case guide host-side, the `plugins/examples` harness way: real
gateway binary (`cargo build -p dwara-bin`), purpose-built python
mocks, per-demo wiring files, and one `test.sh` per recipe. Demos 01
and 05 build SDK-style plugin crates (`proxy-wasm` 0.2,
wasm32-wasip1); demo 04 builds a no_std module for
wasm32-unknown-unknown; demos 02-03 build the shipped example plugins
by path; demo 06 is a standalone embedding crate excluded from the
workspace.

## Run

Run one recipe:

```sh
cd 01-user-subset-migration
./test.sh
```

Run every recipe in order:

```sh
./run-all.sh
```

Requirements: the repo's pinned Rust toolchain, curl, python3, and
enough network for the first `proxy-wasm` crate fetch (demos 01/05)
and the embedding crate's dependency tree (demo 06, slow first build).
Each `test.sh` builds what it needs (the gateway binary is located at
`target/{debug,release}/dwara` or built on demand) and is
self-cleaning: ports are pre-flighted, processes die on EXIT/INT/TERM.

## Ports

Dedicated range 18200-18299; every port below belongs to exactly one
demo and no two demos share a port while `run-all.sh` is going.

| Demo | Ports | Use |
| --- | --- | --- |
| 01 | 18201, 18202, 18203 | gateway, mock user API, entitlement service |
| 02 | 18211, 18212 | gateway, leaky upstream |
| 03 | 18221, 18222 | gateway, protected upstream |
| 04 | 18231 | gateway (no upstream by design) |
| 05 | 18241, 18242 | gateway, per-tenant upstream |
| 06 | 18251 | embedded gateway |
| 07 | 18261, 18262, 18263 | gateway, decision service, user API |

## Files

```
13-extensibility-usecases/
  run-all.sh                       runs every test.sh in order + summary
  01-user-subset-migration/
    plugin/                        v2-migrator (SDK proxy-wasm crate)
    services/user-api.py           mock v1+v2 user API (distinct JSON)
    services/entitlement.py        mock entitlement microservice
    services/publish.sh            the publisher loop (include + reload)
    dwara.yaml                     wiring (includes: the generated plugin config)
    test.sh
  02-response-pii-redaction/
    leaky-upstream.py              buffered leak + SSE endpoint
    dwara.yaml                     /api/ + response-body-redact (by path)
    test.sh
  03-custom-auth/
    protected-upstream.py          echo backend
    dwara.yaml                     /protected/ + static-auth (by path), /public/
    test.sh
  04-feature-flag-nano/
    module/                        no_std nano-service module crate
    dwara.yaml                     /flags/ nano_service action, no upstream
    test.sh
  05-tenant-routing/
    plugin/                        tenant-router (SDK proxy-wasm crate)
    tenants-upstream.py            per-tenant-prefix mock
    dwara.yaml                     /portal/ + tenant-router
    test.sh
  06-embedding-analytics-sink/
    src/main.rs                    embedding binary + custom AnalyticsSink
    Cargo.toml                     dwara-core path dep (workspace-excluded)
    test.sh
```
