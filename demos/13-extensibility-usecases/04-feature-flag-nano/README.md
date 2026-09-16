# Demo 04: zero-upstream endpoints (feature flags)

The
[zero-upstream-endpoints recipe](../../../docs-site/guide/extensibility-use-cases.md):
a feature-flag endpoint whose logic is too dynamic for a `respond`
action and far too small for a service. The route's action IS a WASM
module; no upstream hop.

## The module

`module/` is a hand-written `no_std` Rust crate (the nano-service
guide's documented authoring path: `--target
wasm32-unknown-unknown`, no helper crate, no WASI imports -- a module
importing WASI does not instantiate because the host provides only
the four `dwara` imports). It implements the dedicated nano-service
ABI:

- exports `memory`, `alloc(size) -> ptr` (a bump allocator the host
  uses to place the serialized request), `handle(req_ptr, req_len)
  -> i32` (0 = ok)
- imports `dwara.response_status`, `dwara.response_header`,
  `dwara.response_body` (`dwara.log` is available but unused)
- parses the request's BE length-prefixed wire format just far enough
  to read the PATH: `/flags/<name>` (query string ignored) against
  the compiled-ON set `{new-ui, beta-search}` -> `{"flag":true}`,
  everything else -> `{"flag":false}`

Why no_std Rust rather than raw WAT: the length-prefix parsing and
byte-slice comparisons are one screen of safe-ish Rust versus several
screens of WAT with manual pointer math; the ABI surface is identical.
One consequence: a Rust cdylib declares a 17-page (1.09 MiB) memory
minimum (static data plus the default stack reservation), which
exceeds the 1 MiB schema default -- the demo's route therefore sets
`memory_limit: 2097152` (2 MiB; a hand-written WAT module could fit
under 1 MiB).

## What test.sh asserts

1. `GET /flags/new-ui` -> 200 `{"flag":true}` (compiled ON)
2. `GET /flags/beta-search` -> 200 `{"flag":true}`
3. `GET /flags/legacy-reports` -> 200 `{"flag":false}`
4. `Content-Type: application/json` (set through `dwara.response_header`)
5. a query string does not change the verdict
6. all of this with NO upstream configured for the route (the
   route's service points at dead port 1 on purpose)

## Failure semantics (contract, not asserted here)

| Condition | Client sees |
| --- | --- |
| module missing/broken at handler construction | 502 `nano_service_unavailable` |
| `handle` returns non-zero, traps, exhausts fuel | 502 `nano_service_error` |
| `handle` exceeds `execution_timeout_ms` | 504 `nano_service_timeout` |
| request body over 1 MiB | 413 `nano_service_body_too_large` |

These need oversized bodies or deliberately broken modules; the
nano-services guide documents them and the dwara-core suites pin
them. Changing the ON set means rebuilding (or re-publishing) the
module -- for per-request dynamism use the snapshot-publishing
(demo 01) or embedding (demo 06) recipes.

## Run

```sh
./test.sh          # builds the module for wasm32-unknown-unknown,
                   # starts a gateway with no upstream, asserts
```

Ports: gateway 18231 (no upstream).
