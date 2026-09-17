# Building a nano-service

A complete walkthrough for writing a nano-service module from
scratch: a `no_std` Rust crate compiled to plain WASM, the full
module source, the gateway config that routes to it, and how to test
it. The worked example is the feature-flag endpoint from
[`demos/13-extensibility-usecases/04-feature-flag-nano/`](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/04-feature-flag-nano)
-- every code block below is that demo's verified source.

Read [Nano-services](./nano-services) first for the option's
positioning (a route action, not a plugin) and
[Nano-service ABI](./nano-service-abi) for the full ABI reference.

## What you will build

A route whose action IS a WASM module: `GET /flags/<name>` answers
`200 {"flag":true}` for flags compiled ON (`new-ui`,
`beta-search`), `200 {"flag":false}` for everything else. No
upstream hop, no network, no filesystem -- the sandbox is the whole
world.

| Request | Result |
|---|---|
| `GET /flags/new-ui` | `200` `{"flag":true}` |
| `GET /flags/legacy-reports` | `200` `{"flag":false}` |
| `GET /flags/new-ui?x=1` | unchanged verdict (query string ignored) |

## 1. The crate

A nano-service module must be **plain WASM**: no WASI imports (the
host provides only the four `dwara` imports), so the crate is
`no_std` and targets `wasm32-unknown-unknown`. No helper crate, no
SDK.

```toml
# module/Cargo.toml
[package]
name = "feature-flag-nano"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"
publish = false

[lib]
crate-type = ["cdylib"]

[profile.release]
opt-level = "s"
lto = true
strip = true
```

## 2. The module

The full source (the demo's `module/src/lib.rs`):

```rust
#![no_std]

use core::ffi::c_int;

#[link(wasm_import_module = "dwara")]
extern "C" {
    fn response_status(status: c_int);
    fn response_header(k_ptr: *const u8, k_len: c_int, v_ptr: *const u8, v_len: c_int) -> c_int;
    fn response_body(ptr: *const u8, len: c_int) -> c_int;
}

/// The flags compiled ON. A real deployment rebuilds (or re-publishes)
/// the module to change the set; for per-request dynamism use the
/// extension-trait or snapshot-publishing recipes instead.
const ON_FLAGS: [&[u8]; 2] = [b"new-ui", b"beta-search"];

const CONTENT_TYPE: &[u8] = b"application/json";
const CONTENT_TYPE_NAME: &[u8] = b"content-type";
const BODY_ON: &[u8] = b"{\"flag\":true}\n";
const BODY_OFF: &[u8] = b"{\"flag\":false}\n";

/// Bump-allocated scratch the host writes the serialized request
/// into. The module is instantiated fresh per request, so the static
/// state resets naturally; 8 KiB is far above any real request line.
const HEAP_LEN: usize = 8192;
static mut HEAP: [u8; HEAP_LEN] = [0; HEAP_LEN];
static mut HEAP_NEXT: usize = 0;

#[no_mangle]
pub extern "C" fn alloc(size: c_int) -> *mut u8 {
    let size = if size < 0 { 0 } else { size as usize };
    unsafe {
        let Some(end) = HEAP_NEXT.checked_add(size) else {
            return core::ptr::null_mut();
        };
        if end > HEAP_LEN {
            return core::ptr::null_mut();
        }
        // Raw-pointer addressing only (no references to the mutable
        // static): the bump pointer hands out plain addresses into
        // the module's own linear memory.
        let base = &raw const HEAP as *mut u8;
        let ptr = base.wrapping_add(HEAP_NEXT);
        HEAP_NEXT = end;
        ptr
    }
}

#[no_mangle]
pub extern "C" fn handle(req_ptr: *const u8, req_len: c_int) -> c_int {
    if req_len < 0 || req_ptr.is_null() {
        return 1;
    }
    let request = unsafe { core::slice::from_raw_parts(req_ptr, req_len as usize) };
    let Some(path) = request_path(request) else {
        return 1;
    };
    respond(flag_enabled(path))
}

/// Read the path out of the wire format: skip the method, then take
/// the path bytes. `None` on a truncated buffer (handle answers 502).
fn request_path(request: &[u8]) -> Option<&[u8]> {
    let method_len = read_u32(request, 0)? as usize;
    let path_len_at = 4 + method_len;
    let path_len = read_u32(request, path_len_at)? as usize;
    let start = path_len_at + 4;
    let end = start.checked_add(path_len)?;
    request.get(start..end)
}

fn read_u32(buf: &[u8], at: usize) -> Option<u32> {
    let bytes = buf.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// /flags/<name> -> is <name> in the ON set? Any other path is off.
fn flag_enabled(path: &[u8]) -> bool {
    let Some(rest) = path.strip_prefix(b"/flags/") else {
        return false;
    };
    let name = match rest.iter().position(|&b| b == b'?') {
        Some(query_at) => &rest[..query_at],
        None => rest,
    };
    ON_FLAGS.iter().any(|flag| *flag == name)
}

fn respond(enabled: bool) -> c_int {
    let body = if enabled { BODY_ON } else { BODY_OFF };
    unsafe {
        response_status(200);
        response_header(
            CONTENT_TYPE_NAME.as_ptr(),
            CONTENT_TYPE_NAME.len() as c_int,
            CONTENT_TYPE.as_ptr(),
            CONTENT_TYPE.len() as c_int,
        );
        response_body(body.as_ptr(), body.len() as c_int);
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}
```

How it maps to the ABI:

- **Exports**: `memory` (declared implicitly by the cdylib), `alloc`
  (the bump allocator the host uses to place the serialized
  request), `handle` (parse, decide, respond).
- **Imports**: the three response-building `dwara.*` functions
  (`dwara.log` is available but unused here).
- **Wire format**: the request arrives BE length-prefixed
  (`u32 method_len, method, u32 path_len, path, u32 header_count,
  [...] u32 body_len, body`). This module needs only the path, so it
  skips the method and stops parsing after the path -- the
  headers/body prefix is never touched. Parse only as far as the
  fields you use; a truncated buffer returns non-zero from `handle`
  (the route answers 502).

Why `no_std` Rust rather than raw WAT: the length-prefix parsing and
byte-slice comparisons are one screen of safe-ish Rust versus
several screens of WAT with manual pointer math; the ABI surface is
identical.

## 3. Build the module

```sh
rustup target add wasm32-unknown-unknown   # once, idempotent
cd module
cargo build --release --target wasm32-unknown-unknown
```

The artifact lands at
`module/target/wasm32-unknown-unknown/release/feature_flag_nano.wasm`.

## 4. Wire it into the gateway config

Add a route whose action is `nano_service` (the demo's `dwara.yaml`,
paths relative to the gateway process's working directory):

```yaml
listeners:
  - name: flags-http
    address: 127.0.0.1
    port: 18231
    protocol: http

routes:
  - name: feature-flags
    service: never-dialed
    match:
      path:
        type: prefix
        value: /flags/
    action:
      type: nano_service
      module: module/target/wasm32-unknown-unknown/release/feature_flag_nano.wasm
      # 2 MiB: a Rust no_std cdylib still declares a 17-page (1.09 MiB)
      # memory minimum (static data + the default stack reservation),
      # which exceeds the 1 MiB schema default; hand-written WAT could
      # fit under 1 MiB. Max is 64 MiB.
      memory_limit: 2097152
      execution_timeout_ms: 100

services:
  - name: never-dialed
    upstream: never-dialed-pool

upstreams:
  - name: never-dialed-pool
    load_balancer: round_robin
    protocol: http1
    endpoints:
      - address: 127.0.0.1
        port: 1
```

The `memory_limit` rationale: the schema default is 1 MiB (1048576
bytes), but a Rust cdylib -- even `no_std` -- declares a 17-page
(1.09 MiB) linear-memory minimum (static data plus the default stack
reservation), which exceeds it, so instantiation would fail. The
demo's route therefore sets `memory_limit: 2097152` (2 MiB). A
hand-written WAT module with a minimal footprint could fit under the
1 MiB default.

The route's `service` is still required by the schema but is NEVER
dialed -- the demo points it at dead port 1 on purpose, so any
request that somehow reached it would fail loudly, not silently.

## 5. Run and verify

```sh
DWARA_CONFIG=dwara.yaml dwara
curl -i http://127.0.0.1:18231/flags/new-ui            # 200 {"flag":true}
curl -i http://127.0.0.1:18231/flags/legacy-reports    # 200 {"flag":false}
```

All of this with no upstream configured for the route.

## 6. Test it

- **Through a live gateway**: the demo's `test.sh` builds the module,
  starts a gateway with no upstream, and asserts the verdict table
  above plus the `Content-Type` header (set through
  `dwara.response_header`). This is the primary loop: build, load,
  curl, assert.
- **Failure modes need oversized bodies or deliberately broken
  modules**; the dwara-core suites pin them (see the failure table
  below), so you do not need to reproduce them per module.
- Keep the decision logic in small pure functions
  (`flag_enabled(path)`) so behavior is reviewable at a glance even
  when it cannot be unit-tested outside WASM.

## Failure semantics

| Condition | Client sees |
|---|---|
| Module missing or broken at handler construction | 502 `nano_service_unavailable` |
| `handle` returns non-zero, traps, or exhausts its fuel budget | 502 `nano_service_error` |
| `handle` exceeds `execution_timeout_ms` | 504 `nano_service_timeout` |
| Request body over 1 MiB (the module receives the body whole) | 413 `nano_service_body_too_large` |

Every failure is scoped to the nano-service route only; other routes
are unaffected.

## Hot-load expectations

The module is re-read when a new config generation builds the route
handler -- so changing the module bytes and reloading config swaps
the handler, no binary restart. Changing the compiled-ON flag set
means rebuilding (or re-publishing) the module; for per-request
dynamism use the snapshot-publishing or extension-trait recipes
instead (see [zero-upstream feature flags](./use-cases/zero-upstream-feature-flags)).

## Where to go next

- [Nano-services](./nano-services) - the option landing page.
- [Nano-service ABI](./nano-service-abi) - the full ABI reference:
  exports, imports, wire format, sandbox limits.
- Recipe: [zero-upstream feature flags](./use-cases/zero-upstream-feature-flags).
- Demo: [`demos/13-extensibility-usecases/04-feature-flag-nano/`](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/04-feature-flag-nano)
  (the source of every block on this page).
