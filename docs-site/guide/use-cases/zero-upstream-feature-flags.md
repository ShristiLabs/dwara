# Use case: zero-upstream feature flags

A feature-flag endpoint, a health/echo endpoint, or a contract mock:
logic too dynamic for a `respond`/`mock` action, too small for a
service. You want the endpoint served at the edge with no upstream
hop at all.

## Why the built-ins are not enough

| Built-in | What it does | Why it does not fit |
| --- | --- | --- |
| `respond`/`mock` route actions | Fixed status/headers/body from config | The response depends on the request (the flag name in the path); config cannot compute |
| [CEL expressions](../cel-expressions) | Expressions over the request in match/rewrite/policy blocks | Conditions gate or shape traffic; they do not author a whole response body |
| [Transforms](../transforms) | Rewrite/patch proxied responses | Still needs an upstream to transform — exactly what this use case removes |

If the response is fully static, use `respond` — it is config. The
nano-service is for the band between static and service.

## Options, with tradeoffs

| Option | How | Upstream hop | Dynamism | Works today? |
| --- | --- | --- | --- | --- |
| **A. Nano-service** (recommended) | The route's `action.type` is `nano_service`: a WASM module computes the whole response | None | Per request, inside the sandbox (no network, no filesystem) | Yes |
| B. `respond` action | Canned status/headers/body | None | None (static) | Yes — prefer when static |
| C. A small real service | Deploy an upstream that answers | One | Unlimited | Yes — overkill here |

| Constraint | Nano-service detail |
| --- | --- |
| ABI | Dedicated (not proxy-wasm): `alloc`, `handle`, four `dwara` host imports |
| Sandbox | No network, no filesystem — the module is the whole world |
| Body cap | 1 MiB default request body; over-cap answers 413 `nano_service_body_too_large` |
| Timeout | Per-call `execution_timeout_ms`; over-budget answers 504 `nano_service_timeout` |
| Memory | `memory_limit` (default 1 MiB, max 64 MiB) |

## Implementation

The demo module
([`demos/13-extensibility-usecases/04-feature-flag-nano/module/`](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/04-feature-flag-nano))
is a hand-written `no_std` Rust crate for `wasm32-unknown-unknown` —
no helper crate, no WASI imports (a module importing WASI does not
instantiate: the host provides only the four `dwara` imports). It
answers `{"flag":<bool>}` for `/flags/<name>`, the ON set compiled
in:

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
/// snapshot-publishing or embedding recipes instead.
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

/// `alloc(size) -> ptr`: the host places the serialized request here.
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

/// `handle(req_ptr, req_len) -> i32` (0 = ok, non-zero = 502).
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

/// The request wire format is length-prefixed big-endian: u32
/// method_len, method, u32 path_len, path, headers, body. This module
/// needs only the path, so it skips the method and stops parsing
/// after the path. `None` on a truncated buffer (handle answers 502).
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

Why `no_std` Rust rather than raw WAT: the length-prefix parsing and
byte-slice comparisons are one screen of safe Rust versus several
screens of WAT with manual pointer math; the ABI surface is identical.

## Configuration

The route's action IS the module; the route's `service` is still
required by the schema but is never dialed (the demo points it at
dead port 1 on purpose — any request that somehow reached it would
fail loudly, not silently):

```yaml
routes:
  - name: feature-flags
    service: never-dialed
    match: { path: { type: prefix, value: /flags/ } }
    action:
      type: nano_service
      module: ./feature-flag-nano/target/wasm32-unknown-unknown/release/feature_flag_nano.wasm
      # 2 MiB: a Rust no_std cdylib still declares a 17-page (1.09 MiB)
      # memory minimum (static data + the default stack reservation),
      # which exceeds the 1 MiB default; hand-written WAT could fit
      # under 1 MiB. Max is 64 MiB.
      memory_limit: 2097152
      execution_timeout_ms: 100
```

Build with `cargo build --release --target wasm32-unknown-unknown` —
no SDK, no WASI.

## Operational notes

1. **Hot reload**: the module is re-read when a new config generation
   builds the route handler; pointing `module:` at new bytes swaps it.
   Changing the ON set means rebuilding (or re-publishing) the module
   — for per-request dynamism use the
   [snapshot-publishing](./user-subset-migration) or
   [embedding](./custom-backends-traits) recipes.
2. **Failure behavior**: module missing/broken at handler construction
   answers 502 `nano_service_unavailable`; `handle` returning
   non-zero, trapping, or exhausting fuel answers 502
   `nano_service_error`; exceeding `execution_timeout_ms` answers 504
   `nano_service_timeout`; an over-cap body answers 413
   `nano_service_body_too_large`. All route-scoped: other routes are
   untouched.
3. **Caching interactions**: the module authors the whole response,
   including cache headers — the standard response cache applies
   afterward like any response.
4. **Limits**: no network or filesystem inside the sandbox; great for
   tiny handlers, wrong for anything needing I/O. A decision call is
   [per-request external decisions](./per-request-external-decisions).

## Testing

Assert on the wire behavior: status, `Content-Type`, body per flag,
query-string neutrality — the pattern [Plugin
testing](../plugin-testing) documents for level-2 integration applies
(the harness spawns the gateway against a config like the one above).
The demo's `test.sh` does exactly this.

## Status

Works today, in every build — the nano-service action compiles into
the default OSS build; no cargo feature.

## Runnable demo

[`demos/13-extensibility-usecases/04-feature-flag-nano/`](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/04-feature-flag-nano)
serves the module above with NO upstream configured on the route:
`/flags/new-ui` and `/flags/beta-search` answer `{"flag":true}`,
`/flags/legacy-reports` answers `{"flag":false}`, and a query string
does not change the verdict.
