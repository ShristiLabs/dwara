//! feature-flag-nano: a zero-upstream feature-flag endpoint as a
//! dwara nano-service module.
//!
//! The route's action IS this module: the gateway serializes the
//! request (method, path, headers, body) into linear memory, calls
//! `handle`, and returns the response the module builds through the
//! four host imports. No upstream hop, no network, no filesystem --
//! the sandbox is the whole world.
//!
//! Behavior: the flag name is the path segment after `/flags/`
//! (a query string is ignored). Flags compiled ON answer
//! `{"flag":true}`, everything else `{"flag":false}` -- the canned
//! verdict a client caches, evaluated per request at the edge.
//!
//! ABI (see docs-site guide/nano-services):
//!
//! - exports `memory`, `alloc(size) -> ptr` (bump allocator),
//!   `handle(req_ptr, req_len) -> i32` (0 = ok, non-zero = 502)
//! - imports (module `dwara`): `response_status`, `response_header`,
//!   `response_body`, `log` (unused here)
//!
//! The request wire format is length-prefixed big-endian:
//! `u32 method_len, method, u32 path_len, path, u32 header_count,
//! [u32 k_len, k, u32 v_len, v]..., u32 body_len, body`. This module
//! needs only the path, so it skips the method and stops parsing
//! after the path -- the headers/body prefix is never touched.

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
