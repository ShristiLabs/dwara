//! Minimal proxy-wasm ABI bindings for the dwara example plugins.
//!
//! The examples deliberately depend on nothing: this module is the
//! entire proxy-wasm surface they use, as thin `extern "C"` bindings
//! plus safe wrappers. It mirrors exactly what the dwara proxy-wasm
//! host implements for HTTP filters (crates/dwara-core/src/wasm/
//! host.rs): header map reads/writes, buffer reads/writes, the plugin
//! configuration buffer, logging, and `proxy_send_http_response`.
//!
//! On wasm targets the wrappers call the real host imports. On every
//! other target they run against an in-memory fake host ([`fake`]) so
//! `cargo test` can drive the plugin's `proxy_on_*` callbacks as
//! plain Rust tests on the development machine (see
//! `tests/callbacks.rs` in the `static-auth` example).
//!
//! Copy this file verbatim into your own plugin and delete the calls
//! you do not use. Note that the host validates imports: a module may
//! only import proxy-wasm functions the dwara host links, and this
//! file stays inside that set.

// The file is a shared binding layer: every example uses a different
// subset of it, so an unused wrapper in one crate is expected (and
// importing nothing extra costs nothing at instantiate time).
#![allow(dead_code)]

// --- constants: what the dwara host puts on the wire -----------------
//
// These are the DWARA host's wire values (crates/dwara-core/src/wasm/
// abi.rs), which is exactly what a plugin running on dwara needs.
// The buffer and map numbers below are also the proxy-wasm spec
// values (BufferType and MapType are separate 0-based namespaces
// sharing the `bt` parameter: buffer hostcalls take BufferType,
// header-map hostcalls MapType), but two parts of this binding are
// dwara's own and NOT spec guarantees: the local-response hostcall
// is imported under dwara's `proxy_send_http_response` name and
// argument order (the spec hostcall is `proxy_send_local_response`
// with a different parameter list; the dwara host links both), and
// [`ACTION_END_STREAM`] is a dwara extension (the spec's action enum
// is Continue=0 / Pause=1 only). A module built from this file is a
// dwara plugin, not a module that runs on every spec-conformant host.

/// Buffer type: HTTP request body.
pub const BUFFER_REQUEST_BODY: i32 = 0;
/// Buffer type: HTTP response body.
pub const BUFFER_RESPONSE_BODY: i32 = 1;
/// Map type: HTTP request headers.
pub const MAP_REQUEST_HEADERS: i32 = 0;
/// Map type: HTTP response headers.
pub const MAP_RESPONSE_HEADERS: i32 = 2;
/// Buffer type: plugin configuration bytes (the spec's
/// `PLUGIN_CONFIGURATION` value).
pub const BUFFER_PLUGIN_CONFIGURATION: i32 = 7;

/// Action: continue processing (the phase callback's return value).
pub const ACTION_CONTINUE: i32 = 0;
/// Action: end the stream (return after `send_http_response`).
/// dwara extension: the proxy-wasm spec's action enum is Continue=0
/// and Pause=1 only; the spec way to short-circuit is the local
/// response plus Continue. The dwara host treats 2 as "stop the
/// phase chain".
pub const ACTION_END_STREAM: i32 = 2;

/// proxy-wasm log level: info.
pub const LOG_INFO: i32 = 2;

#[cfg(target_family = "wasm")]
#[link(wasm_import_module = "env")]
extern "C" {
    fn proxy_log(level: i32, msg_ptr: *const u8, msg_size: i32) -> i32;
    fn proxy_get_header_map_value(
        map_type: i32,
        key_ptr: *const u8,
        key_size: i32,
        return_ptr_ptr: *mut i32,
        return_size_ptr: *mut i32,
    ) -> i32;
    fn proxy_add_header_map_value(
        map_type: i32,
        key_ptr: *const u8,
        key_size: i32,
        value_ptr: *const u8,
        value_size: i32,
    ) -> i32;
    fn proxy_get_buffer_bytes(
        buffer_type: i32,
        start: i32,
        max_size: i32,
        return_ptr_ptr: *mut i32,
        return_size_ptr: *mut i32,
    ) -> i32;
    fn proxy_set_buffer_bytes(
        buffer_type: i32,
        start: i32,
        size: i32,
        ptr: *const u8,
        data_size: i32,
    ) -> i32;
    fn proxy_send_http_response(
        status: i32,
        headers_ptr: *const u8,
        headers_size: i32,
        body_ptr: *const u8,
        body_size: i32,
        trailers_ptr: *const u8,
        trailers_size: i32,
    ) -> i32;
}

/// The bump allocator the host calls when it must write a return
/// value (a header value, a buffer chunk) into plugin memory. Routed
/// through the Rust allocator so it can never collide with plugin
/// state; the bytes live for the request (each request gets a fresh
/// plugin instance, so nothing accumulates).
#[no_mangle]
pub extern "C" fn proxy_on_memory_allocate(size: i32) -> *mut u8 {
    use std::alloc::{alloc, Layout};
    if size <= 0 {
        return std::ptr::null_mut();
    }
    // Align 8 is what the proxy-wasm spec asks for; any positive size
    // is a valid Layout at that alignment on wasm32.
    match Layout::from_size_align(size as usize, 8) {
        Ok(layout) => unsafe { alloc(layout) },
        Err(_) => std::ptr::null_mut(),
    }
}

/// Serialize headers into the proxy-wasm wire format `proxy_send_http_response`
/// expects: a sequence of (u32 key length, key, u32 value length, value)
/// tuples, all lengths big-endian.
fn serialize_headers(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut buf = Vec::new();
    for (key, value) in headers {
        buf.extend_from_slice(&(key.len() as u32).to_be_bytes());
        buf.extend_from_slice(key.as_bytes());
        buf.extend_from_slice(&(value.len() as u32).to_be_bytes());
        buf.extend_from_slice(value.as_bytes());
    }
    buf
}

// --- safe wrappers ---------------------------------------------------------
//
// Each wrapper has two cfg arms: the real host import on wasm, the
// fake host on everything else (development/test targets).

/// Log a message at info level.
pub fn log_info(message: &str) {
    #[cfg(target_family = "wasm")]
    unsafe {
        proxy_log(LOG_INFO, message.as_ptr(), message.len() as i32);
    }
    #[cfg(not(target_family = "wasm"))]
    fake::log(LOG_INFO, message);
}

/// Read one request header (the host matches the name
/// case-insensitively). `None` when absent. Pseudo-headers (`:method`,
/// `:path`) ride the same map.
pub fn get_request_header(key: &str) -> Option<String> {
    get_header(MAP_REQUEST_HEADERS, key)
}

/// Read one response header (`:status` rides the same map).
pub fn get_response_header(key: &str) -> Option<String> {
    get_header(MAP_RESPONSE_HEADERS, key)
}

fn get_header(map_type: i32, key: &str) -> Option<String> {
    #[cfg(target_family = "wasm")]
    {
        let mut ptr: i32 = 0;
        let mut size: i32 = 0;
        let status = unsafe {
            proxy_get_header_map_value(
                map_type,
                key.as_ptr(),
                key.len() as i32,
                &mut ptr,
                &mut size,
            )
        };
        if status != 0 || size <= 0 {
            return None;
        }
        Some(unsafe { std::slice::from_raw_parts(ptr as *const u8, size as usize) }.to_vec())
            .and_then(|bytes| String::from_utf8(bytes).ok())
    }
    #[cfg(not(target_family = "wasm"))]
    {
        fake::get_header(map_type, key)
    }
}

/// Append a header to the request map (diffs only: names the plugin
/// never touches keep their original bytes downstream).
pub fn add_request_header(key: &str, value: &str) {
    add_header(MAP_REQUEST_HEADERS, key, value);
}

/// Append a header to the response map.
pub fn add_response_header(key: &str, value: &str) {
    add_header(MAP_RESPONSE_HEADERS, key, value);
}

fn add_header(map_type: i32, key: &str, value: &str) {
    #[cfg(target_family = "wasm")]
    unsafe {
        proxy_add_header_map_value(
            map_type,
            key.as_ptr(),
            key.len() as i32,
            value.as_ptr(),
            value.len() as i32,
        );
    }
    #[cfg(not(target_family = "wasm"))]
    {
        fake::add_header(map_type, key, value);
    }
}

/// Read a host buffer. `max_size` should be the size the phase
/// callback received (or the plugin configuration size in
/// `proxy_on_configure`) so the read never exceeds what exists.
pub fn get_buffer(buffer_type: i32, start: i32, max_size: i32) -> Option<Vec<u8>> {
    #[cfg(target_family = "wasm")]
    {
        let mut ptr: i32 = 0;
        let mut size: i32 = 0;
        let status =
            unsafe { proxy_get_buffer_bytes(buffer_type, start, max_size, &mut ptr, &mut size) };
        if status != 0 {
            // The host refused the read (no such buffer, bad range):
            // report absence, mirroring the fake host. Callers fail
            // closed on None (e.g. `proxy_on_configure` sees an empty
            // config and refuses to activate).
            return None;
        }
        if size <= 0 {
            return Some(Vec::new());
        }
        Some(unsafe { std::slice::from_raw_parts(ptr as *const u8, size as usize) }.to_vec())
    }
    #[cfg(not(target_family = "wasm"))]
    {
        fake::get_buffer(buffer_type, start, max_size)
    }
}

/// Replace a host buffer's content from `start` to the end of the
/// buffer with `data` (the host splices; the new length may differ
/// from the old, and the gateway rewrites Content-Length).
pub fn set_buffer(buffer_type: i32, start: i32, data: &[u8]) -> bool {
    #[cfg(target_family = "wasm")]
    {
        let status = unsafe {
            proxy_set_buffer_bytes(
                buffer_type,
                start,
                data.len() as i32,
                data.as_ptr(),
                data.len() as i32,
            )
        };
        status == 0
    }
    #[cfg(not(target_family = "wasm"))]
    {
        fake::set_buffer(buffer_type, start, data)
    }
}

/// Send a local response and end the stream: the gateway returns
/// `status`/`headers`/`body` verbatim and never dials the upstream.
/// The phase callback must return `ACTION_END_STREAM` after this.
///
/// Hostcall note: this imports `proxy_send_http_response`, dwara's
/// original name and argument order. The proxy-wasm spec hostcall is
/// `proxy_send_local_response` with a different parameter list; the
/// dwara host links both spellings, other hosts may link only the
/// spec one.
pub fn send_http_response(status: u16, headers: &[(&str, &str)], body: &[u8]) {
    #[cfg(target_family = "wasm")]
    {
        let wire = serialize_headers(headers);
        unsafe {
            proxy_send_http_response(
                status as i32,
                if wire.is_empty() {
                    std::ptr::null()
                } else {
                    wire.as_ptr()
                },
                wire.len() as i32,
                if body.is_empty() {
                    std::ptr::null()
                } else {
                    body.as_ptr()
                },
                body.len() as i32,
                std::ptr::null(),
                0,
            );
        }
    }
    #[cfg(not(target_family = "wasm"))]
    {
        fake::send_http_response(status, headers, body);
    }
}

// --- fake host (development/test targets only) ------------------------------

/// An in-memory fake of the dwara proxy-wasm host so `cargo test` on
/// the development machine can call the plugin's `proxy_on_*`
/// exports and observe what the plugin would have done to the real
/// host. State is per-thread; call [`reset`] between scenarios.
#[cfg(not(target_family = "wasm"))]
pub mod fake {
    use std::cell::RefCell;

    /// A recorded local response (`send_http_response`).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct LocalResponse {
        pub status: u16,
        pub headers: Vec<(String, String)>,
        pub body: Vec<u8>,
    }

    #[derive(Default)]
    struct State {
        config: Vec<u8>,
        request_headers: Vec<(String, String)>,
        response_headers: Vec<(String, String)>,
        response_body: Vec<u8>,
        added_request_headers: Vec<(String, String)>,
        added_response_headers: Vec<(String, String)>,
        set_response_body: Option<Vec<u8>>,
        local_response: Option<LocalResponse>,
        logs: Vec<String>,
    }

    thread_local! {
        static STATE: RefCell<State> = RefCell::new(State::default());
    }

    /// Clear all fake-host state (start of a test scenario).
    pub fn reset() {
        STATE.with(|s| *s.borrow_mut() = State::default());
    }

    /// Install the plugin configuration bytes (what the gateway would
    /// pass to `proxy_on_configure`).
    pub fn set_config(bytes: &[u8]) {
        STATE.with(|s| s.borrow_mut().config = bytes.to_vec());
    }

    /// Install the response body bytes (what the gateway would expose
    /// at `response_body`).
    pub fn set_response_body(bytes: &[u8]) {
        STATE.with(|s| s.borrow_mut().response_body = bytes.to_vec());
    }

    /// Install the request header map (what the gateway would expose
    /// at `request_headers`; include `:method`/`:path` as you like).
    pub fn set_request_headers(pairs: &[(&str, &str)]) {
        STATE.with(|s| {
            s.borrow_mut().request_headers = pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
        });
    }

    /// Take the recorded local response, if the plugin sent one.
    pub fn take_local_response() -> Option<LocalResponse> {
        STATE.with(|s| s.borrow_mut().local_response.take())
    }

    /// Take the headers the plugin added to the request map.
    pub fn take_added_request_headers() -> Vec<(String, String)> {
        STATE.with(|s| std::mem::take(&mut s.borrow_mut().added_request_headers))
    }

    /// Take the headers the plugin added to the response map.
    pub fn take_added_response_headers() -> Vec<(String, String)> {
        STATE.with(|s| std::mem::take(&mut s.borrow_mut().added_response_headers))
    }

    /// Take the response body the plugin wrote, if any.
    pub fn take_set_response_body() -> Option<Vec<u8>> {
        STATE.with(|s| s.borrow_mut().set_response_body.take())
    }

    /// Take the logged messages.
    pub fn take_logs() -> Vec<String> {
        STATE.with(|s| std::mem::take(&mut s.borrow_mut().logs))
    }

    // --- the fake hostcalls the cfg(not(wasm)) wrappers call ---

    pub(super) fn log(_level: i32, message: &str) {
        STATE.with(|s| s.borrow_mut().logs.push(message.to_string()));
    }

    pub(super) fn get_header(map_type: i32, key: &str) -> Option<String> {
        STATE.with(|s| {
            let state = s.borrow();
            let map = if map_type == super::MAP_REQUEST_HEADERS {
                &state.request_headers
            } else {
                &state.response_headers
            };
            map.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .map(|(_, v)| v.clone())
        })
    }

    pub(super) fn add_header(map_type: i32, key: &str, value: &str) {
        STATE.with(|s| {
            let mut state = s.borrow_mut();
            let pair = (key.to_string(), value.to_string());
            if map_type == super::MAP_REQUEST_HEADERS {
                state.added_request_headers.push(pair);
            } else {
                state.added_response_headers.push(pair);
            }
        })
    }

    pub(super) fn get_buffer(buffer_type: i32, start: i32, max_size: i32) -> Option<Vec<u8>> {
        STATE.with(|s| {
            let state = s.borrow();
            let data: &[u8] = match buffer_type {
                super::BUFFER_PLUGIN_CONFIGURATION => &state.config,
                super::BUFFER_RESPONSE_BODY => &state.response_body,
                _ => return None,
            };
            if start < 0 || start as usize > data.len() {
                return None;
            }
            let end = (start + max_size.max(0)) as usize;
            Some(data[start as usize..end.min(data.len())].to_vec())
        })
    }

    pub(super) fn set_buffer(buffer_type: i32, start: i32, data: &[u8]) -> bool {
        if buffer_type != super::BUFFER_RESPONSE_BODY {
            return false;
        }
        STATE.with(|s| {
            let mut state = s.borrow_mut();
            let end = state.response_body.len();
            let start = start.max(0) as usize;
            let mut body = state.response_body[..start.min(end)].to_vec();
            body.extend_from_slice(data);
            state.response_body = body;
            state.set_response_body = Some(data.to_vec());
            true
        })
    }

    pub(super) fn send_http_response(status: u16, headers: &[(&str, &str)], body: &[u8]) {
        STATE.with(|s| {
            s.borrow_mut().local_response = Some(LocalResponse {
                status,
                headers: headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                body: body.to_vec(),
            });
        });
    }
}
