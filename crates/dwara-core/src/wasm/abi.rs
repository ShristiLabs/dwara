//! proxy-wasm ABI constants and types (DW-055).
//!
//! The proxy-wasm ABI is the standard interface between a WebAssembly
//! plugin and the host proxy. The spec lives at
//! <https://github.com/proxy-wasm/spec>. This module defines the
//! constants the host and plugin exchange over the ABI boundary; the
//! host implementation (the import functions the plugin calls back to)
//! lives in [`super::host`], and the plugin lifecycle (the exports the
//! host calls) lives in `super::instance`.
//!
//! Only the HTTP filter subset is implemented (dwara is an HTTP
//! gateway, not a TCP proxy): the stream-context calls
//! (`proxy_on_downstream_data`, `proxy_on_upstream_data`, etc.) are
//! stubbed to Continue, and the TCP/context-creation exports are
//! called but their actions are treated as Continue-only.

// --- Buffer types (the `bt` parameter in many ABI calls) ---------------
//
// Maps a buffer type integer to the logical data stream the host
// should read from or write to. The values follow the proxy-wasm spec
// (§2.1 Buffer Types and §2.2 Map Types — the buffer hostcalls use the
// BufferType namespace, the header-map hostcalls the MapType
// namespace; both are 0-based and deliberately share the `bt`
// parameter). NOTE: the header-map values are the SPEC values
// (request headers = 0, response headers = 2) — the Rust proxy-wasm
// SDK (and Envoy/Kong filters built against it) send exactly these.

/// Buffer type: HTTP request body (`proxy_get/set_buffer_bytes`).
pub const BUFFER_REQUEST_BODY: u32 = 0;
/// Buffer type: HTTP response body (`proxy_get/set_buffer_bytes`).
pub const BUFFER_RESPONSE_BODY: u32 = 1;
/// Map type: HTTP request headers (header-map hostcalls).
pub const BUFFER_REQUEST_HEADERS: u32 = 0;
/// Map type: HTTP request trailers (header-map hostcalls).
pub const BUFFER_REQUEST_TRAILERS: u32 = 1;
/// Map type: HTTP response headers (header-map hostcalls).
pub const BUFFER_RESPONSE_HEADERS: u32 = 2;
/// Map type: HTTP response trailers (header-map hostcalls).
pub const BUFFER_RESPONSE_TRAILERS: u32 = 3;
/// Buffer type: VM configuration (passed to `proxy_on_vm_start`).
pub const BUFFER_VM_CONFIGURATION: u32 = 6;
/// Buffer type: Plugin configuration (passed to `proxy_on_configure`).
pub const BUFFER_PLUGIN_CONFIGURATION: u32 = 7;

// --- Log levels (the `level` parameter in `proxy_log`) -----------------

pub const LOG_TRACE: u32 = 0;
pub const LOG_DEBUG: u32 = 1;
pub const LOG_INFO: u32 = 2;
pub const LOG_WARN: u32 = 3;
pub const LOG_ERROR: u32 = 4;
pub const LOG_CRITICAL: u32 = 5;

// --- Action return values (the return type of phase exports) -----------
//
// The plugin returns an action from each phase callback. For HTTP
// filters, only Continue and EndStream matter (Pause is for streaming
// TCP contexts; PauseAndContinueIfUsed is for partial data).

/// Continue processing — the request/response proceeds normally.
pub const ACTION_CONTINUE: u32 = 0;
/// End the stream — short-circuit the request (e.g. after
/// `proxy_send_http_response`). No further phase callbacks fire.
pub const ACTION_END_STREAM: u32 = 2;

// --- Close types (the `close_type` parameter in close callbacks) -------

pub const CLOSE_UNKNOWN: u32 = 0;
pub const CLOSE_LOCAL: u32 = 1;
pub const CLOSE_REMOTE: u32 = 2;

// --- Header map serialization formats -----------------------------------
//
// There are two wire layouts, keyed by import spelling (the additive
// rule: the spec-named hostcalls speak the SDK layout, dwara's legacy
// spellings keep the original layout they shipped with):
//
// 1. Spec/SDK layout — `proxy_get_header_map_pairs`,
//    `proxy_set_header_map_pairs`, and `proxy_send_local_response`.
//    This is the layout the Rust proxy-wasm SDK produces and parses
//    (proxy-wasm 0.2.5, src/hostcalls.rs `utils::serialize_map` /
//    `utils::deserialize_map`, ~lines 1265-1327): a little-endian u32
//    entry count, then a length table of little-endian u32 pairs
//    (key_len, value_len — one pair per entry), then the strings:
//    each key and each value NUL-terminated. An empty buffer
//    deserializes to an empty map; an empty map serializes to the
//    4-byte LE count 0.
//
// 2. dwara legacy layout — `proxy_send_http_response` only. A
//    sequence of (u32 key_len BE, key bytes, u32 val_len BE, val
//    bytes) tuples with no count and no NULs.

/// Serialize a list of (key, value) header pairs into the spec/SDK
/// proxy-wasm wire layout (mirrors the Rust proxy-wasm SDK's
/// `utils::serialize_map`, hostcalls.rs ~line 1265): LE u32 entry
/// count, then the LE u32 (key_len, value_len) length table, then the
/// NUL-terminated strings. An empty map serializes to exactly the
/// 4-byte LE count 0 — the bytes the SDK passes for
/// `send_http_response` with empty headers.
pub fn serialize_header_map_spec(headers: &[(String, String)]) -> Vec<u8> {
    let mut size: usize = 4;
    for (key, value) in headers {
        size += key.len() + value.len() + 10;
    }
    let mut buf = Vec::with_capacity(size);
    buf.extend_from_slice(&(headers.len() as u32).to_le_bytes());
    for (key, value) in headers {
        buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
    }
    for (key, value) in headers {
        buf.extend_from_slice(key.as_bytes());
        buf.push(0);
        buf.extend_from_slice(value.as_bytes());
        buf.push(0);
    }
    buf
}

/// Deserialize a spec/SDK proxy-wasm wire-layout header map (the
/// format `serialize_header_map_spec` produces and the Rust proxy-wasm
/// SDK's `utils::deserialize_map`, hostcalls.rs ~line 1305, parses).
/// An empty buffer is an empty map (the SDK's convention); any
/// truncated or corrupt buffer returns `None` (the SDK would panic on
/// its `unwrap`s — the host fails the hostcall instead).
pub fn deserialize_header_map_spec(buf: &[u8]) -> Option<Vec<(String, String)>> {
    if buf.is_empty() {
        return Some(Vec::new());
    }
    if buf.len() < 4 {
        return None;
    }
    let count = u32::from_le_bytes(buf[0..4].try_into().expect("4 bytes")) as usize;
    let table_end = 4usize.checked_add(count.checked_mul(8)?)?;
    if buf.len() < table_end {
        return None;
    }
    let mut result = Vec::with_capacity(count);
    let mut pos = table_end;
    for n in 0..count {
        let entry = 4 + n * 8;
        let key_len =
            u32::from_le_bytes(buf[entry..entry + 4].try_into().expect("4 bytes")) as usize;
        let val_len =
            u32::from_le_bytes(buf[entry + 4..entry + 8].try_into().expect("4 bytes")) as usize;
        let key = take_nul_terminated(buf, &mut pos, key_len)?;
        let value = take_nul_terminated(buf, &mut pos, val_len)?;
        result.push((key, value));
    }
    Some(result)
}

/// Read `len` bytes at `*pos` followed by a NUL terminator (the SDK's
/// string-data layout), advancing `*pos` past both. Returns `None` on
/// a missing terminator, a truncated string, or non-UTF-8 bytes.
fn take_nul_terminated(buf: &[u8], pos: &mut usize, len: usize) -> Option<String> {
    let start = *pos;
    let end = start.checked_add(len)?;
    if end >= buf.len() || buf[end] != 0 {
        return None;
    }
    let s = String::from_utf8(buf[start..end].to_vec()).ok()?;
    *pos = end + 1;
    Some(s)
}

/// Serialize a list of (key, value) header pairs into dwara's LEGACY
/// wire layout (dwara's own `proxy_send_http_response` spelling only):
/// a sequence of (u32 key_len, key bytes, u32 val_len, val bytes)
/// tuples, big-endian. The spec-named hostcalls use
/// [`serialize_header_map_spec`] instead.
pub fn serialize_header_map(headers: &[(String, String)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(headers.len() * 32);
    for (key, value) in headers {
        buf.extend_from_slice(&(key.len() as u32).to_be_bytes());
        buf.extend_from_slice(key.as_bytes());
        buf.extend_from_slice(&(value.len() as u32).to_be_bytes());
        buf.extend_from_slice(value.as_bytes());
    }
    buf
}

/// Deserialize a LEGACY-layout header map (dwara's
/// `proxy_send_http_response` spelling only) back into pairs. Returns
/// `None` on a truncated/corrupt buffer. The spec-named hostcalls use
/// [`deserialize_header_map_spec`] instead.
pub fn deserialize_header_map(buf: &[u8]) -> Option<Vec<(String, String)>> {
    let mut result = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        if pos + 4 > buf.len() {
            return None;
        }
        let key_len = u32::from_be_bytes(buf[pos..pos + 4].try_into().ok()?) as usize;
        pos += 4;
        if pos + key_len > buf.len() {
            return None;
        }
        let key = String::from_utf8(buf[pos..pos + key_len].to_vec()).ok()?;
        pos += key_len;

        if pos + 4 > buf.len() {
            return None;
        }
        let val_len = u32::from_be_bytes(buf[pos..pos + 4].try_into().ok()?) as usize;
        pos += 4;
        if pos + val_len > buf.len() {
            return None;
        }
        let value = String::from_utf8(buf[pos..pos + val_len].to_vec()).ok()?;
        pos += val_len;

        result.push((key, value));
    }
    Some(result)
}
