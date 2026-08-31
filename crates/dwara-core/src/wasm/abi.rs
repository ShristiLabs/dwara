//! proxy-wasm ABI constants and types (DW-055).
//!
//! The proxy-wasm ABI is the standard interface between a WebAssembly
//! plugin and the host proxy. The spec lives at
//! <https://github.com/proxy-wasm/spec>. This module defines the
//! constants the host and plugin exchange over the ABI boundary; the
//! host implementation (the import functions the plugin calls back to)
//! lives in [`super::host`], and the plugin lifecycle (the exports the
//! host calls) lives in [`super::instance`].
//!
//! Only the HTTP filter subset is implemented (dwara is an HTTP
//! gateway, not a TCP proxy): the stream-context calls
//! (`proxy_on_downstream_data`, `proxy_on_upstream_data`, etc.) are
//! stubbed to Continue, and the TCP/context-creation exports are
//! called but their actions are treated as Continue-only.

// --- Buffer types (the `bt` parameter in many ABI calls) ---------------
//
// Maps a buffer type integer to the logical data stream the host
// should read from or write to. The names follow the proxy-wasm spec
// (§2.1 Buffer Types).

/// Buffer type: HTTP request body.
pub const BUFFER_REQUEST_BODY: u32 = 0;
/// Buffer type: HTTP response body.
pub const BUFFER_RESPONSE_BODY: u32 = 1;
/// Buffer type: HTTP request headers.
pub const BUFFER_REQUEST_HEADERS: u32 = 2;
/// Buffer type: HTTP response headers.
pub const BUFFER_RESPONSE_HEADERS: u32 = 3;
/// Buffer type: HTTP request trailers.
pub const BUFFER_REQUEST_TRAILERS: u32 = 4;
/// Buffer type: HTTP response trailers.
pub const BUFFER_RESPONSE_TRAILERS: u32 = 5;
/// Buffer type: VM configuration (passed to `proxy_on_vm_start`).
pub const BUFFER_VM_CONFIGURATION: u32 = 8;
/// Buffer type: Plugin configuration (passed to `proxy_on_configure`).
pub const BUFFER_PLUGIN_CONFIGURATION: u32 = 9;

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

// --- Header map serialization format -----------------------------------
//
// Headers are serialized as a sequence of (key_size: u32, key, value_size:
// u32, value) tuples, all in network byte order (big-endian). The host
// uses this format when returning headers via
// `proxy_get_header_map_pairs` and when accepting them via
// `proxy_set_header_map_pairs`.

/// Serialize a list of (key, value) header pairs into the proxy-wasm
/// wire format: a sequence of (u32 key_len, key bytes, u32 val_len, val
/// bytes) tuples, big-endian.
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

/// Deserialize a proxy-wasm wire-format header map back into pairs.
/// Returns `None` on a truncated/corrupt buffer.
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
