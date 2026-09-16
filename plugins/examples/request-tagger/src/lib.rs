//! request-tagger: stamp correlation headers on both directions.
//!
//! The "hello plugin+" of the gallery: at `request_headers` it reads
//! the inbound `x-request-id` and stamps `x-plugin-name` +
//! `x-plugin-request-id` onto the request (visible at the upstream);
//! at `response_headers` it stamps the same pair onto the response
//! (visible at the client), echoing the request id captured earlier.
//! When the inbound request carries no `x-request-id`, the value is
//! the literal `unset`.
//!
//! Phase contract: `request_headers` and `response_headers`. Header
//! phases apply diffs only: names the plugin never touched keep their
//! original bytes downstream.
//!
//! No config: `proxy_on_configure` is not exported (the gateway skips
//! it when absent); nothing to parse.
//!
//! Structure: [`HttpContext`] holds the per-request correlation state
//! captured at `request_headers` and reused at `response_headers`
//! (fresh statics per request: dwara instantiates a new plugin
//! instance per request), and [`correlation_id`] is the pure piece
//! the unit tests exercise.

pub mod abi;

use std::sync::Mutex;

/// The header this plugin echoes.
pub const REQUEST_ID_HEADER: &str = "x-request-id";
/// The stamp headers this plugin adds (both directions).
pub const NAME_HEADER: &str = "x-plugin-name";
pub const CORRELATION_HEADER: &str = "x-plugin-request-id";
/// The plugin's name, as stamped in `x-plugin-name`.
pub const PLUGIN_NAME: &str = "request-tagger";

/// The `HttpContext` role: per-request state. Created at the first
/// phase callback (dwara drives the request phase first on every
/// request), read at the response phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpContext {
    correlation_id: String,
}

/// The correlation value stamped on both directions: the inbound
/// `x-request-id` when present and non-empty, else the literal
/// `unset`.
pub fn correlation_id(inbound: Option<&str>) -> &str {
    inbound.filter(|value| !value.is_empty()).unwrap_or("unset")
}

/// Per-instance HTTP context (fresh statics per request).
static HTTP: Mutex<Option<HttpContext>> = Mutex::new(None);

/// Clear per-instance state (host-side callback tests).
#[cfg(not(target_family = "wasm"))]
pub fn test_reset() {
    *HTTP.lock().unwrap() = None;
    abi::fake::reset();
}

#[no_mangle]
/// `proxy_on_vm_start`: nothing to do at VM start; success.
pub extern "C" fn proxy_on_vm_start(_context_id: i32, _vm_config_size: i32) -> i32 {
    1
}

#[no_mangle]
/// `proxy_on_request_headers`: capture the request id and stamp the
/// request headers.
pub extern "C" fn proxy_on_request_headers(
    _context_id: i32,
    _num_headers: i32,
    _end_of_stream: i32,
) -> i32 {
    let inbound = abi::get_request_header(REQUEST_ID_HEADER);
    let correlation = correlation_id(inbound.as_deref()).to_string();
    *HTTP.lock().unwrap() = Some(HttpContext {
        correlation_id: correlation.clone(),
    });
    abi::add_request_header(NAME_HEADER, PLUGIN_NAME);
    abi::add_request_header(CORRELATION_HEADER, &correlation);
    abi::ACTION_CONTINUE
}

#[no_mangle]
/// `proxy_on_response_headers`: stamp the response headers with the
/// request id captured at the request phase.
pub extern "C" fn proxy_on_response_headers(
    _context_id: i32,
    _num_headers: i32,
    _end_of_stream: i32,
) -> i32 {
    let correlation = HTTP
        .lock()
        .unwrap()
        .as_ref()
        .map(|context| context.correlation_id.clone())
        .unwrap_or_else(|| correlation_id(None).to_string());
    abi::add_response_header(NAME_HEADER, PLUGIN_NAME);
    abi::add_response_header(CORRELATION_HEADER, &correlation);
    abi::ACTION_CONTINUE
}
