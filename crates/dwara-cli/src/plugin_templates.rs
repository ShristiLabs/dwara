//! Example-plugin templates for `plugin new --template` (DW-166, #284).
//!
//! `dwara plugin new <name> --template <example>` scaffolds from one
//! of the four runnable examples in `plugins/examples/` instead of
//! the hello-world default ([`crate::plugin_scaffold`]). The example
//! crates are vendored here as template strings only, mirroring
//! `plugin_scaffold.rs`'s pattern: a released `dwara-cli` binary must
//! scaffold without a dwara source checkout on disk.
//!
//! The templates are the raw-ABI examples (no `proxy-wasm` crate
//! dependency): `src/abi.rs` binds the proxy-wasm host imports
//! directly and doubles as a fake host on non-wasm targets, so the
//! scaffolded project runs `cargo test` on the host offline and
//! builds for `wasm32-wasip1` with zero dependencies. Vendored files
//! are verbatim copies of the examples; after changing an example,
//! re-vendor the file here in the same change.
//!
//! ## Substitution
//!
//! The example's hyphenated crate name and its underscored lib form
//! are replaced with the target name's forms everywhere (Cargo.toml,
//! `use` lines in tests, the `x-plugin-name` stamp, log prefixes, doc
//! comments). Within one template every occurrence of either form
//! refers to the crate itself, so a global replace is safe; prose in
//! the generated README deliberately never names the source example.

/// The shared proxy-wasm binding layer (`src/abi.rs`), byte-identical
/// in all four examples.
const ABI_RS: &str = r#"//! Minimal proxy-wasm ABI bindings for the dwara example plugins.
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
"#;

/// The shared flat-JSON config reader (`src/json.rs`), byte-identical
/// in the three examples that parse a plugin config.
const JSON_RS: &str = r#"//! A deliberately tiny flat-JSON reader for plugin configuration.
//!
//! dwara hands a plugin's `config:` string to `proxy_on_configure`
//! as raw bytes; the convention is a small JSON object the plugin
//! parses itself. These example plugins depend on nothing, so instead
//! of pulling a JSON crate into the wasm module they use this
//! purpose-built reader, which supports exactly what plugin configs
//! need: a flat object whose values are strings or arrays of strings.
//!
//! Supported: `{ "key": "value", "key2": ["a", "b"] }` with standard
//! whitespace, empty arrays, empty objects, and the string escapes
//! `\"` `\\` `\/` `\b` `\f` `\n` `\r` `\t`. Anything else (nested
//! objects, numbers, booleans, null, `\uXXXX`) is rejected with an
//! error, so a malformed config fails closed at configure time
//! instead of misbehaving per request.

// A shared helper file: not every consumer uses every accessors.
#![allow(dead_code)]

/// A parsed JSON value: a string or an array of strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    Str(String),
    Arr(Vec<String>),
}

impl JsonValue {
    /// The value as a string, or `None` when it is an array.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::Str(s) => Some(s),
            JsonValue::Arr(_) => None,
        }
    }

    /// The value as an array of strings, or `None` when it is a
    /// string.
    pub fn as_arr(&self) -> Option<&[String]> {
        match self {
            JsonValue::Str(_) => None,
            JsonValue::Arr(items) => Some(items),
        }
    }
}

/// Parse a flat JSON object into ordered key/value pairs. Duplicate
/// keys keep the first occurrence (last-write-wins is a footgun for
/// security-relevant config).
pub fn parse_flat_object(bytes: &[u8]) -> Result<Vec<(String, JsonValue)>, String> {
    let mut parser = Parser { bytes, pos: 0 };
    parser.skip_ws();
    parser.expect(b'{')?;
    let mut pairs = Vec::new();
    parser.skip_ws();
    if parser.peek() == Some(b'}') {
        parser.pos += 1;
    } else {
        loop {
            parser.skip_ws();
            let key = parser.parse_string()?;
            parser.skip_ws();
            parser.expect(b':')?;
            parser.skip_ws();
            let value = parser.parse_value()?;
            if !pairs.iter().any(|(k, _): &(String, JsonValue)| *k == key) {
                pairs.push((key, value));
            }
            parser.skip_ws();
            match parser.peek() {
                Some(b',') => {
                    parser.pos += 1;
                }
                Some(b'}') => {
                    parser.pos += 1;
                    break;
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", parser.pos)),
            }
        }
    }
    parser.skip_ws();
    if parser.pos != bytes.len() {
        return Err(format!("trailing data at byte {}", parser.pos));
    }
    Ok(pairs)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        match self.peek() {
            Some(b) if b == byte => {
                self.pos += 1;
                Ok(())
            }
            _ => Err(format!("expected '{}' at byte {}", byte as char, self.pos)),
        }
    }

    fn skip_ws(&mut self) {
        while matches!(
            self.peek(),
            Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r')
        ) {
            self.pos += 1;
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            match self.peek() {
                None => return Err("unterminated string".to_string()),
                Some(b'"') => {
                    self.pos += 1;
                    // Raw bytes are copied verbatim above, so valid
                    // UTF-8 in the input survives intact and anything
                    // else is rejected here.
                    return String::from_utf8(out)
                        .map_err(|_| "string is not valid UTF-8".to_string());
                }
                Some(b'\\') => {
                    self.pos += 1;
                    match self.peek() {
                        Some(b'"') => out.push(b'"'),
                        Some(b'\\') => out.push(b'\\'),
                        Some(b'/') => out.push(b'/'),
                        Some(b'b') => out.push(0x08),
                        Some(b'f') => out.push(0x0C),
                        Some(b'n') => out.push(b'\n'),
                        Some(b'r') => out.push(b'\r'),
                        Some(b't') => out.push(b'\t'),
                        other => {
                            return Err(format!(
                                "unsupported escape '\\{}' at byte {}",
                                other.map(|b| b as char).unwrap_or('?'),
                                self.pos
                            ));
                        }
                    }
                    self.pos += 1;
                }
                Some(byte) if byte < 0x20 => {
                    return Err(format!("control character at byte {}", self.pos));
                }
                Some(byte) => {
                    out.push(byte);
                    self.pos += 1;
                }
            }
        }
    }

    fn parse_value(&mut self) -> Result<JsonValue, String> {
        match self.peek() {
            Some(b'"') => Ok(JsonValue::Str(self.parse_string()?)),
            Some(b'[') => {
                self.pos += 1;
                let mut items = Vec::new();
                self.skip_ws();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Ok(JsonValue::Arr(items));
                }
                loop {
                    self.skip_ws();
                    items.push(self.parse_string()?);
                    self.skip_ws();
                    match self.peek() {
                        Some(b',') => {
                            self.pos += 1;
                        }
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(JsonValue::Arr(items));
                        }
                        _ => {
                            return Err(format!("expected ',' or ']' at byte {}", self.pos));
                        }
                    }
                }
            }
            _ => Err(format!(
                "expected a string or array of strings at byte {} \
                 (numbers, booleans, null, and nested objects are not supported)",
                self.pos
            )),
        }
    }
}
"#;

/// One scaffoldable example template.
pub struct Template {
    /// The template name (`--template <name>`): the example crate's
    /// own name.
    pub name: &'static str,
    /// One-line description (unknown-template errors, docs).
    pub summary: &'static str,
    /// `src/lib.rs`, verbatim from the example.
    lib_rs: &'static str,
    /// `tests/<file>`, verbatim from the example.
    tests: &'static [(&'static str, &'static str)],
    /// `Cargo.toml`, verbatim from the example.
    cargo_toml: &'static str,
    /// `README.md`, the example's README adapted to a standalone
    /// project (local paths; no gallery-harness references).
    readme: &'static str,
    /// `dwara.yaml`, a minimal gateway config wiring the plugin.
    dwara_yaml: &'static str,
    /// Whether the template carries `src/json.rs`.
    json: bool,
}

/// All scaffoldable templates, in gallery order.
pub const TEMPLATES: &[Template] = &[
    Template {
        name: "static-auth",
        summary: "short-circuit 401 for missing or wrong tokens",
        lib_rs: r#"//! static-auth: gate a route behind a configured bearer-style token.
//!
//! The route only passes when the request presents the configured
//! token in the configured header; anything else is answered `401`
//! with a `WWW-Authenticate` challenge by the plugin itself via
//! `proxy_send_http_response` (the upstream is never dialed).
//!
//! Phase contract: `request_headers` only (after route resolution,
//! before authn).
//!
//! Config (the `config:` string on the plugin entry, parsed at
//! `proxy_on_configure`):
//!
//! ```json
//! {"header": "authorization", "scheme": "Bearer", "token": "s3cr3t"}
//! ```
//!
//! `scheme` is optional. With a scheme, the presented value must be
//! `"<scheme> <token>"` (the standard Authorization shape); without
//! one, the raw header value is compared. Comparison is
//! constant-time ([`constant_time_eq`]).
//!
//! Fail-closed semantics: a missing/empty/unparsable config makes
//! `proxy_on_configure` return false, so the gateway marks the plugin
//! broken and routes referencing it answer 500 `plugin_unavailable`
//! rather than running unauthenticated.
//!
//! Structure: [`RootContext`] holds the parsed config, the
//! `proxy_on_*` exports are thin shims, and [`evaluate`] plus
//! [`constant_time_eq`] are the pure logic the unit tests exercise.
//! `tests/callbacks.rs` drives the actual `proxy_on_*` exports
//! against the fake host from `abi.rs` (the pattern the plugin
//! testing guide documents).

pub mod abi;
mod json;

use std::sync::Mutex;

/// The `RootContext` role: state parsed from the plugin configuration
/// at `proxy_on_configure`. dwara instantiates a fresh plugin
/// instance per request, so this is per-request state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootContext {
    config: AuthConfig,
}

/// The parsed plugin configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthConfig {
    /// The header carrying the credential (matched case-insensitively
    /// by the host).
    pub header: String,
    /// Optional scheme prefix (`"Bearer"` yields `Bearer <token>`).
    pub scheme: Option<String>,
    /// The expected token.
    pub token: String,
}

impl AuthConfig {
    /// Parse the plugin config bytes (a flat JSON object; see
    /// `json.rs`). `header` and `token` are required non-empty;
    /// `scheme` is optional.
    pub fn parse(bytes: &[u8]) -> Result<AuthConfig, String> {
        let fields = json::parse_flat_object(bytes)?;
        let get = |key: &str| -> Result<Option<String>, String> {
            Ok(fields
                .iter()
                .find(|(k, _)| k == key)
                .and_then(|(_, v)| v.as_str().map(str::to_string)))
        };
        let required = |key: &str| -> Result<String, String> {
            get(key)?
                .filter(|v| !v.is_empty())
                .ok_or_else(|| format!("missing or empty string field \"{key}\""))
        };
        Ok(AuthConfig {
            header: required("header")?,
            scheme: get("scheme")?.filter(|s| !s.is_empty()),
            token: required("token")?,
        })
    }
}

/// The decision for one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthDecision {
    /// The credential matched: forward the request.
    Allow,
    /// No credential presented (401, challenge in the response).
    DenyMissing,
    /// A credential was presented but is wrong (401, challenge in the
    /// response).
    DenyInvalid,
}

/// The pure decision function (unit-tested in `tests/logic.rs`).
pub fn evaluate(config: &AuthConfig, presented: Option<&str>) -> AuthDecision {
    let Some(raw) = presented.filter(|v| !v.is_empty()) else {
        return AuthDecision::DenyMissing;
    };
    let candidate = match &config.scheme {
        Some(scheme) => match strip_scheme(raw, scheme) {
            Some(rest) => rest,
            None => return AuthDecision::DenyInvalid,
        },
        None => raw,
    };
    if constant_time_eq(candidate.as_bytes(), config.token.as_bytes()) {
        AuthDecision::Allow
    } else {
        AuthDecision::DenyInvalid
    }
}

/// Strip a `"<scheme> <credentials>"` prefix (the Authorization
/// header shape). The scheme match is ASCII case-insensitive, per
/// RFC 7235. `None` when the value does not carry the scheme.
pub fn strip_scheme<'v>(value: &'v str, scheme: &str) -> Option<&'v str> {
    let (head, rest) = value.split_once(' ')?;
    if !head.eq_ignore_ascii_case(scheme) {
        return None;
    }
    let rest = rest.trim_start();
    if rest.is_empty() {
        None
    } else {
        Some(rest)
    }
}

/// Constant-time byte-slice equality: the comparison walks
/// `max(a.len(), b.len())` bytes and folds every XOR difference, so
/// the running time does not depend on where the first difference
/// occurs. Length differences still leak (that is unavoidable and
/// harmless for token comparison; the token length is not secret).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len = a.len().max(b.len());
    // The fold must stay usize-wide: truncating the length XOR to u8
    // would make lengths differing by a multiple of 256 compare equal
    // (an all-zero buffer and a 256-zero-byte buffer, for example).
    let mut diff: usize = a.len() ^ b.len();
    for i in 0..len {
        let byte_a = if i < a.len() { a[i] } else { 0 };
        let byte_b = if i < b.len() { b[i] } else { 0 };
        diff |= usize::from(byte_a ^ byte_b);
    }
    diff == 0
}

/// The `WWW-Authenticate` challenge headers for a 401.
pub fn challenge_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("WWW-Authenticate", "Bearer realm=\"dwara\""),
        ("x-plugin-name", "static-auth"),
    ]
}

/// The 401 body for a denied request.
pub fn deny_body(denial: AuthDecision) -> Vec<u8> {
    let reason = match denial {
        AuthDecision::DenyMissing => "missing credential",
        _ => "invalid credential",
    };
    format!("{{\"error\":\"unauthorized ({reason})\"}}\n").into_bytes()
}

/// Per-instance root state (fresh statics per request: dwara
/// instantiates a new plugin instance per request).
static ROOT: Mutex<Option<RootContext>> = Mutex::new(None);

/// Clear per-instance state (host-side callback tests).
#[cfg(not(target_family = "wasm"))]
pub fn test_reset() {
    *ROOT.lock().unwrap() = None;
    abi::fake::reset();
}

#[no_mangle]
/// `proxy_on_vm_start`: nothing to do at VM start; success.
pub extern "C" fn proxy_on_vm_start(_context_id: i32, _vm_config_size: i32) -> i32 {
    1
}

#[no_mangle]
/// `proxy_on_configure`: parse the plugin config bytes. Returning 0
/// marks the plugin broken (fail-closed) instead of running unguarded.
pub extern "C" fn proxy_on_configure(_context_id: i32, plugin_config_size: i32) -> i32 {
    let bytes = abi::get_buffer(abi::BUFFER_PLUGIN_CONFIGURATION, 0, plugin_config_size)
        .unwrap_or_default();
    match AuthConfig::parse(&bytes) {
        Ok(config) => {
            *ROOT.lock().unwrap() = Some(RootContext { config });
            1
        }
        Err(error) => {
            abi::log_info(&format!("static-auth: invalid config: {error}"));
            0
        }
    }
}

#[no_mangle]
/// `proxy_on_request_headers` (the only declared phase): present the
/// token or be challenged with a 401.
pub extern "C" fn proxy_on_request_headers(
    _context_id: i32,
    _num_headers: i32,
    _end_of_stream: i32,
) -> i32 {
    let guard = ROOT.lock().unwrap();
    let Some(root) = guard.as_ref() else {
        // Unreachable when configure succeeded; deny if it ever happens.
        let denial = AuthDecision::DenyMissing;
        let headers = challenge_headers();
        abi::send_http_response(401, &headers, &deny_body(denial));
        return abi::ACTION_END_STREAM;
    };
    let presented = abi::get_request_header(&root.config.header);
    match evaluate(&root.config, presented.as_deref()) {
        AuthDecision::Allow => abi::ACTION_CONTINUE,
        denial => {
            let headers = challenge_headers();
            abi::send_http_response(401, &headers, &deny_body(denial));
            abi::ACTION_END_STREAM
        }
    }
}
"#,
        tests: &[
            (
                "callbacks.rs",
                r##"//! Callback-level unit tests: drive the real `proxy_on_*` exports.
//!
//! `src/abi.rs` compiles a fake host on non-wasm targets, so on the
//! development machine `cargo test` can call the plugin's actual
//! proxy-wasm entrypoints and observe exactly what the plugin would
//! have done to the gateway (local response, added headers, logged
//! lines). This is the second half of level 1 in the plugin testing
//! guide: no gateway, no wasm, but the real callback wiring.
//!
//! The scenarios run sequentially in one test: the per-instance root
//! state is a process-wide static (mirroring the wasm module's
//! linear-memory static), so scenarios must not interleave.

use static_auth::{
    abi::{
        fake,
        fake::LocalResponse,
        {ACTION_CONTINUE, ACTION_END_STREAM},
    },
    proxy_on_configure, proxy_on_request_headers, test_reset,
};

const CONFIG: &[u8] = br#"{"header":"authorization","scheme":"Bearer","token":"s3cr3t"}"#;

fn configure() {
    fake::set_config(CONFIG);
    assert_eq!(proxy_on_configure(1, CONFIG.len() as i32), 1);
}

fn request(authorization: Option<&str>) -> i32 {
    let mut headers: Vec<(&str, &str)> = vec![(":method", "GET"), (":path", "/v1/things")];
    if let Some(value) = authorization {
        headers.push(("authorization", value));
    }
    fake::set_request_headers(&headers);
    proxy_on_request_headers(2, headers.len() as i32, 1)
}

fn header<'a>(response: &'a LocalResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

#[test]
fn callback_scenarios() {
    // --- configure: a good config activates the plugin -------------
    test_reset();
    configure();

    // --- allow: the correct bearer token continues the request -----
    assert_eq!(request(Some("Bearer s3cr3t")), ACTION_CONTINUE);
    assert!(
        fake::take_local_response().is_none(),
        "allowed request must not answer locally"
    );

    // --- deny (missing): 401 with a WWW-Authenticate challenge -----
    assert_eq!(request(None), ACTION_END_STREAM);
    let response = fake::take_local_response().expect("missing credential must 401");
    assert_eq!(response.status, 401);
    assert_eq!(
        header(&response, "WWW-Authenticate"),
        Some("Bearer realm=\"dwara\"")
    );
    let body = String::from_utf8(response.body).expect("body is UTF-8");
    assert!(body.contains("missing credential"), "body: {body}");
    // The upstream was never dialed: a local response IS the answer.
    assert_eq!(fake::take_local_response(), None);

    // --- deny (wrong token): same challenge, invalid reason --------
    assert_eq!(request(Some("Bearer wrong")), ACTION_END_STREAM);
    let response = fake::take_local_response().expect("wrong token must 401");
    assert_eq!(response.status, 401);
    let body = String::from_utf8(response.body).expect("body is UTF-8");
    assert!(body.contains("invalid credential"), "body: {body}");

    // --- deny (wrong scheme): Basic does not satisfy Bearer --------
    assert_eq!(request(Some("Basic c2VjcmV0")), ACTION_END_STREAM);
    assert!(fake::take_local_response().is_some());

    // --- fail closed: a malformed config refuses to activate -------
    test_reset();
    fake::set_config(b"not json at all");
    assert_eq!(
        proxy_on_configure(1, 14),
        0,
        "a plugin that cannot parse its config must not run"
    );
    // Every request on the route now fails closed at the gateway
    // (500 plugin_unavailable); nothing the plugin can do about it.

    // --- deny (unconfigured): if configure never ran, deny ---------
    // Directly exercising the defensive branch: fresh state, no
    // configure call.
    test_reset();
    assert_eq!(request(None), ACTION_END_STREAM);
    let response = fake::take_local_response().expect("unconfigured plugin denies");
    assert_eq!(response.status, 401);
}
"##,
            ),
            (
                "logic.rs",
                r##"//! Plain-Rust unit tests for static-auth's decision logic.
//!
//! These run on the development machine (`cargo test`): the pure
//! decision function, the scheme stripper, and the constant-time
//! comparison need neither wasm nor a gateway. See the plugin testing
//! guide (level 1).

use static_auth::{constant_time_eq, evaluate, strip_scheme, AuthConfig, AuthDecision};

fn config() -> AuthConfig {
    AuthConfig::parse(br#"{"header":"authorization","scheme":"Bearer","token":"s3cr3t"}"#)
        .expect("valid config parses")
}

#[test]
fn correct_bearer_token_allows() {
    assert_eq!(
        evaluate(&config(), Some("Bearer s3cr3t")),
        AuthDecision::Allow
    );
}

#[test]
fn missing_header_denies_missing() {
    assert_eq!(evaluate(&config(), None), AuthDecision::DenyMissing);
    assert_eq!(evaluate(&config(), Some("")), AuthDecision::DenyMissing);
}

#[test]
fn wrong_token_denies_invalid() {
    assert_eq!(
        evaluate(&config(), Some("Bearer wrong")),
        AuthDecision::DenyInvalid
    );
}

#[test]
fn wrong_scheme_denies_invalid() {
    assert_eq!(
        evaluate(&config(), Some("Basic c2VjcmV0")),
        AuthDecision::DenyInvalid
    );
}

#[test]
fn bare_token_without_scheme_denies_when_scheme_required() {
    // With `scheme` configured, the raw token without the scheme
    // prefix must not pass.
    assert_eq!(
        evaluate(&config(), Some("s3cr3t")),
        AuthDecision::DenyInvalid
    );
}

#[test]
fn scheme_match_is_case_insensitive_rfc7235() {
    assert_eq!(strip_scheme("bearer abc", "Bearer"), Some("abc"));
    assert_eq!(strip_scheme("BEARER abc", "Bearer"), Some("abc"));
}

#[test]
fn scheme_missing_or_empty_rest_is_rejected() {
    assert_eq!(strip_scheme("abc", "Bearer"), None);
    assert_eq!(strip_scheme("Bearer", "Bearer"), None);
    assert_eq!(strip_scheme("Bearer ", "Bearer"), None);
}

#[test]
fn scheme_config_is_optional() {
    let bare = AuthConfig::parse(br#"{"header":"x-api-key","token":"tok"}"#)
        .expect("scheme-less config parses");
    assert_eq!(bare.scheme, None);
    assert_eq!(evaluate(&bare, Some("tok")), AuthDecision::Allow);
    assert_eq!(
        evaluate(&bare, Some("Bearer tok")),
        AuthDecision::DenyInvalid
    );
}

#[test]
fn config_requires_header_and_token() {
    assert!(AuthConfig::parse(br#"{"token":"t"}"#).is_err());
    assert!(AuthConfig::parse(br#"{"header":"h"}"#).is_err());
    assert!(AuthConfig::parse(b"").is_err());
    assert!(AuthConfig::parse(br#"{"header":"h","token":""}"#).is_err());
    assert!(AuthConfig::parse(br#"{"header":"h","scheme":42,"token":"t"}"#).is_err());
}

#[test]
fn constant_time_eq_basics() {
    assert!(constant_time_eq(b"abc", b"abc"));
    assert!(!constant_time_eq(b"abc", b"abd"));
    assert!(!constant_time_eq(b"abc", b"ab"));
    assert!(!constant_time_eq(b"", b"a"));
    assert!(constant_time_eq(b"", b""));
}

#[test]
fn constant_time_eq_prefix_hardening() {
    // A comparison that stops at the first differing byte (==) would
    // also return false here; this pins that the fold covers the full
    // tail, not just the prefix.
    assert!(!constant_time_eq(b"prefix-aaaa", b"prefix-bbbb"));
    assert!(!constant_time_eq(b"aaaaaaaaaaaaaaaa", b"aaaaaaaaaaaaaaab"));
}

#[test]
fn constant_time_eq_length_fold_is_not_truncated() {
    // Length differences that are multiples of 256 must not compare
    // equal: a u8 width for the length fold would zero (0 ^ 256) as
    // u8 and an all-zero body would then "match" the empty input.
    assert!(!constant_time_eq(b"", &[0u8; 256]));
    assert!(!constant_time_eq(&[b'x'; 256], b""));
    assert!(!constant_time_eq(&[b'x'; 300], &[b'x'; 44]));
}
"##,
            ),
        ],
        cargo_toml: r#"[package]
name = "static-auth"
version = "0.1.0"
edition = "2021"
description = "dwara proxy-wasm plugin (scaffolded from an example): short-circuit 401 for missing or wrong tokens"
license = "Apache-2.0"
publish = false

# A proxy-wasm plugin is a wasm cdylib: the artifact the gateway loads
# is target/wasm32-wasip1/release/static_auth.wasm. The extra "rlib"
# is not part of that artifact; it exists so `cargo test` on the host
# can link the crate and drive its callbacks (tests/logic.rs,
# tests/callbacks.rs). No dependencies: src/abi.rs binds the
# proxy-wasm host imports directly.
[lib]
crate-type = ["cdylib", "rlib"]

[profile.release]
opt-level = "s"
lto = true
strip = true
"#,
        readme: r#"# static-auth

Gate a route behind a configured token. Requests presenting the
configured token in the configured header are forwarded; everything
else is answered `401` with a `WWW-Authenticate: Bearer realm="dwara"`
challenge by the plugin itself (`proxy_send_http_response`) and the
upstream is never dialed. Token comparison is constant-time.

| Request | Result |
|---|---|
| no `authorization` header | `401` + challenge, body `missing credential` |
| `authorization: Basic ...` | `401` + challenge |
| `authorization: Bearer wrong` | `401` + challenge, body `invalid credential` |
| `authorization: Bearer dwara-example-token` | forwarded to the upstream |

## Gateway config

The scaffold's `dwara.yaml` wires the plugin into a minimal gateway
(the plugin entry it ships with):

```yaml
plugins:
  - name: static-auth
    wasm: target/wasm32-wasip1/release/static_auth.wasm
    phases:
      - request_headers
    config: '{"header":"authorization","scheme":"Bearer","token":"dwara-example-token"}'
```

`config` is handed to the plugin's `proxy_on_configure` as raw bytes
and parsed as flat JSON: `header` and `token` are required; `scheme`
is optional (`"Bearer"` yields the standard `Bearer <token>` shape,
matched ASCII case-insensitively per RFC 7235; without it the raw
header value is compared). A missing or unparsable config fails
closed: the plugin refuses to activate and the gateway answers `500
plugin_unavailable` for the route instead of running unauthenticated.

This is a demonstration plugin: a static token in config is
appropriate for demos and internal edges. For real deployments prefer
the gateway's built-in authentication (API keys, OIDC, mTLS) and use
a plugin for custom schemes only.

## Build

```sh
rustup target add wasm32-wasip1   # once, idempotent
cargo build --release --target wasm32-wasip1
```

The gateway loads `target/wasm32-wasip1/release/static_auth.wasm`.

## Run

The included `dwara.yaml` is a complete, valid gateway config (verify
with `dwara-cli validate dwara.yaml`). The gateway listens on
`127.0.0.1:8080` and forwards `/api` requests to `127.0.0.1:9000`:

```sh
DWARA_CONFIG=dwara.yaml dwara
```

## Test

```sh
# Plain-Rust unit tests (no gateway, no wasm). Includes
# tests/callbacks.rs, which drives the real proxy_on_* exports
# against the fake host from src/abi.rs.
cargo test
```

For integration through a real gateway (including the fail-closed
cases that deserve their own assertions), see the plugin testing
guide:
https://shristilabs.github.io/dwara/guide/plugin-testing

## Notes

- Phase contract: `request_headers` only (after route resolution,
  before authn).
- Layout: `src/lib.rs` is the plugin (RootContext holds the parsed
  config; the `proxy_on_*` exports are thin shims around the pure
  `evaluate`/`constant_time_eq`), `src/abi.rs` is the copyable
  proxy-wasm binding layer, `src/json.rs` the flat-JSON config
  reader.

Scaffolded from an example in the dwara plugin gallery with
`dwara-cli plugin new --template`.
"#,
        dwara_yaml: r#"# A minimal gateway config that loads the plugin. It validates
# as generated: `dwara-cli validate dwara.yaml` passes before the
# .wasm exists (validation does not check file existence).
listeners:
  - name: http
    address: 127.0.0.1
    port: 8080
    protocol: http

routes:
  - name: api
    service: backend
    match:
      path:
        type: prefix
        value: /api
    action:
      type: proxy
    plugins:
      - static-auth

services:
  - name: backend
    upstream: backend-upstream

upstreams:
  - name: backend-upstream
    load_balancer: round_robin
    protocol: http1
    endpoints:
      - address: 127.0.0.1
        port: 9000

plugins:
  - name: static-auth
    wasm: target/wasm32-wasip1/release/static_auth.wasm
    phases:
      - request_headers
    config: '{"header":"authorization","scheme":"Bearer","token":"dwara-example-token"}'
"#,
        json: true,
    },
    Template {
        name: "header-guard",
        summary: "allow or deny requests by a header value",
        lib_rs: r#"//! header-guard: allow or deny a request by the value of one header.
//!
//! The simplest access-control plugin: the route only passes when the
//! request carries a configured header with a configured value; every
//! other request is answered `403` by the plugin itself via
//! `proxy_send_http_response` (the upstream is never dialed).
//!
//! Phase contract: `request_headers` only (after route resolution,
//! before authn).
//!
//! Config (the `config:` string on the plugin entry, parsed at
//! `proxy_on_configure`):
//!
//! ```json
//! {"header": "x-guard-key", "value": "open-sesame"}
//! ```
//!
//! Fail-closed semantics: a config that is missing, empty, or
//! unparsable makes `proxy_on_configure` return false, which the
//! gateway treats as a broken plugin (routes referencing it answer
//! 500 `plugin_unavailable`) rather than a guard that silently lets
//! everything through.
//!
//! Structure: [`RootContext`] holds the parsed config (the
//! RootContext role), the `proxy_on_*` exports are thin shims, and
//! [`evaluate`] is the pure decision the unit tests exercise. See
//! `tests/logic.rs` and the plugin testing guide.

pub mod abi;
mod json;

use std::sync::Mutex;

/// The `RootContext` role: state parsed once per instance from the
/// plugin configuration at `proxy_on_configure`. dwara instantiates a
/// fresh plugin instance per request, so this is per-request state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootContext {
    config: GuardConfig,
}

/// The parsed plugin configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardConfig {
    /// The header whose value gates the request (matched
    /// case-insensitively by the host).
    pub header: String,
    /// The exact value that allows the request.
    pub value: String,
}

impl GuardConfig {
    /// Parse the plugin config bytes (a flat JSON object; see
    /// `json.rs`). `header` and `value` are both required and must be
    /// non-empty.
    pub fn parse(bytes: &[u8]) -> Result<GuardConfig, String> {
        let fields = json::parse_flat_object(bytes)?;
        let get = |key: &str| -> Result<String, String> {
            fields
                .iter()
                .find(|(k, _)| k == key)
                .and_then(|(_, v)| v.as_str().map(str::to_string))
                .filter(|v| !v.is_empty())
                .ok_or_else(|| format!("missing or empty string field \"{key}\""))
        };
        Ok(GuardConfig {
            header: get("header")?,
            value: get("value")?,
        })
    }
}

/// The decision for one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The header matched: forward the request.
    Allow,
    /// Missing or wrong value: the plugin answers 403 itself.
    Deny,
}

/// The pure decision function (unit-tested in `tests/logic.rs`).
pub fn evaluate(config: &GuardConfig, presented: Option<&str>) -> Verdict {
    match presented {
        Some(value) if !value.is_empty() && value == config.value => Verdict::Allow,
        _ => Verdict::Deny,
    }
}

/// The 403 body the plugin answers a denied request with.
pub const DENY_BODY: &[u8] = b"{\"error\":\"forbidden by header-guard\"}\n";

/// Per-instance root state. A fresh plugin instance (with fresh
/// statics) is created for every request, so no state leaks between
/// requests.
static ROOT: Mutex<Option<RootContext>> = Mutex::new(None);

/// Clear per-instance state (host-side callback tests).
#[cfg(not(target_family = "wasm"))]
pub fn test_reset() {
    *ROOT.lock().unwrap() = None;
    abi::fake::reset();
}

#[no_mangle]
/// `proxy_on_vm_start`: nothing to do at VM start; success.
pub extern "C" fn proxy_on_vm_start(_context_id: i32, _vm_config_size: i32) -> i32 {
    1
}

#[no_mangle]
/// `proxy_on_configure`: parse the plugin config bytes. Returning 0
/// marks the plugin broken (fail-closed) instead of running unguarded.
pub extern "C" fn proxy_on_configure(_context_id: i32, plugin_config_size: i32) -> i32 {
    let bytes = abi::get_buffer(abi::BUFFER_PLUGIN_CONFIGURATION, 0, plugin_config_size)
        .unwrap_or_default();
    match GuardConfig::parse(&bytes) {
        Ok(config) => {
            *ROOT.lock().unwrap() = Some(RootContext { config });
            1
        }
        Err(error) => {
            abi::log_info(&format!("header-guard: invalid config: {error}"));
            0
        }
    }
}

#[no_mangle]
/// `proxy_on_request_headers` (the only declared phase): allow or
/// deny by the configured header.
pub extern "C" fn proxy_on_request_headers(
    _context_id: i32,
    _num_headers: i32,
    _end_of_stream: i32,
) -> i32 {
    let guard = ROOT.lock().unwrap();
    let Some(root) = guard.as_ref() else {
        // Unreachable when configure succeeded; deny if it ever happens.
        abi::send_http_response(403, &[("x-plugin-name", "header-guard")], DENY_BODY);
        return abi::ACTION_END_STREAM;
    };
    let presented = abi::get_request_header(&root.config.header);
    match evaluate(&root.config, presented.as_deref()) {
        Verdict::Allow => abi::ACTION_CONTINUE,
        Verdict::Deny => {
            abi::send_http_response(403, &[("x-plugin-name", "header-guard")], DENY_BODY);
            abi::ACTION_END_STREAM
        }
    }
}
"#,
        tests: &[(
            "logic.rs",
            r##"//! Plain-Rust unit tests for header-guard's callback logic.
//!
//! These run on the development machine (`cargo test`): the pure
//! decision function and the config parser need neither wasm nor a
//! gateway. See the plugin testing guide (level 1).

use header_guard::{evaluate, GuardConfig, Verdict};

fn config() -> GuardConfig {
    GuardConfig::parse(br#"{"header":"x-guard-key","value":"open-sesame"}"#)
        .expect("valid config parses")
}

#[test]
fn matching_value_allows() {
    assert_eq!(evaluate(&config(), Some("open-sesame")), Verdict::Allow);
}

#[test]
fn missing_header_denies() {
    assert_eq!(evaluate(&config(), None), Verdict::Deny);
}

#[test]
fn wrong_value_denies() {
    assert_eq!(evaluate(&config(), Some("close-sesame")), Verdict::Deny);
}

#[test]
fn empty_value_denies() {
    // An empty header value must never match, even if the configured
    // value were somehow empty.
    assert_eq!(evaluate(&config(), Some("")), Verdict::Deny);
}

#[test]
fn value_must_match_exactly() {
    // No prefix, suffix, or case tolerance: the guard is exact.
    assert_eq!(evaluate(&config(), Some("open-sesame ")), Verdict::Deny);
    assert_eq!(evaluate(&config(), Some("Open-Sesame")), Verdict::Deny);
    assert_eq!(evaluate(&config(), Some("open")), Verdict::Deny);
}

#[test]
fn config_requires_both_fields() {
    assert!(GuardConfig::parse(br#"{"header":"x"}"#).is_err());
    assert!(GuardConfig::parse(br#"{"value":"y"}"#).is_err());
    assert!(GuardConfig::parse(b"").is_err());
    assert!(GuardConfig::parse(br#"{"header":"x","value":""}"#).is_err());
}

#[test]
fn config_rejects_malformed_json() {
    // Fail closed at configure time, not per request.
    assert!(GuardConfig::parse(b"not json").is_err());
    assert!(GuardConfig::parse(br#"{"header": 42}"#).is_err());
    assert!(GuardConfig::parse(br#"{"header":"x","value":"v",}"#).is_err());
}

#[test]
fn config_accepts_whitespace_and_escapes() {
    let parsed = GuardConfig::parse(b"{ \"header\" : \"x-guard-key\" , \"value\" : \"a\\\"b\" }")
        .expect("whitespace and escapes parse");
    assert_eq!(parsed.value, "a\"b");
}
"##,
        )],
        cargo_toml: r#"[package]
name = "header-guard"
version = "0.1.0"
edition = "2021"
description = "dwara proxy-wasm plugin (scaffolded from an example): allow or deny requests by a header value"
license = "Apache-2.0"
publish = false

# A proxy-wasm plugin is a wasm cdylib: the artifact the gateway loads
# is target/wasm32-wasip1/release/header_guard.wasm. The extra "rlib"
# is not part of that artifact; it exists so `cargo test` on the host
# can link the crate and drive its callbacks (tests/logic.rs). No
# dependencies: src/abi.rs binds the proxy-wasm host imports directly.
[lib]
crate-type = ["cdylib", "rlib"]

[profile.release]
opt-level = "s"
lto = true
strip = true
"#,
        readme: r#"# header-guard

Allow or deny requests by the value of one header. The simplest
access-control plugin: requests carrying the configured header with
the configured value are forwarded; everything else is answered `403`
by the plugin itself (`proxy_send_http_response`) and the upstream is
never dialed.

| Request | Result |
|---|---|
| no `x-guard-key` header | `403` `{"error":"forbidden by header-guard"}` |
| `x-guard-key: wrong` | `403` |
| `x-guard-key: open-sesame` | forwarded to the upstream |

## Gateway config

The scaffold's `dwara.yaml` wires the plugin into a minimal gateway
(the plugin entry it ships with):

```yaml
plugins:
  - name: header-guard
    wasm: target/wasm32-wasip1/release/header_guard.wasm
    phases:
      - request_headers
    config: '{"header":"x-guard-key","value":"open-sesame"}'
```

`config` is handed to the plugin's `proxy_on_configure` as raw bytes
and parsed as flat JSON (`{"header": ..., "value": ...}`, both
required). A missing or unparsable config fails closed: the plugin
refuses to activate and the gateway answers `500 plugin_unavailable`
for the route instead of unguarded traffic.

## Build

```sh
rustup target add wasm32-wasip1   # once, idempotent
cargo build --release --target wasm32-wasip1
```

The gateway loads `target/wasm32-wasip1/release/header_guard.wasm`.

## Run

The included `dwara.yaml` is a complete, valid gateway config (verify
with `dwara-cli validate dwara.yaml`). The gateway listens on
`127.0.0.1:8080` and forwards `/api` requests to `127.0.0.1:9000`:

```sh
DWARA_CONFIG=dwara.yaml dwara
```

## Test

```sh
# Plain-Rust unit tests for the guard's decision logic (no gateway,
# no wasm).
cargo test
```

For integration through a real gateway (including the fail-closed
cases that deserve their own assertions), see the plugin testing
guide:
https://shristilabs.github.io/dwara/guide/plugin-testing

## Notes

- Phase contract: `request_headers` only (after route resolution,
  before authn).
- The header name is matched case-insensitively by the host; the
  value must match exactly.
- Layout: `src/lib.rs` is the plugin (RootContext holds the parsed
  config; the `proxy_on_*` exports are thin shims around the pure
  `evaluate`), `src/abi.rs` is the copyable proxy-wasm binding layer,
  `src/json.rs` the flat-JSON config reader.

Scaffolded from an example in the dwara plugin gallery with
`dwara-cli plugin new --template`.
"#,
        dwara_yaml: r#"# A minimal gateway config that loads the plugin. It validates
# as generated: `dwara-cli validate dwara.yaml` passes before the
# .wasm exists (validation does not check file existence).
listeners:
  - name: http
    address: 127.0.0.1
    port: 8080
    protocol: http

routes:
  - name: api
    service: backend
    match:
      path:
        type: prefix
        value: /api
    action:
      type: proxy
    plugins:
      - header-guard

services:
  - name: backend
    upstream: backend-upstream

upstreams:
  - name: backend-upstream
    load_balancer: round_robin
    protocol: http1
    endpoints:
      - address: 127.0.0.1
        port: 9000

plugins:
  - name: header-guard
    wasm: target/wasm32-wasip1/release/header_guard.wasm
    phases:
      - request_headers
    config: '{"header":"x-guard-key","value":"open-sesame"}'
"#,
        json: true,
    },
    Template {
        name: "response-body-redact",
        summary: "redact card numbers and secrets from response bodies",
        lib_rs: r#"//! response-body-redact: scrub sensitive patterns from response
//! bodies before they reach the client.
//!
//! Two pattern classes, both length-preserving (a masked body has the
//! same byte length as the original, so framing never shifts):
//!
//! - payment card numbers: a run of 13-19 digits (single `-` or ` `
//! separators between groups allowed) that passes the Luhn checksum.
//! Every digit except the last four becomes `*`; separators are kept
//! (`4111-1111-1111-1111` -> `****-****-****-1111`). The checksum
//! gate keeps ordinary 16-digit ids (order numbers, tracking codes)
//! readable.
//! - configured literals: each occurrence of a configured string is
//! replaced with `*` repeated (an API key like `sk-live-12345`
//! becomes `************`).
//!
//! Phase contract: `response_body` only. The phase applies to
//! buffered, non-encoded response bodies: dwara buffers the body for
//! the phase when the route has a `response_body` plugin (capped by
//! the route's `limits.max_body_bytes`, default 1 MiB), and skips the
//! phase for streaming bodies (`text/event-stream`, un-framed) and
//! content-encoded bodies -- those stream through untouched. The
//! gateway rewrites `Content-Length` when the plugin changes the
//! body.
//!
//! Config (the `config:` string on the plugin entry, parsed at
//! `proxy_on_configure`); `literals` is optional, card masking is
//! always on:
//!
//! ```json
//! {"literals": ["sk-live-12345"]}
//! ```
//!
//! Fail-closed semantics: an unparsable config makes
//! `proxy_on_configure` return false (routes answer 500
//! `plugin_unavailable`) rather than serving unredacted bytes.
//!
//! Structure: [`RootContext`] holds the parsed config, the
//! `proxy_on_*` exports are thin shims, and [`redact`] /
//! [`mask_card_numbers`] / [`luhn_valid`] are the pure logic the unit
//! tests exercise (see `tests/logic.rs` and `tests/callbacks.rs`).

pub mod abi;
mod json;

use std::sync::Mutex;

/// The `RootContext` role: state parsed from the plugin configuration
/// at `proxy_on_configure`. dwara instantiates a fresh plugin
/// instance per request, so this is per-request state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootContext {
    config: RedactConfig,
}

/// The parsed plugin configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedactConfig {
    /// Literal strings to replace with same-length star masks.
    pub literals: Vec<String>,
}

impl RedactConfig {
    /// Parse the plugin config bytes (a flat JSON object; see
    /// `json.rs`). `literals` is optional (absent means none); when
    /// present it must be an array of strings. A mistyped value
    /// errors (fail closed) instead of silently disabling redaction.
    pub fn parse(bytes: &[u8]) -> Result<RedactConfig, String> {
        let fields = json::parse_flat_object(bytes)?;
        let literals = match fields.iter().find(|(k, _)| k == "literals") {
            None => Vec::new(),
            Some((_, value)) => {
                let items = value
                    .as_arr()
                    .ok_or_else(|| "field \"literals\" must be an array of strings".to_string())?;
                items
                    .iter()
                    .filter(|s| !s.is_empty())
                    .cloned()
                    .collect::<Vec<_>>()
            }
        };
        Ok(RedactConfig { literals })
    }
}

/// How many trailing card digits stay visible.
const KEEP_LAST: usize = 4;

/// The pure redaction pass (unit-tested in `tests/logic.rs`):
/// configured literals first, then card masking. Returns the redacted
/// bytes; the input is returned unchanged when nothing matched.
pub fn redact(body: &[u8], config: &RedactConfig) -> Vec<u8> {
    let mut out = body.to_vec();
    for literal in &config.literals {
        replace_literal(&mut out, literal.as_bytes());
    }
    mask_card_numbers(&mut out);
    out
}

/// Replace every non-overlapping occurrence of `literal` with `*`
/// repeated to the same length (length-preserving).
pub fn replace_literal(body: &mut Vec<u8>, literal: &[u8]) {
    if literal.is_empty() || body.len() < literal.len() {
        return;
    }
    let mut i = 0;
    while i + literal.len() <= body.len() {
        if &body[i..i + literal.len()] == literal {
            for byte in &mut body[i..i + literal.len()] {
                *byte = b'*';
            }
            i += literal.len();
        } else {
            i += 1;
        }
    }
}

/// Mask Luhn-valid 13-19 digit runs (single `-`/` ` separators between
/// groups allowed), keeping the last four digits. Runs are treated
/// whole: a run that is too long, too short, or checksum-invalid
/// passes through untouched (no partial suffix matching).
pub fn mask_card_numbers(body: &mut Vec<u8>) {
    let len = body.len();
    let mut i = 0;
    while i < len {
        if !body[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        // Extend a candidate: digits, optionally one separator
        // between groups when another digit follows.
        let mut digit_positions: Vec<usize> = Vec::new();
        let mut digits: Vec<u8> = Vec::new();
        let mut j = i;
        while j < len && body[j].is_ascii_digit() {
            digit_positions.push(j);
            digits.push(body[j]);
            j += 1;
            if j < len
                && (body[j] == b'-' || body[j] == b' ')
                && j + 1 < len
                && body[j + 1].is_ascii_digit()
            {
                j += 1;
            }
        }
        if (13..=19).contains(&digits.len()) && luhn_valid(&digits) {
            let keep_from = digits.len() - KEEP_LAST;
            for (index, &pos) in digit_positions.iter().enumerate() {
                if index < keep_from {
                    body[pos] = b'*';
                }
            }
        }
        // Consume the whole run either way (masked or passed through).
        i = j;
    }
}

/// The Luhn checksum (ISO/IEC 7812-1): every second digit from the
/// right is doubled (9 subtracted on overflow) and the sum must be a
/// multiple of ten. Total over arbitrary bytes: a non-digit input is
/// not a card number and returns false (the scanner only feeds this
/// ASCII digits, but the function must not rely on that).
pub fn luhn_valid(digits: &[u8]) -> bool {
    let mut sum: u32 = 0;
    for (offset, digit) in digits.iter().rev().enumerate() {
        if !digit.is_ascii_digit() {
            return false;
        }
        let mut value = u32::from(digit - b'0');
        if offset % 2 == 1 {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
    }
    sum % 10 == 0
}

/// Per-instance root state (fresh statics per request: dwara
/// instantiates a new plugin instance per request).
static ROOT: Mutex<Option<RootContext>> = Mutex::new(None);

/// Clear per-instance state (host-side callback tests).
#[cfg(not(target_family = "wasm"))]
pub fn test_reset() {
    *ROOT.lock().unwrap() = None;
    abi::fake::reset();
}

#[no_mangle]
/// `proxy_on_vm_start`: nothing to do at VM start; success.
pub extern "C" fn proxy_on_vm_start(_context_id: i32, _vm_config_size: i32) -> i32 {
    1
}

#[no_mangle]
/// `proxy_on_configure`: parse the plugin config bytes. Returning 0
/// marks the plugin broken (fail-closed) rather than serving
/// unredacted bytes from a misunderstood config.
pub extern "C" fn proxy_on_configure(_context_id: i32, plugin_config_size: i32) -> i32 {
    let bytes = abi::get_buffer(abi::BUFFER_PLUGIN_CONFIGURATION, 0, plugin_config_size)
        .unwrap_or_default();
    match RedactConfig::parse(&bytes) {
        Ok(config) => {
            *ROOT.lock().unwrap() = Some(RootContext { config });
            1
        }
        Err(error) => {
            abi::log_info(&format!("response-body-redact: invalid config: {error}"));
            0
        }
    }
}

#[no_mangle]
/// `proxy_on_response_body` (the only declared phase): redact the
/// buffered body and write it back when anything changed.
pub extern "C" fn proxy_on_response_body(
    _context_id: i32,
    body_size: i32,
    _end_of_stream: i32,
) -> i32 {
    let config = ROOT
        .lock()
        .unwrap()
        .as_ref()
        .map(|root| root.config.clone())
        .unwrap_or_default();
    let Some(body) = abi::get_buffer(abi::BUFFER_RESPONSE_BODY, 0, body_size) else {
        return abi::ACTION_CONTINUE;
    };
    let redacted = redact(&body, &config);
    if redacted != body {
        abi::set_buffer(abi::BUFFER_RESPONSE_BODY, 0, &redacted);
    }
    abi::ACTION_CONTINUE
}
"#,
        tests: &[
            (
                "callbacks.rs",
                r##"//! Callback-level unit tests: drive the real `proxy_on_*` exports.
//!
//! Same pattern as `static-auth`'s `tests/callbacks.rs`: `src/abi.rs`
//! compiles a fake host on non-wasm targets, so `cargo test` on the
//! development machine runs the actual proxy-wasm entrypoints. This
//! file pins the shim wiring (config -> root state -> buffer read ->
//! redact -> buffer write), not the redaction math (`tests/logic.rs`
//! does that).
//!
//! The scenarios run sequentially in one test (the one-test rule):
//! the per-instance root state is a process-wide static (mirroring
//! the wasm module's linear-memory static), so one scenario's
//! `test_reset()` between another scenario's `configure` and
//! `response_body` would race and flake if the scenarios ran as
//! parallel `#[test]` fns.

use response_body_redact::{
    abi::{fake, ACTION_CONTINUE},
    proxy_on_configure, proxy_on_response_body, proxy_on_vm_start, test_reset,
};

const CONFIG: &[u8] = br#"{"literals":["sk-live-12345"]}"#;

#[test]
fn callback_scenarios() {
    redacted_body_is_written_back();
    unchanged_body_is_not_written_back();
    malformed_config_refuses_to_activate();
}

fn redacted_body_is_written_back() {
    test_reset();
    fake::set_config(CONFIG);
    assert_eq!(proxy_on_vm_start(1, 0), 1);
    assert_eq!(proxy_on_configure(1, CONFIG.len() as i32), 1);

    let body = b"{\"card\":\"4111-1111-1111-1111\",\"key\":\"sk-live-12345\"}";
    fake::set_response_body(body);
    assert_eq!(
        proxy_on_response_body(2, body.len() as i32, 1),
        ACTION_CONTINUE
    );

    let written = fake::take_set_response_body().expect("changed body must be written back");
    let text = String::from_utf8(written).expect("body stays UTF-8");
    assert!(text.contains("****-****-****-1111"), "card masked: {text}");
    assert!(text.contains("************"), "literal starred: {text}");
    assert_eq!(text.len(), body.len(), "masking preserves length");
}

fn unchanged_body_is_not_written_back() {
    test_reset();
    fake::set_config(CONFIG);
    assert_eq!(proxy_on_configure(1, CONFIG.len() as i32), 1);

    let body = b"{\"message\":\"nothing sensitive here\"}";
    fake::set_response_body(body);
    assert_eq!(
        proxy_on_response_body(2, body.len() as i32, 1),
        ACTION_CONTINUE
    );
    assert!(
        fake::take_set_response_body().is_none(),
        "an unchanged body must not trigger a write"
    );
}

fn malformed_config_refuses_to_activate() {
    test_reset();
    fake::set_config(b"{oops");
    assert_eq!(
        proxy_on_configure(1, 6),
        0,
        "unparsable config fails closed"
    );
}
"##,
            ),
            (
                "logic.rs",
                r##"//! Plain-Rust unit tests for the redaction logic.
//!
//! These run on the development machine (`cargo test`): the scanner,
//! the checksum gate, and the literal replacement need neither wasm
//! nor a gateway. See the plugin testing guide (level 1).

use response_body_redact::{luhn_valid, mask_card_numbers, redact, replace_literal, RedactConfig};

fn redact_with(body: &str, literals: &[&str]) -> String {
    let config = RedactConfig {
        literals: literals.iter().map(|s| s.to_string()).collect(),
    };
    String::from_utf8(redact(body.as_bytes(), &config)).expect("redaction keeps UTF-8")
}

#[test]
fn luhn_reference_vectors() {
    // The two classic test numbers, plus a corrupted last digit.
    assert!(luhn_valid(b"4111111111111111"));
    assert!(luhn_valid(b"5555555555554444"));
    assert!(!luhn_valid(b"4111111111111112"));
    assert!(!luhn_valid(b"1234567812345678"));
}

#[test]
fn luhn_is_total_over_non_digits() {
    // Non-digit bytes must answer false, not panic (the function is
    // public; the scanner cannot be its only caller forever).
    assert!(!luhn_valid(b"411111111111111x"));
    assert!(!luhn_valid(b"abcdefgh"));
}

#[test]
fn dashed_card_is_masked_keep_last_four() {
    let masked = redact_with("card 4111-1111-1111-1111 on file", &[]);
    assert_eq!(masked, "card ****-****-****-1111 on file");
}

#[test]
fn spaced_card_is_masked_keep_separators() {
    let masked = redact_with("card 5555 5555 5555 4444 on file", &[]);
    assert_eq!(masked, "card **** **** **** 4444 on file");
}

#[test]
fn invalid_checksum_is_left_alone() {
    // A 16-digit id that is not a card number stays readable.
    let masked = redact_with("order 1234567812345678 shipped", &[]);
    assert_eq!(masked, "order 1234567812345678 shipped");
}

#[test]
fn too_short_and_too_long_runs_are_left_alone() {
    assert_eq!(redact_with("call 415-555-2671", &[]), "call 415-555-2671");
    assert_eq!(
        redact_with("ref 41111111111111111111", &[]),
        "ref 41111111111111111111",
    );
}

#[test]
fn literals_are_starred_same_length() {
    // "sk-live-12345" is 13 bytes; the mask is 13 stars.
    let masked = redact_with("key sk-live-12345 here", &["sk-live-12345"]);
    assert_eq!(masked, "key ************* here");
}

#[test]
fn overlapping_literal_matches_are_non_overlapping() {
    let mut body = b"ababab".to_vec();
    replace_literal(&mut body, b"abab");
    assert_eq!(body, b"****ab");
}

#[test]
fn config_parses_literals_and_defaults() {
    let parsed = RedactConfig::parse(br#"{"literals":["a","b"]}"#).expect("parses");
    assert_eq!(parsed.literals, vec!["a".to_string(), "b".to_string()]);
    let empty = RedactConfig::parse(b"{}").expect("empty object parses");
    assert!(empty.literals.is_empty());
    assert!(RedactConfig::parse(b"").is_err());
    assert!(RedactConfig::parse(br#"{"literals":"not-an-array"}"#).is_err());
    assert!(RedactConfig::parse(br#"{"literals":[123]}"#).is_err());
}

#[test]
fn masking_is_length_preserving_and_idempotent() {
    let original = "a 4111-1111-1111-1111 b sk-live-12345";
    let config = RedactConfig {
        literals: vec!["sk-live-12345".to_string()],
    };
    let once = redact(original.as_bytes(), &config);
    assert_eq!(once.len(), original.len(), "masking preserves length");
    let twice = redact(&once, &config);
    assert_eq!(twice, once, "masked text is stable");
}

#[test]
fn card_adjacent_letters_still_mask_the_run() {
    // The scanner sees digit runs, not word boundaries.
    let mut body = b"id=4111111111111111;".to_vec();
    mask_card_numbers(&mut body);
    assert_eq!(&body, b"id=************1111;");
}

#[test]
fn non_ascii_body_survives() {
    let masked = redact_with("naïve 4111-1111-1111-1111 ✓", &[]);
    assert_eq!(masked, "naïve ****-****-****-1111 ✓");
}
"##,
            ),
        ],
        cargo_toml: r#"[package]
name = "response-body-redact"
version = "0.1.0"
edition = "2021"
description = "dwara proxy-wasm plugin (scaffolded from an example): redact card numbers and secrets from response bodies"
license = "Apache-2.0"
publish = false

# A proxy-wasm plugin is a wasm cdylib: the artifact the gateway loads
# is target/wasm32-wasip1/release/response_body_redact.wasm. The extra
# "rlib" is not part of that artifact; it exists so `cargo test` on
# the host can link the crate and drive its callbacks (tests/logic.rs,
# tests/callbacks.rs). No dependencies: src/abi.rs binds the
# proxy-wasm host imports directly.
[lib]
crate-type = ["cdylib", "rlib"]

[profile.release]
opt-level = "s"
lto = true
strip = true
"#,
        readme: r#"# response-body-redact

Scrub sensitive patterns from response bodies before they reach the
client. Two pattern classes, both length-preserving so framing never
shifts:

- **Card numbers**: a run of 13-19 digits (single `-` or ` `
  separators between groups allowed) that passes the Luhn checksum is
  masked to `*` except the last four digits, separators kept:
  `4111-1111-1111-1111` becomes `****-****-****-1111`. The checksum
  gate keeps ordinary 16-digit ids (order numbers, tracking codes)
  readable.
- **Configured literals**: each occurrence of a configured string is
  replaced with `*` repeated to the same length
  (`sk-live-12345` becomes `*************`).

Card masking is always on; `literals` is optional.

| Response body contains | Client sees |
|---|---|
| `4111-1111-1111-1111` | `****-****-****-1111` |
| `5555 5555 5555 4444` | `**** **** **** 4444` |
| `1234567812345678` (invalid checksum) | unchanged |
| `sk-live-12345` (configured literal) | `*************` |

## Gateway config

The scaffold's `dwara.yaml` wires the plugin into a minimal gateway
(the plugin entry it ships with):

```yaml
plugins:
  - name: response-body-redact
    wasm: target/wasm32-wasip1/release/response_body_redact.wasm
    phases:
      - response_body
    config: '{"literals":["sk-live-12345"]}'
```

`config` is handed to the plugin's `proxy_on_configure` as raw bytes
and parsed as flat JSON (`{"literals": [...]}`, an array of strings).
An unparsable config fails closed: the plugin refuses to activate and
the gateway answers `500 plugin_unavailable` for the route instead of
serving unredacted bytes.

## Build

```sh
rustup target add wasm32-wasip1   # once, idempotent
cargo build --release --target wasm32-wasip1
```

The gateway loads `target/wasm32-wasip1/release/response_body_redact.wasm`.

## Run

The included `dwara.yaml` is a complete, valid gateway config (verify
with `dwara-cli validate dwara.yaml`). The gateway listens on
`127.0.0.1:8080` and forwards `/api` requests to `127.0.0.1:9000`:

```sh
DWARA_CONFIG=dwara.yaml dwara
```

## Test

```sh
# Plain-Rust unit tests (no gateway, no wasm). Includes
# tests/callbacks.rs, which drives the real proxy_on_response_body
# export against the fake host from src/abi.rs.
cargo test
```

For integration through a real gateway (including the fail-closed
cases that deserve their own assertions), see the plugin testing
guide:
https://shristilabs.github.io/dwara/guide/plugin-testing

## Notes

- Phase contract: `response_body` only. The phase applies to
  **buffered, non-encoded** response bodies: dwara buffers the body
  for the phase (capped by the route's `limits.max_body_bytes`,
  default 1 MiB) and rewrites `Content-Length` when the plugin
  changes the bytes. Streaming bodies (`text/event-stream`, un-framed
  chunked) and content-encoded bodies skip the phase and stream
  through untouched.
- Layout: `src/lib.rs` is the plugin (RootContext holds the parsed
  config; the `proxy_on_response_body` export is a thin shim around
  the pure `redact`/`mask_card_numbers`/`luhn_valid`), `src/abi.rs`
  is the copyable proxy-wasm binding layer, `src/json.rs` the
  flat-JSON config reader.

Scaffolded from an example in the dwara plugin gallery with
`dwara-cli plugin new --template`.
"#,
        dwara_yaml: r#"# A minimal gateway config that loads the plugin. It validates
# as generated: `dwara-cli validate dwara.yaml` passes before the
# .wasm exists (validation does not check file existence).
listeners:
  - name: http
    address: 127.0.0.1
    port: 8080
    protocol: http

routes:
  - name: api
    service: backend
    match:
      path:
        type: prefix
        value: /api
    action:
      type: proxy
    plugins:
      - response-body-redact

services:
  - name: backend
    upstream: backend-upstream

upstreams:
  - name: backend-upstream
    load_balancer: round_robin
    protocol: http1
    endpoints:
      - address: 127.0.0.1
        port: 9000

plugins:
  - name: response-body-redact
    wasm: target/wasm32-wasip1/release/response_body_redact.wasm
    phases:
      - response_body
    config: '{"literals":["sk-live-12345"]}'
"#,
        json: true,
    },
    Template {
        name: "request-tagger",
        summary: "stamp x-plugin-* correlation headers on request and response",
        lib_rs: r#"//! request-tagger: stamp correlation headers on both directions.
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
"#,
        tests: &[(
            "callbacks.rs",
            r#"//! Unit and callback-level tests for request-tagger.
//!
//! Level 1 of the plugin testing guide: the pure correlation rule,
//! then the real `proxy_on_*` exports against the fake host from
//! `src/abi.rs` (`cargo test` on the development machine).
//!
//! The callback scenarios run sequentially in one test: the
//! per-instance HTTP context is a process-wide static (mirroring the
//! wasm module's linear-memory static), so scenarios must not
//! interleave.

use request_tagger::{
    abi::{fake, ACTION_CONTINUE},
    correlation_id, proxy_on_request_headers, proxy_on_response_headers, proxy_on_vm_start,
    test_reset, CORRELATION_HEADER, NAME_HEADER, PLUGIN_NAME, REQUEST_ID_HEADER,
};

#[test]
fn correlation_rule() {
    assert_eq!(correlation_id(Some("abc-123")), "abc-123");
    assert_eq!(correlation_id(Some("")), "unset");
    assert_eq!(correlation_id(None), "unset");
}

#[test]
fn callback_scenarios() {
    test_reset();
    assert_eq!(proxy_on_vm_start(1, 0), 1);

    // --- with an inbound request id: both directions carry it -----
    fake::set_request_headers(&[
        (":method", "GET"),
        (":path", "/v1/things"),
        (REQUEST_ID_HEADER, "req-42"),
    ]);
    assert_eq!(proxy_on_request_headers(2, 3, 1), ACTION_CONTINUE);
    let stamped = fake::take_added_request_headers();
    assert!(stamped.contains(&(NAME_HEADER.to_string(), PLUGIN_NAME.to_string())));
    assert!(
        stamped.contains(&(CORRELATION_HEADER.to_string(), "req-42".to_string())),
        "request stamps: {stamped:?}"
    );

    // Response phase: the SAME id is stamped on the response headers
    // (what the client would see).
    assert_eq!(proxy_on_response_headers(2, 1, 1), ACTION_CONTINUE);
    let stamped = fake::take_added_response_headers();
    assert!(stamped.contains(&(CORRELATION_HEADER.to_string(), "req-42".to_string())));
    assert!(
        fake::take_local_response().is_none(),
        "the tagger never answers for the request"
    );

    // --- without an inbound request id: the literal "unset" -------
    test_reset();
    fake::set_request_headers(&[(":method", "GET"), (":path", "/v1/things")]);
    assert_eq!(proxy_on_request_headers(2, 2, 1), ACTION_CONTINUE);
    assert_eq!(proxy_on_response_headers(2, 1, 1), ACTION_CONTINUE);
    let stamped = fake::take_added_response_headers();
    assert!(stamped.contains(&(CORRELATION_HEADER.to_string(), "unset".to_string())));
}
"#,
        )],
        cargo_toml: r#"[package]
name = "request-tagger"
version = "0.1.0"
edition = "2021"
description = "dwara proxy-wasm plugin (scaffolded from an example): stamp x-plugin-* correlation headers on request and response"
license = "Apache-2.0"
publish = false

# A proxy-wasm plugin is a wasm cdylib: the artifact the gateway loads
# is target/wasm32-wasip1/release/request_tagger.wasm. The extra
# "rlib" is not part of that artifact; it exists so `cargo test` on
# the host can link the crate and drive its callbacks. No
# dependencies: src/abi.rs binds the proxy-wasm host imports
# directly.
[lib]
crate-type = ["cdylib", "rlib"]

[profile.release]
opt-level = "s"
lto = true
strip = true
"#,
        readme: r#"# request-tagger

Stamp `x-plugin-*` correlation headers on both directions. At
`request_headers` the plugin reads the inbound `x-request-id` and
stamps `x-plugin-name` + `x-plugin-request-id` onto the request
(visible at the upstream); at `response_headers` it stamps the same
pair onto the response (visible at the client), echoing the request id
captured earlier. When the inbound request carries no `x-request-id`,
the value is the literal `unset`. No config.

| Direction | Header | Value |
|---|---|---|
| request | `x-plugin-name` | `request-tagger` |
| request | `x-plugin-request-id` | inbound `x-request-id`, or `unset` |
| response | `x-plugin-name` | `request-tagger` |
| response | `x-plugin-request-id` | the id captured at the request phase |

## Gateway config

The scaffold's `dwara.yaml` wires the plugin into a minimal gateway
(the plugin entry it ships with):

```yaml
plugins:
  - name: request-tagger
    wasm: target/wasm32-wasip1/release/request_tagger.wasm
    phases:
      - request_headers
      - response_headers
```

No config: `proxy_on_configure` is not exported (the gateway skips it
when absent); nothing to parse.

## Build

```sh
rustup target add wasm32-wasip1   # once, idempotent
cargo build --release --target wasm32-wasip1
```

The gateway loads `target/wasm32-wasip1/release/request_tagger.wasm`.

## Run

The included `dwara.yaml` is a complete, valid gateway config (verify
with `dwara-cli validate dwara.yaml`). The gateway listens on
`127.0.0.1:8080` and forwards `/api` requests to `127.0.0.1:9000`:

```sh
DWARA_CONFIG=dwara.yaml dwara
```

## Test

```sh
# Plain-Rust unit tests (no gateway, no wasm). Includes
# tests/callbacks.rs, which drives the real proxy_on_* exports
# against the fake host from src/abi.rs.
cargo test
```

For integration through a real gateway (including the fail-closed
cases that deserve their own assertions), see the plugin testing
guide:
https://shristilabs.github.io/dwara/guide/plugin-testing

## Notes

- Phase contract: `request_headers` and `response_headers`. Header
  phases apply diffs only: names the plugin never touched keep their
  original bytes downstream.
- Layout: `src/lib.rs` is the plugin (HttpContext holds the captured
  request id across the two phases; the `proxy_on_*` exports are thin
  shims), `src/abi.rs` is the copyable proxy-wasm binding layer.

Scaffolded from an example in the dwara plugin gallery with
`dwara-cli plugin new --template`.
"#,
        dwara_yaml: r#"# A minimal gateway config that loads the plugin. It validates
# as generated: `dwara-cli validate dwara.yaml` passes before the
# .wasm exists (validation does not check file existence).
listeners:
  - name: http
    address: 127.0.0.1
    port: 8080
    protocol: http

routes:
  - name: api
    service: backend
    match:
      path:
        type: prefix
        value: /api
    action:
      type: proxy
    plugins:
      - request-tagger

services:
  - name: backend
    upstream: backend-upstream

upstreams:
  - name: backend-upstream
    load_balancer: round_robin
    protocol: http1
    endpoints:
      - address: 127.0.0.1
        port: 9000

plugins:
  - name: request-tagger
    wasm: target/wasm32-wasip1/release/request_tagger.wasm
    phases:
      - request_headers
      - response_headers
"#,
        json: false,
    },
];

/// The available template names, in gallery order.
pub fn names() -> Vec<&'static str> {
    TEMPLATES.iter().map(|t| t.name).collect()
}

/// Look up a template by name. The error lists every available name
/// (the `plugin new` error surface for a typo'd `--template`).
pub fn find(name: &str) -> Result<&'static Template, String> {
    TEMPLATES.iter().find(|t| t.name == name).ok_or_else(|| {
        format!(
            "unknown template '{name}' (available: {})",
            names().join(", ")
        )
    })
}

/// Render every file of the scaffolded project as `(relative path,
/// contents)` pairs, with the target crate name substituted
/// throughout (see the module docs).
pub fn render_files(template: &Template, name: &str) -> Vec<(String, String)> {
    let under = name.replace('-', "_");
    // The template's own hyphenated and underscored names; every
    // occurrence refers to the crate itself, so replace both forms
    // globally. The underscored forms are replaced first so a
    // hypothetical name whose hyphen form is a substring of another
    // template's underscore form cannot interleave (none is today;
    // the order makes that structural, not accidental).
    let sub = |text: &str| -> String {
        let t = text.replace(&template.name.replace('-', "_"), &under);
        t.replace(template.name, name)
    };

    let mut files = vec![
        ("Cargo.toml".to_string(), sub(template.cargo_toml)),
        (".gitignore".to_string(), "/target\n".to_string()),
        ("README.md".to_string(), sub(template.readme)),
        ("dwara.yaml".to_string(), sub(template.dwara_yaml)),
        ("src/lib.rs".to_string(), sub(template.lib_rs)),
        ("src/abi.rs".to_string(), sub(ABI_RS)),
    ];
    if template.json {
        files.push(("src/json.rs".to_string(), sub(JSON_RS)));
    }
    for (file, contents) in template.tests {
        files.push((format!("tests/{file}"), sub(contents)));
    }
    files
}
