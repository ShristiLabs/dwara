//! header-guard: allow or deny a request by the value of one header.
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
