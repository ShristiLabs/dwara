//! static-auth: gate a route behind a configured bearer-style token.
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
