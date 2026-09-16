//! response-body-redact: scrub sensitive patterns from response
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
