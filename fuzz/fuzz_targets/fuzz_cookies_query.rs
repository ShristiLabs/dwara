//! Fuzz the router's cookie parsing and raw query matching (DW-025):
//! `parse_cookies` and `query_param_matches` over arbitrary strings,
//! with match patterns (name / optional value) also derived from the
//! fuzz input so the comparison paths are covered too.

#![no_main]

use dwara_core::config::NameValueMatch;
use dwara_core::proxy::{parse_cookies, query_param_matches};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let raw = String::from_utf8_lossy(data);
    let pairs = parse_cookies(&raw);
    let _ = std::hint::black_box(&pairs);

    // Build a matcher from the input: name = first half (or a fixed
    // interesting name when empty), value = second half, sometimes
    // value-less to hit the presence-only path.
    // Split at a UTF-8 char boundary near the middle (byte-splitting a
    // lossy-converted String mid-char would panic the harness itself).
    let mid = {
        let half = raw.len() / 2;
        (half..=raw.len())
            .find(|i| raw.is_char_boundary(*i))
            .unwrap_or(raw.len())
    };
    let (name, value) = if mid == 0 {
        ("session".to_string(), Some("abc123".to_string()))
    } else {
        let n = raw[..mid]
            .chars()
            .filter(|c| !c.is_control())
            .collect::<String>();
        let v = raw[mid..]
            .chars()
            .filter(|c| !c.is_control())
            .collect::<String>();
        let name = if n.is_empty() {
            "session".to_string()
        } else {
            n
        };
        (name, if v.is_empty() { None } else { Some(v) })
    };
    let want = NameValueMatch { name, value };
    let _ = std::hint::black_box(query_param_matches(Some(&raw), &want));
    let _ = std::hint::black_box(query_param_matches(None, &want));
});
