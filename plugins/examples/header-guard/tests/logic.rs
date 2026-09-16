//! Plain-Rust unit tests for header-guard's callback logic.
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
