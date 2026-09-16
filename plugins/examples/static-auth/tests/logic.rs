//! Plain-Rust unit tests for static-auth's decision logic.
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
