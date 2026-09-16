//! Plain-Rust unit tests for the redaction logic.
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
