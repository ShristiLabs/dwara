//! Integration tests for DW-111 (FIPS 140-3 mode).
//!
//! These tests exercise the FIPS module's self-test, primitive allowlist,
//! and the snapshot validation rules. When the `fips` cargo feature is
//! OFF, the module is inert (self-test returns Disabled, no restrictions).
//! When the feature is ON, the self-test verifies the aws-lc-rs FIPS
//! provider is installed and the validation rejects non-approved
//! primitives (Ed25519 certs, Argon2 credential hashing).

#![cfg(feature = "fips")]

use dwara_core::security::fips;

#[test]
fn fips_self_test_passes_with_feature_on() {
    let attestation = fips::fips_self_test();
    assert!(
        attestation.self_test_passed,
        "FIPS self-test should pass when the fips feature is on and aws-lc-rs is the default provider"
    );
    assert_eq!(attestation.enabled, fips::FipsMode::Enabled);
    assert!(
        !attestation.provider.is_empty(),
        "provider name should be non-empty"
    );
}

#[test]
fn fips_attestation_is_serializable() {
    let attestation = fips::fips_self_test();
    let json = serde_json::to_string(&attestation).expect("attestation serializes");
    assert!(json.contains("self_test_passed"));
    assert!(json.contains("provider"));
}

#[test]
fn fips_allowed_ciphers_are_restricted() {
    // The FIPS-approved cipher list excludes ChaCha20-Poly1305.
    assert!(!fips::is_primitive_allowed("CHACHA20_POLY1305_SHA256"));
    // AES-GCM suites are allowed.
    assert!(fips::is_primitive_allowed("AES_256_GCM_SHA384"));
    assert!(fips::is_primitive_allowed("AES_128_GCM_SHA256"));
}

#[test]
fn fips_disallowed_signatures() {
    // Ed25519 is not on the FIPS-validated list for aws-lc-rs.
    assert!(fips::is_signature_disallowed("ed25519"));
    // ECDSA P-256 is allowed.
    assert!(!fips::is_signature_disallowed("ecdsa_p256"));
}

#[test]
fn fips_disallowed_credential_hashes() {
    // Argon2 is not FIPS-approved.
    assert!(fips::is_credential_hash_disallowed("argon2"));
    // PBKDF2 is FIPS-approved.
    assert!(!fips::is_credential_hash_disallowed("pbkdf2"));
}

#[test]
fn fips_health_attestation_returns_some_when_enabled() {
    let attestation = fips::health_attestation();
    assert!(
        attestation.is_some(),
        "health attestation should be Some when fips feature is on"
    );
    let a = attestation.unwrap();
    assert_eq!(a.enabled, fips::FipsMode::Enabled);
}
