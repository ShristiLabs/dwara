//! Integration tests for DW-111 (FIPS 140-3 mode).
//!
//! These tests exercise the FIPS module's self-test, primitive allowlist,
//! and the snapshot validation rules. FIPS enforcement is an Enterprise-
//! only capability: in OSS builds (the default, no `ent` cargo feature)
//! the module is inert (self-test returns Disabled, no restrictions).
//! In Enterprise builds the self-test verifies the aws-lc-rs FIPS
//! provider is installed and the validation rejects non-approved
//! primitives (Ed25519 certs, Argon2 credential hashing).

use dwara_core::security::fips;

#[test]
fn fips_self_test_is_disabled_in_oss() {
    let attestation = fips::fips_self_test();
    // In OSS builds FIPS enforcement is off; the attestation is inert.
    if !fips::FipsMode::current().is_enabled() {
        assert!(!attestation.enabled, "FIPS mode should be disabled in OSS");
        assert!(
            !attestation.self_test_passed,
            "self-test should not pass when FIPS is disabled"
        );
    } else {
        assert!(
            attestation.self_test_passed,
            "FIPS self-test should pass when the ent feature is on and aws-lc-rs is the default provider"
        );
        assert!(attestation.enabled, "FIPS mode should be enabled");
        assert!(
            !attestation.provider.is_empty(),
            "provider name should be non-empty"
        );
    }
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
    // In OSS builds all primitives are allowed (no FIPS restriction).
    if !fips::FipsMode::current().is_enabled() {
        assert!(fips::is_primitive_allowed("CHACHA20_POLY1305_SHA256"));
        return;
    }
    // The FIPS-approved cipher list excludes ChaCha20-Poly1305.
    assert!(!fips::is_primitive_allowed("CHACHA20_POLY1305_SHA256"));
    // AES-GCM suites are allowed.
    assert!(fips::is_primitive_allowed("AES_256_GCM_SHA384"));
    assert!(fips::is_primitive_allowed("AES_128_GCM_SHA256"));
}

#[test]
fn fips_disallowed_signatures() {
    // In OSS builds no signatures are disallowed.
    if !fips::FipsMode::current().is_enabled() {
        assert!(!fips::is_signature_disallowed("ed25519"));
        return;
    }
    // Ed25519 is not on the FIPS-validated list for aws-lc-rs.
    assert!(fips::is_signature_disallowed("ed25519"));
    // ECDSA P-256 is allowed.
    assert!(!fips::is_signature_disallowed("ecdsa_p256"));
}

#[test]
fn fips_disallowed_credential_hashes() {
    // In OSS builds no credential hashes are disallowed.
    if !fips::FipsMode::current().is_enabled() {
        assert!(!fips::is_credential_hash_disallowed("argon2"));
        return;
    }
    // Argon2 is not FIPS-approved.
    assert!(fips::is_credential_hash_disallowed("argon2"));
    // PBKDF2 is FIPS-approved.
    assert!(!fips::is_credential_hash_disallowed("pbkdf2"));
}

#[test]
fn fips_health_attestation_reflects_mode() {
    let attestation = fips::health_attestation();
    if !fips::FipsMode::current().is_enabled() {
        assert!(
            attestation.is_none(),
            "health attestation should be None in OSS (FIPS disabled)"
        );
    } else {
        assert!(
            attestation.is_some(),
            "health attestation should be Some when FIPS is enabled"
        );
        let a = attestation.unwrap();
        assert!(a.enabled, "FIPS mode should be enabled");
    }
}
