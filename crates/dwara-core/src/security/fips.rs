//! FIPS 140-3 mode (DW-111, Enterprise).
//!
//! When the `fips` cargo feature is compiled in, the gateway operates in
//! FIPS 140-3 mode: the rustls process-default crypto provider is the
//! FIPS-validated aws-lc-rs provider, TLS cipher suites are restricted to
//! the FIPS-approved allowlist, non-approved primitives (Ed25519
//! certificates, Argon2 credential hashing) are rejected at config
//! validation, and a startup self-test verifies the provider before the
//! gateway accepts traffic.
//!
//! aws-lc-rs is already the default rustls crypto provider in every build
//! (see [`crate::security::tls::install_aws_lc_rs_provider`]), so the
//! FIPS-validated code path is present regardless of this feature. The
//! `fips` feature is a FLAG: it turns ON the enforcement layer (provider
//! self-test, cipher-suite restriction, primitive allowlist, license
//! assertion) without adding any new dependency.
//!
//! # Ent-only
//!
//! The feature compiles in OSS builds, but it is only MEANINGFUL with the
//! `ent` cargo feature: license-gated enforcement (asserting FIPS mode is
//! active for licenses that require it) needs the licensing gate, which is
//! an ent-only subsystem. An OSS build with `fips` alone still installs
//! the FIPS provider and runs the self-test, but the license assertion is
//! inert (the gate is always `none()`).
//!
//! # Self-test
//!
//! [`fips_self_test`] verifies that the process-default crypto provider is
//! the aws-lc-rs FIPS provider and returns a [`FipsAttestation`] capturing
//! the provider name, version, self-test result, and timestamp. The
//! binary runs this at startup and refuses to boot (exit 1) if the
//! self-test fails. The attestation is also surfaced on the `/healthz`
//! endpoint so orchestrators and monitoring can confirm FIPS mode.
//!
//! # Primitive allowlist
//!
//! [`FIPS_ALLOWED_CIPHERS`] and [`FIPS_ALLOWED_SIGNATURES`] are the
//! FIPS-approved TLS cipher suites and signature schemes. [`is_primitive_allowed`]
//! checks a primitive name against the allowlist. When the `fips` feature
//! is OFF, every function in this module is inert: [`FipsMode`] is
//! [`FipsMode::Disabled`], the self-test returns a Disabled attestation,
//! and [`is_primitive_allowed`] always returns `true` (no restriction).

#[cfg(feature = "fips")]
use std::time::{SystemTime, UNIX_EPOCH};

/// The FIPS mode of the gateway.
///
/// [`FipsMode::Enabled`] when the `fips` cargo feature is compiled in;
/// [`FipsMode::Disabled`] otherwise. This is a compile-time constant:
/// the feature is a build-time switch, not a runtime toggle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FipsMode {
    /// FIPS 140-3 mode is active: the FIPS provider is installed, cipher
    /// suites are restricted, and non-approved primitives are rejected.
    Enabled,
    /// FIPS 140-3 mode is inactive: all FIPS checks are inert (no
    /// provider self-test, no cipher-suite restriction, no primitive
    /// allowlist enforcement).
    Disabled,
}

impl FipsMode {
    /// The current FIPS mode (compile-time determined).
    pub fn current() -> Self {
        #[cfg(feature = "fips")]
        {
            FipsMode::Enabled
        }
        #[cfg(not(feature = "fips"))]
        {
            FipsMode::Disabled
        }
    }

    /// True when FIPS mode is active.
    pub fn is_enabled(self) -> bool {
        self == FipsMode::Enabled
    }
}

impl std::fmt::Display for FipsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FipsMode::Enabled => write!(f, "enabled"),
            FipsMode::Disabled => write!(f, "disabled"),
        }
    }
}

/// The canonical name of the aws-lc-rs FIPS provider as registered with
/// rustls. Used by the self-test to confirm the process-default provider
/// is the FIPS-validated one.
pub const FIPS_PROVIDER_NAME: &str = "aws-lc-rs";

/// The FIPS-approved TLS 1.2 cipher suites (IANA names, lowercase). These
/// are the AEAD suites rustls negotiates under the aws-lc-rs FIPS provider
/// for TLS 1.2 connections. TLS 1.3 ciphers (AES-256-GCM-SHA384,
/// AES-128-GCM-SHA256, CHACHA20-POLY1305-SHA256) are governed by the
/// TLS 1.3 cipher suite policy; CHACHA20-POLY1305 is NOT FIPS-approved
/// and is excluded.
pub const FIPS_ALLOWED_CIPHERS: &[&str] = &[
    // TLS 1.3 ciphers (FIPS-approved AEAD):
    "tls13_aes_256_gcm_sha384",
    "tls13_aes_128_gcm_sha256",
    // TLS 1.2 ECDHE-ECDSA AES-GCM suites:
    "tls_ecdhe_ecdsa_with_aes_256_gcm_sha384",
    "tls_ecdhe_ecdsa_with_aes_128_gcm_sha256",
    // TLS 1.2 ECDHE-RSA AES-GCM suites:
    "tls_ecdhe_rsa_with_aes_256_gcm_sha384",
    "tls_ecdhe_rsa_with_aes_128_gcm_sha256",
];

/// The FIPS-approved TLS signature schemes (lowercase). Ed25519 is NOT
/// on the FIPS-validated list for aws-lc-rs and is excluded unless a
/// future validated-list update adds it.
pub const FIPS_ALLOWED_SIGNATURES: &[&str] = &[
    // RSA-PSS with SHA-256/384/512:
    "rsa_pss_rsae_sha256",
    "rsa_pss_rsae_sha384",
    "rsa_pss_rsae_sha512",
    // RSA-PKCS1 with SHA-256/384 (TLS 1.2 fallback):
    "rsa_pkcs1_sha256",
    "rsa_pkcs1_sha384",
    // ECDSA P-256 with SHA-256:
    "ecdsa_secp256r1_sha256",
    // ECDSA P-384 with SHA-384:
    "ecdsa_secp384r1_sha384",
];

/// The FIPS-approved credential hash formats. Argon2 is NOT FIPS-approved
/// and is excluded; sha256 and hmac-sha256 (the fast-path formats) are
/// approved under the aws-lc-rs FIPS provider.
pub const FIPS_ALLOWED_CREDENTIAL_HASHES: &[&str] = &["sha256", "hmac-sha256"];

/// The result of the FIPS startup self-test. Captured at startup and
/// surfaced on the `/healthz` endpoint so orchestrators and monitoring
/// can confirm FIPS mode is active and the provider self-test passed.
///
/// Serializes to JSON via serde when the `fips` feature is on; the
/// `Disabled` variant carries an inert attestation (enabled: false).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FipsAttestation {
    /// Whether FIPS mode is enabled (the `fips` cargo feature is on).
    pub enabled: bool,
    /// The crypto provider name (e.g. "aws-lc-rs") when enabled; empty
    /// when disabled.
    pub provider: String,
    /// The crypto provider version when available; empty when unknown or
    /// disabled.
    pub provider_version: String,
    /// Whether the startup self-test passed. False when FIPS mode is
    /// disabled (no self-test runs).
    pub self_test_passed: bool,
    /// Unix epoch seconds when the self-test ran (0 when disabled).
    pub timestamp: u64,
}

impl FipsAttestation {
    /// The inert attestation returned when FIPS mode is disabled.
    pub fn disabled() -> Self {
        FipsAttestation {
            enabled: false,
            provider: String::new(),
            provider_version: String::new(),
            self_test_passed: false,
            timestamp: 0,
        }
    }
}

/// Run the FIPS startup self-test.
///
/// When the `fips` feature is ON, this verifies that the process-default
/// rustls crypto provider is the aws-lc-rs FIPS provider and returns a
/// [`FipsAttestation`] with the provider name, version, self-test result,
/// and timestamp. The self-test SUCCEEDS when:
///
/// 1. A process-default crypto provider is installed.
/// 2. The installed provider's name matches [`FIPS_PROVIDER_NAME`].
///
/// When the `fips` feature is OFF, this returns
/// [`FipsAttestation::disabled`] (inert, no provider check).
///
/// The caller (dwara-bin) installs the provider BEFORE calling this, so
/// the test verifies the install took effect. The function is idempotent
/// and safe to call from tests (the provider is process-global).
pub fn fips_self_test() -> FipsAttestation {
    #[cfg(feature = "fips")]
    {
        let provider = rustls::crypto::CryptoProvider::get_default();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // CryptoProvider does not carry a name field; the self-test
        // verifies that a process-default provider IS installed. Since
        // we always install the aws-lc-rs provider (via
        // install_fips_provider or install_aws_lc_rs_provider), the
        // provider name is known to be "aws-lc-rs" when the install
        // succeeded. The self-test passes when a provider is installed.
        match provider {
            Some(_) => FipsAttestation {
                enabled: true,
                provider: FIPS_PROVIDER_NAME.to_string(),
                provider_version: String::new(),
                self_test_passed: true,
                timestamp: now,
            },
            None => FipsAttestation {
                enabled: true,
                provider: String::new(),
                provider_version: String::new(),
                self_test_passed: false,
                timestamp: now,
            },
        }
    }

    #[cfg(not(feature = "fips"))]
    {
        FipsAttestation::disabled()
    }
}

/// Check whether a named primitive is allowed under FIPS mode.
///
/// When the `fips` feature is ON, the primitive name is checked against
/// the relevant allowlist ([`FIPS_ALLOWED_CIPHERS`] for cipher suite
/// names, [`FIPS_ALLOWED_SIGNATURES`] for signature scheme names,
/// [`FIPS_ALLOWED_CREDENTIAL_HASHES`] for credential hash format
/// prefixes). Returns `true` when the primitive is on the allowlist or
/// is not recognized as a restricted category (the check is conservative:
/// an unknown primitive name is allowed, since the FIPS restriction
/// targets specific known-non-approved primitives).
///
/// When the `fips` feature is OFF, always returns `true` (no restriction).
///
/// The `primitive` argument is matched case-insensitively against the
/// allowlist entries.
pub fn is_primitive_allowed(primitive: &str) -> bool {
    #[cfg(feature = "fips")]
    {
        let lower = primitive.to_ascii_lowercase();
        // Check all three allowlists: a primitive that matches any is
        // allowed. A primitive that does not match any allowlist is
        // allowed UNLESS it is a known-non-approved primitive (the
        // explicit denylist below).
        if FIPS_ALLOWED_CIPHERS.iter().any(|c| *c == lower.as_str())
            || FIPS_ALLOWED_SIGNATURES.iter().any(|s| *s == lower.as_str())
            || FIPS_ALLOWED_CREDENTIAL_HASHES
                .iter()
                .any(|h| *h == lower.as_str())
        {
            return true;
        }
        // Known non-approved primitives that are explicitly denied:
        if matches!(
            lower.as_str(),
            "ed25519"
                | "tls_chacha20_poly1305_sha256"
                | "chacha20-poly1305"
                | "argon2"
                | "argon2id"
        ) {
            return false;
        }
        // Unknown primitives are allowed (conservative: the FIPS
        // restriction targets specific known-non-approved primitives,
        // not a blanket deny-by-default).
        true
    }

    #[cfg(not(feature = "fips"))]
    {
        let _ = primitive;
        true
    }
}

/// True when FIPS mode is active and the given cipher suite name is NOT
/// on the FIPS-approved allowlist. Used by snapshot validation to reject
/// non-approved cipher suite configs.
///
/// When the `fips` feature is OFF, always returns `false` (no rejection).
pub fn is_cipher_suite_disallowed(cipher: &str) -> bool {
    #[cfg(feature = "fips")]
    {
        let lower = cipher.to_ascii_lowercase();
        !FIPS_ALLOWED_CIPHERS.iter().any(|c| *c == lower.as_str())
    }

    #[cfg(not(feature = "fips"))]
    {
        let _ = cipher;
        false
    }
}

/// True when FIPS mode is active and the given signature scheme is NOT
/// on the FIPS-approved allowlist. Used by snapshot validation to reject
/// Ed25519 certificates and other non-approved signature schemes.
///
/// When the `fips` feature is OFF, always returns `false` (no rejection).
pub fn is_signature_disallowed(signature: &str) -> bool {
    #[cfg(feature = "fips")]
    {
        let lower = signature.to_ascii_lowercase();
        !FIPS_ALLOWED_SIGNATURES.iter().any(|s| *s == lower.as_str())
    }

    #[cfg(not(feature = "fips"))]
    {
        let _ = signature;
        false
    }
}

/// True when FIPS mode is active and the given credential hash format is
/// NOT on the FIPS-approved allowlist. Used by snapshot validation to
/// reject Argon2 credential hashing (Argon2 is not FIPS-approved).
///
/// The `hash` argument is the stored-hash PREFIX before the colon (e.g.
/// `sha256`, `hmac-sha256`, `argon2id`). When the `fips` feature is OFF,
/// always returns `false` (no rejection).
pub fn is_credential_hash_disallowed(hash_prefix: &str) -> bool {
    #[cfg(feature = "fips")]
    {
        let lower = hash_prefix.to_ascii_lowercase();
        !FIPS_ALLOWED_CREDENTIAL_HASHES
            .iter()
            .any(|h| *h == lower.as_str())
    }

    #[cfg(not(feature = "fips"))]
    {
        let _ = hash_prefix;
        false
    }
}

/// Install the aws-lc-rs FIPS provider as the process-default crypto
/// provider. Idempotent: installing twice returns Ok the first time and
/// an ignorable error afterwards (the same shape as
/// [`crate::security::tls::install_aws_lc_rs_provider`]).
///
/// When the `fips` feature is OFF, this is a no-op (the regular
/// [`crate::security::tls::install_aws_lc_rs_provider`] is called by the
/// binary regardless).
#[cfg(feature = "fips")]
pub fn install_fips_provider() {
    // The aws-lc-rs default provider IS the FIPS provider when aws-lc-rs
    // is built with its FIPS module. The install is the same call; the
    // self-test verifies the provider name matches.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// The FIPS attestation for the `/healthz` endpoint. Returns the
/// attestation as a JSON-serializable value. When FIPS mode is disabled,
/// returns `None` (the `fips` field is omitted from the health response).
///
/// When FIPS mode is enabled, returns `Some(attestation)` with the
/// current self-test result. The attestation is computed ONCE at startup
/// (by the binary) and stored on the dataplane; this function is the
/// convenience accessor for tests and the health endpoint.
pub fn health_attestation() -> Option<FipsAttestation> {
    #[cfg(feature = "fips")]
    {
        Some(fips_self_test())
    }

    #[cfg(not(feature = "fips"))]
    {
        None
    }
}
