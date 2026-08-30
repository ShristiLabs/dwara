//! Integration tests for the enterprise licensing gate (DW-032).
//!
//! The OSS-mode tests (no `ent` feature) run with the default feature
//! set and verify that the gate is always `none()` — enterprise features
//! are inert by construction. The ent-feature-gated tests run with
//! `cargo test --features ent` and exercise the full verify/grace/
//! feature-claim path using the licensing-core dev signer.
//!
//! Both halves coexist in this file: the `#[cfg(not(feature = "ent"))]`
//! tests compile under the default suite, the `#[cfg(feature = "ent")]`
//! tests compile only with the feature on.

use dwara_core::config::{parse_gateway, Gateway};
use dwara_core::extensions::licensing::{
    LicenseGate, LicenseStatus, DEFAULT_GRACE_PERIOD_DAYS, MAX_GRACE_PERIOD_DAYS,
};
use dwara_core::snapshot::validate;

/// A minimal valid gateway YAML prefix (listeners, routes, services,
/// upstreams) that every test config appends its license block to.
/// Keeps the tests focused on the license schema without repeating the
/// full route grammar.
const BASE_CONFIG: &str = "
listeners:
  - name: main
    address: 127.0.0.1
    port: 8080
    protocol: http
routes:
  - name: echo
    service: echo
    match:
      path:
        type: prefix
        value: /
    action:
      type: proxy
services:
  - name: echo
    upstream: backend
upstreams:
  - name: backend
    load_balancer: round_robin
    protocol: http1
    endpoints:
      - address: 127.0.0.1
        port: 9000
";

// ---------------------------------------------------------------------
// OSS-mode tests (default feature set, no `ent`).
// ---------------------------------------------------------------------

#[test]
fn no_license_configured_is_oss() {
    let gate = LicenseGate::none();
    assert!(!gate.is_enterprise());
    assert!(!gate.is_expired());
    assert!(!gate.has_feature("redis_rate_limiter"));
    assert_eq!(gate.status(), LicenseStatus::NoLicense);
    assert_eq!(gate.status().as_metric(), 0);
}

#[test]
fn oss_gate_has_default_grace_period() {
    let gate = LicenseGate::none();
    assert_eq!(gate.grace_period_days(), DEFAULT_GRACE_PERIOD_DAYS);
}

#[test]
fn license_config_block_parses() {
    // The license block is accepted by the schema in both OSS and ent
    // builds (it is inert without the ent feature). This test verifies
    // the block parses and the grace-period default applies.
    let yaml = format!("{BASE_CONFIG}license:\n  file: /path/to/license.json\n");
    let gateway = parse_gateway(&yaml).expect("license block parses");
    let lic = gateway.license.expect("license block present");
    assert_eq!(lic.file, "/path/to/license.json");
    // Default grace period applies when omitted.
    assert_eq!(lic.grace_period_days, DEFAULT_GRACE_PERIOD_DAYS);
}

#[test]
fn license_config_block_with_grace_period_parses() {
    let yaml = format!(
        "{BASE_CONFIG}license:\n  file: /etc/dwara/license.json\n  grace_period_days: 14\n"
    );
    let gateway = parse_gateway(&yaml).expect("license block with grace parses");
    let lic = gateway.license.expect("license block present");
    assert_eq!(lic.grace_period_days, 14);
}

#[test]
fn license_grace_period_out_of_bounds_rejected() {
    let yaml = format!(
        "{BASE_CONFIG}license:\n  file: /etc/dwara/license.json\n  grace_period_days: {}\n",
        MAX_GRACE_PERIOD_DAYS + 1
    );
    let gateway = parse_gateway(&yaml).expect("schema parses (bounds are semantic)");
    let issues = validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "license.grace_period_days"),
        "expected a grace_period_days out-of-bounds issue, got: {issues:?}"
    );
}

#[test]
fn license_empty_file_rejected() {
    let yaml = format!("{BASE_CONFIG}license:\n  file: ''\n");
    let gateway = parse_gateway(&yaml).expect("schema parses (empty file is semantic)");
    let issues = validate(&gateway);
    assert!(
        issues.iter().any(|i| i.field == "license.file"),
        "expected a license.file empty issue, got: {issues:?}"
    );
}

#[test]
fn no_license_block_validates_clean() {
    let gateway = test_gateway_no_license();
    let issues = validate(&gateway);
    assert!(
        !issues.iter().any(|i| i.field.starts_with("license.")),
        "no license block should produce no license issues, got: {issues:?}"
    );
}

/// A minimal valid Gateway with no license block (for validation tests).
fn test_gateway_no_license() -> Gateway {
    parse_gateway(BASE_CONFIG).expect("minimal gateway parses")
}

// ---------------------------------------------------------------------
// Ent-feature-gated tests (run with `cargo test --features ent`).
// ---------------------------------------------------------------------

#[cfg(feature = "ent")]
mod ent_tests {
    use super::*;
    use chrono::{Duration, Utc};
    use dwara_core::extensions::licensing::{
        LicenseLoadError, LicenseStatus, FEATURE_REDIS_RATE_LIMITER, PRODUCT_ID, PUBLIC_KEY_ENV_VAR,
    };
    use licensing_core::{dev_signer, keys, LicenseClaims, LicenseSigner};

    /// Set the DWARA_LICENSE_PUBLIC_KEY env var to the dev public key
    /// so the verifier uses the dev keypair (the same key the dev
    /// signer signs with). Returns a guard that removes the var on
    /// drop so parallel tests don't interfere.
    struct EnvGuard {
        var: &'static str,
        was_set: bool,
    }

    impl EnvGuard {
        fn set_dev_key() -> Self {
            let var = PUBLIC_KEY_ENV_VAR;
            let was_set = std::env::var(var).is_ok();
            std::env::set_var(var, keys::dev_public_key_b64());
            EnvGuard { var, was_set }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if self.was_set {
                // Leave it as it was (best-effort; env tests are
                // inherently racy, but the guard at least cleans up
                // the common case).
            } else {
                std::env::remove_var(self.var);
            }
        }
    }

    fn sample_claims(expires_at: chrono::DateTime<Utc>, features: Vec<String>) -> LicenseClaims {
        LicenseClaims {
            license_id: "lic_dwara_test_001".to_string(),
            product_id: PRODUCT_ID.to_string(),
            customer: "Acme Corp".to_string(),
            plan: "enterprise".to_string(),
            seats: 50,
            instance_id: "inst_test".to_string(),
            issued_at: Utc::now() - Duration::days(1),
            expires_at,
            features,
        }
    }

    #[test]
    fn valid_license_enters_enterprise_mode() {
        let _guard = EnvGuard::set_dev_key();
        let claims = sample_claims(
            Utc::now() + Duration::days(365),
            vec![
                "redis_rate_limiter".to_string(),
                "config_convergence".to_string(),
            ],
        );
        let file = dev_signer().sign_license(&claims).expect("sign");
        let gate = LicenseGate::from_file_claims(&file, DEFAULT_GRACE_PERIOD_DAYS)
            .expect("valid license loads");
        assert!(gate.is_enterprise());
        assert!(!gate.is_expired());
        assert_eq!(gate.status(), LicenseStatus::Valid);
        assert_eq!(gate.status().as_metric(), 1);
        assert_eq!(gate.customer(), Some("Acme Corp"));
        assert_eq!(gate.plan(), Some("enterprise"));
    }

    #[test]
    fn feature_check_works() {
        let _guard = EnvGuard::set_dev_key();
        let claims = sample_claims(
            Utc::now() + Duration::days(365),
            vec!["redis_rate_limiter".to_string()],
        );
        let file = dev_signer().sign_license(&claims).expect("sign");
        let gate = LicenseGate::from_file_claims(&file, DEFAULT_GRACE_PERIOD_DAYS)
            .expect("valid license loads");
        assert!(gate.has_feature(FEATURE_REDIS_RATE_LIMITER));
        assert!(!gate.has_feature("config_convergence"));
        assert!(!gate.has_feature("nonexistent_feature"));
    }

    #[test]
    fn feature_check_false_without_feature() {
        let _guard = EnvGuard::set_dev_key();
        // License with NO features — enterprise mode but no claims.
        let claims = sample_claims(Utc::now() + Duration::days(365), vec![]);
        let file = dev_signer().sign_license(&claims).expect("sign");
        let gate = LicenseGate::from_file_claims(&file, DEFAULT_GRACE_PERIOD_DAYS)
            .expect("valid license loads");
        assert!(gate.is_enterprise());
        assert!(!gate.has_feature(FEATURE_REDIS_RATE_LIMITER));
    }

    #[test]
    fn expired_within_grace_still_enterprise() {
        let _guard = EnvGuard::set_dev_key();
        // Expired 1 day ago, grace period 7 days — still within grace.
        let claims = sample_claims(
            Utc::now() - Duration::days(1),
            vec!["redis_rate_limiter".to_string()],
        );
        let file = dev_signer().sign_license(&claims).expect("sign");
        let gate = LicenseGate::from_file_claims(&file, 7).expect("expired-within-grace loads");
        assert!(gate.is_enterprise());
        assert!(gate.is_expired());
        assert_eq!(gate.status(), LicenseStatus::ExpiredWithinGrace);
        assert_eq!(gate.status().as_metric(), 2);
        // Feature checks still work during grace.
        assert!(gate.has_feature(FEATURE_REDIS_RATE_LIMITER));
    }

    #[test]
    fn expired_past_grace_degrades_to_oss() {
        let _guard = EnvGuard::set_dev_key();
        // Expired 10 days ago, grace period 7 days — past grace.
        let claims = sample_claims(
            Utc::now() - Duration::days(10),
            vec!["redis_rate_limiter".to_string()],
        );
        let file = dev_signer().sign_license(&claims).expect("sign");
        let gate = LicenseGate::from_file_claims(&file, 7).expect("expired-past-grace loads");
        assert!(!gate.is_enterprise());
        assert!(gate.is_expired());
        assert_eq!(gate.status(), LicenseStatus::ExpiredPastGrace);
        assert_eq!(gate.status().as_metric(), 3);
        // Feature checks return false after degradation.
        assert!(!gate.has_feature(FEATURE_REDIS_RATE_LIMITER));
    }

    #[test]
    fn grace_period_zero_means_immediate_degradation() {
        let _guard = EnvGuard::set_dev_key();
        // Expired 1 second ago, grace period 0 — immediate degradation.
        let claims = sample_claims(
            Utc::now() - Duration::seconds(1),
            vec!["redis_rate_limiter".to_string()],
        );
        let file = dev_signer().sign_license(&claims).expect("sign");
        let gate = LicenseGate::from_file_claims(&file, 0).expect("expired-no-grace loads");
        assert!(!gate.is_enterprise());
        assert_eq!(gate.status(), LicenseStatus::ExpiredPastGrace);
    }

    #[test]
    fn invalid_signature_rejected() {
        let _guard = EnvGuard::set_dev_key();
        let claims = sample_claims(
            Utc::now() + Duration::days(365),
            vec!["redis_rate_limiter".to_string()],
        );
        // Sign with a DIFFERENT key (not the dev key the verifier uses).
        let (other_signer, _) = LicenseSigner::generate();
        let file = other_signer.sign_license(&claims).expect("sign");
        let err = LicenseGate::from_file_claims(&file, DEFAULT_GRACE_PERIOD_DAYS)
            .expect_err("wrong-key license must fail");
        assert!(matches!(err, LicenseLoadError::InvalidSignature));
    }

    #[test]
    fn tampered_signature_rejected() {
        let _guard = EnvGuard::set_dev_key();
        let claims = sample_claims(
            Utc::now() + Duration::days(365),
            vec!["redis_rate_limiter".to_string()],
        );
        let file = dev_signer().sign_license(&claims).expect("sign");
        // Tamper with the signature: flip the last byte.
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        let mut sig_bytes = BASE64
            .decode(file.signature.as_bytes())
            .expect("decode sig");
        let last = sig_bytes.len() - 1;
        sig_bytes[last] ^= 0xff;
        let tampered = licensing_core::LicenseFile {
            claims: file.claims.clone(),
            signature: BASE64.encode(&sig_bytes),
        };
        let err = LicenseGate::from_file_claims(&tampered, DEFAULT_GRACE_PERIOD_DAYS)
            .expect_err("tampered license must fail");
        assert!(matches!(err, LicenseLoadError::InvalidSignature));
    }

    #[test]
    fn product_mismatch_rejected() {
        let _guard = EnvGuard::set_dev_key();
        // License for a different product — the verifier pins product_id
        // to "dwara", so a "madhyamas" license is rejected.
        let mut claims = sample_claims(
            Utc::now() + Duration::days(365),
            vec!["redis_rate_limiter".to_string()],
        );
        claims.product_id = "madhyamas".to_string();
        let file = dev_signer().sign_license(&claims).expect("sign");
        let err = LicenseGate::from_file_claims(&file, DEFAULT_GRACE_PERIOD_DAYS)
            .expect_err("product mismatch must fail");
        assert!(matches!(err, LicenseLoadError::ProductMismatch { .. }));
    }

    #[test]
    fn from_file_not_found() {
        let _guard = EnvGuard::set_dev_key();
        let err = LicenseGate::from_file(
            std::path::Path::new("/nonexistent/dwara/license.json"),
            DEFAULT_GRACE_PERIOD_DAYS,
        )
        .expect_err("missing file must fail");
        assert!(matches!(err, LicenseLoadError::NotFound(_)));
    }

    #[test]
    fn from_file_roundtrip() {
        let _guard = EnvGuard::set_dev_key();
        let claims = sample_claims(
            Utc::now() + Duration::days(365),
            vec!["redis_rate_limiter".to_string()],
        );
        let file = dev_signer().sign_license(&claims).expect("sign");
        // Write to a temp file and verify via from_file (the disk path).
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("license.json");
        std::fs::write(&path, serde_json::to_vec(&file).expect("serialize")).expect("write");
        let gate =
            LicenseGate::from_file(&path, DEFAULT_GRACE_PERIOD_DAYS).expect("file verify succeeds");
        assert!(gate.is_enterprise());
        assert_eq!(gate.status(), LicenseStatus::Valid);
        assert!(gate.has_feature(FEATURE_REDIS_RATE_LIMITER));
    }
}
