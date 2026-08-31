//! Unit tests for `extensions::vault_secrets` -- KMS, LeaseManager,
//! and redaction tests (relocated from src). The VaultSecretSource
//! cache tests stay in src/ because they exercise private methods
//! (`url`, `token`, `store_cached`, `get_cached`, `api_url`).

use dwara_core::extensions::secrets::SecretSource;
use dwara_core::extensions::vault_secrets::{
    KmsSecretSource, Lease, LeaseManager, MockKmsProvider,
};
use dwara_core::extensions::ExtensionsError;

// --- KMS tests ---

#[tokio::test]
async fn kms_resolve_with_mock_provider() {
    let provider = MockKmsProvider::passthrough();
    let source = KmsSecretSource::new(Box::new(provider));

    let result = source.resolve("key-1:aGVsbG8=").await.unwrap();
    assert!(result.is_some());
    assert_eq!(result.unwrap().expose(), "aGVsbG8=");
}

#[tokio::test]
async fn kms_resolve_invalid_name() {
    let provider = MockKmsProvider::passthrough();
    let source = KmsSecretSource::new(Box::new(provider));

    let err = source.resolve("no-colon").await.unwrap_err();
    assert!(matches!(err, ExtensionsError::Invalid(_)));
}

#[tokio::test]
async fn kms_resolve_empty_key_id() {
    let provider = MockKmsProvider::passthrough();
    let source = KmsSecretSource::new(Box::new(provider));

    let err = source.resolve(":ciphertext").await.unwrap_err();
    assert!(matches!(err, ExtensionsError::Invalid(_)));
}

#[tokio::test]
async fn kms_resolve_empty_ciphertext() {
    let provider = MockKmsProvider::passthrough();
    let source = KmsSecretSource::new(Box::new(provider));

    let err = source.resolve("key-1:").await.unwrap_err();
    assert!(matches!(err, ExtensionsError::Invalid(_)));
}

#[tokio::test]
async fn kms_provider_decrypt_failure() {
    let provider =
        MockKmsProvider::new(|_, _| Err(ExtensionsError::Backend("KMS error".to_string())));
    let source = KmsSecretSource::new(Box::new(provider));

    let err = source.resolve("key-1:ciphertext").await.unwrap_err();
    assert!(matches!(err, ExtensionsError::Backend(_)));
}

// --- LeaseManager tests ---

#[test]
fn lease_manager_register_and_get() {
    let mgr = LeaseManager::new();
    let lease = Lease {
        lease_id: "lease-123".to_string(),
        lease_duration: 3600,
        renewable: true,
    };
    mgr.register("db-creds", lease.clone());
    assert_eq!(mgr.lease_count(), 1);

    let got = mgr.get("db-creds").unwrap();
    assert_eq!(got.lease_id, "lease-123");
    assert_eq!(got.lease_duration, 3600);
    assert!(got.renewable);
}

#[test]
fn lease_manager_revoke() {
    let mgr = LeaseManager::new();
    mgr.register(
        "db-creds",
        Lease {
            lease_id: "lease-123".to_string(),
            lease_duration: 3600,
            renewable: true,
        },
    );
    assert_eq!(mgr.lease_count(), 1);

    let revoked = mgr.revoke("db-creds");
    assert!(revoked.is_some());
    assert_eq!(mgr.lease_count(), 0);
    assert!(mgr.get("db-creds").is_none());
}

#[test]
fn lease_manager_needing_renewal() {
    let mgr = LeaseManager::new();
    mgr.register(
        "short-lease",
        Lease {
            lease_id: "lease-1".to_string(),
            lease_duration: 100,
            renewable: true,
        },
    );
    mgr.register(
        "long-lease",
        Lease {
            lease_id: "lease-2".to_string(),
            lease_duration: 7200,
            renewable: true,
        },
    );
    mgr.register(
        "non-renewable",
        Lease {
            lease_id: "lease-3".to_string(),
            lease_duration: 50,
            renewable: false,
        },
    );

    let needing = mgr.leases_needing_renewal(200);
    assert_eq!(needing.len(), 1);
    assert_eq!(needing[0].0, "short-lease");
}

#[tokio::test]
async fn lease_manager_renew_renewable() {
    let mgr = LeaseManager::new();
    mgr.register(
        "db-creds",
        Lease {
            lease_id: "lease-123".to_string(),
            lease_duration: 3600,
            renewable: true,
        },
    );
    mgr.renew("db-creds").await.unwrap();
}

#[tokio::test]
async fn lease_manager_renew_non_renewable_fails() {
    let mgr = LeaseManager::new();
    mgr.register(
        "db-creds",
        Lease {
            lease_id: "lease-123".to_string(),
            lease_duration: 3600,
            renewable: false,
        },
    );
    let err = mgr.renew("db-creds").await.unwrap_err();
    assert!(matches!(err, ExtensionsError::Backend(_)));
}

#[tokio::test]
async fn lease_manager_renew_unknown_fails() {
    let mgr = LeaseManager::new();
    let err = mgr.renew("unknown").await.unwrap_err();
    assert!(matches!(err, ExtensionsError::Backend(_)));
}

// --- Secret redaction ---

#[test]
fn secret_redaction() {
    use dwara_core::extensions::secrets::Secret;
    let secret = Secret::new("super-secret-value");
    let debug = format!("{secret:?}");
    assert!(debug.contains("redacted"));
    assert!(!debug.contains("super-secret-value"));
}
