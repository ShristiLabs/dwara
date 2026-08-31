//! Vault/KMS SecretSource (DW-069, Enterprise).
//!
//! Vault KV + KMS providers; refresh/lease handling.
//!
//! Implements `SecretSource` (section 11.3) alongside DW-045's OSS
//! file/env implementation, behind the same trait. Resolved values
//! must never be logged or echoed back -- including via the admin API
//! -- per section 13.3's blanket secret-redaction requirement; a
//! resolved Vault/KMS value gets the same redaction treatment as an
//! inline config secret.
//!
//! ## Feature gate
//!
//! The `ent` cargo feature must be enabled. Without it, the module is
//! not compiled and the gateway uses the OSS file/env secret sources.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use async_trait::async_trait;

use super::secrets::{Secret, SecretSource};
use super::ExtensionsError;

/// A Vault KV v2 secret source.
///
/// Reads secrets from a Vault server's KV v2 engine via the HTTP API.
/// The `name` passed to `resolve` is interpreted as
/// `<mount>/<path>` (e.g. `secret/data/my-app/db` for a secret at
/// `secret/` mount, path `my-app/db`).
///
/// ## Lease handling
///
/// Vault KV v2 secrets do not have leases (they are static). However,
/// the source caches resolved secrets with a configurable TTL. When
/// the TTL expires, the next `resolve` call re-reads from Vault,
/// allowing rotation without restart.
///
/// ## Secret redaction
///
/// Resolved values are wrapped in `Secret` (redacted Debug, no
/// Display). The source itself never logs resolved values.
#[allow(dead_code)]
pub struct VaultSecretSource {
    /// The Vault server URL (e.g. <https://vault.example.com:8200>).
    url: String,
    /// The Vault token (used for authentication).
    token: String,
    /// The cache TTL: how long a resolved secret is cached before
    /// re-reading from Vault.
    cache_ttl: Duration,
    /// The resolved-secret cache: name -> (secret, resolved_at).
    cache: RwLock<HashMap<String, (Secret, Instant)>>,
}

impl VaultSecretSource {
    /// Create a new Vault secret source.
    pub fn new(url: &str, token: &str, cache_ttl: Duration) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            cache_ttl,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Check if a cached secret is still fresh.
    fn is_cache_fresh(resolved_at: Instant, ttl: Duration) -> bool {
        resolved_at.elapsed() < ttl
    }

    /// Get a cached secret if fresh.
    fn get_cached(&self, name: &str) -> Option<Secret> {
        let cache = self.cache.read().unwrap();
        cache
            .get(name)
            .filter(|(_, at)| Self::is_cache_fresh(*at, self.cache_ttl))
            .map(|(s, _)| s.clone())
    }

    /// Store a secret in the cache.
    #[cfg(test)]
    fn store_cached(&self, name: &str, secret: Secret) {
        let mut cache = self.cache.write().unwrap();
        cache.insert(name.to_string(), (secret, Instant::now()));
    }

    /// Clear the cache (forces re-read on next resolve).
    pub fn clear_cache(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.clear();
    }

    /// The number of cached secrets.
    pub fn cache_size(&self) -> usize {
        let cache = self.cache.read().unwrap();
        cache.len()
    }

    /// Build the Vault API URL for a secret.
    fn api_url(&self, name: &str) -> String {
        format!("{}/v1/{name}", self.url)
    }

    /// The Vault token (for testing).
    #[cfg(test)]
    fn token(&self) -> &str {
        &self.token
    }

    /// The Vault URL (for testing).
    #[cfg(test)]
    fn url(&self) -> &str {
        &self.url
    }
}

#[async_trait]
impl SecretSource for VaultSecretSource {
    async fn resolve(&self, name: &str) -> Result<Option<Secret>, ExtensionsError> {
        // Check cache first.
        if let Some(cached) = self.get_cached(name) {
            return Ok(Some(cached));
        }

        // In a real implementation, this would make an HTTP GET to
        // Vault's KV v2 API:
        //   GET {url}/v1/{name}
        //   X-Vault-Token: {token}
        // and parse the response's `data.data` field.
        //
        // For now, we return an error indicating the HTTP client is
        // not yet wired up. The cache + TTL logic is fully
        // implemented and tested; the HTTP call is the remaining
        // piece (it requires a hyper client setup that is
        // environment-specific).
        Err(ExtensionsError::Backend(format!(
            "vault secret source: HTTP client not yet wired up (would call GET {} with X-Vault-Token)",
            self.api_url(name),
        )))
    }
}

/// A KMS (Key Management Service) secret source.
///
/// Wraps a KMS provider (AWS KMS, GCP KMS, Azure Key Vault, etc.)
/// that can decrypt encrypted secrets. The `name` passed to `resolve`
/// is interpreted as `<key_id>:<ciphertext>` (base64-encoded
/// ciphertext).
///
/// ## Design
///
/// The KMS source does not cache: each `resolve` call decrypts
/// fresh (KMS calls are idempotent and the ciphertext is small).
/// Rotation is handled by updating the ciphertext in the config --
/// the next `resolve` call decrypts the new ciphertext.
pub struct KmsSecretSource {
    /// The KMS provider.
    provider: Box<dyn KmsProvider>,
}

impl KmsSecretSource {
    /// Create a new KMS secret source with the given provider.
    pub fn new(provider: Box<dyn KmsProvider>) -> Self {
        Self { provider }
    }
}

#[async_trait]
impl SecretSource for KmsSecretSource {
    async fn resolve(&self, name: &str) -> Result<Option<Secret>, ExtensionsError> {
        // Parse the name as <key_id>:<ciphertext>.
        let (key_id, ciphertext) = name.split_once(':').ok_or_else(|| {
            ExtensionsError::Invalid(format!(
                "KMS secret name must be <key_id>:<ciphertext>, got: {name}"
            ))
        })?;

        if key_id.is_empty() || ciphertext.is_empty() {
            return Err(ExtensionsError::Invalid(format!(
                "KMS secret name has empty key_id or ciphertext: {name}"
            )));
        }

        let plaintext = self.provider.decrypt(key_id, ciphertext.as_bytes()).await?;
        Ok(Some(Secret::new(plaintext)))
    }
}

/// A KMS provider: can decrypt ciphertext using a named key.
///
/// Implementations: AWS KMS, GCP KMS, Azure Key Vault, etc.
#[async_trait]
pub trait KmsProvider: Send + Sync {
    /// Decrypt `ciphertext` using the named key.
    ///
    /// Returns the plaintext bytes. The provider must not log the
    /// plaintext or ciphertext.
    async fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> Result<String, ExtensionsError>;
}

/// The decryption function signature for [`MockKmsProvider`]:
/// (key_id, ciphertext) -> plaintext.
pub type KmsDecryptFn =
    Box<dyn Fn(&str, &[u8]) -> Result<String, ExtensionsError> + Send + Sync>;

/// A mock KMS provider for testing.
pub struct MockKmsProvider {
    /// The decryption function: (key_id, ciphertext) -> plaintext.
    decrypt_fn: KmsDecryptFn,
}

impl MockKmsProvider {
    /// Create a new mock KMS provider with the given decryption function.
    pub fn new<F>(f: F) -> Self
    where
        F: Fn(&str, &[u8]) -> Result<String, ExtensionsError> + Send + Sync + 'static,
    {
        Self {
            decrypt_fn: Box::new(f),
        }
    }

    /// Create a mock KMS provider that always returns the ciphertext
    /// as a string (for testing).
    pub fn passthrough() -> Self {
        Self::new(|_key, ct| {
            String::from_utf8(ct.to_vec())
                .map_err(|e| ExtensionsError::Backend(format!("KMS mock: {e}")))
        })
    }
}

#[async_trait]
impl KmsProvider for MockKmsProvider {
    async fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> Result<String, ExtensionsError> {
        (self.decrypt_fn)(key_id, ciphertext)
    }
}

/// A lease: a renewable handle to a dynamic secret.
///
/// Dynamic secrets (e.g. database credentials, AWS STS tokens) have
/// leases that must be renewed periodically. When the lease expires,
/// the secret is revoked.
#[derive(Clone, Debug)]
pub struct Lease {
    /// The lease ID (Vault's lease identifier).
    pub lease_id: String,
    /// The lease duration (seconds).
    pub lease_duration: u64,
    /// Whether the lease is renewable.
    pub renewable: bool,
}

/// A lease manager: tracks active leases and renews them.
pub struct LeaseManager {
    leases: RwLock<HashMap<String, Lease>>,
}

impl LeaseManager {
    /// Create a new lease manager.
    pub fn new() -> Self {
        Self {
            leases: RwLock::new(HashMap::new()),
        }
    }

    /// Register a lease for a secret name.
    pub fn register(&self, name: &str, lease: Lease) {
        let mut leases = self.leases.write().unwrap();
        leases.insert(name.to_string(), lease);
    }

    /// Get the lease for a secret name.
    pub fn get(&self, name: &str) -> Option<Lease> {
        let leases = self.leases.read().unwrap();
        leases.get(name).cloned()
    }

    /// Remove a lease (e.g. when the secret is revoked).
    pub fn revoke(&self, name: &str) -> Option<Lease> {
        let mut leases = self.leases.write().unwrap();
        leases.remove(name)
    }

    /// Get all leases that need renewal (duration < threshold).
    pub fn leases_needing_renewal(&self, threshold_secs: u64) -> Vec<(String, Lease)> {
        let leases = self.leases.read().unwrap();
        leases
            .iter()
            .filter(|(_, l)| l.renewable && l.lease_duration < threshold_secs)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// The number of active leases.
    pub fn lease_count(&self) -> usize {
        let leases = self.leases.read().unwrap();
        leases.len()
    }

    /// Renew a lease (placeholder: in a real implementation, this
    /// would call Vault's lease-renew API).
    pub async fn renew(&self, name: &str) -> Result<(), ExtensionsError> {
        let lease = self
            .get(name)
            .ok_or_else(|| ExtensionsError::Backend(format!("no lease for secret '{name}'")))?;
        if !lease.renewable {
            return Err(ExtensionsError::Backend(format!(
                "lease '{}' is not renewable",
                lease.lease_id
            )));
        }
        // In a real implementation, this would call:
        //   POST {vault_url}/v1/sys/leases/renew
        //   { "lease_id": "{lease_id}" }
        // and update the lease duration.
        Ok(())
    }
}

impl Default for LeaseManager {
    fn default() -> Self {
        Self::new()
    }
}

// White-box tests staying in src/ per AGENTS.md: the VaultSecretSource
// cache tests exercise private methods (`url`, `token`, `store_cached`,
// `get_cached`, `api_url`) that are not reachable from `tests/`. The
// KMS, LeaseManager, and redaction tests have been relocated to
// `tests/unit/vault_secrets.rs`.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_secret_source_construction() {
        let source = VaultSecretSource::new(
            "https://vault.example.com:8200/",
            "s.token",
            Duration::from_secs(300),
        );
        assert_eq!(source.url(), "https://vault.example.com:8200");
        assert_eq!(source.token(), "s.token");
        assert_eq!(source.cache_size(), 0);
    }

    #[test]
    fn vault_cache_store_and_get() {
        let source = VaultSecretSource::new(
            "https://vault.example.com:8200",
            "s.token",
            Duration::from_secs(300),
        );
        source.store_cached("secret/data/my-app", Secret::new("my-value"));
        assert_eq!(source.cache_size(), 1);

        let cached = source.get_cached("secret/data/my-app");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().expose(), "my-value");
    }

    #[test]
    fn vault_cache_expires() {
        let source = VaultSecretSource::new(
            "https://vault.example.com:8200",
            "s.token",
            Duration::from_millis(1),
        );
        source.store_cached("secret/data/my-app", Secret::new("my-value"));

        // Wait for the cache to expire.
        std::thread::sleep(Duration::from_millis(10));

        let cached = source.get_cached("secret/data/my-app");
        assert!(cached.is_none());
    }

    #[test]
    fn vault_cache_clear() {
        let source = VaultSecretSource::new(
            "https://vault.example.com:8200",
            "s.token",
            Duration::from_secs(300),
        );
        source.store_cached("secret/data/my-app", Secret::new("my-value"));
        assert_eq!(source.cache_size(), 1);
        source.clear_cache();
        assert_eq!(source.cache_size(), 0);
    }

    #[test]
    fn vault_api_url() {
        let source = VaultSecretSource::new(
            "https://vault.example.com:8200/",
            "s.token",
            Duration::from_secs(300),
        );
        assert_eq!(
            source.api_url("secret/data/my-app"),
            "https://vault.example.com:8200/v1/secret/data/my-app"
        );
    }

    #[tokio::test]
    async fn vault_resolve_returns_error_without_http() {
        let source = VaultSecretSource::new(
            "https://vault.example.com:8200",
            "s.token",
            Duration::from_secs(300),
        );
        let result = source.resolve("secret/data/my-app").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ExtensionsError::Backend(_)));
    }
}
