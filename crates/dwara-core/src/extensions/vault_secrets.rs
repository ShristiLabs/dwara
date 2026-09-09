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

/// Object-safe alias over the two transports a Vault fetch can run on
/// (`Box<dyn AsyncRead + AsyncWrite>` is not a legal trait object; an
/// alias trait with a blanket impl is the standard shape).
trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T> Io for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

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

        // SEC-10: Make the actual HTTP GET to Vault's KV v2 API.
        //   GET {url}/v1/{name}
        //   X-Vault-Token: {token}
        // The response JSON has the shape:
        //   { "data": { "data": { <key>: <value> }, "metadata": {...} } }
        // We extract the first string value from `data.data` (the
        // secret value). For multi-key secrets, the caller names the
        // key as `<mount>/<path>#<key>` and we extract that key.
        let url = self.api_url(name);
        let parsed: hyper::Uri = url
            .parse()
            .map_err(|e| ExtensionsError::Backend(format!("vault url parse: {e}")))?;
        let host = parsed
            .host()
            .ok_or_else(|| ExtensionsError::Backend("vault url has no host".to_string()))?;
        let port = parsed
            .port_u16()
            .unwrap_or(if parsed.scheme_str() == Some("https") {
                443
            } else {
                80
            });
        let path = parsed
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());

        // Build a simple HTTP/1.1 request. We use a raw TCP connection
        // to avoid pulling in a hyper client dependency (the vault
        // source is ent-gated and the HTTP call is simple enough to
        // hand-roll, matching the webhook deliverer's approach).
        let addr = format!("{host}:{port}");
        let use_tls = parsed.scheme_str() == Some("https");

        // Connect and read the response in a blocking fashion (this
        // is called from an async context; for simplicity we use
        // spawn_blocking internally via tokio's TCP. A future change
        // may use a pooled hyper client).
        let token = self.token.clone();
        let request_body = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nX-Vault-Token: {token}\r\nConnection: close\r\n\r\n"
        );

        // Use tokio's TCP + TLS for the connection.
        let response = fetch_vault_secret(&addr, use_tls, &request_body, host)
            .await
            .map_err(|e| ExtensionsError::Backend(format!("vault fetch: {e}")))?;

        // Parse the JSON response.
        let body_start = response
            .find("\r\n\r\n")
            .ok_or_else(|| ExtensionsError::Backend("vault response has no body".to_string()))?;
        let body = &response[body_start + 4..];

        let json: serde_json::Value = serde_json::from_str(body)
            .map_err(|e| ExtensionsError::Backend(format!("vault response parse: {e}")))?;

        // Navigate to data.data and extract the first string value.
        let data = json
            .get("data")
            .and_then(|d| d.get("data"))
            .ok_or_else(|| {
                ExtensionsError::Backend("vault response missing data.data".to_string())
            })?;

        // If the name has a #key suffix, extract that key; otherwise
        // take the first string value.
        let value = if let Some((_, key)) = name.rsplit_once('#') {
            data.get(key).and_then(|v| v.as_str()).ok_or_else(|| {
                ExtensionsError::Backend(format!("vault secret has no key '{key}'"))
            })?
        } else {
            data.as_object()
                .and_then(|obj| obj.values().find_map(|v| v.as_str()))
                .ok_or_else(|| {
                    ExtensionsError::Backend("vault secret has no string value".to_string())
                })?
        };

        let secret = Secret::new(value.to_string());
        self.store_cached(name, secret.clone());
        Ok(Some(secret))
    }
}

/// SEC-10: Fetch a secret from Vault over a raw TCP/TLS connection.
/// Hand-rolled HTTP/1.1 (same approach as the webhook deliverer) to
/// avoid pulling in a hyper client dependency. Returns the full
/// response string (headers + body).
async fn fetch_vault_secret(
    addr: &str,
    use_tls: bool,
    request: &str,
    host: &str,
) -> Result<String, String> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| format!("connect: {e}"))?;

    let mut io: Box<dyn Io> = if use_tls {
        // Use the same rustls config as the webhook deliverer (webpki
        // roots, no client auth). A future change may support a
        // custom CA for private Vault deployments.
        let name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| format!("server name: {e}"))?;
        let connector = tokio_rustls::TlsConnector::from(vault_tls_config());
        let tls = connector
            .connect(name, stream)
            .await
            .map_err(|e| format!("tls handshake: {e}"))?;
        Box::new(tls)
    } else {
        Box::new(stream)
    };

    io.write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;

    let mut response = Vec::new();
    io.read_to_end(&mut response)
        .await
        .map_err(|e| format!("read: {e}"))?;

    Ok(String::from_utf8_lossy(&response).to_string())
}

/// Build a rustls client config for Vault HTTPS (webpki roots, no
/// client auth). Reuses the same pattern as the webhook TLS config.
fn vault_tls_config() -> std::sync::Arc<rustls::ClientConfig> {
    use std::sync::OnceLock;
    static CONFIG: OnceLock<std::sync::Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut cfg = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            std::sync::Arc::new(cfg)
        })
        .clone()
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
pub type KmsDecryptFn = Box<dyn Fn(&str, &[u8]) -> Result<String, ExtensionsError> + Send + Sync>;

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
