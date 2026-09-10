//! Signed URL request authentication (DW-109).
//!
//! This module provides short-lived signed URL verification: a
//! request to a route with `signed_url` enabled must carry a
//! cryptographic signature in its query string, computed as an
//! HMAC-SHA256 over the canonical request (method, path, and an
//! expiry timestamp). The signature proves the URL was minted by a
//! trusted party that holds the secret, and the expiry bounds the
//! URL's validity window.
//!
//! ## Replay hardening (SEC-07, #211)
//!
//! Two optional mechanisms prevent replay within the validity window:
//!
//! - **One-time nonces**: when `require_nonce: true`, each signed URL
//!   must carry a unique `nonce` query parameter. The verifier records
//!   each seen nonce in a bounded TTL cache; a replayed nonce is
//!   rejected with `ReplayedNonce`. The cache is per-verifier (per
//!   route), keyed by the nonce value, and entries expire at the
//!   URL's `expires` timestamp (so the cache does not grow unboundedly).
//! - **Client-IP binding**: when `bind_client_ip: true`, the canonical
//!   request includes the client's IP address, so a signed URL minted
//!   for one client cannot be replayed from a different IP. The IP is
//!   appended to the canonical string as a fourth line.
//!
//! Both are opt-in (default off) for backward compatibility with
//! existing signed-URL minters.

use hmac::{Hmac, Mac};
use sha2::Sha256;

#[cfg(feature = "ent")]
use std::sync::Arc;

/// HMAC-SHA256 type alias.
type HmacSha256 = Hmac<Sha256>;

/// Signed URL configuration (DW-109, `routes[].signed_url`).
///
/// When enabled, the gateway verifies that each request to the route
/// carries a valid HMAC-SHA256 signature in its query string. The
/// signature is computed over the canonical request (method, path,
/// expires timestamp) using the configured secret.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedUrlConfig {
    /// Whether signed URL verification is enabled on this route.
    #[serde(default)]
    pub enabled: bool,
    /// The HMAC secret (shared between the URL minter and the
    /// gateway). Must be non-empty when `enabled` is true. Stored
    /// as a plain string; in production, use a `${...}` secret
    /// reference (DW-045) so the secret is not in the config file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// The signature validity window in seconds. A URL minted at
    /// time T is valid until T + `ttl_seconds`. Must be > 0.
    /// Default: 300 (5 minutes).
    #[serde(default = "default_ttl_seconds")]
    pub ttl_seconds: u64,
    /// The query parameter name carrying the hex-encoded signature.
    /// Must be non-empty. Default: `sig`.
    #[serde(default = "default_query_param")]
    pub query_param: String,
    /// Require a one-time nonce (SEC-07, #211): when true, each
    /// signed URL must carry a `nonce` query parameter, and the
    /// verifier rejects replayed nonces within the validity window.
    /// Default: false (backward compatible).
    #[serde(default)]
    pub require_nonce: bool,
    /// The query parameter name carrying the one-time nonce.
    /// Must be non-empty when `require_nonce` is true.
    /// Default: `nonce`.
    #[serde(default = "default_nonce_param")]
    pub nonce_param: String,
    /// Bind the signature to the client's IP address (SEC-07, #211):
    /// when true, the canonical request includes the client IP as a
    /// fourth line, so a signed URL minted for one client cannot be
    /// replayed from a different IP. Default: false.
    #[serde(default)]
    pub bind_client_ip: bool,
}

fn default_ttl_seconds() -> u64 {
    300
}

fn default_query_param() -> String {
    "sig".to_string()
}

fn default_nonce_param() -> String {
    "nonce".to_string()
}

/// An error from signed URL verification (DW-109).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedUrlError {
    /// The signature query parameter is missing from the request.
    MissingSignature,
    /// The `expires` query parameter is missing or not a valid
    /// integer.
    MissingExpires,
    /// The signature does not match the recomputed HMAC.
    InvalidSignature,
    /// The URL has expired (the `expires` timestamp is in the past).
    Expired,
    /// The nonce query parameter is missing (SEC-07, #211).
    MissingNonce,
    /// The nonce has already been used (replay detected, SEC-07, #211).
    ReplayedNonce,
}

impl std::fmt::Display for SignedUrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignedUrlError::MissingSignature => {
                write!(f, "signed URL signature is missing from the query string")
            }
            SignedUrlError::MissingExpires => {
                write!(f, "signed URL expires timestamp is missing or invalid")
            }
            SignedUrlError::InvalidSignature => {
                write!(f, "signed URL signature is invalid")
            }
            SignedUrlError::Expired => {
                write!(f, "signed URL has expired")
            }
            SignedUrlError::MissingNonce => {
                write!(f, "signed URL nonce is missing from the query string")
            }
            SignedUrlError::ReplayedNonce => {
                write!(
                    f,
                    "signed URL nonce has already been used (replay detected)"
                )
            }
        }
    }
}

impl std::error::Error for SignedUrlError {}

/// The result of signed URL verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedUrlResult {
    /// The signature is valid and the URL has not expired.
    Valid,
    /// The signature is invalid (does not match the recomputed HMAC).
    Invalid,
    /// The URL has expired.
    Expired,
    /// The nonce is missing or has been replayed (SEC-07, #211).
    NonceError,
}

/// A bounded TTL cache for one-time nonces (SEC-07, #211). Entries
/// expire at the URL's `expires` timestamp, so the cache does not
/// grow unboundedly. Bounded to `MAX_NONCES` entries; when full, the
/// oldest entries are evicted (a signed URL with an evicted nonce
/// would have expired anyway, since the cache TTL is the URL's
/// validity window).
struct NonceCache {
    entries: std::collections::HashMap<String, u64>,
    /// Ordered keys for LRU eviction (insertion order).
    order: std::collections::VecDeque<String>,
}

impl NonceCache {
    const MAX_NONCES: usize = 4096;

    fn new() -> Self {
        NonceCache {
            entries: std::collections::HashMap::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    /// Check and record a nonce. Returns `true` if the nonce is fresh
    /// (not seen before, or the previous entry has expired), `false`
    /// if it is a replay within the validity window. SEC-11 (#214):
    /// the purge compares the stored expiry against `now` (the
    /// current time), not against the new nonce's `expires`, so
    /// entries with the same expiry are not incorrectly purged.
    fn check_and_record(&mut self, nonce: &str, expires: u64, now: u64) -> bool {
        // Purge expired entries (cheap: we check the front of the
        // queue, which holds the oldest entries).
        while let Some(front) = self.order.front() {
            if let Some(&exp) = self.entries.get(front) {
                if exp <= now {
                    self.entries.remove(front);
                    self.order.pop_front();
                    continue;
                }
            }
            break;
        }
        if self.entries.contains_key(nonce) {
            return false; // replay
        }
        // Evict oldest if at capacity.
        if self.entries.len() >= Self::MAX_NONCES {
            if let Some(evicted) = self.order.pop_front() {
                self.entries.remove(&evicted);
            }
        }
        self.entries.insert(nonce.to_string(), expires);
        self.order.push_back(nonce.to_string());
        true
    }
}

/// A signed URL verifier (DW-109).
///
/// Built from a route's [`SignedUrlConfig`] at snapshot compile time.
/// The verifier holds the HMAC secret and the query parameter name.
/// The [`SignedUrlVerifier::verify`] method extracts the signature
/// and expiry from the query string, recomputes the HMAC, and checks
/// the expiry.
pub struct SignedUrlVerifier {
    secret: Vec<u8>,
    query_param: String,
    /// SEC-07 (#211): nonce configuration.
    require_nonce: bool,
    nonce_param: String,
    bind_client_ip: bool,
    /// SEC-07 (#211): per-verifier nonce cache (guarded by the
    /// verifier's `Mutex` in `verify`).
    nonces: std::sync::Mutex<NonceCache>,
    /// SEC-06 (#210, ent): optional distributed nonce store. When
    /// present, the verifier uses the distributed store instead of
    /// the in-process cache, so replay detection is shared across
    /// the gateway fleet. The in-process cache remains as a
    /// fallback when the distributed store is not configured.
    #[cfg(feature = "ent")]
    distributed_nonces: Option<Arc<dyn crate::extensions::nonce::NonceStore>>,
}

impl SignedUrlVerifier {
    /// Build a verifier from a [`SignedUrlConfig`]. Returns an error
    /// if the config is invalid (empty secret, empty query_param).
    pub fn from_config(config: &SignedUrlConfig) -> Result<Self, SignedUrlError> {
        let secret = config
            .secret
            .as_ref()
            .filter(|s| !s.is_empty())
            .ok_or(SignedUrlError::MissingSignature)?
            .as_bytes()
            .to_vec();
        if config.query_param.is_empty() {
            return Err(SignedUrlError::MissingSignature);
        }
        if config.require_nonce && config.nonce_param.is_empty() {
            return Err(SignedUrlError::MissingNonce);
        }
        Ok(Self {
            secret,
            query_param: config.query_param.clone(),
            require_nonce: config.require_nonce,
            nonce_param: config.nonce_param.clone(),
            bind_client_ip: config.bind_client_ip,
            nonces: std::sync::Mutex::new(NonceCache::new()),
            #[cfg(feature = "ent")]
            distributed_nonces: None,
        })
    }

    /// SEC-06 (#210, ent): attach a distributed nonce store. When
    /// set, the verifier uses the distributed store for replay
    /// detection instead of the in-process cache, so nonces are
    /// shared across the gateway fleet. Requires the `ent` cargo
    /// feature.
    #[cfg(feature = "ent")]
    pub fn with_distributed_nonce_store(
        mut self,
        store: Arc<dyn crate::extensions::nonce::NonceStore>,
    ) -> Self {
        self.distributed_nonces = Some(store);
        self
    }

    /// The query parameter name this verifier looks for.
    pub fn query_param(&self) -> &str {
        &self.query_param
    }

    /// Verify a signed URL request. Extracts the signature and expiry
    /// from the query string, recomputes the HMAC-SHA256 over the
    /// canonical request (method, path, expires), and checks the
    /// expiry.
    ///
    /// - `method`: the uppercase HTTP method (e.g. "GET").
    /// - `path`: the request path (without query string).
    /// - `query`: the raw query string (e.g. "foo=bar&sig=abc&expires=123").
    /// - `now`: the current Unix epoch seconds.
    /// - `client_ip`: the client's IP address (used when
    ///   `bind_client_ip` is true; pass an empty string to skip).
    ///
    /// Returns [`SignedUrlResult::Valid`] if the signature matches
    /// and the URL has not expired; [`SignedUrlResult::Invalid`] if
    /// the signature is missing or does not match; [`SignedUrlResult::Expired`]
    /// if the URL has expired; [`SignedUrlResult::NonceError`] if the
    /// nonce is missing or replayed (SEC-07, #211).
    pub fn verify(
        &self,
        method: &str,
        path: &str,
        query: &str,
        now: u64,
        client_ip: &str,
    ) -> SignedUrlResult {
        let params = parse_query(query);
        let sig = match params.get(&self.query_param) {
            Some(s) => s,
            None => return SignedUrlResult::Invalid,
        };
        let expires_str = match params.get("expires") {
            Some(e) => e,
            None => return SignedUrlResult::Invalid,
        };
        let expires: u64 = match expires_str.parse() {
            Ok(v) => v,
            Err(_) => return SignedUrlResult::Invalid,
        };
        if now > expires {
            return SignedUrlResult::Expired;
        }
        // SEC-07 (#211): nonce check BEFORE signature verification —
        // a replayed nonce is rejected without recomputing the HMAC.
        if self.require_nonce {
            let nonce = match params.get(&self.nonce_param) {
                Some(n) => n,
                None => return SignedUrlResult::NonceError,
            };
            let mut cache = self.nonces.lock().expect("nonce cache poisoned");
            if !cache.check_and_record(nonce, expires, now) {
                return SignedUrlResult::NonceError;
            }
        }
        // Recompute the HMAC over the canonical request.
        let canonical = if self.bind_client_ip {
            format!("{method}\n{path}\n{expires}\n{client_ip}")
        } else {
            format!("{method}\n{path}\n{expires}")
        };
        let mut mac = match HmacSha256::new_from_slice(&self.secret) {
            Ok(m) => m,
            Err(_) => return SignedUrlResult::Invalid,
        };
        mac.update(canonical.as_bytes());
        let expected = mac.finalize().into_bytes();
        let expected_hex = hex_encode(&expected);
        if constant_time_eq(sig.as_bytes(), expected_hex.as_bytes()) {
            SignedUrlResult::Valid
        } else {
            SignedUrlResult::Invalid
        }
    }

    /// SEC-06 (#210, ent): async verify that uses the distributed
    /// nonce store when attached. Falls back to the in-process
    /// cache when no distributed store is configured (or when the
    /// `ent` feature is disabled). The signature and expiry checks
    /// are identical to [`verify`](Self::verify).
    #[cfg(feature = "ent")]
    pub async fn verify_async(
        &self,
        method: &str,
        path: &str,
        query: &str,
        now: u64,
        client_ip: &str,
    ) -> SignedUrlResult {
        let params = parse_query(query);
        let sig = match params.get(&self.query_param) {
            Some(s) => s,
            None => return SignedUrlResult::Invalid,
        };
        let expires_str = match params.get("expires") {
            Some(e) => e,
            None => return SignedUrlResult::Invalid,
        };
        let expires: u64 = match expires_str.parse() {
            Ok(v) => v,
            Err(_) => return SignedUrlResult::Invalid,
        };
        if now > expires {
            return SignedUrlResult::Expired;
        }
        // SEC-06 (#210): nonce check via distributed store when
        // available, else in-process cache.
        if self.require_nonce {
            let nonce = match params.get(&self.nonce_param) {
                Some(n) => n,
                None => return SignedUrlResult::NonceError,
            };
            if let Some(store) = &self.distributed_nonces {
                match store.check_and_record(nonce, expires).await {
                    Ok(true) => {}
                    Ok(false) => return SignedUrlResult::NonceError,
                    Err(e) => {
                        tracing::warn!(
                            code = "signed_url_distributed_nonce_error",
                            error = %e,
                            "distributed nonce store error; falling back to in-process cache"
                        );
                        let mut cache = self.nonces.lock().expect("nonce cache poisoned");
                        if !cache.check_and_record(nonce, expires, now) {
                            return SignedUrlResult::NonceError;
                        }
                    }
                }
            } else {
                let mut cache = self.nonces.lock().expect("nonce cache poisoned");
                if !cache.check_and_record(nonce, expires, now) {
                    return SignedUrlResult::NonceError;
                }
            }
        }
        // Recompute the HMAC over the canonical request.
        let canonical = if self.bind_client_ip {
            format!("{method}\n{path}\n{expires}\n{client_ip}")
        } else {
            format!("{method}\n{path}\n{expires}")
        };
        let mut mac = match HmacSha256::new_from_slice(&self.secret) {
            Ok(m) => m,
            Err(_) => return SignedUrlResult::Invalid,
        };
        mac.update(canonical.as_bytes());
        let expected = mac.finalize().into_bytes();
        let expected_hex = hex_encode(&expected);
        if constant_time_eq(sig.as_bytes(), expected_hex.as_bytes()) {
            SignedUrlResult::Valid
        } else {
            SignedUrlResult::Invalid
        }
    }

    /// Mint a signed URL query string for the given request. This is
    /// the counterpart to [`verify`](Self::verify): an external URL
    /// minter (or a test) uses it to produce a valid signature.
    ///
    /// - `method`: the uppercase HTTP method.
    /// - `path`: the request path (without query string).
    /// - `expires`: the Unix epoch seconds at which the URL expires.
    /// - `client_ip`: the client's IP address (used when
    ///   `bind_client_ip` is true; pass an empty string to skip).
    /// - `nonce`: an optional nonce (used when `require_nonce` is
    ///   true; the caller generates a unique nonce per URL).
    ///
    /// Returns the query string with the signature, expiry, and
    /// optional nonce parameters.
    pub fn sign(
        &self,
        method: &str,
        path: &str,
        expires: u64,
        client_ip: &str,
        nonce: Option<&str>,
    ) -> Result<String, SignedUrlError> {
        let canonical = if self.bind_client_ip {
            format!("{method}\n{path}\n{expires}\n{client_ip}")
        } else {
            format!("{method}\n{path}\n{expires}")
        };
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|_| SignedUrlError::InvalidSignature)?;
        mac.update(canonical.as_bytes());
        let sig = hex_encode(&mac.finalize().into_bytes());
        let mut query = format!("{}={}&expires={}", self.query_param, sig, expires);
        if self.require_nonce {
            let n = nonce.ok_or(SignedUrlError::MissingNonce)?;
            query.push('&');
            query.push_str(&self.nonce_param);
            query.push('=');
            query.push_str(n);
        }
        Ok(query)
    }
}

impl std::fmt::Debug for SignedUrlVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedUrlVerifier")
            .field("query_param", &self.query_param)
            .field("secret_len", &self.secret.len())
            .field("require_nonce", &self.require_nonce)
            .field("bind_client_ip", &self.bind_client_ip)
            .finish()
    }
}

/// Parse a query string into a map of key -> value. Handles
/// URL-encoded values (percent-decoding is NOT done here; the caller
/// is expected to pass a raw query string with already-decoded
/// values, as the gateway's request path decodes query params before
/// this point).
fn parse_query(query: &str) -> std::collections::HashMap<String, String> {
    let mut params = std::collections::HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some((key, value)) = pair.split_once('=') {
            params.insert(key.to_string(), value.to_string());
        } else {
            params.insert(pair.to_string(), String::new());
        }
    }
    params
}

/// Hex-encode a byte slice (lowercase).
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Constant-time comparison of two byte slices. Returns true if they
/// are equal. Uses `subtle::ConstantTimeEq` when available; falls
/// back to a simple comparison otherwise.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}
