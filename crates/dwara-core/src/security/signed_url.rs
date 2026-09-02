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
//! The verifier is feature-gated behind the `signed_url` cargo
//! feature (default OFF). The config schema (`SignedUrlConfig` on
//! the route) is always present so configs round-trip without the
//! feature; when the feature is off, the block is accepted but inert
//! (validation warns, the runtime check does not run).
//!
//! ## Canonical request
//!
//! The canonical string signed by the HMAC is:
//!
//! ```text
//! <METHOD>\n<path>\n<expires>
//! ```
//!
//! Where `<METHOD>` is the uppercase HTTP method, `<path>` is the
//! request path (without query string), and `<expires>` is the
//! expiry timestamp as a Unix epoch seconds string. The signature is
//! the HMAC-SHA256 of this canonical string, hex-encoded.
//!
//! ## Query parameters
//!
//! The verifier extracts two query parameters:
//!
//! - `sig` (configurable via `query_param`): the hex-encoded
//!   HMAC-SHA256 signature.
//! - `expires`: the Unix epoch seconds timestamp at which the URL
//!   expires.
//!
//! ## Verification
//!
//! 1. Extract `sig` and `expires` from the query string.
//! 2. Check that `expires` is in the future (with optional clock
//!    skew tolerance).
//! 3. Recompute the HMAC-SHA256 over the canonical request.
//! 4. Compare the recomputed signature with the provided `sig` using
//!    a constant-time comparison.
//!
//! ## Integration point
//!
//! Signed URL verification runs as an authn method, before authz
//! (the request-path order positions it alongside API key / JWT /
//! HMAC request signing). A route with `signed_url.enabled: true`
//! requires a valid signature; a missing or invalid signature is
//! rejected with 401 `signed_url_invalid` or 401 `signed_url_expired`.

use hmac::{Hmac, Mac};
use sha2::Sha256;

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
}

fn default_ttl_seconds() -> u64 {
    300
}

fn default_query_param() -> String {
    "sig".to_string()
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
        Ok(Self {
            secret,
            query_param: config.query_param.clone(),
        })
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
    ///
    /// Returns [`SignedUrlResult::Valid`] if the signature matches
    /// and the URL has not expired; [`SignedUrlResult::Invalid`] if
    /// the signature is missing or does not match; [`SignedUrlResult::Expired`]
    /// if the URL has expired.
    pub fn verify(&self, method: &str, path: &str, query: &str, now: u64) -> SignedUrlResult {
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
        // Recompute the HMAC over the canonical request.
        let canonical = format!("{method}\n{path}\n{expires}");
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
    ///
    /// Returns the query string `"<query_param>=<sig>&expires=<expires>"`.
    pub fn sign(&self, method: &str, path: &str, expires: u64) -> Result<String, SignedUrlError> {
        let canonical = format!("{method}\n{path}\n{expires}");
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|_| SignedUrlError::InvalidSignature)?;
        mac.update(canonical.as_bytes());
        let sig = hex_encode(&mac.finalize().into_bytes());
        Ok(format!("{}={}&expires={}", self.query_param, sig, expires))
    }
}

impl std::fmt::Debug for SignedUrlVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedUrlVerifier")
            .field("query_param", &self.query_param)
            .field("secret_len", &self.secret.len())
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
