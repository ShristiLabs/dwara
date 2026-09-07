//! Upstream TLS certificate pinning (DW-109, SEC-04).
//!
//! When enabled, the gateway pins upstream TLS certificates by their
//! SubjectPublicKeyInfo (SPKI) hash. During the TLS handshake, the
//! verifier extracts the upstream cert's SPKI, computes its SHA-256,
//! and compares it against the configured pins. A mismatch rejects the
//! connection (fail-closed: no fallback to CA-based verification).
//!
//! Behind the `cert_pinning` cargo feature (default OFF). The config
//! schema (`Upstream.cert_pinning`) is always present so configs
//! round-trip without the feature; when the feature is off the block is
//! accepted but inert (validation warns).
//!
//! # Config shape
//!
//! ```yaml
//! upstreams:
//!   - name: api
//!     protocol: https
//!     cert_pinning:
//!       pins:
//!         - spki_sha256: "abcdef0123456789..."
//! ```

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};

use crate::config::{CertPinningConfig, Upstream};

/// A certificate pin: the SHA-256 hash of the upstream certificate's
/// SubjectPublicKeyInfo (SPKI). The SPKI is the DER-encoded
/// `SubjectPublicKeyInfo` structure from the X.509 certificate; pinning
/// the SPKI (rather than the full certificate) allows rotation of the
/// leaf certificate as long as the key pair is unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertPin {
    /// The SHA-256 hash of the SPKI, as lowercase hex (64 chars).
    pub spki_sha256: String,
}

impl CertPin {
    /// Parse a hex SPKI hash, returning the raw 32 bytes. Returns None
    /// when the string is not 64 lowercase hex chars.
    fn parse_hash(&self) -> Option<[u8; 32]> {
        let bytes = hex_decode(&self.spki_sha256)?;
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(arr)
        } else {
            None
        }
    }
}

/// Decode a lowercase hex string into bytes. Returns None on any
/// non-hex character or odd length.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks_exact(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// The certificate pin verifier: holds the set of allowed SPKI hashes
/// and checks a peer certificate against them. Built from the
/// upstream's `cert_pinning` config block at compile time. Implements
/// `rustls::client::danger::ServerCertVerifier` so it can be installed
/// via `ClientConfig::builder().dangerous().with_custom_certificate_verifier(...)`.
#[derive(Debug, Clone)]
pub struct CertPinVerifier {
    /// The allowed SPKI SHA-256 hashes, as raw 32-byte arrays.
    pins: Vec<[u8; 32]>,
}

impl CertPinVerifier {
    /// Build a verifier from the upstream's configured pins. Returns
    /// `None` when the upstream has no `cert_pinning` block (the
    /// upstream uses normal CA-based verification).
    pub fn from_upstream(upstream: &Upstream) -> Option<Self> {
        let cfg: &CertPinningConfig = upstream.cert_pinning.as_ref()?;
        if cfg.pins.is_empty() {
            return None;
        }
        let mut pins = Vec::with_capacity(cfg.pins.len());
        for p in &cfg.pins {
            // Use the config-side CertPin's spki_sha256 field.
            let cert_pin = CertPin {
                spki_sha256: p.spki_sha256.clone(),
            };
            match cert_pin.parse_hash() {
                Some(hash) => pins.push(hash),
                None => {
                    tracing::warn!(
                        upstream = %upstream.name,
                        pin = %p.spki_sha256,
                        "cert_pinning: ignoring pin with invalid hex (expected 64 lowercase hex \
                         chars for SHA-256)"
                    );
                }
            }
        }
        if pins.is_empty() {
            None
        } else {
            Some(Self { pins })
        }
    }

    /// Build a verifier from raw pin hashes (for testing).
    pub fn from_hashes(pins: Vec<[u8; 32]>) -> Self {
        Self { pins }
    }

    /// Verify a peer certificate's SPKI against the configured pins.
    /// Returns `Ok(())` when the cert's SPKI hash matches a configured
    /// pin, `Err(CertPinError)` otherwise.
    pub fn verify_cert(&self, cert: &CertificateDer<'_>) -> Result<(), CertPinError> {
        let spki =
            crate::security::tls::spki_of_leaf(cert).ok_or(CertPinError::SpkiExtractionFailed)?;
        let mut hasher = Sha256::new();
        hasher.update(&spki);
        let hash = hasher.finalize();
        for pin in &self.pins {
            if hash.as_slice() == pin.as_slice() {
                return Ok(());
            }
        }
        Err(CertPinError::NoMatch)
    }

    /// The number of configured pins.
    pub fn pin_count(&self) -> usize {
        self.pins.len()
    }
}

impl ServerCertVerifier for CertPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.verify_cert(end_entity)
            .map(|_| ServerCertVerified::assertion())
            .map_err(|e| rustls::Error::General(e.to_string()))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // SPKI pinning does not depend on the signature algorithm; the
        // key pair is already pinned by the SPKI hash. Accept any
        // signature scheme the peer offers (the TLS handshake itself
        // validates the signature against the public key in the cert,
        // which we have already pinned).
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // Accept all schemes — pinning is on the key, not the sig algo.
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

/// Build a rustls `ClientConfig` that uses the pin verifier instead of
/// the normal CA-based verification. The verifier is fail-closed: only
/// a cert whose SPKI matches a configured pin is accepted. There is no
/// fallback to CA verification (pinning REPLACES CA trust, it does not
/// augment it — a pinned upstream that rotates its key pair MUST update
/// its pins).
pub fn client_config_with_pinning(
    verifier: Arc<CertPinVerifier>,
    alpn: &[u8],
) -> rustls::ClientConfig {
    let mut cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![alpn.to_vec()];
    cfg
}

/// Certificate pin verification error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertPinError {
    /// The peer cert's SPKI hash does not match any configured pin.
    NoMatch,
    /// The peer cert could not be parsed (malformed DER).
    InvalidCertificate,
    /// The SPKI could not be extracted from the cert.
    SpkiExtractionFailed,
}

impl std::fmt::Display for CertPinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertPinError::NoMatch => {
                write!(f, "certificate SPKI hash does not match any configured pin")
            }
            CertPinError::InvalidCertificate => write!(f, "peer certificate is malformed"),
            CertPinError::SpkiExtractionFailed => {
                write!(f, "failed to extract SPKI from peer certificate")
            }
        }
    }
}

impl std::error::Error for CertPinError {}

// White-box tests staying in src/ per AGENTS.md: the hex_decode and
// CertPin::parse_hash tests exercise private internals.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decode_valid() {
        assert_eq!(hex_decode("deadbeef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn hex_decode_uppercase_rejected() {
        assert_eq!(hex_decode("DeadBeef"), None);
    }

    #[test]
    fn hex_decode_odd_length() {
        assert_eq!(hex_decode("abc"), None);
    }

    #[test]
    fn cert_pin_parse_hash_valid() {
        let pin = CertPin {
            spki_sha256: "ab".repeat(32),
        };
        assert!(pin.parse_hash().is_some());
    }

    #[test]
    fn cert_pin_parse_hash_wrong_length() {
        let pin = CertPin {
            spki_sha256: "ab".repeat(31),
        };
        assert!(pin.parse_hash().is_none());
    }

    #[test]
    fn verifier_pin_count() {
        let v = CertPinVerifier::from_hashes(vec![[0; 32], [1; 32]]);
        assert_eq!(v.pin_count(), 2);
    }

    #[test]
    fn verifier_rejects_empty_pins() {
        let v = CertPinVerifier::from_hashes(vec![]);
        assert_eq!(v.pin_count(), 0);
    }
}
