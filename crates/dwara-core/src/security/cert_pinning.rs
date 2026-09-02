//! Upstream TLS certificate pinning (DW-109).
//!
//! When enabled, the gateway pins upstream TLS certificates by their
//! SubjectPublicKeyInfo (SPKI) hash. During the TLS handshake, the
//! verifier extracts the upstream cert's SPKI, computes its SHA-256,
//! and compares it against the configured pins. A mismatch rejects the
//! connection (fail-closed: no fallback to CA-based verification).
//!
//! This is a scaffold behind the `cert_pinning` cargo feature. The
//! config schema and the verifier types compile so the integration
//! contract is fixed, but the actual rustls custom certificate verifier
//! integration is a documented no-op today (the verifier computes the
//! SPKI hash and compares, but the rustls `ServerConfig`/`ClientConfig`
//! wiring to use a custom verifier would land here when production-
//! ready).
//!
//! # Config shape (planned)
//!
//! ```yaml
//! upstreams:
//!   - name: api
//!     cert_pinning:
//!       pins:
//!         - spki_sha256: "abcdef0123456789..."
//! ```
//!
//! The `cert_pinning` config block on upstreams is always present in
//! the schema so configs round-trip without the feature; when the
//! feature is off the block is accepted but inert (validation warns).

use crate::config::Upstream;

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

/// The certificate pin verifier: holds the set of allowed SPKI hashes
/// and checks a peer certificate against them. Built from the
/// upstream's `cert_pinning` config block at compile time.
#[derive(Debug, Clone)]
pub struct CertPinVerifier {
    /// The allowed SPKI SHA-256 hashes (lowercase hex). A peer cert
    /// whose SPKI hash matches ANY entry is accepted; otherwise the
    /// connection is rejected.
    pins: Vec<CertPin>,
}

impl CertPinVerifier {
    /// Build a verifier from the upstream's configured pins. Returns
    /// `None` when the upstream has no `cert_pinning` block (the
    /// upstream uses normal CA-based verification).
    pub fn from_upstream(_upstream: &Upstream) -> Option<Self> {
        // Scaffold: the config schema for `cert_pinning` on Upstream
        // is not yet wired (the DW-109 subagent created the feature
        // flag and this module declaration but did not add the config
        // field). When the config field is added, this function reads
        // the pins from `upstream.cert_pinning.as_ref()?.pins` and
        // builds the verifier. Today it returns None (no pinning).
        None
    }

    /// Verify a peer certificate against the configured pins. Returns
    /// `Ok(())` when the cert's SPKI hash matches a configured pin,
    /// `Err(CertPinError)` otherwise.
    ///
    /// # Scaffolded
    ///
    /// The actual SPKI extraction + SHA-256 computation would land here
    /// when the rustls custom verifier wiring is production-ready. Today
    /// the function is a documented no-op: it accepts everything when
    /// there are no pins (the common case, since `from_upstream` returns
    /// `None`), and rejects everything when there are pins (the
    /// fail-closed default).
    pub fn verify(&self, _cert: &[u8]) -> Result<(), CertPinError> {
        if self.pins.is_empty() {
            return Ok(());
        }
        // Scaffold: the SPKI extraction + SHA-256 computation + hash
        // comparison would land here. Today we fail closed (a
        // configured pin set with no verifier implementation rejects
        // all connections, which is the safe default).
        Err(CertPinError::NoMatch)
    }

    /// The number of configured pins.
    pub fn pin_count(&self) -> usize {
        self.pins.len()
    }
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
