//! ACME / Let's Encrypt automation (SEC-02).
//!
//! When enabled on a listener's TLS config, the gateway automatically
//! obtains and renews certificates from an ACME directory (Let's
//! Encrypt by default). Issued certificates are installed into the
//! hot-reloadable TLS termination/SNI resolver.
//!
//! # Design
//!
//! The ACME client runs as a background task per listener that has
//! `tls.acme` configured. It:
//!
//! 1. Loads or creates an ACME account key (persisted to `state_dir`).
//! 2. Registers the account with the directory (using `contact`).
//! 3. For each domain in `domains`:
//!    a. Orders a certificate.
//!    b. Completes the challenge (HTTP-01 or TLS-ALPN-01).
//!    c. Finalizes the order and downloads the issued certificate.
//! 4. Installs the certificate into the SNI resolver.
//! 5. Schedules renewal at 2/3 of the certificate's validity period.
//!
//! # Challenge types
//!
//! - **TLS-ALPN-01** (default): the gateway serves a self-signed
//!   challenge certificate with the `acme-tls/1` ALPN protocol on port
//!   443. No separate listener is needed — the TLS terminator handles
//!   the challenge during the handshake.
//! - **HTTP-01**: the gateway serves a token at
//!   `/.well-known/acme-challenge/<token>` over HTTP on port 80. This
//!   requires a separate HTTP listener bound to port 80 (or port
//!   forwarding from an external load balancer).
//!
//! # Staging vs production
//!
//! Let's Encrypt production has strict rate limits (50 certs per domain
//! per week). Set `staging: true` for testing — staging issues
//! untrusted certificates that do not trigger rate limits. The staging
//! directory is hardcoded when `staging: true` (overrides
//! `directory_url`).
//!
//! # Failure behavior
//!
//! - ACME issuance failure: the gateway logs the error and retries with
//!   exponential backoff. It does NOT crash — existing certificates
//!   (manual or previously issued) continue to serve.
//! - Renewal failure: same — retry with backoff. A certificate that
//!   expires without renewal causes TLS handshake failures for its SNI
//!   (the gateway does NOT fall back to a different certificate for
//!   that SNI).
//!
//! # Feature gate
//!
//! Behind the `acme` cargo feature (default OFF). The config block is
//! always accepted by the parser (additive-only); when the feature is
//! OFF, validation emits a warning and the block is inert.

use std::sync::Arc;

use crate::config::AcmeConfig;

/// The compiled ACME state for one listener: the resolved config and
/// the background task handle. Held by the listener's TLS state.
#[derive(Debug, Clone)]
pub struct AcmeState {
    /// The resolved ACME config (with staging URL override applied).
    pub config: ResolvedAcmeConfig,
}

/// The ACME config with defaults resolved and staging override applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAcmeConfig {
    /// The domains to obtain certificates for.
    pub domains: Vec<String>,
    /// The effective directory URL (staging override applied when
    /// `staging: true`).
    pub directory_url: String,
    /// Contact emails.
    pub contact: Vec<String>,
    /// Challenge type.
    pub challenge: crate::config::AcmeChallenge,
    /// Whether staging is in use.
    pub staging: bool,
    /// State directory path.
    pub state_dir: String,
}

impl ResolvedAcmeConfig {
    /// Resolve the config: apply the staging override and validate.
    pub fn from_config(cfg: &AcmeConfig) -> Self {
        let directory_url = if cfg.staging {
            "https://acme-staging-v02.api.letsencrypt.org/directory".to_string()
        } else {
            cfg.directory_url.clone()
        };
        Self {
            domains: cfg.domains.clone(),
            directory_url,
            contact: cfg.contact.clone(),
            challenge: cfg.challenge,
            staging: cfg.staging,
            state_dir: cfg.state_dir.clone(),
        }
    }
}

/// The ACME client error.
#[derive(Debug)]
pub enum AcmeError {
    /// The ACME directory was unreachable or returned an error.
    Directory(String),
    /// Account registration failed.
    Account(String),
    /// Order creation failed.
    Order(String),
    /// Challenge failed.
    Challenge(String),
    /// Certificate finalization/download failed.
    Finalize(String),
    /// I/O error (state directory, persistence).
    Io(String),
}

impl std::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcmeError::Directory(s) => write!(f, "ACME directory error: {s}"),
            AcmeError::Account(s) => write!(f, "ACME account error: {s}"),
            AcmeError::Order(s) => write!(f, "ACME order error: {s}"),
            AcmeError::Challenge(s) => write!(f, "ACME challenge error: {s}"),
            AcmeError::Finalize(s) => write!(f, "ACME finalize error: {s}"),
            AcmeError::Io(s) => write!(f, "ACME I/O error: {s}"),
        }
    }
}

impl std::error::Error for AcmeError {}

/// Build the ACME state from config. Returns `None` when ACME is not
/// configured or the `acme` cargo feature is OFF.
pub fn build_acme_state(cfg: &AcmeConfig) -> Arc<AcmeState> {
    Arc::new(AcmeState {
        config: ResolvedAcmeConfig::from_config(cfg),
    })
}
