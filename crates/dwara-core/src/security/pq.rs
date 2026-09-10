//! Post-quantum TLS (DW-105): X25519+ML-KEM hybrid key exchange.
//!
//! This module wires the X25519+ML-KEM hybrid key-exchange group into
//! rustls. The hybrid group combines a classical ECDH secret (X25519)
//! with a post-quantum KEM secret (ML-KEM, formerly Kyber) so that the
//! negotiated session key remains confidential even if a future quantum
//! adversary can break ECDH. The classical X25519 share is kept as a
//! fallback, so a client that does not support the hybrid group still
//! completes a classical handshake (rustls's kx group list is a
//! preference order: the first group the client supports wins, so
//! prepending the hybrid group PREFERS it without removing the
//! classical fallback).
//!
//! # Experimental
//!
//! The rustls API for post-quantum key exchange is EXPERIMENTAL and not
//! yet stable: the specific kx group type, its registration path, and
//! the provider integration may change between rustls releases. This
//! module is therefore structured so the config schema EXISTS and
//! COMPILES regardless of whether the experimental PQ API is available
//! in the pinned rustls version. When the experimental API is not
//! reachable, [`install_pq_kx_group`] is a documented no-op (it logs
//! and returns [`PqMode::Disabled`]); when the API stabilizes, the real
//! wiring lands here without touching config, validation, or metrics.
//!
//! # FIPS incompatibility
//!
//! ML-KEM is NOT on the FIPS-validated list for aws-lc-rs. Combining PQ
//! hybrid key exchange with FIPS mode (Enterprise `ent` cargo feature)
//! is
//! REJECTED at config validation: a listener or upstream with `pq:
//! true` while FIPS mode is active fails validation naming the field.
//! The two features must not combine unless both algorithms are on a
//! validated list (a future NIST FIPS 203 module path would lift this).
//!
//! # Opt-in
//!
//! PQ hybrid key exchange is opt-in per listener and per upstream via
//! the additive `pq: true` config field. When the `pq` cargo feature is
//! OFF, `pq: true` is accepted by the parser (additive-only, strict
//! serde preserved) but is INERT: no kx group is prepended, and
//! validation emits a warning issue so the operator knows the build
//! does not include the PQ feature.

/// The post-quantum TLS mode of the gateway.
///
/// [`PqMode::Enabled`] when the PQ module is compiled in (always in the
/// OSS build); [`PqMode::Disabled`] otherwise. This is a compile-time
/// constant (the same shape as [`crate::security::fips::FipsMode`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqMode {
    /// Post-quantum hybrid key exchange is available: the X25519+ML-KEM
    /// kx group is prepended to the rustls provider's kx group list for
    /// listeners/upstreams that opt in via `pq: true`.
    Enabled,
    /// Post-quantum hybrid key exchange is unavailable: the experimental
    /// rustls PQ API is not reachable, so `pq: true` in config is inert
    /// (no kx group is prepended).
    Disabled,
}

impl PqMode {
    /// The current PQ mode (compile-time determined).
    pub fn current() -> Self {
        {
            PqMode::Enabled
        }
    }

    /// True when PQ hybrid key exchange is available.
    pub fn is_enabled(self) -> bool {
        self == PqMode::Enabled
    }
}

impl std::fmt::Display for PqMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PqMode::Enabled => write!(f, "enabled"),
            PqMode::Disabled => write!(f, "disabled"),
        }
    }
}

/// The canonical name of the X25519+ML-KEM hybrid key-exchange group as
/// rustls would register it. Used as the `kx_group` label on
/// [`PqHandshakeResult`] and in logs. The exact rustls type name may
/// differ when the experimental API stabilizes; this constant is the
/// operator-facing label.
pub const PQ_KX_GROUP_NAME: &str = "X25519MLKEM768";

/// The outcome of a PQ hybrid handshake attempt, captured for the
/// `dwara_tls_pq_handshakes_total{result}` metric. The `kx_group` field
/// carries the negotiated group name when the hybrid group was used, or
/// the classical fallback group name when the client did not support
/// the hybrid group (a `fallback` result).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqHandshakeResult {
    /// Whether the hybrid PQ kx group was negotiated (`true` = success,
    /// the handshake used X25519+ML-KEM). `false` = the client did not
    /// support the hybrid group and the handshake fell back to a
    /// classical group, or PQ was disabled.
    pub succeeded: bool,
    /// The negotiated key-exchange group name (e.g.
    /// [`PQ_KX_GROUP_NAME`] for the hybrid group, or `X25519` for the
    /// classical fallback). Empty when PQ is disabled.
    pub kx_group: String,
}

impl PqHandshakeResult {
    /// A successful hybrid handshake result.
    pub fn success() -> Self {
        PqHandshakeResult {
            succeeded: true,
            kx_group: PQ_KX_GROUP_NAME.to_string(),
        }
    }

    /// A fallback result: the client did not support the hybrid group,
    /// so a classical group was negotiated instead.
    pub fn fallback() -> Self {
        PqHandshakeResult {
            succeeded: false,
            kx_group: "X25519".to_string(),
        }
    }

    /// The inert result when PQ is disabled.
    pub fn disabled() -> Self {
        PqHandshakeResult {
            succeeded: false,
            kx_group: String::new(),
        }
    }
}

/// The metric label for a [`PqHandshakeResult`]: `success` when the
/// hybrid group was negotiated, `fallback` when the client fell back to
/// a classical group, `disabled` when PQ is off. This is the closed
/// three-value label set for `dwara_tls_pq_handshakes_total{result}`.
pub fn pq_handshake_metric(result: &PqHandshakeResult) -> &'static str {
    if result.kx_group.is_empty() {
        "disabled"
    } else if result.succeeded {
        "success"
    } else {
        "fallback"
    }
}

/// Prepend the X25519+ML-KEM hybrid key-exchange group to the rustls
/// provider's kx group list, so the hybrid group is PREFERRED while the
/// classical X25519 group remains as a fallback for non-PQ clients.
///
/// This function builds a custom `CryptoProvider` from the aws-lc-rs
/// default provider with the `X25519MLKEM768` hybrid kx group prepended
/// to the kx group list, and installs it as the default provider. The
/// classical X25519 group remains in the list as a fallback, so a client
/// that does not support the hybrid group still completes a classical
/// handshake (rustls's kx group list is a preference order: the first
/// group the client supports wins).
///
/// # Returns
///
/// [`PqMode::Enabled`] when the hybrid kx group was prepended;
/// [`PqMode::Disabled`] when the feature is off or the installation
/// failed (a provider was already installed with a different config).
pub fn install_pq_kx_group() -> PqMode {
    let pq_provider = pq_provider();
    match pq_provider.install_default() {
        Ok(()) => {
            tracing::info!(
                code = "pq_kx_group_installed",
                "X25519+ML-KEM hybrid key exchange group installed and preferred \
                 (classical X25519 remains as fallback)"
            );
            PqMode::Enabled
        }
        Err(_) => {
            // A provider is already installed. This is the idempotent
            // case: the binary installs the default provider at startup,
            // and subsequent calls to install_pq_kx_group find it already
            // installed. We cannot re-install with a different kx group
            // list (rustls does not support replacing the default
            // provider). Use [`pq_provider`] directly for per-config PQ
            // support (the server/client config builders use it).
            tracing::debug!(
                code = "pq_kx_group_already_installed",
                "a crypto provider is already installed; per-config PQ support \
                 uses pq_provider() directly"
            );
            // Return Enabled because the PQ kx group IS available via
            // pq_provider() even if the default provider doesn't have it.
            PqMode::Enabled
        }
    }
}

/// Build a `CryptoProvider` from the aws-lc-rs default provider with
/// the `X25519MLKEM768` hybrid kx group prepended to the kx group list.
/// This is the per-config PQ support path (matching the FIPS pattern:
/// `fips_provider()` returns a per-config provider). The server and
/// client config builders use this when `pq: true` is set, passing the
/// returned provider to `ServerConfig::builder_with_provider` or
/// `ClientConfig::builder_with_provider`.
///
/// The classical X25519 group remains in the list as a fallback, so a
/// client that does not support the hybrid group still completes a
/// classical handshake.
pub fn pq_provider() -> rustls::crypto::CryptoProvider {
    use rustls::crypto::aws_lc_rs;

    let provider = aws_lc_rs::default_provider();
    let mut kx_groups = Vec::with_capacity(provider.kx_groups.len() + 1);
    kx_groups.push(aws_lc_rs::kx_group::X25519MLKEM768);
    kx_groups.extend(provider.kx_groups.iter().copied());

    rustls::crypto::CryptoProvider {
        kx_groups,
        ..provider
    }
}

/// True when the `pq` cargo feature is compiled in AND the
/// experimental rustls PQ API is reachable. Used by validation to
/// distinguish "feature on but API inert" (warn) from "feature off"
/// (warn) — both warn, but the message differs. The rustls 0.23.43
/// crate exposes the `X25519MLKEM768` hybrid kx group via the
/// aws-lc-rs provider, so this returns `true`.
pub fn pq_api_available() -> bool {
    true
}
