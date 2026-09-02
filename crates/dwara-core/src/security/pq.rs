//! Post-quantum TLS (DW-105): X25519+ML-KEM hybrid key exchange.
//!
//! This module wires the X25519+ML-KEM hybrid key-exchange group into
//! rustls, behind the experimental `pq` cargo feature. The hybrid group
//! combines a classical ECDH secret (X25519) with a post-quantum KEM
//! secret (ML-KEM, formerly Kyber) so that the negotiated session key
//! remains confidential even if a future quantum adversary can break
//! ECDH. The classical X25519 share is kept as a fallback, so a client
//! that does not support the hybrid group still completes a classical
//! handshake (rustls's kx group list is a preference order: the first
//! group the client supports wins, so prepending the hybrid group
//! PREFERS it without removing the classical fallback).
//!
//! # Experimental
//!
//! The rustls API for post-quantum key exchange is EXPERIMENTAL and not
//! yet stable: the specific kx group type, its registration path, and
//! the provider integration may change between rustls releases. This
//! module is therefore structured so the feature gate and config schema
//! EXIST and COMPILE regardless of whether the experimental PQ API is
//! available in the pinned rustls version. When the `pq` feature is ON
//! but the experimental API is not reachable, [`install_pq_kx_group`]
//! is a documented no-op (it logs and returns [`PqMode::Disabled`]);
//! when the API stabilizes, the real wiring lands here without touching
//! config, validation, or metrics.
//!
//! # FIPS incompatibility
//!
//! ML-KEM is NOT on the FIPS-validated list for aws-lc-rs. Combining PQ
//! hybrid key exchange with FIPS mode (`fips` cargo feature) is
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
/// [`PqMode::Enabled`] when the `pq` cargo feature is compiled in;
/// [`PqMode::Disabled`] otherwise. This is a compile-time constant:
/// the feature is a build-time switch, not a runtime toggle (the same
/// shape as [`crate::security::fips::FipsMode`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqMode {
    /// Post-quantum hybrid key exchange is available: the X25519+ML-KEM
    /// kx group is prepended to the rustls provider's kx group list for
    /// listeners/upstreams that opt in via `pq: true`.
    Enabled,
    /// Post-quantum hybrid key exchange is unavailable: the `pq` cargo
    /// feature is off, so `pq: true` in config is inert (no kx group
    /// manipulation, validation warns).
    Disabled,
}

impl PqMode {
    /// The current PQ mode (compile-time determined).
    pub fn current() -> Self {
        #[cfg(feature = "pq")]
        {
            PqMode::Enabled
        }
        #[cfg(not(feature = "pq"))]
        {
            PqMode::Disabled
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
/// When the `pq` cargo feature is ON, this is the wiring point for the
/// experimental rustls PQ API. The rustls PQ API is not yet stable: the
/// specific kx group type and its registration path may change between
/// releases. This function is structured so it COMPILES regardless of
/// whether the experimental API is reachable in the pinned rustls
/// version. When the API is not available, the function is a documented
/// no-op: it logs a warning and returns [`PqMode::Disabled`] so the
/// caller treats the config as inert. When the API stabilizes, the real
/// kx group construction lands here without touching config, validation,
/// or metrics.
///
/// When the `pq` cargo feature is OFF, this is a no-op that returns
/// [`PqMode::Disabled`] (the caller never calls it when the feature is
/// off, but the inert return keeps the contract safe).
///
/// # Returns
///
/// [`PqMode::Enabled`] when the hybrid kx group was prepended;
/// [`PqMode::Disabled`] when the feature is off or the experimental API
/// is not available.
pub fn install_pq_kx_group() -> PqMode {
    #[cfg(feature = "pq")]
    {
        // The rustls PQ API for X25519+ML-KEM is experimental. The
        // aws-lc-rs provider does not yet expose a stable named kx
        // group for the hybrid construction in the pinned rustls
        // version. When the API stabilizes (a rustls release that
        // exposes the hybrid kx group type), the real wiring lands
        // here: construct the hybrid group, prepend it to the
        // provider's kx_groups vector, and return PqMode::Enabled.
        //
        // Until then, this is a documented no-op: the feature gate and
        // config schema exist and compile, validation enforces the
        // FIPS-incompatibility rule, and the metric records `disabled`.
        // An operator who builds with `--features pq` and sets `pq:
        // true` sees a warning log explaining the build is ahead of the
        // stable API; the handshake proceeds with the classical kx
        // group list (no regression — the default rustls behavior).
        tracing::warn!(
            code = "pq_kx_group_experimental",
            "the `pq` cargo feature is ON but the rustls X25519+ML-KEM hybrid kx group API is \
             not yet stable in the pinned rustls version; PQ hybrid key exchange is inert \
             (handshakes use the classical kx group list). This will activate when the rustls \
             PQ API stabilizes."
        );
        PqMode::Disabled
    }

    #[cfg(not(feature = "pq"))]
    {
        PqMode::Disabled
    }
}

/// True when the `pq` cargo feature is compiled in AND the
/// experimental rustls PQ API is reachable. Used by validation to
/// distinguish "feature on but API inert" (warn) from "feature off"
/// (warn) — both warn, but the message differs. Today this always
/// returns `false` because the experimental API is not wired; when the
/// API stabilizes, this returns `true` under `#[cfg(feature = "pq")]`.
pub fn pq_api_available() -> bool {
    // The experimental rustls PQ API is not yet reachable in the pinned
    // version. When it stabilizes, this becomes `true` under
    // `#[cfg(feature = "pq")]`.
    false
}
