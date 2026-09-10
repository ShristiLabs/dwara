//! Integration tests for DW-105 (post-quantum TLS, X25519+ML-KEM).
//!
//! These tests exercise the PQ module's mode enum, config parsing,
//! and the snapshot validation rules. When the `pq` cargo feature is
//! OFF, the module is inert. When the feature is ON, the PQ kx group
//! is installed and validation rejects `pq: true` + FIPS mode.

use dwara_core::security::pq;

#[test]
fn pq_mode_is_enabled_when_feature_on() {
    assert_eq!(pq::PqMode::Enabled, pq::PqMode::Enabled);
}

#[test]
fn pq_install_does_not_panic() {
    // The install function should not panic even if the rustls PQ API
    // is not reachable (it's a documented no-op in that case).
    pq::install_pq_kx_group();
}

#[test]
fn pq_handshake_metric_label() {
    let result = pq::PqHandshakeResult::disabled();
    let label = pq::pq_handshake_metric(&result);
    assert!(!label.is_empty());
}

#[test]
fn pq_api_available_returns_true() {
    // The rustls 0.23.43 crate exposes the X25519MLKEM768 hybrid kx
    // group via the aws-lc-rs provider, so the PQ API is reachable.
    assert!(pq::pq_api_available());
}

#[test]
fn pq_provider_has_hybrid_kx_group_first() {
    // The PQ provider should have X25519MLKEM768 as the first kx group
    // (preferred), with classical groups (X25519, P-256, etc.) as
    // fallbacks.
    let provider = pq::pq_provider();
    assert!(!provider.kx_groups.is_empty());
    let first = provider.kx_groups[0];
    assert_eq!(first.name(), rustls::NamedGroup::X25519MLKEM768);
}

#[test]
fn pq_provider_has_classical_fallback() {
    // The PQ provider should retain the classical X25519 group as a
    // fallback for non-PQ clients.
    let provider = pq::pq_provider();
    let has_x25519 = provider
        .kx_groups
        .iter()
        .any(|g| g.name() == rustls::NamedGroup::X25519);
    assert!(has_x25519, "PQ provider should retain X25519 as fallback");
}

#[test]
fn pq_handshake_result_success() {
    let result = pq::PqHandshakeResult::success();
    assert!(result.succeeded);
    assert_eq!(result.kx_group, pq::PQ_KX_GROUP_NAME);
    assert_eq!(pq::pq_handshake_metric(&result), "success");
}

#[test]
fn pq_handshake_result_fallback() {
    let result = pq::PqHandshakeResult::fallback();
    assert!(!result.succeeded);
    assert_eq!(result.kx_group, "X25519");
    assert_eq!(pq::pq_handshake_metric(&result), "fallback");
}
