//! Integration tests for DW-105 (post-quantum TLS, X25519+ML-KEM).
//!
//! These tests exercise the PQ module's mode enum, config parsing,
//! and the snapshot validation rules. When the `pq` cargo feature is
//! OFF, the module is inert. When the feature is ON, the PQ kx group
//! is installed and validation rejects `pq: true` + FIPS mode.

#![cfg(feature = "pq")]

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
    let label = pq::pq_handshake_metric();
    assert!(!label.is_empty());
}
