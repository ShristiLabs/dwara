//! Fuzz the signed URL verifier (DW-109, SEC-07 #211): verify
//! arbitrary query strings against a fixed-secret verifier. Only
//! panic-freedom is asserted — an invalid signature, expired URL,
//! or replayed nonce is a rejection, never a crash.

#![no_main]

use dwara_core::security::signed_url::{SignedUrlConfig, SignedUrlVerifier};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let config = SignedUrlConfig {
        enabled: true,
        secret: Some("test-secret".to_string()),
        ttl_seconds: 300,
        query_param: "sig".to_string(),
        require_nonce: true,
        nonce_param: "nonce".to_string(),
        bind_client_ip: false,
    };
    let verifier = SignedUrlVerifier::from_config(&config).unwrap();
    // Feed arbitrary bytes as a query string.
    let query = std::str::from_utf8(data).unwrap_or("");
    let now = 1_000_000;
    let _ = std::hint::black_box(verifier.verify("GET", "/path", query, now, ""));
});
