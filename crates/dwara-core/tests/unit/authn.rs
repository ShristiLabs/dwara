//! Unit tests for `security::authn` (relocated from src).
//!
//! `X_API_KEY` was a module-private const in src; the one test that
//! inserted it uses the literal header name instead.

use std::collections::HashMap;

use hyper::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION};

use dwara_core::config::credentials::{credential_selector, sha256_hex, sha256_stored_hash};
use dwara_core::security::authn::*;

#[test]
fn selector_and_hash_are_sha256_hex_not_plaintext() {
    let key = "secret-key";
    let selector = credential_selector(key);
    assert_eq!(selector.len(), 64);
    assert!(selector.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(!selector.contains(key));
    assert_eq!(sha256_stored_hash(key), format!("sha256:{selector}"));
    // SHA-256 of the empty string, well-known vector.
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn verify_secret_accepts_and_rejects() {
    let stored = sha256_stored_hash("hunter2");
    assert!(verify_secret(&stored, "hunter2", None));
    assert!(!verify_secret(&stored, "hunter3", None));
    // Unknown hash formats never accept.
    assert!(!verify_secret("plaintext", "plaintext", None));
    assert!(!verify_secret("sha256:short", "x", None));
}

#[test]
fn verify_secret_handles_argon2id_phc_strings() {
    use argon2::password_hash::{PasswordHasher as _, SaltString};
    use argon2::Argon2;
    // Mint a real PHC string at test time (memory-hard hashing is
    // slow; one hash per test run is fine). The salt is fixed test
    // material to avoid pulling a rand feature.
    let salt = SaltString::from_b64("c2FsdHNhbHRzYWx0c2FsdHNhbHQ").unwrap();
    let phc = Argon2::default()
        .hash_password(b"password", &salt)
        .unwrap()
        .to_string();
    assert!(phc.starts_with("$argon2id$"));
    assert!(verify_secret(&phc, "password", None));
    assert!(!verify_secret(&phc, "passwordd", None));
    // A malformed PHC string never accepts.
    assert!(!verify_secret("$argon2id$garbage", "password", None));
}

#[test]
fn algorithm_allowlist_rejects_symmetric_and_none() {
    assert!(parse_algorithms(&["RS256".into(), "ES256".into()]).is_some());
    assert!(parse_algorithms(&["HS256".into()]).is_none());
    assert!(parse_algorithms(&["none".into()]).is_none());
    assert!(parse_algorithms(&[]).is_none());
    assert!(parse_algorithms(&["GARBAGE".into()]).is_none());
}

#[test]
fn config_registry_hashes_keys_and_drops_plaintext() {
    let gateway = dwara_core::config::parse_gateway(
        "consumers:\n  - name: acme\n    credentials:\n      - type: api_key\n        key: \
         sekrit\n",
    )
    .unwrap();
    let registry = CredentialRegistry::from_config(&gateway, None);
    let CredentialRegistry::Config(map) = &registry else {
        panic!("config registry");
    };
    let entry = map.get(&credential_selector("sekrit")).unwrap();
    assert_eq!(entry.len(), 1);
    assert_eq!(entry[0].consumer_name, "acme");
    assert_eq!(entry[0].hash, sha256_stored_hash("sekrit"));
    // No plaintext anywhere in the registry.
    let dumped = format!("{map:?}");
    assert!(!dumped.contains("sekrit"));
}

#[tokio::test]
async fn disabled_composite_is_anonymous_for_anything() {
    let gateway = dwara_core::config::parse_gateway("routes:\n").unwrap();
    let auth = CompositeAuthenticator::build(&gateway, None, &mut HashMap::new(), None, None);
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer abc.def.ghi"),
    );
    headers.insert(
        HeaderName::from_static("x-api-key"),
        HeaderValue::from_static("whatever"),
    );
    assert_eq!(auth.authenticate(&headers, None).await.unwrap(), None);
    assert_eq!(auth.challenge(), "Bearer");
}

// ---- credential pepper (#124) ----------------------------------------------

#[test]
fn peppered_hmac_format_and_verification_contract() {
    use dwara_core::config::credentials::hmac_stored_hash;
    let pepper = b"unit-test-pepper-0123456789abcdef";
    let stored = hmac_stored_hash(pepper, "hunter2");
    assert!(stored.starts_with("hmac-sha256:"));
    assert_eq!(stored.len(), "hmac-sha256:".len() + 64);
    assert!(!stored.contains("hunter2"), "no plaintext in the hash");
    // Verifies only with the SAME pepper, constant-time like the sha256
    // path; a different pepper is a different key, so the digest differs.
    assert!(verify_secret(&stored, "hunter2", Some(pepper)));
    assert!(!verify_secret(
        &stored,
        "hunter2",
        Some(b"a-different-pepper")
    ));
    assert!(!verify_secret(&stored, "hunter3", Some(pepper)));
    // Missing pepper: peppered entries fail closed (legacy-only mode).
    assert!(!verify_secret(&stored, "hunter2", None));
    // Legacy sha256 entries verify in BOTH modes (the transition keeps
    // every pre-pepper row valid).
    let legacy = sha256_stored_hash("hunter2");
    assert!(verify_secret(&legacy, "hunter2", Some(pepper)));
    assert!(verify_secret(&legacy, "hunter2", None));
    // Malformed peppered digests never accept.
    assert!(!verify_secret("hmac-sha256:short", "x", Some(pepper)));
    let non_hex = format!("hmac-sha256:{}", "z".repeat(64));
    assert!(!verify_secret(&non_hex, "x", Some(pepper)));
}

#[test]
fn config_registry_hashes_peppered_when_a_pepper_is_set() {
    let gateway = dwara_core::config::parse_gateway(
        "consumers:\n  - name: acme\n    credentials:\n      - type: api_key\n        key: \
         sekrit\n",
    )
    .unwrap();
    let pepper = b"registry-pepper-1234";
    let registry = CredentialRegistry::from_config(&gateway, Some(pepper));
    let CredentialRegistry::Config(map) = &registry else {
        panic!("config registry");
    };
    let entry = map.get(&credential_selector("sekrit")).unwrap();
    assert_eq!(entry.len(), 1);
    assert_eq!(
        entry[0].hash,
        dwara_core::config::credentials::hmac_stored_hash(pepper, "sekrit")
    );
    // No plaintext (or pepper) anywhere in the registry dump.
    let dumped = format!("{map:?}");
    assert!(!dumped.contains("sekrit"));
    assert!(!dumped.contains("registry-pepper-1234"));
}

#[test]
fn client_certificate_debug_redacts_match_values() {
    use dwara_core::security::authn::ClientCertificate;
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "match-me");
    let cert = params.self_signed(&key).unwrap();
    let cc = ClientCertificate::from_cert(cert.der());
    // The public fields are the match values; the Debug output must not
    // carry them (selector-redaction precedent).
    let dumped = format!("{cc:?}");
    assert!(
        !dumped.contains("match-me"),
        "Debug leaked the CN: {dumped}"
    );
    let fp = dwara_core::config::credentials::sha256_hex(cert.der().as_ref());
    assert!(!dumped.contains(&fp), "Debug leaked the digest");
}

#[test]
fn subject_cn_extraction_reads_rcgen_certificates() {
    // The hand-rolled DER walk must read a REAL certificate subject: a
    // CN-bearing rcgen cert yields its CN, and a SAN-only cert (no
    // distinguished name) yields None (fingerprint-only matching).
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "acme-client");
    let cert = params.self_signed(&key).unwrap();
    assert_eq!(
        dwara_core::tls::subject_cn_of_leaf(cert.der()),
        Some("acme-client".to_string())
    );
    // A SAN-only certificate (rcgen stamps a placeholder CN into every
    // params constructor, so the DN is explicitly cleared) has no CN to
    // extract.
    let san_key = rcgen::KeyPair::generate().unwrap();
    let mut san_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    san_params.distinguished_name = rcgen::DistinguishedName::new();
    let san_cert = san_params.self_signed(&san_key).unwrap();
    assert_eq!(
        dwara_core::tls::subject_cn_of_leaf(san_cert.der()),
        None,
        "a subject with no CN attribute must yield None"
    );
}

/// Minimal DER TLV (tag, short-form length, content) for the hand-rolled
/// certificate below.
fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag, content.len() as u8];
    out.extend_from_slice(content);
    out
}

#[test]
fn subject_cn_extraction_rejects_invalid_utf8_cn_bytes() {
    // The CN decode is STRICT (#124 round): a CN carrying invalid UTF-8
    // must yield None (the certificate falls back to fingerprint-only
    // matching), never a U+FFFD-folded string — folding could collide
    // two distinct malformed names into one selector. The certificate is
    // hand-rolled DER because rcgen cannot emit an invalid-UTF8 CN; the
    // valid twin proves the walk itself works, so the None comes from
    // the strict decode alone.
    let build = |cn: &[u8]| {
        let attr = der_tlv(
            0x30,
            &[der_tlv(0x06, &[0x55, 0x04, 0x03]), der_tlv(0x0c, cn)].concat(),
        );
        let subject = der_tlv(0x30, &der_tlv(0x31, &attr));
        // serialNumber, signature, issuer, validity precede the subject
        // in the TBS walk; minimal empty elements suffice for the skip.
        let tbs = der_tlv(
            0x30,
            &[
                der_tlv(0x02, &[1]),
                der_tlv(0x30, &[]),
                der_tlv(0x30, &[]),
                der_tlv(0x30, &[]),
                subject,
            ]
            .concat(),
        );
        rustls::pki_types::CertificateDer::from(der_tlv(0x30, &tbs))
    };
    let valid = build(b"acme-client");
    assert_eq!(
        dwara_core::tls::subject_cn_of_leaf(&valid),
        Some("acme-client".to_string()),
        "the hand-rolled walk must read a valid UTF8String CN"
    );
    let invalid = build(&[0xff, 0xfe, 0x28]);
    assert_eq!(
        dwara_core::tls::subject_cn_of_leaf(&invalid),
        None,
        "invalid UTF-8 CN bytes must be rejected, not lossy-folded"
    );
}
