//! Unit tests for `security::authn` (relocated from src).
//!
//! `X_API_KEY` was a module-private const in src; the one test that
//! inserted it uses the literal header name instead.

use std::collections::HashMap;

use hyper::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION};

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
    assert!(verify_secret(&stored, "hunter2"));
    assert!(!verify_secret(&stored, "hunter3"));
    // Unknown hash formats never accept.
    assert!(!verify_secret("plaintext", "plaintext"));
    assert!(!verify_secret("sha256:short", "x"));
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
    assert!(verify_secret(&phc, "password"));
    assert!(!verify_secret(&phc, "passwordd"));
    // A malformed PHC string never accepts.
    assert!(!verify_secret("$argon2id$garbage", "password"));
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
    let registry = CredentialRegistry::from_config(&gateway);
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
    let auth = CompositeAuthenticator::build(&gateway, None, &mut HashMap::new(), None);
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer abc.def.ghi"),
    );
    headers.insert(
        HeaderName::from_static("x-api-key"),
        HeaderValue::from_static("whatever"),
    );
    assert_eq!(auth.authenticate(&headers).await.unwrap(), None);
    assert_eq!(auth.challenge(), "Bearer");
}
