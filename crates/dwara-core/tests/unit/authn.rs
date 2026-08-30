//! Unit tests for `security::authn` (relocated from src).
//!
//! `X_API_KEY` was a module-private const in src; the one test that
//! inserted it uses the literal header name instead.

use std::collections::HashMap;
use std::sync::Arc;

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
    let auth = CompositeAuthenticator::build(
        &gateway,
        None,
        &mut HashMap::new(),
        None,
        None,
        std::sync::Arc::new(NonceCache::new()),
        std::sync::Arc::new(dwara_core::security::oidc::OidcIntrospectionCache::new()),
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer abc.def.ghi"),
    );
    headers.insert(
        HeaderName::from_static("x-api-key"),
        HeaderValue::from_static("whatever"),
    );
    let request = AuthnRequest {
        method: &hyper::Method::GET,
        uri: &"/".parse().unwrap(),
        headers: &headers,
        client_cert: None,
    };
    assert_eq!(auth.authenticate(&request).await.unwrap(), None);
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

// ---- HMAC request signing (DW-036) ------------------------------------------

/// The canonical string is the INTEROP contract: pin its exact bytes
/// for a representative request (the integration suite re-derives the
/// same grammar independently through real HTTP).
#[test]
fn canonical_string_exact_bytes() {
    let method = hyper::Method::GET;
    let canonical = canonical_string(
        "key-1",
        &method,
        "/api/x",
        Some("a=1&b=2"),
        "1700000000",
        "nonce-abc",
        "deadbeef",
    );
    assert_eq!(
        canonical,
        "dwara-hmac-v1\nkey-1\nGET\n/api/x\na=1&b=2\n1700000000\nnonce-abc\ndeadbeef"
    );
    // No query: the query line is EMPTY, not omitted.
    let no_query = canonical_string(
        "key-1",
        &hyper::Method::POST,
        "/api/x",
        None,
        "1700000000",
        "nonce-abc",
        "deadbeef",
    );
    assert_eq!(
        no_query,
        "dwara-hmac-v1\nkey-1\nPOST\n/api/x\n\n1700000000\nnonce-abc\ndeadbeef"
    );
}

#[test]
fn nonce_cache_fresh_replay_and_expiry() {
    let cache = NonceCache::new();
    let ttl = std::time::Duration::from_millis(80);
    assert!(
        cache.check_and_insert("k\nn1", ttl),
        "first presentation is fresh"
    );
    assert!(
        !cache.check_and_insert("k\nn1", ttl),
        "second presentation inside the TTL is a replay"
    );
    assert!(
        cache.check_and_insert("k\nn2", ttl),
        "a different nonce under the same key is fresh"
    );
    assert!(
        cache.check_and_insert("other-key\nn1", ttl),
        "nonce scope is per key: the same value under another key is fresh"
    );
    // Expiry: a tiny TTL with a generous wait margin (never sleeps as
    // synchronization — this IS the timed behavior under test).
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(
        cache.check_and_insert("k\nn1", ttl),
        "after the TTL the nonce is forgotten"
    );
}

#[test]
fn nonce_cache_evicts_under_flood_not_before() {
    // 64 keys into 16 shards of cap 1: every within-shard collision
    // forces an eviction — the documented fail-open-under-flood trade.
    // Shard assignment is per-process random (RandomState), so the
    // assertions are pigeonhole bounds immune to placement: at most
    // NONCE_CACHE_SHARDS entries can survive the cap (one per shard),
    // hence at least 64 - 16 of the second presentations are FRESH
    // again (those nonces were forgotten under flood, by design).
    let cache = NonceCache::with_shard_capacity(1);
    let ttl = std::time::Duration::from_secs(60);
    for i in 0..64 {
        assert!(
            cache.check_and_insert(&format!("k{i}"), ttl),
            "first presentations are always fresh"
        );
    }
    let remembered = (0..64)
        .filter(|i| !cache.check_and_insert(&format!("k{i}"), ttl))
        .count();
    assert!(
        remembered <= dwara_core::security::authn::NONCE_CACHE_SHARDS,
        "the cap bounds survivors to one per shard: {remembered}"
    );
    let forgotten = 64 - remembered;
    assert!(
        forgotten >= 64 - dwara_core::security::authn::NONCE_CACHE_SHARDS,
        "the flood evicted within-TTL nonces (fail-open, documented): {forgotten}"
    );
}

#[test]
fn hmac_credential_debug_and_registry_never_leak_the_secret() {
    // The config tree redacts the secret (DW-045 shape) and the
    // composite's key map holds only Zeroizing material; a whole-tree
    // Debug print must not carry the secret bytes.
    let gateway = dwara_core::config::parse_gateway(
        "consumers:\n  - name: acme\n    credentials:\n      - type: hmac\n        key_id: \
         k-1\n        secret: super-secret-mac-key\n",
    )
    .unwrap();
    let dumped = format!("{gateway:?}");
    assert!(!dumped.contains("super-secret-mac-key"), "{dumped}");
    assert!(dumped.contains("k-1"), "the key id is public: {dumped}");
    // The inline secret redacts through the DW-045 transform.
    let redacted = gateway.redacted();
    assert_ne!(redacted, gateway);
}

// ---- HMAC gap coverage (DW-036, tester stage) --------------------------------

/// Build an authenticator from one YAML string (the hmac consumer shape
/// the integration suite uses, minus the routing the authenticator
/// never sees).
fn hmac_authenticator(yaml: &str) -> Arc<CompositeAuthenticator> {
    let gateway = dwara_core::config::parse_gateway(yaml).unwrap();
    CompositeAuthenticator::build(
        &gateway,
        None,
        &mut HashMap::new(),
        None,
        None,
        Arc::new(NonceCache::new()),
        Arc::new(dwara_core::security::oidc::OidcIntrospectionCache::new()),
    )
}

/// The five X-Dwara headers for a correctly signed request, computed
/// over the gateway's own public `canonical_string` (this suite pins
/// identity plumbing, not the grammar — the integration signer derives
/// the grammar independently).
fn signed_headers(secret: &str, key_id: &str, nonce: &str, timestamp: &str) -> HeaderMap {
    use hmac::{Hmac, Mac};
    let body_digest = {
        use sha2::Digest as _;
        let bytes: [u8; 32] = sha2::Sha256::digest(b"").into();
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    let canonical = canonical_string(
        key_id,
        &hyper::Method::GET,
        "/api/x",
        Some("a=1"),
        timestamp,
        nonce,
        &body_digest,
    );
    let signature = {
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(canonical.as_bytes());
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let mut headers = HeaderMap::new();
    let mut insert = |name: &'static str, value: String| {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_str(&value).unwrap(),
        );
    };
    insert("x-dwara-key-id", key_id.to_string());
    insert("x-dwara-timestamp", timestamp.to_string());
    insert("x-dwara-nonce", nonce.to_string());
    insert("x-dwara-body-sha256", body_digest);
    insert("x-dwara-signature", signature);
    headers
}

fn now_ts() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string()
}

fn authn_req<'a>(
    method: &'a hyper::Method,
    uri: &'a hyper::Uri,
    headers: &'a HeaderMap,
) -> AuthnRequest<'a> {
    AuthnRequest {
        method,
        uri,
        headers,
        client_cert: None,
    }
}

#[tokio::test]
async fn hmac_identity_carries_kind_consumer_and_decoded_digest() {
    let auth = hmac_authenticator(
        "consumers:\n  - name: signer\n    credentials:\n      - type: hmac\n        key_id: \
         k-1\n        secret: unit-test-secret\n",
    );
    let headers = signed_headers("unit-test-secret", "k-1", "nonce-unit-identity", &now_ts());
    let method = hyper::Method::GET;
    let uri: hyper::Uri = "/api/x?a=1".parse().unwrap();
    let identity = auth
        .authenticate(&authn_req(&method, &uri, &headers))
        .await
        .expect("a correctly signed request authenticates")
        .expect("...and resolves a concrete identity");
    assert_eq!(identity.consumer_name, "signer");
    assert_eq!(
        identity.credential_kind,
        dwara_core::state::store::CredentialKind::Hmac
    );
    assert!(identity.groups.is_empty(), "no groups configured");
    // The forward path's enforcement input: the DECODED digest bytes of
    // the empty body (the only body this signature covers).
    use sha2::Digest as _;
    let expected: [u8; 32] = sha2::Sha256::digest(b"").into();
    assert_eq!(identity.body_digest, Some(expected));
    // The hmac-only gateway advertises exactly the HMAC challenge.
    assert_eq!(auth.challenge(), "Dwara-HMAC-SHA256 realm=\"dwara\"");
}

#[tokio::test]
async fn hmac_timestamp_format_boundaries_at_the_authenticator() {
    let auth = hmac_authenticator(
        "consumers:\n  - name: signer\n    credentials:\n      - type: hmac\n        key_id: \
         k-1\n        secret: unit-test-secret\n",
    );
    let method = hyper::Method::GET;
    let uri: hyper::Uri = "/api/x?a=1".parse().unwrap();
    for (label, ts) in [
        ("non-digit", "not-a-timestamp"),
        ("negative sign", "-100"),
        ("21 digits", "100000000000000000000"),
        // Parseable but far outside any window: a clean window verdict,
        // not a parse artifact.
        ("ten quintillion", "10000000000000000000"),
        ("u64 max", "18446744073709551615"),
    ] {
        let headers = signed_headers(
            "unit-test-secret",
            "k-1",
            &format!("nonce-unit-ts-{label}"),
            ts,
        );
        let err = auth
            .authenticate(&authn_req(&method, &uri, &headers))
            .await
            .err()
            .unwrap_or_else(|| panic!("{label}: a hostile timestamp must not authenticate"));
        assert!(matches!(err, AuthError::Invalid(_)), "{label}: {err:?}");
    }
}

#[test]
fn nonce_cache_concurrent_presentation_has_exactly_one_winner() {
    // One nonce, eight concurrent presenters, released together: the
    // single shard critical section must linearize them so exactly ONE
    // presentation is fresh (the replay guarantee under concurrency).
    let cache = std::sync::Arc::new(NonceCache::new());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let fresh = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let (cache, barrier, fresh) = (
                std::sync::Arc::clone(&cache),
                std::sync::Arc::clone(&barrier),
                std::sync::Arc::clone(&fresh),
            );
            std::thread::spawn(move || {
                barrier.wait();
                if cache.check_and_insert("k\nrace", std::time::Duration::from_secs(60)) {
                    fresh.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("no shard lock poisoning");
    }
    assert_eq!(
        fresh.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "exactly one concurrent presentation of a nonce may win"
    );
}

#[tokio::test]
async fn twenty_digit_timestamp_above_u64_max_is_rejected_not_a_panic() {
    // 18446744073709551616 = u64::MAX + 1: all digits, exactly 20 of
    // them, unrepresentable. The contract is a presented-but-malformed
    // credential (401 AuthError), never a panic.
    let auth = hmac_authenticator(
        "consumers:\n  - name: signer\n    credentials:\n      - type: hmac\n        key_id: \
         k-1\n        secret: unit-test-secret\n",
    );
    let headers = signed_headers(
        "unit-test-secret",
        "k-1",
        "nonce-unit-defect-u64",
        "18446744073709551616",
    );
    let method = hyper::Method::GET;
    let uri: hyper::Uri = "/api/x?a=1".parse().unwrap();
    let result = auth.authenticate(&authn_req(&method, &uri, &headers)).await;
    assert!(
        matches!(result, Err(AuthError::Invalid(_))),
        "expected a clean 401 verdict, got {result:?}"
    );
}
