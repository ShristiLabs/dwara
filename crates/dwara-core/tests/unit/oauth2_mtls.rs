//! Unit tests for the DW-035 OAuth2 client-credentials and mTLS consumer
//! mapping / X-Client-Cert-* forwarding internals.
//!
//! - Fingerprint computation (SHA-256 of cert DER, colon-separated hex)
//! - Token cache TTL logic (min of expires_in - 60s skew and override,
//!   clamped to 1s)
//! - Config validation matrix (missing fields, invalid URLs, invalid
//!   fingerprints, unknown consumers, invalid prefix)
//! - MtlsConsumerMap resolution (fingerprint lookup, subject CN lookup,
//!   unmapped cert rejection) — exercised through the public
//!   `CompositeAuthenticator` since the map is a private struct
//! - Header name derivation from prefix (the validation-side check that
//!   `<prefix>-{Fingerprint,Subject-CN,Issuer-CN,Not-After}` are valid
//!   HTTP header names)

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use hyper::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION};
use hyper::Method;
use rcgen::CertificateParams;

use dwara_core::config::credentials::sha256_hex;
use dwara_core::config::{
    Endpoint, Gateway, LoadBalancer, MtlsConsumerMapping, MtlsFingerprintMapping,
    MtlsForwardHeaders, OAuth2ClientCredentials, Upstream, UpstreamProtocol,
};
use dwara_core::security::authn::{
    Authenticator, AuthnRequest, ClientCertificate, CompositeAuthenticator, NonceCache,
};
use dwara_core::security::oauth2::{OAuth2Client, OAuth2Error};
use dwara_core::security::tls::{
    fingerprint_colon_hex, issuer_cn_of_leaf, not_after_unix_secs, subject_cn_of_leaf,
};
use dwara_core::snapshot::validate;

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

/// A self-signed client certificate carrying the given subject CN.
fn client_cert_with_cn(cn: &str) -> rcgen::Certificate {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.self_signed(&key).unwrap()
}

/// A self-signed certificate with a CN, returning the cert AND the key
/// PEM (for tests that write mTLS cert/key files to disk). Uses
/// `generate_simple_self_signed` which exposes `key_pair`.
fn client_cert_and_key_pem(cn: &str) -> (String, String) {
    let cert = rcgen::generate_simple_self_signed(vec![cn.to_string()]).expect("rcgen cert");
    (cert.cert.pem(), cert.key_pair.serialize_pem())
}

/// A minimal valid gateway with one upstream (no OAuth2, no mTLS mapping)
/// that the validation-matrix tests mutate.
fn base_gateway() -> Gateway {
    dwara_core::config::parse_gateway(
        "routes:
  - name: r
    service: svc
    match:
      path: { type: regex, value: /.* }
    action: { type: proxy }
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 9001
consumers:
  - name: acme
    credentials: []
",
    )
    .expect("base gateway parses")
}

/// An `OAuth2ClientCredentials` with all required fields filled in.
fn oauth2_cfg(endpoint: &str) -> OAuth2ClientCredentials {
    OAuth2ClientCredentials {
        token_endpoint: endpoint.into(),
        client_id: "test-client".into(),
        client_secret: "test-secret".into(),
        scopes: vec![],
        mtls: None,
        token_cache_ttl_s: None,
    }
}

/// Build a `CompositeAuthenticator` from a gateway config (no store, no
/// pepper, no JWKS caches — the mTLS mapping path needs none of those).
fn authenticator(gateway: &Gateway) -> Arc<CompositeAuthenticator> {
    CompositeAuthenticator::build(
        gateway,
        None,
        &mut HashMap::new(),
        None,
        None,
        Arc::new(NonceCache::new()),
        Arc::new(dwara_core::security::oidc::OidcIntrospectionCache::new()),
    )
}

/// An `AuthnRequest` carrying only a client certificate (no header
/// credentials) so the ambient mTLS family is engaged. The caller owns
/// the method, uri, and headers so the borrow is valid for the call.
fn cert_request<'a>(
    method: &'a Method,
    uri: &'a hyper::Uri,
    headers: &'a HeaderMap,
    cert: &'a ClientCertificate,
) -> AuthnRequest<'a> {
    AuthnRequest {
        method,
        uri,
        headers,
        client_cert: Some(cert),
    }
}

// ---------------------------------------------------------------------------
// 1. Fingerprint computation
// ---------------------------------------------------------------------------

#[test]
fn fingerprint_colon_hex_is_sha256_of_der_with_colon_separators() {
    let cert = client_cert_with_cn("fp-test");
    let der = cert.der();
    // The colon-separated form is the raw hex (no colons) grouped into
    // byte pairs joined by ':'.
    let raw_hex = sha256_hex(der.as_ref());
    let colon = fingerprint_colon_hex(der);
    // 64 hex chars + 31 colons = 95 chars.
    assert_eq!(colon.len(), 95, "colon fingerprint: {colon}");
    assert_eq!(
        colon.matches(':').count(),
        31,
        "exactly 31 colons (32 byte pairs)"
    );
    // Strip colons and compare to the raw hex.
    let stripped: String = colon.chars().filter(|c| *c != ':').collect();
    assert_eq!(stripped, raw_hex, "colon form matches raw SHA-256 hex");
    // All bytes are lowercase hex or ':'.
    assert!(
        colon
            .bytes()
            .all(|b| b == b':' || (b as char).is_ascii_hexdigit()),
        "only hex digits and colons: {colon}"
    );
}

#[test]
fn fingerprint_is_deterministic_for_the_same_cert() {
    let cert = client_cert_with_cn("stable-cn");
    let der = cert.der();
    assert_eq!(
        fingerprint_colon_hex(der),
        fingerprint_colon_hex(der),
        "same cert -> same fingerprint"
    );
}

#[test]
fn different_certs_have_different_fingerprints() {
    let a = client_cert_with_cn("cert-a");
    let b = client_cert_with_cn("cert-b");
    assert_ne!(
        fingerprint_colon_hex(a.der()),
        fingerprint_colon_hex(b.der()),
        "different certs -> different fingerprints"
    );
}

#[test]
fn client_certificate_from_cert_extracts_all_metadata() {
    let cert = client_cert_with_cn("extract-cn");
    let der = cert.der();
    let cc = ClientCertificate::from_cert(der);
    // Subject CN.
    assert_eq!(cc.subject_cn(), Some("extract-cn"));
    // Fingerprint (colon form) matches the tls helper.
    assert_eq!(cc.fingerprint_colon(), fingerprint_colon_hex(der));
    // Issuer CN: self-signed -> issuer == subject.
    assert_eq!(cc.issuer_cn(), Some("extract-cn"));
    // Not-After: a well-formed cert has a decodable validity.
    assert!(cc.not_after().is_some(), "not_after must decode");
    // The tls helpers agree with ClientCertificate.
    assert_eq!(subject_cn_of_leaf(der), Some("extract-cn".to_string()));
    assert_eq!(issuer_cn_of_leaf(der), Some("extract-cn".to_string()));
    assert_eq!(not_after_unix_secs(der), cc.not_after());
}

#[test]
fn client_certificate_with_no_subject_cn_still_has_fingerprint() {
    // A certificate whose subject carries NO CommonName: subject_cn is
    // None, but the fingerprint is always present (it is the SHA-256 of
    // the DER, independent of the subject). rcgen's default params
    // include a CN, so explicitly clear the distinguished name.
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    let cert = params.self_signed(&key).unwrap();
    let cc = ClientCertificate::from_cert(cert.der());
    assert!(cc.subject_cn().is_none(), "no CN in empty DN");
    assert!(
        !cc.fingerprint_colon().is_empty(),
        "fingerprint always present"
    );
}

// ---------------------------------------------------------------------------
// 2. Token cache TTL logic
// ---------------------------------------------------------------------------

/// Build an `OAuth2Client` with the given `token_cache_ttl_s` override
/// (None = no override). The mTLS cert files are not loaded (mtls: None),
/// so no filesystem access is needed.
fn oauth2_client(ttl_override: Option<u64>) -> Arc<OAuth2Client> {
    let mut cfg = oauth2_cfg("http://127.0.0.1:1/token");
    cfg.token_cache_ttl_s = ttl_override;
    OAuth2Client::build(cfg).expect("oauth2 client builds")
}

#[test]
fn ttl_no_override_is_expires_in_minus_skew() {
    // 60s skew: expires_in 3600 -> TTL 3540.
    let client = oauth2_client(None);
    assert_eq!(
        client.effective_ttl_for_test(3600),
        Duration::from_secs(3540)
    );
}

#[test]
fn ttl_override_caps_below_expires_in_minus_skew() {
    // expires_in 3600 -> base 3540; override 100 -> min(3540, 100) = 100.
    let client = oauth2_client(Some(100));
    assert_eq!(
        client.effective_ttl_for_test(3600),
        Duration::from_secs(100)
    );
}

#[test]
fn ttl_override_does_not_extend_a_short_expires_in() {
    // expires_in 30 -> base max(30 - 60, 1) = 1; override 100 -> min(1, 100) = 1.
    // The override never extends a token's real lifetime.
    let client = oauth2_client(Some(100));
    assert_eq!(
        client.effective_ttl_for_test(30),
        Duration::from_secs(1),
        "override must not extend below the skew-clamped base"
    );
}

#[test]
fn ttl_clamps_to_one_second_when_expires_in_below_skew() {
    // expires_in 10 -> base max(10 - 60, 1) = 1 (saturating_sub + max).
    let client = oauth2_client(None);
    assert_eq!(
        client.effective_ttl_for_test(10),
        Duration::from_secs(1),
        "tiny expires_in clamps to 1s, not 0"
    );
}

#[test]
fn ttl_exactly_at_skew_boundary_clamps_to_one() {
    // expires_in 60 -> base max(60 - 60, 1) = 1.
    let client = oauth2_client(None);
    assert_eq!(client.effective_ttl_for_test(60), Duration::from_secs(1));
}

#[test]
fn ttl_override_equal_to_base_is_unchanged() {
    // expires_in 3600 -> base 3540; override 3540 -> min(3540, 3540) = 3540.
    let client = oauth2_client(Some(3540));
    assert_eq!(
        client.effective_ttl_for_test(3600),
        Duration::from_secs(3540)
    );
}

// ---------------------------------------------------------------------------
// 3. Config validation matrix
// ---------------------------------------------------------------------------

fn upstream_with_oauth2(cfg: OAuth2ClientCredentials) -> Upstream {
    Upstream {
        name: "pool".into(),
        load_balancer: LoadBalancer::RoundRobin,
        protocol: UpstreamProtocol::Http1,
        endpoints: vec![Endpoint {
            address: "127.0.0.1".into(),
            port: 9001,
            weight: 1,
        }],
        connection_cap: None,
        slow_start_ms: None,
        health: None,
        active_health: None,
        retries: None,
        timeouts: None,
        breaker: None,
        max_pending: None,
        trusted_ca_file: None,
        oauth2_client_credentials: Some(cfg),
    }
}

fn assert_issue(gw: &Gateway, field_substr: &str) {
    let issues = validate(gw);
    assert!(
        issues.iter().any(|i| i.field.contains(field_substr)),
        "expected an issue matching '{field_substr}', got: {issues:?}"
    );
}

fn assert_no_issues(gw: &Gateway) {
    let issues = validate(gw);
    assert!(issues.is_empty(), "expected no issues, got: {issues:?}");
}

#[test]
fn validation_accepts_valid_oauth2_config() {
    let mut gw = base_gateway();
    gw.upstreams[0] = upstream_with_oauth2(oauth2_cfg("http://127.0.0.1:8080/token"));
    assert_no_issues(&gw);
}

#[test]
fn validation_rejects_empty_token_endpoint() {
    let mut gw = base_gateway();
    gw.upstreams[0] = upstream_with_oauth2(oauth2_cfg(""));
    assert_issue(&gw, "oauth2_client_credentials.token_endpoint");
}

#[test]
fn validation_rejects_non_http_scheme_token_endpoint() {
    let mut gw = base_gateway();
    gw.upstreams[0] = upstream_with_oauth2(oauth2_cfg("ftp://127.0.0.1/token"));
    assert_issue(&gw, "oauth2_client_credentials.token_endpoint");
}

#[test]
fn validation_rejects_relative_token_endpoint() {
    let mut gw = base_gateway();
    gw.upstreams[0] = upstream_with_oauth2(oauth2_cfg("/token"));
    assert_issue(&gw, "oauth2_client_credentials.token_endpoint");
}

#[test]
fn validation_rejects_empty_client_id() {
    let mut cfg = oauth2_cfg("http://127.0.0.1:8080/token");
    cfg.client_id = String::new();
    let mut gw = base_gateway();
    gw.upstreams[0] = upstream_with_oauth2(cfg);
    assert_issue(&gw, "oauth2_client_credentials.client_id");
}

#[test]
fn validation_rejects_empty_client_secret() {
    let mut cfg = oauth2_cfg("http://127.0.0.1:8080/token");
    cfg.client_secret = String::new();
    let mut gw = base_gateway();
    gw.upstreams[0] = upstream_with_oauth2(cfg);
    assert_issue(&gw, "oauth2_client_credentials.client_secret");
}

#[test]
fn validation_rejects_zero_token_cache_ttl() {
    let mut cfg = oauth2_cfg("http://127.0.0.1:8080/token");
    cfg.token_cache_ttl_s = Some(0);
    let mut gw = base_gateway();
    gw.upstreams[0] = upstream_with_oauth2(cfg);
    assert_issue(&gw, "oauth2_client_credentials.token_cache_ttl_s");
}

#[test]
fn validation_rejects_missing_mtls_cert_file() {
    let mut cfg = oauth2_cfg("http://127.0.0.1:8080/token");
    cfg.mtls = Some(dwara_core::config::OAuth2Mtls {
        client_cert: "/no/such/cert.pem".into(),
        client_key: "/no/such/key.pem".into(),
    });
    let mut gw = base_gateway();
    gw.upstreams[0] = upstream_with_oauth2(cfg);
    let issues = validate(&gw);
    assert!(
        issues.iter().any(|i| i.field.contains("mtls.client_cert")),
        "expected mtls.client_cert issue, got: {issues:?}"
    );
    assert!(
        issues.iter().any(|i| i.field.contains("mtls.client_key")),
        "expected mtls.client_key issue, got: {issues:?}"
    );
}

#[test]
fn validation_accepts_real_mtls_cert_files() {
    let dir = tempfile::tempdir().unwrap();
    let (cert_pem, key_pem) = client_cert_and_key_pem("mtls-client");
    let cpath = dir.path().join("client.crt.pem");
    let kpath = dir.path().join("client.key.pem");
    std::fs::write(&cpath, cert_pem).unwrap();
    std::fs::write(&kpath, key_pem).unwrap();
    let mut cfg = oauth2_cfg("http://127.0.0.1:8080/token");
    cfg.mtls = Some(dwara_core::config::OAuth2Mtls {
        client_cert: cpath.display().to_string(),
        client_key: kpath.display().to_string(),
    });
    let mut gw = base_gateway();
    gw.upstreams[0] = upstream_with_oauth2(cfg);
    assert_no_issues(&gw);
}

// --- mTLS consumer mapping validation ---

#[test]
fn validation_accepts_enabled_mtls_consumer_mapping_with_known_consumer() {
    let mut gw = base_gateway();
    gw.mtls_consumer_mapping = Some(MtlsConsumerMapping {
        enabled: true,
        consumers: vec![MtlsFingerprintMapping {
            fingerprint: "ab:cd:ef:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc"
                .into(),
            consumer: "acme".into(),
        }],
        subject_cn_mapping: Default::default(),
    });
    assert_no_issues(&gw);
}

#[test]
fn validation_rejects_mtls_mapping_with_invalid_fingerprint() {
    let mut gw = base_gateway();
    gw.mtls_consumer_mapping = Some(MtlsConsumerMapping {
        enabled: true,
        consumers: vec![MtlsFingerprintMapping {
            fingerprint: "not-a-fingerprint".into(),
            consumer: "acme".into(),
        }],
        subject_cn_mapping: Default::default(),
    });
    assert_issue(&gw, "mtls_consumer_mapping.consumers[0].fingerprint");
}

#[test]
fn validation_rejects_mtls_mapping_with_unknown_consumer() {
    let mut gw = base_gateway();
    gw.mtls_consumer_mapping = Some(MtlsConsumerMapping {
        enabled: true,
        consumers: vec![MtlsFingerprintMapping {
            fingerprint: "ab:cd:ef:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc"
                .into(),
            consumer: "no-such-consumer".into(),
        }],
        subject_cn_mapping: Default::default(),
    });
    assert_issue(&gw, "mtls_consumer_mapping.consumers[0].consumer");
}

#[test]
fn validation_rejects_empty_subject_cn_key() {
    let mut gw = base_gateway();
    let mut mapping = std::collections::BTreeMap::new();
    mapping.insert("".into(), "acme".into());
    gw.mtls_consumer_mapping = Some(MtlsConsumerMapping {
        enabled: true,
        consumers: vec![],
        subject_cn_mapping: mapping,
    });
    assert_issue(&gw, "mtls_consumer_mapping.subject_cn_mapping");
}

#[test]
fn validation_rejects_subject_cn_mapping_to_unknown_consumer() {
    let mut gw = base_gateway();
    let mut mapping = std::collections::BTreeMap::new();
    mapping.insert("acme-client".into(), "no-such-consumer".into());
    gw.mtls_consumer_mapping = Some(MtlsConsumerMapping {
        enabled: true,
        consumers: vec![],
        subject_cn_mapping: mapping,
    });
    assert_issue(&gw, "mtls_consumer_mapping.subject_cn_mapping");
}

#[test]
fn validation_ignores_disabled_mtls_consumer_mapping() {
    // A disabled mapping with an invalid fingerprint is NOT validated
    // (the operator turned it off).
    let mut gw = base_gateway();
    gw.mtls_consumer_mapping = Some(MtlsConsumerMapping {
        enabled: false,
        consumers: vec![MtlsFingerprintMapping {
            fingerprint: "garbage".into(),
            consumer: "no-such".into(),
        }],
        subject_cn_mapping: Default::default(),
    });
    assert_no_issues(&gw);
}

// --- mTLS forward headers validation (header name derivation) ---

#[test]
fn validation_accepts_default_prefix() {
    let mut gw = base_gateway();
    gw.mtls_forward_headers = Some(MtlsForwardHeaders {
        enabled: true,
        prefix: "X-Client-Cert".into(),
    });
    assert_no_issues(&gw);
}

#[test]
fn validation_rejects_empty_prefix() {
    let mut gw = base_gateway();
    gw.mtls_forward_headers = Some(MtlsForwardHeaders {
        enabled: true,
        prefix: String::new(),
    });
    assert_issue(&gw, "mtls_forward_headers.prefix");
}

#[test]
fn validation_rejects_prefix_with_invalid_header_chars() {
    // A space in the prefix makes `<prefix>-Fingerprint` an invalid
    // header name (HTTP header names cannot contain spaces).
    let mut gw = base_gateway();
    gw.mtls_forward_headers = Some(MtlsForwardHeaders {
        enabled: true,
        prefix: "X Client Cert".into(),
    });
    assert_issue(&gw, "mtls_forward_headers.prefix");
}

#[test]
fn validation_accepts_custom_valid_prefix() {
    let mut gw = base_gateway();
    gw.mtls_forward_headers = Some(MtlsForwardHeaders {
        enabled: true,
        prefix: "X-My-Cert".into(),
    });
    assert_no_issues(&gw);
}

#[test]
fn validation_ignores_disabled_forward_headers() {
    let mut gw = base_gateway();
    gw.mtls_forward_headers = Some(MtlsForwardHeaders {
        enabled: false,
        prefix: "Invalid Prefix!".into(),
    });
    assert_no_issues(&gw);
}

#[test]
fn header_name_derivation_from_prefix_produces_valid_names() {
    // The four derived header names from a valid prefix are all valid
    // HTTP header names (this is what validation checks, and what the
    // proxy's inject_client_cert_headers constructs at runtime).
    let prefix = "X-Client-Cert";
    for suffix in &["Fingerprint", "Subject-CN", "Issuer-CN", "Not-After"] {
        let name = format!("{prefix}-{suffix}");
        assert!(
            HeaderName::from_bytes(name.as_bytes()).is_ok(),
            "'{name}' must be a valid header name"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. MtlsConsumerMap resolution (through CompositeAuthenticator)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mtls_map_resolves_by_subject_cn() {
    let cert = client_cert_with_cn("acme-client");
    let cc = ClientCertificate::from_cert(cert.der());
    let mut gw = base_gateway();
    let mut cn_map = std::collections::BTreeMap::new();
    cn_map.insert("acme-client".into(), "acme".into());
    gw.mtls_consumer_mapping = Some(MtlsConsumerMapping {
        enabled: true,
        consumers: vec![],
        subject_cn_mapping: cn_map,
    });
    let auth = authenticator(&gw);
    let method = Method::GET;
    let uri: hyper::Uri = "/x".parse().unwrap();
    let headers = HeaderMap::new();
    let req = cert_request(&method, &uri, &headers, &cc);
    let identity = auth.authenticate(&req).await.unwrap();
    let identity = identity.expect("must resolve a consumer");
    assert_eq!(identity.consumer_name, "acme");
    assert_eq!(
        identity.credential_kind,
        dwara_core::store::CredentialKind::Mtls
    );
}

#[tokio::test]
async fn mtls_map_resolves_by_fingerprint() {
    let cert = client_cert_with_cn("fp-client");
    let cc = ClientCertificate::from_cert(cert.der());
    let fp_colon = fingerprint_colon_hex(cert.der());
    let mut gw = base_gateway();
    gw.mtls_consumer_mapping = Some(MtlsConsumerMapping {
        enabled: true,
        consumers: vec![MtlsFingerprintMapping {
            fingerprint: fp_colon,
            consumer: "acme".into(),
        }],
        subject_cn_mapping: Default::default(),
    });
    let auth = authenticator(&gw);
    let method = Method::GET;
    let uri: hyper::Uri = "/x".parse().unwrap();
    let headers = HeaderMap::new();
    let req = cert_request(&method, &uri, &headers, &cc);
    let identity = auth.authenticate(&req).await.unwrap();
    let identity = identity.expect("must resolve a consumer");
    assert_eq!(identity.consumer_name, "acme");
}

#[tokio::test]
async fn mtls_map_subject_cn_takes_priority_over_fingerprint() {
    // When both maps would match, the subject-CN map wins (checked
    // first in MtlsConsumerMap::resolve).
    let cert = client_cert_with_cn("shared-cn");
    let cc = ClientCertificate::from_cert(cert.der());
    let fp_colon = fingerprint_colon_hex(cert.der());
    let mut gw = base_gateway();
    gw.consumers.push(dwara_core::config::Consumer {
        name: "by-fp".into(),
        credentials: vec![],
        policies: vec![],
        priority: None,
        groups: vec![],
        authorization: None,
        quotas: None,
    });
    let mut cn_map = std::collections::BTreeMap::new();
    cn_map.insert("shared-cn".into(), "acme".into());
    gw.mtls_consumer_mapping = Some(MtlsConsumerMapping {
        enabled: true,
        consumers: vec![MtlsFingerprintMapping {
            fingerprint: fp_colon,
            consumer: "by-fp".into(),
        }],
        subject_cn_mapping: cn_map,
    });
    let auth = authenticator(&gw);
    let method = Method::GET;
    let uri: hyper::Uri = "/x".parse().unwrap();
    let headers = HeaderMap::new();
    let req = cert_request(&method, &uri, &headers, &cc);
    let identity = auth.authenticate(&req).await.unwrap();
    let identity = identity.expect("must resolve a consumer");
    assert_eq!(
        identity.consumer_name, "acme",
        "subject CN map takes priority over fingerprint"
    );
}

#[tokio::test]
async fn mtls_map_unmapped_cert_is_rejected() {
    let cert = client_cert_with_cn("unknown-cn");
    let cc = ClientCertificate::from_cert(cert.der());
    let mut gw = base_gateway();
    let mut cn_map = std::collections::BTreeMap::new();
    cn_map.insert("known-cn".into(), "acme".into());
    gw.mtls_consumer_mapping = Some(MtlsConsumerMapping {
        enabled: true,
        consumers: vec![],
        subject_cn_mapping: cn_map,
    });
    let auth = authenticator(&gw);
    let method = Method::GET;
    let uri: hyper::Uri = "/x".parse().unwrap();
    let headers = HeaderMap::new();
    let req = cert_request(&method, &uri, &headers, &cc);
    let result = auth.authenticate(&req).await;
    assert!(result.is_err(), "unmapped cert must be rejected");
}

#[tokio::test]
async fn mtls_map_disabled_falls_through_to_credential_registry() {
    // When the mapping is disabled (or absent), the DW-019 per-consumer
    // mtls credential registry path runs. A cert with no matching
    // credential is rejected there too, but the gateway-level map is
    // NOT consulted.
    let cert = client_cert_with_cn("acme-client");
    let cc = ClientCertificate::from_cert(cert.der());
    let mut gw = base_gateway();
    // No mtls_consumer_mapping; a per-consumer mtls credential by subject.
    gw.consumers[0]
        .credentials
        .push(dwara_core::config::Credential::Mtls {
            subject: Some("acme-client".into()),
            fingerprint: None,
        });
    let auth = authenticator(&gw);
    let method = Method::GET;
    let uri: hyper::Uri = "/x".parse().unwrap();
    let headers = HeaderMap::new();
    let req = cert_request(&method, &uri, &headers, &cc);
    let identity = auth.authenticate(&req).await.unwrap();
    let identity = identity.expect("must resolve via credential registry");
    assert_eq!(identity.consumer_name, "acme");
}

#[tokio::test]
async fn mtls_map_no_cert_stays_anonymous_when_no_header_credential() {
    // No client cert and no header credential: the ambient family is
    // not engaged, so the result is Anonymous (Ok(None)) — even with
    // the mapping enabled.
    let mut gw = base_gateway();
    gw.mtls_consumer_mapping = Some(MtlsConsumerMapping {
        enabled: true,
        consumers: vec![MtlsFingerprintMapping {
            fingerprint: "ab:cd:ef:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc"
                .into(),
            consumer: "acme".into(),
        }],
        subject_cn_mapping: Default::default(),
    });
    let auth = authenticator(&gw);
    let method = Method::GET;
    let uri: hyper::Uri = "/x".parse().unwrap();
    let headers = HeaderMap::new();
    let req = AuthnRequest {
        method: &method,
        uri: &uri,
        headers: &headers,
        client_cert: None,
    };
    let identity = auth.authenticate(&req).await.unwrap();
    assert!(identity.is_none(), "no cert -> anonymous, not an error");
}

// ---------------------------------------------------------------------------
// 5. OAuth2 client build error (mTLS cert load failure)
// ---------------------------------------------------------------------------

#[test]
fn oauth2_build_fails_on_missing_mtls_cert_file() {
    let mut cfg = oauth2_cfg("http://127.0.0.1:8080/token");
    cfg.mtls = Some(dwara_core::config::OAuth2Mtls {
        client_cert: "/no/such/cert.pem".into(),
        client_key: "/no/such/key.pem".into(),
    });
    let result = OAuth2Client::build(cfg);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, OAuth2Error::MtlsConfig(_)),
        "expected MtlsConfig error, got: {err}"
    );
}

#[test]
fn oauth2_build_succeeds_without_mtls() {
    let cfg = oauth2_cfg("http://127.0.0.1:8080/token");
    let client = OAuth2Client::build(cfg);
    assert!(client.is_ok(), "build without mtls must succeed");
}

#[test]
fn oauth2_build_succeeds_with_real_mtls_files() {
    let dir = tempfile::tempdir().unwrap();
    let (cert_pem, key_pem) = client_cert_and_key_pem("mtls-client");
    let cpath = dir.path().join("client.crt.pem");
    let kpath = dir.path().join("client.key.pem");
    std::fs::write(&cpath, cert_pem).unwrap();
    std::fs::write(&kpath, key_pem).unwrap();
    let mut cfg = oauth2_cfg("http://127.0.0.1:8080/token");
    cfg.mtls = Some(dwara_core::config::OAuth2Mtls {
        client_cert: cpath.display().to_string(),
        client_key: kpath.display().to_string(),
    });
    let client = OAuth2Client::build(cfg);
    assert!(client.is_ok(), "build with real mtls files must succeed");
}

// ---------------------------------------------------------------------------
// 6. OAuth2 token cache basics
// ---------------------------------------------------------------------------

#[test]
fn oauth2_token_cache_starts_empty() {
    let cache = dwara_core::security::oauth2::OAuth2TokenCache::new();
    // The cache is empty; a client's get returns None (verified by the
    // integration suite's caching test). Here we only confirm the
    // constructor does not panic and Debug does not leak.
    let debug = format!("{cache:?}");
    assert!(debug.contains("OAuth2TokenCache"), "debug: {debug}");
}

// ---------------------------------------------------------------------------
// 7. OAuth2 config debug redacts the secret
// ---------------------------------------------------------------------------

#[test]
fn oauth2_client_debug_redacts_client_secret() {
    let cfg = oauth2_cfg("http://127.0.0.1:8080/token");
    let client = OAuth2Client::build(cfg).expect("builds");
    let debug = format!("{client:?}");
    assert!(
        !debug.contains("test-secret"),
        "client secret must be redacted in Debug: {debug}"
    );
    assert!(debug.contains("[redacted]"), "debug: {debug}");
}

// ---------------------------------------------------------------------------
// 8. Authorization header replacement semantics (unit-level)
// ---------------------------------------------------------------------------

#[test]
fn bearer_header_value_is_constructed_from_token() {
    // The proxy constructs `Authorization: Bearer <token>` and INSERTS
    // (replaces) it. This unit test pins the header-value format the
    // proxy builds, independent of the HTTP round-trip.
    let token = "my-access-token";
    let value = HeaderValue::from_str(&format!("Bearer {token}")).unwrap();
    assert_eq!(value.to_str().unwrap(), "Bearer my-access-token");
    // A pre-existing Authorization header is replaced (insert, not append).
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, "Bearer client-token".parse().unwrap());
    headers.insert(AUTHORIZATION, value);
    assert_eq!(
        headers.get(AUTHORIZATION).unwrap().to_str().unwrap(),
        "Bearer my-access-token",
        "insert replaces the client's Authorization"
    );
}
