//! Integration tests for OAuth2 client-credentials proxying and mTLS
//! consumer mapping / X-Client-Cert-* forwarding (DW-035).
//!
//! OAuth2 tests spawn a mock token endpoint (a hyper server returning a
//! JSON token response) and an echo upstream, then drive the gateway's
//! `proxy::handle` directly to verify the upstream sees the gateway's
//! Bearer token, the token is cached, expiry triggers a re-fetch, and a
//! token-endpoint failure surfaces as 502.
//!
//! mTLS tests insert a `ClientCertificate` request extension (the same
//! path the TLS listener frontend uses) and verify the gateway-level
//! consumer mapping resolves the correct consumer, an unmapped cert is
//! 401, the X-Client-Cert-* forwarding headers reach the upstream, and
//! inbound spoofed X-Client-Cert-* headers are stripped.

use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use tokio::net::TcpListener;

use dwara_core::authn::ClientCertificate;
use dwara_core::proxy::DataPlane;

mod support;

use support::dataplane_from;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn peer() -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))
}

/// Spawn an upstream that echoes the request's headers as the response
/// body, one `name: value` line per header (order-free assertions).
async fn spawn_echo_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let io = hyper_util::rt::TokioIo::new(stream);
            tokio::spawn(async move {
                let service = service_fn(|req: Request<Incoming>| async move {
                    let mut lines: Vec<String> = Vec::new();
                    for (n, v) in req.headers() {
                        lines.push(format!("{}: {}", n, v.to_str().unwrap_or("<binary>")));
                    }
                    lines.sort();
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(lines.join("\n")))))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });
    port
}

/// A mock OAuth2 token endpoint: returns a JSON token response with a
/// configurable `expires_in` and access-token value. Counts every
/// request so the caching tests can verify the endpoint was hit only
/// once. When `error_status` is set, every response is that status
/// (no body) — the error-path test.
struct MockTokenEndpoint {
    port: u16,
    hits: Arc<AtomicU64>,
}

impl MockTokenEndpoint {
    /// Spawn a mock token endpoint returning a token with the given
    /// `access_token` and `expires_in` seconds.
    async fn spawn(access_token: &str, expires_in: u64) -> Self {
        Self::spawn_with(access_token, expires_in, None).await
    }

    /// Spawn a mock token endpoint that always returns `error_status`.
    async fn spawn_error(error_status: u16) -> Self {
        Self::spawn_with("", 0, Some(error_status)).await
    }

    async fn spawn_with(access_token: &str, expires_in: u64, error_status: Option<u16>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicU64::new(0));
        let token = access_token.to_string();
        let hits_clone = Arc::clone(&hits);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let io = hyper_util::rt::TokioIo::new(stream);
                let token = token.clone();
                let hits = Arc::clone(&hits_clone);
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let token = token.clone();
                        let hits = Arc::clone(&hits);
                        async move {
                            // Drain the request body (the token POST body).
                            let _ = req.into_body().collect().await;
                            hits.fetch_add(1, Ordering::SeqCst);
                            if let Some(status) = error_status {
                                return Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::from_u16(status).unwrap())
                                        .body(Full::new(Bytes::new()))
                                        .unwrap(),
                                );
                            }
                            let body = format!(
                                "{{\"access_token\":\"{token}\",\"token_type\":\"Bearer\",\
                                 \"expires_in\":{expires_in}}}"
                            );
                            Ok(Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(body)))
                                .unwrap())
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                });
            }
        });
        MockTokenEndpoint { port, hits }
    }

    /// How many requests the token endpoint has received.
    fn hit_count(&self) -> u64 {
        self.hits.load(Ordering::SeqCst)
    }
}

/// Gateway YAML: one route -> one upstream with an
/// `oauth2_client_credentials` block pointing at the mock token
/// endpoint. No auth_required (the OAuth2 token is injected regardless
/// of authn; the test verifies the upstream sees the Bearer header).
fn oauth2_yaml(token_port: u16, upstream_port: u16, ttl_override: Option<u64>) -> String {
    let ttl = match ttl_override {
        Some(t) => format!("    token_cache_ttl_s: {t}\n"),
        None => String::new(),
    };
    format!(
        "listeners: []
routes:
  - name: r
    service: svc
    match:
      path: {{ type: regex, value: /.* }}
    action: {{ type: proxy }}
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: {upstream_port}
    oauth2_client_credentials:
      token_endpoint: http://127.0.0.1:{token_port}/token
      client_id: test-client
      client_secret: test-secret
{ttl}"
    )
}

/// Send a request through the dataplane (no client cert) and return
/// (status, headers, body-text).
async fn send(
    dp: &Arc<DataPlane>,
    path: &str,
    headers: Vec<(&str, &str)>,
) -> (StatusCode, hyper::HeaderMap, String) {
    send_with_cert(dp, path, headers, None).await
}

/// Send a request through the dataplane with an optional client cert
/// extension (the path the TLS listener frontend uses).
async fn send_with_cert(
    dp: &Arc<DataPlane>,
    path: &str,
    headers: Vec<(&str, &str)>,
    cert: Option<Arc<ClientCertificate>>,
) -> (StatusCode, hyper::HeaderMap, String) {
    let mut builder = Request::builder().uri(path);
    for (n, v) in headers {
        builder = builder.header(n, v);
    }
    let mut req = builder.body(Full::new(Bytes::new())).unwrap();
    if let Some(cert) = cert {
        req.extensions_mut().insert(cert);
    }
    let resp = dwara_core::proxy::handle(dp, peer(), req).await;
    let (parts, body) = resp.into_parts();
    let text =
        String::from_utf8(body.collect().await.expect("body read").to_bytes().to_vec()).unwrap();
    (parts.status, parts.headers, text)
}

/// A self-signed client certificate carrying the given subject CN.
fn client_cert_with_cn(cn: &str) -> rcgen::Certificate {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.self_signed(&key).unwrap()
}

/// Gateway YAML for mTLS consumer-mapping tests: one auth_required route,
/// a `mtls_consumer_mapping` block, and a `mtls_forward_headers` block.
fn mtls_yaml(upstream_port: u16, mapping_yaml: &str, forward_yaml: &str) -> String {
    format!(
        "listeners: []
routes:
  - name: r
    service: svc
    auth_required: true
    match:
      path: {{ type: regex, value: /.* }}
    action: {{ type: proxy }}
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: {upstream_port}
consumers:
  - name: acme
{mapping_yaml}
{forward_yaml}"
    )
}

// ---------------------------------------------------------------------------
// OAuth2 client-credentials tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oauth2_token_forwarded_as_bearer_to_upstream() {
    let upstream = spawn_echo_upstream().await;
    let token_ep = MockTokenEndpoint::spawn("gateway-token-123", 3600).await;
    let dp = dataplane_from(&oauth2_yaml(token_ep.port, upstream, None));
    let (status, _, body) = send(&dp, "/x", vec![]).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(
        body.contains("authorization: Bearer gateway-token-123"),
        "upstream must see the gateway's Bearer token: {body}"
    );
}

#[tokio::test]
async fn oauth2_token_cached_second_request_reuses_token() {
    let upstream = spawn_echo_upstream().await;
    let token_ep = MockTokenEndpoint::spawn("cached-token", 3600).await;
    let dp = dataplane_from(&oauth2_yaml(token_ep.port, upstream, None));
    // First request: fetches a token.
    let (s1, _, b1) = send(&dp, "/x", vec![]).await;
    assert_eq!(s1, StatusCode::OK, "body: {b1}");
    assert!(
        b1.contains("authorization: Bearer cached-token"),
        "body: {b1}"
    );
    assert_eq!(
        token_ep.hit_count(),
        1,
        "token endpoint hit once after first request"
    );
    // Second request: reuses the cached token (no new fetch).
    let (s2, _, b2) = send(&dp, "/x", vec![]).await;
    assert_eq!(s2, StatusCode::OK, "body: {b2}");
    assert!(
        b2.contains("authorization: Bearer cached-token"),
        "body: {b2}"
    );
    assert_eq!(
        token_ep.hit_count(),
        1,
        "token endpoint must NOT be hit again (cached token reused)"
    );
}

#[tokio::test]
async fn oauth2_expired_token_triggers_new_fetch() {
    let upstream = spawn_echo_upstream().await;
    // A 2-second expiry minus the 60s skew clamps to a 1s TTL (the
    // minimum), so the token expires almost immediately.
    let token_ep = MockTokenEndpoint::spawn("short-lived-token", 2).await;
    let dp = dataplane_from(&oauth2_yaml(token_ep.port, upstream, None));
    // First request: fetches a token.
    let (s1, _, b1) = send(&dp, "/x", vec![]).await;
    assert_eq!(s1, StatusCode::OK, "body: {b1}");
    assert!(
        b1.contains("authorization: Bearer short-lived-token"),
        "body: {b1}"
    );
    assert_eq!(token_ep.hit_count(), 1);
    // Wait for the 1s TTL to elapse (the skew-clamped minimum).
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    // Second request: the cached token is expired -> new fetch.
    let (s2, _, b2) = send(&dp, "/x", vec![]).await;
    assert_eq!(s2, StatusCode::OK, "body: {b2}");
    assert!(
        b2.contains("authorization: Bearer short-lived-token"),
        "body: {b2}"
    );
    assert_eq!(
        token_ep.hit_count(),
        2,
        "token endpoint must be hit again after expiry"
    );
}

#[tokio::test]
async fn oauth2_token_endpoint_error_returns_502() {
    let upstream = spawn_echo_upstream().await;
    let token_ep = MockTokenEndpoint::spawn_error(500).await;
    let dp = dataplane_from(&oauth2_yaml(token_ep.port, upstream, None));
    let (status, headers, body) = send(&dp, "/x", vec![]).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "body: {body}");
    assert_eq!(
        support::envelope_code(body.as_bytes()),
        "oauth2_token_unavailable",
        "error envelope must carry the oauth2 code"
    );
    // The error envelope never leaks the token endpoint's response.
    assert!(
        !body.contains("500"),
        "body must not leak upstream status: {body}"
    );
    assert!(
        !headers.contains_key("authorization"),
        "no Authorization header on a gateway-generated error"
    );
}

// ---------------------------------------------------------------------------
// mTLS consumer mapping tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mtls_consumer_mapping_by_fingerprint_resolves_consumer() {
    let upstream = spawn_echo_upstream().await;
    let cert = client_cert_with_cn("acme-client");
    let cert_identity = Arc::new(ClientCertificate::from_cert(cert.der()));
    let fp = dwara_core::config::credentials::sha256_hex(cert.der().as_ref());
    // Convert the no-colon hex to colon-separated for the config field.
    let fp_colon = fp
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(":");
    let mapping = format!(
        "    credentials: []
mtls_consumer_mapping:
  enabled: true
  consumers:
    - fingerprint: {fp_colon}
      consumer: acme"
    );
    let dp = dataplane_from(&mtls_yaml(upstream, &mapping, ""));
    let (status, _, body) =
        send_with_cert(&dp, "/x", vec![], Some(Arc::clone(&cert_identity))).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(
        body.contains("x-consumer-name: acme"),
        "upstream must see the mapped consumer: {body}"
    );
}

#[tokio::test]
async fn mtls_consumer_mapping_by_subject_cn_resolves_consumer() {
    let upstream = spawn_echo_upstream().await;
    let cert = client_cert_with_cn("acme-client");
    let cert_identity = Arc::new(ClientCertificate::from_cert(cert.der()));
    let mapping = "    credentials: []
mtls_consumer_mapping:
  enabled: true
  subject_cn_mapping:
    acme-client: acme";
    let dp = dataplane_from(&mtls_yaml(upstream, mapping, ""));
    let (status, _, body) =
        send_with_cert(&dp, "/x", vec![], Some(Arc::clone(&cert_identity))).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(
        body.contains("x-consumer-name: acme"),
        "upstream must see the mapped consumer: {body}"
    );
}

#[tokio::test]
async fn mtls_unmapped_cert_returns_401() {
    let upstream = spawn_echo_upstream().await;
    let mapping = "    credentials: []
mtls_consumer_mapping:
  enabled: true
  subject_cn_mapping:
    known-client: acme";
    let dp = dataplane_from(&mtls_yaml(upstream, mapping, ""));
    // A verified certificate matching NO mapping entry.
    let stranger = Arc::new(ClientCertificate::from_cert(
        client_cert_with_cn("someone-else").der(),
    ));
    let (status, headers, _body) = send_with_cert(&dp, "/x", vec![], Some(stranger)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(headers.contains_key("www-authenticate"));
}

#[tokio::test]
async fn mtls_forward_headers_present_at_upstream() {
    let upstream = spawn_echo_upstream().await;
    let cert = client_cert_with_cn("acme-client");
    let cert_identity = Arc::new(ClientCertificate::from_cert(cert.der()));
    let mapping = "    credentials: []
mtls_consumer_mapping:
  enabled: true
  subject_cn_mapping:
    acme-client: acme
mtls_forward_headers:
  enabled: true";
    let dp = dataplane_from(&mtls_yaml(upstream, mapping, ""));
    let (status, _, body) =
        send_with_cert(&dp, "/x", vec![], Some(Arc::clone(&cert_identity))).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    // Fingerprint (colon-separated hex, always present).
    let fp_colon = cert_identity.fingerprint_colon();
    assert!(
        body.contains(&format!("x-client-cert-fingerprint: {fp_colon}")),
        "upstream must see the fingerprint header: {body}"
    );
    // Subject CN.
    assert!(
        body.contains("x-client-cert-subject-cn: acme-client"),
        "upstream must see the subject CN header: {body}"
    );
    // Issuer CN (self-signed cert: issuer == subject).
    assert!(
        body.contains("x-client-cert-issuer-cn: acme-client"),
        "upstream must see the issuer CN header: {body}"
    );
    // Not-After (RFC 3339 timestamp, present for a well-formed cert).
    assert!(
        body.contains("x-client-cert-not-after: "),
        "upstream must see the not-after header: {body}"
    );
}

#[tokio::test]
async fn mtls_inbound_client_cert_headers_stripped_spoofing_prevention() {
    let upstream = spawn_echo_upstream().await;
    let cert = client_cert_with_cn("acme-client");
    let cert_identity = Arc::new(ClientCertificate::from_cert(cert.der()));
    let mapping = "    credentials: []
mtls_consumer_mapping:
  enabled: true
  subject_cn_mapping:
    acme-client: acme
mtls_forward_headers:
  enabled: true";
    let dp = dataplane_from(&mtls_yaml(upstream, mapping, ""));
    // Send a SPOOFED X-Client-Cert-Fingerprint header from the client.
    // The gateway must strip it and inject its own value.
    let (status, _, body) = send_with_cert(
        &dp,
        "/x",
        vec![("x-client-cert-fingerprint", "aa:bb:cc:spoofed")],
        Some(Arc::clone(&cert_identity)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(
        !body.contains("aa:bb:cc:spoofed"),
        "spoofed fingerprint must NOT reach the upstream: {body}"
    );
    // The gateway's own fingerprint is present instead.
    let fp_colon = cert_identity.fingerprint_colon();
    assert!(
        body.contains(&format!("x-client-cert-fingerprint: {fp_colon}")),
        "upstream must see the GATEWAY's fingerprint, not the client's: {body}"
    );
}

#[tokio::test]
async fn mtls_forward_headers_with_custom_prefix() {
    let upstream = spawn_echo_upstream().await;
    let cert = client_cert_with_cn("acme-client");
    let cert_identity = Arc::new(ClientCertificate::from_cert(cert.der()));
    let mapping = "    credentials: []
mtls_consumer_mapping:
  enabled: true
  subject_cn_mapping:
    acme-client: acme
mtls_forward_headers:
  enabled: true
  prefix: X-My-Cert";
    let dp = dataplane_from(&mtls_yaml(upstream, mapping, ""));
    let (status, _, body) =
        send_with_cert(&dp, "/x", vec![], Some(Arc::clone(&cert_identity))).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(
        body.contains("x-my-cert-subject-cn: acme-client"),
        "upstream must see the custom-prefixed header: {body}"
    );
    assert!(
        !body.contains("x-client-cert-subject-cn"),
        "default-prefixed header must NOT appear with a custom prefix: {body}"
    );
}
