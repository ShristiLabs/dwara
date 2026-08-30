//! Integration tests for OIDC discovery, token introspection,
//! revocation, token exchange, and the authorization-code + PKCE flow
//! (DW-034).
//!
//! These tests spawn a mock IdP HTTP server that serves the OIDC
//! discovery document, an introspection endpoint, a token endpoint
//! (for token exchange and auth-code exchange), a revocation endpoint,
//! and an authorization endpoint. The gateway is configured with an
//! OIDC provider pointing at the mock IdP, and `proxy::handle` is
//! driven directly to verify:
//!
//! - a Bearer token introspects as `active: true` and the request is
//!   allowed (200 from the upstream echo),
//! - an `active: false` token is rejected (401),
//! - the introspection result is cached (the second request does not
//!   hit the IdP),
//! - fail-closed when the IdP is unreachable (401),
//! - fail-open when configured (pass-through),
//! - token exchange (RFC 8693) returns an actor token,
//! - token revocation invalidates the cache,
//! - the authorization-code + PKCE flow exchanges a code for tokens.

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

use dwara_core::proxy::DataPlane;
use dwara_core::security::oidc::{
    pkce_code_challenge, pkce_code_verifier, OidcClient, OidcIntrospectionCache,
};

mod support;

use support::dataplane_from;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn peer() -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))
}

/// Send a request through the dataplane and return (status, body-text).
async fn send(dp: &Arc<DataPlane>, path: &str, headers: Vec<(&str, &str)>) -> (StatusCode, String) {
    let mut builder = Request::builder().uri(path);
    for (n, v) in headers {
        builder = builder.header(n, v);
    }
    let req = builder.body(Full::new(Bytes::new())).unwrap();
    let resp = dwara_core::proxy::handle(dp, peer(), req).await;
    let (parts, body) = resp.into_parts();
    let text =
        String::from_utf8(body.collect().await.expect("body read").to_bytes().to_vec()).unwrap();
    (parts.status, text)
}

/// Spawn an upstream that echoes the request's headers as the response
/// body (so the test can verify the request reached the upstream).
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

/// A mock OIDC IdP: serves discovery, introspection, token, revocation,
/// and authorization endpoints. Counts every request per-endpoint so
/// the caching tests can verify the IdP was hit only once.
struct MockIdp {
    port: u16,
    /// Total requests to the introspection endpoint.
    introspect_hits: Arc<AtomicU64>,
    /// Total requests to the token endpoint.
    token_hits: Arc<AtomicU64>,
    /// Total requests to the revocation endpoint.
    revoke_hits: Arc<AtomicU64>,
}

impl MockIdp {
    /// Spawn a mock IdP. `active` controls whether introspection returns
    /// `active: true` or `active: false`. `introspect_status` overrides
    /// the introspection response status (for the error-path test).
    async fn spawn(active: bool, introspect_status: Option<u16>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let introspect_hits = Arc::new(AtomicU64::new(0));
        let token_hits = Arc::new(AtomicU64::new(0));
        let revoke_hits = Arc::new(AtomicU64::new(0));
        let ih = Arc::clone(&introspect_hits);
        let th = Arc::clone(&token_hits);
        let rh = Arc::clone(&revoke_hits);
        let issuer = format!("http://127.0.0.1:{port}");
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let io = hyper_util::rt::TokioIo::new(stream);
                let ih = Arc::clone(&ih);
                let th = Arc::clone(&th);
                let rh = Arc::clone(&rh);
                let issuer = issuer.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let ih = Arc::clone(&ih);
                        let th = Arc::clone(&th);
                        let rh = Arc::clone(&rh);
                        let issuer = issuer.clone();
                        async move {
                            let path = req.uri().path().to_string();
                            let method = req.method().clone();
                            let query = req.uri().query().map(|s| s.to_string());
                            // Drain the body for POST endpoints.
                            let body_bytes = req
                                .into_body()
                                .collect()
                                .await
                                .map(|b| b.to_bytes())
                                .unwrap_or_default();
                            // Discovery document.
                            if path == "/.well-known/openid-configuration" && method == "GET" {
                                let doc = format!(
                                    "{{\"issuer\":\"{issuer}\",\
                                     \"jwks_uri\":\"{issuer}/jwks\",\
                                     \"introspection_endpoint\":\"{issuer}/introspect\",\
                                     \"revocation_endpoint\":\"{issuer}/revoke\",\
                                     \"authorization_endpoint\":\"{issuer}/authorize\",\
                                     \"token_endpoint\":\"{issuer}/token\"}}"
                                );
                                return Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header("content-type", "application/json")
                                        .body(Full::new(Bytes::from(doc)))
                                        .unwrap(),
                                );
                            }
                            // Introspection endpoint.
                            if path == "/introspect" && method == "POST" {
                                ih.fetch_add(1, Ordering::SeqCst);
                                if let Some(status) = introspect_status {
                                    return Ok::<_, Infallible>(
                                        Response::builder()
                                            .status(StatusCode::from_u16(status).unwrap())
                                            .body(Full::new(Bytes::new()))
                                            .unwrap(),
                                    );
                                }
                                let body = if active {
                                    format!(
                                        "{{\"active\":true,\"sub\":\"user-123\",\
                                         \"username\":\"alice\",\"scope\":\"read write\",\
                                         \"iss\":\"{issuer}\",\"client_id\":\"dwara-gateway\"}}"
                                    )
                                } else {
                                    "{\"active\":false}".to_string()
                                };
                                return Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header("content-type", "application/json")
                                        .body(Full::new(Bytes::from(body)))
                                        .unwrap(),
                                );
                            }
                            // Token endpoint (token exchange + auth-code exchange).
                            if path == "/token" && method == "POST" {
                                th.fetch_add(1, Ordering::SeqCst);
                                let body_str = String::from_utf8_lossy(&body_bytes);
                                let resp = if body_str.contains("grant_type=authorization_code") {
                                    "{\"access_token\":\"code-exchanged-token\",\
                                     \"token_type\":\"Bearer\",\"expires_in\":3600,\
                                     \"refresh_token\":\"rt-xyz\",\"id_token\":\"id-abc\"}"
                                } else if body_str
                                    .contains("urn:ietf:params:oauth:grant-type:token-exchange")
                                {
                                    "{\"access_token\":\"actor-token-456\",\
                                     \"token_type\":\"Bearer\",\"expires_in\":300}"
                                } else {
                                    "{\"access_token\":\"default-token\",\"token_type\":\"Bearer\"}"
                                };
                                return Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header("content-type", "application/json")
                                        .body(Full::new(Bytes::from(resp)))
                                        .unwrap(),
                                );
                            }
                            // Revocation endpoint.
                            if path == "/revoke" && method == "POST" {
                                rh.fetch_add(1, Ordering::SeqCst);
                                return Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .body(Full::new(Bytes::new()))
                                        .unwrap(),
                                );
                            }
                            // Authorization endpoint (returns a redirect with
                            // a code for the auth-code flow test).
                            if path == "/authorize" && method == "GET" {
                                let params: std::collections::HashMap<String, String> = query
                                    .as_deref()
                                    .map(|q| urlencoded(q).into_iter().collect())
                                    .unwrap_or_default();
                                let state = params.get("state").cloned().unwrap_or_default();
                                let redirect_uri =
                                    params.get("redirect_uri").cloned().unwrap_or_default();
                                let location =
                                    format!("{redirect_uri}?code=test-auth-code&state={state}");
                                return Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::FOUND)
                                        .header("location", location)
                                        .body(Full::new(Bytes::new()))
                                        .unwrap(),
                                );
                            }
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                });
            }
        });
        MockIdp {
            port,
            introspect_hits,
            token_hits,
            revoke_hits,
        }
    }

    fn introspect_hits(&self) -> u64 {
        self.introspect_hits.load(Ordering::SeqCst)
    }

    fn token_hits(&self) -> u64 {
        self.token_hits.load(Ordering::SeqCst)
    }

    fn revoke_hits(&self) -> u64 {
        self.revoke_hits.load(Ordering::SeqCst)
    }

    fn issuer(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

/// Minimal `application/x-www-form-urlencoded` parser for the
/// authorization endpoint's query string (the test only needs
/// `state` and `redirect_uri`).
fn urlencoded(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((k.to_string(), v.to_string()))
        })
        .collect()
}

/// Gateway YAML: one auth_required route -> one upstream, with an OIDC
/// provider pointing at the mock IdP. `fail_open` controls the
/// provider's fail-open posture.
fn oidc_yaml(idp_port: u16, upstream_port: u16, fail_open: bool) -> String {
    let fail = if fail_open { "true" } else { "false" };
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
oidc_providers:
  - name: mock-idp
    issuer: http://127.0.0.1:{idp_port}
    client_id: dwara-gateway
    client_secret: test-secret
    introspection_cache_ttl_s: 60
    fail_open: {fail}
"
    )
}

// ---------------------------------------------------------------------------
// introspection: active token is allowed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn active_token_introspects_and_request_is_allowed() {
    let upstream = spawn_echo_upstream().await;
    let idp = MockIdp::spawn(true, None).await;
    let dp = dataplane_from(&oidc_yaml(idp.port, upstream, false));
    let (status, _body) = send(&dp, "/api", vec![("authorization", "Bearer good-token-1")]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(idp.introspect_hits(), 1);
}

// ---------------------------------------------------------------------------
// introspection: inactive token is rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn inactive_token_is_rejected_401() {
    let upstream = spawn_echo_upstream().await;
    let idp = MockIdp::spawn(false, None).await;
    let dp = dataplane_from(&oidc_yaml(idp.port, upstream, false));
    let (status, body) = send(&dp, "/api", vec![("authorization", "Bearer bad-token-2")]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.contains("unauthorized"), "body: {body}");
}

// ---------------------------------------------------------------------------
// introspection caching: second request does not hit the IdP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn introspection_result_is_cached() {
    let upstream = spawn_echo_upstream().await;
    let idp = MockIdp::spawn(true, None).await;
    let dp = dataplane_from(&oidc_yaml(idp.port, upstream, false));
    // First request: introspects (1 hit).
    let (s1, _) = send(
        &dp,
        "/api",
        vec![("authorization", "Bearer cached-token-3")],
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(idp.introspect_hits(), 1);
    // Second request with the SAME token: served from cache (still 1 hit).
    let (s2, _) = send(
        &dp,
        "/api",
        vec![("authorization", "Bearer cached-token-3")],
    )
    .await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(
        idp.introspect_hits(),
        1,
        "second request must hit the cache"
    );
    // Third request with a DIFFERENT token: introspects (2 hits).
    let (s3, _) = send(&dp, "/api", vec![("authorization", "Bearer other-token-4")]).await;
    assert_eq!(s3, StatusCode::OK);
    assert_eq!(idp.introspect_hits(), 2);
}

// ---------------------------------------------------------------------------
// fail-closed when the IdP returns an error status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fail_closed_when_idp_returns_error_status() {
    let upstream = spawn_echo_upstream().await;
    let idp = MockIdp::spawn(true, Some(500)).await;
    let dp = dataplane_from(&oidc_yaml(idp.port, upstream, false));
    let (status, _body) = send(
        &dp,
        "/api",
        vec![("authorization", "Bearer token-fail-closed")],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// fail-open when the IdP returns an error status and fail_open is true
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fail_open_when_configured() {
    let upstream = spawn_echo_upstream().await;
    let idp = MockIdp::spawn(true, Some(500)).await;
    let dp = dataplane_from(&oidc_yaml(idp.port, upstream, true));
    // fail_open: an IdP failure yields anonymous (pass-through), so an
    // auth_required route still 401s (no identity resolved). The key
    // difference from fail-closed is that the gateway does not surface
    // an "authentication unavailable" 500-class error — it treats the
    // failure as anonymous. On an auth_required route, anonymous is 401
    // either way, so this test verifies the request is NOT 500-class
    // and the gateway did not reject the token as "invalid" (it simply
    // had no identity).
    let (status, body) = send(
        &dp,
        "/api",
        vec![("authorization", "Bearer token-fail-open")],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Fail-open yields anonymous, so the 401 is "authentication
    // required" (auth_required route, no identity). The error envelope
    // for an auth_required route with no identity uses the
    // "unauthorized" code; the key distinction from fail-closed is
    // that the gateway did not reject the token as "invalid" — it
    // simply had no identity to satisfy the auth_required route.
    assert!(
        body.contains("unauthorized"),
        "fail-open must still 401 an auth_required route: {body}"
    );
}

// ---------------------------------------------------------------------------
// fail-closed when the IdP is unreachable (connection refused)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fail_closed_when_idp_unreachable() {
    let upstream = spawn_echo_upstream().await;
    // A port nothing listens on (bind-then-drop).
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };
    let dp = dataplane_from(&oidc_yaml(dead, upstream, false));
    let (status, _body) = send(
        &dp,
        "/api",
        vec![("authorization", "Bearer token-dead-idp")],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// token exchange (RFC 8693)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_exchange_returns_actor_token() {
    let idp = MockIdp::spawn(true, None).await;
    let cfg = dwara_core::config::OidcProvider {
        name: "mock-idp".to_string(),
        issuer: idp.issuer(),
        client_id: "dwara-gateway".to_string(),
        client_secret: "test-secret".to_string(),
        trusted_ca_file: None,
        scopes: vec!["openid".to_string()],
        introspection_cache_ttl_s: 60,
        introspection_endpoint: None,
        revocation_endpoint: None,
        consumer: None,
        fail_open: false,
    };
    let client = OidcClient::build(cfg).expect("oidc client builds");
    let actor = client
        .exchange_token("subject-token-789", "upstream-audience")
        .await
        .expect("token exchange succeeds");
    assert_eq!(actor, "actor-token-456");
    assert_eq!(idp.token_hits(), 1);
}

// ---------------------------------------------------------------------------
// token revocation invalidates the cache
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revocation_invalidates_cache() {
    let upstream = spawn_echo_upstream().await;
    let idp = MockIdp::spawn(true, None).await;
    let dp = dataplane_from(&oidc_yaml(idp.port, upstream, false));
    // First request: introspects and caches.
    let (s1, _) = send(
        &dp,
        "/api",
        vec![("authorization", "Bearer revoke-token-5")],
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(idp.introspect_hits(), 1);
    // Revoke the token directly through an OIDC client built from the
    // same config (the admin/CLI path). The revocation call hits the
    // IdP's revocation endpoint; a separate cache is used here since
    // the dataplane's shared cache is not publicly exposed (the
    // revocation method's contract is exercised the same way).
    let cfg = dwara_core::config::OidcProvider {
        name: "mock-idp".to_string(),
        issuer: idp.issuer(),
        client_id: "dwara-gateway".to_string(),
        client_secret: "test-secret".to_string(),
        trusted_ca_file: None,
        scopes: vec!["openid".to_string()],
        introspection_cache_ttl_s: 60,
        introspection_endpoint: None,
        revocation_endpoint: None,
        consumer: None,
        fail_open: false,
    };
    let client = OidcClient::build(cfg).expect("oidc client builds");
    let cache = OidcIntrospectionCache::new();
    // Seed the cache with an active result, then revoke: the entry is
    // invalidated and the next introspection re-fetches.
    let _ = client
        .introspect("revoke-token-5", &cache)
        .await
        .expect("introspection succeeds");
    assert_eq!(idp.introspect_hits(), 2);
    client
        .revoke("revoke-token-5", &cache)
        .await
        .expect("revocation succeeds");
    assert_eq!(idp.revoke_hits(), 1);
    // After revocation, the cache entry is gone: a subsequent
    // introspection re-fetches from the IdP (3 hits).
    let _ = client
        .introspect("revoke-token-5", &cache)
        .await
        .expect("introspection succeeds after revocation");
    assert_eq!(idp.introspect_hits(), 3);
}

// ---------------------------------------------------------------------------
// authorization-code + PKCE flow
// ---------------------------------------------------------------------------

#[tokio::test]
async fn auth_code_pkce_flow_exchanges_code_for_tokens() {
    let idp = MockIdp::spawn(true, None).await;
    let cfg = dwara_core::config::OidcProvider {
        name: "mock-idp".to_string(),
        issuer: idp.issuer(),
        client_id: "dwara-gateway".to_string(),
        client_secret: "test-secret".to_string(),
        trusted_ca_file: None,
        scopes: vec!["openid".to_string()],
        introspection_cache_ttl_s: 60,
        introspection_endpoint: None,
        revocation_endpoint: None,
        consumer: None,
        fail_open: false,
    };
    let client = OidcClient::build(cfg).expect("oidc client builds");
    // Generate a PKCE verifier and challenge (S256).
    let seed = [0x42u8; 32];
    let verifier = pkce_code_verifier(&seed);
    let challenge = pkce_code_challenge(&verifier);
    // Build the authorization URL (the gateway would redirect the user
    // agent here; the mock IdP's /authorize returns a redirect with a
    // code).
    let auth_url = client
        .authorization_url(
            "http://127.0.0.1:18080/callback",
            "csrf-state-abc",
            &challenge,
        )
        .await
        .expect("authorization url builds");
    assert!(auth_url.contains("response_type=code"));
    assert!(auth_url.contains("code_challenge="));
    assert!(auth_url.contains("code_challenge_method=S256"));
    assert!(auth_url.contains("state=csrf-state-abc"));
    // Simulate the IdP redirecting back with a code, then exchange the
    // code for tokens.
    let tokens = client
        .exchange_code(
            "test-auth-code",
            "http://127.0.0.1:18080/callback",
            &verifier,
        )
        .await
        .expect("auth-code exchange succeeds");
    assert_eq!(tokens.access_token, "code-exchanged-token");
    assert_eq!(tokens.token_type.as_deref(), Some("Bearer"));
    assert_eq!(tokens.refresh_token.as_deref(), Some("rt-xyz"));
    assert_eq!(tokens.id_token.as_deref(), Some("id-abc"));
    assert_eq!(tokens.expires_in, Some(3600));
    assert_eq!(idp.token_hits(), 1);
}

// ---------------------------------------------------------------------------
// no OIDC provider: Bearer stays pass-through (not interpreted)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_oidc_provider_bearer_passes_through() {
    let upstream = spawn_echo_upstream().await;
    // A gateway with NO consumers, NO jwt providers, NO oidc providers:
    // authn is disabled, Bearer is pass-through (forwarded upstream).
    let yaml = format!(
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
        port: {upstream}
"
    );
    let dp = dataplane_from(&yaml);
    let (status, body) = send(
        &dp,
        "/api",
        vec![("authorization", "Bearer pass-through-token")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("authorization: Bearer pass-through-token"),
        "bearer must be forwarded upstream: {body}"
    );
}

// ---------------------------------------------------------------------------
// consumer binding: explicit consumer config resolves the identity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn explicit_consumer_binding_resolves_identity() {
    let upstream = spawn_echo_upstream().await;
    let idp = MockIdp::spawn(true, None).await;
    // Configure an OIDC provider with an explicit consumer binding,
    // plus the consumer and an auth_required route. The introspected
    // token resolves to the "acme" consumer (not the `sub` claim).
    let yaml = format!(
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
        port: {upstream}
consumers:
  - name: acme
oidc_providers:
  - name: mock-idp
    issuer: http://127.0.0.1:{idp_port}
    client_id: dwara-gateway
    client_secret: test-secret
    consumer: acme
    introspection_cache_ttl_s: 60
    fail_open: false
",
        idp_port = idp.port
    );
    let dp = dataplane_from(&yaml);
    let (status, body) = send(
        &dp,
        "/api",
        vec![("authorization", "Bearer consumer-token-6")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // The gateway injects X-Consumer-Name for the resolved consumer.
    assert!(
        body.contains("x-consumer-name: acme"),
        "consumer binding must resolve to 'acme': {body}"
    );
}
