//! Authentication integration tests (DW-019, feature analysis 4.6).
//!
//! Drives `proxy::handle` directly against a real upstream echo server:
//! API keys (happy/401/constant-time path), Basic auth (store-seeded),
//! JWT (signature, expiry + leeway, iss/aud, alg confusion, JWKS
//! rotation mid-flight — the issue's done-when), rate-limit identity
//! flow-through, auth_required 401 + WWW-Authenticate, and X-Consumer-*
//! strip/inject spoof prevention.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use bytes::Bytes;
use dwara_core::config::credentials::credential_selector;
use dwara_core::config::parse_gateway;
use dwara_core::proxy::DataPlane;
use dwara_core::snapshot::ConfigState;
use dwara_core::store::{sync_consumers_from_config, StateStore};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{HeaderMap, Request, Response, StatusCode};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use tokio::net::TcpListener;

const API_KEY: &str = "test-key-12345";

mod support;

use support::dataplane_from;

fn basic_config(auth_required: bool) -> String {
    format!(
        "listeners: []
routes:
  - name: r
    service: svc
    auth_required: {auth_required}
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
        port: 1
consumers:
  - name: acme
    credentials:
      - type: api_key
        key: {API_KEY}
"
    )
}

fn peer() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
}

async fn send_with(
    dp: &DataPlane,
    path: &str,
    headers: Vec<(&str, &str)>,
) -> (StatusCode, HeaderMap, String) {
    let mut builder = Request::builder().uri(path);
    for (n, v) in headers {
        builder = builder.header(n, v);
    }
    let req = builder.body(Full::new(Bytes::new())).unwrap();
    let resp = dwara_core::proxy::handle(dp, peer(), req).await;
    let (parts, body) = resp.into_parts();
    let text =
        String::from_utf8(body.collect().await.expect("body read").to_bytes().to_vec()).unwrap();
    (parts.status, parts.headers, text)
}

// ---- upstream echo --------------------------------------------------------

/// Spawn an upstream that echoes the request's headers as the response
/// body, one `name: value` line per header (order-free assertions).
async fn spawn_echo_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
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
                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(
                        lines.join("\n"),
                    ))))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });
    addr
}

fn yaml_with_upstream(auth_required: bool, upstream_port: u16) -> String {
    format!(
        "listeners: []
routes:
  - name: r
    service: svc
    auth_required: {auth_required}
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
    credentials:
      - type: api_key
        key: {API_KEY}
"
    )
}

// ---- API keys -------------------------------------------------------------

#[tokio::test]
async fn api_key_happy_and_401() {
    let dp = dataplane_from(&basic_config(false));
    let (status, _, _) = send_with(&dp, "/x", vec![("x-api-key", API_KEY)]).await;
    // Proxy attempt reached the (dead) upstream: 502, not a 401.
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let (status, _, _) = send_with(&dp, "/x", vec![("x-api-key", "wrong-key")]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // No credential: anonymous allowed (route does not require auth).
    let (status, _, _) = send_with(&dp, "/x", vec![]).await;
    assert_ne!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_key_uses_constant_time_sha256_path() {
    // The constant-time path cannot be timing-tested here; pin that the
    // registry stores the sha256 format the ct verifier expects.
    let gateway = parse_gateway(&basic_config(false)).unwrap();
    let selector = credential_selector(API_KEY);
    assert_eq!(selector.len(), 64);
    assert!(!selector.contains(API_KEY));
    assert_eq!(gateway.consumers.len(), 1);
}

#[tokio::test]
async fn auth_required_route_answers_401_with_www_authenticate() {
    let dp = dataplane_from(&basic_config(true));
    let (status, headers, _) = send_with(&dp, "/x", vec![]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        headers.get("www-authenticate").unwrap(),
        "Basic realm=\"dwara\""
    );
    // Valid key passes auth (the proxy then fails on the dead upstream:
    // 502, distinctly not 401).
    let (status, _, _) = send_with(&dp, "/x", vec![("x-api-key", API_KEY)]).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn invalid_credential_rejected_even_when_anonymous_allowed() {
    let dp = dataplane_from(&basic_config(false));
    let (status, _, _) = send_with(&dp, "/x", vec![("x-api-key", "nope")]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---- Basic auth (store-seeded) -------------------------------------------

#[tokio::test]
async fn basic_auth_against_store_seeded_credential() {
    // Config-only deployments declare API keys; Basic records live in the
    // store (username = selector, password hash = stored hash).
    let gateway = parse_gateway(&basic_config(false)).unwrap();
    let state = Arc::new(ConfigState::new());
    state.compile_and_publish(&gateway).unwrap();
    let dp = DataPlane::new(state);
    let store = Arc::new(StateStore::open_in_memory().unwrap());
    sync_consumers_from_config(&store, &gateway).unwrap();
    let consumer = store.lookup_consumer("acme").unwrap().unwrap();
    store
        .add_credential(
            consumer.id,
            dwara_core::store::CredentialKind::ApiKey,
            dwara_core::config::credentials::sha256_stored_hash("hunter2"),
            None,
            credential_selector("basic-user"),
        )
        .unwrap();
    dp.set_state_store(Arc::clone(&store));

    let creds = BASE64.encode("basic-user:hunter2");
    let (status, _, _) = send_with(
        &dp,
        "/x",
        vec![("authorization", &format!("Basic {creds}"))],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY); // past auth, dead upstream

    let bad = BASE64.encode("basic-user:wrong");
    let (status, _, _) =
        send_with(&dp, "/x", vec![("authorization", &format!("Basic {bad}"))]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let unknown = BASE64.encode("nobody:hunter2");
    let (status, _, _) = send_with(
        &dp,
        "/x",
        vec![("authorization", &format!("Basic {unknown}"))],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---- X-Consumer strip/inject ----------------------------------------------

#[tokio::test]
async fn consumer_headers_are_stripped_and_identity_injected() {
    let upstream = spawn_echo_upstream().await;
    let dp = dataplane_from(&yaml_with_upstream(false, upstream.port()));
    // Spoofed identity headers must NOT reach the upstream; the trusted
    // X-Consumer-Name of the authenticated consumer must.
    let (status, _, body) = send_with(
        &dp,
        "/x",
        vec![
            ("x-api-key", API_KEY),
            ("x-consumer-name", "evil"),
            ("x-consumer-role", "admin"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("evil"), "spoofed identity leaked: {body}");
    assert!(!body.contains("admin"), "spoofed role leaked: {body}");
    assert!(body.contains("x-consumer-name: acme"), "body: {body}");

    // Anonymous request: no X-Consumer-* at all reaches the upstream.
    let (_, _, body) = send_with(&dp, "/x", vec![("x-consumer-name", "evil")]).await;
    assert!(!body.contains("x-consumer"), "body: {body}");
}

// ---- rate-limit identity flow ---------------------------------------------

#[tokio::test]
async fn consumer_identity_feeds_rate_limiting() {
    // A policy attached to the CONSUMER applies once authN identifies the
    // consumer; anonymous requests are not limited by it.
    let yaml = format!(
        "listeners: []
routes:
  - name: r
    service: svc
    match:
      path: {{ type: regex, value: /.* }}
    action: {{ type: respond, status: 200 }}
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 1
policies:
  - name: tight
    rate_limits:
      - selector: [credential]
        requests_per: {{ minute: 1 }}
consumers:
  - name: acme
    policies: [tight]
    credentials:
      - type: api_key
        key: {API_KEY}
"
    );
    let dp = dataplane_from(&yaml);
    let (s1, h1, _) = send_with(&dp, "/x", vec![("x-api-key", API_KEY)]).await;
    assert_eq!(s1, StatusCode::OK);
    assert!(h1.contains_key("x-ratelimit-limit"));
    let (s2, _, _) = send_with(&dp, "/x", vec![("x-api-key", API_KEY)]).await;
    assert_eq!(s2, StatusCode::TOO_MANY_REQUESTS);
    // Anonymous traffic on the same route: no consumer policy applies.
    for _ in 0..3 {
        let (s, h, _) = send_with(&dp, "/x", vec![]).await;
        assert_eq!(s, StatusCode::OK);
        assert!(!h.contains_key("x-ratelimit-limit"));
    }
}

// ---- JWT ------------------------------------------------------------------

struct JwtSetup {
    dp: Arc<DataPlane>,
    jwks: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    enc: EncodingKey,
    kid: String,
}

/// Spawn a JWKS server whose key set can be FLIPPED mid-flight (the
/// done-when: rotation without restart or failure).
async fn spawn_jwks(keys: Arc<std::sync::Mutex<Vec<serde_json::Value>>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let keys = Arc::clone(&keys);
            let io = hyper_util::rt::TokioIo::new(stream);
            tokio::spawn(async move {
                let service = service_fn(move |_req: Request<Incoming>| {
                    let keys = Arc::clone(&keys);
                    async move {
                        let body = serde_json::json!({ "keys": *keys.lock().unwrap() }).to_string();
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(body)))
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
    addr
}

/// Extract the P-256 public point (x, y) from an rcgen SPKI DER.
fn p256_xy(spki_der: &[u8]) -> (String, String) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    // SPKI: SEQ { SEQ {oid...}, BIT STRING 00 04 x y }
    let body = &spki_der[spki_der.len() - 65..];
    assert_eq!(body[0], 0x04, "uncompressed EC point");
    (B64URL.encode(&body[1..33]), B64URL.encode(&body[33..65]))
}

async fn jwt_setup(issuer: Option<&str>, audience: Option<&str>) -> JwtSetup {
    jwt_setup_full(issuer, audience, None).await
}

async fn jwt_setup_full(
    issuer: Option<&str>,
    audience: Option<&str>,
    leeway: Option<u64>,
) -> JwtSetup {
    let key = rcgen::KeyPair::generate().unwrap();
    let (x, y) = p256_xy(&key.public_key_der());
    let kid = "key-1".to_string();
    let jwk = serde_json::json!({
        "kty": "EC", "crv": "P-256", "x": x, "y": y,
        "kid": kid, "alg": "ES256", "use": "sig",
    });
    let jwks = Arc::new(std::sync::Mutex::new(vec![jwk]));
    let jwks_addr = spawn_jwks(Arc::clone(&jwks)).await;
    let upstream = spawn_echo_upstream().await;
    let mut provider = format!(
        "jwt_providers:\n  - name: idp\n    jwks_url: http://127.0.0.1:{}\n    \
         algorithms: [ES256]\n",
        jwks_addr.port()
    );
    if let Some(iss) = issuer {
        provider.push_str(&format!("    issuer: {iss}\n"));
    }
    if let Some(aud) = audience {
        provider.push_str(&format!("    audience: {aud}\n"));
    }
    if let Some(l) = leeway {
        provider.push_str(&format!("    leeway_secs: {l}\n"));
    }
    let yaml = format!(
        "{provider}listeners: []
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
        port: {}
consumers:
  - name: acme
    credentials:
      - type: jwt
        issuer: https://idp.example
        audiences: [dwara-api]
",
        upstream.port()
    );
    let dp = dataplane_from(&yaml);
    let enc = EncodingKey::from_ec_der(&key.serialize_der());
    JwtSetup { dp, jwks, enc, kid }
}

fn token_with_kid(setup: &JwtSetup, claims: &serde_json::Value, kid: &str) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(kid.to_string());
    jsonwebtoken::encode(&header, claims, &setup.enc).unwrap()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn es_claims(iss: &str, aud: &str, exp: u64) -> serde_json::Value {
    serde_json::json!({
        "iss": iss, "aud": aud, "sub": "user-1", "exp": exp,
    })
}

#[tokio::test]
async fn jwt_happy_path_maps_consumer_and_injects_identity() {
    let setup = jwt_setup(Some("https://idp.example"), Some("dwara-api")).await;
    let claims = es_claims("https://idp.example", "dwara-api", now() + 3600);
    let tok = token_with_kid(&setup, &claims, &setup.kid);
    let (status, _, body) = send_with(
        &setup.dp,
        "/x",
        vec![("authorization", &format!("Bearer {tok}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body.contains("x-consumer-name: acme"), "body: {body}");
}

#[tokio::test]
async fn jwt_rejects_forged_expired_wrong_iss_aud_and_alg_confusion() {
    let setup = jwt_setup(Some("https://idp.example"), Some("dwara-api")).await;

    // Forged: signed by a DIFFERENT key (verification failure).
    let forged_key = rcgen::KeyPair::generate().unwrap();
    let forged_enc = EncodingKey::from_ec_der(&forged_key.serialize_der());
    let claims = es_claims("https://idp.example", "dwara-api", now() + 3600);
    let forged = jsonwebtoken::encode(
        &Header {
            kid: Some(setup.kid.clone()),
            ..Header::new(Algorithm::ES256)
        },
        &claims,
        &forged_enc,
    )
    .unwrap();
    let (status, _, _) = send_with(
        &setup.dp,
        "/x",
        vec![("authorization", &format!("Bearer {forged}"))],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Expired beyond leeway.
    let expired = token_with_kid(
        &setup,
        &es_claims("https://idp.example", "dwara-api", now() - 3600),
        &setup.kid,
    );
    let (status, _, _) = send_with(
        &setup.dp,
        "/x",
        vec![("authorization", &format!("Bearer {expired}"))],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Within leeway (default 30s): a token expiring in 10s passes.
    let nearly = token_with_kid(
        &setup,
        &es_claims("https://idp.example", "dwara-api", now() + 10),
        &setup.kid,
    );
    let (status, _, _) = send_with(
        &setup.dp,
        "/x",
        vec![("authorization", &format!("Bearer {nearly}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Wrong issuer.
    let wrong_iss = token_with_kid(
        &setup,
        &es_claims("https://evil.example", "dwara-api", now() + 3600),
        &setup.kid,
    );
    let (status, _, _) = send_with(
        &setup.dp,
        "/x",
        vec![("authorization", &format!("Bearer {wrong_iss}"))],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Wrong audience.
    let wrong_aud = token_with_kid(
        &setup,
        &es_claims("https://idp.example", "other-api", now() + 3600),
        &setup.kid,
    );
    let (status, _, _) = send_with(
        &setup.dp,
        "/x",
        vec![("authorization", &format!("Bearer {wrong_aud}"))],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Alg confusion: an HS256-header token (signed with whatever key
    // material the attacker has) against the ES256-only provider.
    let hs_header = serde_json::json!({ "alg": "HS256", "kid": setup.kid, "typ": "JWT" });
    let payload = serde_json::json!({ "iss": "https://idp.example", "aud": "dwara-api", "exp": now() + 3600 });
    let hs_token = format!(
        "{}.{}.attacker-signature",
        b64url(&hs_header.to_string()),
        b64url(&payload.to_string())
    );
    let (status, _, _) = send_with(
        &setup.dp,
        "/x",
        vec![("authorization", &format!("Bearer {hs_token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

fn b64url(s: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B;
    B.encode(s)
}

#[tokio::test]
async fn jwks_rotation_mid_flight_serves_new_kid_without_failure() {
    // The issue's done-when: the server serves kid A, then flips to kid B
    // mid-flight; requests with the NEW key's tokens succeed without a
    // gateway restart or failure.
    let setup = jwt_setup(Some("https://idp.example"), Some("dwara-api")).await;

    // Warm the cache with key A.
    let claims = es_claims("https://idp.example", "dwara-api", now() + 3600);
    let tok_a = token_with_kid(&setup, &claims, "key-1");
    let (status, _, _) = send_with(
        &setup.dp,
        "/x",
        vec![("authorization", &format!("Bearer {tok_a}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Rotate: the JWKS now serves ONLY key B.
    let key_b = rcgen::KeyPair::generate().unwrap();
    let (bx, by) = p256_xy(&key_b.public_key_der());
    *setup.jwks.lock().unwrap() = vec![serde_json::json!({
        "kty": "EC", "crv": "P-256", "x": bx, "y": by,
        "kid": "key-2", "alg": "ES256", "use": "sig",
    })];
    let enc_b = EncodingKey::from_ec_der(&key_b.serialize_der());
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("key-2".to_string());
    let tok_b = jsonwebtoken::encode(&header, &claims, &enc_b).unwrap();

    // Unknown kid triggers a refresh; the B token verifies immediately.
    let (status, _, body) = send_with(
        &setup.dp,
        "/x",
        vec![("authorization", &format!("Bearer {tok_b}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rotation failed: {body}");

    // And the RETIRED key's tokens no longer verify.
    let (status, _, _) = send_with(
        &setup.dp,
        "/x",
        vec![("authorization", &format!("Bearer {tok_a}"))],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bearer_passes_through_when_no_provider_configured() {
    // A gateway with consumers but no jwt_providers forwards the client's
    // Authorization header upstream untouched (documented pass-through).
    let upstream = spawn_echo_upstream().await;
    let yaml = yaml_with_upstream(false, upstream.port());
    let dp = dataplane_from(&yaml);
    let (status, _, body) =
        send_with(&dp, "/x", vec![("authorization", "Bearer upstreams-token")]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("authorization: Bearer upstreams-token"),
        "body: {body}"
    );
}

// ---- config validation ----------------------------------------------------

#[test]
fn jwt_provider_validation_rejects_bad_configs() {
    let base = "jwt_providers:\n  - name: idp\n    jwks_url: http://127.0.0.1:1/jwks\n";
    let gateway = parse_gateway(base).unwrap();
    assert!(dwara_core::snapshot::validate(&gateway).is_empty());

    let gateway = parse_gateway(
        "jwt_providers:\n  - name: idp\n    jwks_url: http://127.0.0.1:1/jwks\n    algorithms: [HS256]\n",
    )
    .unwrap();
    let issues = dwara_core::snapshot::validate(&gateway);
    assert!(issues.iter().any(|i| i.message.contains("asymmetric")));

    let gateway = parse_gateway(
        "jwt_providers:\n  - name: idp\n    jwks_url: http://127.0.0.1:1/jwks\n    consumer: ghost\n",
    )
    .unwrap();
    let issues = dwara_core::snapshot::validate(&gateway);
    assert!(issues
        .iter()
        .any(|i| i.message.contains("unknown consumer")));

    let gateway =
        parse_gateway("jwt_providers:\n  - name: idp\n    jwks_url: not-a-url\n").unwrap();
    let issues = dwara_core::snapshot::validate(&gateway);
    assert!(issues.iter().any(|i| i.message.contains("absolute http")));
}

#[test]
fn jwt_provider_validation_rejects_url_algorithm_and_refresh_edge_cases() {
    // Relative URL: no scheme.
    let gateway =
        parse_gateway("jwt_providers:\n  - name: idp\n    jwks_url: /jwks.json\n").unwrap();
    let issues = dwara_core::snapshot::validate(&gateway);
    assert!(issues.iter().any(|i| i.message.contains("absolute http")));

    // Non-http scheme.
    let gateway =
        parse_gateway("jwt_providers:\n  - name: idp\n    jwks_url: ftp://idp/jwks\n").unwrap();
    let issues = dwara_core::snapshot::validate(&gateway);
    assert!(issues.iter().any(|i| i.message.contains("absolute http")));

    // Empty algorithm list.
    let gateway = parse_gateway(
        "jwt_providers:\n  - name: idp\n    jwks_url: http://127.0.0.1:1/jwks\n    algorithms: []\n",
    )
    .unwrap();
    let issues = dwara_core::snapshot::validate(&gateway);
    assert!(issues
        .iter()
        .any(|i| i.message.contains("at least one algorithm")));

    // Zero refresh cadence.
    let gateway = parse_gateway(
        "jwt_providers:\n  - name: idp\n    jwks_url: http://127.0.0.1:1/jwks\n    refresh_secs: 0\n",
    )
    .unwrap();
    let issues = dwara_core::snapshot::validate(&gateway);
    assert!(issues
        .iter()
        .any(|i| i.message.contains("refresh_secs must be > 0")));
}

// ---- negative matrix: malformed credentials --------------------------------

#[tokio::test]
async fn malformed_authorization_and_api_key_shapes_answer_401() {
    let dp = dataplane_from(&basic_config(true));
    let cases: Vec<(&str, String)> = vec![
        // Unknown Authorization scheme is not a credential family: the
        // request is anonymous (pinned separately below), which 401s on
        // an auth_required route.
        ("authorization", "Digest realm=x, nonce=y".to_string()),
        // Basic: undecodable base64.
        ("authorization", "Basic !!!not-base64!!!".to_string()),
        // Basic: valid base64 but no ':' separator.
        (
            "authorization",
            format!("Basic {}", BASE64.encode("useronly")),
        ),
        // Basic: empty username.
        ("authorization", format!("Basic {}", BASE64.encode(":pass"))),
        // Basic: empty password.
        ("authorization", format!("Basic {}", BASE64.encode("user:"))),
        // Bearer with no token.
        ("authorization", "Bearer".to_string()),
        ("authorization", "Bearer   ".to_string()),
        // Empty API key header value.
        ("x-api-key", "".to_string()),
    ];
    for (name, value) in cases {
        let (status, _, _) = send_with(&dp, "/x", vec![(name, value.as_str())]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "case {name}:{value}");
    }
}

#[tokio::test]
async fn unknown_authorization_scheme_is_anonymous_pass_through() {
    // A scheme the gateway does not interpret (Digest) is not a presented
    // credential: on an open route the request proceeds anonymously.
    let dp = dataplane_from(&basic_config(false));
    let (status, _, _) = send_with(&dp, "/x", vec![("authorization", "Digest realm=x")]).await;
    // Dead upstream: 502 proves the request was NOT rejected as anonymous
    // or invalid — it was forwarded.
    assert_eq!(status, StatusCode::BAD_GATEWAY);
}

// ---- JWKS lab: raw-body server for refresh/malformed/endpoint-down cases --

struct JwksLab {
    dp: Arc<DataPlane>,
    /// Raw JWKS response body, mutable mid-flight.
    body: Arc<std::sync::Mutex<Vec<u8>>>,
    #[allow(dead_code)]
    jwks_port: u16,
}

fn ec_jwk(key: &rcgen::KeyPair, kid: &str) -> serde_json::Value {
    let (x, y) = p256_xy(&key.public_key_der());
    serde_json::json!({
        "kty": "EC", "crv": "P-256", "x": x, "y": y,
        "kid": kid, "alg": "ES256", "use": "sig",
    })
}

/// Serve an arbitrary (possibly garbage) body at /jwks.
async fn spawn_raw_jwks(body: Arc<std::sync::Mutex<Vec<u8>>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let body = Arc::clone(&body);
            let io = hyper_util::rt::TokioIo::new(stream);
            tokio::spawn(async move {
                let service = service_fn(move |_req: Request<Incoming>| {
                    let body = Arc::clone(&body);
                    async move {
                        let bytes = body.lock().unwrap().clone();
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(bytes)))
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
    addr
}

async fn jwks_lab(refresh_secs: u64) -> (JwksLab, rcgen::KeyPair) {
    let key = rcgen::KeyPair::generate().unwrap();
    let body = Arc::new(std::sync::Mutex::new(
        serde_json::json!({ "keys": [ec_jwk(&key, "key-1")] })
            .to_string()
            .into_bytes(),
    ));
    let jwks_addr = spawn_raw_jwks(Arc::clone(&body)).await;
    let upstream = spawn_echo_upstream().await;
    let yaml = format!(
        "jwt_providers:
  - name: idp
    jwks_url: http://127.0.0.1:{}
    algorithms: [ES256]
    issuer: https://idp.example
    audience: dwara-api
    refresh_secs: {refresh_secs}
listeners: []
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
        port: {}
consumers:
  - name: acme
    credentials:
      - type: jwt
        issuer: https://idp.example
        audiences: [dwara-api]
",
        jwks_addr.port(),
        upstream.port()
    );
    let dp = dataplane_from(&yaml);
    (
        JwksLab {
            dp,
            body,
            jwks_port: jwks_addr.port(),
        },
        key,
    )
}

fn lab_token(key: &rcgen::KeyPair, kid: &str) -> String {
    let enc = EncodingKey::from_ec_der(&key.serialize_der());
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(kid.to_string());
    jsonwebtoken::encode(
        &header,
        &es_claims("https://idp.example", "dwara-api", now() + 3600),
        &enc,
    )
    .unwrap()
}

#[tokio::test]
async fn jwt_tampered_payload_fails_signature() {
    let (lab, key) = jwks_lab(300).await;
    // Warm the cache, then tamper with the payload segment of a valid
    // token: the signature no longer covers the claims.
    let tok = lab_token(&key, "key-1");
    let (status, _, _) = send_with(
        &lab.dp,
        "/x",
        vec![("authorization", &format!("Bearer {tok}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let mut segs = tok.split('.').collect::<Vec<_>>();
    assert_eq!(segs.len(), 3);
    let tampered_payload = serde_json::json!({
        "iss": "https://idp.example", "aud": "dwara-api",
        "sub": "attacker", "exp": now() + 3600, "role": "admin",
    });
    let tampered_payload_b64 = b64url(&tampered_payload.to_string());
    segs[1] = &tampered_payload_b64;
    let tampered = segs.join(".");
    let (status, _, _) = send_with(
        &lab.dp,
        "/x",
        vec![("authorization", &format!("Bearer {tampered}"))],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Structurally malformed tokens (not three segments) also 401.
    for junk in ["not-a-token", "a.b", "a.b.c.d"] {
        let (status, _, _) = send_with(
            &lab.dp,
            "/x",
            vec![("authorization", &format!("Bearer {junk}"))],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "junk: {junk}");
    }
}

#[tokio::test]
async fn jwt_from_entirely_unknown_key_answers_401_not_500() {
    let (lab, _key) = jwks_lab(300).await;
    // Signed by a key the issuer never published, with a kid the JWKS
    // does not know: refresh happens, still unknown -> 401 (invalid),
    // never a gateway-side 500.
    let stranger = rcgen::KeyPair::generate().unwrap();
    let tok = lab_token(&stranger, "ghost-kid");
    let (status, _, _) = send_with(
        &lab.dp,
        "/x",
        vec![("authorization", &format!("Bearer {tok}"))],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cached_jwks_keeps_verifying_while_fresh_then_refreshes_after_expiry() {
    let (lab, key) = jwks_lab(1).await; // 1s staleness bound
    let tok_a = lab_token(&key, "key-1");
    let (status, _, _) = send_with(
        &lab.dp,
        "/x",
        vec![("authorization", &format!("Bearer {tok_a}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The endpoint flips to serve ONLY key B. While the cache is fresh
    // (sub-second), the OLD cached key set still verifies key-1 tokens —
    // an endpoint disturbance is not an immediate outage.
    let key_b = rcgen::KeyPair::generate().unwrap();
    *lab.body.lock().unwrap() = serde_json::json!({ "keys": [ec_jwk(&key_b, "key-2")] })
        .to_string()
        .into_bytes();
    let (status, _, _) = send_with(
        &lab.dp,
        "/x",
        vec![("authorization", &format!("Bearer {tok_a}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "fresh cache should keep old key");

    // FIXED BEHAVIOR (developer flip, DW-019 loop 1 — the ONLY authorized
    // edit in this tester file): after the staleness bound passes, the
    // cache refreshes BEFORE use even for a KNOWN kid. The endpoint now
    // serves only key-2, so the retired key-1 token no longer verifies:
    // stale cached sets cannot keep verifying retired issuer keys forever.
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let (status, _, _) = send_with(
        &lab.dp,
        "/x",
        vec![("authorization", &format!("Bearer {tok_a}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "stale cache must refresh before use; retired kid -> 401"
    );

    // An unknown kid forces the refresh against the endpoint: the cache
    // swaps to the new set (which lacks both key-1 and the ghost).
    let stranger = rcgen::KeyPair::generate().unwrap();
    let ghost = lab_token(&stranger, "ghost");
    let (status, _, _) = send_with(
        &lab.dp,
        "/x",
        vec![("authorization", &format!("Bearer {ghost}"))],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // After the swap, the retired key-1 no longer verifies and key-2 does.
    let (status, _, _) = send_with(
        &lab.dp,
        "/x",
        vec![("authorization", &format!("Bearer {tok_a}"))],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let tok_b = lab_token(&key_b, "key-2");
    let (status, _, _) = send_with(
        &lab.dp,
        "/x",
        vec![("authorization", &format!("Bearer {tok_b}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn malformed_jwks_body_keeps_cached_keys_working_and_500s_only_on_refresh() {
    let (lab, key) = jwks_lab(300).await;
    let tok = lab_token(&key, "key-1");
    let (status, _, _) = send_with(
        &lab.dp,
        "/x",
        vec![("authorization", &format!("Bearer {tok}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The endpoint starts serving garbage. Cached keys keep verifying —
    // no outage for already-known keys.
    *lab.body.lock().unwrap() = b"{{{not json at all".to_vec();
    let (status, _, _) = send_with(
        &lab.dp,
        "/x",
        vec![("authorization", &format!("Bearer {tok}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "cached keys must survive garbage jwks"
    );

    // A refresh forced by an unknown kid hits the garbage: gateway-side
    // failure -> 500 (the gateway cannot vouch for the caller either way).
    let stranger = rcgen::KeyPair::generate().unwrap();
    let unknown = lab_token(&stranger, "ghost");
    let (status, _, _) = send_with(
        &lab.dp,
        "/x",
        vec![("authorization", &format!("Bearer {unknown}"))],
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn jwks_endpoint_down_answers_500_without_panicking_or_hanging() {
    // Reserve a port then drop the listener: connection refused on every
    // fetch. The first Bearer request must fail fast with a 500 (gateway
    // cannot verify), never a panic or hang.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let key = rcgen::KeyPair::generate().unwrap();
    let yaml = format!(
        "jwt_providers:
  - name: idp
    jwks_url: http://127.0.0.1:{port}
    algorithms: [ES256]
listeners: []
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
        port: 1
consumers:
  - name: acme
    credentials:
      - type: jwt
        issuer: https://idp.example
        audiences: [dwara-api]
"
    );
    let dp = dataplane_from(&yaml);
    let tok = lab_token(&key, "key-1");
    let hdr = format!("Bearer {tok}");
    let (status, _, _) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        send_with(&dp, "/x", vec![("authorization", hdr.as_str())]),
    )
    .await
    .expect("must not hang");
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

// ---- hash-format dispatch through the store path ---------------------------

#[tokio::test]
async fn argon2id_and_unknown_format_hashes_dispatch_cleanly() {
    // A PHC argon2id hash seeded in the store verifies through the SAME
    // hot path; a wrong password and an unknown hash format are clean
    // 401s, never 500s.
    let gateway = parse_gateway(&basic_config(false)).unwrap();
    let state = Arc::new(ConfigState::new());
    state.compile_and_publish(&gateway).unwrap();
    let dp = DataPlane::new(state);
    let store = Arc::new(StateStore::open_in_memory().unwrap());
    sync_consumers_from_config(&store, &gateway).unwrap();
    let consumer = store.lookup_consumer("acme").unwrap().unwrap();

    use argon2::password_hash::{PasswordHasher as _, SaltString};
    let salt = SaltString::from_b64("c2FsdHNhbHRzYWx0c2FsdHNhbHQ").unwrap();
    let phc = argon2::Argon2::default()
        .hash_password(b"phc-password", &salt)
        .unwrap()
        .to_string();
    store
        .add_credential(
            consumer.id,
            dwara_core::store::CredentialKind::ApiKey,
            phc,
            None,
            credential_selector("phc-user"),
        )
        .unwrap();
    // An unknown-format hash can never accept.
    store
        .add_credential(
            consumer.id,
            dwara_core::store::CredentialKind::ApiKey,
            "bcrypt:$2b$12$whatever".to_string(),
            None,
            credential_selector("odd-user"),
        )
        .unwrap();
    dp.set_state_store(Arc::clone(&store));

    // Correct password via Basic: past auth (dead upstream -> 502).
    let ok = BASE64.encode("phc-user:phc-password");
    let (status, _, _) =
        send_with(&dp, "/x", vec![("authorization", &format!("Basic {ok}"))]).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);

    // Wrong password: clean 401.
    let bad = BASE64.encode("phc-user:wrong");
    let (status, _, _) =
        send_with(&dp, "/x", vec![("authorization", &format!("Basic {bad}"))]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Unknown-format stored hash: clean 401, never an error.
    let odd = BASE64.encode("odd-user:phc-password");
    let (status, _, _) =
        send_with(&dp, "/x", vec![("authorization", &format!("Basic {odd}"))]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---- store-backed hot path + revocation ------------------------------------

#[tokio::test]
async fn store_backed_credentials_authenticate_and_revoke_is_immediate() {
    let gateway = parse_gateway(&basic_config(false)).unwrap();
    let state = Arc::new(ConfigState::new());
    state.compile_and_publish(&gateway).unwrap();
    let dp = DataPlane::new(state);
    let store = Arc::new(StateStore::open_in_memory().unwrap());
    sync_consumers_from_config(&store, &gateway).unwrap();
    let consumer = store.lookup_consumer("acme").unwrap().unwrap();
    let extra = store
        .add_credential(
            consumer.id,
            dwara_core::store::CredentialKind::ApiKey,
            dwara_core::config::credentials::sha256_stored_hash("store-only-key"),
            None,
            credential_selector("store-only-key"),
        )
        .unwrap();
    dp.set_state_store(Arc::clone(&store));

    // Config-seeded key works THROUGH the store (hot path).
    let (status, _, _) = send_with(&dp, "/x", vec![("x-api-key", API_KEY)]).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    // Store-only credential (no config declaration) works too.
    let (status, _, _) = send_with(&dp, "/x", vec![("x-api-key", "store-only-key")]).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);

    // Revocation takes effect on the very next request (cache invalidated).
    store.revoke_credential(extra.id).unwrap();
    let (status, _, _) = send_with(&dp, "/x", vec![("x-api-key", "store-only-key")]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Other credentials are unaffected.
    let (status, _, _) = send_with(&dp, "/x", vec![("x-api-key", API_KEY)]).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
}

// ---- hostile unknown-kid throttle (DW-019 loop 2, the high) -----------------

/// A JWKS server that COUNTS fetches (AtomicU64) while serving a mutable
/// key set — the oracle for the DoS-bound pin.
async fn spawn_counting_jwks(
    keys: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    fetches: Arc<std::sync::atomic::AtomicU64>,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let keys = Arc::clone(&keys);
            let fetches = Arc::clone(&fetches);
            let io = hyper_util::rt::TokioIo::new(stream);
            tokio::spawn(async move {
                let service = service_fn(move |_req: Request<Incoming>| {
                    let keys = Arc::clone(&keys);
                    let fetches = Arc::clone(&fetches);
                    async move {
                        fetches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let body = serde_json::json!({ "keys": *keys.lock().unwrap() }).to_string();
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(body)))
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
    addr
}

#[tokio::test]
async fn hostile_random_kid_storm_is_throttled_and_rotation_still_works() {
    use std::sync::atomic::{AtomicU64, Ordering};

    let key = rcgen::KeyPair::generate().unwrap();
    let jwks = Arc::new(std::sync::Mutex::new(vec![ec_jwk(&key, "key-1")]));
    let fetches = Arc::new(AtomicU64::new(0));
    let jwks_addr = spawn_counting_jwks(Arc::clone(&jwks), Arc::clone(&fetches)).await;
    let upstream = spawn_echo_upstream().await;
    // refresh_secs 1: the forced-refresh throttle window is min(5s, 1s) = 1s,
    // so the post-storm legitimate rotation only needs a ~1.2s sleep.
    let yaml = format!(
        "jwt_providers:
  - name: idp
    jwks_url: http://127.0.0.1:{}
    algorithms: [ES256]
    issuer: https://idp.example
    audience: dwara-api
    refresh_secs: 1
listeners: []
routes:
  - name: r
    service: svc
    match: {{ path: {{ type: regex, value: /.* }} }}
    action: {{ type: proxy }}
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: {}
consumers:
  - name: acme
    credentials:
      - type: jwt
        issuer: https://idp.example
        audiences: [dwara-api]
",
        jwks_addr.port(),
        upstream.port()
    );
    let dp = dataplane_from(&yaml);

    // Warm the cache with a legitimate key-1 token (fetch #1).
    let tok_a = lab_token(&key, "key-1");
    let (status, _, _) = send_with(
        &dp,
        "/x",
        vec![("authorization", &format!("Bearer {tok_a}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // THE STORM: 25 requests, each with a UNIQUE random kid. Every one
    // must 401, the total fetch budget is bounded (first warm + at most
    // one window-edge fetch), and the whole storm completes quickly (no
    // serialized-fetch stall).
    let start = std::time::Instant::now();
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        for i in 0..25 {
            let stranger = rcgen::KeyPair::generate().unwrap();
            let tok = lab_token(&stranger, &format!("forged-kid-{i}"));
            let (status, _, _) =
                send_with(&dp, "/x", vec![("authorization", &format!("Bearer {tok}"))]).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "forged req {i}");
        }
    })
    .await
    .expect("storm must not stall the dataplane");
    let elapsed = start.elapsed();
    let served = fetches.load(Ordering::SeqCst);
    assert!(
        served <= 2,
        "hostile random-kid storm bought {served} fetches (bound: 2)"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(20),
        "storm wall time {elapsed:?} is not bounded"
    );

    // THE PRESERVED DONE-WHEN: after the throttle window passes, a
    // LEGITIMATE rotation (the issuer publishes a new key) still pays at
    // most one fetch and the new-kid token verifies — the throttle bounds
    // attackers, not the issuer.
    let before = fetches.load(Ordering::SeqCst);
    let key_b = rcgen::KeyPair::generate().unwrap();
    *jwks.lock().unwrap() = vec![ec_jwk(&key_b, "key-2")];
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let tok_b = lab_token(&key_b, "key-2");
    let (status, _, body) = send_with(
        &dp,
        "/x",
        vec![("authorization", &format!("Bearer {tok_b}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rotation failed: {body}");
    let spent = fetches.load(Ordering::SeqCst) - before;
    assert_eq!(spent, 1, "legitimate rotation cost {spent} fetches");
}

// ---- legacy config:api_key: cleanup e2e (DW-019 loop 2) ---------------------

#[tokio::test]
async fn legacy_config_api_key_rows_are_deleted_at_sync_and_bindings_survive() {
    let gateway = parse_gateway(
        "consumers:\n  - name: acme\n    credentials:\n      - type: api_key\n        \
         key: secret-key\n      - type: jwt\n        issuer: https://issuer.example\n",
    )
    .unwrap();
    let store = StateStore::open_in_memory().unwrap();
    // Hand-insert a pre-DW-019 store exactly as the transitional build left
    // it: a PLAINTEXT selector with a `config:api_key:<key>` placeholder
    // hash (the secret verbatim), plus a current-format jwt binding row.
    store.upsert_consumer("acme", None).unwrap();
    let consumer = store.lookup_consumer("acme").unwrap().unwrap();
    store
        .add_credential(
            consumer.id,
            dwara_core::store::CredentialKind::ApiKey,
            "config:api_key:secret-key".into(),
            None,
            "secret-key".into(),
        )
        .unwrap();
    store
        .add_credential(
            consumer.id,
            dwara_core::store::CredentialKind::Jwt,
            "config:jwt:https://issuer.example".into(),
            None,
            "https://issuer.example".into(),
        )
        .unwrap();

    sync_consumers_from_config(&store, &gateway).unwrap();

    // The legacy row (plaintext secret) is GONE...
    assert!(store
        .lookup_credentials_by_selector("secret-key")
        .unwrap()
        .is_empty());
    // ...the properly hashed api_key row is present...
    let selector = credential_selector("secret-key");
    let api = store.lookup_credentials_by_selector(&selector).unwrap();
    assert_eq!(api.len(), 1);
    assert_eq!(
        api[0].hash,
        dwara_core::config::credentials::sha256_stored_hash("secret-key")
    );
    // ...and the config:jwt: binding row SURVIVES the cleanup.
    let jwt = store
        .lookup_credentials_by_selector("https://issuer.example")
        .unwrap();
    assert!(jwt
        .iter()
        .any(|c| c.hash == "config:jwt:https://issuer.example"));
}

// ---- consumer-name visible-ASCII validation (DW-019 loop 2) ----------------

#[test]
fn consumer_name_validation_rejects_unicode_and_accepts_visible_ascii() {
    // A unicode (non-visible-ASCII) name cannot be a header value and is
    // rejected at compile time with a ValidationIssue.
    let gateway = parse_gateway(
        "consumers:\n  - name: \"acmé-ünicode\"\n    credentials:\n      - { type: api_key, key: k }\n",
    )
    .unwrap();
    let issues = dwara_core::snapshot::validate(&gateway);
    assert!(
        issues.iter().any(|i| i.message.contains("visible ASCII")),
        "issues: {issues:?}"
    );

    // Control characters (a tab) are likewise not visible ASCII.
    let gateway = parse_gateway(
        "consumers:\n  - name: \"a\\tb\"\n    credentials:\n      - { type: api_key, key: k }\n",
    )
    .unwrap();
    let issues = dwara_core::snapshot::validate(&gateway);
    assert!(
        issues.iter().any(|i| i.message.contains("visible ASCII")),
        "issues: {issues:?}"
    );

    // A plain visible-ASCII name is accepted (no name-related issue).
    let gateway = parse_gateway(
        "consumers:\n  - name: acme.corp_1\n    credentials:\n      - { type: api_key, key: k }\n",
    )
    .unwrap();
    let issues = dwara_core::snapshot::validate(&gateway);
    assert!(
        !issues.iter().any(|i| i.message.contains("visible ASCII")),
        "issues: {issues:?}"
    );
}

// ---- stale-cache refresh degradation (DW-019 loop 2 pin) --------------------

#[tokio::test]
async fn stale_cache_with_garbage_endpoint_degrades_to_cached_keys() {
    // A STALE cache (age > refresh_secs) must refresh before use; when the
    // refresh fails because the endpoint serves garbage, the cached keys
    // KEEP VERIFYING — degradation, not an outage.
    let (lab, key) = jwks_lab(1).await; // 1s staleness bound
    let tok = lab_token(&key, "key-1");
    let (status, _, _) = send_with(
        &lab.dp,
        "/x",
        vec![("authorization", &format!("Bearer {tok}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The endpoint goes bad AND the cache goes stale.
    *lab.body.lock().unwrap() = b"{{{garbage not json".to_vec();
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let (status, _, body) = send_with(
        &lab.dp,
        "/x",
        vec![("authorization", &format!("Bearer {tok}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "stale cache + garbage endpoint must degrade to cached keys: {body}"
    );

    // Still true on the immediately following request (the failed refresh
    // did not poison the cache).
    let (status, _, _) = send_with(
        &lab.dp,
        "/x",
        vec![("authorization", &format!("Bearer {tok}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ---- stale-cache failed-refresh backoff (DW-019 loop 3, reviewer #20) -------

/// A raw-body JWKS server that COUNTS fetches: the oracle for the
/// failed-refresh backoff pin (fetch attempts are observable even though
/// each failure here is fast).
async fn spawn_counting_raw_jwks(
    body: Arc<std::sync::Mutex<Vec<u8>>>,
    fetches: Arc<std::sync::atomic::AtomicU64>,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let body = Arc::clone(&body);
            let fetches = Arc::clone(&fetches);
            let io = hyper_util::rt::TokioIo::new(stream);
            tokio::spawn(async move {
                let service = service_fn(move |_req: Request<Incoming>| {
                    let body = Arc::clone(&body);
                    let fetches = Arc::clone(&fetches);
                    async move {
                        fetches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let bytes = body.lock().unwrap().clone();
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(bytes)))
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
    addr
}

#[tokio::test]
async fn stale_cache_failed_refresh_backs_off_instead_of_refetching_per_request() {
    use std::sync::atomic::{AtomicU64, Ordering};

    // refresh_secs 1: the failure backoff window is min(5s, 1s) = 1s, so
    // the post-backoff recovery attempt needs only a ~1.2s sleep.
    let key = rcgen::KeyPair::generate().unwrap();
    let body = Arc::new(std::sync::Mutex::new(
        serde_json::json!({ "keys": [ec_jwk(&key, "key-1")] })
            .to_string()
            .into_bytes(),
    ));
    let fetches = Arc::new(AtomicU64::new(0));
    let jwks_addr = spawn_counting_raw_jwks(Arc::clone(&body), Arc::clone(&fetches)).await;
    let upstream = spawn_echo_upstream().await;
    let yaml = format!(
        "jwt_providers:
  - name: idp
    jwks_url: http://127.0.0.1:{}
    algorithms: [ES256]
    issuer: https://idp.example
    audience: dwara-api
    refresh_secs: 1
listeners: []
routes:
  - name: r
    service: svc
    match: {{ path: {{ type: regex, value: /.* }} }}
    action: {{ type: proxy }}
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
    - address: 127.0.0.1
      port: {}
consumers:
  - name: acme
    credentials:
      - type: jwt
        issuer: https://idp.example
        audiences: [dwara-api]
",
        jwks_addr.port(),
        upstream.port()
    );
    let dp = dataplane_from(&yaml);
    let tok = lab_token(&key, "key-1");
    let hdr = format!("Bearer {tok}");

    // Warm the cache (fetch #1).
    let (status, _, _) = send_with(&dp, "/x", vec![("authorization", hdr.as_str())]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fetches.load(Ordering::SeqCst), 1);

    // The endpoint goes bad (garbage body) AND the cache goes stale. The
    // FIRST stale request pays one doomed refresh (fetch #2, fails, the
    // gateway degrades to the cached keys: 200, not an outage).
    *body.lock().unwrap() = b"{{{endpoint is down garbage".to_vec();
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let (status, _, body_txt) = send_with(&dp, "/x", vec![("authorization", hdr.as_str())]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "first failed refresh must degrade to cached keys: {body_txt}"
    );
    assert_eq!(fetches.load(Ordering::SeqCst), 2);

    // THE PIN: while the failure backoff window holds, ten more stale
    // Bearer requests answer from the cached keys WITHOUT any new fetch
    // attempt — bounded wall time, bounded fetch budget, all 200s.
    let start = std::time::Instant::now();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        for _ in 0..10 {
            let (status, _, _) = send_with(&dp, "/x", vec![("authorization", hdr.as_str())]).await;
            assert_eq!(status, StatusCode::OK);
        }
    })
    .await
    .expect("backoff window must not stall the dataplane");
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "backoff window wall time {:?} is not bounded",
        start.elapsed()
    );
    assert_eq!(
        fetches.load(Ordering::SeqCst),
        2,
        "backed-off requests must not attempt new fetches"
    );

    // After the window passes, the next stale request retries the endpoint
    // (fetch #3 — the backoff bounds, it does not pin) and still degrades.
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let (status, _, _) = send_with(&dp, "/x", vec![("authorization", hdr.as_str())]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fetches.load(Ordering::SeqCst), 3);
}

// ---- consumer priority + cap admission -------------------------------------

#[tokio::test]
async fn consumer_priority_overrides_route_class_but_does_not_carve_the_cap() {
    // Consumer priority 9, route with NO priority, cap 1, no high-priority
    // ROUTE: the reserved bucket is NOT carved (otherwise cap 1 would
    // leave zero general permits and every request would shed 503), and
    // an admitted authenticated request is counted in class 9.
    let yaml = format!(
        "listeners: []
routes:
  - name: r
    service: svc
    match:
      path: {{ type: regex, value: /.* }}
    action: {{ type: respond, status: 200 }}
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 1
max_concurrent_requests: 1
consumers:
  - name: vip
    priority: 9
    credentials:
      - type: api_key
        key: {API_KEY}
"
    );
    let dp = dataplane_from(&yaml);
    let (status, _, _) = send_with(&dp, "/x", vec![("x-api-key", API_KEY)]).await;
    // 200 proves admission (a carve at cap 1 would 503 everything).
    assert_eq!(status, StatusCode::OK);
    assert_eq!(dp.priority_counters().admitted_at(9), 1);
    assert_eq!(dp.priority_counters().admitted_at(5), 0);
    assert_eq!(dp.priority_counters().shed_at(9), 0);

    // Anonymous traffic on the same route stays in the DEFAULT class (5).
    let (status, _, _) = send_with(&dp, "/x", vec![]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(dp.priority_counters().admitted_at(5), 1);
    assert_eq!(dp.priority_counters().admitted_at(9), 1);
}
