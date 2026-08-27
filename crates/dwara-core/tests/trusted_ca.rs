//! Custom upstream CA roots (#121): `trusted_ca_file` on upstreams and
//! JWT providers, end to end from YAML alone.
//!
//! Every fixture here is a REAL private CA (rcgen) whose leaf certificate
//! serves HTTPS on a loopback port; the gateway is built purely from the
//! YAML (no programmatic root injection). The done-when for the issue is
//! the first test: a private-CA upstream AND its https active-health
//! probe both work from config; the rest pin the negative paths (no trust
//! configured -> proxying and probing fail) and the JWKS connector, which
//! shares the trust model for https JWKS URLs.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dwara_core::active::ActiveProbes;
use dwara_core::config::parse_gateway;
use dwara_core::proxy::DataPlane;
use dwara_core::snapshot::ConfigState;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use tokio::net::TcpListener;

mod support;

// ---------------------------------------------------------------- fixtures

/// A private CA plus a leaf certificate it signed (SAN `localhost`), with
/// the CA's PEM written to a temp file the config can point
/// `trusted_ca_file` at. The `TempDir` stays alive for the test's scope;
/// dropping it removes the bundle.
struct PrivateCa {
    #[allow(dead_code)]
    dir: tempfile::TempDir,
    ca_pem: String,
    leaf_cert: rcgen::Certificate,
    leaf_key: rcgen::KeyPair,
    ca_der: rustls::pki_types::CertificateDer<'static>,
}

fn private_ca() -> PrivateCa {
    let (ca, ca_key) = make_ca("dwara-test-private-ca");

    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("private-ca.pem");
    std::fs::write(&ca_path, ca.pem()).unwrap();
    PrivateCa {
        dir,
        ca_pem: ca_path.display().to_string(),
        leaf_cert,
        leaf_key,
        ca_der: ca.der().clone(),
    }
}

/// A standalone self-signed CA: its PEM (for composing multi-anchor
/// bundle files) and its DER (for a server's served chain).
fn make_ca(cn: &str) -> (rcgen::Certificate, rcgen::KeyPair) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let cert = params.self_signed(&key).unwrap();
    (cert, key)
}

/// Sync responder for the private-CA test server: (method, path) in, full
/// response out.
type Responder = Arc<dyn Fn(&Method, &str) -> Response<Full<Bytes>> + Send + Sync>;

/// HTTPS server whose certificate chains to the private CA. Records every
/// served "<METHOD> <path>" line and answers from `handler`. ALPN offers
/// http/1.1 (what both the pooled https connector and the probes speak).
async fn serve_private_https(ca: &PrivateCa, handler: Responder) -> (u16, Arc<Mutex<Vec<String>>>) {
    serve_private_https_alpn(ca, handler, vec![b"http/1.1".to_vec()]).await
}

/// `serve_private_https` with explicit ALPN protocols: the http2-upstream
/// test needs a server that also speaks h2 (the pooled http2 connector
/// negotiates h2; the probe still speaks HTTP/1.1 on its own connection).
async fn serve_private_https_alpn(
    ca: &PrivateCa,
    handler: Responder,
    alpn: Vec<Vec<u8>>,
) -> (u16, Arc<Mutex<Vec<String>>>) {
    dwara_core::tls::install_aws_lc_rs_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    // Serve the full chain (leaf + CA): a real private-CA deployment's
    // server hands the client everything except the anchor itself.
    let mut server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![ca.leaf_cert.der().clone(), ca.ca_der.clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                ca.leaf_key.serialize_der(),
            )),
        )
        .expect("server cert");
    server_cfg.alpn_protocols = alpn;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
    // The served-request log outlives the spawn; the task keeps its own
    // handle so the caller can poll what was served.
    let served = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let hits = Arc::clone(&served);
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return; // handshake refused (e.g. a client without trust)
                };
                let service = service_fn(move |req: Request<Incoming>| {
                    let hits = Arc::clone(&hits);
                    let handler = Arc::clone(&handler);
                    async move {
                        let line = format!("{} {}", req.method(), req.uri().path());
                        hits.lock().expect("hits").push(line);
                        Ok::<_, std::convert::Infallible>(handler(req.method(), req.uri().path()))
                    }
                });
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    (port, hits)
}

/// Gateway YAML: `/.*` -> one `https` upstream served by the private CA,
/// with fast http active-health probes. `ca_file` is the
/// `trusted_ca_file` line when trust is configured (None: public roots
/// only, which cannot verify the private CA).
fn private_ca_yaml(backend_port: u16, ca_file: Option<&str>) -> String {
    let trust = match ca_file {
        Some(path) => format!("    trusted_ca_file: \"{path}\"\n"),
        None => String::new(),
    };
    format!(
        "listeners: []
routes:
  - name: r
    service: svc
    match:
      path: {{ type: regex, value: \"/.*\" }}
    action: {{ type: proxy }}
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    protocol: https
{trust}    endpoints:
      - address: localhost
        port: {backend_port}
    health:
      consecutive_failures: 3
      eject_ms: 60000
    active_health:
      kind: http
      path: /healthz
      interval_ms: 100
      timeout_ms: 100
      success_threshold: 1
      failure_threshold: 2
      jitter_ms: 0
"
    )
}

/// Publish the YAML, build the dataplane, and start the active probes —
/// the exact startup sequence dwara-bin runs.
fn launch(
    yaml: &str,
) -> (
    Arc<DataPlane>,
    ActiveProbes,
    Arc<dwara_core::snapshot::Snapshot>,
) {
    let (dp, probes, state) = launch_with_state(yaml);
    (dp, probes, state.snapshot())
}

/// `launch` but returning the `ConfigState` too: the reload test drives
/// forced re-publishes through it (the same `compile_and_publish` +
/// `dp.refresh()` + `probes.respawn` sequence dwara-bin's SIGHUP reload
/// runs).
fn launch_with_state(yaml: &str) -> (Arc<DataPlane>, ActiveProbes, Arc<ConfigState>) {
    let gateway = parse_gateway(yaml).expect("test config parses");
    let state = Arc::new(ConfigState::new());
    state
        .compile_and_publish(&gateway)
        .expect("test config publishes");
    let snapshot = state.snapshot();
    let dp = DataPlane::new(Arc::clone(&state));
    let mut probes = ActiveProbes::new();
    probes.respawn(&dp.registry(), &snapshot);
    (dp, probes, state)
}

/// SIGHUP-equivalent forced reload: re-publish (the same parsed config is
/// fine — `compile_and_publish` always advances the generation), rebuild
/// the (snapshot, registry) pair, and respawn the probe loops against the
/// new registry. Mirrors `dwara_bin::reload` exactly.
fn force_reload(dp: &DataPlane, probes: &mut ActiveProbes, state: &ConfigState, yaml: &str) {
    let gateway = parse_gateway(yaml).expect("reload config parses");
    state
        .compile_and_publish(&gateway)
        .expect("reload config publishes");
    dp.refresh();
    probes.respawn(&dp.registry(), &state.snapshot());
}

fn peer() -> std::net::IpAddr {
    "127.0.0.1".parse().unwrap()
}

async fn send(dp: &DataPlane, path: &str, headers: &[(&str, &str)]) -> (StatusCode, String) {
    let mut builder = Request::builder().uri(path);
    for (n, v) in headers.iter().copied() {
        builder = builder.header(n, v);
    }
    let req = builder.body(Full::new(Bytes::new())).unwrap();
    let resp = dwara_core::proxy::handle(dp, peer(), req).await;
    let (parts, body) = resp.into_parts();
    let text = String::from_utf8_lossy(&body.collect().await.unwrap().to_bytes()).into_owned();
    (parts.status, text)
}

/// Poll the upstream's sole endpoint tracker until it reports `want`
/// (bounded; no sleep-sync — the probes themselves are the event source).
async fn wait_endpoint_available(dp: &DataPlane, want: bool, deadline: Duration) -> bool {
    let handle = dp.registry().get("pool").expect("handle");
    let lb = handle.lb();
    let start = Instant::now();
    while start.elapsed() < deadline {
        let targets = lb.health_targets();
        let tracker = targets[0].2.as_ref().expect("tracker");
        if tracker.is_available(lb.now_ms()) == want {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

/// Bounded wait until the private-CA server has served a probe request.
async fn wait_probe_hit(hits: &Arc<Mutex<Vec<String>>>, deadline: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if hits
            .lock()
            .expect("hits")
            .iter()
            .any(|l| l == "GET /healthz")
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

fn ok_text(body: &str) -> Response<Full<Bytes>> {
    Response::new(Full::new(Bytes::from(body.to_string())))
}

// ------------------------------------------------- upstream + probe (e2e)

/// THE ISSUE'S DONE-WHEN: a private-CA upstream plus an https active
/// health probe work end to end from config alone. Proxying through the
/// gateway succeeds (the connector trusts the configured bundle) and the
/// probe reaches the endpoint over https with the SAME trust (visible as
/// a served `GET /healthz`), leaving the endpoint in rotation.
#[tokio::test]
async fn private_ca_upstream_proxies_and_probes_over_https() {
    let ca = private_ca();
    let (port, hits) = serve_private_https(
        &ca,
        Arc::new(|_: &Method, _: &str| ok_text("private-ca-ok")),
    )
    .await;
    let (dp, _probes, _snap) = launch(&private_ca_yaml(port, Some(&ca.ca_pem)));

    let (status, body) = send(&dp, "/x", &[]).await;
    assert_eq!(status, StatusCode::OK, "proxied via the private CA");
    assert_eq!(body, "private-ca-ok");

    assert!(
        wait_probe_hit(&hits, Duration::from_secs(3)).await,
        "https probe reached the private-CA endpoint (same trust as the connector): {:?}",
        hits.lock().unwrap()
    );
    assert!(
        wait_endpoint_available(&dp, true, Duration::from_millis(500)).await,
        "probed endpoint stays in rotation"
    );
}

/// Without `trusted_ca_file` the same upstream is unreachable: the
/// proxied request fails against the public roots (502) and the https
/// probes keep failing until the endpoint is ejected.
#[tokio::test]
async fn private_ca_upstream_without_trust_fails_proxying_and_probing() {
    let ca = private_ca();
    let (port, hits) = serve_private_https(
        &ca,
        Arc::new(|_: &Method, _: &str| ok_text("private-ca-ok")),
    )
    .await;
    let (dp, _probes, _snap) = launch(&private_ca_yaml(port, None));

    // Proxying first (before ejection changes the failure mode): the TLS
    // handshake cannot verify the private-CA certificate, so the gateway
    // answers 502, never the upstream's 200.
    let (status, _) = send(&dp, "/x", &[]).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "no trust, no proxying");

    // Probes fail the same way: after failure_threshold consecutive
    // failures the endpoint leaves rotation.
    assert!(
        wait_endpoint_available(&dp, false, Duration::from_secs(3)).await,
        "https probes fail without the CA trust and eject the endpoint"
    );
    assert!(
        !hits.lock().unwrap().iter().any(|l| l.contains("/healthz")),
        "no probe ever completed a request over untrusted TLS"
    );
}

// --------------------------------------------------------- JWKS over TLS

/// Minimal EC JWK for the JWKS body (same encoding as the authn suite's
/// fixture: uncompressed P-256 point out of the SPKI).
fn ec_jwk(key: &rcgen::KeyPair, kid: &str) -> serde_json::Value {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use base64::Engine as _;
    let spki = key.public_key_der();
    let body = &spki[spki.len() - 65..];
    assert_eq!(body[0], 0x04, "uncompressed EC point");
    serde_json::json!({
        "kty": "EC", "crv": "P-256",
        "x": B64URL.encode(&body[1..33]), "y": B64URL.encode(&body[33..65]),
        "kid": kid, "alg": "ES256", "use": "sig",
    })
}

fn es_token(key: &rcgen::KeyPair, kid: &str) -> String {
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(kid.to_string());
    jsonwebtoken::encode(
        &header,
        &serde_json::json!({
            "iss": "https://idp.example", "aud": "dwara-api",
            "sub": "alice", "exp": exp,
        }),
        &EncodingKey::from_ec_der(&key.serialize_der()),
    )
    .unwrap()
}

/// Gateway YAML with a JWT provider whose JWKS URL is served over the
/// private CA; `ca_file` toggles the trusted_ca_file line.
fn jwks_yaml(jwks_port: u16, echo_port: u16, ca_file: Option<&str>) -> String {
    let trust = match ca_file {
        Some(path) => format!("    trusted_ca_file: \"{path}\"\n"),
        None => String::new(),
    };
    format!(
        "listeners: []
routes:
  - name: r
    service: svc
    match:
      path: {{ type: regex, value: \"/.*\" }}
    action: {{ type: proxy }}
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: {echo_port}
jwt_providers:
  - name: idp
    jwks_url: https://localhost:{jwks_port}/jwks
{trust}    algorithms: [ES256]
    issuer: https://idp.example
    audience: dwara-api
consumers:
  - name: acme
    credentials:
      - type: jwt
        issuer: https://idp.example
        audiences: [dwara-api]
"
    )
}

/// A token presented to a provider whose JWKS is behind the private CA
/// validates (the fetcher trusts the configured bundle): the request is
/// authenticated — the echo upstream sees the injected X-Consumer-Name —
/// and proxied with 200.
#[tokio::test]
async fn jwks_over_private_ca_authenticates_tokens() {
    let ca = private_ca();
    let idp_key = rcgen::KeyPair::generate().unwrap();
    let jwks_body = serde_json::json!({ "keys": [ec_jwk(&idp_key, "key-1")] }).to_string();
    let (jwks_port, _hits) = serve_private_https(
        &ca,
        Arc::new(move |_: &Method, path: &str| {
            assert_eq!(path, "/jwks");
            Response::builder()
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(jwks_body.clone())))
                .unwrap()
        }),
    )
    .await;
    // Plaintext echo upstream: its body (the proxied request's headers)
    // proves the authenticated consumer identity was injected upstream.
    let echo_port = support::spawn_backend_full(Arc::new(|req: Request<Incoming>| {
        let mut lines: Vec<String> = Vec::new();
        for (n, v) in req.headers() {
            lines.push(format!("{}: {}", n, v.to_str().unwrap_or("<binary>")));
        }
        lines.sort();
        Response::new(Full::new(Bytes::from(lines.join("\n"))))
    }))
    .await;

    let dp = support::dataplane_from(&jwks_yaml(jwks_port, echo_port, Some(&ca.ca_pem)));
    let token = es_token(&idp_key, "key-1");
    let (status, body) = send(&dp, "/x", &[("authorization", &format!("Bearer {token}"))]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "token validated via the private-CA JWKS"
    );
    assert!(
        body.contains("x-consumer-name: acme"),
        "authenticated identity injected upstream: {body}"
    );
}

/// The same provider WITHOUT the trust configuration cannot fetch its
/// JWKS: every Bearer request fails on the gateway side (500, JWKS
/// endpoint unreachable over untrusted TLS) — never a silent 401 that
/// would masquerade as an invalid token.
#[tokio::test]
async fn jwks_over_private_ca_without_trust_is_unavailable() {
    let ca = private_ca();
    let idp_key = rcgen::KeyPair::generate().unwrap();
    let jwks_body = serde_json::json!({ "keys": [ec_jwk(&idp_key, "key-1")] }).to_string();
    let (jwks_port, hits) = serve_private_https(
        &ca,
        Arc::new(move |_: &Method, _: &str| {
            Response::builder()
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(jwks_body.clone())))
                .unwrap()
        }),
    )
    .await;
    let echo_port = support::spawn_backend_full(Arc::new(|_: Request<Incoming>| {
        Response::new(Full::new(Bytes::new()))
    }))
    .await;

    let dp = support::dataplane_from(&jwks_yaml(jwks_port, echo_port, None));
    let token = es_token(&idp_key, "key-1");
    let (status, _) = send(&dp, "/x", &[("authorization", &format!("Bearer {token}"))]).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "JWKS fetch fails over untrusted TLS -> authentication unavailable"
    );
    assert!(
        hits.lock().unwrap().is_empty(),
        "no JWKS request ever completed over untrusted TLS"
    );
}

// ------------------------------------------------- multi-certificate bundle

/// A bundle file with MORE THAN ONE certificate (the documented bundle
/// semantics: "every certificate in it becomes a trust anchor"). The
/// anchor that actually signed the served leaf is the SECOND PEM in the
/// file, behind an unrelated CA and a comment line — so the test fails
/// if the loader only takes the first certificate (or chokes on
/// non-PEM filler between the blocks, which real bundles carry).
#[tokio::test]
async fn multi_certificate_bundle_trusts_every_anchor_in_the_file() {
    let ca = private_ca();
    let (other_ca, _other_key) = make_ca("dwara-test-unrelated-ca");
    let signer_pem = std::fs::read_to_string(&ca.ca_pem).unwrap();
    std::fs::write(
        &ca.ca_pem,
        format!(
            "{}# bundle: several anchors follow\n{}",
            other_ca.pem(),
            signer_pem
        ),
    )
    .unwrap();

    let (port, hits) =
        serve_private_https(&ca, Arc::new(|_: &Method, _: &str| ok_text("bundle-ok"))).await;
    let (dp, _probes, _snap) = launch(&private_ca_yaml(port, Some(&ca.ca_pem)));

    let (status, body) = send(&dp, "/x", &[]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "second anchor in the bundle is trusted"
    );
    assert_eq!(body, "bundle-ok");
    assert!(
        wait_probe_hit(&hits, Duration::from_secs(3)).await,
        "probe trusts the multi-anchor bundle too: {:?}",
        hits.lock().unwrap()
    );
}

// ------------------------------------------------------------- reload (SIGHUP)

/// Gateway YAML for the reload test: https upstream behind the private CA
/// with fast probes, but failure/ejection thresholds high enough that the
/// CA-only-down phase cannot eject the endpoint (the test pins TRUST
/// swap-in, not the ejection machinery).
fn reload_yaml(backend_port: u16, ca_path: &str) -> String {
    format!(
        "listeners: []
routes:
  - name: r
    service: svc
    match:
      path: {{ type: regex, value: \"/.*\" }}
    action: {{ type: proxy }}
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    protocol: https
    trusted_ca_file: \"{ca_path}\"
    endpoints:
      - address: localhost
        port: {backend_port}
    health:
      consecutive_failures: 1000
      eject_ms: 60000
    active_health:
      kind: http
      path: /healthz
      interval_ms: 100
      timeout_ms: 90
      success_threshold: 1
      failure_threshold: 1000
      jitter_ms: 0
"
    )
}

/// Changing the trusted_ca_file's CONTENT (same path, same config) takes
/// effect on the next forced reload (SIGHUP): the new generation's
/// connector AND its respawned probes verify against the re-read bundle,
/// while the pre-reload generation keeps its old roots.
#[tokio::test]
async fn reload_rereads_ca_bundle_for_connector_and_probes() {
    let ca = private_ca();
    let signer_pem = std::fs::read_to_string(&ca.ca_pem).unwrap();
    let (other_ca, _other_key) = make_ca("dwara-test-rotation-ca");
    let (port, hits) =
        serve_private_https(&ca, Arc::new(|_: &Method, _: &str| ok_text("reload-ok"))).await;
    let yaml = reload_yaml(port, &ca.ca_pem);
    let (dp, mut probes, state) = launch_with_state(&yaml);

    // Generation 1 (bundle = signer): proxying and probing both work.
    let (status, _) = send(&dp, "/x", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(wait_probe_hit(&hits, Duration::from_secs(3)).await);

    // Rewrite the bundle in place to the UNRELATED CA, but do NOT
    // reload: the running generation keeps its (old) roots.
    std::fs::write(&ca.ca_pem, other_ca.pem()).unwrap();
    let (status, _) = send(&dp, "/x", &[]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "pre-reload generation is unaffected by the file changing on disk"
    );

    // Forced reload (SIGHUP): the registry rebuild re-reads the bundle,
    // so the signer is no longer trusted -> 502, and the respawned
    // probes fail their TLS handshakes (no served request) for as long
    // as the unrelated anchor is the only one in the file.
    force_reload(&dp, &mut probes, &state, &yaml);
    let (status, _) = send(&dp, "/x", &[]).await;
    assert_eq!(
        status,
        StatusCode::BAD_GATEWAY,
        "reloaded generation verifies against the re-read bundle"
    );
    // Grace window for a straggler from the cancelled old-generation
    // probe loop (a request already handed to the server still gets
    // served); after it, count probes over several intervals.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let quiet = hits.lock().unwrap().len();
    tokio::time::sleep(Duration::from_millis(600)).await; // 6 probe intervals
    assert_eq!(
        hits.lock().unwrap().len(),
        quiet,
        "respawned probes use the new roots: no probe request may complete"
    );

    // Rotate the bundle to BOTH anchors and reload again: proxying
    // recovers and the (again respawned) probes resume hitting the
    // endpoint — the reload path rebuilt connector AND probe trust.
    std::fs::write(&ca.ca_pem, format!("{signer_pem}{}", other_ca.pem())).unwrap();
    force_reload(&dp, &mut probes, &state, &yaml);
    let (status, body) = send(&dp, "/x", &[]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "second reload picked up the new anchors"
    );
    assert_eq!(body, "reload-ok");
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if hits.lock().unwrap().len() > quiet {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        hits.lock().unwrap().len() > quiet,
        "probes resumed after the trust rotation: {:?}",
        hits.lock().unwrap()
    );
}

// ------------------------------------------------------- http2 upstreams

/// The same private-CA trust for an `http2` upstream: the pooled client
/// negotiates h2 (server offers h2 + http/1.1), the probe still speaks
/// HTTP/1.1 on its own connection — both must verify against the
/// configured bundle.
#[tokio::test]
async fn private_ca_http2_upstream_proxies_and_probes() {
    let ca = private_ca();
    let (port, hits) = serve_private_https_alpn(
        &ca,
        Arc::new(|_: &Method, _: &str| ok_text("h2-ok")),
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    )
    .await;
    let mut yaml = private_ca_yaml(port, Some(&ca.ca_pem));
    yaml = yaml.replace("protocol: https", "protocol: http2");
    let (dp, _probes, _snap) = launch(&yaml);

    let (status, body) = send(&dp, "/x", &[]).await;
    assert_eq!(status, StatusCode::OK, "http2 upstream via the private CA");
    assert_eq!(body, "h2-ok");
    assert!(
        wait_probe_hit(&hits, Duration::from_secs(3)).await,
        "http/1.1 probe against the http2 upstream: {:?}",
        hits.lock().unwrap()
    );
    assert!(
        wait_endpoint_available(&dp, true, Duration::from_millis(500)).await,
        "probed http2 endpoint stays in rotation"
    );
}

// ------------------------------------------ bundle breaks after publication

/// A bundle that goes bad AFTER publish (swap to garbage + forced
/// reload) is caught at VALIDATION: the reload is rejected naming
/// trusted_ca_file and the old generation keeps serving — the broken
/// bundle can never take over a live gateway. (Publishing garbage
/// outright is equally rejected — the same compile_and_publish path —
/// which is why the premise must go through a good generation first:
/// with the validation-time PEM parse there is no longer a config that
/// reaches the registry build with an unparseable bundle. The runtime
/// fail-closed build — empty root store, ERROR log — stays in the code
/// as a microsecond-race backstop for a bundle that breaks between
/// validate and build; its error mapping is pinned at the unit level in
/// tests/unit/tls.rs.)
#[tokio::test]
async fn reload_rejects_a_bundle_that_became_garbage_and_old_generation_keeps_serving() {
    let ca = private_ca();
    let (port, _hits) =
        serve_private_https(&ca, Arc::new(|_: &Method, _: &str| ok_text("still-ok"))).await;
    let yaml = reload_yaml(port, &ca.ca_pem);
    let (dp, _probes, state) = launch_with_state(&yaml);

    // Generation 1 (good bundle): proxying works.
    let (status, body) = send(&dp, "/x", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "still-ok");

    // The bundle breaks on disk; a forced reload (the same
    // compile_and_publish dwara-bin's SIGHUP path runs) must be
    // REJECTED at validation. On rejection reload.rs skips
    // dp.refresh()/probes.respawn — the test does the same.
    std::fs::write(&ca.ca_pem, "definitely not a pem bundle\n").unwrap();
    let gateway = parse_gateway(&yaml).expect("config still parses");
    let err = state
        .compile_and_publish(&gateway)
        .expect_err("reload with a garbage bundle must be rejected");
    let text = format!("{err}");
    assert!(
        text.contains("trusted_ca_file"),
        "the rejection names the offending field: {text}"
    );
    assert!(
        text.contains("holds no usable CA certificates"),
        "the rejection says what is wrong with the bundle: {text}"
    );

    // The published generation is untouched (rollback = not-published):
    // proxying keeps working with the anchors it already holds.
    let (status, body) = send(&dp, "/x", &[]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "old generation keeps serving after the rejected reload"
    );
    assert_eq!(body, "still-ok");
}

/// The JWKS equivalent: a provider whose bundle goes bad after publish
/// keeps its OLD generation authenticating tokens, because the reload is
/// rejected at validation. With the validation-time PEM parse, the
/// disabled-provider state (JwksConnector::new fails -> the
/// `jwt_provider_disabled` ERROR in CompositeAuthenticator::build) is
/// unreachable from config; it remains reachable only via the
/// microsecond validate-to-build race, and since #131 that residual
/// fails CLOSED — authenticate_jwt answers `Err(Unavailable)` (500-class
/// authentication_unavailable), never the old unverified Bearer
/// pass-through — the reason the build keeps failing closed instead of
/// trusting validation alone.
#[tokio::test]
async fn jwks_reload_rejects_a_broken_bundle_and_old_generation_keeps_authenticating() {
    let ca = private_ca();
    let idp_key = rcgen::KeyPair::generate().unwrap();
    let jwks_body = serde_json::json!({ "keys": [ec_jwk(&idp_key, "key-1")] }).to_string();
    let (jwks_port, _hits) = serve_private_https(
        &ca,
        Arc::new(move |_: &Method, _: &str| {
            Response::builder()
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(jwks_body.clone())))
                .unwrap()
        }),
    )
    .await;
    let echo_port = support::spawn_backend_full(Arc::new(|req: Request<Incoming>| {
        let mut lines: Vec<String> = Vec::new();
        for (n, v) in req.headers() {
            lines.push(format!("{}: {}", n, v.to_str().unwrap_or("<binary>")));
        }
        lines.sort();
        Response::new(Full::new(Bytes::from(lines.join("\n"))))
    }))
    .await;

    let yaml = jwks_yaml(jwks_port, echo_port, Some(&ca.ca_pem));
    let gateway = parse_gateway(&yaml).expect("test config parses");
    let state = Arc::new(ConfigState::new());
    state
        .compile_and_publish(&gateway)
        .expect("good bundle publishes");
    let dp = DataPlane::new(Arc::clone(&state));

    // Generation 1: the token authenticates via the private-CA JWKS.
    let token = es_token(&idp_key, "key-1");
    let (status, body) = send(&dp, "/x", &[("authorization", &format!("Bearer {token}"))]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("x-consumer-name: acme"),
        "authenticated identity injected upstream: {body}"
    );

    // The bundle breaks on disk; the reload must be rejected at
    // validation, not published into a disabled provider.
    std::fs::write(&ca.ca_pem, "not a pem file\n").unwrap();
    let err = state
        .compile_and_publish(&gateway)
        .expect_err("reload with a garbage bundle must be rejected");
    assert!(
        format!("{err}").contains("trusted_ca_file"),
        "the rejection names the offending field: {err}"
    );

    // The old generation still authenticates the SAME token — never the
    // disabled-provider pass-through (which would 200 WITHOUT the
    // consumer identity).
    let (status, body) = send(&dp, "/x", &[("authorization", &format!("Bearer {token}"))]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "old generation keeps authenticating"
    );
    assert!(
        body.contains("x-consumer-name: acme"),
        "identity still verified and injected: {body}"
    );
}
