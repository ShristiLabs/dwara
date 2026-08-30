//! Admin API integration tests (DW-022): the mTLS gate (done-when),
//! the endpoint set, PATCH semantics (atomic write + publish), and the
//! dev-mode loopback fallback.

use std::path::PathBuf;
use std::sync::Arc;

use dwara_admin::{AdminContext, ListenMode};
use dwara_core::proxy::DataPlane;
use dwara_core::snapshot::ConfigState;
use dwara_core::tls;
use tokio::net::TcpListener;
use tokio::sync::watch;

/// One PKI: a CA plus leaves it signed (server + admin clients).
struct Pki {
    dir: PathBuf,
    ca_cert: rcgen::Certificate,
    ca_key: rcgen::KeyPair,
}

impl Pki {
    fn new(dir: &std::path::Path) -> Self {
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let mut params =
            rcgen::CertificateParams::new(vec!["dwara-test-ca".to_string()]).expect("ca params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = params.self_signed(&ca_key).expect("ca cert");
        Pki {
            dir: dir.to_path_buf(),
            ca_cert,
            ca_key,
        }
    }

    /// Issue a leaf certificate for `name` signed by this CA; returns
    /// (cert_path, key_path).
    fn issue(&self, name: &str) -> (PathBuf, PathBuf) {
        self.issue_custom(name, |_| {})
    }

    /// Issue a leaf with caller mutation of the rcgen params (expiry,
    /// EKU control for the deep mTLS tests).
    fn issue_custom(
        &self,
        name: &str,
        mutate: impl FnOnce(&mut rcgen::CertificateParams),
    ) -> (PathBuf, PathBuf) {
        let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
        let mut params =
            rcgen::CertificateParams::new(vec![name.to_string()]).expect("leaf params");
        mutate(&mut params);
        let cert = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .expect("leaf cert");
        let cpath = self.dir.join(format!("{name}.crt.pem"));
        let kpath = self.dir.join(format!("{name}.key.pem"));
        std::fs::write(&cpath, cert.pem()).unwrap();
        std::fs::write(&kpath, leaf_key.serialize_pem()).unwrap();
        (cpath, kpath)
    }

    fn ca_path(&self) -> PathBuf {
        let p = self.dir.join("ca.crt.pem");
        std::fs::write(&p, self.ca_cert.pem()).unwrap();
        p
    }
}

/// A minimal valid gateway config with one upstream; `extra_upstream`
/// appends a second upstream (used to observe a PATCH taking effect).
fn config_yaml(extra_upstream: Option<&str>) -> String {
    let mut s = String::from(
        "listeners:\n  - name: main\n    address: 127.0.0.1\n    port: 18080\n\
         routes:\n  - name: r1\n    service: svc\n\
         \x20   match:\n      path:\n        type: prefix\n        value: /api\n\
         \x20   action:\n      type: proxy\n\
         services:\n  - name: svc\n    upstream: echo\n\
         upstreams:\n  - name: echo\n    endpoints:\n      - { address: 127.0.0.1, port: 1 }\n",
    );
    if let Some(name) = extra_upstream {
        s.push_str(&format!(
            "  - name: {name}\n    endpoints:\n      - {{ address: 127.0.0.1, port: 1 }}\n"
        ));
    }
    s
}

struct Server {
    addr: std::net::SocketAddr,
    state: Arc<ConfigState>,
    dp: Arc<DataPlane>,
    config_path: PathBuf,
    _shutdown: watch::Sender<()>,
}

/// Start the admin server in mTLS mode on an ephemeral loopback port.
async fn start_mtls(pki: &Pki) -> Server {
    tls::install_aws_lc_rs_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert, key) = pki.issue("localhost");
    let admin_cfg = dwara_core::config::AdminConfig {
        bind: "127.0.0.1:0".to_string(),
        tls: dwara_core::config::AdminTlsConfig {
            cert_file: cert.display().to_string(),
            key_file: key.display().to_string(),
            client_ca_file: pki.ca_path().display().to_string(),
        },
    };
    let mode = ListenMode::mtls(&admin_cfg).expect("mtls mode builds");
    start(mode, dir).await
}

async fn start(mode: ListenMode, dir: tempfile::TempDir) -> Server {
    let config_path = dir.path().join("dwara.yaml");
    std::fs::write(&config_path, config_yaml(None)).unwrap();
    let state = Arc::new(ConfigState::new());
    state
        .compile_and_publish(
            &dwara_core::config::parse_gateway(&config_yaml(None)).expect("base config"),
        )
        .expect("publish base");
    let dp = DataPlane::new(Arc::clone(&state));
    let ctx = Arc::new(AdminContext::new(
        Arc::clone(&state),
        Arc::clone(&dp),
        config_path.clone(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let (tx, rx) = watch::channel(());
    tokio::spawn(dwara_admin::serve(ctx, listener, mode, rx));
    std::mem::forget(dir); // keep the temp dir alive for the test body
    Server {
        addr,
        state,
        dp,
        config_path,
        _shutdown: tx,
    }
}

/// Build a TLS client config trusting `ca_path`; `client` optionally
/// presents a certificate (cert PEM bytes, key PEM bytes).
fn client_config(ca_path: &std::path::Path, client: Option<(&str, &str)>) -> rustls::ClientConfig {
    use rustls::pki_types::pem::PemObject as _;
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls::pki_types::CertificateDer::pem_file_iter(ca_path)
        .expect("ca pem file")
        .collect::<Result<Vec<_>, _>>()
        .expect("ca pem parse")
    {
        roots.add(c).unwrap();
    }
    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    match client {
        None => builder.with_no_client_auth(),
        Some((cert_pem, key_pem)) => {
            let certs: Vec<_> =
                rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                    .collect::<Result<Vec<_>, _>>()
                    .expect("client cert pem");
            let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
                .expect("client key pem");
            builder
                .with_client_auth_cert(certs, key)
                .expect("client auth")
        }
    }
}

/// Issue one raw HTTP/1.1 request over (maybe-mTLS) TLS and return
/// (status, headers, body). Returns Err on TLS handshake failure.
async fn request(
    addr: std::net::SocketAddr,
    ca_path: &std::path::Path,
    client: Option<(&str, &str)>,
    req: &str,
) -> Result<(u16, String, String), String> {
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| e.to_string())?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config(ca_path, client)));
    let name =
        rustls::pki_types::ServerName::try_from("localhost".to_string()).expect("server name");
    let mut tls = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        connector.connect(name, stream),
    )
    .await
    .map_err(|_| "handshake timed out".to_string())?
    .map_err(|e| format!("tls handshake failed: {e}"))?;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    tls.write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    // #128 flake class: write_all completing does NOT mean the bytes are on
    // the wire — tokio-rustls may keep the final TLS record (the 4 MiB
    // body's tail) buffered, and poll_read never flushes pending writes, so
    // the server would sit below the size cap forever. Flush before reading.
    tls.flush().await.map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    // #128 flake class: 10s read bound is load tolerance for full-suite parallelism (4 MiB over loopback mTLS takes milliseconds); a genuine hang still trips the caller's outer deadline.
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tls.read_to_end(&mut buf),
    )
    .await
    .map_err(|_| "read timed out".to_string())?
    .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&buf).to_string();
    parse_response(&text).ok_or_else(|| "malformed response".to_string())
}

fn parse_response(text: &str) -> Option<(u16, String, String)> {
    let (head, body) = text.split_once("\r\n\r\n")?;
    let mut lines = head.lines();
    let status_line = lines.next()?;
    let status: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;
    Some((status, head.to_string(), body.to_string()))
}

/// Read a PEM file to a string.
fn pem(path: &std::path::Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

// --- the mTLS gate (done-when) ------------------------------------------

#[tokio::test]
async fn mtls_rejects_client_without_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let err = request(
        server.addr,
        &pki.ca_path(),
        None,
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .expect_err("handshake without a client cert must fail");
    // The server aborts the handshake with a fatal alert (surfacing on
    // the client either at connect or the first read/write).
    assert!(
        err.contains("handshake") || err.contains("alert"),
        "expected handshake failure, got: {err}"
    );
}

#[tokio::test]
async fn mtls_rejects_certificate_from_wrong_ca() {
    let dir = tempfile::tempdir().unwrap();
    let good = Pki::new(&dir.path().join("good"));
    std::fs::create_dir_all(dir.path().join("good")).unwrap();
    let server = start_mtls(&good).await;
    let wrong = Pki::new(&dir.path().join("wrong"));
    std::fs::create_dir_all(dir.path().join("wrong")).unwrap();
    let (cert, key) = wrong.issue("rogue-client");
    let err = request(
        server.addr,
        &good.ca_path(),
        Some((&pem(&cert), &pem(&key))),
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .expect_err("handshake with a wrong-CA cert must fail");
    assert!(
        err.contains("handshake") || err.contains("alert") || err.contains("DecryptError"),
        "expected handshake failure, got: {err}"
    );
}

#[tokio::test]
async fn mtls_accepts_valid_client_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let (cert, key) = pki.issue("admin-client");
    let (status, _, _) = request(
        server.addr,
        &pki.ca_path(),
        Some((&pem(&cert), &pem(&key))),
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .expect("valid client cert must handshake");
    assert_eq!(status, 200);
}

// --- endpoints -----------------------------------------------------------

#[tokio::test]
async fn get_config_returns_normalized_yaml_and_generation_headers() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let (cert, key) = pki.issue("admin-client");
    let (status, headers, body) = request(
        server.addr,
        &pki.ca_path(),
        Some((&pem(&cert), &pem(&key))),
        "GET /config HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert_eq!(status, 200);
    assert!(headers.contains("x-dwara-config-generation: 1"));
    assert!(headers.contains("x-dwara-config-hash: "));
    // Normalized YAML: parse round-trip works and the upstream is there.
    let parsed = dwara_core::config::parse_gateway(&body).expect("GET body parses");
    assert!(parsed.upstreams.iter().any(|u| u.name == "echo"));
}

#[tokio::test]
async fn get_health_and_stats_shape() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let (cert, key) = pki.issue("admin-client");
    let cert_pem = pem(&cert);
    let key_pem = pem(&key);

    let (status, _, body) = request(
        server.addr,
        &pki.ca_path(),
        Some((&cert_pem, &key_pem)),
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert_eq!(status, 200);
    let health: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(health["ready"], true);
    assert_eq!(health["config_generation"], 1);
    assert_eq!(
        health["upstreams"]["echo"]["endpoints"]["127.0.0.1:1"],
        "healthy"
    );

    let (status, _, body) = request(
        server.addr,
        &pki.ca_path(),
        Some((&cert_pem, &key_pem)),
        "GET /stats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert_eq!(status, 200);
    let stats: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(stats["breakers"]["echo"], "disabled");
    assert_eq!(stats["config_generation"], 1);
    assert!(stats["active_requests"].is_i64());
    // No state store attached: schema_version is null.
    assert!(stats["schema_version"].is_null());
}

#[tokio::test]
async fn unknown_path_and_wrong_method_use_error_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let (cert, key) = pki.issue("admin-client");
    let c = (pem(&cert), pem(&key));
    let (status, _, body) = request(
        server.addr,
        &pki.ca_path(),
        Some((&c.0, &c.1)),
        "GET /nope HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert_eq!(status, 404);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"]["code"], "not_found");
    assert!(v["error"]["request_id"].is_string());

    let (status, _, _) = request(
        server.addr,
        &pki.ca_path(),
        Some((&c.0, &c.1)),
        "DELETE /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert_eq!(status, 405);
}

// --- PATCH ---------------------------------------------------------------

#[tokio::test]
async fn patch_invalid_config_is_400_with_all_issues() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let (cert, key) = pki.issue("admin-client");
    // Two issues at once: unknown route service reference + duplicate
    // upstream name. Validation reports everything in one response.
    let bad = "listeners:\n  - name: main\n    address: 127.0.0.1\n    port: 18080\n\
               routes:\n  - name: r1\n    service: ghost\n\
               \x20   match:\n      path:\n        type: prefix\n        value: /api\n\
               \x20   action:\n      type: proxy\n\
               upstreams:\n  - name: a\n    endpoints:\n      - { address: 127.0.0.1, port: 1 }\n\
               \x20 - name: a\n    endpoints:\n      - { address: 127.0.0.1, port: 2 }\n";
    let body = format!(
        "PATCH /config HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/yaml\r\nContent-Length: {}\r\n\r\n{}",
        bad.len(),
        bad
    );
    let (status, _, resp) = request(
        server.addr,
        &pki.ca_path(),
        Some((&pem(&cert), &pem(&key))),
        &body,
    )
    .await
    .unwrap();
    assert_eq!(status, 400);
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["error"]["code"], "config_invalid");
    let msg = v["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("ghost"),
        "message should list the issue: {msg}"
    );
    assert!(
        msg.contains("duplicate"),
        "message should list the issue: {msg}"
    );
    // Nothing was published or written.
    assert_eq!(server.state.snapshot().generation(), 1);
    let on_disk = std::fs::read_to_string(&server.config_path).unwrap();
    assert!(on_disk.contains("name: echo"));
}

#[tokio::test]
async fn patch_with_zero_routes_is_400_naming_the_guard_and_keeps_generation() {
    // #129 through the admin path: the PATCH dry run inherits the
    // snapshot zero-route guard — a route-less body (the torn-write
    // shape) is a 400 naming routes and the allow_empty_routes remedy,
    // with nothing published and nothing written to disk.
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let (cert, key) = pki.issue("admin-client");
    let bad = "listeners: []\n";
    let body = format!(
        "PATCH /config HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/yaml\r\nContent-Length: {}\r\n\r\n{}",
        bad.len(),
        bad
    );
    let (status, _, resp) = request(
        server.addr,
        &pki.ca_path(),
        Some((&pem(&cert), &pem(&key))),
        &body,
    )
    .await
    .unwrap();
    assert_eq!(status, 400);
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["error"]["code"], "config_invalid");
    let msg = v["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("routes is empty"),
        "message should name the zero-route guard: {msg}"
    );
    assert!(
        msg.contains("allow_empty_routes"),
        "message should name the opt-in remedy: {msg}"
    );
    // The old generation keeps serving and the file was not touched.
    assert_eq!(server.state.snapshot().generation(), 1);
    assert_eq!(server.state.snapshot().route_table().find("/api"), Some(0));
    let on_disk = std::fs::read_to_string(&server.config_path).unwrap();
    assert!(on_disk.contains("name: echo"));
}

#[tokio::test]
async fn patch_opted_in_empty_config_publishes_and_reports_zero_routes() {
    // The opt-in side of #129 through the admin path: the same
    // route-less body WITH allow_empty_routes publishes — generation 2,
    // zero routes in the response, and the flag lands on disk.
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let (cert, key) = pki.issue("admin-client");
    let doc = "allow_empty_routes: true\n";
    let body = format!(
        "PATCH /config HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/yaml\r\nContent-Length: {}\r\n\r\n{}",
        doc.len(),
        doc
    );
    let (status, _, resp) = request(
        server.addr,
        &pki.ca_path(),
        Some((&pem(&cert), &pem(&key))),
        &body,
    )
    .await
    .unwrap();
    assert_eq!(status, 200, "resp: {resp}");
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["generation"], 2);
    assert_eq!(v["routes"], 0);
    assert_eq!(server.state.snapshot().generation(), 2);
    assert!(server.state.snapshot().route_table().find("/api").is_none());
    let on_disk = std::fs::read_to_string(&server.config_path).unwrap();
    assert!(
        on_disk.contains("allow_empty_routes: true"),
        "the opt-in is persisted: {on_disk}"
    );
}

#[tokio::test]
async fn patch_valid_config_writes_file_and_publishes_to_dataplane() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let (cert, key) = pki.issue("admin-client");
    let new_config = config_yaml(Some("added"));
    let body = format!(
        "PATCH /config HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/yaml\r\nContent-Length: {}\r\n\r\n{}",
        new_config.len(),
        new_config
    );
    let (status, headers, resp) = request(
        server.addr,
        &pki.ca_path(),
        Some((&pem(&cert), &pem(&key))),
        &body,
    )
    .await
    .unwrap();
    assert_eq!(status, 200, "resp: {resp}");
    assert!(headers.contains("x-dwara-config-generation: 2"));
    // The file was rewritten (normalized: same content, gateway_to_yaml
    // formatting) and parses to the new shape.
    let on_disk = std::fs::read_to_string(&server.config_path).unwrap();
    let parsed = dwara_core::config::parse_gateway(&on_disk).expect("file parses after PATCH");
    assert!(parsed.upstreams.iter().any(|u| u.name == "added"));
    // The publish is visible to the dataplane: the registry now carries
    // the new upstream (subsequent proxy picks would use it).
    assert!(server.dp.registry().names().contains(&"added"));
    assert_eq!(server.state.snapshot().generation(), 2);
}

// --- dev fallback ---------------------------------------------------------

#[tokio::test]
async fn dev_mode_serves_plaintext_on_loopback_only() {
    // Loopback: plaintext works.
    let dir = tempfile::tempdir().unwrap();
    let server = start(ListenMode::DevPlaintext, dir).await;
    let mut stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let (status, _, _) = parse_response(&String::from_utf8_lossy(&buf)).unwrap();
    assert_eq!(status, 200);

    // Non-loopback bind: dev mode refuses outright.
    let err = match ListenMode::dev(&dwara_core::config::AdminConfig {
        bind: "0.0.0.0:2019".to_string(),
        tls: dwara_core::config::AdminTlsConfig {
            cert_file: "x".into(),
            key_file: "y".into(),
            client_ca_file: "z".into(),
        },
    }) {
        Err(e) => e,
        Ok(_) => panic!("dev must refuse non-loopback"),
    };
    assert!(err.to_string().contains("LOOPBACK"));
}

// --- admin mTLS build from the TLS module ---------------------------------

#[test]
fn mtls_config_rejects_missing_client_ca_file() {
    tls::install_aws_lc_rs_provider();
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let (cert, key) = pki.issue("localhost");
    let r = tls::admin_mtls_server_config(&dwara_core::config::AdminTlsConfig {
        cert_file: cert.display().to_string(),
        key_file: key.display().to_string(),
        client_ca_file: dir.path().join("missing.pem").display().to_string(),
    });
    assert!(r.is_err());
}

#[test]
fn validation_rejects_admin_block_without_client_ca() {
    let gw = dwara_core::config::parse_gateway(&format!(
        "{}admin:\n  tls:\n    cert_file: a\n    key_file: b\n",
        config_yaml(None)
    ))
    .expect_err("client_ca_file is a required field at the schema level");
    assert!(gw.to_string().contains("client_ca_file"));
}

// --- deep mTLS (done-when follow-ups) -------------------------------------

/// A client cert whose validity window ended in the past is rejected at
/// the handshake (webpki expiry check on the server's client verifier).
#[tokio::test]
async fn mtls_rejects_expired_client_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let (cert, key) = pki.issue_custom("expired-client", |p| {
        p.not_before = rcgen::date_time_ymd(2000, 1, 1);
        p.not_after = rcgen::date_time_ymd(2001, 1, 1);
    });
    let err = request(
        server.addr,
        &pki.ca_path(),
        Some((&pem(&cert), &pem(&key))),
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .expect_err("expired client cert must fail the handshake");
    assert!(
        err.contains("handshake") || err.contains("alert") || err.contains("Expired"),
        "expected handshake failure, got: {err}"
    );
}

/// A cert carrying only the serverAuth EKU (no clientAuth) is rejected
/// for client authentication.
#[tokio::test]
async fn mtls_rejects_client_cert_with_wrong_eku() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let (cert, key) = pki.issue_custom("server-only-eku", |p| {
        p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    });
    let err = request(
        server.addr,
        &pki.ca_path(),
        Some((&pem(&cert), &pem(&key))),
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .expect_err("serverAuth-only client cert must fail the handshake");
    assert!(
        err.contains("handshake") || err.contains("alert"),
        "expected handshake failure, got: {err}"
    );
}

/// Both TLS 1.2 and TLS 1.3 clients authenticate and are served.
#[tokio::test]
async fn mtls_accepts_tls12_and_tls13_clients() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let (cert, key) = pki.issue("admin-client");
    let (cert_pem, key_pem) = (pem(&cert), pem(&key));
    for versions in [
        &[&rustls::version::TLS12][..],
        &[&rustls::version::TLS13][..],
    ] {
        let stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
        let mut roots = rustls::RootCertStore::empty();
        use rustls::pki_types::pem::PemObject as _;
        for c in rustls::pki_types::CertificateDer::pem_file_iter(pki.ca_path())
            .expect("ca pem")
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
        {
            roots.add(c).unwrap();
        }
        let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
        let config = rustls::ClientConfig::builder_with_protocol_versions(versions)
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)
            .expect("client auth");
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
        let name = rustls::pki_types::ServerName::try_from("localhost".to_string()).expect("name");
        let mut tls = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            connector.connect(name, stream),
        )
        .await
        .expect("handshake completes (generous margin)")
        .expect("handshake succeeds");
        assert_eq!(
            Some(versions[0].version),
            tls.get_ref().1.protocol_version(),
            "negotiated version must be the pinned one"
        );
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        tls.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        tls.read_to_end(&mut buf).await.unwrap();
        let (status, _, _) =
            parse_response(&String::from_utf8_lossy(&buf)).expect("valid response");
        assert_eq!(status, 200);
    }
}

/// Speaking plaintext HTTP to the mTLS port gets no HTTP response at
/// all: the server aborts the connection (it is expecting a handshake).
#[tokio::test]
async fn plaintext_http_to_mtls_port_fails() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let mut stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut buf),
    )
    .await
    .expect("connection must close, not hang")
    .expect("read succeeds");
    let text = String::from_utf8_lossy(&buf);
    let status = parse_response(&text).map(|(s, _, _)| s);
    assert_ne!(status, Some(200), "no HTTP 200 may come off the mTLS port");
    // Either a clean close or a bare TLS alert record (a handful of
    // binary bytes) — never an HTTP response.
    assert!(n == 0 || parse_response(&text).is_none(), "got {n} bytes");
}

/// A burst of failed handshakes does not wedge the accept loop: a valid
/// client connects and is served immediately after.
#[tokio::test]
async fn failed_handshakes_do_not_wedge_subsequent_valid_ones() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    for _ in 0..5 {
        let _ = request(
            server.addr,
            &pki.ca_path(),
            None,
            "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
    }
    let (cert, key) = pki.issue("admin-client");
    let (status, _, _) = request(
        server.addr,
        &pki.ca_path(),
        Some((&pem(&cert), &pem(&key))),
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .expect("valid client must still be served after failed handshakes");
    assert_eq!(status, 200);
}

// --- PATCH semantics (in-process, no watcher running) ----------------------

/// One PATCH changing exactly one route bumps the generation by exactly
/// 1. (The documented watcher-driven second bump only occurs when the
/// dwara-bin config watcher is running; that is pinned in the dwara-bin
/// e2e test admin_reload_coherence.)
#[tokio::test]
async fn patch_changing_one_route_increments_generation_exactly_one() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let (cert, key) = pki.issue("admin-client");
    let extra_route = "  - name: r2\n    service: svc\n\
         \x20   match:\n      path:\n        type: prefix\n        value: /v2\n\
         \x20   action:\n      type: proxy\n";
    let changed = config_yaml(None).replacen("services:", &format!("{extra_route}services:"), 1);
    let body = format!(
        "PATCH /config HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/yaml\r\nContent-Length: {}\r\n\r\n{}",
        changed.len(),
        changed
    );
    let (status, headers, _) = request(
        server.addr,
        &pki.ca_path(),
        Some((&pem(&cert), &pem(&key))),
        &body,
    )
    .await
    .unwrap();
    assert_eq!(status, 200);
    assert!(
        headers.contains("x-dwara-config-generation: 2"),
        "exactly one publish: {headers}"
    );
    assert_eq!(server.state.snapshot().generation(), 2);
}

/// An identical-content PATCH still publishes (documented): generation
/// advances, the content hash does not change.
#[tokio::test]
async fn patch_with_identical_content_still_publishes() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let (cert, key) = pki.issue("admin-client");
    let before_hash = server.state.snapshot().content_hash();
    let same = config_yaml(None);
    let body = format!(
        "PATCH /config HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/yaml\r\nContent-Length: {}\r\n\r\n{}",
        same.len(),
        same
    );
    let (status, headers, _) = request(
        server.addr,
        &pki.ca_path(),
        Some((&pem(&cert), &pem(&key))),
        &body,
    )
    .await
    .unwrap();
    assert_eq!(status, 200);
    assert!(
        headers.contains("x-dwara-config-generation: 2"),
        "identical content still publishes: {headers}"
    );
    assert_eq!(server.state.snapshot().content_hash(), before_hash);
}

/// Atomicity across a publish: a snapshot handle taken before the PATCH
/// keeps serving the OLD route table; the dataplane's fresh snapshot
/// sees the new one. (The true in-flight-request e2e lives in
/// dwara-bin/tests/admin_reload_coherence.)
#[tokio::test]
async fn publish_swaps_snapshots_atomically_for_readers() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let old_snapshot = server.state.snapshot();
    assert!(old_snapshot.match_route("/api").is_some());
    // New config renames the route's prefix away from /api.
    let changed = config_yaml(None).replace("value: /api", "value: /beta");
    let gateway = dwara_core::config::parse_gateway(&changed).unwrap();
    server
        .state
        .compile_and_publish(&gateway)
        .expect("publishes");
    server.dp.refresh();
    // The pre-PATCH handle still resolves the old prefix; the live
    // snapshot resolves only the new one.
    assert!(old_snapshot.match_route("/api").is_some());
    assert!(server.state.snapshot().match_route("/api").is_none());
    assert!(server.state.snapshot().match_route("/beta").is_some());
}

/// Two concurrent PATCHes are serialized by the write lock: both
/// succeed, and the file ends as valid YAML containing exactly one of
/// the two documents (no interleaved corruption).
#[tokio::test]
async fn concurrent_patches_serialize_without_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let (cert, key) = pki.issue("admin-client");
    let (cert_pem, key_pem) = (pem(&cert), pem(&key));

    let mk = |upstream: &str| {
        let doc = config_yaml(Some(upstream));
        format!(
            "PATCH /config HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
             Content-Type: application/yaml\r\nContent-Length: {}\r\n\r\n{}",
            doc.len(),
            doc
        )
    };
    let addr = server.addr;
    let ca = pki.ca_path();
    let ca2 = ca.clone();
    let cp = cert_pem.clone();
    let kp = key_pem.clone();
    let req_alpha = mk("alpha");
    let req_omega = mk("omega");
    let a =
        tokio::spawn(
            async move { request(addr, &ca, Some((&cert_pem, &key_pem)), &req_alpha).await },
        );
    let b = tokio::spawn(async move { request(addr, &ca2, Some((&cp, &kp)), &req_omega).await });
    let (ra, rb) = (a.await.unwrap(), b.await.unwrap());
    assert_eq!(ra.unwrap().0, 200);
    assert_eq!(rb.unwrap().0, 200);

    // Final file parses and carries exactly one of the two writers'
    // upstreams (a full-document replacement wins whole).
    let on_disk = std::fs::read_to_string(&server.config_path).unwrap();
    let parsed = dwara_core::config::parse_gateway(&on_disk)
        .expect("final file is valid YAML (no interleaving)");
    let has_alpha = parsed.upstreams.iter().any(|u| u.name == "alpha");
    let has_omega = parsed.upstreams.iter().any(|u| u.name == "omega");
    assert!(
        has_alpha ^ has_omega,
        "exactly one full document must win: alpha={has_alpha} omega={has_omega}"
    );
    // Both publishes happened, serialized.
    assert_eq!(server.state.snapshot().generation(), 3);
}

// --- admin/dataplane isolation ---------------------------------------------

/// Admin requests never traverse the dataplane: after a burst of admin
/// calls the active-requests gauge rests at zero and there is no
/// metrics endpoint on the admin port.
#[tokio::test]
async fn admin_traffic_is_not_counted_by_the_dataplane() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let (cert, key) = pki.issue("admin-client");
    let (cert_pem, key_pem) = (pem(&cert), pem(&key));
    for _ in 0..3 {
        let _ = request(
            server.addr,
            &pki.ca_path(),
            Some((&cert_pem, &key_pem)),
            "GET /stats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    }
    let (_, _, body) = request(
        server.addr,
        &pki.ca_path(),
        Some((&cert_pem, &key_pem)),
        "GET /stats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let stats: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(stats["active_requests"], 0, "admin plane is separate");
    // No /metrics surface on the admin listener.
    let (status, _, _) = request(
        server.addr,
        &pki.ca_path(),
        Some((&cert_pem, &key_pem)),
        "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert_eq!(status, 404, "admin has no metrics endpoint");
}

// --- security ---------------------------------------------------------------

/// A PATCH body over the 4 MiB cap is rejected with a 413 envelope,
/// promptly (no hang, nothing published).
#[tokio::test]
async fn oversized_patch_body_is_413_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let (cert, key) = pki.issue("admin-client");
    // A syntactically YAML comment padded past the cap: if the cap were
    // absent this would parse fine, so the 413 is purely the size gate.
    let mut big = config_yaml(None);
    big.push_str(&format!("# {}\n", "x".repeat(4 * 1024 * 1024)));
    let body = format!(
        "PATCH /config HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/yaml\r\nContent-Length: {}\r\n\r\n{}",
        big.len(),
        big
    );
    let (status, _, resp) = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        request(
            server.addr,
            &pki.ca_path(),
            Some((&pem(&cert), &pem(&key))),
            &body,
        ),
    )
    .await
    .expect("oversized PATCH must not hang")
    .unwrap();
    assert_eq!(status, 413);
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["error"]["code"], "config_too_large");
    assert_eq!(server.state.snapshot().generation(), 1);
}

/// GET /config returns the config document and nothing else: no file
/// system paths, no key material.
#[tokio::test]
async fn get_config_leaks_no_paths_or_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let (cert, key) = pki.issue("admin-client");
    let (_, _, body) = request(
        server.addr,
        &pki.ca_path(),
        Some((&pem(&cert), &pem(&key))),
        "GET /config HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert!(
        !body.contains(&server.config_path.display().to_string()),
        "config file path must not leak"
    );
    assert!(!body.contains("BEGIN"), "no PEM material must leak");
    assert!(!body.contains(&pem(&pki.ca_path())), "no CA material");
    // And no store hashes: the body is exactly a gateway document.
    let parsed = dwara_core::config::parse_gateway(&body).expect("pure config document");
    assert!(parsed.admin.is_none());
}

// --- secret redaction (DW-045) ------------------------------------------------

/// Canary bytes that must NEVER appear in an admin response carrying
/// configuration.
const DW045_CANARY: &str = "sk-live-canary-dw045-77e2b1aa";

/// Publish a config carrying both secret shapes over the live server
/// (an inline canary key and a `${file:...}` reference), exactly like a
/// reload would.
async fn publish_secrets_config(server: &Server) -> String {
    let secret_file = server.config_path.parent().unwrap().join("acme.secret");
    std::fs::write(&secret_file, "file-resolved-key\n").unwrap();
    let yaml = format!(
        "{}consumers:\n  - name: acme\n    credentials:\n      - type: api_key\n        key: {}\n      - type: api_key\n        key: ${{file:{}}}\n",
        config_yaml(None),
        DW045_CANARY,
        secret_file.display()
    );
    let gateway = dwara_core::config::parse_gateway(&yaml).expect("secrets config parses");
    server
        .state
        .compile_and_publish(&gateway)
        .expect("secrets config publishes");
    server.dp.refresh();
    yaml
}

/// The DW-045 done-when, admin side: a canary secret written through
/// config never appears in GET /config (the config-dump surface) —
/// inline keys become unresolvable placeholders, references echo as
/// references — while /health and /stats stay secret-free as always.
#[tokio::test]
async fn get_config_redacts_secrets_canary_grep() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    publish_secrets_config(&server).await;
    let (cert, key) = pki.issue("admin-client");
    let cert_pem = pem(&cert);
    let key_pem = pem(&key);

    let (_, _, config_body) = request(
        server.addr,
        &pki.ca_path(),
        Some((&cert_pem, &key_pem)),
        "GET /config HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert!(
        !config_body.contains(DW045_CANARY),
        "the inline canary must never appear in the config dump: {config_body}"
    );
    assert!(
        config_body.contains("${redacted:sha256:"),
        "the inline key appears as the fingerprinted placeholder: {config_body}"
    );
    assert!(
        config_body.contains("${file:"),
        "references echo as references (a path is not secret bytes): {config_body}"
    );
    // The redacted dump is still a parseable gateway document.
    dwara_core::config::parse_gateway(&config_body).expect("redacted dump parses");

    for path in ["/health", "/stats"] {
        let (_, _, body) = request(
            server.addr,
            &pki.ca_path(),
            Some((&cert_pem, &key_pem)),
            &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
        )
        .await
        .unwrap();
        assert!(
            !body.contains(DW045_CANARY),
            "no secret material in {path}: {body}"
        );
    }
}

/// The GET-then-PATCH footgun, closed: a document carrying a redaction
/// placeholder back through PATCH is REJECTED with a precise issue —
/// placeholder bytes must never install as a live key, and nothing is
/// published or written.
#[tokio::test]
async fn patch_of_a_redacted_placeholder_is_rejected_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let before_publish = std::fs::read_to_string(&server.config_path).unwrap();
    let (cert, key) = pki.issue("admin-client");

    let body_yaml = format!(
        "{}consumers:\n  - name: acme\n    credentials:\n      - type: api_key\n        key: ${{redacted:sha256:e3b0c442}}\n",
        config_yaml(None)
    );
    let patch = format!(
        "PATCH /config HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/yaml\r\nContent-Length: {}\r\n\r\n{}",
        body_yaml.len(),
        body_yaml
    );
    let (status, _, resp) = request(
        server.addr,
        &pki.ca_path(),
        Some((&pem(&cert), &pem(&key))),
        &patch,
    )
    .await
    .unwrap();
    assert_eq!(status, 400, "placeholder must be rejected: {resp}");
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    let message = v["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("credentials[0]") && message.contains("redaction placeholder"),
        "the issue names the field and the placeholder: {message}"
    );
    // Nothing published, nothing written.
    assert_eq!(server.state.snapshot().generation(), 1);
    assert_eq!(
        std::fs::read_to_string(&server.config_path).unwrap(),
        before_publish,
        "the rejected PATCH must not touch the config file"
    );
}

/// The operator's escape hatch (DW-045): GET /config returns
/// placeholders; swapping ONE placeholder for a `${file:...}` reference
/// and PATCHing the document back publishes cleanly. This is the
/// positive-path counterpart of the fail-closed pin — the round trip
/// works exactly when the secret is re-expressed as a reference, and
/// the inline secret leaves the config document for good.
#[tokio::test]
async fn patch_swapping_a_placeholder_for_a_reference_republishes_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let (cert, key) = pki.issue("admin-client");
    let cert_pem = pem(&cert);
    let key_pem = pem(&key);
    let client = Some((cert_pem.as_str(), key_pem.as_str()));

    // Generation 2: publish a config carrying an inline canary.
    let yaml = format!(
        "{}consumers:\n  - name: acme\n    credentials:\n      - type: api_key\n        key: {DW045_CANARY}\n",
        config_yaml(None)
    );
    let gateway = dwara_core::config::parse_gateway(&yaml).expect("inline config parses");
    server
        .state
        .compile_and_publish(&gateway)
        .expect("inline config publishes");
    server.dp.refresh();
    assert_eq!(server.state.snapshot().generation(), 2);

    // GET /config: the canary comes back only as a placeholder.
    let (_, _, body) = request(
        server.addr,
        &pki.ca_path(),
        client,
        "GET /config HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert!(body.contains("${redacted:sha256:"));
    assert!(
        !body.contains(DW045_CANARY),
        "the canary never echoes: {body}"
    );

    // The operator's edit: replace the placeholder with a reference to
    // a secret file next to the config.
    let secret_file = server.config_path.parent().unwrap().join("rotated.secret");
    std::fs::write(&secret_file, "reference-resolved-key\n").unwrap();
    let start = body
        .find("${redacted:sha256:")
        .expect("placeholder present");
    let end = start + body[start..].find('}').expect("placeholder ends");
    let edited = format!(
        "{}${{file:{}}}{}",
        &body[..start],
        secret_file.display(),
        &body[end + 1..]
    );
    let patch = format!(
        "PATCH /config HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/yaml\r\nContent-Length: {}\r\n\r\n{}",
        edited.len(),
        edited
    );
    let (status, _, resp) = request(server.addr, &pki.ca_path(), client, &patch)
        .await
        .unwrap();
    assert_eq!(status, 200, "the reference-swap PATCH must publish: {resp}");

    // Published (generation 3), the file on disk carries the REFERENCE,
    // and the canary has left the config document entirely.
    assert_eq!(server.state.snapshot().generation(), 3);
    let on_disk = std::fs::read_to_string(&server.config_path).unwrap();
    assert!(
        on_disk.contains("${file:") && !on_disk.contains(DW045_CANARY),
        "the written config references the secret file, not the canary: {on_disk}"
    );

    // The new generation echoes as a reference — no placeholder, no
    // secret — because no inline value exists anymore.
    let (_, _, after) = request(
        server.addr,
        &pki.ca_path(),
        client,
        "GET /config HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert!(after.contains("${file:"));
    assert!(
        !after.contains("${redacted:sha256:") && !after.contains(DW045_CANARY),
        "a reference-only config echoes with neither placeholder nor secret: {after}"
    );
}

// --- POST /cache/purge (DW-037) ----------------------------------------------

/// Purge one named route: 200, names the route and its new epoch, and
/// the epoch is observable on the dataplane. The whole call is an O(1)
/// generation advance — the <100 ms bar holds by construction, and the
/// test also bounds it in wall time (loopback mTLS included) so a
/// future regression to store enumeration fails loudly.
#[tokio::test]
async fn cache_purge_names_route_and_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let (cert, key) = pki.issue("admin-client");
    let client = (pem(&cert), pem(&key));
    let started = std::time::Instant::now();
    let (status, _, body) = request(
        server.addr,
        &pki.ca_path(),
        Some((&client.0, &client.1)),
        "POST /cache/purge HTTP/1.1\r\nHost: localhost\r\ncontent-type: application/json\r\ncontent-length: 15\r\nConnection: close\r\n\r\n{\"route\": \"r1\"}",
    )
    .await
    .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(status, 200, "body: {body}");
    assert!(
        elapsed < std::time::Duration::from_millis(100),
        "purge took {elapsed:?} (the <100ms DW-037 bar)"
    );
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(doc["route"], "r1", "the response names what was purged");
    let epoch = doc["epoch"].as_u64().unwrap();
    assert!(epoch >= 1, "the epoch advanced (got {epoch})");
    assert_eq!(
        server.dp.response_cache().epoch("r1"),
        epoch,
        "the dataplane observed the same epoch"
    );
}

/// Purge-all invalidates every CURRENT route and lists them.
#[tokio::test]
async fn cache_purge_all_names_every_route() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let (cert, key) = pki.issue("admin-client");
    let client = (pem(&cert), pem(&key));
    let (status, _, body) = request(
        server.addr,
        &pki.ca_path(),
        Some((&client.0, &client.1)),
        "POST /cache/purge HTTP/1.1\r\nHost: localhost\r\ncontent-type: application/json\r\ncontent-length: 13\r\nConnection: close\r\n\r\n{\"all\": true}",
    )
    .await
    .unwrap();
    assert_eq!(status, 200, "body: {body}");
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(doc["all"], true);
    assert_eq!(doc["routes"], serde_json::json!(["r1"]));
    assert_eq!(doc["routes_invalidated"], 1);
    assert_eq!(server.dp.response_cache().epoch("r1"), 1);
}

/// The error shapes: unknown route is 404 naming it; a body that is
/// neither shape is 400; the wrong method on a known path is 405.
#[tokio::test]
async fn cache_purge_error_shapes() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new(dir.path());
    let server = start_mtls(&pki).await;
    let (cert, key) = pki.issue("admin-client");
    let client = (pem(&cert), pem(&key));

    let (status, _, body) = request(
        server.addr,
        &pki.ca_path(),
        Some((&client.0, &client.1)),
        "POST /cache/purge HTTP/1.1\r\nHost: localhost\r\ncontent-length: 24\r\nConnection: close\r\n\r\n{\"route\": \"nonexistent\"}",
    )
    .await
    .unwrap();
    assert_eq!(status, 404, "body: {body}");
    assert!(body.contains("cache_purge_unknown_route"));

    let (status, _, body) = request(
        server.addr,
        &pki.ca_path(),
        Some((&client.0, &client.1)),
        "POST /cache/purge HTTP/1.1\r\nHost: localhost\r\ncontent-length: 4\r\nConnection: close\r\n\r\n{}{}",
    )
    .await
    .unwrap();
    assert_eq!(status, 400, "body: {body}");
    assert!(body.contains("cache_purge_invalid"));

    let (status, _, _) = request(
        server.addr,
        &pki.ca_path(),
        Some((&client.0, &client.1)),
        "GET /cache/purge HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert_eq!(status, 405);

    // /stats carries the cache block (DW-037).
    let (status, _, body) = request(
        server.addr,
        &pki.ca_path(),
        Some((&client.0, &client.1)),
        "GET /stats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert_eq!(status, 200);
    assert!(
        body.contains("\"cache\""),
        "stats carries the cache block: {body}"
    );
}

// --- analytics endpoints (DW-043) ----------------------------------------

async fn plaintext_request(addr: std::net::SocketAddr, req: &str) -> (u16, String) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut buf),
    )
    .await
    .expect("read bound")
    .expect("read ok");
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, text)
}

#[tokio::test]
async fn analytics_endpoints_404_without_a_store() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(ListenMode::DevPlaintext, dir).await;
    for path in ["/analytics/dashboard", "/analytics/top"] {
        let (status, body) = plaintext_request(
            server.addr,
            &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert_eq!(status, 404, "{path}: {body}");
        assert!(body.contains("analytics_not_configured"), "{body}");
    }
    let (status, body) = plaintext_request(
        server.addr,
        "POST /analytics/query HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
    )
    .await;
    assert_eq!(status, 404, "{body}");
}

#[tokio::test]
async fn analytics_dashboard_top_and_query_serve_rollups() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(ListenMode::DevPlaintext, dir).await;
    let db = std::env::temp_dir().join(format!(
        "dwara-dw043-admin-{}-{}.db",
        std::process::id(),
        line!()
    ));
    let store = dwara_core::analytics::EmbeddedAnalytics::open(
        db.to_str().unwrap(),
        dwara_core::analytics::DEFAULT_RETENTION_MS,
        1000,
    )
    .unwrap();
    server.dp.set_analytics(Arc::clone(&store));
    // Seed deterministic history directly (the writer/rollup pipeline
    // is pinned in dwara-core's suites; these tests pin the ENDPOINTS).
    store
        .query(|c| {
            for i in 0..4i64 {
                c.execute(
                    "INSERT INTO raw (ts_ms, listener, route, consumer, upstream, method,
                                      status, status_class, duration_ms, attempts,
                                      rate_limited, broken, shed, dims)
                     VALUES (?1, 'edge', 'api', 'acme', 'up', 'GET', ?2, ?3, 10.0, 1,
                             ?4, 0, 0, '{}')",
                    rusqlite::params![
                        i * 60_000 + 1_000,
                        if i == 3 { 500 } else { 200 },
                        if i == 3 { "5xx" } else { "2xx" },
                        if i == 2 { 1 } else { 0 },
                    ],
                )
                .unwrap();
            }
            dwara_core::analytics::rollup::roll_raw_range(c, 0, 4 * 60_000).unwrap();
            Ok(())
        })
        .unwrap();

    // Dashboard: four 1-minute windows, 4 requests, 1 error, 1
    // rate-limited.
    let (status, body) = plaintext_request(
        server.addr,
        "GET /analytics/dashboard?from_ms=0&to_ms=240000&gran=0 HTTP/1.1\r\n\
         Host: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200, "{body}");
    // Per-window series: four points of one request each; the error
    // lands in window 180000 and the rate-limit rejection in 120000.
    assert_eq!(body.matches("\"window_start\"").count(), 4, "{body}");
    assert!(body.contains("\"errors\":1"), "{body}");
    assert!(body.contains("\"rate_limited\":1"), "{body}");

    // Dashboard drill-down by consumer with an equality filter.
    let (status, body) = plaintext_request(
        server.addr,
        "GET /analytics/dashboard?from_ms=0&to_ms=240000&gran=0&group_by=consumer&consumer=acme HTTP/1.1\r\n\
         Host: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"key\":\"acme\""), "{body}");

    // Bad params are rejected with named envelopes.
    let (status, body) = plaintext_request(
        server.addr,
        "GET /analytics/dashboard?from_ms=9&to_ms=1 HTTP/1.1\r\n\
         Host: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 400, "{body}");
    let (status, body) = plaintext_request(
        server.addr,
        "GET /analytics/dashboard?from_ms=0&to_ms=240000&group_by=evil HTTP/1.1\r\n\
         Host: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("analytics_bad_group_by"), "{body}");

    // Top: consumers and error_prone.
    let (status, body) = plaintext_request(
        server.addr,
        "GET /analytics/top?kind=consumers&from_ms=0&to_ms=240000&n=5 HTTP/1.1\r\n\
         Host: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"name\":\"acme\""), "{body}");
    let (status, _body) = plaintext_request(
        server.addr,
        "GET /analytics/top?kind=nope&from_ms=0&to_ms=240000 HTTP/1.1\r\n\
         Host: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 400);

    // Structured query: group by status_class.
    let query = r#"{"from_ms":0,"to_ms":240000,"gran":0,"group_by":["status_class"]}"#;
    let req = format!(
        "POST /analytics/query HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        query.len(),
        query
    );
    let (status, body) = plaintext_request(server.addr, &req).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"requests\":3"), "{body}");
    assert!(body.contains("\"requests\":1"), "{body}");

    // The closed grammar rejects SQL text, not by pattern, by column
    // set.
    let evil =
        r#"{"from_ms":0,"to_ms":240000,"gran":0,"group_by":["status_class; DROP TABLE raw"]}"#;
    let req = format!(
        "POST /analytics/query HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        evil.len(),
        evil
    );
    let (status, body) = plaintext_request(server.addr, &req).await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("analytics_query_invalid"), "{body}");
    let _ = std::fs::remove_file(&db);
}

// --- Credential lifecycle endpoints (DW-046) --------------------------------

#[tokio::test]
async fn credential_endpoints_404_without_a_state_store() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(ListenMode::DevPlaintext, dir).await;
    for (method, path, body) in [
        ("GET", "/consumers/acme/credentials", ""),
        (
            "POST",
            "/consumers/acme/credentials",
            "{\"key\":\"aaaaaaaaaaaaaaaa\"}",
        ),
        ("POST", "/credentials/1/retire", ""),
    ] {
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (status, text) = plaintext_request(server.addr, &req).await;
        assert_eq!(status, 404, "{path}: {text}");
        assert!(text.contains("state_store_not_configured"), "{text}");
    }
}

#[tokio::test]
async fn credential_rotation_flow_issue_list_retire_over_admin() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("state.db");
    let server = start(ListenMode::DevPlaintext, dir).await;
    // Attach a store with one consumer and one OLD credential (the
    // dwara-bin startup shape, minus the file).
    let store = std::sync::Arc::new(dwara_core::store::StateStore::open(&db).unwrap());
    let consumer = store.upsert_consumer("acme", None, &[]).unwrap();
    store
        .add_credential(
            consumer.id,
            dwara_core::store::CredentialKind::ApiKey,
            dwara_core::config::credentials::sha256_stored_hash("the-old-secret-value"),
            None,
            dwara_core::config::credentials::credential_selector("the-old-secret-value"),
        )
        .unwrap();
    server.dp.set_state_store(std::sync::Arc::clone(&store));

    // Unknown consumer: named 404.
    let (status, body) = plaintext_request(
        server.addr,
        "GET /consumers/ghost/credentials HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 404, "{body}");
    assert!(body.contains("unknown_consumer"), "{body}");

    // Issue the new key: 201, id, and the runbook note.
    let key = "the-new-rotated-secret";
    let body_json = format!("{{\"key\":\"{key}\"}}");
    let req = format!(
        "POST /consumers/acme/credentials HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body_json.len(),
        body_json
    );
    let (status, body) = plaintext_request(server.addr, &req).await;
    assert_eq!(status, 201, "{body}");
    assert!(body.contains("credential_id"), "{body}");

    // The issued key authenticates through the dataplane-backed store
    // (the dual-validity window is open: the row verifies).
    let active = store
        .lookup_credentials_by_selector(&dwara_core::config::credentials::credential_selector(key))
        .unwrap();
    assert_eq!(active.len(), 1, "issued key is live: {active:?}");

    // Weak keys are refused.
    let weak = "{\"key\":\"short\"}";
    let req = format!(
        "POST /consumers/acme/credentials HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        weak.len(),
        weak
    );
    let (status, body) = plaintext_request(server.addr, &req).await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("credential_issue_invalid"), "{body}");

    // List: two rows, lifecycle stamps only (no selector/hash material).
    let (status, body) = plaintext_request(
        server.addr,
        "GET /consumers/acme/credentials HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body.matches("\"id\"").count(), 2, "{body}");
    assert!(!body.contains("selector"), "no selector material: {body}");
    assert!(!body.contains("hash"), "no hash material: {body}");

    // Retire the OLD row immediately (empty body).
    let old_id: i64 = {
        let rows = store.list_credentials_for_consumer("acme").unwrap();
        // The list is newest-first; the OLD key is the smallest id.
        rows.iter().map(|r| r.id).min().unwrap()
    };
    let req = format!(
        "POST /credentials/{old_id}/retire HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Length: 0\r\n\r\n"
    );
    let (status, body) = plaintext_request(server.addr, &req).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"effective\":\"immediate\""), "{body}");
    // The old key is gone from the active set.
    let active = store
        .lookup_credentials_by_selector(&dwara_core::config::credentials::credential_selector(
            "the-old-secret-value",
        ))
        .unwrap();
    assert!(active.is_empty());

    // Retiring it again: named 404 (not active).
    let req = format!(
        "POST /credentials/{old_id}/retire HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Length: 0\r\n\r\n"
    );
    let (status, body) = plaintext_request(server.addr, &req).await;
    assert_eq!(status, 404, "{body}");
    assert!(body.contains("credential_not_active"), "{body}");

    // Scheduled retirement carries the stamp and the scheduled flag.
    let new_id: i64 = store
        .list_credentials_for_consumer("acme")
        .unwrap()
        .iter()
        .find(|r| r.retire_at.is_none())
        .map(|r| r.id)
        .unwrap();
    let future = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64)
        + 3_600_000;
    let body_json = format!("{{\"at_ms\":{future}}}");
    let req = format!(
        "POST /credentials/{new_id}/retire HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body_json.len(),
        body_json
    );
    let (status, body) = plaintext_request(server.addr, &req).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"effective\":\"scheduled\""), "{body}");
}

// --- quotas (DW-033) -------------------------------------------------------

#[tokio::test]
async fn quotas_usage_404s_without_a_state_store() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(ListenMode::DevPlaintext, dir).await;
    let (status, body) = plaintext_request(
        server.addr,
        "GET /quotas/usage HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 404, "{body}");
    assert!(body.contains("state_store_not_configured"), "{body}");
}

#[tokio::test]
async fn quotas_usage_reports_current_windows_and_validates_the_filter() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("state.db");
    let server = start(ListenMode::DevPlaintext, dir).await;
    // Publish a config carrying one quota consumer (the base config the
    // start() helper publishes has none — quotas are config-declared).
    let yaml = "consumers:
  - name: acme
    credentials:
      - type: api_key
        key: acme-key
    quotas:
      daily_requests: 2
      monthly_requests: 10
routes:
  - name: r1
    service: svc
    match: { path: { type: prefix, value: /api } }
    action: { type: respond, status: 200, body: ok }
services:
  - name: svc
    upstream: echo
upstreams:
  - name: echo
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";
    let gw = dwara_core::config::parse_gateway(yaml).unwrap();
    server.state.compile_and_publish(&gw).unwrap();
    // The publish-side refresh the admin PATCH path performs (a raw
    // state publish alone does not rebuild the dataplane generation).
    server.dp.refresh();
    // The dwara-bin startup shape: open the store, seed consumers from
    // the config, attach to the dataplane.
    let store = std::sync::Arc::new(dwara_core::store::StateStore::open(&db).unwrap());
    dwara_core::store::sync_consumers_from_config(&store, &gw, None).unwrap();
    server.dp.set_state_store(std::sync::Arc::clone(&store));

    // Spend one daily unit through the REAL request path (x-api-key),
    // so the endpoint reports live counters, not just zeros.
    let req = http_body_util::Full::new(bytes::Bytes::new());
    let req = hyper::Request::builder()
        .uri("/api/thing")
        .header("x-api-key", "acme-key")
        .body(req)
        .unwrap();
    let resp =
        dwara_core::proxy::handle(&server.dp, std::net::IpAddr::from([127, 0, 0, 1]), req).await;
    use http_body_util::BodyExt as _;
    let (parts, body) = resp.into_parts();
    let _ = body.collect().await.unwrap();
    assert_eq!(parts.status, 200);

    let (status, text) = plaintext_request(
        server.addr,
        "GET /quotas/usage HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200, "{text}");
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
    let v: serde_json::Value = serde_json::from_str(body).unwrap();
    let consumers = v["consumers"].as_array().unwrap();
    assert_eq!(consumers.len(), 1);
    let c = &consumers[0];
    assert_eq!(c["consumer"], "acme");
    assert_eq!(c["synced"], true);
    let budgets = c["budgets"].as_array().unwrap();
    assert_eq!(budgets.len(), 2, "daily and monthly: {budgets:?}");
    let daily = &budgets[0];
    assert_eq!(daily["budget"], "daily");
    assert_eq!(daily["limit"], 2);
    assert_eq!(daily["used"], 1, "the request-path unit is visible");
    assert_eq!(daily["remaining"], 1);
    let monthly = &budgets[1];
    assert_eq!(monthly["budget"], "monthly");
    assert_eq!(
        monthly["used"], 1,
        "one request spends one unit in every window"
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap();
    assert!(daily["reset_epoch_s"].as_u64().unwrap() > now);
    assert!(monthly["reset_epoch_s"].as_u64().unwrap() > daily["reset_epoch_s"].as_u64().unwrap());

    // The consumer filter narrows; an unknown name is a named 400.
    let (status, text) = plaintext_request(
        server.addr,
        "GET /quotas/usage?consumer=acme HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200, "{text}");
    let (status, body) = plaintext_request(
        server.addr,
        "GET /quotas/usage?consumer=ghost HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("quota_bad_consumer"), "{body}");

    // Wrong method on a known path: the 405 envelope.
    let (status, body) = plaintext_request(
        server.addr,
        "POST /quotas/usage HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Length: 0\r\n\r\n",
    )
    .await;
    assert_eq!(status, 405, "{body}");
}

#[tokio::test]
async fn quotas_usage_marks_an_unsynced_consumer_without_faking_zeros() {
    // A store is attached but the quota consumer was never synced into
    // it (no consumer row): there are no counters, so the endpoint
    // reports synced=false with an EMPTY budgets list — zero-usage
    // figures would be a lie (nothing was ever counted).
    let dir = tempfile::tempdir().unwrap();
    let server = start(ListenMode::DevPlaintext, dir).await;
    let yaml = "consumers:
  - name: ghost-budget
    credentials:
      - type: api_key
        key: ghost-key
    quotas:
      daily_requests: 5
routes:
  - name: r1
    service: svc
    match: { path: { type: prefix, value: /api } }
    action: { type: respond, status: 200, body: ok }
services:
  - name: svc
    upstream: echo
upstreams:
  - name: echo
    endpoints: [{ address: 127.0.0.1, port: 1 }]
";
    let gw = dwara_core::config::parse_gateway(yaml).unwrap();
    server.state.compile_and_publish(&gw).unwrap();
    server.dp.refresh();
    // An EMPTY store: attached, but sync_consumers_from_config never ran.
    let empty = std::sync::Arc::new(dwara_core::store::StateStore::open_in_memory().unwrap());
    server.dp.set_state_store(empty);

    let (status, text) = plaintext_request(
        server.addr,
        "GET /quotas/usage HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200, "{text}");
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
    let v: serde_json::Value = serde_json::from_str(body).unwrap();
    let consumers = v["consumers"].as_array().unwrap();
    assert_eq!(consumers.len(), 1);
    assert_eq!(consumers[0]["consumer"], "ghost-budget");
    assert_eq!(consumers[0]["synced"], false);
    assert_eq!(
        consumers[0]["budgets"].as_array().map(Vec::len),
        Some(0),
        "no counters exist; no fabricated zeros"
    );
}
