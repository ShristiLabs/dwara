//! Integration tests for DW-007: TLS termination with multiple SNI certs
//! (TLS 1.3 and 1.2), h2c prior-knowledge on cleartext listeners, h2
//! over TLS (ALPN), SNI-routed TLS passthrough, and certificate
//! hot-reload. All certificates are generated at test time with rcgen;
//! nothing is committed.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::aws_lc_rs;
use tokio_rustls::rustls::DigitallySignedStruct;
use tokio_rustls::rustls::{ClientConfig, SignatureScheme};
use tokio_rustls::{rustls, TlsConnector};

struct ServerGuard(Child);

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("addr").port()
}

fn temp_dir(tag: &str) -> PathBuf {
    // #128: a process-global counter instead of clock nanos — nanosecond
    // stamps collide across parallel test threads (one test's cleanup
    // then deletes a sibling's certs/config).
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("dwara-dw007-{}-{n}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct CertFiles {
    cert: PathBuf,
    key: PathBuf,
}

fn write_cert(dir: &std::path::Path, cn: &str) -> CertFiles {
    let cert = rcgen::generate_simple_self_signed(vec![cn.to_string()]).expect("rcgen");
    let cpath = dir.join(format!("{cn}.crt.pem"));
    let kpath = dir.join(format!("{cn}.key.pem"));
    std::fs::write(&cpath, cert.cert.pem()).unwrap();
    std::fs::write(&kpath, cert.key_pair.serialize_pem()).unwrap();
    CertFiles {
        cert: cpath,
        key: kpath,
    }
}

/// Accept-any verifier: tests only assert WHICH self-signed certificate
/// was served (by inspecting the peer certificate), so chain validation
/// is intentionally bypassed on the client side.
/// Accept-any verifier (see above). A unit struct: nothing about the
/// provider is consulted.
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let _ = (message, cert, dss);
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let _ = (message, cert, dss);
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}

fn tls_connector(sni: &str, alpn: &[&str]) -> TlsConnector {
    let provider = Arc::new(aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    let _ = sni;
    Arc::new(config).into()
}

/// TLS 1.2-only connector.
fn tls12_connector(alpn: &[&str]) -> TlsConnector {
    let provider = Arc::new(aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    Arc::new(config).into()
}

/// Run one HTTPS GET over the connector; returns (peer cert DER, ALPN,
/// response bytes).
async fn tls_get(
    addr: &str,
    sni: &str,
    connector: &TlsConnector,
) -> (Vec<u8>, Option<String>, Vec<u8>) {
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .expect("sni")
        .to_owned();
    let mut tls = connector.connect(name, tcp).await.expect("tls handshake");
    let (cert, alpn) = {
        let (_, session) = tls.get_ref();
        let cert = session
            .peer_certificates()
            .and_then(|c| c.first())
            .map(|c| c.to_vec())
            .expect("peer cert");
        let alpn = session
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned());
        (cert, alpn)
    };
    let http = b"GET / HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n";
    tokio::io::AsyncWriteExt::write_all(&mut tls, http)
        .await
        .unwrap();
    let mut resp = Vec::new();
    let _ = tokio::io::AsyncReadExt::read_to_end(&mut tls, &mut resp).await;
    (cert, alpn, resp)
}

fn start_server(config_path: &std::path::Path) -> ServerGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_dwara"))
        .env("DWARA_CONFIG", config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dwara");
    ServerGuard(child)
}

fn wait_tcp(addr: &str, deadline: Instant) {
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("dwara did not listen on {addr}");
}

/// Re-read a written PEM cert file and decode it to DER bytes, so the
/// served peer certificate can be compared to the on-disk file.
fn cert_der_of(files: &CertFiles) -> Vec<u8> {
    base64_decode_shim(&std::fs::read_to_string(&files.cert).unwrap())
}

/// Minimal base64 decoder (standard alphabet, padded) to avoid another
/// dependency in dev-deps.
fn base64_decode_shim(pem: &str) -> Vec<u8> {
    let mut table = [255u8; 256];
    for (i, c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .iter()
        .enumerate()
    {
        table[*c as usize] = i as u8;
    }
    let input: Vec<u8> = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.trim().bytes())
        .collect();
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &b in &input {
        if b == b'=' {
            break;
        }
        let v = table[b as usize];
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}

#[tokio::test]
async fn tls_terminate_serves_per_sni_cert_over_13_12_and_alpn_h2() {
    let dir = temp_dir("term");
    let ca = write_cert(&dir, "fallback.example.com");
    let a = write_cert(&dir, "a.example.com");
    let b = write_cert(&dir, "b.example.com");
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let config = dir.join("dwara.yaml");
    std::fs::write(
        &config,
        format!(
            "\
listeners:
  - name: tls-edge
    address: 127.0.0.1
    port: {port}
    protocol: https
    tls:
      mode: terminate
      cert_file: {}
      key_file: {}
      certificates:
        - server_names: [a.example.com]
          cert_file: {}
          key_file: {}
        - server_names: [b.example.com]
          cert_file: {}
          key_file: {}
routes:
  - name: catch
    service: local
    match:
      path:
        type: regex
        value: /.*
    action:
      type: respond
      status: 200
      body: dwara
services:
  - name: local
    upstream: local-up
upstreams:
  - name: local-up
    endpoints:
      - address: 127.0.0.1
        port: 9

",
            ca.cert.display(),
            ca.key.display(),
            a.cert.display(),
            a.key.display(),
            b.cert.display(),
            b.key.display()
        ),
    )
    .unwrap();

    let _server = start_server(&config);
    wait_tcp(&addr, Instant::now() + Duration::from_secs(30));

    // TLS 1.3, SNI a -> cert a; HTTP/1.1 body.
    let conn = tls_connector("a.example.com", &["http/1.1"]);
    let (cert, alpn, resp) = tls_get(&addr, "a.example.com", &conn).await;
    assert_eq!(cert, cert_der_of(&a), "SNI a must serve cert a");
    assert_eq!(alpn.as_deref(), Some("http/1.1"));
    assert!(
        String::from_utf8_lossy(&resp).ends_with("dwara"),
        "{resp:?}"
    );

    // TLS 1.3, SNI b -> cert b.
    let conn = tls_connector("b.example.com", &["http/1.1"]);
    let (cert, _, resp) = tls_get(&addr, "b.example.com", &conn).await;
    assert_eq!(cert, cert_der_of(&b), "SNI b must serve cert b");
    assert!(String::from_utf8_lossy(&resp).ends_with("dwara"));

    // No SNI match -> fallback cert.
    let conn = tls_connector("unknown.example.com", &["http/1.1"]);
    let (cert, _, _) = tls_get(&addr, "unknown.example.com", &conn).await;
    assert_eq!(cert, cert_der_of(&ca), "unmatched SNI must serve fallback");

    // TLS 1.2 still works.
    let conn12 = tls12_connector(&["http/1.1"]);
    let (cert, _, resp) = tls_get(&addr, "a.example.com", &conn12).await;
    assert_eq!(cert, cert_der_of(&a));
    assert!(String::from_utf8_lossy(&resp).ends_with("dwara"));

    // ALPN h2: the server must negotiate h2 and answer the HTTP/2
    // connection preface with its own SETTINGS frame (frame type 0x04).
    let h2conn = tls_connector("a.example.com", &["h2"]);
    let tcp = TcpStream::connect(&addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("a.example.com".to_string())
        .unwrap()
        .to_owned();
    let mut tls = h2conn.connect(name, tcp).await.unwrap();
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(&b"h2"[..]),
        "server must negotiate h2 via ALPN"
    );
    tls.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    // Empty SETTINGS frame.
    tls.write_all(&[0, 0, 0, 0x04, 0, 0, 0, 0]).await.unwrap();
    let mut frame = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(5), tls.read_exact(&mut frame))
        .await
        .expect("h2 response within timeout")
        .expect("read frame");
    assert_eq!(
        frame[3], 0x04,
        "first h2 frame must be SETTINGS, got {frame:?}"
    );
    let _ = tokio::io::AsyncWriteExt::shutdown(&mut tls).await;
}

#[tokio::test]
async fn cleartext_listener_accepts_http1_and_h2c_prior_knowledge() {
    let dir = temp_dir("h2c");
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let config = dir.join("dwara.yaml");
    std::fs::write(
        &config,
        format!(
            "listeners:\n  - name: plain\n    address: 127.0.0.1\n    port: {port}\nroutes:
  - name: catch
    service: local
    match:
      path:
        type: regex
        value: /.*
    action:
      type: respond
      status: 200
      body: dwara
services:
  - name: local
    upstream: local-up
upstreams:
  - name: local-up
    endpoints:
      - address: 127.0.0.1
        port: 9
\n"
        ),
    )
    .unwrap();
    let _server = start_server(&config);
    wait_tcp(&addr, Instant::now() + Duration::from_secs(30));

    // HTTP/1.1.
    let mut tcp = std::net::TcpStream::connect(&addr).unwrap();
    tcp.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut buf = Vec::new();
    tcp.read_to_end(&mut buf).unwrap();
    assert!(String::from_utf8_lossy(&buf).ends_with("dwara"));

    // h2c prior knowledge: preface + empty SETTINGS -> server SETTINGS.
    let mut tcp = std::net::TcpStream::connect(&addr).unwrap();
    tcp.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
    tcp.write_all(&[0, 0, 0, 0x04, 0, 0, 0, 0]).unwrap();
    let mut frame = [0u8; 9];
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    tcp.read_exact(&mut frame).unwrap();
    assert_eq!(
        frame[3], 0x04,
        "h2c must yield a SETTINGS frame, got {frame:?}"
    );
}

/// Minimal TLS backend for passthrough: terminates TLS itself and answers
/// HTTP/1.1 with a fixed body.
async fn spawn_backend(cert: CertFiles, name: &'static str) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let certs = <rustls::pki_types::CertificateDer<'_> as rustls::pki_types::pem::PemObject>::pem_file_iter(&cert.cert)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key =
        <rustls::pki_types::PrivateKeyDer<'_> as rustls::pki_types::pem::PemObject>::pem_file_iter(
            &cert.key,
        )
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let provider = Arc::new(aws_lc_rs::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => return,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let _ = tls.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nbackend",
                    )
                    .await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    let _ = name;
    (port, task)
}

#[tokio::test]
async fn tls_passthrough_routes_by_sni_to_backend() {
    let dir = temp_dir("pass");
    let cert = write_cert(&dir, "back.example.com");
    let (back_port, _backend) = spawn_backend(cert, "backend").await;

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let config = dir.join("dwara.yaml");
    // Genuinely zero-route (#129 opt-in): passthrough routing is by SNI
    // (sni_routes), so the HTTP route table is empty by design.
    std::fs::write(
        &config,
        format!(
            "\
listeners:
  - name: pass-edge
    address: 127.0.0.1
    port: {port}
    protocol: https
    tls:
      mode: passthrough
      sni_routes:
        - server_names: [back.example.com]
          upstream: backends
upstreams:
  - name: backends
    endpoints:
      - address: 127.0.0.1
        port: {back_port}
allow_empty_routes: true
"
        ),
    )
    .unwrap();
    let _server = start_server(&config);
    wait_tcp(&addr, Instant::now() + Duration::from_secs(30));

    // Matching SNI: handshake completes against the BACKEND cert and the
    // backend's response arrives through the splice.
    let conn = tls_connector("back.example.com", &["http/1.1"]);
    let (cert_der, alpn, resp) = tls_get(&addr, "back.example.com", &conn).await;
    let expected = std::fs::read_to_string(
        std::fs::read_dir(&dir)
            .unwrap()
            .find(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains("back.example.com.crt")
            })
            .unwrap()
            .unwrap()
            .path(),
    )
    .unwrap();
    assert_eq!(
        cert_der,
        base64_decode_shim(&expected),
        "passthrough must present the BACKEND certificate (no termination)"
    );
    assert_eq!(alpn.as_deref(), Some("http/1.1"), "backend negotiated ALPN");
    assert!(
        String::from_utf8_lossy(&resp).ends_with("backend"),
        "{resp:?}"
    );

    // Unmatched SNI: the gateway closes the connection.
    let conn = tls_connector("nomatch.example.com", &["http/1.1"]);
    let tcp = TcpStream::connect(&addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("nomatch.example.com".to_string())
        .unwrap()
        .to_owned();
    let result = conn.connect(name, tcp).await;
    assert!(result.is_err(), "unmatched SNI must be closed");
}

#[tokio::test]
async fn certificate_hot_reload_serves_new_cert_without_restart() {
    let dir = temp_dir("reload");
    let ca = write_cert(&dir, "edge.example.com");
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let config = dir.join("dwara.yaml");
    std::fs::write(
        &config,
        format!(
            "\
listeners:
  - name: edge
    address: 127.0.0.1
    port: {port}
    protocol: https
    tls:
      mode: terminate
      cert_file: {}
      key_file: {}
routes:
  - name: catch
    service: local
    match:
      path:
        type: regex
        value: /.*
    action:
      type: respond
      status: 200
      body: dwara
services:
  - name: local
    upstream: local-up
upstreams:
  - name: local-up
    endpoints:
      - address: 127.0.0.1
        port: 9

",
            ca.cert.display(),
            ca.key.display()
        ),
    )
    .unwrap();
    let _server = start_server(&config);
    wait_tcp(&addr, Instant::now() + Duration::from_secs(30));

    let conn = tls_connector("edge.example.com", &["http/1.1"]);
    let (cert1, _, resp) = tls_get(&addr, "edge.example.com", &conn).await;
    assert_eq!(cert1, cert_der_of(&ca));
    assert!(String::from_utf8_lossy(&resp).ends_with("dwara"));

    // Swap the certificate files on disk (atomic rename, as a deployer
    // would), then poll with fresh handshakes until the reloaded
    // certificate is served. A fixed sleep raced the reload pipeline
    // (file-watcher latency + 250ms debounce) under parallel load; the
    // bounded poll removes the timing dependency without weakening the
    // assertion: if the new cert is never served within the window the
    // test still fails on the final iteration.
    let new_cert = write_cert(dir.parent().unwrap(), "edge2.example.com");
    let expected_der = cert_der_of(&new_cert);
    let tmp_cert = dir.join("cert.new");
    let tmp_key = dir.join("key.new");
    std::fs::copy(&new_cert.cert, &tmp_cert).unwrap();
    std::fs::copy(&new_cert.key, &tmp_key).unwrap();
    std::fs::rename(&tmp_cert, &ca.cert).unwrap();
    std::fs::rename(&tmp_key, &ca.key).unwrap();

    let deadline = Instant::now() + Duration::from_secs(30);
    let (cert2, resp) = loop {
        let conn = tls_connector("edge2.example.com", &["http/1.1"]);
        let (cert, _, body) = tls_get(&addr, "edge2.example.com", &conn).await;
        if cert == expected_der || Instant::now() >= deadline {
            break (cert, body);
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(
        cert2, expected_der,
        "new handshake must serve the reloaded certificate"
    );
    assert_ne!(cert1, cert2);
    assert!(String::from_utf8_lossy(&resp).ends_with("dwara"));
}

// ---------------------------------------------------------------------------
// #124: mTLS client-certificate authn on a terminate listener
// ---------------------------------------------------------------------------

/// A self-signed client CA plus a leaf certificate it signed carrying
/// the given subject CommonName (the by-subject matcher's input).
struct ClientCert {
    cert_pem: String,
    key_der: Vec<u8>,
}

fn client_ca_and_leaf(ca_cn: &str, leaf_cn: &str) -> (rcgen::Certificate, ClientCert) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, ca_cn);
    let ca = ca_params.self_signed(&ca_key).unwrap();

    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let mut leaf_params = rcgen::CertificateParams::default();
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, leaf_cn);
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    (
        ca,
        ClientCert {
            cert_pem: leaf.pem(),
            key_der: leaf_key.serialize_der(),
        },
    )
}

/// Connector presenting a client certificate (server trust bypassed as
/// everywhere in this suite: only client-cert AUTHENTICATION is under
/// test, not the server chain).
fn client_cert_connector(cert_pem: &str, key_der: &[u8]) -> TlsConnector {
    let provider = Arc::new(aws_lc_rs::default_provider());
    let cert = <rustls::pki_types::CertificateDer<'_> as rustls::pki_types::pem::PemObject>::pem_slice_iter(cert_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        key_der.to_vec(),
    ));
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_client_auth_cert(vec![cert], key)
        .expect("client cert");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config).into()
}

/// One plain GET over an established TLS stream; returns the response
/// bytes (status line + headers + body). #128: a FAILED write means the
/// connection died before anything was received (a reset racing the
/// exchange under parallel load — the #121 class); the empty Vec tells
/// [`tls_get_retrying_reset`] to retry rather than panicking here.
async fn raw_get(tls: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    if tls
        .write_all(b"GET / HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n")
        .await
        .is_err()
    {
        return Vec::new();
    }
    let mut resp = Vec::new();
    let _ = tls.read_to_end(&mut resp).await;
    resp
}

/// Connect + [`raw_get`] in one exchange, retrying under a bounded budget
/// while NOTHING has been received. Under parallel load the gateway's
/// close can reach the client as ECONNRESET instead of a clean FIN (the
/// kernel replaces FIN with RST when the closing socket still has
/// unread data queued, and CPU contention widens that race window), so
/// the handshake or the request write fails before any response bytes
/// exist. Retrying that specific shape does not weaken the callers'
/// assertions: the asserted response must still arrive within the same
/// bounded budget — a genuinely failing listener fails every attempt.
async fn tls_get_retrying_reset(addr: &str, connector: &TlsConnector) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let exchange = async {
            let mut tls = connect_tls(addr, connector).await?;
            let resp = raw_get(&mut tls).await;
            Ok::<Vec<u8>, std::io::Error>(resp)
        };
        if let Ok(resp) = exchange.await {
            if !resp.is_empty() {
                return resp;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no response bytes within the 10s retry budget (repeated resets or a dead listener)"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn connect_tls(
    addr: &str,
    connector: &TlsConnector,
) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    let name = rustls::pki_types::ServerName::try_from("edge.example.com".to_string())
        .expect("sni")
        .to_owned();
    connector.connect(name, tcp).await
}

#[tokio::test]
async fn mtls_client_certificate_authenticates_on_terminate_listener() {
    let dir = temp_dir("mtls");
    let server = write_cert(&dir, "edge.example.com");
    let (client_ca, good_client) = client_ca_and_leaf("dwara-test-client-ca", "mtls-acme");
    // A second CA whose leaf is NOT trusted by the listener.
    let (_stranger_ca, stranger_client) = client_ca_and_leaf("other-ca", "mtls-acme");
    let ca_path = dir.join("client-ca.pem");
    std::fs::write(&ca_path, client_ca.pem()).unwrap();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let config = dir.join("dwara.yaml");
    std::fs::write(
        &config,
        format!(
            "\
listeners:
  - name: mtls-edge
    address: 127.0.0.1
    port: {port}
    protocol: https
    tls:
      mode: terminate
      cert_file: {}
      key_file: {}
      client_ca_file: {}
routes:
  - name: catch
    service: local
    auth_required: true
    match:
      path:
        type: regex
        value: /.*
    action:
      type: respond
      status: 200
      body: hello-mtls
services:
  - name: local
    upstream: local-up
upstreams:
  - name: local-up
    endpoints:
      - address: 127.0.0.1
        port: 9
consumers:
  - name: acme
    credentials:
      - type: mtls
        subject: mtls-acme
",
            server.cert.display(),
            server.key.display(),
            ca_path.display()
        ),
    )
    .unwrap();

    let _server = start_server(&config);
    wait_tcp(&addr, Instant::now() + Duration::from_secs(30));

    // WITH the CA-verified client certificate whose CN matches the
    // consumer's mtls credential: proxied (here: answered) with identity.
    let connector = client_cert_connector(&good_client.cert_pem, &good_client.key_der);
    let resp = tls_get_retrying_reset(&addr, &connector).await;
    let text = String::from_utf8_lossy(&resp);
    assert!(text.starts_with("HTTP/1.1 200"), "resp: {text}");
    assert!(text.ends_with("hello-mtls"), "resp: {text}");

    // WITHOUT a client certificate: the mTLS family has nothing to
    // match, the route requires auth -> 401 envelope.
    let plain = tls_connector("edge.example.com", &["http/1.1"]);
    let resp = tls_get_retrying_reset(&addr, &plain).await;
    let text = String::from_utf8_lossy(&resp);
    assert!(text.starts_with("HTTP/1.1 401"), "resp: {text}");

    // A certificate from an UNTRUSTED CA is rejected at the TLS layer;
    // authn never sees it. In TLS 1.3 the client-side handshake can
    // COMPLETE before the server's bad_certificate alert arrives, so the
    // rejection may surface on the first read instead of connect — either
    // way, NO HTTP response is ever served.
    let bad = client_cert_connector(&stranger_client.cert_pem, &stranger_client.key_der);
    let tcp = TcpStream::connect(&addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("edge.example.com".to_string())
        .unwrap()
        .to_owned();
    let served = match bad.connect(name, tcp).await {
        Err(_) => None, // TLS 1.2 shape: the handshake itself fails.
        Ok(mut tls) => {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let _ = tls
                .write_all(b"GET / HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n")
                .await;
            let mut resp = Vec::new();
            let _ = tls.read_to_end(&mut resp).await;
            Some(resp)
        }
    };
    assert!(
        served
            .as_ref()
            .is_none_or(|resp| !String::from_utf8_lossy(resp).starts_with("HTTP/1.1")),
        "untrusted client cert must never serve a response"
    );
}

#[tokio::test]
async fn client_ca_listener_serves_anonymous_traffic_when_auth_not_required() {
    // allow_unauthenticated semantics (#124): a terminate listener with
    // a client_ca_file still accepts connections that present NO client
    // certificate — the bundle only adds an optional verification
    // family, it never turns the listener into require-mTLS. On a route
    // that does not require auth, a certificate-less client is served
    // like on any plain terminate listener.
    let dir = temp_dir("mtls-anon");
    let server = write_cert(&dir, "edge.example.com");
    let (client_ca, _client) = client_ca_and_leaf("dwara-test-client-ca", "mtls-acme");
    let ca_path = dir.join("client-ca.pem");
    std::fs::write(&ca_path, client_ca.pem()).unwrap();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let config = dir.join("dwara.yaml");
    std::fs::write(
        &config,
        format!(
            "\
listeners:
  - name: mtls-edge
    address: 127.0.0.1
    port: {port}
    protocol: https
    tls:
      mode: terminate
      cert_file: {}
      key_file: {}
      client_ca_file: {}
routes:
  - name: catch
    service: local
    match:
      path:
        type: regex
        value: /.*
    action:
      type: respond
      status: 200
      body: hello-anon
services:
  - name: local
    upstream: local-up
upstreams:
  - name: local-up
    endpoints:
      - address: 127.0.0.1
        port: 9
consumers:
  - name: acme
    credentials:
      - type: mtls
        subject: mtls-acme
",
            server.cert.display(),
            server.key.display(),
            ca_path.display()
        ),
    )
    .unwrap();

    let _server = start_server(&config);
    wait_tcp(&addr, Instant::now() + Duration::from_secs(30));

    // No client certificate at all: handshake completes, request is
    // served anonymously (the route does not require auth).
    let plain = tls_connector("edge.example.com", &["http/1.1"]);
    let resp = tls_get_retrying_reset(&addr, &plain).await;
    let text = String::from_utf8_lossy(&resp);
    assert!(text.starts_with("HTTP/1.1 200"), "resp: {text}");
    assert!(text.ends_with("hello-anon"), "resp: {text}");
}

/// Minimal TLS backend that DELAYS its response by `delay` before
/// answering HTTP/1.1 with a fixed body. Used by the passthrough drain
/// test (#175): the delay keeps the splice in-flight when SIGTERM
/// arrives, so the drain must keep the relay alive long enough for the
/// backend's response to flow back through the gateway to the client.
async fn spawn_delayed_backend(
    cert: CertFiles,
    delay: Duration,
) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let certs = <rustls::pki_types::CertificateDer<'_> as rustls::pki_types::pem::PemObject>::pem_file_iter(&cert.cert)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key =
        <rustls::pki_types::PrivateKeyDer<'_> as rustls::pki_types::pem::PemObject>::pem_file_iter(
            &cert.key,
        )
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let provider = Arc::new(aws_lc_rs::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => return,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    // Read the request (drain the client's HTTP head).
                    let mut buf = [0u8; 256];
                    let _ = tokio::io::AsyncReadExt::read(&mut tls, &mut buf).await;
                    // Hold the connection open past the SIGTERM so the
                    // splice is in-flight when the drain begins.
                    tokio::time::sleep(delay).await;
                    let _ = tls.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\ndrained",
                    )
                    .await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    (port, task)
}

fn read_stdout(stdout: &mut Option<std::process::ChildStdout>) -> String {
    let mut out = String::new();
    if let Some(mut s) = stdout.take() {
        let _ = std::io::Read::read_to_string(&mut s, &mut out);
    }
    out
}

/// #175 (REL-04): an in-flight passthrough splice must be drained (not
/// dropped) on SIGTERM. The backend delays its response past the
/// SIGTERM; the gateway's splice drain keeps the relay alive so the
/// response still arrives at the client and the process exits 0.
#[tokio::test]
async fn passthrough_splice_drains_on_sigterm() {
    let dir = temp_dir("drain");
    let cert = write_cert(&dir, "back.example.com");
    let (back_port, _backend) = spawn_delayed_backend(cert, Duration::from_millis(400)).await;

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let config = dir.join("dwara.yaml");
    std::fs::write(
        &config,
        format!(
            "\
listeners:
  - name: pass-drain
    address: 127.0.0.1
    port: {port}
    protocol: https
    tls:
      mode: passthrough
      sni_routes:
        - server_names: [back.example.com]
          upstream: backends
upstreams:
  - name: backends
    endpoints:
      - address: 127.0.0.1
        port: {back_port}
allow_empty_routes: true
"
        ),
    )
    .unwrap();
    // Generous drain budget so the 400 ms backend delay is well inside
    // the window; the test asserts the splice completes (not that the
    // timeout fires). DWARA_ACCESS_LOG_SAMPLE=0 keeps the piped stdout
    // from filling its kernel buffer mid-test (the JSON subscriber
    // writes to stdout).
    let (mut guard, mut stdout) = start_server_captured_with_env(
        &config,
        &[
            ("DWARA_SHUTDOWN_TIMEOUT_SECS", "5"),
            ("DWARA_ACCESS_LOG_SAMPLE", "0.0"),
        ],
    );
    wait_tcp(&addr, Instant::now() + Duration::from_secs(30));

    // Establish the passthrough splice and write the request so the
    // backend is mid-response when SIGTERM arrives.
    let conn = tls_connector("back.example.com", &["http/1.1"]);
    let tcp = TcpStream::connect(&addr).await.expect("tcp connect");
    let name = rustls::pki_types::ServerName::try_from("back.example.com".to_string())
        .unwrap()
        .to_owned();
    let mut tls = conn.connect(name, tcp).await.expect("tls handshake");
    tls.write_all(b"GET / HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    // SIGTERM while the splice is in-flight (the backend has not yet
    // responded).
    let pid = guard.0.id();
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .expect("kill -TERM");
    assert!(status.success(), "kill -TERM failed");

    // The response must still arrive through the drained splice.
    let mut resp = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut resp)).await;
    assert!(
        read.is_ok(),
        "passthrough response did not arrive within 10s (splice was dropped, not drained)"
    );
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.ends_with("drained"),
        "expected drained passthrough response, got: {text}"
    );

    // Close the client side so the bidirectional splice completes
    // naturally (copy_bidirectional waits for both directions to EOF;
    // holding the client open would keep the splice alive past the
    // drain budget). The response already arriving proves the relay
    // was kept alive through the SIGTERM.
    drop(tls);

    // The process must exit 0 (clean drain, not a forced exit).
    let exit = wait_child_exit(&mut guard.0, Duration::from_secs(15));
    assert!(exit.success(), "expected clean exit 0, got {exit}");
    let out = read_stdout(&mut stdout);
    assert!(
        out.contains("drained, exiting"),
        "missing drain log in:\n{out}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Start dwara with piped stdout (the JSON subscriber writes to stdout)
/// and extra env (for the drain test).
fn start_server_captured_with_env(
    config_path: &std::path::Path,
    extra_env: &[(&str, &str)],
) -> (ServerGuard, Option<std::process::ChildStdout>) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dwara"));
    cmd.env("DWARA_CONFIG", config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn dwara");
    let stdout = child.stdout.take();
    (ServerGuard(child), stdout)
}

fn wait_child_exit(child: &mut std::process::Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().expect("try_wait failed") {
            Some(status) => return status,
            None if Instant::now() > deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("dwara did not exit within {:?}", timeout)
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// Minimal TLS backend that accepts the connection, drains the client's
/// HTTP head, then HOLDS the connection open for `hold` without ever
/// writing a response or closing. Used by the drain-timeout force-close
/// test (#175): the splice is still in-flight when the shutdown deadline
/// expires, so the process must force-close it and exit on time rather
/// than waiting for the backend.
async fn spawn_holding_backend(
    cert: CertFiles,
    hold: Duration,
) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let certs = <rustls::pki_types::CertificateDer<'_> as rustls::pki_types::pem::PemObject>::pem_file_iter(&cert.cert)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key =
        <rustls::pki_types::PrivateKeyDer<'_> as rustls::pki_types::pem::PemObject>::pem_file_iter(
            &cert.key,
        )
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let provider = Arc::new(aws_lc_rs::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => return,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    // Drain the client's HTTP head so the request is
                    // fully delivered before the hold begins.
                    let mut buf = [0u8; 256];
                    let _ = tokio::io::AsyncReadExt::read(&mut tls, &mut buf).await;
                    // Hold the connection open without responding: the
                    // splice stays in-flight past the shutdown deadline.
                    tokio::time::sleep(hold).await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    (port, task)
}

/// #175 (REL-04): with NO in-flight splices, SIGTERM must drain
/// immediately and exit 0 well inside the shutdown budget. The
/// SpliceDrain counter is zero, so `drain` returns at once and the
/// process exits without waiting for the deadline.
#[tokio::test]
async fn passthrough_shutdown_immediate_with_no_splices() {
    let dir = temp_dir("drain-immediate");
    let cert = write_cert(&dir, "back.example.com");
    // The backend is never contacted (no client connects), but the
    // config still needs a valid upstream target.
    let (back_port, _backend) = spawn_backend(cert, "backend").await;

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let config = dir.join("dwara.yaml");
    std::fs::write(
        &config,
        format!(
            "\
listeners:
  - name: pass-immediate
    address: 127.0.0.1
    port: {port}
    protocol: https
    tls:
      mode: passthrough
      sni_routes:
        - server_names: [back.example.com]
          upstream: backends
upstreams:
  - name: backends
    endpoints:
      - address: 127.0.0.1
        port: {back_port}
allow_empty_routes: true
"
        ),
    )
    .unwrap();
    // Generous budget so the test proves the drain does NOT wait for
    // it: with zero in-flight splices the exit must be near-instant.
    let (mut guard, mut stdout) = start_server_captured_with_env(
        &config,
        &[
            ("DWARA_SHUTDOWN_TIMEOUT_SECS", "30"),
            ("DWARA_ACCESS_LOG_SAMPLE", "0.0"),
        ],
    );
    wait_tcp(&addr, Instant::now() + Duration::from_secs(30));

    // No connection is established: the splice tracker is empty.
    let pid = guard.0.id();
    let start = Instant::now();
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .expect("kill -TERM");
    assert!(status.success(), "kill -TERM failed");

    // Must exit 0 quickly -- well under the 30s budget. A 5s ceiling is
    // generous for backlog flush + drain on a loaded CI box while still
    // proving the drain did not wait for the deadline.
    let exit = wait_child_exit(&mut guard.0, Duration::from_secs(5));
    assert!(exit.success(), "expected clean exit 0, got {exit}");
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "shutdown took {:?} with no in-flight splices (drain waited for the deadline)",
        start.elapsed()
    );
    let out = read_stdout(&mut stdout);
    assert!(
        out.contains("drained, exiting"),
        "missing drain log in:\n{out}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// #175 (REL-04): when the shutdown deadline expires with an in-flight
/// splice that never completes, the process must force-close it and
/// exit on time (not hang waiting for the backend). The holding backend
/// keeps the splice alive past the deadline; the drain budget is small
/// so the force-close happens promptly.
#[tokio::test]
async fn passthrough_splice_drain_timeout_force_closes() {
    let dir = temp_dir("drain-timeout");
    let cert = write_cert(&dir, "back.example.com");
    // Hold the connection far longer than the shutdown budget so the
    // splice is provably still in-flight when the deadline expires.
    let (back_port, _backend) = spawn_holding_backend(cert, Duration::from_secs(60)).await;

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let config = dir.join("dwara.yaml");
    std::fs::write(
        &config,
        format!(
            "\
listeners:
  - name: pass-timeout
    address: 127.0.0.1
    port: {port}
    protocol: https
    tls:
      mode: passthrough
      sni_routes:
        - server_names: [back.example.com]
          upstream: backends
upstreams:
  - name: backends
    endpoints:
      - address: 127.0.0.1
        port: {back_port}
allow_empty_routes: true
"
        ),
    )
    .unwrap();
    // Small drain budget: the splice cannot complete in 2s (the
    // backend holds for 60s), so the deadline must fire and force-close.
    // stdout is not read here: the force-close log at the exact deadline
    // is a select! race (see the assertion rationale below), so the
    // reliable signal is exit timing + client read termination.
    let (mut guard, _stdout) = start_server_captured_with_env(
        &config,
        &[
            ("DWARA_SHUTDOWN_TIMEOUT_SECS", "2"),
            ("DWARA_ACCESS_LOG_SAMPLE", "0.0"),
        ],
    );
    wait_tcp(&addr, Instant::now() + Duration::from_secs(30));

    // Establish the passthrough splice and deliver the request so the
    // backend is in its hold loop when SIGTERM arrives.
    let conn = tls_connector("back.example.com", &["http/1.1"]);
    let tcp = TcpStream::connect(&addr).await.expect("tcp connect");
    let name = rustls::pki_types::ServerName::try_from("back.example.com".to_string())
        .unwrap()
        .to_owned();
    let mut tls = conn.connect(name, tcp).await.expect("tls handshake");
    tls.write_all(b"GET / HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    // SIGTERM while the splice is in-flight (backend is holding).
    let pid = guard.0.id();
    let start = Instant::now();
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .expect("kill -TERM");
    assert!(status.success(), "kill -TERM failed");

    // The process must exit on time (force-close at the 2s deadline,
    // not hang for the backend's 60s hold). A 10s ceiling covers the
    // backlog flush + 2s drain + margin on a loaded box. The reliable
    // signal is the EXIT TIMING: the splice never completes (the
    // backend holds for 60s), so the process must exit at the ~2s
    // deadline, not before (which would mean the splice drained) and
    // not after (which would mean the drain hung). The "forcing exit"
    // vs "drained, exiting" log at the exact deadline is a select!
    // race (both branches fire at the deadline) and is NOT a reliable
    // assertion, so the test relies on timing + the client read
    // terminating + no response body.
    let exit = wait_child_exit(&mut guard.0, Duration::from_secs(10));
    assert!(
        exit.success(),
        "expected exit 0 after force-close, got {exit}"
    );
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(8),
        "shutdown took {elapsed:?}; the drain deadline did not force-close the in-flight splice"
    );
    assert!(
        elapsed >= Duration::from_millis(1500),
        "shutdown took {elapsed:?}; the in-flight splice was drained before the 2s deadline (force-close path not exercised)"
    );

    // The client side of the force-closed splice must terminate: the
    // read returns (with an error/empty) rather than blocking for the
    // backend's 60s hold.
    let mut resp = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut resp)).await;
    assert!(
        read.is_ok(),
        "force-closed splice should terminate the client read within 5s"
    );
    // No response body was ever written by the holding backend.
    assert!(
        !String::from_utf8_lossy(&resp).contains("HTTP/1.1 200"),
        "force-close must not deliver the held-back response: {resp:?}"
    );
    drop(tls);
    std::fs::remove_dir_all(&dir).ok();
}

/// #175 (REL-04): several concurrent in-flight passthrough splices must
/// ALL drain within the shutdown budget. Each delayed backend responds
/// after the SIGTERM; the process-wide SpliceDrain counter tracks every
/// splice and the drain waits for all of them before exiting 0.
#[tokio::test]
async fn passthrough_multiple_splices_all_drain() {
    let dir = temp_dir("drain-multi");
    let cert = write_cert(&dir, "back.example.com");
    // One shared delayed backend serves every splice; each connection
    // is handled in its own task, so all splices are in-flight at once.
    let (back_port, _backend) = spawn_delayed_backend(cert, Duration::from_millis(400)).await;

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let config = dir.join("dwara.yaml");
    std::fs::write(
        &config,
        format!(
            "\
listeners:
  - name: pass-multi
    address: 127.0.0.1
    port: {port}
    protocol: https
    tls:
      mode: passthrough
      sni_routes:
        - server_names: [back.example.com]
          upstream: backends
upstreams:
  - name: backends
    endpoints:
      - address: 127.0.0.1
        port: {back_port}
allow_empty_routes: true
"
        ),
    )
    .unwrap();
    let (mut guard, mut stdout) = start_server_captured_with_env(
        &config,
        &[
            ("DWARA_SHUTDOWN_TIMEOUT_SECS", "5"),
            ("DWARA_ACCESS_LOG_SAMPLE", "0.0"),
        ],
    );
    wait_tcp(&addr, Instant::now() + Duration::from_secs(30));

    // Open N concurrent passthrough splices and deliver each request so
    // all are in-flight when SIGTERM arrives.
    const N: usize = 4;
    let conn = tls_connector("back.example.com", &["http/1.1"]);
    let mut streams = Vec::with_capacity(N);
    for _ in 0..N {
        let tcp = TcpStream::connect(&addr).await.expect("tcp connect");
        let name = rustls::pki_types::ServerName::try_from("back.example.com".to_string())
            .unwrap()
            .to_owned();
        let mut tls = conn.connect(name, tcp).await.expect("tls handshake");
        tls.write_all(b"GET / HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        streams.push(tls);
    }

    // SIGTERM while every splice is in-flight (backends are mid-delay).
    let pid = guard.0.id();
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .expect("kill -TERM");
    assert!(status.success(), "kill -TERM failed");

    // Every drained splice must deliver its response through the relay.
    let mut all_ok = true;
    for mut tls in streams {
        let mut resp = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut resp)).await;
        if read.is_err() || !String::from_utf8_lossy(&resp).ends_with("drained") {
            all_ok = false;
        }
        drop(tls);
    }
    assert!(
        all_ok,
        "at least one of {N} concurrent splices was dropped, not drained"
    );

    // The process must exit 0 (all splices drained within the budget).
    let exit = wait_child_exit(&mut guard.0, Duration::from_secs(15));
    assert!(exit.success(), "expected clean exit 0, got {exit}");
    let out = read_stdout(&mut stdout);
    assert!(
        out.contains("drained, exiting"),
        "missing drain log in:\n{out}"
    );
    std::fs::remove_dir_all(&dir).ok();
}
