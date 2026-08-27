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
