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
    let dir = std::env::temp_dir().join(format!(
        "dwara-dw007-{}-{}-{tag}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
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
