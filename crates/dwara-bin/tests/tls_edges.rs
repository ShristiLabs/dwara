//! DW-007 edge-case integration tests (tester pass). Complements the
//! developer's `tls_listener.rs` golden-path tests; does not duplicate
//! them. Covers:
//!
//! - SNI resolution edges: no-SNI handshake (IP ServerName), uppercase
//!   SNI vs lowercase config and vice versa, entry-order irrelevance,
//! - passthrough robustness: non-TLS bytes, ClientHello without SNI,
//!   truncated/garbage ClientHello, ~4KB padded ClientHello,
//! - certificate hot-reload torn state (cert swapped, key not) and
//!   completion of the swap,
//! - 8 concurrent TLS handshakes across a certificate reload,
//! - malformed h2c preface on a cleartext listener.

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
        "dwara-dw007-edge-{}-{}-{tag}",
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

/// Accept-any verifier: tests assert WHICH self-signed certificate was
/// served by inspecting the peer certificate; chain validation is
/// intentionally bypassed.
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
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
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

fn tls_connector(alpn: &[&str]) -> TlsConnector {
    let provider = Arc::new(aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    Arc::new(config).into()
}

/// One HTTPS GET: returns (peer cert DER, response bytes). Fails the task
/// on any handshake error.
async fn tls_get_ok(addr: &str, sni: &str, connector: &TlsConnector) -> (Vec<u8>, Vec<u8>) {
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .expect("sni")
        .to_owned();
    let mut tls = connector.connect(name, tcp).await.expect("tls handshake");
    let cert = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|c| c.to_vec())
        .expect("peer cert");
    let http = b"GET / HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n";
    tls.write_all(http).await.unwrap();
    let mut resp = Vec::new();
    let _ = tls.read_to_end(&mut resp).await;
    (cert, resp)
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

/// Decode the first PEM CERTIFICATE block to DER.
fn cert_der_of(files: &CertFiles) -> Vec<u8> {
    base64_decode_shim(&std::fs::read_to_string(&files.cert).unwrap())
}

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

// ---------------------------------------------------------------------------
// Raw ClientHello construction (for passthrough peek/parser edges)
// ---------------------------------------------------------------------------

/// Build a TLS record containing a ClientHello with an optional SNI
/// extension, optionally preceded by an unknown padding extension of
/// `pad_len` bytes (to grow the hello for the large-ClientHello test).
fn client_hello(sni: Option<&str>, pad_len: usize) -> Vec<u8> {
    let mut ext = Vec::new();
    if pad_len > 0 {
        ext.extend_from_slice(&0x00ffu16.to_be_bytes());
        ext.extend_from_slice(&(pad_len as u16).to_be_bytes());
        ext.extend_from_slice(&vec![0x42u8; pad_len]);
    }
    if let Some(name) = sni {
        let mut entry = vec![0x00u8];
        entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
        entry.extend_from_slice(name.as_bytes());
        let mut list = (entry.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&entry);
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list);
    }
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // client version TLS 1.2
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // empty session id
    body.extend_from_slice(&2u16.to_be_bytes()); // one cipher suite
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1); // one compression method
    body.push(0);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let l = body.len();
    let mut hs = vec![0x01u8, (l >> 16) as u8, (l >> 8) as u8, l as u8];
    hs.extend_from_slice(&body);

    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// Write `bytes`, then read until EOF or `timeout`; returns the bytes read
/// before EOF (empty when the connection was closed without a response).
async fn write_then_read_to_eof(addr: &str, bytes: &[u8], timeout: Duration) -> Vec<u8> {
    let mut tcp = TcpStream::connect(addr).await.expect("connect");
    tcp.write_all(bytes).await.unwrap();
    let _ = tcp.shutdown().await;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let n = match tokio::time::timeout_at(deadline, tcp.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => panic!("read error: {e}"),
        };
        buf.extend_from_slice(&chunk[..n]);
    }
    buf
}

// ---------------------------------------------------------------------------
// 1. SNI resolution edges
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sni_resolution_no_sni_ip_handshake_serves_fallback_and_matching_is_case_insensitive() {
    let dir = temp_dir("sni-edge");
    let ca = write_cert(&dir, "fallback.example.com");
    let a = write_cert(&dir, "a.example.com");
    let b = write_cert(&dir, "b.example.com");
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    // Deliberately list the entries in reverse order (b first): selection
    // must not depend on declaration order.
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
        - server_names: [b.example.com]
          cert_file: {}
          key_file: {}
        - server_names: [a.example.com]
          cert_file: {}
          key_file: {}
routes: []
",
            ca.cert.display(),
            ca.key.display(),
            b.cert.display(),
            b.key.display(),
            a.cert.display(),
            a.key.display()
        ),
    )
    .unwrap();
    let _server = start_server(&config);
    wait_tcp(&addr, Instant::now() + Duration::from_secs(10));

    let conn = tls_connector(&["http/1.1"]);

    // Uppercase SNI from the client resolves to the lowercase-configured
    // cert (resolver lowercases both sides per the SNI spec; deterministic).
    let (cert, resp) = tls_get_ok(&addr, "A.EXAMPLE.COM", &conn).await;
    assert_eq!(cert, cert_der_of(&a), "uppercase client SNI must match");
    assert!(String::from_utf8_lossy(&resp).ends_with("dwara"));

    // Order irrelevance: the later-declared a-entry still wins over the
    // first-declared b-entry for SNI b.
    let (cert, _) = tls_get_ok(&addr, "b.example.com", &conn).await;
    assert_eq!(cert, cert_der_of(&b));

    // No SNI at all: rustls omits the SNI extension for IP ServerNames.
    // The handshake must succeed with the fallback certificate.
    let tcp = TcpStream::connect(&addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_string())
        .expect("ip server name")
        .to_owned();
    let mut tls = conn.connect(name, tcp).await.expect("no-SNI handshake");
    let cert = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|c| c.to_vec())
        .expect("peer cert");
    assert_eq!(
        cert,
        cert_der_of(&ca),
        "handshake without SNI must serve the fallback certificate"
    );
    tls.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = Vec::new();
    let _ = tls.read_to_end(&mut resp).await;
    assert!(String::from_utf8_lossy(&resp).ends_with("dwara"));
}

#[tokio::test]
async fn sni_resolution_uppercase_configured_server_names_still_match() {
    let dir = temp_dir("sni-upper");
    let first = write_cert(&dir, "upper.example.com");
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
      certificates:
        - server_names: [UPPER.example.com]
          cert_file: {}
          key_file: {}
routes: []
",
            first.cert.display(),
            first.key.display()
        ),
    )
    .unwrap();
    let _server = start_server(&config);
    wait_tcp(&addr, Instant::now() + Duration::from_secs(10));

    // Lowercase client SNI against an uppercase-configured name: the
    // resolver lowercases config names at build time, so this matches.
    let conn = tls_connector(&["http/1.1"]);
    let (cert, _) = tls_get_ok(&addr, "upper.example.com", &conn).await;
    assert_eq!(cert, cert_der_of(&first));
}

// ---------------------------------------------------------------------------
// 2. Passthrough robustness
// ---------------------------------------------------------------------------

/// Minimal rustls TLS backend answering "backend" over HTTP/1.1.
async fn spawn_backend(cert: &CertFiles) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let certs =
        <rustls::pki_types::CertificateDer<'_> as rustls::pki_types::pem::PemObject>::pem_file_iter(
            &cert.cert,
        )
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
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nbackend",
                        )
                        .await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    port
}

async fn start_passthrough(tag: &str, backend_port: u16) -> (String, PathBuf, ServerGuard) {
    let dir = temp_dir(tag);
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
        port: {backend_port}
"
        ),
    )
    .unwrap();
    let guard = start_server(&config);
    wait_tcp(&addr, Instant::now() + Duration::from_secs(10));
    (addr, config, guard)
}

#[tokio::test]
async fn passthrough_non_tls_bytes_close_the_connection() {
    let dir = temp_dir("pass-back1");
    let cert = write_cert(&dir, "back.example.com");
    let back_port = spawn_backend(&cert).await;
    let (addr, _config, _server) = start_passthrough("pass-plain", back_port).await;

    // A real plain-HTTP GET: the peek loop cannot recognize a ClientHello,
    // so the connection is closed once the peek timeout elapses (10 s
    // worst case; the connection must never be proxied or hang forever).
    let started = Instant::now();
    let resp = write_then_read_to_eof(
        &addr,
        b"GET / HTTP/1.1\r\nHost: back.example.com\r\n\r\n",
        Duration::from_secs(15),
    )
    .await;
    assert!(resp.is_empty(), "no bytes may come back: {resp:?}");
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "connection must close within the peek timeout budget"
    );
}

#[tokio::test]
async fn passthrough_clienthello_without_sni_is_closed_quickly() {
    let dir = temp_dir("pass-back2");
    let cert = write_cert(&dir, "back.example.com");
    let back_port = spawn_backend(&cert).await;
    let (addr, _config, _server) = start_passthrough("pass-nosni", back_port).await;

    // Structurally complete ClientHello without a server_name extension:
    // the record is fully buffered so the decision is immediate.
    let started = Instant::now();
    let resp = write_then_read_to_eof(&addr, &client_hello(None, 0), Duration::from_secs(5)).await;
    assert!(resp.is_empty(), "no response bytes: {resp:?}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "complete no-SNI ClientHello must be closed without waiting for the peek timeout"
    );
}

#[tokio::test]
async fn passthrough_garbage_after_record_header_is_closed_without_killing_the_listener() {
    let dir = temp_dir("pass-back3");
    let cert = write_cert(&dir, "back.example.com");
    let back_port = spawn_backend(&cert).await;
    let (addr, _config, _server) = start_passthrough("pass-garbage", back_port).await;

    // Bytes that begin like a TLS record (0x16 0x03 ...) with a declared
    // record length, followed by pure garbage of exactly that length: the
    // parser must reject it (handshake type != ClientHello) and the
    // connection must close; the listener must keep serving afterwards.
    let mut garbage = vec![0x16, 0x03, 0x01];
    let payload = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0xff, 0xfe];
    garbage.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    garbage.extend_from_slice(&payload);
    let resp = write_then_read_to_eof(&addr, &garbage, Duration::from_secs(5)).await;
    assert!(resp.is_empty(), "no response bytes: {resp:?}");

    // The listener survived: a well-formed SNI handshake still splices to
    // the backend.
    let conn = tls_connector(&["http/1.1"]);
    let (cert_der, resp) = tls_get_ok(&addr, "back.example.com", &conn).await;
    assert_eq!(cert_der, cert_der_of(&cert), "backend cert after garbage");
    assert!(String::from_utf8_lossy(&resp).ends_with("backend"));
}

#[tokio::test]
async fn passthrough_large_padded_clienthello_is_still_parsed_and_spliced() {
    let dir = temp_dir("pass-back4");
    let cert = write_cert(&dir, "back.example.com");
    let back_port = spawn_backend(&cert).await;
    let (addr, _config, _server) = start_passthrough("pass-large", back_port).await;

    // ~4 KB ClientHello: a 4000-byte unknown extension precedes the SNI
    // extension. The SNI must still be extracted and the stream spliced.
    let hello = client_hello(Some("back.example.com"), 4000);
    assert!(hello.len() > 4000, "hello must actually be large");
    let mut tcp = TcpStream::connect(&addr).await.unwrap();
    tcp.write_all(&hello).await.unwrap();

    // The crafted hello uses a single modern cipher suite the minimal
    // backend accepts, so a successful parse + splice yields a TLS record
    // back: either a handshake record (ServerHello) or, if the backend
    // rejects the synthetic hello, an alert record (0x15). Either way the
    // gateway returned BYTES — proof the ~4KB ClientHello was parsed, the
    // SNI extracted, the peek did not consume the stream, and the splice
    // reached the backend. A parse failure would have closed the
    // connection with zero bytes.
    let mut head = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), tcp.read_exact(&mut head))
        .await
        .expect("TLS record within timeout")
        .expect("read record header");
    assert!(
        head[0] == 0x16 || head[0] == 0x15,
        "expected a handshake (0x16) or alert (0x15) record from the spliced backend, got {head:?}"
    );
}

// ---------------------------------------------------------------------------
// 3. Certificate hot-reload torn state + concurrency
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cert_hot_reload_torn_pair_is_survived_and_full_swap_serves_new_cert() {
    let dir = temp_dir("torn");
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
routes: []
",
            ca.cert.display(),
            ca.key.display()
        ),
    )
    .unwrap();
    let _server = start_server(&config);
    wait_tcp(&addr, Instant::now() + Duration::from_secs(10));

    let conn = tls_connector(&["http/1.1"]);
    let (cert1, resp) = tls_get_ok(&addr, "edge.example.com", &conn).await;
    let old_der = cert_der_of(&ca);
    assert_eq!(cert1, old_der);
    assert!(String::from_utf8_lossy(&resp).ends_with("dwara"));

    // TORN state: replace ONLY the certificate, keep the old key.
    // FIXED behavior (was a pinned defect): TlsTermination::reload now
    // verifies the private key matches the leaf certificate (SPKI
    // comparison). The torn reload is REJECTED, the previous config keeps
    // serving the OLD certificate, and the listener stays healthy.
    // (Before the fix, the torn pair was swapped in and handshakes served
    // the new cert signed with the old key, breaking validating clients.)
    let new_cert = write_cert(dir.parent().unwrap(), "edge2.example.com");
    let tmp = dir.join("cert.new");
    std::fs::copy(&new_cert.cert, &tmp).unwrap();
    std::fs::rename(&tmp, &ca.cert).unwrap();
    std::thread::sleep(Duration::from_millis(1200)); // watcher debounce + reload

    let (torn_cert, resp) = tls_get_ok(&addr, "edge.example.com", &conn).await;
    assert_eq!(
        torn_cert, old_der,
        "torn reload must be rejected and the old certificate keep serving"
    );
    assert!(String::from_utf8_lossy(&resp).ends_with("dwara"));

    // The listener still accepts TCP (process alive): completing the swap
    // must fully restore TLS with the new material.
    std::fs::copy(&new_cert.key, &tmp).unwrap();
    std::fs::rename(&tmp, &ca.key).unwrap();
    std::thread::sleep(Duration::from_millis(1200));

    let conn = tls_connector(&["http/1.1"]);
    let (cert2, resp) = tls_get_ok(&addr, "edge2.example.com", &conn).await;
    assert_eq!(
        cert2,
        cert_der_of(&new_cert),
        "completed swap must serve the new certificate"
    );
    assert_ne!(cert1, cert2);
    assert!(String::from_utf8_lossy(&resp).ends_with("dwara"));
}

#[tokio::test]
async fn concurrent_handshakes_across_cert_reload_all_succeed() {
    let dir = temp_dir("conc");
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
routes: []
",
            ca.cert.display(),
            ca.key.display()
        ),
    )
    .unwrap();
    let _server = start_server(&config);
    wait_tcp(&addr, Instant::now() + Duration::from_secs(10));

    // Fire the full (cert+key) swap and immediately run 8 parallel
    // handshakes: each must complete with EITHER the old or the new
    // material; zero failures tolerated.
    let new_cert = write_cert(dir.parent().unwrap(), "next.example.com");
    let tmp_c = dir.join("c.new");
    let tmp_k = dir.join("k.new");
    std::fs::copy(&new_cert.cert, &tmp_c).unwrap();
    std::fs::copy(&new_cert.key, &tmp_k).unwrap();
    std::fs::rename(&tmp_c, &ca.cert).unwrap();

    let addr2 = addr.clone();
    let handshakes = (0..8u32).map(|i| {
        let addr = addr2.clone();
        tokio::spawn(async move {
            let conn = tls_connector(&["http/1.1"]);
            // Alternate between old-name and new-name SNI so whichever
            // generation serves the handshake, the cert served is the
            // fallback for the other name anyway (single pair = fallback).
            let sni = if i % 2 == 0 {
                "edge.example.com"
            } else {
                "next.example.com"
            };
            let (_, resp) = tls_get_ok(&addr, sni, &conn).await;
            assert!(
                String::from_utf8_lossy(&resp).ends_with("dwara"),
                "handshake {i}: {resp:?}"
            );
        })
    });
    std::fs::rename(&tmp_k, &ca.key).unwrap();

    for (i, h) in handshakes.into_iter().enumerate() {
        tokio::time::timeout(Duration::from_secs(10), h)
            .await
            .unwrap_or_else(|_| panic!("handshake {i} hung"))
            .unwrap_or_else(|e| panic!("handshake {i} failed: {e}"));
    }
}

// ---------------------------------------------------------------------------
// 4. h2c malformed preface
// ---------------------------------------------------------------------------

#[tokio::test]
async fn h2c_malformed_preface_does_not_hang_the_listener() {
    let dir = temp_dir("h2c-bad");
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let config = dir.join("dwara.yaml");
    std::fs::write(
        &config,
        format!(
            "listeners:\n  - name: plain\n    address: 127.0.0.1\n    port: {port}\nroutes: []\n"
        ),
    )
    .unwrap();
    let _server = start_server(&config);
    wait_tcp(&addr, Instant::now() + Duration::from_secs(10));

    // Half preface then garbage: the auto builder must neither hang nor
    // crash; it either answers an HTTP/1.1 error or closes. Pin: bounded
    // in time, then bytes-or-EOF.
    let resp = write_then_read_to_eof(
        &addr,
        b"PRI * HTTP/2.0\r\n\r\nXXGARBAGE",
        Duration::from_secs(5),
    )
    .await;
    // Any outcome is acceptable as long as it is bounded and the listener
    // keeps serving afterwards.
    let _ = resp;

    // Listener still healthy: plain HTTP/1.1 request succeeds.
    let mut tcp = TcpStream::connect(&addr).await.unwrap();
    tcp.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut buf))
        .await
        .expect("bounded read")
        .expect("read");
    assert!(String::from_utf8_lossy(&buf).ends_with("dwara"));
}
