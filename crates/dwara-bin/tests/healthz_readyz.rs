//! Integration tests for the reserved gateway endpoints (DW-013):
//! `/healthz` and `/readyz` are served on every listener before route
//! resolution. The config here installs a catch-all route that would
//! otherwise answer every path, proving the reserved paths shadow it —
//! through a cleartext listener AND a TLS-terminated listener.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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
    // #128: counter suffix — clock nanos collide across parallel threads.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("dwara-dw013-{}-{n}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_config(dir: &std::path::Path, port: u16, tls: Option<(String, String)>) -> PathBuf {
    let tls_block = tls
        .map(|(cert, key)| {
            format!(
                "    protocol: https\n    tls:\n      mode: terminate\n      \
                 cert_file: {cert}\n      key_file: {key}\n"
            )
        })
        .unwrap_or_default();
    let config = dir.join("dwara.yaml");
    std::fs::write(
        &config,
        format!(
            "listeners:\n  - name: edge\n    address: 127.0.0.1\n    port: {port}\n\
             {tls_block}\
             routes:\n  - name: catch\n    service: local\n    match:\n      path:\n        \
             type: regex\n        value: /.*\n    action:\n      type: respond\n      \
             status: 418\n      body: shadowed\nservices:\n  - name: local\n    \
             upstream: local-up\nupstreams:\n  - name: local-up\n    endpoints:\n      \
             - address: 127.0.0.1\n        port: 9\n"
        ),
    )
    .unwrap();
    config
}

fn start_server(config: &std::path::Path) -> ServerGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_dwara"))
        .env("DWARA_CONFIG", config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dwara");
    ServerGuard(child)
}

fn wait_tcp(addr: &str, deadline: Instant) {
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("dwara did not listen on {addr}");
}

/// One GET attempt; a transport failure (connect, write, or a reset
/// racing the read — the #128 class) yields the empty string so the
/// retry wrapper can distinguish "nothing arrived" from a real answer.
fn http_get_once(addr: &str, path: &str) -> String {
    let Ok(mut stream) = TcpStream::connect(addr) else {
        return String::new();
    };
    if stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .is_err()
    {
        return String::new();
    }
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// Connect + GET, retrying the WHOLE exchange while ZERO response bytes
/// have arrived (#128 item-H class, the same tolerance as
/// tls_listener::tls_get_retrying_reset): under parallel load the
/// kernel's FIN-to-RST replacement can discard the in-flight answer
/// before any byte lands. Once a byte has arrived the result is final —
/// no partial-data truncation is ever masked. Every caller of this
/// helper asserts on response CONTENT, so an exhausted 10 s budget with
/// zero bytes is a failure, not a verdict.
fn http_get(addr: &str, path: &str) -> String {
    let started = Instant::now();
    loop {
        let response = http_get_once(addr, path);
        if !response.is_empty() {
            return response;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "no response bytes within the 10s retry budget (repeated resets or a dead listener)"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn healthz_and_readyz_served_on_cleartext_listener_and_shadow_routes() {
    let dir = temp_dir("plain");
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let config = write_config(&dir, port, None);
    let _server = start_server(&config);
    wait_tcp(&addr, Instant::now() + Duration::from_secs(10));

    let healthz = http_get(&addr, "/healthz");
    assert!(
        healthz.starts_with("HTTP/1.1 200"),
        "healthz must be 200: {healthz}"
    );
    // DW-021: reserved bodies are aligned to the JSON error envelope.
    assert!(
        healthz.contains("\"code\":\"ok\""),
        "healthz body must carry code 'ok': {healthz}"
    );

    let readyz = http_get(&addr, "/readyz");
    assert!(
        readyz.starts_with("HTTP/1.1 200"),
        "readyz must be 200 after the startup publish: {readyz}"
    );
    assert!(readyz.contains("\"code\":\"ready\""), "{readyz}");

    // The catch-all route still owns every other path (418 + body).
    let other = http_get(&addr, "/anything");
    assert!(other.starts_with("HTTP/1.1 418"), "{other}");
    assert!(other.ends_with("shadowed"), "{other}");
    std::fs::remove_file(&config).ok();
}

#[test]
fn healthz_and_readyz_served_through_tls_terminated_listener() {
    let dir = temp_dir("tls");
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let cert_path = dir.join("localhost.crt.pem");
    let key_path = dir.join("localhost.key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let config = write_config(
        &dir,
        port,
        Some((
            cert_path.display().to_string(),
            key_path.display().to_string(),
        )),
    );
    let _server = start_server(&config);
    wait_tcp(&addr, Instant::now() + Duration::from_secs(10));

    // Minimal synchronous TLS 1.2/1.3 client is out of scope here; instead
    // drive the request with the same rustls stack the other suites use.
    // (A blocking wrapper around the async connector keeps this test in
    // the sync harness style of the file.)
    let resp = tls_http_get(&addr, "/healthz");
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.contains("\"code\":\"ok\""), "{resp}");
    let resp = tls_http_get(&addr, "/readyz");
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.contains("\"code\":\"ready\""), "{resp}");
    std::fs::remove_file(&config).ok();
}

/// One HTTPS GET attempt using a dedicated tokio runtime; the peer
/// certificate is self-signed, so verification is disabled (tests only
/// assert status and body, mirroring tls_listener.rs's NoVerify
/// approach). Transport failures yield the empty string for the retry
/// wrapper (#128 class: a reset racing the exchange discards the answer
/// before any byte lands).
fn tls_http_get_once(addr: &str, path: &str) -> String {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        use tokio_rustls::rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        use tokio_rustls::rustls::crypto::aws_lc_rs;
        use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
        #[derive(Debug)]
        struct NoVerify;
        impl ServerCertVerifier for NoVerify {
            fn verify_server_cert(
                &self,
                _e: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
                _i: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
                _s: &tokio_rustls::rustls::pki_types::ServerName<'_>,
                _o: &[u8],
                _n: tokio_rustls::rustls::pki_types::UnixTime,
            ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _m: &[u8],
                _c: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
                _d: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _m: &[u8],
                _c: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
                _d: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
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
        let provider = std::sync::Arc::new(aws_lc_rs::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
        let tcp = match tokio::net::TcpStream::connect(addr).await {
            Ok(tcp) => tcp,
            Err(_) => return String::new(),
        };
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost".to_string())
            .unwrap()
            .to_owned();
        let mut tls = match connector.connect(name, tcp).await {
            Ok(tls) => tls,
            Err(_) => return String::new(),
        };
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        if tls
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .is_err()
        {
            return String::new();
        }
        let mut buf = Vec::new();
        let _ = tls.read_to_end(&mut buf).await;
        String::from_utf8_lossy(&buf).into_owned()
    })
}

/// Connect + HTTPS GET, retrying the WHOLE exchange while ZERO response
/// bytes have arrived (#128 item-H class; the same tolerance as
/// tls_listener's tls_get_retrying_reset: under parallel load the
/// kernel's FIN-to-RST replacement can discard the in-flight answer
/// before any byte lands). Once a byte has arrived the result is final —
/// no partial-data truncation is ever masked. Callers assert on response
/// CONTENT, so an exhausted 10 s budget with zero bytes is a failure.
fn tls_http_get(addr: &str, path: &str) -> String {
    let started = Instant::now();
    loop {
        let response = tls_http_get_once(addr, path);
        if !response.is_empty() {
            return response;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "no response bytes within the 10s retry budget (repeated resets or a dead listener)"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}
