//! gRPC and WebSocket polish, end to end (DW-039, feature analysis
//! section 4.13): real h2c gRPC traffic through the gateway into a
//! real TLS-h2 upstream double (trailers, grpc-timeout), and real
//! WebSocket upgrades through the gateway into a raw 101 echo double
//! (origin allowlist, post-upgrade frame-rate policing).
//!
//! - a gRPC-style request round-trips: `:path` routing, the spec's
//!   `TE: trailers` forwarded, response trailers (grpc-status)
//!   delivered to the client;
//! - `grpc-timeout` bounds a hanging upstream: the gateway answers
//!   504 with `grpc-status: 4` (DEADLINE_EXCEEDED) inside the budget;
//! - a WebSocket upgrade with a non-allowlisted (or missing) Origin
//!   is denied 403 BEFORE any upstream contact;
//! - an abusive client past `max_frames_per_sec` is closed with the
//!   1008 policy close frame and disconnected — the Done-when pin.
//!
//! Zero new dependencies on either side: the doubles speak the
//! protocols by hand (the TLS-h2 server is hyper's auto builder with
//! h2 ALPN over an rcgen private CA, the WS double is a raw TcpStream
//! speaking the 101 handshake and echoing frames).

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Frame;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Version};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

mod support;

use support::spawn_gateway;

// --- shared TLS CA fixture (the trusted_ca.rs shapes) ------------------------

fn private_ca() -> (
    tempfile::TempDir,
    String,
    rcgen::Certificate,
    rcgen::KeyPair,
) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "dwara-test-grpc-ca");
    let ca = params.self_signed(&ca_key).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, ca.pem()).unwrap();
    (dir, ca_path.display().to_string(), leaf, leaf_key)
}

/// A body that yields one data frame, then a trailer frame carrying
/// `grpc-status: 0` — the minimal gRPC response shape (hand-rolled;
/// no new dependencies).
struct GrpcBody {
    data_sent: bool,
    trailers_sent: bool,
}

impl hyper::body::Body for GrpcBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if !self.data_sent {
            self.data_sent = true;
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(
                b"\x00\x00\x00\x00\x02hi",
            )))));
        }
        if !self.trailers_sent {
            self.trailers_sent = true;
            let mut trailers = hyper::HeaderMap::new();
            trailers.insert("grpc-status", "0".parse().unwrap());
            trailers.insert("grpc-message", "ok".parse().unwrap());
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        false
    }
}

/// A TLS h2 upstream double speaking gRPC: records the request line +
/// TE header, answers 200 + application/grpc + data + trailers. With
/// `hang`, it sleeps past any sane grpc-timeout before answering.
async fn grpc_backend(
    ca_leaf: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
    hang: Duration,
) -> (u16, Arc<Mutex<Vec<String>>>) {
    dwara_core::tls::install_aws_lc_rs_provider();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![ca_leaf.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                ca_key.serialize_der(),
            )),
        )
        .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(tls) = acceptor.accept(stream).await else {
                continue;
            };
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(tls),
                        service_fn(move |req: Request<hyper::body::Incoming>| {
                            let log = Arc::clone(&log);
                            async move {
                                let te = req
                                    .headers()
                                    .get("te")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("(none)")
                                    .to_string();
                                log.lock().unwrap().push(format!(
                                    "{} {} te={}",
                                    req.method(),
                                    req.uri().path(),
                                    te
                                ));
                                if !hang.is_zero() {
                                    tokio::time::sleep(hang).await;
                                }
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(200)
                                        .header("content-type", "application/grpc")
                                        .body(GrpcBody {
                                            data_sent: false,
                                            trailers_sent: false,
                                        })
                                        .unwrap(),
                                )
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    (port, seen)
}

/// An h2c prior-knowledge client (cleartext HTTP/2 to the gateway).
fn grpc_client() -> Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>> {
    Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build_http()
}

/// Gateway YAML with one route to a TLS-h2 upstream.
fn grpc_yaml(ca_file: &str, backend: u16, route_extra: &str, upstream_extra: &str) -> String {
    format!(
        "routes:\n\
         - name: grpc\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /helloworld.\n{route_extra}\
         \x20 action:\n\
         \x20   type: proxy\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 protocol: http2\n{upstream_extra}\
         \x20 trusted_ca_file: {ca_file}\n\
         \x20 endpoints:\n\
         \x20   - address: localhost\n\
         \x20     port: {backend}\n"
    )
}

// --- 1. the gRPC round trip --------------------------------------------------

#[tokio::test]
async fn a_grpc_request_round_trips_with_trailers() {
    let (_dir, ca_pem, leaf, key) = private_ca();
    let (backend, seen) = grpc_backend(&leaf, &key, Duration::ZERO).await;
    let yaml = grpc_yaml(&ca_pem, backend, "", "");
    let dp = support::dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    let client = grpc_client();
    let (mut parts, body) = Request::builder()
        .method("POST")
        .uri(format!("http://127.0.0.1:{gw}/helloworld.Greeter/SayHello"))
        .version(Version::HTTP_2)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("grpc-timeout", "5S")
        .body(Full::<Bytes>::new(Bytes::from_static(
            b"\x00\x00\x00\x00\x00",
        )))
        .unwrap()
        .into_parts();
    parts.headers.remove(hyper::header::HOST);
    let resp = client
        .request(Request::from_parts(parts, body))
        .await
        .expect("gRPC request through the gateway");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/grpc"
    );
    // The trailers (grpc-status) MUST reach the client.
    use http_body_util::BodyExt as _;
    let collected = resp.into_body().collect().await.unwrap();
    let got_trailers = collected.trailers().cloned();
    let data = collected.to_bytes();
    assert!(data.starts_with(&[0, 0, 0, 0]), "gRPC data frame: {data:?}");
    let trailers = got_trailers.expect("trailers arrived");
    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
    assert_eq!(trailers.get("grpc-message").unwrap(), "ok");

    // The upstream saw the :path (gRPC routes by path like any
    // request) and the spec's TE header forwarded intact.
    let logged = seen.lock().unwrap().join("\n");
    assert!(
        logged.contains("POST /helloworld.Greeter/SayHello"),
        "{logged}"
    );
    assert!(logged.contains("te=trailers"), "TE forwarded: {logged}");
}

// --- 2. grpc-timeout bounds a hang --------------------------------------------

#[tokio::test]
async fn grpc_timeout_bounds_a_hanging_upstream() {
    let (_dir, ca_pem, leaf, key) = private_ca();
    let (backend, _seen) = grpc_backend(&leaf, &key, Duration::from_secs(30)).await;
    let yaml = grpc_yaml(&ca_pem, backend, "", "");
    let dp = support::dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    let client = grpc_client();
    let started = Instant::now();
    let (mut parts, body) = Request::builder()
        .method("POST")
        .uri(format!("http://127.0.0.1:{gw}/helloworld.Greeter/SayHello"))
        .version(Version::HTTP_2)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("grpc-timeout", "400m")
        .body(Full::<Bytes>::new(Bytes::from_static(
            b"\x00\x00\x00\x00\x00",
        )))
        .unwrap()
        .into_parts();
    parts.headers.remove(hyper::header::HOST);
    let resp = client
        .request(Request::from_parts(parts, body))
        .await
        .expect("the gateway answers the deadline");

    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(
        resp.headers().get("grpc-status").unwrap(),
        "4",
        "DEADLINE_EXCEEDED in the headers (the trailers-only shape)"
    );
    assert_eq!(
        support::envelope_code(&read_body(resp).await),
        "grpc_deadline_exceeded"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the answer lands inside the budget: {:?}",
        started.elapsed()
    );
}

async fn read_body(resp: Response<hyper::body::Incoming>) -> Bytes {
    use http_body_util::BodyExt as _;
    resp.into_body().collect().await.unwrap().to_bytes()
}

// --- WebSocket doubles ---------------------------------------------------------

/// A raw WebSocket echo double: answers 101 to any upgrade, then
/// echoes bytes back. Records the forwarded Origin header.
async fn ws_echo_backend() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let origins: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&origins);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                // Read the request head.
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read_exact(&mut b).await {
                        Ok(_) => head.push(b[0]),
                        Err(_) => return,
                    }
                }
                let text = String::from_utf8_lossy(&head).into_owned();
                let origin = text
                    .lines()
                    .find(|l| l.to_lowercase().starts_with("origin:"))
                    .unwrap_or("origin: (none)")
                    .to_string();
                log.lock().unwrap().push(origin);
                let key = text
                    .lines()
                    .find_map(|l| l.split_once(": "))
                    .filter(|(n, _)| n.eq_ignore_ascii_case("sec-websocket-key"))
                    .map(|(_, v)| v.trim().to_string())
                    .unwrap_or_default();
                // The accept value is irrelevant to the gateway (it
                // relays bytes verbatim); a fixed token is fine.
                let _ = key;
                let resp = "HTTP/1.1 101 Switching Protocols\r\n\
                            upgrade: websocket\r\n\
                            connection: upgrade\r\n\
                            sec-websocket-accept: dwara-test-double\r\n\r\n";
                if stream.write_all(resp.as_bytes()).await.is_err() {
                    return;
                }
                // Echo loop: the policer's close frame rides this path.
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (port, origins)
}

/// Gateway YAML with one WS route and the given `websocket:` block.
fn ws_yaml(backend: u16, ws_block: &str) -> String {
    format!(
        "routes:\n\
         - name: ws\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /chat\n{ws_block}\
         \x20 action:\n\
         \x20   type: proxy\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {backend}\n"
    )
}

/// Speak a WebSocket handshake with a raw TCP stream; returns the
/// response head (status line + headers).
async fn ws_handshake(stream: &mut tokio::net::TcpStream, gw: u16, origin: Option<&str>) -> String {
    let mut req = format!(
        "GET /chat HTTP/1.1\r\nhost: 127.0.0.1:{gw}\r\nupgrade: websocket\r\n\
         connection: Upgrade\r\nsec-websocket-key: d2FyYQ==\r\n\
         sec-websocket-version: 13\r\n"
    );
    if let Some(o) = origin {
        req.push_str(&format!("origin: {o}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        stream.read_exact(&mut b).await.expect("head byte");
        head.push(b[0]);
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// Read the response body declared by a head's Content-Length.
async fn read_all(stream: &mut tokio::net::TcpStream, head: &str) -> Bytes {
    let len: usize = head
        .lines()
        .find_map(|l| {
            l.split_once(':')
                .filter(|(n, _)| n.trim().eq_ignore_ascii_case("content-length"))
        })
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);
    let mut buf = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut buf).await.expect("body");
    }
    Bytes::from(buf)
}

/// A small masked text frame (client framing).
fn ws_frame(payload: &[u8]) -> Vec<u8> {
    let mask = [0x11u8, 0x22, 0x33, 0x44];
    let mut f = vec![0x81, 0x80 | payload.len() as u8];
    f.extend_from_slice(&mask);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    f
}

// --- 3. the origin allowlist ---------------------------------------------------

#[tokio::test]
async fn the_origin_allowlist_denies_before_upstream_contact() {
    let (backend, origins) = ws_echo_backend().await;
    let yaml = ws_yaml(
        backend,
        "  websocket:\n    origins: [https://app.example.com]\n",
    );
    let dp = support::dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    // Allowed origin: the upgrade proceeds and the tunnel works.
    let mut good = tokio::net::TcpStream::connect(("127.0.0.1", gw))
        .await
        .unwrap();
    let head = ws_handshake(&mut good, gw, Some("https://app.example.com")).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    // Round-trip one frame through the tunnel.
    good.write_all(&ws_frame(b"hello")).await.unwrap();
    let mut echo = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), good.read(&mut echo))
        .await
        .expect("echo")
        .unwrap();
    assert_eq!(&echo[..n], &ws_frame(b"hello"));

    // Denied origin: 403, and the upstream NEVER sees the handshake.
    let mut bad = tokio::net::TcpStream::connect(("127.0.0.1", gw))
        .await
        .unwrap();
    let head = ws_handshake(&mut bad, gw, Some("https://evil.example")).await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    let body = read_all(&mut bad, &head).await;
    assert_eq!(
        support::envelope_code(&body),
        "websocket_origin_denied",
        "{head}"
    );

    // Missing origin: fail closed.
    let mut none = tokio::net::TcpStream::connect(("127.0.0.1", gw))
        .await
        .unwrap();
    let head = ws_handshake(&mut none, gw, None).await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    let body = read_all(&mut none, &head).await;
    assert_eq!(support::envelope_code(&body), "websocket_origin_denied");

    // Exactly one handshake reached the backend (the allowed one).
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(origins.lock().unwrap().len(), 1);
}

// --- 4. post-upgrade rate policing ----------------------------------------------

#[tokio::test]
async fn an_abusive_websocket_flood_is_closed_with_1008() {
    let (backend, _origins) = ws_echo_backend().await;
    let yaml = ws_yaml(
        backend,
        "  websocket:\n    origins: [https://app.example.com]\n    max_frames_per_sec: 5\n",
    );
    let dp = support::dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    let mut ws = tokio::net::TcpStream::connect(("127.0.0.1", gw))
        .await
        .unwrap();
    let head = ws_handshake(&mut ws, gw, Some("https://app.example.com")).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");

    // Flood far past the allowance (5/s burst 5): send 50 small frames
    // back-to-back. The policer trips inside the burst.
    let mut flood = Vec::new();
    for i in 0..50u8 {
        flood.extend_from_slice(&ws_frame(&[i; 4]));
    }
    ws.write_all(&flood).await.unwrap();

    // The gateway answers with the 1008 policy close frame and cuts
    // the connection (EOF or the close frame; both end the stream).
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        assert!(Instant::now() < deadline, "policer never closed the flood");
        let n = tokio::time::timeout(Duration::from_secs(2), ws.read(&mut chunk))
            .await
            .expect("read bounded")
            .unwrap_or(0);
        if n == 0 {
            break; // EOF after the close frame
        }
        buf.extend_from_slice(&chunk[..n]);
        // The 1008 close frame: 0x88 0x02 0x03 0xe8.
        if buf.windows(4).any(|w| w == [0x88, 0x02, 0x03, 0xe8]) {
            break;
        }
    }
    assert!(
        buf.windows(4).any(|w| w == [0x88, 0x02, 0x03, 0xe8]),
        "the policy close frame (1008) reached the client: {buf:?}"
    );

    // The policy decision is observable.
    let rendered = dp.observability().render();
    assert!(
        rendered.contains("dwara_websocket_policy_total") && rendered.contains("rate_closed"),
        "{rendered}"
    );
}

// --- 5. no websocket block: transparent (regression pin) ------------------------

#[tokio::test]
async fn without_a_websocket_block_upgrades_stay_transparent() {
    let (backend, origins) = ws_echo_backend().await;
    let yaml = ws_yaml(backend, "");
    let dp = support::dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    // Any origin, no rate cap: the DW-009 transparent tunnel.
    let mut ws = tokio::net::TcpStream::connect(("127.0.0.1", gw))
        .await
        .unwrap();
    let head = ws_handshake(&mut ws, gw, Some("https://wherever.example")).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    // A burst far past any cap flows unpoliced.
    let mut flood = Vec::new();
    for i in 0..50u8 {
        flood.extend_from_slice(&ws_frame(&[i; 4]));
    }
    ws.write_all(&flood).await.unwrap();
    let mut echo = vec![0u8; flood.len()];
    let mut got = 0;
    let deadline = Instant::now() + Duration::from_secs(5);
    while got < flood.len() {
        assert!(Instant::now() < deadline);
        let n = ws.read(&mut echo[got..]).await.unwrap();
        if n == 0 {
            break;
        }
        got += n;
    }
    assert_eq!(got, flood.len(), "the whole burst echoed, unpoliced");
    assert_eq!(origins.lock().unwrap().len(), 1);
}

// --- 6. sustained rate: the bucket refills over time ----------------------------

#[tokio::test]
async fn the_policer_refills_over_time_and_still_caps_bursts() {
    // rate 20/s, capacity 20 (a one-second burst). Phase A spends 10
    // tokens; a 700 ms pause refills the bucket toward capacity (at
    // 20/s, >= 10 new tokens); phase B's 15 frames therefore fit ONLY
    // if refill happened (10 were left after A, 15 > 10); phase C's
    // oversized burst trips the policer. Margins: refill is guaranteed
    // after >= 500 ms, phases are instantaneous.
    let (backend, _origins) = ws_echo_backend().await;
    let yaml = ws_yaml(
        backend,
        "  websocket:\n    origins: [https://app.example.com]\n    max_frames_per_sec: 20\n",
    );
    let dp = support::dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let mut ws = tokio::net::TcpStream::connect(("127.0.0.1", gw))
        .await
        .unwrap();
    let head = ws_handshake(&mut ws, gw, Some("https://app.example.com")).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");

    let burst = |n: usize| {
        let mut v = Vec::new();
        for i in 0..n {
            v.extend_from_slice(&ws_frame(&[i as u8; 4]));
        }
        v
    };
    // Phase A: 10 frames (well inside capacity).
    ws.write_all(&burst(10)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    // Drain the echo so the tunnel stays live.
    let mut sink = [0u8; 4096];
    let _ = tokio::time::timeout(Duration::from_millis(300), ws.read(&mut sink)).await;

    // Refill pause: 700 ms at 20/s restores >= 10 tokens.
    tokio::time::sleep(Duration::from_millis(700)).await;

    // Phase B: 15 frames — only fundable if the bucket refilled.
    ws.write_all(&burst(15)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    let mut sink = [0u8; 4096];
    let got = tokio::time::timeout(Duration::from_millis(400), ws.read(&mut sink))
        .await
        .expect("echo still flowing: phase B was funded by the refill")
        .unwrap_or(0);
    assert!(got > 0, "the tunnel survived phase B (refill worked)");

    // Phase C: a 40-frame burst far past capacity trips the policer
    // with the 1008 close frame.
    ws.write_all(&burst(40)).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        assert!(Instant::now() < deadline, "policer never fired");
        let n = tokio::time::timeout(Duration::from_secs(2), ws.read(&mut chunk))
            .await
            .expect("bounded read")
            .unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == [0x88, 0x02, 0x03, 0xe8]) {
            break;
        }
    }
    assert!(
        buf.windows(4).any(|w| w == [0x88, 0x02, 0x03, 0xe8]),
        "phase C tripped the policer: close frame seen in {buf:?}"
    );
}

// --- 7. grpc-timeout keeps ticking through a retry -------------------------------

/// A TLS h2 gRPC double that answers the FIRST request 503 (retryable)
/// and hangs on every later one.
async fn grpc_flaky_backend(ca_leaf: &rcgen::Certificate, ca_key: &rcgen::KeyPair) -> u16 {
    dwara_core::tls::install_aws_lc_rs_provider();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // Per-REQUEST counter (h2 multiplexes attempts onto one connection,
    // so counting connections would answer 503 to every request).
    let served = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![ca_leaf.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                ca_key.serialize_der(),
            )),
        )
        .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(tls) = acceptor.accept(stream).await else {
                continue;
            };
            let counter = Arc::clone(&served);
            tokio::spawn(async move {
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(tls),
                        service_fn(move |_req: Request<hyper::body::Incoming>| {
                            let served = Arc::clone(&counter);
                            async move {
                                let n = served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                if n == 0 {
                                    Ok::<_, Infallible>(
                                        Response::builder()
                                            .status(503)
                                            .body(GrpcBody {
                                                data_sent: true,
                                                trailers_sent: true,
                                            })
                                            .unwrap(),
                                    )
                                } else {
                                    tokio::time::sleep(Duration::from_secs(30)).await;
                                    Ok(Response::builder()
                                        .status(200)
                                        .header("content-type", "application/grpc")
                                        .body(GrpcBody {
                                            data_sent: false,
                                            trailers_sent: false,
                                        })
                                        .unwrap())
                                }
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    port
}

#[tokio::test]
async fn a_grpc_deadline_cuts_a_retry_that_cannot_fit() {
    let (_dir, ca_pem, leaf, key) = private_ca();
    let backend = grpc_flaky_backend(&leaf, &key).await;
    let yaml = grpc_yaml(
        &ca_pem,
        backend,
        "",
        "  retries:\n    attempts: 2\n    retry_post: true\n    buffer_max_bytes: 1024\n    backoff_base_ms: 50\n    backoff_cap_ms: 100\n    budget_percent: 100\n",
    );
    let dp = support::dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    let client = grpc_client();
    let started = Instant::now();
    let (mut parts, body) = Request::builder()
        .method("POST")
        .uri(format!("http://127.0.0.1:{gw}/helloworld.Greeter/SayHello"))
        .version(Version::HTTP_2)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("grpc-timeout", "1S")
        .body(Full::<Bytes>::new(Bytes::from_static(
            b"\x00\x00\x00\x00\x00",
        )))
        .unwrap()
        .into_parts();
    parts.headers.remove(hyper::header::HOST);
    let resp = client
        .request(Request::from_parts(parts, body))
        .await
        .expect("the gateway answers");

    // Attempt 1 saw the 503; the retry started; the 1 s budget cut it
    // (the hang is 30 s). The answer is the deadline envelope, well
    // inside any attempt that could have completed.
    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(resp.headers().get("grpc-status").unwrap(), "4");
    assert_eq!(
        support::envelope_code(&read_body(resp).await),
        "grpc_deadline_exceeded"
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "budget: {:?}",
        started.elapsed()
    );
}

// --- 8. a non-websocket 101 on a policied route tunnels unpoliced --------------

/// A raw double that answers 101 upgrading a NON-websocket protocol,
/// then echoes bytes (the same echo shape; only the upgrade token in
/// the 101 differs).
async fn other_upgrade_echo_backend() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read_exact(&mut b).await {
                        Ok(_) => head.push(b[0]),
                        Err(_) => return,
                    }
                }
                let resp = "HTTP/1.1 101 Switching Protocols\r\n\
                            upgrade: foobar\r\n\
                            connection: upgrade\r\n\r\n";
                if stream.write_all(resp.as_bytes()).await.is_err() {
                    return;
                }
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

#[tokio::test]
async fn a_non_websocket_101_on_a_policied_route_is_tunneled_unpoliced() {
    // M1's pin: policing keys off the UPSTREAM's 101, not the client's
    // offered tokens. A client offering "foo, websocket" whose backend
    // upgrades "foo" gets the generic tunnel — no WS frame parsing, no
    // close-frame injection, no rate_closed metric.
    let backend = other_upgrade_echo_backend().await;
    let yaml = ws_yaml(
        backend,
        "  websocket:\n    origins: []\n    max_frames_per_sec: 5\n",
    );
    let dp = support::dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    let mut ws = tokio::net::TcpStream::connect(("127.0.0.1", gw))
        .await
        .unwrap();
    // Offer a mixed token list; no Origin needed (empty allowlist).
    let req = format!(
        "GET /chat HTTP/1.1\r\nhost: 127.0.0.1:{gw}\r\nupgrade: foobar, websocket\r\n\
         connection: Upgrade\r\n\r\n"
    );
    ws.write_all(req.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        ws.read_exact(&mut b).await.expect("head byte");
        head.push(b[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");

    // A burst far past the configured rate (5/s) echoes back whole:
    // the tunnel is NOT policed (the backend upgraded foobar, not
    // websocket). The flood bytes deliberately do NOT form WS frames.
    let flood = vec![0xA5u8; 400];
    ws.write_all(&flood).await.unwrap();
    let mut echo = vec![0u8; flood.len()];
    let mut got = 0;
    let deadline = Instant::now() + Duration::from_secs(5);
    while got < flood.len() {
        assert!(Instant::now() < deadline, "echo stalled at {got}");
        let n = ws.read(&mut echo[got..]).await.unwrap();
        if n == 0 {
            break;
        }
        got += n;
    }
    assert_eq!(
        got,
        flood.len(),
        "the non-websocket tunnel echoed unpoliced"
    );
    assert_eq!(echo, flood);
    // And no rate_closed series was counted.
    assert!(!dp.observability().render().contains("rate_closed"));
}
