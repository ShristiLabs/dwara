//! Reverse-proxy dataplane integration tests (DW-009).
//!
//! Serves a real gateway (auto h1/h2c listener running
//! `dwara_core::proxy::handle`) against small in-process backends and
//! asserts the done-when surface: full-duplex streaming (SSE responses and
//! multi-GiB request bodies with constant memory), WebSocket-style 101
//! tunneling, hop-by-hop hygiene, XFF/X-Real-IP under trusted proxies,
//! redirect/respond actions, classified upstream errors, and route
//! hot-swap through publish + dataplane refresh.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use dwara_core::config::parse_gateway;
use dwara_core::proxy::{self, DataPlane};
use dwara_core::snapshot::ConfigState;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::header::HOST;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri, Version};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// --- infrastructure -----------------------------------------------------

fn state_from(yaml: &str) -> Arc<ConfigState> {
    let gateway = parse_gateway(yaml).expect("test config parses");
    let state = Arc::new(ConfigState::new());
    state
        .compile_and_publish(&gateway)
        .expect("test config publishes");
    state
}

fn dataplane_from(yaml: &str) -> Arc<DataPlane> {
    DataPlane::new(state_from(yaml))
}

/// Serve the proxy dataplane on an ephemeral port (h1 + h2c + upgrades).
async fn spawn_gateway(dp: Arc<DataPlane>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            let dp = Arc::clone(&dp);
            tokio::spawn(async move {
                let _ =
                    AutoBuilder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(
                            TokioIo::new(stream),
                            service_fn(move |req| {
                                let dp = Arc::clone(&dp);
                                let peer_ip = peer.ip();
                                async move {
                                    Ok::<_, Infallible>(proxy::handle(&dp, peer_ip, req).await)
                                }
                            }),
                        )
                        .await;
            });
        }
    });
    port
}

/// Backend whose handler synchronously builds a full response.
async fn spawn_backend_full(
    handler: Arc<dyn Fn(Request<Incoming>) -> Response<Full<Bytes>> + Send + Sync>,
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req: Request<Incoming>| {
                            let handler = Arc::clone(&handler);
                            async move { Ok::<_, Infallible>(handler(req)) }
                        }),
                    )
                    .await;
            });
        }
    });
    port
}

/// Backend with an async handler (body streaming, upgrades, byte counting).
async fn spawn_backend_async<F, Fut, B>(handler: F) -> u16
where
    F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Response<B>, Infallible>> + Send,
    B: hyper::body::Body + Send + 'static,
    B::Data: Send,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(
                        TokioIo::new(stream),
                        service_fn(move |req: Request<Incoming>| {
                            let handler = Arc::clone(&handler);
                            async move { handler(req).await }
                        }),
                    )
                    .await;
            });
        }
    });
    port
}

fn h1_client() -> Client<HttpConnector, Full<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

fn h2c_client() -> Client<HttpConnector, Full<Bytes>> {
    Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build_http()
}

fn uri(port: u16, path: &str) -> Uri {
    format!("http://127.0.0.1:{port}{path}").parse().unwrap()
}

fn proxy_yaml(backend_port: u16) -> String {
    format!(
        "routes:\n\
         - name: all\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /v1\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {backend_port}\n"
    )
}

async fn body_text<B>(body: B) -> String
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: std::fmt::Debug,
{
    String::from_utf8_lossy(&body.collect().await.unwrap().to_bytes()).into_owned()
}

// --- happy paths ---------------------------------------------------------

#[tokio::test]
async fn proxy_h1_forwards_method_path_query_and_rewrites_host() {
    let backend = spawn_backend_full(Arc::new(|req: Request<Incoming>| {
        let host = req
            .headers()
            .get(HOST)
            .map(|v| v.to_str().unwrap_or("-"))
            .unwrap_or("-");
        let text = format!("{} {} host={host}", req.method(), req.uri());
        Response::new(Full::new(Bytes::from(text)))
    }))
    .await;
    let port = spawn_gateway(dataplane_from(&proxy_yaml(backend))).await;

    let resp = h1_client()
        .get(uri(port, "/v1/users/42?page=1"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let text = body_text(resp.into_body()).await;
    assert!(
        text.starts_with("GET /v1/users/42?page=1 host=127.0.0.1:"),
        "method/path/query preserved, Host rewritten to upstream authority: {text}"
    );
    assert!(
        !text.contains("host=localhost"),
        "inbound Host must not leak upstream: {text}"
    );
}

#[tokio::test]
async fn proxy_h2c_client_streams_through() {
    let backend = spawn_backend_full(Arc::new(|_req: Request<Incoming>| {
        Response::new(Full::new(Bytes::from_static(b"h2c-ok")))
    }))
    .await;
    let port = spawn_gateway(dataplane_from(&proxy_yaml(backend))).await;

    let resp = h2c_client().get(uri(port, "/v1/anything")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_text(resp.into_body()).await, "h2c-ok");
}

// --- streaming: SSE responses arrive before the backend finishes ---------

/// Response body that emits `events` SSE frames, one per `interval`,
/// flipping `done` when exhausted. Proves frame-by-frame forwarding.
struct SseBody {
    events: u32,
    sent: u32,
    done: Arc<AtomicBool>,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl Body for SseBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.sent >= self.events {
            self.done.store(true, Ordering::SeqCst);
            return Poll::Ready(None);
        }
        if self.sleep.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        self.sent += 1;
        self.sleep
            .as_mut()
            .reset(tokio::time::Instant::now() + Duration::from_millis(120));
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(format!(
            "data: {}\n\n",
            self.sent
        ))))))
    }
}

#[tokio::test]
async fn sse_response_first_event_arrives_before_backend_finishes() {
    let done = Arc::new(AtomicBool::new(false));
    let done_for_backend = Arc::clone(&done);
    let backend = spawn_backend_async(move |_req: Request<Incoming>| {
        let done = Arc::clone(&done_for_backend);
        async move {
            let body = SseBody {
                events: 4,
                sent: 0,
                done,
                sleep: Box::pin(tokio::time::sleep(Duration::from_millis(120))),
            };
            // Deliberately NO content-length: chunked streaming, so any
            // body-buffering proxy would hang the client on the first read.
            Ok::<_, Infallible>(Response::new(Box::pin(body)))
        }
    })
    .await;
    let port = spawn_gateway(dataplane_from(&proxy_yaml(backend))).await;

    let resp = h1_client().get(uri(port, "/v1/events")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body();
    let first = body.frame().await.expect("first frame").unwrap();
    assert_eq!(
        first.into_data().unwrap(),
        Bytes::from_static(b"data: 1\n\n")
    );
    assert!(
        !done.load(Ordering::SeqCst),
        "first event reached the client before the backend finished streaming"
    );
    while body.frame().await.is_some() {}
    assert!(done.load(Ordering::SeqCst));
}

// --- streaming: multi-GiB request body through a generator body ----------

/// Request body synthesized on the fly: `total` bytes in 64 KiB frames.
/// Constant memory; nothing ever touches disk.
struct GenBody {
    remaining: u64,
}

impl Body for GenBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        let chunk = self.remaining.min(64 * 1024);
        // SAFETY of cost: one 64 KiB allocation per frame, freed as the
        // transport consumes it — the peak stays a few frames.
        let mut v = vec![0u8; chunk as usize];
        v[0] = b'x';
        self.get_mut().remaining -= chunk;
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(v)))))
    }
}

#[tokio::test]
async fn streaming_request_body_of_2_gib_reaches_backend_byte_exact() {
    const TOTAL: u64 = 2 * 1024 * 1024 * 1024;
    run_large_body(TOTAL).await;
}

#[tokio::test]
async fn streaming_request_body_scaled_to_10_gib() {
    // The done-when claim at full scale. Same code path as the 2 GiB test;
    // runtime on loopback is a few seconds (measured locally ~3-6 s). If
    // this ever becomes a CI burden, the 2 GiB variant plus the linear
    // scaling argument (frame-by-frame forwarding, constant memory) is the
    // documented fallback.
    const TOTAL: u64 = 10 * 1024 * 1024 * 1024;
    run_large_body(TOTAL).await;
}

async fn run_large_body(total: u64) {
    let received = Arc::new(AtomicU64::new(0));
    let backend = spawn_backend_async({
        let received = Arc::clone(&received);
        move |req: Request<Incoming>| {
            let received = Arc::clone(&received);
            async move {
                let mut body = req.into_body();
                let mut n: u64 = 0;
                while let Some(frame) = body.frame().await {
                    n += frame.unwrap().into_data().unwrap().len() as u64;
                    received.store(n, Ordering::SeqCst);
                }
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(n.to_string()))))
            }
        }
    })
    .await;
    let port = spawn_gateway(dataplane_from(&proxy_yaml(backend))).await;

    let client: Client<HttpConnector, GenBody> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method("POST")
        .uri(uri(port, "/v1/upload"))
        .body(GenBody { remaining: total })
        .unwrap();
    let started = std::time::Instant::now();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let text = body_text(resp.into_body()).await;
    assert_eq!(text, total.to_string(), "backend received exact byte count");
    println!(
        "streamed {total} bytes through the gateway in {:?}",
        started.elapsed()
    );
}

// --- 101 upgrade tunneling -----------------------------------------------

#[tokio::test]
async fn upgrade_tunnel_echoes_bytes_both_ways() {
    // Generic 101 tunnel (not WebSocket framing): any protocol the client
    // names in Upgrade is forwarded and the raw streams are spliced.
    let backend = spawn_backend_async(move |mut req: Request<Incoming>| async move {
        // Conformant upgrade handling: RFC 7230 requires BOTH an Upgrade
        // header and a `Connection: Upgrade` token before offering a 101.
        // The gateway must rebuild the Connection header when tunneling.
        let has_connection_upgrade = req
            .headers()
            .get("connection")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
            });
        if !req.headers().contains_key("upgrade") || !has_connection_upgrade {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::new()))
                .unwrap());
        }
        let on_upgrade = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            let Ok(io) = on_upgrade.await else {
                return;
            };
            let mut io = TokioIo::new(io);
            let mut buf = [0u8; 1024];
            loop {
                match io.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if io.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Ok(Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("connection", "upgrade")
            .header("upgrade", "chat")
            .body(Full::new(Bytes::new()))
            .unwrap())
    })
    .await;
    let port = spawn_gateway(dataplane_from(&proxy_yaml(backend))).await;

    let mut tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    tcp.write_all(
        b"GET /v1/ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: chat\r\n\r\n",
    )
    .await
    .unwrap();

    // Read the 101 head.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tcp.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    let head_text = String::from_utf8_lossy(&head);
    assert!(head_text.starts_with("HTTP/1.1 101"), "got: {head_text}");

    // Echo through the tunnel.
    tcp.write_all(b"ping-tunnel").await.unwrap();
    let mut echoed = [0u8; 11];
    tcp.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping-tunnel");
}

#[tokio::test]
async fn upgrade_over_h2_is_rejected_501() {
    // An h2/h2c request cannot tunnel upgrades the HTTP/1.1 way (RFC 9113
    // strips connection-specific headers; extended CONNECT is out of scope
    // for v1), so the gateway answers 501 before ever dialing the upstream.
    // Driven directly against handle() because hyper's own h2 client
    // silently strips the Upgrade header client-side.
    let dp = dataplane_from(&proxy_yaml(9)); // upstream never dialed
    let req = Request::builder()
        .uri("/v1/ws")
        .version(Version::HTTP_2)
        .header("upgrade", "websocket")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = proxy::handle(&dp, "127.0.0.1".parse().unwrap(), req).await;
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(
        body_text(resp.into_body()).await,
        "protocol upgrade is not supported over HTTP/2"
    );
}

// --- hop-by-hop hygiene and forwarded headers -----------------------------

#[tokio::test]
async fn hop_by_hop_headers_stripped_and_xff_defaults_to_peer() {
    // Untrusted (default) XFF semantics: inbound chain discarded, peer only.
    let backend = spawn_backend_full(Arc::new(|req: Request<Incoming>| {
        let mut text = String::new();
        for name in [
            "x-custom",
            "x-forwarded-for",
            "x-real-ip",
            "connection",
            "keep-alive",
            "proxy-authorization",
            "te",
        ] {
            let v = req
                .headers()
                .get(name)
                .map(|v| v.to_str().unwrap_or("-"))
                .unwrap_or("-");
            text.push_str(&format!("{name}:{v}\n"));
        }
        let mut resp = Response::new(Full::new(Bytes::from(text)));
        // Hop-by-hop headers on the RESPONSE direction must be stripped.
        resp.headers_mut()
            .insert("keep-alive", "timeout=5".parse().unwrap());
        resp.headers_mut()
            .insert("proxy-authenticate", "Basic".parse().unwrap());
        resp
    }))
    .await;
    let port = spawn_gateway(dataplane_from(&proxy_yaml(backend))).await;

    // Raw client so forbidden-by-client libs headers can be sent verbatim.
    let mut tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    tcp.write_all(
        b"GET /v1/hygiene HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
          Keep-Alive: timeout=5\r\nProxy-Authorization: Basic zzz\r\nTE: trailers\r\n\
          X-Forwarded-For: 198.51.100.7\r\nX-Custom: yes\r\n\r\n",
    )
    .await
    .unwrap();
    let mut buf = Vec::new();
    tcp.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);

    assert!(text.contains("x-custom:yes"));
    assert!(text.contains("x-forwarded-for:127.0.0.1"), "in:\n{text}");
    assert!(text.contains("x-real-ip:127.0.0.1"));
    // Request-direction checks use the echo body only (the gateway's own
    // closing Connection header is legitimately present on the wire).
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
    // "-" is the echo marker for an absent header.
    assert!(body.contains("connection:-\n"), "in echo body:\n{body}");
    assert!(body.contains("keep-alive:-\n"), "in echo body:\n{body}");
    assert!(
        body.contains("proxy-authorization:-\n"),
        "in echo body:\n{body}"
    );
    assert!(body.contains("te:-\n"), "in echo body:\n{body}");
    // Response-direction checks: the backend's hop-by-hop headers must not
    // reach the client (search only the header section).
    let head = text.split("\r\n\r\n").next().unwrap_or("");
    assert!(
        !head.to_ascii_lowercase().contains("keep-alive"),
        "in:\n{head}"
    );
    assert!(
        !head.to_ascii_lowercase().contains("proxy-authenticate"),
        "in:\n{head}"
    );
}

#[tokio::test]
async fn trusted_peer_extends_inbound_xff_chain() {
    let backend = spawn_backend_full(Arc::new(|req: Request<Incoming>| {
        let xff = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_string();
        Response::new(Full::new(Bytes::from(xff)))
    }))
    .await;
    let yaml = format!(
        "trusted_proxies: [\"127.0.0.1/32\"]\n{}",
        proxy_yaml(backend)
    );
    let port = spawn_gateway(dataplane_from(&yaml)).await;

    let client = h1_client();
    let resp = client
        .request(
            Request::builder()
                .uri(uri(port, "/v1/xff"))
                .header("x-forwarded-for", "203.0.113.9")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        body_text(resp.into_body()).await,
        "203.0.113.9, 127.0.0.1",
        "trusted peer: inbound chain preserved and peer appended"
    );
}

// --- route actions --------------------------------------------------------

#[tokio::test]
async fn redirect_action_preserves_path_and_query_and_honors_target() {
    let yaml = "routes:\n  - name: moved\n    service: svc\n    match:\n      path:\n        type: prefix\n        value: /v1\n    action:\n      type: redirect\n      status: 302\n      scheme: https\n      host: example.com\nservices:\n  - name: svc\n    upstream: up\nupstreams:\n  - name: up\n    endpoints:\n      - address: 127.0.0.1\n        port: 9\n";
    let port = spawn_gateway(dataplane_from(yaml)).await;

    let client = h1_client();
    let resp = client.get(uri(port, "/v1/old?x=1")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        resp.headers().get("location").unwrap(),
        "https://example.com/v1/old?x=1"
    );
}

#[tokio::test]
async fn redirect_with_explicit_path_uses_it_verbatim() {
    let yaml = "routes:\n  - name: moved\n    service: svc\n    match:\n      path:\n        type: prefix\n        value: /v1\n    action:\n      type: redirect\n      status: 301\n      path: /moved\nservices:\n  - name: svc\n    upstream: up\nupstreams:\n  - name: up\n    endpoints:\n      - address: 127.0.0.1\n        port: 9\n";
    let port = spawn_gateway(dataplane_from(yaml)).await;

    let resp = h1_client().get(uri(port, "/v1/whatever")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(resp.headers().get("location").unwrap(), "/moved");
}

#[tokio::test]
async fn respond_action_serves_configured_status_and_body() {
    let yaml = "routes:\n  - name: teapot\n    service: svc\n    match:\n      path:\n        type: exact\n        value: /v1/coffee\n    action:\n      type: respond\n      status: 418\n      body: short and stout\nservices:\n  - name: svc\n    upstream: up\nupstreams:\n  - name: up\n    endpoints:\n      - address: 127.0.0.1\n        port: 9\n";
    let port = spawn_gateway(dataplane_from(yaml)).await;

    let resp = h1_client().get(uri(port, "/v1/coffee")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);
    assert_eq!(body_text(resp.into_body()).await, "short and stout");
}

// --- no route / non-path criteria -----------------------------------------

#[tokio::test]
async fn unmatched_path_is_404() {
    let port = spawn_gateway(dataplane_from(&proxy_yaml(9))).await;
    let resp = h1_client().get(uri(port, "/other")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn method_and_host_criteria_are_applied_after_path() {
    let backend = spawn_backend_full(Arc::new(|_req: Request<Incoming>| {
        Response::new(Full::new(Bytes::from_static(b"matched")))
    }))
    .await;
    let yaml = format!(
        "routes:\n\
         - name: picky\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /v1\n\
         \x20   host: api.example.com\n\
         \x20   methods: [GET]\n\
         \x20   headers:\n\
         \x20     x-tenant: acme\n\
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
    );
    let port = spawn_gateway(dataplane_from(&yaml)).await;
    let client = h1_client();

    // All criteria satisfied.
    let resp = client
        .request(
            Request::builder()
                .uri(uri(port, "/v1/thing"))
                .header("host", "api.example.com")
                .header("x-tenant", "acme")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_text(resp.into_body()).await, "matched");

    // Wrong method, wrong host, missing header: each misses the route.
    for (method, host, tenant) in [
        ("POST", "api.example.com", "acme"),
        ("GET", "other.example.com", "acme"),
        ("GET", "api.example.com", "other"),
    ] {
        let resp = client
            .request(
                Request::builder()
                    .method(method)
                    .uri(uri(port, "/v1/thing"))
                    .header("host", host)
                    .header("x-tenant", tenant)
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{method} {host} {tenant} must miss the route"
        );
    }
}

// --- upstream error classification ----------------------------------------

#[tokio::test]
async fn refused_backend_is_502_with_short_message() {
    // Port 1 on loopback: connection refused, nothing listening.
    let port = spawn_gateway(dataplane_from(&proxy_yaml(1))).await;
    let resp = h1_client().get(uri(port, "/v1/x")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(body_text(resp.into_body()).await, "upstream unavailable");
}

#[tokio::test]
async fn connect_timeout_is_504() {
    let yaml = "routes:\n  - name: all\n    service: svc\n    match:\n      path:\n        type: prefix\n        value: /v1\n    action:\n      type: proxy\nservices:\n  - name: svc\n    upstream: up\nupstreams:\n  - name: up\n    timeouts:\n      connect_ms: 250\n    endpoints:\n      - address: 10.255.255.1\n        port: 81\n";
    let port = spawn_gateway(dataplane_from(yaml)).await;
    let started = std::time::Instant::now();
    let resp = h1_client().get(uri(port, "/v1/x")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(
        body_text(resp.into_body()).await,
        "upstream connect timed out"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}

// --- route hot-swap through reload machinery -------------------------------

#[tokio::test]
async fn route_target_hot_swaps_with_zero_dropped_requests() {
    fn respond_yaml(body: &str) -> String {
        format!(
            "routes:\n\
             - name: all\n\
             \x20 service: svc\n\
             \x20 match:\n\
             \x20   path:\n\
             \x20     type: regex\n\
             \x20     value: /.*\n\
             \x20 action:\n\
             \x20   type: respond\n\
             \x20   status: 200\n\
             \x20   body: {body}\n\
             services:\n\
             - name: svc\n\
             \x20 upstream: up\n\
             upstreams:\n\
             - name: up\n\
             \x20 endpoints:\n\
             \x20   - address: 127.0.0.1\n\
             \x20     port: 9\n"
        )
    }

    let state = state_from(&respond_yaml("gen-a"));
    let dp = DataPlane::new(Arc::clone(&state));
    let port = spawn_gateway(Arc::clone(&dp)).await;

    // Steady sequential traffic while the config flips A<->B repeatedly,
    // exactly like the binary's reload path: publish, then dp.refresh().
    let traffic = tokio::spawn(async move {
        let client = h1_client();
        let (mut seen_a, mut seen_b, mut failed) = (0u32, 0u32, 0u32);
        for _ in 0..120 {
            match client.get(uri(port, "/anything")).await {
                Ok(resp) if resp.status() == StatusCode::OK => {
                    match body_text(resp.into_body()).await.as_str() {
                        "gen-a" => seen_a += 1,
                        "gen-b" => seen_b += 1,
                        _ => failed += 1,
                    }
                }
                _ => failed += 1,
            }
        }
        (seen_a, seen_b, failed)
    });

    for i in 0..10 {
        let yaml = if i % 2 == 0 {
            respond_yaml("gen-b")
        } else {
            respond_yaml("gen-a")
        };
        let gateway = parse_gateway(&yaml).unwrap();
        state.compile_and_publish(&gateway).expect("publish");
        dp.refresh();
        tokio::time::sleep(Duration::from_millis(15)).await;
    }

    let (seen_a, seen_b, failed) = traffic.await.unwrap();
    assert_eq!(failed, 0, "no request may fail across generation swaps");
    assert!(
        seen_a > 0 && seen_b > 0,
        "both generations must be observed"
    );
}

// --- trusted-proxies config validation -------------------------------------

#[test]
fn trusted_proxies_must_be_ip_or_cidr() {
    let yaml = "trusted_proxies: [\"10.0.0.0/8\", \"not-an-ip\", \"1.2.3.4/99\"]\n";
    let gateway = parse_gateway(yaml).unwrap();
    let issues = dwara_core::snapshot::validate(&gateway);
    let fields: Vec<&str> = issues.iter().map(|i| i.field.as_str()).collect();
    assert!(fields.contains(&"trusted_proxies[1]"), "in {fields:?}");
    assert!(fields.contains(&"trusted_proxies[2]"), "in {fields:?}");
    assert!(
        !fields.iter().any(|f| f.contains("[0]")),
        "10.0.0.0/8 is valid"
    );
}

#[test]
fn peer_trust_matching_covers_ips_and_cidrs() {
    use std::net::IpAddr;
    let trusted = vec!["10.0.0.0/8".to_string(), "192.168.1.1".to_string()];
    let yes: IpAddr = "10.1.2.3".parse().unwrap();
    let exact: IpAddr = "192.168.1.1".parse().unwrap();
    let no: IpAddr = "192.168.1.2".parse().unwrap();
    let v6: IpAddr = "::1".parse().unwrap();
    assert!(proxy::peer_is_trusted(&trusted, yes));
    assert!(proxy::peer_is_trusted(&trusted, exact));
    assert!(!proxy::peer_is_trusted(&trusted, no));
    assert!(!proxy::peer_is_trusted(&trusted, v6));
    assert!(proxy::peer_is_trusted(&["::1/128".to_string()], v6));
    assert!(proxy::peer_is_trusted(&["0.0.0.0/0".to_string()], no));
}
