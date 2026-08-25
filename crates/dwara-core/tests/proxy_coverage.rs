//! Complementary DW-009 coverage: XFF chain semantics end-to-end, the
//! hand-rolled CIDR parser, hop-by-hop edge cases (Connection token lists,
//! Upgrade on non-101 traffic, 101 declined by upstream), slow-client and
//! slow-request-body streaming correctness, regex route passthrough,
//! host-with-port matching, mid-body upstream abort, invalid upstream HTTP,
//! HEAD proxying, and mixed concurrent traffic through one route.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use dwara_core::config::parse_gateway;
use dwara_core::proxy::{self, DataPlane};
use dwara_core::snapshot::{validate, CompileError, ConfigState};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// DW-021: gateway-generated error bodies are the JSON envelope; compare
/// by its stable `code` field.
fn envelope_code(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body).unwrap()["error"]["code"]
        .as_str()
        .unwrap()
        .to_string()
}

// --- infrastructure (sibling style, self-contained) -----------------------

fn dataplane_from(yaml: &str) -> Arc<DataPlane> {
    let gateway = parse_gateway(yaml).expect("test config parses");
    let state = Arc::new(ConfigState::new());
    state
        .compile_and_publish(&gateway)
        .expect("test config publishes");
    DataPlane::new(state)
}

/// Gateway on an arbitrary bind address (needed for a ::1 peer).
async fn spawn_gateway_on(dp: Arc<DataPlane>, bind: &str) -> (String, u16) {
    let listener = TcpListener::bind(bind).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let host = match addr.ip() {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(_) => format!("[{}]", addr.ip()),
    };
    let port = addr.port();
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
    (host, port)
}

async fn spawn_gateway(dp: Arc<DataPlane>) -> u16 {
    spawn_gateway_on(dp, "127.0.0.1:0").await.1
}

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

/// Minimal raw HTTP/1.1 exchange: send `raw`, then read until EOF or a
/// 2 s read-idle timeout (the peer may legitimately keep the connection
/// open). Returns everything received.
async fn raw_exchange(addr: &str, raw: &[u8]) -> Vec<u8> {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(raw).await.unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match tokio::time::timeout(Duration::from_secs(2), tcp.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => panic!("raw read failed: {e}"),
        }
    }
    buf
}

// --- 1. XFF chains end-to-end ----------------------------------------------

#[tokio::test]
async fn trusted_peer_preserves_multi_hop_inbound_xff_chain() {
    let backend = spawn_backend_full(Arc::new(|req: Request<Incoming>| {
        let get = |name: &str| {
            req.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-")
                .to_string()
        };
        let text = format!("{}|{}", get("x-forwarded-for"), get("x-real-ip"));
        Response::new(Full::new(Bytes::from(text)))
    }))
    .await;
    let yaml = format!("trusted_proxies: [\"127.0.0.1\"]\n{}", proxy_yaml(backend));
    let port = spawn_gateway(dataplane_from(&yaml)).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .uri(uri(port, "/v1/xff"))
                .header("x-forwarded-for", "1.1.1.1, 2.2.2.2")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        body_text(resp.into_body()).await,
        "1.1.1.1, 2.2.2.2, 127.0.0.1|127.0.0.1",
        "trusted peer: inbound chain preserved + peer appended; X-Real-IP = peer"
    );
}

#[tokio::test]
async fn untrusted_peer_discards_spoofed_multi_hop_xff_chain() {
    let backend = spawn_backend_full(Arc::new(|req: Request<Incoming>| {
        let get = |name: &str| {
            req.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-")
                .to_string()
        };
        let text = format!("{}|{}", get("x-forwarded-for"), get("x-real-ip"));
        Response::new(Full::new(Bytes::from(text)))
    }))
    .await;
    // No trusted_proxies at all: trust nobody.
    let port = spawn_gateway(dataplane_from(&proxy_yaml(backend))).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .uri(uri(port, "/v1/xff"))
                .header("x-forwarded-for", "1.1.1.1, 2.2.2.2")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        body_text(resp.into_body()).await,
        "127.0.0.1|127.0.0.1",
        "untrusted peer: inbound chain discarded, XFF = peer only, X-Real-IP = peer"
    );
}

#[tokio::test]
async fn ipv6_peer_on_trusted_list_extends_xff_chain() {
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
    let yaml = format!("trusted_proxies: [\"::1\"]\n{}", proxy_yaml(backend));
    let dp = dataplane_from(&yaml);
    let (host, port) = spawn_gateway_on(dp, "::1:0").await;

    let resp = h1_client()
        .request(
            Request::builder()
                .uri(
                    format!("http://{host}:{port}/v1/xff")
                        .parse::<Uri>()
                        .unwrap(),
                )
                .header("x-forwarded-for", "2001:db8::9")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        body_text(resp.into_body()).await,
        "2001:db8::9, ::1",
        "IPv6 peer matched exactly against the trusted list"
    );
}

// --- 2. CIDR parser and matcher (unit level) --------------------------------

#[test]
fn parse_ip_or_cidr_rejects_invalid_forms() {
    for bad in [
        "999.1.1.1",
        "10.0.0.0/33",
        "not-an-ip",
        "",
        "1.2.3.4/notanumber",
        "1.2.3.4/-1",
        "1.2.3.4/",
        "/8",
        "::1/129",
        "1.2.3.4/8/9",
    ] {
        assert!(
            proxy::parse_ip_or_cidr(bad).is_none(),
            "'{bad}' must be rejected"
        );
    }
}

#[test]
fn parse_ip_or_cidr_accepts_bare_ips_and_valid_cidrs() {
    assert_eq!(
        proxy::parse_ip_or_cidr("10.0.0.0/8"),
        Some(("10.0.0.0".parse().unwrap(), 8))
    );
    assert_eq!(
        proxy::parse_ip_or_cidr(" 192.168.1.1 "),
        Some(("192.168.1.1".parse().unwrap(), 32))
    );
    assert_eq!(
        proxy::parse_ip_or_cidr("2001:db8::/32"),
        Some(("2001:db8::".parse().unwrap(), 32))
    );
    // /0 is legal (matches everything of that family).
    assert_eq!(
        proxy::parse_ip_or_cidr("0.0.0.0/0"),
        Some(("0.0.0.0".parse().unwrap(), 0))
    );
}

#[test]
fn ipv4_mapped_ipv6_is_a_v6_address_not_a_v4_match() {
    // "::ffff:1.2.3.4" parses as IPv6; it must NOT match the plain IPv4
    // trusted entry "1.2.3.4" (family mismatch, pinned deliberately).
    let mapped: std::net::IpAddr = "::ffff:1.2.3.4".parse().unwrap();
    assert!(mapped.is_ipv6());
    assert!(!proxy::peer_is_trusted(&["1.2.3.4".to_string()], mapped));
    assert!(proxy::peer_is_trusted(
        &["::ffff:1.2.3.4".to_string()],
        mapped
    ));
}

#[test]
fn cidr_matching_ranges_and_respects_family_boundaries() {
    let trusted = |e: &str| vec![e.to_string()];
    let in8: std::net::IpAddr = "10.255.1.2".parse().unwrap();
    let out8: std::net::IpAddr = "11.0.0.1".parse().unwrap();
    assert!(proxy::peer_is_trusted(&trusted("10.0.0.0/8"), in8));
    assert!(!proxy::peer_is_trusted(&trusted("10.0.0.0/8"), out8));

    // IPv6 exact, /128, and /64 forms.
    let lo: std::net::IpAddr = "::1".parse().unwrap();
    assert!(proxy::peer_is_trusted(&trusted("::1"), lo));
    assert!(proxy::peer_is_trusted(&trusted("::1/128"), lo));
    let in64: std::net::IpAddr = "2001:db8:1::dead:beef".parse().unwrap();
    let out64: std::net::IpAddr = "2001:db8:2::dead:beef".parse().unwrap();
    assert!(proxy::peer_is_trusted(&trusted("2001:db8:1::/64"), in64));
    assert!(!proxy::peer_is_trusted(&trusted("2001:db8:1::/64"), out64));

    // A v4 CIDR never matches a v6 peer and vice versa.
    assert!(!proxy::peer_is_trusted(&trusted("10.0.0.0/8"), lo));
}

// --- 3. Hop-by-hop edge cases ------------------------------------------------

#[tokio::test]
async fn connection_token_list_strips_both_keep_alive_and_custom_hop_inbound() {
    let backend = spawn_backend_full(Arc::new(|req: Request<Incoming>| {
        let get = |name: &str| {
            req.headers()
                .get(name)
                .map(|v| v.to_str().unwrap_or("-"))
                .unwrap_or("-")
        };
        let text = format!(
            "keep-alive:{} x-custom-hop:{}",
            get("keep-alive"),
            get("x-custom-hop")
        );
        Response::new(Full::new(Bytes::from(text)))
    }))
    .await;
    let port = spawn_gateway(dataplane_from(&proxy_yaml(backend))).await;

    let raw = raw_exchange(
        &format!("127.0.0.1:{port}"),
        b"GET /v1/hop HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive, X-Custom-Hop\r\n\
          Keep-Alive: timeout=5\r\nX-Custom-Hop: secret\r\nConnection-Close-Marker: 1\r\n\r\n",
    )
    .await;
    let text = String::from_utf8_lossy(&raw);
    let text: &str = &text;
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
    assert_eq!(
        body.trim(),
        "keep-alive:- x-custom-hop:-",
        "both Keep-Alive and the Connection-listed custom token must be stripped upstream:\n{text}"
    );
}

#[tokio::test]
async fn response_connection_tokens_stripped_before_client() {
    let backend = spawn_backend_full(Arc::new(|_req: Request<Incoming>| {
        let mut resp = Response::new(Full::new(Bytes::from_static(b"ok")));
        resp.headers_mut()
            .insert("connection", "X-Resp-Hop".parse().unwrap());
        resp.headers_mut()
            .insert("x-resp-hop", "hop-data".parse().unwrap());
        resp
    }))
    .await;
    let port = spawn_gateway(dataplane_from(&proxy_yaml(backend))).await;

    let raw = raw_exchange(
        &format!("127.0.0.1:{port}"),
        b"GET /v1/hop HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    let text = String::from_utf8_lossy(&raw);
    let head = text
        .split("\r\n\r\n")
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    assert!(
        !head.contains("x-resp-hop"),
        "Connection-listed response header must not reach the client:\n{head}"
    );
    assert!(
        String::from_utf8_lossy(&raw).contains("\r\n\r\nok"),
        "body intact"
    );
}

#[tokio::test]
async fn upgrade_header_on_normal_request_is_forwarded_not_stripped() {
    // PINS CURRENT BEHAVIOR (see finding in the test report): the gateway
    // cannot know before the response whether the upstream will switch
    // protocols, so it forwards `Upgrade` on every HTTP/1.1 request that
    // carries one. RFC 7230 hop-by-hop strictness would strip it; the v1
    // upgrade-forwarding design keeps it. Assert the pinned behavior so a
    // future change is deliberate.
    let backend = spawn_backend_full(Arc::new(|req: Request<Incoming>| {
        let saw = if req.headers().contains_key("upgrade") {
            "saw-upgrade"
        } else {
            "no-upgrade"
        };
        Response::new(Full::new(Bytes::from(saw)))
    }))
    .await;
    let port = spawn_gateway(dataplane_from(&proxy_yaml(backend))).await;

    // Raw client: hyper's client strips/rejects Upgrade on normal requests.
    let raw = raw_exchange(
        &format!("127.0.0.1:{port}"),
        b"GET /v1/normal HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nUpgrade: h2c\r\n\r\n",
    )
    .await;
    let text = String::from_utf8_lossy(&raw);
    assert!(text.contains("saw-upgrade"), "in:\n{text}");
}

// --- 4. Upstream declines the upgrade ---------------------------------------

#[tokio::test]
async fn upstream_declining_upgrade_streams_200_normally() {
    let backend = spawn_backend_full(Arc::new(|req: Request<Incoming>| {
        let saw = if req.headers().contains_key("upgrade") {
            "upgrade-forwarded"
        } else {
            "no-upgrade"
        };
        Response::new(Full::new(Bytes::from(format!("plain-200-{saw}"))))
    }))
    .await;
    let port = spawn_gateway(dataplane_from(&proxy_yaml(backend))).await;

    let raw = raw_exchange(
        &format!("127.0.0.1:{port}"),
        b"GET /v1/maybe-upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: chat\r\n\r\n",
    )
    .await;
    let text = String::from_utf8_lossy(&raw);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "declined upgrade must stream back as a normal 200:\n{text}"
    );
    assert!(
        text.contains("plain-200-upgrade-forwarded"),
        "request reached upstream, body returned, no hang/hijack:\n{text}"
    );
}

// --- 5. Backpressure / slow sides -------------------------------------------

#[tokio::test]
async fn slow_client_receives_streaming_chunks_incrementally_without_truncation() {
    // Backend produces 6 x 512 KiB chunks, 120 ms apart. The client reads
    // one chunk, pauses 150 ms, reads the next. Assert: total bytes exact,
    // and the first chunk arrives while the backend is still producing.
    const CHUNKS: u32 = 6;
    const SIZE: usize = 512 * 1024;
    let all_done = Arc::new(AtomicBool::new(false));

    struct Timed {
        sent: u32,
        sleep: Pin<Box<tokio::time::Sleep>>,
        all_done: Arc<AtomicBool>,
    }
    impl Body for Timed {
        type Data = Bytes;
        type Error = std::io::Error;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            if self.sent >= CHUNKS {
                self.all_done.store(true, Ordering::SeqCst);
                return Poll::Ready(None);
            }
            if self.sleep.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.sent += 1;
            self.sleep
                .as_mut()
                .reset(tokio::time::Instant::now() + Duration::from_millis(120));
            let mut v = vec![b'z'; SIZE];
            v[0] = b'0' + self.sent as u8;
            Poll::Ready(Some(Ok(Frame::data(Bytes::from(v)))))
        }
    }

    let backend = {
        let all_done = Arc::clone(&all_done);
        spawn_backend_async(move |_req: Request<Incoming>| {
            let all_done = Arc::clone(&all_done);
            async move {
                Ok::<_, Infallible>(Response::new(Box::pin(Timed {
                    sent: 0,
                    sleep: Box::pin(tokio::time::sleep(Duration::from_millis(120))),
                    all_done,
                })))
            }
        })
        .await
    };
    let port = spawn_gateway(dataplane_from(&proxy_yaml(backend))).await;

    let resp = h1_client().get(uri(port, "/v1/slow")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body();
    let mut total: usize = 0;
    let mut first_chunk_seen_backend_done: Option<bool> = None;
    // Frames may arrive split (HTTP chunk boundaries), so read to EOF and
    // count bytes; pause between reads so the client is the slow side.
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), body.frame())
            .await
            .expect("no hang waiting for a chunk");
        match frame {
            None => break,
            Some(f) => {
                let data = f.unwrap().into_data().unwrap();
                if first_chunk_seen_backend_done.is_none() {
                    first_chunk_seen_backend_done = Some(all_done.load(Ordering::SeqCst));
                }
                total += data.len();
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }
    assert_eq!(
        total,
        CHUNKS as usize * SIZE,
        "no truncation under slowness"
    );
    assert_eq!(
        first_chunk_seen_backend_done,
        Some(false),
        "first chunk reached the slow client before the backend finished"
    );
    // Drain to EOF and confirm the backend completed.
    while body.frame().await.is_some() {}
    assert!(all_done.load(Ordering::SeqCst));
}

/// Request body that emits 5 frames 100 ms apart.
struct SlowReqBody {
    sent: u32,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl Body for SlowReqBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        const FRAMES: u32 = 5;
        if self.sent >= FRAMES {
            return Poll::Ready(None);
        }
        if self.sleep.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        self.sent += 1;
        self.sleep
            .as_mut()
            .reset(tokio::time::Instant::now() + Duration::from_millis(100));
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(format!(
            "frame-{};",
            self.sent
        ))))))
    }
}

#[tokio::test]
async fn slow_request_body_reaches_backend_incrementally() {
    use std::time::Instant;
    let backend = spawn_backend_async(|req: Request<Incoming>| async move {
        let started = Instant::now();
        let first = Arc::new(std::sync::Mutex::new(None::<Duration>));
        let mut body = req.into_body();
        let first_c = Arc::clone(&first);
        let mut n = 0u32;
        while let Some(frame) = body.frame().await {
            n += frame.unwrap().into_data().unwrap().len() as u32;
            let mut g = first_c.lock().unwrap();
            if g.is_none() {
                *g = Some(started.elapsed());
            }
        }
        let first_gap = first.lock().unwrap().expect("first frame instant");
        // Gap between the first frame arriving and the body completing:
        // 5 frames 100 ms apart means at least ~300 ms if frames trickle
        // through as they are sent (vs one burst at the end).
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!(
            "{n}|{}",
            started.elapsed().as_millis() - first_gap.as_millis()
        )))))
    })
    .await;
    let port = spawn_gateway(dataplane_from(&proxy_yaml(backend))).await;

    let client: Client<HttpConnector, SlowReqBody> =
        Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method("POST")
        .uri(uri(port, "/v1/slow-upload"))
        .body(SlowReqBody {
            sent: 0,
            sleep: Box::pin(tokio::time::sleep(Duration::from_millis(100))),
        })
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let text = body_text(resp.into_body()).await;
    let (bytes, gap) = text.split_once('|').unwrap();
    assert_eq!(bytes, "40", "5 frames x 8 bytes, no truncation");
    let gap: u64 = gap.parse().unwrap();
    assert!(
        gap >= 250,
        "first frame must reach the backend well before the body completes (gap {gap} ms)"
    );
}

// --- 6. Route criteria through real HTTP -------------------------------------

#[tokio::test]
async fn regex_route_passes_full_path_and_query_through() {
    let backend = spawn_backend_full(Arc::new(|req: Request<Incoming>| {
        Response::new(Full::new(Bytes::from(req.uri().to_string())))
    }))
    .await;
    let yaml = format!(
        "routes:\n\
         - name: api\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: regex\n\
         \x20     value: /api/.*\n\
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

    let resp = h1_client()
        .get(uri(port, "/api/users/9?fields=all"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_text(resp.into_body()).await,
        "/api/users/9?fields=all",
        "regex match passes the full path+query through untouched"
    );
    // Outside the regex: 404.
    let resp = h1_client().get(uri(port, "/other")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn host_criteria_matches_with_port_and_case_insensitively() {
    let backend = spawn_backend_full(Arc::new(|_req: Request<Incoming>| {
        Response::new(Full::new(Bytes::from_static(b"matched")))
    }))
    .await;
    let yaml = format!(
        "routes:\n\
         - name: hosty\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /v1\n\
         \x20   host: api.example.com\n\
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

    for host in ["api.example.com:8080", "API.EXAMPLE.COM", "api.example.com"] {
        let raw = raw_exchange(
            &format!("127.0.0.1:{port}"),
            format!("GET /v1/h HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await;
        let text = String::from_utf8_lossy(&raw);
        assert!(
            text.contains("matched"),
            "Host '{host}' must match host criterion 'api.example.com':\n{text}"
        );
    }
}

// --- 7. Upstream failure paths ------------------------------------------------

#[tokio::test]
async fn upstream_mid_body_abort_yields_classified_error_without_hang() {
    // Backend sends a partial chunked body, then errors the connection.
    // PINS CURRENT BEHAVIOR: hyper's pooled client surfaces the abort as a
    // request-level error, so the gateway classifies it 502 rather than
    // streaming a truncated 200 — the client never sees a silently
    // truncated success, nothing hangs, nothing panics.
    struct Aborting {
        sent: bool,
    }
    impl Body for Aborting {
        type Data = Bytes;
        type Error = std::io::Error;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            if self.sent {
                return Poll::Ready(Some(Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "backend died mid-body",
                ))));
            }
            self.sent = true;
            Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(
                b"partial-chunk-only",
            )))))
        }
    }
    let backend = spawn_backend_async(|_req: Request<Incoming>| async {
        Ok::<_, Infallible>(Response::new(Box::pin(Aborting { sent: false })))
    })
    .await;
    let port = spawn_gateway(dataplane_from(&proxy_yaml(backend))).await;

    let started = std::time::Instant::now();
    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        h1_client().get(uri(port, "/v1/abort")),
    )
    .await
    .expect("no hang on mid-body upstream abort")
    .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        envelope_code(&body_text(resp.into_body()).await.into_bytes()),
        "upstream_unavailable"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn upstream_speaking_invalid_http_is_502() {
    // A raw "backend" that answers with garbage instead of HTTP.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let _ = stream.write_all(b"not http at all\r\n\r\n").await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let gw_port = spawn_gateway(dataplane_from(&proxy_yaml(port))).await;
    let resp = h1_client().get(uri(gw_port, "/v1/garbage")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        envelope_code(&body_text(resp.into_body()).await.into_bytes()),
        "upstream_unavailable"
    );
}

#[tokio::test]
async fn head_request_is_proxied_and_returns_header_only_response() {
    let backend = spawn_backend_full(Arc::new(|req: Request<Incoming>| {
        let mut resp = Response::new(Full::new(Bytes::from_static(b"body-that-head-wont-carry")));
        resp.headers_mut()
            .insert("x-method", req.method().as_str().parse().unwrap());
        resp
    }))
    .await;
    let port = spawn_gateway(dataplane_from(&proxy_yaml(backend))).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .method("HEAD")
                .uri(uri(port, "/v1/meta"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("x-method").unwrap(), "HEAD");
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(
        bytes.is_empty(),
        "HEAD response must carry no body, got {} bytes",
        bytes.len()
    );
}

// --- 8. Mixed concurrent traffic through one route ---------------------------

#[tokio::test]
async fn twenty_concurrent_mixed_requests_no_cross_talk() {
    let backend = spawn_backend_async(|req: Request<Incoming>| async move {
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or("").to_string();
        // One body type serves both halves: `chunks` frames carrying the
        // request's own marker (small = 1 frame, stream = 4 spaced frames).
        struct M {
            left: u32,
            chunks: u32,
            marker: String,
            sleep: Pin<Box<tokio::time::Sleep>>,
            delay: Duration,
        }
        impl Body for M {
            type Data = Bytes;
            type Error = std::io::Error;
            fn poll_frame(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
                if self.left == 0 {
                    return Poll::Ready(None);
                }
                if self.sleep.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                self.left -= 1;
                let delay = self.delay;
                self.sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + delay);
                let sep = if self.chunks == 1 { "" } else { ":" };
                Poll::Ready(Some(Ok(Frame::data(Bytes::from(format!(
                    "[{}{sep}{}]",
                    self.marker,
                    self.chunks - self.left
                ))))))
            }
        }
        let body = if path == "/v1/stream" {
            M {
                left: 4,
                chunks: 4,
                marker: query,
                sleep: Box::pin(tokio::time::sleep(Duration::from_millis(25))),
                delay: Duration::from_millis(25),
            }
        } else {
            M {
                left: 1,
                chunks: 1,
                marker: format!("small-{query}"),
                sleep: Box::pin(tokio::time::sleep(Duration::ZERO)),
                delay: Duration::ZERO,
            }
        };
        Ok::<_, Infallible>(Response::new(Box::pin(body)))
    })
    .await;
    let port = spawn_gateway(dataplane_from(&proxy_yaml(backend))).await;

    let mut tasks = Vec::new();
    for i in 0..20u32 {
        let is_stream = i % 2 == 0;
        tasks.push(tokio::spawn(async move {
            let client = h1_client();
            if is_stream {
                let resp = client
                    .get(uri(port, &format!("/v1/stream?mk{i}")))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                let text = body_text(resp.into_body()).await;
                assert_eq!(
                    text,
                    format!("[mk{i}:1][mk{i}:2][mk{i}:3][mk{i}:4]"),
                    "stream {i} must see exactly its own frames in order"
                );
            } else {
                let resp = client
                    .get(uri(port, &format!("/v1/small?mk{i}")))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                assert_eq!(
                    body_text(resp.into_body()).await,
                    format!("[small-mk{i}1]"),
                    "request {i} must see exactly its own marker"
                );
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
}

// --- 9. Loop-1 fix regressions ------------------------------------------------

/// Strict WebSocket-style conformant backend: offers 101 ONLY when the
/// forwarded handshake carries `Upgrade: websocket` AND a Connection header
/// whose token list includes `upgrade` (RFC 6455/tungstenite strictness).
/// Anything less is a 400 — a gateway that strips or fails to rebuild
/// `Connection: Upgrade` can never establish a tunnel here.
#[tokio::test]
async fn conformant_websocket_backend_requires_connection_token_and_echo_tunnels() {
    let seen_connection: Arc<std::sync::Mutex<Option<String>>> =
        Arc::new(std::sync::Mutex::new(None));
    let sc = Arc::clone(&seen_connection);
    let backend = spawn_backend_async(move |mut req: Request<Incoming>| {
        let sc = Arc::clone(&sc);
        async move {
            let upgrade_ok = req
                .headers()
                .get("upgrade")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
            let conn = req
                .headers()
                .get("connection")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            *sc.lock().unwrap() = Some(conn.clone());
            let conn_has_upgrade = conn
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
            if !upgrade_ok || !conn_has_upgrade {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::new()))
                    .unwrap());
            }
            let on_upgrade = hyper::upgrade::on(&mut req);
            tokio::spawn(async move {
                let Ok(io) = on_upgrade.await else { return };
                let mut io = TokioIo::new(io);
                // Server->client push first: proves the tunnel carries both
                // directions, not just client echo.
                if io.write_all(b"hello-from-server").await.is_err() {
                    return;
                }
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
                .header("connection", "Upgrade")
                .header("upgrade", "websocket")
                .body(Full::new(Bytes::new()))
                .unwrap())
        }
    })
    .await;
    let port = spawn_gateway(dataplane_from(&proxy_yaml(backend))).await;

    let mut tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    tcp.write_all(
        b"GET /v1/ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n\
          Upgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
          Sec-WebSocket-Version: 13\r\n\r\n",
    )
    .await
    .unwrap();

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tcp.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    let head_text = String::from_utf8_lossy(&head);
    assert!(
        head_text.starts_with("HTTP/1.1 101"),
        "strict backend must accept the handshake (gateway rebuilt Connection):\n{head_text}"
    );
    assert!(
        head_text
            .to_ascii_lowercase()
            .contains("connection: upgrade"),
        "101 must relay Connection: Upgrade to the client:\n{head_text}"
    );

    // Server->client through the tunnel.
    let mut greeting = [0u8; 17];
    tcp.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"hello-from-server");
    // Client->server->client echo.
    tcp.write_all(b"client-ping").await.unwrap();
    let mut echoed = [0u8; 11];
    tcp.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"client-ping");

    let conn = seen_connection.lock().unwrap().clone().unwrap();
    assert!(
        conn.to_ascii_lowercase()
            .split(',')
            .any(|t| t.trim() == "upgrade"),
        "forwarded Connection must carry an upgrade token, got '{conn}'"
    );
}

/// Multiple inbound `Connection` header lines: tokens from EVERY line gate
/// stripping (`get_all`, not `get`), so `X-Second-Hop` named only on the
/// second line must still be stripped from the upstream request.
#[tokio::test]
async fn multiple_connection_headers_strip_tokens_from_every_line() {
    let backend = spawn_backend_full(Arc::new(|req: Request<Incoming>| {
        let second_hop = req
            .headers()
            .get("x-second-hop")
            .map(|_| "present")
            .unwrap_or("stripped");
        Response::new(Full::new(Bytes::from(second_hop.to_string())))
    }))
    .await;
    let port = spawn_gateway(dataplane_from(&proxy_yaml(backend))).await;

    let raw = raw_exchange(
        &format!("127.0.0.1:{port}"),
        b"GET /v1/hop HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\
          Connection: X-Second-Hop\r\nX-Second-Hop: secret\r\n\r\n",
    )
    .await;
    let text = String::from_utf8_lossy(&raw);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
    assert_eq!(
        body.trim(),
        "stripped",
        "header listed on the SECOND Connection line must be stripped:\n{text}"
    );
}

/// Tunneling with multiple inbound `Connection` lines: the rebuilt
/// Connection header must merge the surviving tokens with `Upgrade` so a
/// strict upstream still sees the upgrade token (merge semantics).
#[tokio::test]
async fn tunneled_upgrade_with_multiple_connection_headers_merges_tokens() {
    let seen_connection: Arc<std::sync::Mutex<Option<String>>> =
        Arc::new(std::sync::Mutex::new(None));
    let sc = Arc::clone(&seen_connection);
    let backend = spawn_backend_async(move |mut req: Request<Incoming>| {
        let sc = Arc::clone(&sc);
        async move {
            let conn = req
                .headers()
                .get_all("connection")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect::<Vec<_>>()
                .join(" | ");
            *sc.lock().unwrap() = Some(conn.clone());
            let has_upgrade = conn
                .replace('|', ",")
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
            if !req.headers().contains_key("upgrade") || !has_upgrade {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::new()))
                    .unwrap());
            }
            let on_upgrade = hyper::upgrade::on(&mut req);
            tokio::spawn(async move {
                let Ok(io) = on_upgrade.await else { return };
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
                .header("connection", "Upgrade")
                .header("upgrade", "chat")
                .body(Full::new(Bytes::new()))
                .unwrap())
        }
    })
    .await;
    let port = spawn_gateway(dataplane_from(&proxy_yaml(backend))).await;

    let mut tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    tcp.write_all(
        b"GET /v1/ws HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\
          Connection: X-Second-Hop, close\r\nUpgrade: chat\r\n\r\n",
    )
    .await
    .unwrap();

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tcp.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    let head_text = String::from_utf8_lossy(&head);
    assert!(
        head_text.starts_with("HTTP/1.1 101"),
        "merged Connection must satisfy the strict upstream:\n{head_text}"
    );
    tcp.write_all(b"ping-merged").await.unwrap();
    let mut echoed = [0u8; 11];
    tcp.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping-merged");

    let conn = seen_connection.lock().unwrap().clone().unwrap();
    let tokens: Vec<String> = conn
        .replace('|', ",")
        .split(',')
        .map(|t| t.trim().to_ascii_lowercase())
        .collect();
    for want in ["upgrade", "x-second-hop", "close", "keep-alive"] {
        assert!(
            tokens.contains(&want.to_string()),
            "rebuilt Connection must merge surviving token '{want}', got '{conn}'"
        );
    }
}

// --- 10. Redirect target validation (compile-time) -----------------------------

fn redirect_yaml(extras: &str) -> String {
    format!(
        "routes:\n\
         - name: moved\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /v1\n\
         \x20 action:\n\
         \x20   type: redirect\n\
         \x20   status: 302\n\
         {extras}\
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

fn assert_redirect_issue(extras: &str, field: &str) {
    let yaml = redirect_yaml(extras);
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.entity == "route" && i.name == "moved" && i.field == field),
        "expected an issue at route.moved.{field} for extras '{extras}', got {issues:?}"
    );
}

#[test]
fn redirect_validation_rejects_non_http_scheme() {
    assert_redirect_issue("    scheme: ftp\n", "action.scheme");
}

#[test]
fn redirect_validation_rejects_host_with_space() {
    assert_redirect_issue("    host: bad host.example\n", "action.host");
}

#[test]
fn redirect_validation_rejects_host_with_carriage_return() {
    // Raw YAML double-quoted string carries a real CR through the parser.
    assert_redirect_issue("    host: \"evil\\rhost\"\n", "action.host");
}

#[test]
fn redirect_validation_rejects_path_not_starting_with_slash() {
    assert_redirect_issue("    path: no-slash\n", "action.path");
}

#[test]
fn redirect_validation_accepts_clean_https_target() {
    let yaml = redirect_yaml("    scheme: https\n    host: example.com\n    path: /moved\n");
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues.is_empty(),
        "clean https redirect must produce no issues: {issues:?}"
    );
}

#[test]
fn hostile_redirect_host_is_rejected_at_compile_time() {
    // Defense-in-depth ordering: a control-character host never reaches the
    // dataplane, so the runtime HeaderValue fallback cannot be triggered by
    // config alone.
    let yaml = redirect_yaml("    scheme: https\n    host: \"evil\\rhost\"\n");
    let gateway = parse_gateway(&yaml).expect("parses");
    let state = ConfigState::new();
    match state.compile_and_publish(&gateway) {
        Err(CompileError::Validation(issues)) => {
            assert!(issues
                .iter()
                .any(|i| i.entity == "route" && i.field == "action.host"));
        }
        other => panic!("expected Validation error, got {other:?}"),
    }
}

// --- 11. IPv6 upstream endpoint -------------------------------------------------

#[tokio::test]
async fn ipv6_upstream_endpoint_gets_bracketed_authority_and_host() {
    // Backend on ::1; upstream endpoint address ::1. Without bracketing in
    // BOTH the dial URI and the Host header, hyper cannot parse the
    // authority and the request dies.
    let listener = TcpListener::bind("[::1]:0").await.unwrap();
    let backend_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(|req: Request<Incoming>| async move {
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(
                                req.headers()
                                    .get("host")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("-")
                                    .to_string(),
                            ))))
                        }),
                    )
                    .await;
            });
        }
    });

    let yaml = format!(
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
         \x20   - address: ::1\n\
         \x20     port: {backend_port}\n"
    );
    let port = spawn_gateway(dataplane_from(&yaml)).await;

    let resp = h1_client().get(uri(port, "/v1/v6")).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "request via ::1 upstream must succeed"
    );
    assert_eq!(
        body_text(resp.into_body()).await,
        format!("[::1]:{backend_port}"),
        "Host header received by the backend must be the bracketed authority"
    );
}

// --- 12. DataPlane construction serves immediately (single snapshot load) ------

#[tokio::test]
async fn dataplane_new_loads_once_and_serves_without_refresh() {
    // Behavior-level regression for the single-snapshot load: a DataPlane
    // built right after publish must serve correctly WITHOUT any refresh()
    // call. (If construction loaded twice or not at all, this fails.)
    let backend = spawn_backend_full(Arc::new(|_req: Request<Incoming>| {
        Response::new(Full::new(Bytes::from_static(b"ok")))
    }))
    .await;
    let port = spawn_gateway(dataplane_from(&proxy_yaml(backend))).await;
    let resp = h1_client().get(uri(port, "/v1/first")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_text(resp.into_body()).await, "ok");
}

// --- 13. DW-010 routing through real HTTP -------------------------------------

fn dw010_yaml(backend_port: u16, routes: &str) -> String {
    format!(
        "routes:\n\
         {routes}\
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

#[tokio::test]
async fn matching_cookie_and_query_reach_upstream_with_rewritten_path() {
    let backend = spawn_backend_full(Arc::new(|req: Request<Incoming>| {
        Response::new(Full::new(Bytes::from(req.uri().to_string())))
    }))
    .await;
    let yaml = dw010_yaml(
        backend,
        "- name: api\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20   query:\n\
         \x20     - {name: v, value: '2'}\n\
         \x20   cookies:\n\
         \x20     - {name: session, value: abc}\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         \x20   rewrite:\n\
         \x20     type: replace_prefix\n\
         \x20     prefix: /api\n\
         \x20     replacement: /internal\n",
    );
    let port = spawn_gateway(dataplane_from(&yaml)).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .uri(uri(port, "/api/orders?x=9&v=2"))
                .header("cookie", "other=1; session=abc")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_text(resp.into_body()).await,
        "/internal/orders?x=9&v=2",
        "criteria matched: rewrite applied AND query preserved upstream"
    );
}

#[tokio::test]
async fn non_matching_query_is_404_with_no_upstream_contact() {
    let hit = Arc::new(AtomicBool::new(false));
    let h = Arc::clone(&hit);
    let backend = spawn_backend_full(Arc::new(move |_req: Request<Incoming>| {
        h.store(true, Ordering::SeqCst);
        Response::new(Full::new(Bytes::from_static(b"should-not-happen")))
    }))
    .await;
    let yaml = dw010_yaml(
        backend,
        "- name: api\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20   query:\n\
         \x20     - {name: v, value: '2'}\n\
         \x20 action:\n\
         \x20   type: proxy\n",
    );
    let port = spawn_gateway(dataplane_from(&yaml)).await;

    let resp = h1_client().get(uri(port, "/api/x?v=wrong")).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "criteria miss must not fall through to any other route: 404"
    );
    assert_eq!(
        envelope_code(&body_text(resp.into_body()).await.into_bytes()),
        "no_route"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !hit.load(Ordering::SeqCst),
        "a criteria miss must never reach the upstream"
    );
}

#[tokio::test]
async fn respond_action_headers_reach_the_client() {
    let yaml = dw010_yaml(
        9,
        "- name: fixed\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /maintenance\n\
         \x20 action:\n\
         \x20   type: respond\n\
         \x20   status: 503\n\
         \x20   body: down for maintenance\n\
         \x20   headers:\n\
         \x20     x-retry-after-s: '30'\n\
         \x20     x-tag: dwara\n",
    );
    let port = spawn_gateway(dataplane_from(&yaml)).await;

    let resp = h1_client()
        .get(uri(port, "/maintenance/anything"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.headers().get("x-retry-after-s").unwrap(), "30");
    assert_eq!(resp.headers().get("x-tag").unwrap(), "dwara");
    assert_eq!(body_text(resp.into_body()).await, "down for maintenance");
}

#[tokio::test]
async fn query_string_survives_every_rewrite_kind() {
    let backend = spawn_backend_full(Arc::new(|req: Request<Incoming>| {
        Response::new(Full::new(Bytes::from(req.uri().to_string())))
    }))
    .await;
    let yaml = dw010_yaml(
        backend,
        "- name: strip\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /s\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         \x20   rewrite: {type: strip_prefix}\n\
         - name: replace\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /r\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         \x20   rewrite:\n\
         \x20     type: replace_prefix\n\
         \x20     prefix: /r\n\
         \x20     replacement: /replaced\n\
         - name: regex\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /x\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         \x20   rewrite:\n\
         \x20     type: regex\n\
         \x20     pattern: '^/x/(.*)$'\n\
         \x20     substitution: '/xr/$1'\n",
    );
    let port = spawn_gateway(dataplane_from(&yaml)).await;

    for (inbound, expected) in [
        ("/s/deep/path?keep=1", "/deep/path?keep=1"),
        ("/r/deep?keep=1", "/replaced/deep?keep=1"),
        ("/x/thing?keep=1", "/xr/thing?keep=1"),
    ] {
        let resp = h1_client().get(uri(port, inbound)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            body_text(resp.into_body()).await,
            expected,
            "query must survive the rewrite for '{inbound}'"
        );
    }
}

#[test]
fn relative_rewrite_substitution_is_rejected_at_compile_time() {
    // TEST EDIT (DW-010 hardening follow-up): this test previously pinned
    // the OLD behavior end-to-end — a substitution without a leading '/'
    // produced a relative path that could not be reparsed as a URI, and
    // the dataplane silently forwarded the original path. Validation now
    // rejects the shape at compile time, so the config must not publish.
    // The runtime no-op in proxy::handle remains only as defense-in-depth
    // for snapshots compiled before the rule.
    let yaml = dw010_yaml(
        9,
        "- name: rel\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /rel\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         \x20   rewrite:\n\
         \x20     type: regex\n\
         \x20     pattern: '^/rel/(.*)$'\n\
         \x20     substitution: 'v1/$1'\n",
    );
    let gateway = parse_gateway(&yaml).expect("test config parses");
    let state = ConfigState::new();
    match state.compile_and_publish(&gateway) {
        Err(CompileError::Validation(issues)) => assert!(
            issues
                .iter()
                .any(|i| i.field == "action.rewrite.substitution"),
            "expected a substitution issue, got: {issues:?}"
        ),
        other => panic!("expected Validation rejection, got {other:?}"),
    }
}
