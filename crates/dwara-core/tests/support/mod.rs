//! Shared helpers for the top-level integration suites.
//!
//! `tests/support/` is NOT a cargo test target (only top-level
//! `tests/*.rs` files are); each adopting suite declares `mod support;`
//! and this file is compiled into that suite's binary. Because no suite
//! uses every helper, unused items in any given binary are expected.
//!
//! Only helpers that were byte-identical (or trivially unifiable via a
//! parameter) across suites live here; per-suite variants stay local.

#![allow(dead_code)]

use std::convert::Infallible;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dwara_core::config::parse_gateway;
use dwara_core::proxy::{self, DataPlane};
use dwara_core::snapshot::ConfigState;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::net::TcpListener;

/// A port that nothing listens on (bind-then-drop).
pub fn dead_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

/// DW-021: gateway-generated error bodies are the JSON envelope; compare
/// by its stable `code` field.
pub fn envelope_code(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body).unwrap()["error"]["code"]
        .as_str()
        .unwrap()
        .to_string()
}

pub fn h1_client() -> Client<HttpConnector, Full<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

pub fn uri(port: u16, path: &str) -> Uri {
    format!("http://127.0.0.1:{port}{path}").parse().unwrap()
}

pub fn state_from(yaml: &str) -> Arc<ConfigState> {
    let gateway = parse_gateway(yaml).expect("test config parses");
    let state = Arc::new(ConfigState::new());
    state
        .compile_and_publish(&gateway)
        .expect("test config publishes");
    state
}

pub fn dataplane_from(yaml: &str) -> Arc<DataPlane> {
    DataPlane::new(state_from(yaml))
}

/// Gateway on an arbitrary bind address (needed for a ::1 peer). Returns
/// the host as it must appear in a URL (bracketed for IPv6) and the port.
pub async fn spawn_gateway_on(dp: Arc<DataPlane>, bind: &str) -> (String, u16) {
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

/// Serve the proxy dataplane on an ephemeral loopback port
/// (h1 + h2c + upgrades).
pub async fn spawn_gateway(dp: Arc<DataPlane>) -> u16 {
    spawn_gateway_on(dp, "127.0.0.1:0").await.1
}

/// Backend whose handler synchronously builds a full response.
pub async fn spawn_backend_full(
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
pub async fn spawn_backend_async<F, Fut, B>(handler: F) -> u16
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

/// Backend counting every request; `delay` is served per request. The
/// handler sees the FULL request body: `first` receives
/// (request number, method, path, body) and builds a response.
pub async fn spawn_backend<F>(first: F, delay: Duration) -> (u16, Arc<AtomicU64>)
where
    F: Fn(u32, Method, String, Bytes) -> Response<Full<Bytes>> + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&count);
    let handler = Arc::new(first);
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            let counter = Arc::clone(&counter);
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req: Request<Incoming>| {
                            let counter = Arc::clone(&counter);
                            let handler = Arc::clone(&handler);
                            let delay = delay;
                            async move {
                                let (parts, body) = req.into_parts();
                                let bytes = body.collect().await.unwrap().to_bytes();
                                let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                                tokio::time::sleep(delay).await;
                                Ok::<_, Infallible>(handler(
                                    n as u32,
                                    parts.method,
                                    parts.uri.path().to_string(),
                                    bytes,
                                ))
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    (port, count)
}

pub async fn body_of<B>(resp: Response<B>) -> (StatusCode, Bytes)
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: std::fmt::Debug + Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (parts.status, bytes)
}

pub async fn body_text<B>(body: B) -> String
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: std::fmt::Debug,
{
    String::from_utf8_lossy(&body.collect().await.unwrap().to_bytes()).into_owned()
}

/// Gateway YAML: one `/api` route to one upstream (optionally a SECOND
/// endpoint via `backend_port2`), with `gateway_extra` prepended as
/// gateway-level keys and `upstream_extra` spliced into the upstream
/// block.
pub fn gateway_yaml(
    gateway_extra: &str,
    backend_port: u16,
    backend_port2: Option<u16>,
    upstream_extra: &str,
) -> String {
    let second = match backend_port2 {
        Some(p) => format!(
            "\x20   - address: 127.0.0.1\n\
             \x20     port: {p}\n"
        ),
        None => String::new(),
    };
    format!(
        "{gateway_extra}routes:\n\
         - name: all\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {backend_port}\n{second}{upstream_extra}"
    )
}

/// Gateway YAML: one `/v1` route to one upstream, no extras.
pub fn proxy_yaml(backend_port: u16) -> String {
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
