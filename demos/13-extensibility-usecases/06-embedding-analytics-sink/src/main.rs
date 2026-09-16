//! Embedding demo: dwara-core as a library, with a custom
//! `AnalyticsSink`.
//!
//! The "your own analytics backend" recipe (docs-site "Extension use
//! cases and recipes"): when decisions or state must live in YOUR
//! infrastructure, you embed dwara-core in your own binary and
//! register trait implementations at startup. This binary demonstrates
//! the easiest seam, `extensions::analytics::AnalyticsSink`:
//!
//! 1. `StdoutSink` implements the trait the way the contract demands:
//!    `record` is a bounded-channel `try_send` (never blocks the
//!    dataplane; overload drops and reports, it never stalls a
//!    request), with one background task rendering each event.
//! 2. The gateway itself is embedded exactly the way
//!    crates/dwara-core/tests/proxy_plugins.rs constructs one: parse
//!    a YAML config, `ConfigState::compile_and_publish`, `DataPlane`,
//!    then a plain hyper serve loop calling `proxy::handle` -- except
//!    the embedder OWNS the completion seam, so it wraps `handle` and
//!    records one `Event` per completed request into its sink. That
//!    wrapper is where an embedding binary plugs its own pipeline in
//!    (dwara-bin attaches the embedded SQLite store at the same
//!    boundary).
//! 3. A tiny client fires real requests (200s and a 404) through the
//!    listener; the sink's printed records prove every completed
//!    request flowed through the custom backend.

use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use dwara_core::config::parse_gateway;
use dwara_core::extensions::analytics::{AnalyticsSink, Event};
use dwara_core::extensions::ExtensionsError;
use dwara_core::proxy::{self, DataPlane};
use dwara_core::snapshot::ConfigState;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::StatusCode;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::net::TcpListener;

/// Exclusive port for this demo (see the category README's port map).
const BIND: &str = "127.0.0.1:18251";

/// The embedded gateway config: one respond route plus the listener.
/// Zero upstreams -- nothing here needs a backend.
const CONFIG: &str = r#"
listeners:
  - name: embed-http
    address: 127.0.0.1
    port: 18251
    protocol: http

routes:
  - name: hello
    service: embed-service
    match:
      path:
        type: exact
        value: /hello
    action:
      type: respond
      status: 200
      body: '{"hello":"embedded"}'
      headers:
        Content-Type: application/json

services:
  - name: embed-service
    upstream: never-dialed
upstreams:
  - name: never-dialed
    load_balancer: round_robin
    protocol: http1
    endpoints:
      - address: 127.0.0.1
        port: 1
"#;

/// A custom `AnalyticsSink`: prints every accepted event to stdout.
///
/// Contract notes (extensions::analytics): `record` means "accepted",
/// not "rendered" -- a bounded enqueue that reports `Backend` on a
/// full channel and never blocks the caller. The printing happens on
/// a dedicated task; `printed` counts rendered events so the demo can
/// wait for the pipeline to drain.
struct StdoutSink {
    tx: tokio::sync::mpsc::Sender<Event>,
    printed: Arc<AtomicU64>,
}

impl StdoutSink {
    /// Register the sink: spawn its render loop and return the handle.
    fn spawn() -> Arc<Self> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(256);
        let printed = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&printed);
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                println!("sink: {}", render(&event));
                counter.fetch_add(1, Ordering::Relaxed);
            }
        });
        Arc::new(Self { tx, printed })
    }
}

/// One line per event -- the "warehouse record" this backend writes.
fn render(event: &Event) -> String {
    let attribute = |key: &str| {
        event
            .attributes
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .unwrap_or("-")
    };
    format!(
        "kind={} listener={} method={} path={} status={} duration_ms={:.2}",
        event.kind,
        event.listener.as_deref().unwrap_or("-"),
        event.method.as_deref().unwrap_or("-"),
        attribute("path"),
        event.status.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
        event.duration_ms.unwrap_or(0.0),
    )
}

#[async_trait]
impl AnalyticsSink for StdoutSink {
    async fn record(&self, event: Event) -> Result<(), ExtensionsError> {
        match self.tx.try_send(event) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Err(ExtensionsError::Backend(
                "stdout sink channel full; event dropped (never blocking the dataplane)".into(),
            )),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(
                ExtensionsError::Backend("stdout sink channel closed".into()),
            ),
        }
    }
}

/// The embedder's completion seam: serve one request through the real
/// dataplane, then record the finished request into the custom sink.
/// This wrapper is the embedding binary's own plumbing -- the same
/// boundary dwara-bin uses to attach its analytics store.
async fn record_and_handle(
    dp: &Arc<DataPlane>,
    sink: &StdoutSink,
    peer: std::net::IpAddr,
    req: Request,
) -> hyper::Response<proxy::ProxyBody> {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let started = Instant::now();

    let response = proxy::handle(dp, peer, req).await;

    let mut event = Event::request_now();
    event.listener = Some("embed-http".to_string());
    event.method = Some(method);
    event.status = Some(response.status().as_u16());
    event.duration_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
    event.attributes.push(("path".to_string(), path));
    // Fire-and-forget: a sink failure is logged, never fatal to the
    // request (the contract's failure model).
    if let Err(error) = sink.record(event).await {
        eprintln!("embed: sink dropped an event: {error}");
    }
    response
}

type Request = hyper::Request<Incoming>;

/// The embedded gateway: a plain hyper loop over `proxy::handle`
/// (h1 + upgrades), copied from the dwara-core integration harness.
async fn serve(dp: Arc<DataPlane>, sink: Arc<StdoutSink>) -> std::io::Result<()> {
    let listener = TcpListener::bind(BIND).await?;
    println!("embed: gateway listening on http://{BIND}");
    loop {
        let (stream, peer) = listener.accept().await?;
        let dp = Arc::clone(&dp);
        let sink = Arc::clone(&sink);
        tokio::spawn(async move {
            let service = service_fn(move |req: Request| {
                let dp = Arc::clone(&dp);
                let sink = Arc::clone(&sink);
                let peer_ip = peer.ip();
                async move {
                    Ok::<_, Infallible>(record_and_handle(&dp, &sink, peer_ip, req).await)
                }
            });
            let _ = AutoBuilder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(stream), service)
                .await;
        });
    }
}

#[tokio::main]
async fn main() {
    // 1) Build the dataplane from config (the test-suite pattern).
    let gateway = parse_gateway(CONFIG).expect("demo config parses");
    let state = Arc::new(ConfigState::new());
    state
        .compile_and_publish(&gateway)
        .expect("demo config publishes");
    let dp = DataPlane::new(Arc::clone(&state));

    // 2) Register the custom AnalyticsSink at startup.
    let sink = StdoutSink::spawn();
    println!("embed: custom AnalyticsSink registered (StdoutSink)");

    // 3) Serve on the demo port.
    let server = tokio::spawn(serve(Arc::clone(&dp), Arc::clone(&sink)));

    // 4) Fire real requests through the embedded gateway.
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let paths = ["/hello", "/hello", "/hello", "/no-such-route"];
    let mut ok_count = 0usize;
    for path in paths {
        let uri: hyper::Uri = format!("http://{BIND}{path}").parse().unwrap();
        let response = client.get(uri).await.expect("request completes");
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        println!("client: GET {path} -> {} ({} bytes)", status, bytes.len());
        if status == StatusCode::OK {
            ok_count += 1;
        }
    }

    // 5) Wait (bounded) for the sink to render every record, then
    //    verify the custom backend saw all of it.
    let expected = paths.len() as u64;
    let deadline = Instant::now() + Duration::from_secs(10);
    while sink.printed.load(Ordering::Relaxed) < expected && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let printed = sink.printed.load(Ordering::Relaxed);
    println!("embed: sink rendered {printed}/{expected} records");
    server.abort();

    if printed < expected || ok_count != 3 {
        std::process::exit(1);
    }
}
