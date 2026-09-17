# Building an extension

A complete walkthrough for replacing one of dwara's five swappable
subsystems with your own implementation: embedding dwara-core in a
binary you own, picking the right seam, a complete worked
`AnalyticsSink`, registration, rollout, and testing. Every code
block below is adapted from the verified embedding demo
[`demos/13-extensibility-usecases/06-embedding-analytics-sink/`](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/06-embedding-analytics-sink)
and the trait sources under `crates/dwara-core/src/extensions/`.

Read [Extension traits](./extension-traits) first for the option's
positioning and [Extension trait API](./extension-trait-api) for the
full signatures.

## What you will build

A binary that embeds the whole gateway as a library and swaps the
analytics destination for your own: every completed request --
including unrouted 404s -- is rendered by a custom sink instead of
the embedded SQLite store. The same shape swaps any of the five
traits.

## 1. Set up the crate

The embedding crate sits outside the cargo workspace (so
`cargo build --workspace` never picks it up) and depends on
dwara-core by path -- the crate setup the embedding demo uses:

```toml
# dwara-embed-analytics/Cargo.toml
[package]
name = "dwara-embed-analytics"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"
publish = false

[dependencies]
# The whole point: dwara-core as a PATH DEPENDENCY. Adjust the
# relative path to your checkout.
dwara-core = { path = "../dwara/crates/dwara-core" }
async-trait = "0.1"
bytes = "1"
http-body-util = "0.1"
hyper = { version = "1", features = ["client", "server", "http1"] }
hyper-util = { version = "0.1", features = ["tokio", "client", "client-legacy", "server", "http1"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "time"] }
```

If the crate lives inside the repository checkout, add its directory
to the `exclude` list of the root `Cargo.toml` (the same way
`plugins/examples` and `demos/13-extensibility-usecases` are
excluded). An excluded crate builds its own dependency tree: the
first build compiles all of dwara-core's dependencies and is slow;
later runs are incremental.

## 2. Pick a seam

Each trait is consumed by exactly one domain, so the hook point
decides which trait you implement:

| Trait | Hook point | Your implementation supplies |
|---|---|---|
| `RateLimiter` | The traffic-policy stage of the request pipeline (hot path) | Rate-limit decisions per scope |
| `ConfigSource` | The snapshot publish pipeline (parse, validate, compile, publish); pull-only, never per request | Where config generations come from |
| `CacheStore` | The response-caching stage after a route matches | Response cache get/set/invalidate |
| `AnalyticsSink` | Fire-and-forget after request completion -- never on the request path | Where completed-request records go |
| `SecretSource` | Config-compile time (cold start and every reload), never per request | How `${...}` secret references resolve |

`AnalyticsSink` is the easiest seam (one method, fire-and-forget), so
that is the worked example below.

## 3. Implement the sink

The contract (from the trait's source): `record` means "accepted",
not "rendered" -- a bounded enqueue that reports `Backend` on a full
channel and never blocks the dataplane. The rendering happens on a
dedicated background task. This is the demo's `StdoutSink`, verbatim:

```rust
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use dwara_core::extensions::analytics::{AnalyticsSink, Event};
use dwara_core::extensions::ExtensionsError;

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
```

A real backend replaces `println!` with your write path (a Kafka
producer, an HTTP shipper, your warehouse's ingest API); the shape --
bounded channel, `try_send`, drop-and-report under pressure -- stays.

## 4. Register it and serve

The embedder owns the completion seam: it wraps the dataplane's
`proxy::handle`, and when a request completes it builds one `Event`
(method, path, status, duration) and records it into the sink -- the
same boundary the stock gateway binary uses to attach its embedded
SQLite store.

```rust
use std::convert::Infallible;

use dwara_core::config::parse_gateway;
use dwara_core::proxy::{self, DataPlane};
use dwara_core::snapshot::ConfigState;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::net::TcpListener;

type Request = hyper::Request<Incoming>;

const BIND: &str = "127.0.0.1:18251";

/// The embedder's completion seam: serve one request through the real
/// dataplane, then record the finished request into the custom sink.
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
    // 1) Build the dataplane from config (parse, compile, publish).
    let gateway = parse_gateway(CONFIG).expect("config parses");
    let state = Arc::new(ConfigState::new());
    state.compile_and_publish(&gateway).expect("config publishes");
    let dp = DataPlane::new(Arc::clone(&state));

    // 2) Register the custom AnalyticsSink at startup.
    let sink = StdoutSink::spawn();

    // 3) Serve on your listener.
    serve(Arc::new(dp), sink).await.expect("serve failed");
}
```

`CONFIG` is your gateway YAML as a string (or read from a file and
passed to `parse_gateway`); the demo embeds a one-respond-route
config with a listener on the demo port. The wrapper is where an
embedding binary plugs its own pipeline in -- this is deliberately
the same plumbing the stock binary uses, not a private API.

## 5. A second seam in brief: SecretSource

The same shape swaps secret resolution. The trait is one async
method; `Ok(None)` is a miss, resolution happens at config-compile
time (never per request), and `Secret`'s `Debug` is redacted so a
log line can never leak the value:

```rust
use async_trait::async_trait;
use dwara_core::extensions::secrets::SecretSource;
use dwara_core::extensions::{ExtensionsError, Secret};
use std::collections::HashMap;

/// A SecretSource over your own store. Re-read on every resolve so a
/// rotation lands on the next reload -- do not cache.
struct MySecretSource {
    secrets: HashMap<String, String>,
}

#[async_trait]
impl SecretSource for MySecretSource {
    async fn resolve(&self, name: &str) -> Result<Option<Secret>, ExtensionsError> {
        match self.secrets.get(name) {
            Some(value) => Ok(Some(Secret::new(value.clone()))),
            None => Ok(None), // a miss: this source has no such secret
        }
    }
}
```

Note the failure-model difference from the file-backed source the
gateway ships: when the name IS the location (a file path), a
missing file is fail-closed `Io` -- but a lookup miss in your own
store is `Ok(None)`. Pick the semantics your source actually has and
document them; the shared `ExtensionsError` carries either.

## 6. Build and roll out

```sh
cargo build
./target/debug/dwara-embed-analytics
```

An extension trait implementation is compiled in: swapping it means
rebuilding your binary and restarting it -- there is no hot swap and
no config flag that selects a trait implementation at runtime.
Rollout is the same shape as a native filter's: a fronting load
balancer with health-check drain, or a zero-downtime SO_REUSEPORT
hand-off like [the stock gateway's upgrade
mechanism](./zero-downtime-upgrade). Config reloads still hot-apply;
only the trait implementation is build-time.

## 7. Test it

- **Self-check in the binary**: the demo fires real requests (200s
  and a 404), then waits a bounded time for the sink's rendered
  counter to reach the expected count, and exits non-zero if any
  record is missing. That drain-and-assert pattern is the cheapest
  honest test of a fire-and-forget seam.
- **Contract tests**: your implementation against the trait's
  contract -- for a sink: `record` never blocks (assert the bounded
  channel drops under pressure instead of stalling), `Ok` means
  accepted, and events carry no secret material.
- **Integration**: fire known traffic through the embedded gateway
  and assert the records your backend received match (kind, method,
  path, status, duration).

## Failure semantics

Each trait documents its own posture (see
[Extension trait API](./extension-trait-api)); for the worked
example: a sink failure is logged and the request is unaffected --
fire-and-forget means the dataplane must never stall on your
backend. Bound your buffers; drop-oldest under pressure; report
through `ExtensionsError::Backend` so the drop is countable.

## Hot-load expectations

None for code: rebuild plus restart (see rollout above). The
enterprise Redis/Vault backends are additional implementations of
these same traits compiled in behind the `ent` cargo feature -- an
edition choice at build time, not a runtime swap.

## Where to go next

- [Extension traits](./extension-traits) - the option landing page.
- [Extension trait API](./extension-trait-api) - full signatures for
  all five traits and the shared error type.
- Recipe: [custom backends (extension traits)](./use-cases/custom-backends-traits).
- Demo: [`demos/13-extensibility-usecases/06-embedding-analytics-sink/`](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/06-embedding-analytics-sink)
  (the source of the worked example).
