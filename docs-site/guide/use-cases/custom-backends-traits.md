# Use case: your own rate limiting, config, cache, analytics, or secrets backend

Decisions or state must live in YOUR infrastructure: a shared
limiter in your store, config sourced from etcd, analytics into your
warehouse, secrets from your vault. The gateway must consult YOUR
backend, not the built-in one.

## Why the built-ins are not enough

| Built-in | What it does | Why it does not fit |
| --- | --- | --- |
| Local rate limiting | In-process token bucket per policy | Not shared across your fleet; state dies with the process |
| File config + watch | YAML on disk, hot reload | Your source of truth is etcd/Consul/a database |
| Embedded analytics store | SQLite inside the gateway | Your warehouse/queue is the destination of record |
| Local secrets file | File-backed secret references | Your vault is the source of truth |

This is not a gap in coverage — it is a different ownership boundary.
The built-ins are the OSS defaults; the seams exist so you can swap
them.

## Options, with tradeoffs

| Option | How | Integration | Failure semantics | Works today? |
| --- | --- | --- | --- | --- |
| **A. Extension traits** (recommended) | Implement `RateLimiter`, `ConfigSource`, `CacheStore`, `AnalyticsSink`, or `SecretSource` in a binary that embeds dwara-core; register at startup | Build-time (a binary you own) | You own them — deliberately | Yes (embedding) |
| B. HTTP callout plugin | Per-request `proxy_http_call` to your service | Config-time (hot loaded) | Route fails closed on callout failure | Yes — see [per-request external decisions](./per-request-external-decisions) |
| C. Enterprise backends | Redis/Vault implementations behind the enterprise edition | Build-time (ent build) | Shipped, supported | Yes (ent) |

B is not a substitute for stateful backends: a callout plugin has no
connection pooling or shared client for your store, which is exactly
why the traits exist. Enterprise backends (Redis, Vault) are just
other implementations of the same seams — option C when you want them
maintained for you.

## Implementation

`AnalyticsSink` is the easiest seam, so that is what the
[demo](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/06-embedding-analytics-sink)
swaps. The contract: `record` means "accepted", not "rendered" — a
bounded enqueue that reports `Backend` on a full channel and never
blocks the dataplane:

```rust
use dwara_core::extensions::analytics::{AnalyticsSink, Event};
use dwara_core::extensions::ExtensionsError;

/// A custom `AnalyticsSink`: prints every accepted event to stdout.
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

#[async_trait::async_trait]
impl AnalyticsSink for StdoutSink {
    async fn record(&self, event: Event) -> Result<(), ExtensionsError> {
        match self.tx.try_send(event) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Err(
                ExtensionsError::Backend(
                    "stdout sink channel full; event dropped (never blocking the dataplane)".into(),
                ),
            ),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(
                ExtensionsError::Backend("stdout sink channel closed".into()),
            ),
        }
    }
}
```

The embedder also owns the completion seam — it wraps the dataplane's
`proxy::handle`, and when a request completes it records one `Event`
(the same boundary dwara-bin uses to attach the embedded SQLite
store):

```rust
/// Serve one request through the real dataplane, then record the
/// finished request into the custom sink.
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
```

The gateway itself is embedded the way dwara-core's own integration
tests construct one — parse YAML, `ConfigState::compile_and_publish`,
`DataPlane::new`, then a plain hyper accept loop calling
`proxy::handle`:

```rust
#[tokio::main]
async fn main() {
    // 1) Build the dataplane from config.
    let gateway = parse_gateway(CONFIG).expect("config parses");
    let state = Arc::new(ConfigState::new());
    state.compile_and_publish(&gateway).expect("config publishes");
    let dp = DataPlane::new(Arc::clone(&state));

    // 2) Register the custom AnalyticsSink at startup.
    let sink = StdoutSink::spawn();

    // 3) Serve (a plain hyper loop over proxy::handle).
    tokio::spawn(serve(Arc::clone(&dp), Arc::clone(&sink))).await.ok();
}
```

The same shape swaps any of the five traits: implement, register at
startup, run your own front end. See [Extension
traits](../extension-traits) for each trait's contract.

## Configuration

There is no YAML for the trait itself — the swap happens in your
`main.rs`. The embedded gateway still takes ordinary dwara YAML (the
demo embeds a `respond` route plus a listener as a `const` string and
passes it to `parse_gateway`). Your `Cargo.toml` depends on
`dwara-core` as a path or registry dependency; the demo crate is
deliberately excluded from the gateway's own workspace so it builds
its own dependency tree.

## Operational notes

1. **Hot reload semantics**: build-time integration, no hot loading —
   swapping an implementation is a rebuild and a binary roll (use the
   [zero-downtime upgrade](../zero-downtime-upgrade)). Config the
   gateway loads still hot-reloads through `ConfigSource` publishes
   like any source.
2. **Failure behavior is yours**: the traits define WHERE an
   implementation is consulted, not what happens when your backend is
   down. Fail-open rate limiting at the edge is usually wrong —
   decide explicitly. `AnalyticsSink` is fire-and-forget by contract
   (never fatal to a request); the others are on decision paths.
3. **Limits**: `record`/equivalents run on request paths — bound your
   queues (the demo's 256-slot channel) and drop-and-report rather
   than block.
4. **Caching interactions**: a custom `CacheStore` IS the response
   cache — epoch semantics on plugin/config changes are the gateway's,
   storage policy is yours.

## Testing

Your implementation is ordinary Rust: unit-test the queue/failure
semantics, integration-test through the embedded gateway (fire real
requests, assert the backend saw them — the demo's `test.sh` asserts
on the binary's own output, including the unrouted 404s). [Plugin
testing](../plugin-testing) covers the plugin surfaces; the embedding
level is your binary's test suite.

## Status

Works today — requires an embedding build (a binary you compile that
links dwara-core as a library). The OSS build ships local defaults
for all five seams.

## Runnable demo

[`demos/13-extensibility-usecases/06-embedding-analytics-sink/`](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/06-embedding-analytics-sink)
is a standalone binary embedding dwara-core with the `StdoutSink`
above: every completed request (200s and 404s alike) flows through
the registered backend, with a bounded sink-drain self-check.
