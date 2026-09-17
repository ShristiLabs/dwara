# Building a native filter

A complete walkthrough for writing a native plugin filter: setting up
a binary that embeds dwara-core, implementing `NativeFilter` with a
working filter, registering it at startup, building, running, and
rolling it out. Every code block below is adapted from verified
artifacts in the repository: the embedding pattern from
[`demos/13-extensibility-usecases/06-embedding-analytics-sink/`](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/06-embedding-analytics-sink)
and the dwara-core integration suite, and the filter logic from the
[`plugins/examples/header-guard/`](https://github.com/shristilabs/dwara/tree/main/plugins/examples/header-guard)
proxy-wasm example ported to native form.

Read [Native plugin filters](./native-plugins) first for the option's
positioning (compiled-in versus sandboxed, the phase contract) and
[Native filter API](./native-filter-api) for the full signatures.

## What you will build

The worked example is `header-guard` as a native filter: the route
only passes when the request carries a configured header with a
configured value; every other request is answered `403` by the filter
itself and the upstream is never dialed. In proxy-wasm form this
plugin calls `proxy_send_http_response`; in native form it returns
`FilterOutcome::LocalResponse` -- the same phase slot, the same
short-circuit, no sandbox and no ABI marshalling.

| Request | Result |
|---|---|
| no `x-guard-key` header | `403` `{"error":"forbidden by header-guard"}` |
| `x-guard-key: wrong` | `403` |
| `x-guard-key: open-sesame` | forwarded to the upstream |

## 1. Set up the crate

A native filter lives in a binary you own that embeds dwara-core as
a library. Mirror the embedding demo's crate setup: a crate
**outside the cargo workspace** (so `cargo build --workspace` never
picks it up) depending on dwara-core by path.

```toml
# dwara-embed-native/Cargo.toml
[package]
name = "dwara-embed-native"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"
publish = false

[dependencies]
# The whole point: dwara-core as a PATH DEPENDENCY. Adjust the
# relative path to your checkout.
dwara-core = { path = "../dwara/crates/dwara-core" }
serde_json = "1"
hyper = { version = "1", features = ["server", "http1"] }
hyper-util = { version = "0.1", features = ["tokio", "server", "http1"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net"] }
```

If the crate lives inside the repository checkout, add its directory
to the `exclude` list of the root `Cargo.toml` (the same way
`plugins/examples` and `demos/13-extensibility-usecases` are
excluded). An excluded crate builds its own dependency tree: the
first build compiles all of dwara-core's dependencies and is slow;
later runs are incremental.

## 2. Implement the filter

The decision logic is a plain, testable function; the trait methods
are thin shims over it. Put this in `src/main.rs` (or split into a
lib + bin once it grows):

```rust
use dwara_core::plugins::{FilterOutcome, LocalResponse, NativeFilter};

/// The 403 body a denied request is answered with.
const DENY_BODY: &[u8] = b"{\"error\":\"forbidden by header-guard\"}\n";

/// The parsed plugin configuration: {"header": ..., "value": ...}.
#[derive(Debug, Clone, PartialEq, Eq)]
struct GuardConfig {
    header: String,
    value: String,
}

impl GuardConfig {
    /// Parse the plugin entry's `config` string. This runs in the
    /// factory (below), so a bad config fails registration-time
    /// construction -- never a half-configured filter.
    fn parse(config: &Option<String>) -> Result<GuardConfig, String> {
        let raw = config.as_deref().unwrap_or("");
        let json: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| format!("invalid config: {e}"))?;
        let header = json["header"].as_str().unwrap_or("");
        let value = json["value"].as_str().unwrap_or("");
        if header.is_empty() || value.is_empty() {
            return Err("missing or empty string field".into());
        }
        Ok(GuardConfig { header: header.to_owned(), value: value.to_owned() })
    }
}

/// The decision for one request (the pure function unit tests exercise).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Allow,
    Deny,
}

fn evaluate(config: &GuardConfig, presented: Option<&str>) -> Verdict {
    match presented {
        Some(value) if !value.is_empty() && value == config.value => Verdict::Allow,
        _ => Verdict::Deny,
    }
}

/// The filter: header-guard's logic in native form.
#[derive(Debug, Clone)]
struct HeaderGuardFilter {
    config: GuardConfig,
}

impl NativeFilter for HeaderGuardFilter {
    // The only phase this filter hooks; the other three keep their
    // default implementations (Continue with the input unchanged).
    fn on_request_headers(&mut self, headers: Vec<(String, String)>) -> FilterOutcome {
        // Header names match case-insensitively; values match exactly
        // (the same semantics the WASM host applies).
        let presented = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(&self.config.header))
            .map(|(_, value)| value.as_str());
        match evaluate(&self.config, presented) {
            Verdict::Allow => FilterOutcome::Continue { headers, body: Vec::new() },
            Verdict::Deny => FilterOutcome::LocalResponse(LocalResponse {
                status: 403,
                headers: vec![("x-plugin-name".to_owned(), "header-guard".to_owned())],
                body: DENY_BODY.to_vec(),
            }),
        }
    }
}
```

Notes on the shape:

- The methods are synchronous, receive headers/body **by value**, and
  return the (possibly modified) input on `Continue`.
- A new filter instance is constructed per request through the
  factory, so fields are per-request state -- no shared mutable
  state, no locking.
- `Error(String)` exists for genuine failures: the route answers 500
  and the message is logged server-side, never sent to the client.

## 3. Wire registration into the binary

The gateway itself is embedded the way the dwara-core integration
suite constructs one: parse a YAML config, compile and publish it,
build the `DataPlane`, register the factory, then serve.

```rust
use std::convert::Infallible;
use std::sync::Arc;

use dwara_core::config::parse_gateway;
use dwara_core::proxy::{self, DataPlane};
use dwara_core::snapshot::ConfigState;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::net::TcpListener;

const BIND: &str = "127.0.0.1:18261";

const CONFIG: &str = r#"
listeners:
  - name: guard-http
    address: 127.0.0.1
    port: 18261
    protocol: http

routes:
  - name: guarded
    service: echo-service
    match:
      path: { type: prefix, value: /guard/ }
    action: { type: proxy }
    auth_required: false
    plugins: [header-guard]

services:
  - name: echo-service
    upstream: echo-upstream

upstreams:
  - name: echo-upstream
    load_balancer: round_robin
    protocol: http1
    endpoints:
      - address: 127.0.0.1
        port: 18102

plugins:
  - name: header-guard
    native: header-guard
    phases: [request_headers]
    config: '{"header":"x-guard-key","value":"open-sesame"}'
"#;

type Request = hyper::Request<Incoming>;

#[tokio::main]
async fn main() {
    // 1) Build the dataplane from config.
    let gateway = parse_gateway(CONFIG).expect("config parses");
    let state = Arc::new(ConfigState::new());
    state.compile_and_publish(&gateway).expect("config publishes");
    let dp = Arc::new(DataPlane::new(Arc::clone(&state)));

    // 2) Register the native filter BEFORE serving traffic. The
    //    factory parses the plugin's `config` string; an Err fails
    //    the per-request chain construction (500 plugin_unavailable),
    //    never a silently unguarded route.
    dp.native_plugin_registry()
        .register(
            "header-guard",
            Box::new(|config: &Option<String>| {
                let parsed = GuardConfig::parse(config)?;
                Ok(Box::new(HeaderGuardFilter { config: parsed })
                    as Box<dyn NativeFilter>)
            }),
        )
        .expect("register header-guard");

    // 3) Serve: a plain hyper loop over proxy::handle.
    serve(dp).await.expect("serve failed");
}

async fn serve(dp: Arc<DataPlane>) -> std::io::Result<()> {
    let listener = TcpListener::bind(BIND).await?;
    println!("gateway listening on http://{BIND}");
    loop {
        let (stream, peer) = listener.accept().await?;
        let dp = Arc::clone(&dp);
        tokio::spawn(async move {
            let peer_ip = peer.ip();
            let service = service_fn(move |req: Request| {
                let dp = Arc::clone(&dp);
                async move {
                    Ok::<_, Infallible>(proxy::handle(&dp, peer_ip, req).await)
                }
            });
            let _ = AutoBuilder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(stream), service)
                .await;
        });
    }
}
```

The config selects the filter with `native: header-guard` -- the
registered name -- exactly as a WASM plugin is selected with a
`wasm:` path. The `phases` list and route `plugins` reference work
identically for both.

## 4. Build and run

```sh
cargo build
python3 plugins/examples/echo-upstream.py &   # any echo upstream on 18102
./target/debug/dwara-embed-native
```

Verify:

```sh
curl -i http://127.0.0.1:18261/guard/hello                    # 403
curl -i -H 'x-guard-key: wrong' http://127.0.0.1:18261/guard/hello   # 403
curl -i -H 'x-guard-key: open-sesame' http://127.0.0.1:18261/guard/hello  # 200, echoed
```

## 5. Roll it out

A native filter is compiled in: changing the filter means rebuilding
your binary and restarting it. There is no hot swap. Two rollout
shapes:

- A fronting load balancer with health-check drain: stop routing to
  the old instance once `/readyz` goes 503, restart, re-admit. Good
  enough when seconds-per-instance of drain are tolerable.
- A zero-downtime hand-off like the stock gateway's own upgrade
  mechanism (SO_REUSEPORT plus a `SIGUSR2` spawn-and-drain): see
  [Zero-downtime upgrade](./zero-downtime-upgrade) for the pattern
  your binary can replicate.

Config-only changes (which routes reference the filter, its `config`
string, its `phases`) hot-reload like any other config -- it is the
filter *code* that requires the rebuild.

## 6. Test it

- **Unit**: `evaluate` is a pure function -- test the verdict table
  (missing header, wrong value, empty value, exact match) with plain
  `cargo test`, no gateway involved. The filter struct itself is also
  directly constructible in tests: call `on_request_headers` and
  `assert_eq!` the returned `FilterOutcome` (`LocalResponse` derives
  `PartialEq`).
- **Integration**: the embedded binary *is* the harness -- or drive
  the same registration against a `DataPlane` built from a test
  config, the pattern the dwara-core integration suite uses: register
  the factory, fire real requests through the listener, assert the
  client-visible outcome (403 body and header; upstream saw nothing
  on deny).
- **Regression**: keep the verdict table pinned in CI so a refactor
  cannot silently flip a deny into an allow.

## Honest constraints

- **No built-in native filters ship with the stock gateway binary**,
  and filter registration is an embedder seam: there is no
  config-file or plugin-file mechanism that loads a native filter
  into `dwara` as published. If you want loadable, config-attached
  logic, use [proxy-wasm plugins](./proxy-wasm-plugins).
- You own the binary: builds, CVE scanning, and rollout are yours.
- The filter runs in-process with no sandbox: a panic in a filter is
  a gateway bug, not a contained trap. Keep filters small and
  test them like gateway code.

## Failure semantics

| Condition | Client sees |
|---|---|
| Factory errors while the per-request chain is built (bad config string, name not registered) | 500 `plugin_unavailable`, never a silent skip |
| Filter returns `FilterOutcome::Error` | 500 `plugin_failed` (message logged server-side only) |
| Filter returns `FilterOutcome::LocalResponse` | that response, verbatim; upstream never dialed |

Failures are scoped to the referencing route only; routes that do not
reference the filter are unaffected.

## Hot-load expectations

None for code: rebuild plus restart (see rollout above). Config
attachment (`native:` name selection, `phases`, `config` string)
follows normal config reload semantics.

## Where to go next

- [Native plugin filters](./native-plugins) - the option landing
  page.
- [Native filter API](./native-filter-api) - full signatures: the
  trait, `FilterOutcome`, the registry.
- Recipes: [custom request authentication](./use-cases/custom-request-auth)
  (the same guard logic as a proxy-wasm plugin),
  [user-subset API migration](./use-cases/user-subset-migration).
- Demos: [`demos/08-extensibility/`](https://github.com/shristilabs/dwara/tree/main/demos/08-extensibility)
  (`test-01-native-plugins.sh`),
  [`plugins/examples/header-guard/`](https://github.com/shristilabs/dwara/tree/main/plugins/examples/header-guard)
  (the WASM original of this example).
