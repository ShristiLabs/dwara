# Use case: per-request external decisions

The verdict genuinely must be computed per request by an external
service: entitlement checks, experiment bucketing, fraud scores,
per-user quotas. A proxy-wasm plugin asks the decision service over
`proxy_http_call`, applies the verdict to the request, and caches it
briefly so the per-request hop does not land on every call.

This recipe is fully live: `proxy_http_call` is supported today
(http/https, the plugin timeout clamped to [1ms, 5s], a 4 MiB
response cap, SSRF-checked targets, refused redirects, up to 8
callout rounds per phase, and non-2xx responses delivered as data the
plugin decides on). The [Plugin SDK: HTTP
callouts](../plugin-sdk#http-callouts-proxy_http_call) section has
the full contract.

## Why the built-ins are not enough

| Built-in | What it does | Why it does not fit |
| --- | --- | --- |
| [Authorization](../authorization) (`allowed_consumers`, `required_claims`) | Static allow-lists and claim gates | The verdict is computed per request by a service, not enumerable in config |
| [Rate limiting](../rate-limiting) policies | Quotas by key | Counts requests; does not consult an external decider |
| Snapshot publishing (the [migration recipe](./user-subset-migration)) | Decisions land in config and reload | Publisher-triggered freshness (seconds); wrong for real-time verdicts |

## Options, with tradeoffs

The snapshot-vs-callout tradeoff — both work now; choose by freshness
needs:

| Option | How | Latency | Freshness | Availability | Works today? |
| --- | --- | --- | --- | --- | --- |
| **A. Callout plugin + TTL cache** (this recipe) | `proxy_http_call` per uncached request, verdict cached in shared data | One hop on cache miss | Per request (bounded by the TTL window) | A new failure domain at the edge — size the timeout deliberately | Yes |
| B. Entitlement snapshot | The decider publishes verdicts into plugin config; reload applies | Zero (local lookup) | Per config reload (seconds) | No per-request dependency | Yes — the [migration recipe](./user-subset-migration) in full |
| C. Auth-layer header | An edge/IdP component decides and stamps a header; config gates on it | Zero at the gateway | Per token/session | Moved to the stamping component | Yes (no extension) |

Choose A when verdicts are genuinely per-request (real-time quotas,
experiments, fraud). Choose B when the decision set is stable on
second timescales — publish-on-change plus hot reload has no
per-request hop and no edge dependency. B also degrades more
gracefully: a stale snapshot keeps answering during decision-service
downtime, while A's cache window is your only buffer.

## Implementation

The complete plugin from the
[runnable demo](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/07-per-request-decision)
(Rust, proxy-wasm 0.2 SDK, `wasm32-wasip1`). At `request_headers` it
reads `x-user`, consults a VM-scoped shared-data cache, and on a miss
dispatches the callout and pauses; the delivered response carries the
verdict, which is applied as request headers the upstream (and the
access log) can see:

- `x-user` on the inbound request names the principal;
- `x-entitlement: allow|deny` is the applied verdict;
- `x-entitlement-source: service|cache` says whether THIS request hit
  the decision service or the in-plugin cache.

```rust
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use proxy_wasm::traits::{Context, HttpContext, RootContext};
use proxy_wasm::types::{Action, ContextType, LogLevel};

/// The decision service's base URI.
const DECISION_URI: &str = "http://127.0.0.1:18262";
/// Callout timeout: the fail-closed budget for one decision.
const CALLOUT_TIMEOUT: Duration = Duration::from_millis(400);
/// Cache entry lifetime.
const CACHE_TTL_MS: u128 = 2_000;
/// Shared-data key prefix for cached verdicts.
const CACHE_KEY_PREFIX: &str = "ent:";

#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(EntitlementRoot)
    });
}

struct EntitlementRoot;

impl Context for EntitlementRoot {}

impl RootContext for EntitlementRoot {
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(EntitlementFilter {
            user: String::new(),
        }))
    }
}

/// The per-request filter. `user` is captured at request_headers and
/// reused in the callout callback (one instance per request).
struct EntitlementFilter {
    user: String,
}

/// Milliseconds since the Unix epoch (the shared-data expiry clock).
fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

impl Context for EntitlementFilter {
    /// The delivered callout response: read the verdict header, apply
    /// it, cache it, and resume (returning Continue from this callback
    /// resumes the paused phase -- the SDK expresses the decision
    /// through the hostcalls made here, not a return value).
    fn on_http_call_response(
        &mut self,
        _token_id: u32,
        _num_headers: usize,
        _body_size: usize,
        _num_trailers: usize,
    ) {
        let verdict = self
            .get_http_call_response_header("x-verdict")
            .filter(|v| v == "allow" || v == "deny")
            .unwrap_or_else(|| "deny".to_string());
        // Cache the verdict behind the next request (VM-scoped shared
        // data: every instance of this module sees the entry) -- even
        // the deny, so a banned user does not hammer the service.
        let entry = format!("{verdict}|{}", now_ms() + CACHE_TTL_MS);
        let _ = self.set_shared_data(
            &format!("{CACHE_KEY_PREFIX}{}", self.user),
            Some(entry.as_bytes()),
            None,
        );
        let _ = proxy_wasm::hostcalls::log(
            LogLevel::Info,
            &format!("user={} verdict={} (service)", self.user, verdict),
        );
        if verdict == "deny" {
            // A deny is decided at the edge: short-circuit (the
            // upstream is never dialed).
            self.send_http_response(
                403,
                vec![("x-entitlement-source", "service")],
                Some(b"entitlement denied"),
            );
            return;
        }
        self.set_http_request_header("x-entitlement", Some(&verdict));
        self.set_http_request_header("x-entitlement-source", Some("service"));
    }
}

impl HttpContext for EntitlementFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        self.user = self
            .get_http_request_header("x-user")
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| "anonymous".to_string());

        // Cache hit: a fresh entry answers without a callout.
        let (cached, _cas) =
            self.get_shared_data(&format!("{CACHE_KEY_PREFIX}{}", self.user));
        if let Some(entry) = cached.and_then(|bytes| String::from_utf8(bytes).ok()) {
            if let Some((verdict, expiry)) = entry.split_once('|') {
                if let Ok(expiry_ms) = expiry.parse::<u128>() {
                    if expiry_ms > now_ms() {
                        let _ = proxy_wasm::hostcalls::log(
                            LogLevel::Info,
                            &format!("user={} verdict={} (cache)", self.user, verdict),
                        );
                        if verdict == "deny" {
                            self.send_http_response(
                                403,
                                vec![("x-entitlement-source", "cache")],
                                Some(b"entitlement denied"),
                            );
                            return Action::Continue;
                        }
                        self.set_http_request_header("x-entitlement", Some(verdict));
                        self.set_http_request_header("x-entitlement-source", Some("cache"));
                        return Action::Continue;
                    }
                }
            }
        }

        // Cache miss: dispatch the decision callout and pause. The
        // gateway performs the exchange and delivers
        // proxy_on_http_call_response (see the Context impl above). A
        // dispatch that cannot even register (BadArgument) answers
        // 503 from the plugin -- never a silent pass-through.
        match self.dispatch_http_call(
            DECISION_URI,
            vec![
                (":method", "GET"),
                (":path", &format!("/decide?user={}", self.user)),
                (":authority", "127.0.0.1:18262"),
            ],
            None,
            vec![],
            CALLOUT_TIMEOUT,
        ) {
            Ok(_token) => Action::Pause,
            Err(status) => {
                let _ = proxy_wasm::hostcalls::log(
                    LogLevel::Error,
                    &format!("dispatch_http_call failed: {status:?}"),
                );
                self.send_http_response(
                    503,
                    vec![("x-entitlement-source", "unavailable")],
                    Some(b"entitlement decision unavailable"),
                );
                Action::Continue
            }
        }
    }
}
```

## Configuration

The plugin declares only `request_headers`; the callout target lives
in the module (a config-driven URI is a small extension of the
pattern above — parse it at `on_configure` like the migration recipe
does):

```yaml
listeners:
  - name: decision-http
    address: 127.0.0.1
    port: 8080
    protocol: http

routes:
  - name: user-api
    service: user-api-service
    match: { path: { type: prefix, value: /api/ } }
    action: { type: proxy }
    plugins: [entitlement-guard]

services:
  - name: user-api-service
    upstream: user-api-pool

upstreams:
  - name: user-api-pool
    load_balancer: round_robin
    protocol: http1
    endpoints:
      - address: 127.0.0.1
        port: 9000

plugins:
  - name: entitlement-guard
    wasm: ./entitlement-guard/target/wasm32-wasip1/release/entitlement_guard.wasm
    phases: [request_headers]
```

## Operational notes

1. **Fail-open vs fail-closed is a deliberate choice**: the gateway
   fails a route CLOSED when a callout cannot COMPLETE (timeout,
   refused) — the plugin never sees an empty-response callback (the
   deliberate deviation from Envoy documented under [HTTP
   callouts](../plugin-sdk#http-callouts-proxy_http_call)). A
   fail-open recipe therefore needs a fallback the plugin applies
   WITHOUT a callout answer (a default verdict baked into the module
   or its config, served on paths that do not depend on the callout).
2. **The cache is your availability lever**: VM-scoped shared data
   (one map for every per-request instance of the module), keyed by
   principal, TTL-bounded. During decision-service downtime the
   cached window keeps answering; size the TTL against both
   freshness needs and blast radius (a denied user stays denied for
   the TTL too — that is the point of caching the deny).
3. **Hot reload semantics**: verdicts do not survive a config
   generation that re-instantiates the VM-scoped shared data — treat
   the cache as best-effort, not durable state. Config-side plugin
   changes reload normally.
4. **Latency budget**: budget the callout under the route's timeouts
   (the plugin timeout is clamped to [1ms, 5s]); every cache miss
   pays the hop. Up to 8 callout rounds per phase are allowed —
   chained lookups are possible but each adds a failure point.
5. **Limits**: 4 MiB response cap, SSRF-checked targets, redirects
   refused. Non-2xx verdicts arrive as data — the plugin above
   treats a `deny` verdict, not an HTTP error, as the refusal path.

## Testing

The pause -> callout -> callback -> resume sequence is testable at
all three [Plugin testing](../plugin-testing) levels: pure verdict
logic as unit tests, the callback contract through integration
harnesses, and `dwara replay` for regression. The demo asserts the
full behavior including both cache sides and the timeout failing
closed.

## Status

Works today, in every build — `proxy_http_call` is supported (see
the [hostcall support matrix](../plugin-sdk#hostcall-support-matrix)).

## Runnable demo

[`demos/13-extensibility-usecases/07-per-request-decision/`](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/07-per-request-decision)
runs the full recipe against a mock decision service: pause ->
callout -> response callback -> resume, the verdict stamped on the
forwarded request, a 2-second in-plugin TTL cache suppressing repeat
hits, a denied verdict short-circuiting at the edge, and the timeout
failing closed.
