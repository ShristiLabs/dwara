# Extension API

Signature-level reference for every extension surface: the proxy-wasm
hostcalls the gateway's WASM host registers, the native filter trait,
the five extension traits, and the nano-service handler ABI. Every
entry below was extracted from the host source
(`crates/dwara-core/src/wasm/`, `crates/dwara-core/src/plugins/`,
`crates/dwara-core/src/extensions/`, `crates/dwara-core/src/dataplane/nano_service.rs`).

This page is deliberately dry: parameters, returns, statuses, and
error codes. For workflow-oriented prose (quickstarts, recipes,
lifecycle, troubleshooting) see the linked guides. The full
generated Rust API documentation for the workspace crates is
published at <https://shristilabs.github.io/dwara/api/dwara_core/>
(built by CI from `main`; public items only).

Upstream references:

- Rust proxy-wasm SDK (the crate `dwara-cli plugin new` scaffolds
  against): <https://docs.rs/proxy-wasm/0.2.5/proxy_wasm/>
- proxy-wasm ABI specification (the source of truth for every import
  name, parameter, and wire layout used below):
  <https://proxy-wasm.spec.vec.io/>

## Proxy-wasm hostcalls

The host registers every import under the module name `env`. Where a
hostcall has a Rust SDK spelling, the table names it; parameters and
returns are given in SDK terms (strings and byte vectors, not ABI
pointers). Status values below (`Supported` / `Partial` / `Stub`)
match the [hostcall support matrix](../guide/plugin-sdk#hostcall-support-matrix)
-- that page carries the prose; this one carries the signatures.

### Status codes the host can return

Every hostcall returns a proxy-wasm status integer. The values dwara
can actually answer with:

| Status | Value | Returned by |
|---|---|---|
| `Ok` | `0` | Success (including "not found, zero values written" reads). |
| generic error | `1` | Invalid pointer/size arguments, unknown buffer or map selector, corrupt map serialization, allocation failure in plugin memory. Indicates a bug or ABI mismatch, not a branchable condition. |
| `BadArgument` | `2` | `proxy_http_call` only: unparsable or non-`http(s)` URI, invalid dispatch header map, or a request-head validation failure (see [Callouts](#callouts)). The SDK surfaces it as `Err(Status::BadArgument)` from `dispatch_http_call`. |
| `CasMismatch` | `8` | `proxy_set_shared_data` only: CAS mismatch or a set that would exceed the shared-data caps. The SDK surfaces it as `Err(Status::CasMismatch)` from `set_shared_data`. |
| `InternalFailure` | `10` | Every stubbed hostcall. See [Stubs](#stubs) for which SDK wrappers trap versus return `Err` on this status. |

The Rust SDK maps only specific statuses to `Err` per wrapper; every
other non-Ok status panics the module (which the host reports as a
plugin failure). The three statuses above are the ones dwara emits
deliberately.

### Header operations

Selector: the MapType integer (`bt`). Valid selectors: request
headers `0`, request trailers `1`, response headers `2`, response
trailers `3`, callout response headers `6`, callout response trailers
`7`. Trailer maps read as empty and their writes are accepted and
discarded (trailers are not plumbed through the pipeline).

| Hostcall | SDK surface | Parameters -> return | Status |
|---|---|---|---|
| `proxy_get_header_map_pairs` | `get_http_request_headers()` / `get_http_response_headers()` / `get_http_call_response_headers()` -> `Vec<(String, String)>` | `bt` -> the whole map | Supported |
| `proxy_set_header_map_pairs` | `set_http_request_headers(Vec<(String, String)>)` / `set_http_response_headers(...)` | `bt`, the whole map -> unit | Partial |
| `proxy_get_header_map_value` | `get_http_request_header(name: &str)` / `get_http_response_header(name: &str)` -> `Option<String>` | `bt`, `key: String` -> value or empty | Supported |
| `proxy_add_header_map_value` | `add_http_request_header(name, value)` / `add_http_response_header(name, value)` | `bt`, `key`, `value` -> unit | Supported |
| `proxy_replace_header_map_value` | (SDK: `set_map`-level; no typed wrapper) | `bt`, `key`, `value` -> unit | Supported |
| `proxy_remove_header_map_value` | `remove_http_request_header(name)` / `remove_http_response_header(name)` | `bt`, `key` -> unit | Supported |

Caveats:

- `get`/`add`/`replace`/`remove` lookups are case-insensitive; `add`
  appends (duplicate names possible); `replace` replaces the first
  case-insensitive match or appends; `remove` removes every
  case-insensitive match. A missing key on `get` reads as empty
  (the SDK maps that to `None`).
- `proxy_set_header_map_pairs` replaces the **whole** map and cannot
  carry non-UTF-8 values (untouched headers keep theirs). The map
  wire format is the spec/SDK serialization: LE u32 entry count, LE
  u32 `(key_len, value_len)` table, then NUL-terminated strings.
- The callout response map (selector `6`) is readable only inside
  `on_http_call_response`; it carries `:status` first, then the
  ordinary headers with hop-by-hop headers stripped. Writes to it are
  discarded.

### Buffers and bodies

Selector: the BufferType integer (`bt`). Valid selectors: request
body `0`, response body `1`, callout response body `4`, VM
configuration `6`, plugin configuration `7`.

| Hostcall | SDK surface | Parameters -> return | Status |
|---|---|---|---|
| `proxy_get_buffer_bytes` | `get_http_request_body(offset, max_size)` / `get_http_response_body(...)` / `get_http_call_response_body(...)` / `get_plugin_configuration()` / `get_vm_configuration()` -> `Option<Vec<u8>>` | `bt`, `offset: usize`, `max_size: usize` -> chunk | Supported |
| `proxy_get_buffer_status` | `get_http_request_body_size()` / `get_http_response_body_size()` -> `Option<usize>` | `bt` -> length | Supported |
| `proxy_set_buffer_bytes` | `set_http_request_body(offset, size, data)` / `set_http_response_body(offset, size, data)` | `bt`, `offset`, data -> unit | Partial |

Caveats:

- `proxy_set_buffer_bytes` writes the request and response bodies
  only; the write **replaces the buffer from `offset` to the end**
  (spec-range in-place edits are not supported). Configuration
  buffers are read-only.
- A body phase only runs when the body is buffered (route
  `limits.max_body_bytes`, default 1 MiB); over-cap answers 500
  `plugin_body_too_large`. Streaming and content-encoded responses
  skip `response_body`.
- The configuration buffers are how `on_configure` receives the
  plugin `config` string (bytes) and `on_vm_start` receives the VM
  buffer (empty today).

### Local response

| Hostcall | SDK surface | Parameters -> return | Status |
|---|---|---|---|
| `proxy_send_local_response` | `send_http_response(status: u16, headers: Vec<(String, String)>, body: Option<Vec<u8>>)` | `status_code: i32`, status details (ignored), `body`, `headers` (spec map serialization), gRPC status (ignored) -> unit | Supported |
| `proxy_send_http_response` | none (dwara's original spelling) | `status: i32`, `headers` (**legacy** big-endian map layout), `body`, trailers (ignored) -> unit | Supported |

Caveats:

- Both spellings store the same local response and end the stream:
  the proxy returns it immediately, the upstream is never dialed.
- The spec spelling parses the SDK map serialization (an empty map is
  the 4-byte LE count 0); the legacy spelling parses dwara's
  big-endian `(u32 key_len, key, u32 val_len, val)` layout. Modules
  built with the Rust SDK must use `send_http_response` (the SDK
  imports the spec name).
- A non-empty body without a content-type defaults to
  `application/json`.

### Logging and time

| Hostcall | SDK surface | Parameters -> return | Status |
|---|---|---|---|
| `proxy_log` | `log(level: LogLevel, message: &str)` | `level: i32` (0 Trace .. 5 Critical), `message: String` -> unit | Partial |
| `proxy_get_log_level` | (ABI-level) | -> `level: i32` | Partial |
| `proxy_get_current_time_nanoseconds` | `get_current_time()` | -> nanoseconds since Unix epoch (`u64`) | Supported |

Caveats:

- `proxy_log` lines (and WASI `fd_write` bytes, including panic
  output) land in a per-instance buffer capped at **64 KiB**: past
  the cap the head of the overflowing line plus a truncation marker
  is kept and further lines are dropped. The buffer is not surfaced
  to the gateway log today; no level filtering.
- `proxy_get_log_level` always reports `Info`.
- dwara's original spelling `proxy_get_current_time` shares the same
  implementation.

### Shared state

| Hostcall | SDK surface | Parameters -> return | Status |
|---|---|---|---|
| `proxy_get_shared_data` | `get_shared_data(key: &str)` -> `Option<(Vec<u8>, Option<u32>)>` | `key: String` -> value bytes + CAS | Partial |
| `proxy_set_shared_data` | `set_shared_data(key: &str, value: Option<&[u8]>, cas: Option<u32>)` -> `Result<(), Status>` | `key`, `value: Vec<u8>`, `cas: u32` -> status | Partial |

Caveats:

- The store is **VM-scoped**: one map per compiled plugin module,
  shared by every per-request instance of that plugin; not shared
  across different plugins; a plugin definition change starts a fresh
  map on reload.
- Caps per module: 1024 entries and 1 MiB of key + value bytes. An
  over-cap set fails with `CasMismatch` (the SDK's only clean
  `set_shared_data` error); entries are never evicted.
- `cas` of `0` means write unconditionally; a positive `cas` that
  does not match the current version fails with `CasMismatch`.
  The CAS check, cap check, and write are one critical section
  (racing instances cannot interleave).

### Metrics

| Hostcall | SDK surface | Parameters -> return | Status |
|---|---|---|---|
| `proxy_define_metric` | `define_metric(MetricType, name: &str)` -> `u32` | `metric_type: i32` (0 Counter, 1 Gauge, 2 Histogram), `name: String` -> metric id | Partial |
| `proxy_record_metric` | `record_metric(metric_id: u32, value: f64)` | name bytes, `value: f64` -> unit | Partial |
| `proxy_increment_metric` | `increment_metric(metric_id: u32, increment: f64)` | name bytes, `increment: f64` -> unit | Partial |
| `proxy_get_metric` | `get_metric(metric_id: u32)` -> `f64` | name bytes -> `f64` | Partial |

Caveats:

- The per-instance metric map is keyed by the **name bytes** the ABI
  call carries; the metric-id return pointer of
  `proxy_define_metric` is not populated, so SDK wrappers that pass
  the numeric id back find no metric (the call stays `Ok`).
- Metrics are per-instance (reset every request) and are **not
  exported** to `/metrics`. Emit gateway-visible signals from plugin
  config or headers instead.

### Callouts

| Hostcall | SDK surface | Parameters -> return | Status |
|---|---|---|---|
| `proxy_http_call` | `dispatch_http_call(uri: &str, headers: Vec<(String, String)>, body: Option<&[u8]>, trailers: Vec<(String, String)>, timeout: Duration)` -> `Result<u32, Status>` | `upstream` (absolute URI string), dispatch headers (spec map serialization), `body`, trailers (ignored), `timeout_ms: i32` -> `token: u32` | Supported |

Returns `Ok` + token, `BadArgument` (unparsable or non-`http(s)`
URI, invalid dispatch map, or request-head validation failure), or
`InternalFailure` (token write failure). The response arrives via
the `proxy_on_http_call_response(token_id, num_headers, body_size,
num_trailers)` export; read it with the callout map/buffer selectors
(`6` and `4`). Dispatching a callout pauses the phase regardless of
the returned action.

The full contract -- pause/resume, pseudo-headers, guardrails
(timeout clamp 1 ms .. 5 s, 8 callout rounds per phase, 4 MiB
response cap, refused redirects, SSRF filter), and failure
semantics -- is documented once in
[Plugin SDK: HTTP callouts](../guide/plugin-sdk#http-callouts-proxy_http_call).

### Properties, contexts, streams

| Hostcall | SDK surface | Parameters -> return | Status |
|---|---|---|---|
| `proxy_get_property` | `get_property(path: Vec<&str>)` -> `Option<Vec<u8>>` | path parts -> value | Stub |
| `proxy_set_property` | `set_property(path, value)` | path parts, value -> unit | Stub |
| `proxy_set_effective_context` | `set_effective_context(id: u32)` | `context_id: i32` -> unit | Partial |
| `proxy_continue_stream` | `resume_stream()` | `bt: i32` -> unit | Partial |
| `proxy_close_stream` | `close_stream()` | `bt: i32` -> unit | Partial |
| `proxy_done` | `done()` | -> unit | Supported |
| `proxy_get_status` | `get_grpc_status()` -> `Option<i32>` | -> code + message | Partial |

Caveats:

- `proxy_get_property` returns an empty value for every path; no
  properties resolve. `proxy_set_property` is a no-op reporting
  success.
- `proxy_set_effective_context` records the ID; cross-context
  callbacks are not re-dispatched.
- `proxy_continue_stream` is a no-op reporting success;
  `proxy_close_stream` ends the stream (same as returning
  `Action::EndStream`).
- `proxy_get_status` always answers `Ok` with code `0` and no
  message (no gRPC callout is ever in flight); the SDK reads that as
  `(0, None)`. It must answer `Ok` because the SDK wrapper panics on
  any non-Ok status.

### Stubs

Registered with their spec signatures so SDK modules instantiate,
but unsupported. All return `InternalFailure` (`10`):

`proxy_grpc_call`, `proxy_grpc_stream`, `proxy_grpc_send`,
`proxy_grpc_cancel`, `proxy_grpc_close`,
`proxy_register_shared_queue`, `proxy_resolve_shared_queue`,
`proxy_dequeue_shared_queue`, `proxy_enqueue_shared_queue`,
`proxy_set_tick_period_milliseconds`,
`proxy_call_foreign_function`.

Of the SDK wrappers over these, only `dispatch_grpc_call` and
`open_grpc_stream` map `InternalFailure` to a clean `Err`; the rest
panic, which traps the module and fails the referencing route closed
(500 `plugin_failed`). There is no tick loop (`on_tick` never fires)
and no shared-queue mechanism.

### WASI subset (`wasm32-wasip1`)

Modules built for `wasm32-wasip1` import a small
`wasi_snapshot_preview1` set; the host stubs exactly these:

| Import | Behavior |
|---|---|
| `environ_sizes_get` / `environ_get` | Empty environment. |
| `fd_write` | Routed into the per-instance log buffer under the 64 KiB cap. |
| `proc_exit(code)` | Traps the instance (reported like any plugin failure). |
| `random_get` | Non-cryptographic (splitmix64); not for key material. |
| `clock_time_get` | Wall-clock nanoseconds. |
| `sched_yield` | No-op. |

Any other WASI import fails instantiation, and referencing routes
fail closed.

## Native filter API

Compiled-in Rust filters implement
`dwara_core::plugins::NativeFilter` (from
`crates/dwara-core/src/plugins/filter.rs`). The trait is
dyn-compatible; every method is synchronous and receives the current
headers/body **by value**; default implementations continue with the
input unchanged.

```rust
pub trait NativeFilter: Send + Sync {
    fn on_request_headers(&mut self, headers: Vec<(String, String)>) -> FilterOutcome;
    fn on_request_body(&mut self, body: Vec<u8>) -> FilterOutcome;
    fn on_response_headers(&mut self, headers: Vec<(String, String)>) -> FilterOutcome;
    fn on_response_body(&mut self, body: Vec<u8>) -> FilterOutcome;
}
```

Phase placement: `on_request_headers` runs after route resolution,
before authn; `on_request_body` after authn/authz/rate-limit, before
upstream; `on_response_headers` after the upstream responds, before
masking; `on_response_body` after masking, before compression.

The outcome of each callback:

```rust
pub enum FilterOutcome {
    Continue { headers: Vec<(String, String)>, body: Vec<u8> },
    LocalResponse(LocalResponse),
    Error(String),
}

pub struct LocalResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
```

- `Continue` threads the (possibly modified) headers/body back into
  the chain; pass the empty `Vec` for the side you did not receive.
- `LocalResponse` short-circuits: the proxy returns it immediately.
- `Error` answers 500 (mirroring a WASM trap); the message is
  logged, never sent to the client.

### Registration

Registration is an embedder seam
(`crates/dwara-core/src/plugins/registry.rs`): a factory parses the
plugin's opaque `config` string (the same blob a WASM plugin gets in
`proxy_on_configure`) and produces a boxed filter.

```rust
pub type NativeFilterFactory =
    Box<dyn Fn(&Option<String>) -> Result<Box<dyn NativeFilter>, String> + Send + Sync>;

pub struct NativeRegistry { /* name -> factory map, clone-shared */ }

impl NativeRegistry {
    pub fn register(
        &self,
        name: impl Into<String>,
        factory: NativeFilterFactory,
    ) -> Result<(), RegistryError>;
    pub fn create(
        &self,
        name: &str,
        config: &Option<String>,
    ) -> Result<Box<dyn NativeFilter>, RegistryError>;
    pub fn contains(&self, name: &str) -> bool;
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn names(&self) -> Vec<String>;
}

pub enum RegistryError {
    NotFound { name: String },
    Construction { name: String, error: String },
    Duplicate { name: String },
}
```

The embedding binary reaches the registry through the dataplane
accessor:

```rust
pub fn native_plugin_registry(&self) -> &NativeRegistry   // on dwara_core::dataplane::DataPlane
```

Config selects a registered filter with `native: <name>` on a plugin
entry (exactly one of `wasm:` / `native:`, plus a non-empty `phases`
list). A factory error while the chain is built answers 500
`plugin_unavailable`, never a silent skip. Workflow prose:
[Native plugin filters](../guide/native-plugins).

## Extension traits

The five swappable subsystem seams
(`crates/dwara-core/src/extensions/`). All are `async` via
`async_trait`, dyn-compatible, used as `Arc<dyn Trait>`, and share
one error type. The contracts (retry posture, fail-open versus
fail-closed, edition wiring) are described in
[Extension traits](../guide/extension-traits); the signatures:

```rust
pub enum ExtensionsError { Io(String), Invalid(String), Backend(String), Unsupported(String) }  // non-exhaustive
```

### RateLimiter (`extensions::rate_limiter`)

```rust
pub struct RateDecision {
    pub allowed: bool,
    pub remaining: u64,
    pub retry_after_ms: Option<u64>,
}

pub trait RateLimiter: Send + Sync {
    async fn check(&self, key: &str, cost: u32) -> Result<RateDecision, ExtensionsError>;
}
```

One-line contract: hot-path, atomic decide-**and**-reserve (an
`allowed` decision has already deducted `cost`; there is no refund);
the caller picks the fail-open/fail-closed policy. `retry_after_ms`
is the window remainder, not a success promise.

### ConfigSource (`extensions::config_source`)

```rust
pub trait ConfigSource: Send + Sync {
    async fn load(&self) -> Result<Gateway, ExtensionsError>;
}
```

One-line contract: full read of the current configuration
generation, pull-only, off the request hot path; an unreadable
source fails the publish (fail-closed at publish).

### CacheStore (`extensions::cache`)

```rust
pub trait CacheStore: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, ExtensionsError>;
    async fn set(&self, key: String, value: Vec<u8>) -> Result<(), ExtensionsError>;
    async fn delete(&self, key: &str) -> Result<bool, ExtensionsError>;
    async fn set_with_ttl(&self, key: String, value: Vec<u8>, ttl: Duration) -> Result<(), ExtensionsError> { /* defaults to set */ }
    fn entry_count(&self) -> Option<u64> { None }
}
```

One-line contract: errors are treated as a miss by call sites
(degrade, never fail the request); `set_with_ttl` is a memory hint
only -- readers re-check expiry from the value itself; `delete` of a
missing key is `Ok(false)`.

### AnalyticsSink (`extensions::analytics`)

```rust
pub struct Event {
    pub kind: String,              // e.g. "request"
    pub timestamp_ms: u64,
    pub route: Option<String>,
    pub consumer: Option<String>,
    pub endpoint: Option<String>,
    pub status: Option<u16>,
    pub listener: Option<String>,
    pub method: Option<String>,
    pub duration_ms: Option<f64>,
    pub attempts: Option<u32>,
    pub rate_limited: bool,
    pub broken: bool,
    pub shed: bool,
    pub edge_id: Option<String>,
    pub attributes: Vec<(String, String)>,
}   // non-exhaustive

pub trait AnalyticsSink: Send + Sync {
    async fn record(&self, event: Event) -> Result<(), ExtensionsError>;
}
```

One-line contract: fire-and-forget -- `Ok` means accepted, not
durably persisted; implementations bound themselves (drop-oldest
under pressure) and must never stall the dataplane; events must not
carry secret material.

### SecretSource (`extensions::secrets`)

```rust
pub struct Secret(String);  // Debug is redacted; expose() -> &str

pub trait SecretSource: Send + Sync {
    async fn resolve(&self, name: &str) -> Result<Option<Secret>, ExtensionsError>;
}
```

One-line contract: resolution happens at config-compile time (cold
start and every reload), never per request; `Ok(None)` is a miss
(the source has no such secret); implementors re-read on each
resolve so a rotation lands on the next reload.

## Nano-service ABI

A nano-service module implements a small dedicated handler ABI --
not proxy-wasm. The full contract (request serialization, sandbox
limits, failure semantics) is documented once in
[Nano-services](../guide/nano-services); the surface summary:

| Direction | Symbol | Signature |
|---|---|---|
| Export | `memory` | Linear memory shared with the host. |
| Export | `alloc` | `alloc(size: i32) -> i32` |
| Export | `handle` | `handle(req_ptr: i32, req_len: i32) -> i32` (`0` success, non-zero answers 502) |
| Import | `dwara.response_status` | `response_status(status: i32)` |
| Import | `dwara.response_header` | `response_header(k_ptr, k_len, v_ptr, v_len: i32)` |
| Import | `dwara.response_body` | `response_body(ptr, len: i32)` |
| Import | `dwara.log` | `log(ptr, len: i32)` |

The request is a length-prefixed blob (u32 big-endian lengths):
method, path, header count plus key/value pairs, body. A module
importing WASI functions does not instantiate.
