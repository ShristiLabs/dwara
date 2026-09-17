# Hostcall API reference

Signature-level reference for every proxy-wasm hostcall the gateway's
WASM host registers: parameters, returns, statuses, selector values,
and error codes. Every entry below was extracted from the host source
(`crates/dwara-core/src/wasm/`).

This page is deliberately dry. For workflow-oriented prose (the
scaffold/build/load quickstart, recipes, lifecycle, troubleshooting)
see [Proxy-Wasm plugins](./proxy-wasm-plugins) and the
[Plugin SDK](./plugin-sdk). The full generated Rust API documentation
for the workspace crates is published at
<https://shristilabs.github.io/dwara/api/dwara_core/>
(built by CI from `main`; public items only).

Upstream references:

- Rust proxy-wasm SDK (the crate `dwara-cli plugin new` scaffolds
  against): <https://docs.rs/proxy-wasm/0.2.5/proxy_wasm/>
- proxy-wasm ABI specification (the source of truth for every import
  name, parameter, and wire layout used below):
  <https://proxy-wasm.spec.vec.io/>

## Hostcalls

The host registers every import under the module name `env`. Where a
hostcall has a Rust SDK spelling, the table names it; parameters and
returns are given in SDK terms (strings and byte vectors, not ABI
pointers). Status values below (`Supported` / `Partial` / `Stub`)
match the [hostcall support matrix](./plugin-sdk#hostcall-support-matrix)
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
[Plugin SDK: HTTP callouts](./plugin-sdk#http-callouts-proxy_http_call).

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

## Where to go next

- [Proxy-Wasm plugins](./proxy-wasm-plugins) - configuration and
  operations: phases, limits, failure semantics.
- [Plugin SDK](./plugin-sdk) - the building guide: scaffold, build,
  load, iterate.
- [Extension API](../reference/extension-api) - the index of every
  extension surface's reference page.
