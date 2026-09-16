//! proxy-wasm host implementation (DW-055).
//!
//! This module implements the host side of the proxy-wasm ABI: the
//! import functions that a WebAssembly plugin calls to interact with
//! the proxy. The plugin exports phase callbacks (e.g.
//! `proxy_on_request_headers`) that the host calls at the appropriate
//! point in the request pipeline; the plugin calls back into the host
//! via the imports defined here to read/write request data, log, send
//! responses, etc.
//!
//! ## Architecture
//!
//! - [`WasmEngine`] — process-wide wasmtime engine + linker, compiled
//!   once at startup. Holds the compiled modules keyed by config name.
//!   Cheap to clone (Arc internals).
//! - [`PluginModule`] — a compiled wasmtime module for one plugin
//!   config entry. Created once at config publish time.
//! - [`PluginInstance`] — a per-request plugin instance (store +
//!   instance + context). Created for each request that passes through
//!   a route with plugins.
//! - [`PluginContext`] — the per-instance state the host imports read
//!   from and write to: request/response headers, body, the action
//!   returned by the plugin, etc. Stored in the wasmtime store's
//!   user data.
//!
//! ## Fuel and epoch preemption
//!
//! Each instance is created with a fuel budget
//! ([`PluginLimits::fuel`]). wasmtime consumes fuel on every operation;
//! when the budget is exhausted, the plugin traps with an out-of-fuel
//! error, which the host catches and converts to a 500 (the plugin is
//! misbehaving, not the request). Epoch-based interruption is used for
//! time caps: a background thread increments the epoch, and the plugin
//! is interrupted if it runs past [`PluginLimits::timeout_ms`].
//!
//! ## Memory caps
//!
//! [`PluginLimits::memory_mb`] caps the linear memory the plugin can
//! allocate. wasmtime's `ResourceLimiter` trait enforces this at the
//! allocation boundary.
//!
//! ## Import names and WASI
//!
//! Modules built with the Rust `proxy-wasm` SDK (what
//! `dwara-cli plugin new` scaffolds) import the spec ABI names, so the
//! host registers BOTH the spec names (`proxy_send_local_response`,
//! `proxy_get_current_time_nanoseconds`) and dwara's original spellings
//! (`proxy_send_http_response`, `proxy_get_current_time`) with
//! identical behavior. The `wasm32-wasip1` target additionally emits a
//! small `wasi_snapshot_preview1` import set (environment, fd_write,
//! proc_exit, random_get, clock_time_get, sched_yield); the host
//! provides minimal stubs for exactly that set — a module importing
//! other WASI functions fails to instantiate (fail-closed).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use wasmtime::{Engine, Linker, Module, ResourceLimiter, Store};

use super::abi;
use super::callout::CalloutResponse;

/// The VM-scoped shared-data store (DW-167): one map per compiled
/// plugin module, shared by every per-request instance through the
/// Mutex. Keys are strings; values are bytes with a CAS version for
/// optimistic concurrency.
pub type SharedData = HashMap<String, (Vec<u8>, u32)>;

/// Per-module cap on the VM-scoped shared-data store: total bytes
/// (key + value lengths summed over the entries). The store outlives
/// every request (module lifetime), so an unbounded map is a slow OOM
/// the wasm `ResourceLimiter` cannot see. A set that would exceed the
/// cap FAILS (the plugin gets an error status it can branch on) —
/// entries are never evicted: a silently evicted rate-limit counter
/// or cache entry is a correctness bug, a refused set is a signal.
pub const SHARED_DATA_CAP_BYTES: usize = 1024 * 1024;
/// Per-module cap on the VM-scoped shared-data store: entry count
/// (same posture as [`SHARED_DATA_CAP_BYTES`]; bounds key overhead a
/// byte cap alone would miss).
pub const SHARED_DATA_CAP_ENTRIES: usize = 1024;

/// Whether inserting `key` -> `value` (replacing the current value if
/// any) fits the shared-data caps ([`SHARED_DATA_CAP_BYTES`] /
/// [`SHARED_DATA_CAP_ENTRIES`]). Runs inside the caller's critical
/// section; the entry cap bounds the byte-sum walk to 1024 entries.
fn shared_data_fits(shared: &SharedData, key: &str, value: &[u8]) -> bool {
    let exists = shared.contains_key(key);
    if !exists && shared.len() >= SHARED_DATA_CAP_ENTRIES {
        return false;
    }
    let occupied: usize = shared.iter().map(|(k, (v, _))| k.len() + v.len()).sum();
    let replaced = shared
        .get(key)
        .map(|(v, _)| key.len() + v.len())
        .unwrap_or(0);
    occupied - replaced + key.len() + value.len() <= SHARED_DATA_CAP_BYTES
}

/// Per-instance cap on buffered plugin log output (`proxy_log` plus
/// the `fd_write` sink), in bytes. Fuel bounds plugin EXECUTION but
/// not host-side copies: without this cap a plugin looping over
/// `proxy_log`/`fd_write` would grow the host-side buffer without
/// bound. When the cap is hit the head of the overflowing line is
/// kept (if any budget remains), a marker line is appended, and every
/// further line is dropped. 64 KiB is far above any legitimate
/// diagnostic output.
const LOG_BUFFER_CAP_BYTES: usize = 64 * 1024;

/// Process-wide wasmtime engine + linker for proxy-wasm plugins.
///
/// Created once at startup and shared across all plugin instances. The
/// engine is configured with fuel consumption and epoch interruption
/// enabled. The linker connects the proxy-wasm ABI imports to the host
/// functions.
///
/// Cheap to clone (Arc internals).
#[derive(Clone)]
pub struct WasmEngine {
    engine: Engine,
    linker: Arc<Linker<PluginContext>>,
}

/// A compiled plugin module (one per config entry).
pub struct PluginModule {
    module: Module,
    limits: PluginLimits,
    plugin_config: Vec<u8>,
    vm_config: Vec<u8>,
    /// The VM-scoped shared-data store (DW-167): every per-request
    /// instance of THIS module sees the same map — the proxy-wasm
    /// `proxy_get/set_shared_data` contract Envoy implements (shared
    /// across the contexts of one VM). Instances on different tokio
    /// tasks share it through the Mutex.
    shared: Arc<Mutex<SharedData>>,
}

/// Per-plugin resource limits (DW-055 decision 4; §9.3).
#[derive(Clone, Debug)]
pub struct PluginLimits {
    /// Maximum fuel (wasmtime operations). Each wasm operation consumes
    /// a small amount of fuel; when the budget is exhausted, the plugin
    /// traps. Default: 1,000,000 (enough for typical header inspection
    /// and response short-circuiting).
    pub fuel: u64,
    /// Maximum linear memory in MB. Default: 32.
    pub memory_mb: usize,
    /// Maximum execution time in milliseconds. Enforced via epoch
    /// interruption. Default: 100.
    pub timeout_ms: u64,
}

impl Default for PluginLimits {
    fn default() -> Self {
        Self {
            fuel: 1_000_000,
            memory_mb: 32,
            timeout_ms: 100,
        }
    }
}

/// The per-instance context the host imports read from and write to.
///
/// Stored as the wasmtime store's `T` type. The host import functions
/// receive a `&mut PluginContext` via `Caller` and use it to exchange
/// data with the plugin.
pub struct PluginContext {
    /// Request headers (set by the host before `proxy_on_request_headers`).
    pub request_headers: Vec<(String, String)>,
    /// Response headers (set by the host before `proxy_on_response_headers`).
    pub response_headers: Vec<(String, String)>,
    /// Request body (set by the host before `proxy_on_request_body`).
    pub request_body: Vec<u8>,
    /// Response body (set by the host before `proxy_on_response_body`).
    pub response_body: Vec<u8>,
    /// Plugin configuration (passed to `proxy_on_configure`).
    pub plugin_config: Vec<u8>,
    /// VM configuration (passed to `proxy_on_vm_start`).
    pub vm_config: Vec<u8>,
    /// The action the plugin returned from the last phase callback.
    pub action: u32,
    /// Whether the plugin has called `proxy_send_http_response` (a
    /// short-circuit response). When set, the host should stop
    /// processing and return the stored response.
    pub local_response: Option<LocalResponse>,
    /// Log lines emitted by the plugin via `proxy_log`.
    pub logs: Vec<(u32, String)>,
    /// The VM-scoped shared-data store handle (see [`SharedData`]).
    pub shared_data: Arc<Mutex<SharedData>>,
    /// Callouts registered by `proxy_http_call` and not yet answered
    /// (DW-167). One instance can queue several; the dispatch driver
    /// performs them in FIFO order, one round each.
    pub pending_callouts: Vec<PendingCallout>,
    /// Monotonic callout-token counter (tokens are handed out by the
    /// host and delivered back with `proxy_on_http_call_response`).
    pub callout_token_counter: u32,
    /// The last delivered callout response's header map (`:status`
    /// plus ordinary headers, hop-by-hop stripped) — what MapType 6
    /// reads return inside `proxy_on_http_call_response`.
    pub callout_response_headers: Vec<(String, String)>,
    /// The last delivered callout response's body — what BufferType 4
    /// reads return inside `proxy_on_http_call_response`.
    pub callout_response_body: Vec<u8>,
    /// Metrics registered by the plugin.
    pub metrics: HashMap<String, PluginMetric>,
    /// The current context ID (set by the host before calling exports).
    pub current_context_id: u32,
    /// The effective context ID (set by `proxy_set_effective_context`).
    pub effective_context_id: u32,
    /// Whether `proxy_done` was called.
    pub done: bool,
    /// Memory limiter state (tracks current allocation against the cap).
    pub memory_used: usize,
    /// Memory cap in bytes.
    pub memory_cap: usize,
    /// Log bytes buffered so far (the buffer is capped at
    /// [`LOG_BUFFER_CAP_BYTES`]; see [`PluginContext::push_log`]).
    log_bytes: usize,
    /// Whether the log cap was hit — every further line is dropped.
    log_dropped: bool,
}

/// A local response set by the plugin via `proxy_send_http_response`.
#[derive(Clone, Debug)]
pub struct LocalResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A plugin-registered metric.
#[derive(Clone, Debug)]
pub struct PluginMetric {
    pub metric_type: PluginMetricType,
    pub value: f64,
}

/// One `proxy_http_call` dispatch, parsed and validated at the
/// hostcall boundary (DW-167). The instance queues it; the dispatch
/// driver (the async plugin_dispatch boundary) performs the exchange
/// and delivers the response back through
/// [`PluginInstance::deliver_callout_response`].
#[derive(Clone, Debug)]
pub struct PendingCallout {
    /// The token the host handed the plugin (returned with the
    /// response; the SDK dispatcher routes by it).
    pub token: u32,
    /// The full `http(s)://host[:port]/path?query` URI string.
    pub uri: String,
    /// The request method (`:method`; GET when the dispatch map
    /// carried none).
    pub method: String,
    /// Ordinary headers (pseudo-headers stripped; `:authority` folds
    /// into the URI's authority when the map carried one).
    pub headers: Vec<(String, String)>,
    /// The request body (may be empty).
    pub body: Vec<u8>,
    /// The plugin-requested timeout in milliseconds (the unit the
    /// Rust SDK's `dispatch_http_call` sends); clamped at perform
    /// time.
    pub timeout_ms: u32,
}

/// Metric types (proxy-wasm §2.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PluginMetricType {
    Counter,
    Gauge,
    Histogram,
}

impl PluginContext {
    fn new(
        plugin_config: Vec<u8>,
        vm_config: Vec<u8>,
        memory_cap: usize,
        shared: Arc<Mutex<SharedData>>,
    ) -> Self {
        Self {
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            request_body: Vec::new(),
            response_body: Vec::new(),
            plugin_config,
            vm_config,
            action: abi::ACTION_CONTINUE,
            local_response: None,
            logs: Vec::new(),
            shared_data: shared,
            pending_callouts: Vec::new(),
            callout_token_counter: 0,
            callout_response_headers: Vec::new(),
            callout_response_body: Vec::new(),
            metrics: HashMap::new(),
            current_context_id: 0,
            effective_context_id: 0,
            done: false,
            memory_used: 0,
            memory_cap,
            log_bytes: 0,
            log_dropped: false,
        }
    }

    /// Append a log line to the per-instance buffer, enforcing the
    /// [`LOG_BUFFER_CAP_BYTES`] cap: once the budget is spent, the
    /// head of the overflowing line is kept (if it fits), a truncation
    /// marker is appended, and every further line is dropped. Use this
    /// instead of pushing to `logs` directly.
    fn push_log(&mut self, level: u32, msg: String) {
        if self.log_dropped {
            return;
        }
        if self.log_bytes + msg.len() > LOG_BUFFER_CAP_BYTES {
            let remaining = LOG_BUFFER_CAP_BYTES - self.log_bytes;
            if remaining > 0 {
                // Keep the head of the overflowing line (a panic's
                // first line is the diagnostic that matters).
                let mut cut = remaining.min(msg.len());
                while cut > 0 && !msg.is_char_boundary(cut) {
                    cut -= 1;
                }
                if cut > 0 {
                    self.log_bytes += cut;
                    let head = msg[..cut].to_string();
                    self.logs.push((level, head));
                }
            }
            self.log_dropped = true;
            self.logs.push((
                level,
                format!(
                    "... log buffer cap ({} KiB) reached; further plugin log output dropped",
                    LOG_BUFFER_CAP_BYTES / 1024
                ),
            ));
            return;
        }
        self.log_bytes += msg.len();
        self.logs.push((level, msg));
    }
}

/// The memory cap for a plugin instance, enforced via wasmtime's
/// `ResourceLimiter` trait on the store's user data (`PluginContext`).
impl ResourceLimiter for PluginContext {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= self.memory_cap)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= 10_000)
    }
}

impl WasmEngine {
    /// Create a new engine with the proxy-wasm ABI linker.
    pub fn new() -> Result<Self, String> {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        // cranelift is the compiler (enabled via the `cranelift` feature).
        config.strategy(wasmtime::Strategy::Cranelift);

        let engine = Engine::new(&config).map_err(|e| format!("wasmtime engine: {e}"))?;

        let mut linker: Linker<PluginContext> = Linker::new(&engine);

        // --- proxy-wasm ABI imports ---
        //
        // Each import is a function the plugin can call. The names
        // follow the proxy-wasm spec (§3). All return i32 (WasmResult:
        // 0 = OK, non-zero = error).

        // proxy_log(level: i32, msg_ptr: i32, msg_size: i32) -> i32
        linker
            .func_wrap(
                "env",
                "proxy_log",
                |mut caller: wasmtime::Caller<PluginContext>,
                 level: i32,
                 msg_ptr: i32,
                 msg_size: i32|
                 -> i32 {
                    if msg_ptr < 0 || msg_size < 0 {
                        return 1;
                    }
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    let msg = match memory
                        .data(&caller)
                        .get(msg_ptr as usize..(msg_ptr as usize + msg_size as usize))
                    {
                        Some(slice) => slice.to_vec(),
                        None => return 1,
                    };
                    let msg = String::from_utf8_lossy(&msg).into_owned();
                    caller.data_mut().push_log(level as u32, msg);
                    0
                },
            )
            .map_err(|e| format!("linker proxy_log: {e}"))?;

        // proxy_get_buffer_bytes(bt, offset, max_size, ptr_ptr, size_ptr) -> i32
        linker
            .func_wrap(
                "env",
                "proxy_get_buffer_bytes",
                |mut caller: wasmtime::Caller<PluginContext>,
                 bt: i32,
                 offset: i32,
                 max_size: i32,
                 ptr_ptr: i32,
                 size_ptr: i32|
                 -> i32 {
                    // Extract the requested chunk into an owned Vec so the
                    // mutable borrow of `caller` ends before we touch memory.
                    let chunk: Vec<u8> = {
                        let ctx = caller.data_mut();
                        let data = match bt as u32 {
                            abi::BUFFER_REQUEST_BODY => &ctx.request_body,
                            abi::BUFFER_RESPONSE_BODY => &ctx.response_body,
                            abi::BUFFER_CALLOUT_RESPONSE_BODY => &ctx.callout_response_body,
                            abi::BUFFER_PLUGIN_CONFIGURATION => &ctx.plugin_config,
                            abi::BUFFER_VM_CONFIGURATION => &ctx.vm_config,
                            _ => return 1,
                        };
                        let offset = offset as usize;
                        let max_size = max_size as usize;
                        if offset > data.len() {
                            return 1;
                        }
                        let end = (offset + max_size).min(data.len());
                        data[offset..end].to_vec()
                    };
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    if chunk.is_empty() {
                        // Write zero to ptr_ptr and 0 to size_ptr.
                        if write_i32_to_memory(&memory, &mut caller, ptr_ptr, 0).is_err() {
                            return 1;
                        }
                        if write_i32_to_memory(&memory, &mut caller, size_ptr, 0).is_err() {
                            return 1;
                        }
                        return 0;
                    }
                    // Allocate space in plugin memory by calling the
                    // plugin's `proxy_on_memory_allocate` export (the
                    // standard proxy-wasm allocation pattern). If the
                    // export doesn't exist, use a simple bump approach
                    // via memory.grow.
                    let alloc_ptr = match allocate_in_plugin(&mut caller, &memory, chunk.len()) {
                        Ok(p) => p,
                        Err(_) => return 1,
                    };
                    if memory
                        .data_mut(&mut caller)
                        .get_mut(alloc_ptr..alloc_ptr + chunk.len())
                        .map(|dst| {
                            dst.copy_from_slice(&chunk);
                        })
                        .is_none()
                    {
                        return 1;
                    }
                    if write_i32_to_memory(&memory, &mut caller, ptr_ptr, alloc_ptr as i32).is_err()
                    {
                        return 1;
                    }
                    if write_i32_to_memory(&memory, &mut caller, size_ptr, chunk.len() as i32)
                        .is_err()
                    {
                        return 1;
                    }
                    0
                },
            )
            .map_err(|e| format!("linker proxy_get_buffer_bytes: {e}"))?;

        // proxy_get_buffer_status(bt, ptr_ptr, size_ptr) -> i32
        linker
            .func_wrap(
                "env",
                "proxy_get_buffer_status",
                |mut caller: wasmtime::Caller<PluginContext>,
                 bt: i32,
                 _ptr_ptr: i32,
                 size_ptr: i32|
                 -> i32 {
                    let ctx = caller.data();
                    let len = match bt as u32 {
                        abi::BUFFER_REQUEST_BODY => ctx.request_body.len(),
                        abi::BUFFER_RESPONSE_BODY => ctx.response_body.len(),
                        abi::BUFFER_CALLOUT_RESPONSE_BODY => ctx.callout_response_body.len(),
                        abi::BUFFER_PLUGIN_CONFIGURATION => ctx.plugin_config.len(),
                        abi::BUFFER_VM_CONFIGURATION => ctx.vm_config.len(),
                        _ => return 1,
                    };
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    if write_i32_to_memory(&memory, &mut caller, size_ptr, len as i32).is_err() {
                        return 1;
                    }
                    0
                },
            )
            .map_err(|e| format!("linker proxy_get_buffer_status: {e}"))?;

        // proxy_set_buffer_bytes(bt, offset, size, ptr, size) -> i32
        linker
            .func_wrap(
                "env",
                "proxy_set_buffer_bytes",
                |mut caller: wasmtime::Caller<PluginContext>,
                 bt: i32,
                 offset: i32,
                 _size: i32,
                 ptr: i32,
                 data_size: i32|
                 -> i32 {
                    if ptr < 0 || data_size < 0 {
                        return 1;
                    }
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    let data = match memory
                        .data(&caller)
                        .get(ptr as usize..(ptr as usize + data_size as usize))
                    {
                        Some(slice) => slice.to_vec(),
                        None => return 1,
                    };
                    let ctx = caller.data_mut();
                    let offset = offset as usize;
                    let buf = match bt as u32 {
                        abi::BUFFER_REQUEST_BODY => &mut ctx.request_body,
                        abi::BUFFER_RESPONSE_BODY => &mut ctx.response_body,
                        _ => return 1,
                    };
                    if offset > buf.len() {
                        buf.resize(offset, 0);
                    }
                    buf.splice(offset.., data);
                    0
                },
            )
            .map_err(|e| format!("linker proxy_set_buffer_bytes: {e}"))?;

        // proxy_get_header_map_pairs(bt, ptr_ptr, size_ptr) -> i32
        // Serialized in the spec/SDK wire layout (LE count + length
        // table + NUL-terminated strings — what the Rust proxy-wasm
        // SDK's get_map parses; see abi::serialize_header_map_spec).
        // An empty map reports ptr=0/size=0 (the SDK reads that as an
        // empty map without allocating).
        linker
            .func_wrap(
                "env",
                "proxy_get_header_map_pairs",
                |mut caller: wasmtime::Caller<PluginContext>,
                 bt: i32,
                 ptr_ptr: i32,
                 size_ptr: i32|
                 -> i32 {
                    let headers = {
                        let ctx = caller.data();
                        match bt as u32 {
                            abi::BUFFER_REQUEST_HEADERS => ctx.request_headers.clone(),
                            abi::BUFFER_RESPONSE_HEADERS => ctx.response_headers.clone(),
                            // The delivered callout response's headers
                            // (DW-167): `:status` first, then the
                            // ordinary headers (hop-by-hop stripped).
                            abi::BUFFER_CALLOUT_RESPONSE_HEADERS => {
                                ctx.callout_response_headers.clone()
                            }
                            // Trailers are not plumbed through dwara's
                            // pipeline: they read as an empty map.
                            abi::BUFFER_REQUEST_TRAILERS
                            | abi::BUFFER_RESPONSE_TRAILERS
                            | abi::BUFFER_CALLOUT_RESPONSE_TRAILERS => Vec::new(),
                            _ => return 1,
                        }
                    };
                    let encoded = abi::serialize_header_map_spec(&headers);
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    if encoded.len() <= 4 {
                        if write_i32_to_memory(&memory, &mut caller, ptr_ptr, 0).is_err() {
                            return 1;
                        }
                        if write_i32_to_memory(&memory, &mut caller, size_ptr, 0).is_err() {
                            return 1;
                        }
                        return 0;
                    }
                    let alloc_ptr = match allocate_in_plugin(&mut caller, &memory, encoded.len()) {
                        Ok(p) => p,
                        Err(_) => return 1,
                    };
                    if memory
                        .data_mut(&mut caller)
                        .get_mut(alloc_ptr..alloc_ptr + encoded.len())
                        .map(|dst| dst.copy_from_slice(&encoded))
                        .is_none()
                    {
                        return 1;
                    }
                    if write_i32_to_memory(&memory, &mut caller, ptr_ptr, alloc_ptr as i32).is_err()
                    {
                        return 1;
                    }
                    if write_i32_to_memory(&memory, &mut caller, size_ptr, encoded.len() as i32)
                        .is_err()
                    {
                        return 1;
                    }
                    0
                },
            )
            .map_err(|e| format!("linker proxy_get_header_map_pairs: {e}"))?;

        // proxy_set_header_map_pairs(bt, ptr, size) -> i32
        // Parses the spec/SDK wire layout (what the Rust proxy-wasm
        // SDK's set_map serializes; see
        // abi::deserialize_header_map_spec). A zero-size buffer is an
        // empty map.
        linker
            .func_wrap(
                "env",
                "proxy_set_header_map_pairs",
                |mut caller: wasmtime::Caller<PluginContext>,
                 bt: i32,
                 ptr: i32,
                 size: i32|
                 -> i32 {
                    if ptr < 0 || size < 0 {
                        return 1;
                    }
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    let data = match memory
                        .data(&caller)
                        .get(ptr as usize..(ptr as usize + size as usize))
                    {
                        Some(slice) => slice.to_vec(),
                        None => return 1,
                    };
                    let headers = match abi::deserialize_header_map_spec(&data) {
                        Some(h) => h,
                        None => return 1,
                    };
                    let ctx = caller.data_mut();
                    match bt as u32 {
                        abi::BUFFER_REQUEST_HEADERS => ctx.request_headers = headers,
                        abi::BUFFER_RESPONSE_HEADERS => ctx.response_headers = headers,
                        // Trailer and callout-response-map stores are
                        // accepted and discarded (neither is plumbed
                        // through the pipeline); reporting success
                        // keeps SDK plugins from panicking on a
                        // benign store.
                        abi::BUFFER_REQUEST_TRAILERS
                        | abi::BUFFER_RESPONSE_TRAILERS
                        | abi::BUFFER_CALLOUT_RESPONSE_HEADERS
                        | abi::BUFFER_CALLOUT_RESPONSE_TRAILERS => {}
                        _ => return 1,
                    }
                    0
                },
            )
            .map_err(|e| format!("linker proxy_set_header_map_pairs: {e}"))?;

        // proxy_get_header_map_value(bt, key_ptr, key_size, value_ptr_ptr, value_size_ptr) -> i32
        linker
            .func_wrap(
                "env",
                "proxy_get_header_map_value",
                |mut caller: wasmtime::Caller<PluginContext>,
                 bt: i32,
                 key_ptr: i32,
                 key_size: i32,
                 value_ptr_ptr: i32,
                 value_size_ptr: i32|
                 -> i32 {
                    if key_ptr < 0 || key_size < 0 {
                        return 1;
                    }
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    let key = match memory
                        .data(&caller)
                        .get(key_ptr as usize..(key_ptr as usize + key_size as usize))
                    {
                        Some(slice) => String::from_utf8_lossy(slice).into_owned(),
                        None => return 1,
                    };
                    let value = {
                        let ctx = caller.data();
                        let headers: &[(String, String)] = match bt as u32 {
                            abi::BUFFER_REQUEST_HEADERS => &ctx.request_headers,
                            abi::BUFFER_RESPONSE_HEADERS => &ctx.response_headers,
                            // The delivered callout response's headers
                            // (DW-167): a lookup lands on `:status` or
                            // an ordinary header the target sent.
                            abi::BUFFER_CALLOUT_RESPONSE_HEADERS => &ctx.callout_response_headers,
                            // Trailers are not plumbed through dwara's
                            // pipeline: they read as empty (the SDK
                            // maps an empty result to None).
                            abi::BUFFER_REQUEST_TRAILERS
                            | abi::BUFFER_RESPONSE_TRAILERS
                            | abi::BUFFER_CALLOUT_RESPONSE_TRAILERS => &[],
                            _ => return 1,
                        };
                        headers
                            .iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case(&key))
                            .map(|(_, v)| v.clone())
                            .unwrap_or_default()
                    };
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    if value.is_empty() {
                        if write_i32_to_memory(&memory, &mut caller, value_ptr_ptr, 0).is_err() {
                            return 1;
                        }
                        if write_i32_to_memory(&memory, &mut caller, value_size_ptr, 0).is_err() {
                            return 1;
                        }
                        return 0;
                    }
                    let alloc_ptr = match allocate_in_plugin(&mut caller, &memory, value.len()) {
                        Ok(p) => p,
                        Err(_) => return 1,
                    };
                    if memory
                        .data_mut(&mut caller)
                        .get_mut(alloc_ptr..alloc_ptr + value.len())
                        .map(|dst| dst.copy_from_slice(value.as_bytes()))
                        .is_none()
                    {
                        return 1;
                    }
                    if write_i32_to_memory(&memory, &mut caller, value_ptr_ptr, alloc_ptr as i32)
                        .is_err()
                    {
                        return 1;
                    }
                    if write_i32_to_memory(&memory, &mut caller, value_size_ptr, value.len() as i32)
                        .is_err()
                    {
                        return 1;
                    }
                    0
                },
            )
            .map_err(|e| format!("linker proxy_get_header_map_value: {e}"))?;

        // proxy_add_header_map_value(bt, key_ptr, key_size, value_ptr, value_size) -> i32
        linker
            .func_wrap(
                "env",
                "proxy_add_header_map_value",
                |mut caller: wasmtime::Caller<PluginContext>,
                 bt: i32,
                 key_ptr: i32,
                 key_size: i32,
                 value_ptr: i32,
                 value_size: i32|
                 -> i32 {
                    if key_ptr < 0 || key_size < 0 || value_ptr < 0 || value_size < 0 {
                        return 1;
                    }
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    let key = match memory
                        .data(&caller)
                        .get(key_ptr as usize..(key_ptr as usize + key_size as usize))
                    {
                        Some(slice) => String::from_utf8_lossy(slice).into_owned(),
                        None => return 1,
                    };
                    let value = match memory
                        .data(&caller)
                        .get(value_ptr as usize..(value_ptr as usize + value_size as usize))
                    {
                        Some(slice) => String::from_utf8_lossy(slice).into_owned(),
                        None => return 1,
                    };
                    let ctx = caller.data_mut();
                    // Trailer and callout-response-map mutations are
                    // accepted and discarded (neither is plumbed
                    // through the pipeline); reporting success keeps
                    // SDK plugins from panicking on a benign store.
                    if bt as u32 == abi::BUFFER_REQUEST_TRAILERS
                        || bt as u32 == abi::BUFFER_RESPONSE_TRAILERS
                        || bt as u32 == abi::BUFFER_CALLOUT_RESPONSE_HEADERS
                        || bt as u32 == abi::BUFFER_CALLOUT_RESPONSE_TRAILERS
                    {
                        return 0;
                    }
                    let headers = match bt as u32 {
                        abi::BUFFER_REQUEST_HEADERS => &mut ctx.request_headers,
                        abi::BUFFER_RESPONSE_HEADERS => &mut ctx.response_headers,
                        _ => return 1,
                    };
                    headers.push((key, value));
                    0
                },
            )
            .map_err(|e| format!("linker proxy_add_header_map_value: {e}"))?;

        // proxy_replace_header_map_value(bt, key_ptr, key_size, value_ptr, value_size) -> i32
        linker
            .func_wrap(
                "env",
                "proxy_replace_header_map_value",
                |mut caller: wasmtime::Caller<PluginContext>,
                 bt: i32,
                 key_ptr: i32,
                 key_size: i32,
                 value_ptr: i32,
                 value_size: i32|
                 -> i32 {
                    if key_ptr < 0 || key_size < 0 || value_ptr < 0 || value_size < 0 {
                        return 1;
                    }
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    let key = match memory
                        .data(&caller)
                        .get(key_ptr as usize..(key_ptr as usize + key_size as usize))
                    {
                        Some(slice) => String::from_utf8_lossy(slice).into_owned(),
                        None => return 1,
                    };
                    let value = match memory
                        .data(&caller)
                        .get(value_ptr as usize..(value_ptr as usize + value_size as usize))
                    {
                        Some(slice) => String::from_utf8_lossy(slice).into_owned(),
                        None => return 1,
                    };
                    let ctx = caller.data_mut();
                    // Trailer and callout-response-map mutations are
                    // accepted and discarded (neither is plumbed
                    // through the pipeline); reporting success keeps
                    // SDK plugins from panicking on a benign store.
                    if bt as u32 == abi::BUFFER_REQUEST_TRAILERS
                        || bt as u32 == abi::BUFFER_RESPONSE_TRAILERS
                        || bt as u32 == abi::BUFFER_CALLOUT_RESPONSE_HEADERS
                        || bt as u32 == abi::BUFFER_CALLOUT_RESPONSE_TRAILERS
                    {
                        return 0;
                    }
                    let headers = match bt as u32 {
                        abi::BUFFER_REQUEST_HEADERS => &mut ctx.request_headers,
                        abi::BUFFER_RESPONSE_HEADERS => &mut ctx.response_headers,
                        _ => return 1,
                    };
                    if let Some(entry) = headers
                        .iter_mut()
                        .find(|(k, _)| k.eq_ignore_ascii_case(&key))
                    {
                        entry.1 = value;
                    } else {
                        headers.push((key, value));
                    }
                    0
                },
            )
            .map_err(|e| format!("linker proxy_replace_header_map_value: {e}"))?;

        // proxy_remove_header_map_value(bt, key_ptr, key_size) -> i32
        linker
            .func_wrap(
                "env",
                "proxy_remove_header_map_value",
                |mut caller: wasmtime::Caller<PluginContext>,
                 bt: i32,
                 key_ptr: i32,
                 key_size: i32|
                 -> i32 {
                    if key_ptr < 0 || key_size < 0 {
                        return 1;
                    }
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    let key = match memory
                        .data(&caller)
                        .get(key_ptr as usize..(key_ptr as usize + key_size as usize))
                    {
                        Some(slice) => String::from_utf8_lossy(slice).into_owned(),
                        None => return 1,
                    };
                    let ctx = caller.data_mut();
                    // Trailer and callout-response-map mutations are
                    // accepted and discarded (neither is plumbed
                    // through the pipeline); reporting success keeps
                    // SDK plugins from panicking on a benign store.
                    if bt as u32 == abi::BUFFER_REQUEST_TRAILERS
                        || bt as u32 == abi::BUFFER_RESPONSE_TRAILERS
                        || bt as u32 == abi::BUFFER_CALLOUT_RESPONSE_HEADERS
                        || bt as u32 == abi::BUFFER_CALLOUT_RESPONSE_TRAILERS
                    {
                        return 0;
                    }
                    let headers = match bt as u32 {
                        abi::BUFFER_REQUEST_HEADERS => &mut ctx.request_headers,
                        abi::BUFFER_RESPONSE_HEADERS => &mut ctx.response_headers,
                        _ => return 1,
                    };
                    headers.retain(|(k, _)| !k.eq_ignore_ascii_case(&key));
                    0
                },
            )
            .map_err(|e| format!("linker proxy_remove_header_map_value: {e}"))?;

        // proxy_send_http_response(status, headers_ptr, headers_size, body_ptr, body_size, trailers_ptr, trailers_size) -> i32
        // dwara's original spelling (the WAT fixtures and host tests
        // use it).
        linker
            .func_wrap("env", "proxy_send_http_response", send_http_response_impl)
            .map_err(|e| format!("linker proxy_send_http_response: {e}"))?;

        // proxy_send_local_response(status_code, details_ptr, details_size,
        //                            body_ptr, body_size, headers_ptr,
        //                            headers_size, grpc_status) -> i32
        // The proxy-wasm SPEC hostcall (a different signature and
        // argument order than dwara's original spelling above): the
        // Rust proxy-wasm SDK's `send_http_response` imports this name
        // with this shape, and its header argument is always the
        // spec/SDK map serialization (serialize_map — for empty
        // headers that is the 4-byte LE count 0, so a 4-byte buffer
        // parses as an empty map, never a parse failure). Status-code
        // details and the gRPC status are carried on the
        // LocalResponse's status/body path only — dwara does not
        // forward them anywhere today.
        linker
            .func_wrap(
                "env",
                "proxy_send_local_response",
                |mut caller: wasmtime::Caller<PluginContext>,
                 status_code: i32,
                 _details_ptr: i32,
                 _details_size: i32,
                 body_ptr: i32,
                 body_size: i32,
                 headers_ptr: i32,
                 headers_size: i32,
                 _grpc_status: i32|
                 -> i32 {
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    let headers = if headers_ptr > 0 && headers_size > 0 {
                        let data = match memory.data(&caller).get(
                            headers_ptr as usize..(headers_ptr as usize + headers_size as usize),
                        ) {
                            Some(slice) => slice.to_vec(),
                            None => return 1,
                        };
                        match abi::deserialize_header_map_spec(&data) {
                            Some(h) => h,
                            None => return 1,
                        }
                    } else {
                        Vec::new()
                    };
                    let body = if body_ptr > 0 && body_size > 0 {
                        match memory
                            .data(&caller)
                            .get(body_ptr as usize..(body_ptr as usize + body_size as usize))
                        {
                            Some(slice) => slice.to_vec(),
                            None => return 1,
                        }
                    } else {
                        Vec::new()
                    };
                    let ctx = caller.data_mut();
                    ctx.local_response = Some(LocalResponse {
                        status: status_code as u16,
                        headers,
                        body,
                    });
                    ctx.action = abi::ACTION_END_STREAM;
                    0
                },
            )
            .map_err(|e| format!("linker proxy_send_local_response: {e}"))?;

        // proxy_continue_stream(bt) -> i32
        linker
            .func_wrap(
                "env",
                "proxy_continue_stream",
                |_caller: wasmtime::Caller<PluginContext>, _bt: i32| -> i32 { 0 },
            )
            .map_err(|e| format!("linker proxy_continue_stream: {e}"))?;

        // proxy_close_stream(bt) -> i32
        linker
            .func_wrap(
                "env",
                "proxy_close_stream",
                |mut caller: wasmtime::Caller<PluginContext>, _bt: i32| -> i32 {
                    caller.data_mut().action = abi::ACTION_END_STREAM;
                    0
                },
            )
            .map_err(|e| format!("linker proxy_close_stream: {e}"))?;

        // proxy_get_shared_data(key_ptr, key_size, value_ptr_ptr, value_size_ptr, cas_ptr) -> i32
        linker
            .func_wrap(
                "env",
                "proxy_get_shared_data",
                |mut caller: wasmtime::Caller<PluginContext>,
                 key_ptr: i32,
                 key_size: i32,
                 value_ptr_ptr: i32,
                 value_size_ptr: i32,
                 cas_ptr: i32|
                 -> i32 {
                    if key_ptr < 0 || key_size < 0 {
                        return 1;
                    }
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    let key = match memory
                        .data(&caller)
                        .get(key_ptr as usize..(key_ptr as usize + key_size as usize))
                    {
                        Some(slice) => String::from_utf8_lossy(slice).into_owned(),
                        None => return 1,
                    };
                    // VM-scoped store (DW-167): the lock is held only
                    // for the clone, never across a hostcall that
                    // re-enters wasm or writes plugin memory. Poison
                    // recovery: the critical section is a read+clone
                    // (nothing can half-mutate the map), so a panic
                    // elsewhere must not take every later request on
                    // this module down with the lock.
                    let lookup = {
                        let shared = caller
                            .data()
                            .shared_data
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        shared.get(&key).map(|(v, c)| (v.clone(), *c))
                    };
                    let Some((value, cas)) = lookup else {
                        // Not found: return OK with zero values.
                        if write_i32_to_memory(&memory, &mut caller, value_ptr_ptr, 0).is_err() {
                            return 1;
                        }
                        if write_i32_to_memory(&memory, &mut caller, value_size_ptr, 0).is_err() {
                            return 1;
                        }
                        if write_i32_to_memory(&memory, &mut caller, cas_ptr, 0).is_err() {
                            return 1;
                        }
                        return 0;
                    };
                    let alloc_ptr = match allocate_in_plugin(&mut caller, &memory, value.len()) {
                        Ok(p) => p,
                        Err(_) => return 1,
                    };
                    if memory
                        .data_mut(&mut caller)
                        .get_mut(alloc_ptr..alloc_ptr + value.len())
                        .map(|dst| dst.copy_from_slice(&value))
                        .is_none()
                    {
                        return 1;
                    }
                    if write_i32_to_memory(&memory, &mut caller, value_ptr_ptr, alloc_ptr as i32)
                        .is_err()
                    {
                        return 1;
                    }
                    if write_i32_to_memory(&memory, &mut caller, value_size_ptr, value.len() as i32)
                        .is_err()
                    {
                        return 1;
                    }
                    if write_i32_to_memory(&memory, &mut caller, cas_ptr, cas as i32).is_err() {
                        return 1;
                    }
                    0
                },
            )
            .map_err(|e| format!("linker proxy_get_shared_data: {e}"))?;

        // proxy_set_shared_data(key_ptr, key_size, value_ptr, value_size, cas) -> i32
        linker
            .func_wrap(
                "env",
                "proxy_set_shared_data",
                |mut caller: wasmtime::Caller<PluginContext>,
                 key_ptr: i32,
                 key_size: i32,
                 value_ptr: i32,
                 value_size: i32,
                 cas: i32|
                 -> i32 {
                    if key_ptr < 0 || key_size < 0 {
                        return 1;
                    }
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    let key = match memory
                        .data(&caller)
                        .get(key_ptr as usize..(key_ptr as usize + key_size as usize))
                    {
                        Some(slice) => String::from_utf8_lossy(slice).into_owned(),
                        None => return 1,
                    };
                    let value = if value_ptr > 0 && value_size > 0 {
                        match memory
                            .data(&caller)
                            .get(value_ptr as usize..(value_ptr as usize + value_size as usize))
                        {
                            Some(slice) => slice.to_vec(),
                            None => return 1,
                        }
                    } else {
                        Vec::new()
                    };
                    let ctx = caller.data_mut();
                    // VM-scoped store (DW-167): the CAS read, the cap
                    // check, and the write are one critical section, so
                    // two instances racing a compare-and-set cannot
                    // interleave. Poison recovery: the section is a
                    // read plus one `insert` (the map cannot be left
                    // half-mutated), so a panic elsewhere must not
                    // poison every later request on this module.
                    let mut shared = ctx
                        .shared_data
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let current_cas = shared.get(&key).map(|(_, c)| *c).unwrap_or(0);
                    if cas > 0 && cas != current_cas as i32 {
                        // Status::CasMismatch — the ONE error status
                        // the Rust SDK's set_shared_data maps to a
                        // clean Err (any other status panics the
                        // module).
                        return 8;
                    }
                    if !shared_data_fits(&shared, &key, &value) {
                        // Over-cap set: refused, never evicted (see
                        // SHARED_DATA_CAP_BYTES). The same error-status
                        // surface as the CAS mismatch — the SDK's only
                        // branchable error for this hostcall.
                        return 8;
                    }
                    let new_cas = current_cas + 1;
                    shared.insert(key, (value, new_cas));
                    0
                },
            )
            .map_err(|e| format!("linker proxy_set_shared_data: {e}"))?;

        // proxy_set_effective_context(context_id) -> i32
        linker
            .func_wrap(
                "env",
                "proxy_set_effective_context",
                |mut caller: wasmtime::Caller<PluginContext>, context_id: i32| -> i32 {
                    caller.data_mut().effective_context_id = context_id as u32;
                    0
                },
            )
            .map_err(|e| format!("linker proxy_set_effective_context: {e}"))?;

        // proxy_done() -> i32
        linker
            .func_wrap(
                "env",
                "proxy_done",
                |mut caller: wasmtime::Caller<PluginContext>| -> i32 {
                    caller.data_mut().done = true;
                    0
                },
            )
            .map_err(|e| format!("linker proxy_done: {e}"))?;

        // proxy_get_property(path_ptr, path_size, value_ptr_ptr, value_size_ptr) -> i32
        // Minimal implementation: supports a few well-known properties.
        linker
            .func_wrap(
                "env",
                "proxy_get_property",
                |mut caller: wasmtime::Caller<PluginContext>,
                 path_ptr: i32,
                 path_size: i32,
                 value_ptr_ptr: i32,
                 value_size_ptr: i32|
                 -> i32 {
                    if path_ptr < 0 || path_size < 0 {
                        return 1;
                    }
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    let path = match memory
                        .data(&caller)
                        .get(path_ptr as usize..(path_ptr as usize + path_size as usize))
                    {
                        Some(slice) => String::from_utf8_lossy(slice).into_owned(),
                        None => return 1,
                    };
                    // Minimal property support: return empty for unknown
                    // properties (the plugin should handle this).
                    let _ = path;
                    if write_i32_to_memory(&memory, &mut caller, value_ptr_ptr, 0).is_err() {
                        return 1;
                    }
                    if write_i32_to_memory(&memory, &mut caller, value_size_ptr, 0).is_err() {
                        return 1;
                    }
                    0
                },
            )
            .map_err(|e| format!("linker proxy_get_property: {e}"))?;

        // proxy_set_property(path_ptr, path_size, value_ptr, value_size) -> i32
        // Minimal implementation: no-op (returns OK).
        linker
            .func_wrap(
                "env",
                "proxy_set_property",
                |_caller: wasmtime::Caller<PluginContext>,
                 _path_ptr: i32,
                 _path_size: i32,
                 _value_ptr: i32,
                 _value_size: i32|
                 -> i32 { 0 },
            )
            .map_err(|e| format!("linker proxy_set_property: {e}"))?;

        // proxy_define_metric(metric_type, name_ptr, name_size, metric_id_ptr, metric_id_size_ptr) -> i32
        linker
            .func_wrap(
                "env",
                "proxy_define_metric",
                |mut caller: wasmtime::Caller<PluginContext>,
                 metric_type: i32,
                 name_ptr: i32,
                 name_size: i32,
                 _metric_id_ptr: i32,
                 _metric_id_size_ptr: i32|
                 -> i32 {
                    if name_ptr < 0 || name_size < 0 {
                        return 1;
                    }
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    let name = match memory
                        .data(&caller)
                        .get(name_ptr as usize..(name_ptr as usize + name_size as usize))
                    {
                        Some(slice) => String::from_utf8_lossy(slice).into_owned(),
                        None => return 1,
                    };
                    let mt = match metric_type {
                        0 => PluginMetricType::Counter,
                        1 => PluginMetricType::Gauge,
                        2 => PluginMetricType::Histogram,
                        _ => return 1,
                    };
                    let ctx = caller.data_mut();
                    ctx.metrics.insert(
                        name,
                        PluginMetric {
                            metric_type: mt,
                            value: 0.0,
                        },
                    );
                    0
                },
            )
            .map_err(|e| format!("linker proxy_define_metric: {e}"))?;

        // proxy_record_metric(metric_id_ptr, metric_id_size, value) -> i32
        linker
            .func_wrap(
                "env",
                "proxy_record_metric",
                |mut caller: wasmtime::Caller<PluginContext>,
                 name_ptr: i32,
                 name_size: i32,
                 value: f64|
                 -> i32 {
                    if name_ptr < 0 || name_size < 0 {
                        return 1;
                    }
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    let name = match memory
                        .data(&caller)
                        .get(name_ptr as usize..(name_ptr as usize + name_size as usize))
                    {
                        Some(slice) => String::from_utf8_lossy(slice).into_owned(),
                        None => return 1,
                    };
                    let ctx = caller.data_mut();
                    if let Some(m) = ctx.metrics.get_mut(&name) {
                        m.value = value;
                    }
                    0
                },
            )
            .map_err(|e| format!("linker proxy_record_metric: {e}"))?;

        // proxy_increment_metric(metric_id_ptr, metric_id_size, increment) -> i32
        linker
            .func_wrap(
                "env",
                "proxy_increment_metric",
                |mut caller: wasmtime::Caller<PluginContext>,
                 name_ptr: i32,
                 name_size: i32,
                 increment: f64|
                 -> i32 {
                    if name_ptr < 0 || name_size < 0 {
                        return 1;
                    }
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    let name = match memory
                        .data(&caller)
                        .get(name_ptr as usize..(name_ptr as usize + name_size as usize))
                    {
                        Some(slice) => String::from_utf8_lossy(slice).into_owned(),
                        None => return 1,
                    };
                    let ctx = caller.data_mut();
                    if let Some(m) = ctx.metrics.get_mut(&name) {
                        m.value += increment;
                    }
                    0
                },
            )
            .map_err(|e| format!("linker proxy_increment_metric: {e}"))?;

        // proxy_get_metric(metric_id_ptr, metric_id_size, return_value_ptr) -> i32
        linker
            .func_wrap(
                "env",
                "proxy_get_metric",
                |mut caller: wasmtime::Caller<PluginContext>,
                 name_ptr: i32,
                 name_size: i32,
                 return_value_ptr: i32|
                 -> i32 {
                    if name_ptr < 0 || name_size < 0 {
                        return 1;
                    }
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    let name = match memory
                        .data(&caller)
                        .get(name_ptr as usize..(name_ptr as usize + name_size as usize))
                    {
                        Some(slice) => String::from_utf8_lossy(slice).into_owned(),
                        None => return 1,
                    };
                    let value = caller
                        .data()
                        .metrics
                        .get(&name)
                        .map(|m| m.value)
                        .unwrap_or(0.0);
                    // Write the f64 value to the return pointer.
                    let bytes = value.to_le_bytes();
                    if memory
                        .data_mut(&mut caller)
                        .get_mut(return_value_ptr as usize..(return_value_ptr as usize + 8))
                        .map(|dst| dst.copy_from_slice(&bytes))
                        .is_none()
                    {
                        return 1;
                    }
                    0
                },
            )
            .map_err(|e| format!("linker proxy_get_metric: {e}"))?;

        // proxy_get_current_time(return_value_ptr) -> i32
        // proxy_get_current_time_nanoseconds(return_time) -> i32 (the
        // proxy-wasm spec name; the Rust SDK's `get_current_time`
        // imports this spelling). Both names share one implementation.
        for name in [
            "proxy_get_current_time",
            "proxy_get_current_time_nanoseconds",
        ] {
            linker
                .func_wrap("env", name, get_current_time_impl)
                .map_err(|e| format!("linker {name}: {e}"))?;
        }

        // proxy_get_log_level(return_level_ptr) -> i32
        // The host buffers every proxy_log line (no level filtering),
        // so the query always reports Info. Registered because the Rust
        // SDK declares the import even when unused; plugins that gate
        // work on the reported level see Info.
        linker
            .func_wrap(
                "env",
                "proxy_get_log_level",
                |mut caller: wasmtime::Caller<PluginContext>, return_level_ptr: i32| -> i32 {
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    if write_i32_to_memory(
                        &memory,
                        &mut caller,
                        return_level_ptr,
                        abi::LOG_INFO as i32,
                    )
                    .is_err()
                    {
                        return 1;
                    }
                    0
                },
            )
            .map_err(|e| format!("linker proxy_get_log_level: {e}"))?;

        // proxy_get_status(return_code_ptr, return_message_ptr_ptr, return_message_size_ptr) -> i32
        // The gRPC callout status fetch (the Rust SDK's
        // `get_grpc_status`). dwara's grpc_* hostcalls never put a
        // callout in flight, so there is no status to report — but the
        // SDK 0.2.5 wrapper PANICS on any non-Ok status (hostcalls.rs
        // `get_grpc_status`, ~line 1037), so answering NotFound would
        // trap every SDK caller. Return Ok with code 0 and a null
        // message (the SDK reads that as `(0, None)`: no gRPC status).
        linker
            .func_wrap(
                "env",
                "proxy_get_status",
                |mut caller: wasmtime::Caller<PluginContext>,
                 return_code_ptr: i32,
                 return_message_ptr_ptr: i32,
                 return_message_size_ptr: i32|
                 -> i32 {
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    for (ptr, value) in [
                        (return_code_ptr, 0),
                        (return_message_ptr_ptr, 0),
                        (return_message_size_ptr, 0),
                    ] {
                        if write_i32_to_memory(&memory, &mut caller, ptr, value).is_err() {
                            return 1;
                        }
                    }
                    0 // Ok: no callout, no gRPC status (code 0, null message)
                },
            )
            .map_err(|e| format!("linker proxy_get_status: {e}"))?;

        // Stub imports for functions we don't implement but the plugin
        // may call (returns error to signal unsupported). Each is
        // registered with its proxy-wasm spec ARITY: wasmtime's typed
        // linking rejects a module whose import signature does not
        // match, and the Rust SDK declares every import with its spec
        // signature even when the plugin never calls it.
        for name in [
            "proxy_set_tick_period_milliseconds",
            "proxy_grpc_cancel",
            "proxy_grpc_close",
        ] {
            linker
                .func_wrap("env", name, stub_unsupported_1)
                .map_err(|e| format!("linker {name}: {e}"))?;
        }
        for name in [
            "proxy_register_shared_queue",
            "proxy_dequeue_shared_queue",
            "proxy_enqueue_shared_queue",
        ] {
            linker
                .func_wrap("env", name, stub_unsupported_3)
                .map_err(|e| format!("linker {name}: {e}"))?;
        }
        linker
            .func_wrap("env", "proxy_resolve_shared_queue", stub_unsupported_5)
            .map_err(|e| format!("linker proxy_resolve_shared_queue: {e}"))?;
        linker
            .func_wrap("env", "proxy_grpc_stream", stub_unsupported_9)
            .map_err(|e| format!("linker proxy_grpc_stream: {e}"))?;
        // proxy_http_call(upstream_ptr, upstream_size, headers_ptr,
        //                 headers_size, body_ptr, body_size,
        //                 trailers_ptr, trailers_size, timeout_ms,
        //                 return_token_ptr) -> i32
        // The proxy-wasm HTTP callout dispatcher (DW-167). The Rust
        // SDK's `dispatch_http_call` (hostcalls.rs ~812) sends the URI
        // string, the headers/trailers in the spec map serialization
        // (what `proxy_set_header_map_pairs` parses), an optional
        // body, and the timeout in MILLISECONDS; it reads the token
        // from the return pointer and maps Ok/BadArgument/
        // InternalFailure to `Ok(token)`/`Err(BadArgument)`/
        // `Err(InternalFailure)` — every other status panics the
        // module, so this import answers only 0/2/10.
        linker
            .func_wrap(
                "env",
                "proxy_http_call",
                |mut caller: wasmtime::Caller<PluginContext>,
                 upstream_ptr: i32,
                 upstream_size: i32,
                 headers_ptr: i32,
                 headers_size: i32,
                 body_ptr: i32,
                 body_size: i32,
                 _trailers_ptr: i32,
                 _trailers_size: i32,
                 timeout_ms: i32,
                 return_token_ptr: i32|
                 -> i32 {
                    if upstream_ptr < 0 || upstream_size < 0 || headers_ptr < 0 || headers_size < 0
                    {
                        return 2; // Status::BadArgument
                    }
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 10,
                    };
                    let read = |ptr: i32, size: i32| -> Option<Vec<u8>> {
                        memory
                            .data(&caller)
                            .get(ptr as usize..(ptr as usize + size as usize))
                            .map(|s| s.to_vec())
                    };
                    let uri_bytes = match read(upstream_ptr, upstream_size) {
                        Some(b) => b,
                        None => return 2,
                    };
                    let uri = match String::from_utf8(uri_bytes) {
                        Ok(u) => u,
                        Err(_) => return 2,
                    };
                    let headers_bytes = match read(headers_ptr, headers_size) {
                        Some(b) => b,
                        None => return 2,
                    };
                    let body = if body_ptr > 0 && body_size > 0 {
                        match read(body_ptr, body_size) {
                            Some(b) => b,
                            None => return 2,
                        }
                    } else {
                        Vec::new()
                    };
                    // Trailers are accepted and ignored (dwara does
                    // not plumb trailers on callout requests).
                    match register_callout(
                        caller.data_mut(),
                        &uri,
                        &headers_bytes,
                        body,
                        timeout_ms,
                    ) {
                        Some(token) => {
                            let memory = match caller.get_export("memory") {
                                Some(wasmtime::Extern::Memory(m)) => m,
                                _ => return 10,
                            };
                            if write_i32_to_memory(
                                &memory,
                                &mut caller,
                                return_token_ptr,
                                token as i32,
                            )
                            .is_err()
                            {
                                return 10;
                            }
                            0 // Status::Ok
                        }
                        None => 2, // Status::BadArgument (invalid URI/map/head)
                    }
                },
            )
            .map_err(|e| format!("linker proxy_http_call: {e}"))?;
        linker
            .func_wrap("env", "proxy_grpc_call", stub_unsupported_12)
            .map_err(|e| format!("linker proxy_grpc_call: {e}"))?;
        linker
            .func_wrap("env", "proxy_grpc_send", stub_unsupported_4)
            .map_err(|e| format!("linker proxy_grpc_send: {e}"))?;
        linker
            .func_wrap("env", "proxy_call_foreign_function", stub_unsupported_6)
            .map_err(|e| format!("linker proxy_call_foreign_function: {e}"))?;

        // --- WASI p1 stubs (wasm32-wasip1) ----------------------------------
        //
        // Modules built for wasm32-wasip1 emit a small
        // `wasi_snapshot_preview1` import set even when they never
        // touch WASI consciously (Rust std's panic printing, HashMap
        // seeding, environment access). The host provides minimal
        // stubs for exactly that observed set; anything beyond it
        // (files, sockets) fails to instantiate, fail-closed.

        // environ_sizes_get(environ_count_ptr, environ_buf_size_ptr) -> errno
        linker
            .func_wrap(
                "wasi_snapshot_preview1",
                "environ_sizes_get",
                |mut caller: wasmtime::Caller<PluginContext>,
                 count_ptr: i32,
                 buf_size_ptr: i32|
                 -> i32 {
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    let _ = caller.data_mut();
                    // Empty environment: count 0, buffer size 0.
                    for (ptr, value) in [(count_ptr, 0), (buf_size_ptr, 0)] {
                        if write_i32_to_memory(&memory, &mut caller, ptr, value).is_err() {
                            return 1; // EPERM-ish; any non-zero is an errno
                        }
                    }
                    0 // ESUCCESS
                },
            )
            .map_err(|e| format!("linker environ_sizes_get: {e}"))?;

        // environ_get(environ_ptrs_ptr, environ_buf_ptr) -> errno
        linker
            .func_wrap(
                "wasi_snapshot_preview1",
                "environ_get",
                |_caller: wasmtime::Caller<PluginContext>,
                 _environ_ptrs_ptr: i32,
                 _environ_buf_ptr: i32|
                 -> i32 {
                    0 // ESUCCESS: the (empty) environment needs no writes
                },
            )
            .map_err(|e| format!("linker environ_get: {e}"))?;

        // fd_write(fd, iovs_ptr, iovs_len, nwritten_ptr) -> errno
        // Route the plugin's stderr (panic output, debug prints) into
        // the per-instance log buffer so operators can see why a plugin
        // died without the bytes escaping the sandbox. The buffer is
        // capped (PluginContext::push_log): a plugin that spews through
        // stderr cannot grow host memory without bound — unlike fuel,
        // which bounds plugin execution, not host-side copies.
        linker
            .func_wrap(
                "wasi_snapshot_preview1",
                "fd_write",
                |mut caller: wasmtime::Caller<PluginContext>,
                 _fd: i32,
                 iovs_ptr: i32,
                 iovs_len: i32,
                 nwritten_ptr: i32|
                 -> i32 {
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    if iovs_ptr < 0 || iovs_len < 0 || nwritten_ptr < 0 {
                        return 1;
                    }
                    let mut out = Vec::new();
                    for i in 0..iovs_len as usize {
                        let iov_base = iovs_ptr as usize + i * 8;
                        let (buf_ptr, buf_len) = {
                            let data = memory.data(&caller);
                            let Some(base) = data.get(iov_base..iov_base + 8) else {
                                return 1;
                            };
                            let buf_ptr =
                                u32::from_le_bytes(base[0..4].try_into().expect("4 bytes"))
                                    as usize;
                            let buf_len =
                                u32::from_le_bytes(base[4..8].try_into().expect("4 bytes"))
                                    as usize;
                            (buf_ptr, buf_len)
                        };
                        match memory.data(&caller).get(buf_ptr..buf_ptr + buf_len) {
                            Some(slice) => out.extend_from_slice(slice),
                            None => return 1,
                        }
                    }
                    let written = out.len() as i32;
                    caller
                        .data_mut()
                        .push_log(abi::LOG_INFO, String::from_utf8_lossy(&out).into_owned());
                    if write_i32_to_memory(&memory, &mut caller, nwritten_ptr, written).is_err() {
                        return 1;
                    }
                    0 // ESUCCESS
                },
            )
            .map_err(|e| format!("linker fd_write: {e}"))?;

        // proc_exit(code) -> ! : the plugin terminated itself. Trap the
        // instance (the runner reports the trap like any other plugin
        // failure; the code rides the trap message).
        linker
            .func_wrap(
                "wasi_snapshot_preview1",
                "proc_exit",
                |_caller: wasmtime::Caller<PluginContext>,
                 code: i32|
                 -> Result<(), wasmtime::Error> {
                    Err(wasmtime::format_err!(
                        "wasi proc_exit({code}): the plugin terminated itself"
                    ))
                },
            )
            .map_err(|e| format!("linker proc_exit: {e}"))?;

        // random_get(buf_ptr, buf_len) -> errno
        // Non-cryptographic: splitmix64 seeded from the wall clock and
        // a process-global counter. Enough to seed std collections;
        // plugins must not use it for key material.
        linker
            .func_wrap(
                "wasi_snapshot_preview1",
                "random_get",
                |mut caller: wasmtime::Caller<PluginContext>, buf_ptr: i32, buf_len: i32| -> i32 {
                    if buf_ptr < 0 || buf_len < 0 {
                        return 1;
                    }
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    let mut state = wasi_random_seed();
                    let mut filled = 0usize;
                    while filled < buf_len as usize {
                        state = state.wrapping_add(0x9E3779B97F4A7C15);
                        let mut z = state;
                        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
                        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
                        z ^= z >> 31;
                        for byte in z.to_le_bytes() {
                            if filled >= buf_len as usize {
                                break;
                            }
                            let dst = buf_ptr as usize + filled;
                            match memory.data_mut(&mut caller).get_mut(dst..dst + 1) {
                                Some(slot) => slot[0] = byte,
                                None => return 1,
                            }
                            filled += 1;
                        }
                    }
                    0 // ESUCCESS
                },
            )
            .map_err(|e| format!("linker random_get: {e}"))?;

        // clock_time_get(clock_id, precision, time_ptr) -> errno
        linker
            .func_wrap(
                "wasi_snapshot_preview1",
                "clock_time_get",
                |mut caller: wasmtime::Caller<PluginContext>,
                 _clock_id: i32,
                 _precision: i64,
                 time_ptr: i32|
                 -> i32 {
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0);
                    let bytes = now.to_le_bytes();
                    if memory
                        .data_mut(&mut caller)
                        .get_mut(time_ptr as usize..(time_ptr as usize + 8))
                        .map(|dst| dst.copy_from_slice(&bytes))
                        .is_none()
                    {
                        return 1;
                    }
                    0 // ESUCCESS
                },
            )
            .map_err(|e| format!("linker clock_time_get: {e}"))?;

        // sched_yield() -> errno
        linker
            .func_wrap(
                "wasi_snapshot_preview1",
                "sched_yield",
                |_caller: wasmtime::Caller<PluginContext>| -> i32 { 0 },
            )
            .map_err(|e| format!("linker sched_yield: {e}"))?;

        Ok(Self {
            engine,
            linker: Arc::new(linker),
        })
    }

    /// The underlying wasmtime engine.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Compile a .wasm module from bytes.
    pub fn compile(
        &self,
        wasm_bytes: &[u8],
        limits: PluginLimits,
        plugin_config: Vec<u8>,
        vm_config: Vec<u8>,
    ) -> Result<PluginModule, String> {
        let module =
            Module::new(&self.engine, wasm_bytes).map_err(|e| format!("wasm compile: {e}"))?;
        Ok(PluginModule {
            module,
            limits,
            plugin_config,
            vm_config,
            shared: Arc::new(Mutex::new(SharedData::new())),
        })
    }

    /// The linker (used by instance creation).
    pub fn linker(&self) -> &Linker<PluginContext> {
        &self.linker
    }
}

impl PluginModule {
    /// Create a new per-request instance and run the VM start + configure
    /// lifecycle. Returns the store and instance ready for phase calls.
    pub fn instantiate(&self, engine: &WasmEngine) -> Result<PluginInstance, String> {
        let memory_cap = self.limits.memory_mb * 1024 * 1024;
        let ctx = PluginContext::new(
            self.plugin_config.clone(),
            self.vm_config.clone(),
            memory_cap,
            Arc::clone(&self.shared),
        );
        let mut store = Store::new(&engine.engine, ctx);
        store.limiter(move |ctx| ctx as &mut dyn ResourceLimiter);

        // Set the fuel budget.
        store
            .set_fuel(self.limits.fuel)
            .map_err(|e| format!("set_fuel: {e}"))?;

        // Set the epoch deadline so epoch interruption does not fire
        // immediately. A background thread (when configured) increments
        // the engine epoch; the store traps when the current epoch
        // reaches the deadline. Without this call the default deadline
        // is 0 and any wasm execution traps right away.
        store.set_epoch_deadline(self.limits.timeout_ms.max(1));

        // Instantiate the module.
        let instance = engine
            .linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| format!("wasm instantiate: {e}"))?;

        let mut inst = PluginInstance {
            store,
            instance,
            http_context_created: false,
        };

        // Standard proxy-wasm VM initialization (SDK modules, e.g.
        // anything built from `dwara-cli plugin new`): the module
        // registers its root-context factory in `_start` and builds its
        // contexts on `proxy_on_context_create`; calling
        // `proxy_on_vm_start` without both panics inside the module.
        // Both exports are optional (dwara's WAT fixtures implement
        // neither) — call them when present, skip when absent. A trap
        // inside `_start` fails the instantiation with the trap itself.
        inst.call_optional_start()?;
        inst.call_optional_context_create(1, 0);

        // Call proxy_on_vm_start(root_context_id=1, vm_config_size).
        inst.set_context_id(1);
        if let Some(export) = inst
            .instance
            .get_export(&mut inst.store, "proxy_on_vm_start")
        {
            let func = export
                .into_func()
                .ok_or("proxy_on_vm_start is not a func")?;
            let vm_config_size = self.vm_config.len() as i32;
            let typed: wasmtime::TypedFunc<(i32, i32), i32> = func
                .typed(&inst.store)
                .map_err(|e| format!("proxy_on_vm_start typed: {e}"))?;
            let result = typed
                .call(&mut inst.store, (1, vm_config_size))
                .map_err(|e| format!("proxy_on_vm_start call: {e}"))?;
            if result == 0 {
                return Err("proxy_on_vm_start returned false".to_string());
            }
        }

        // Call proxy_on_configure(root_context_id=1, plugin_config_size).
        if let Some(export) = inst
            .instance
            .get_export(&mut inst.store, "proxy_on_configure")
        {
            let func = export
                .into_func()
                .ok_or("proxy_on_configure is not a func")?;
            let plugin_config_size = self.plugin_config.len() as i32;
            let typed: wasmtime::TypedFunc<(i32, i32), i32> = func
                .typed(&inst.store)
                .map_err(|e| format!("proxy_on_configure typed: {e}"))?;
            let result = typed
                .call(&mut inst.store, (1, plugin_config_size))
                .map_err(|e| format!("proxy_on_configure call: {e}"))?;
            if result == 0 {
                return Err("proxy_on_configure returned false".to_string());
            }
        }

        Ok(inst)
    }

    /// The resource limits for this plugin.
    pub fn limits(&self) -> &PluginLimits {
        &self.limits
    }
}

/// A per-request plugin instance: a wasmtime store + instance.
pub struct PluginInstance {
    store: Store<PluginContext>,
    instance: wasmtime::Instance,
    /// Whether `proxy_on_context_create(2, 1)` has been called for the
    /// per-request HTTP context (SDK modules panic on a phase call for
    /// a context they were never told to create; fixtures without the
    /// export skip it).
    http_context_created: bool,
}

/// The result of a phase callback.
#[derive(Clone, Debug)]
pub enum PhaseResult {
    /// Continue processing the request.
    Continue,
    /// The plugin short-circuited with a local response.
    LocalResponse(LocalResponse),
    /// The plugin trapped (out of fuel, memory error, or panic).
    Trap(String),
    /// The plugin registered one or more HTTP callouts and paused
    /// (DW-167). The dispatch driver performs the exchanges and calls
    /// [`PluginInstance::deliver_callout_response`]; the phase's
    /// outcome is then re-collected from the instance.
    Pause,
}

impl PluginInstance {
    /// Set the current context ID (used by exports that receive a
    /// context_id parameter).
    fn set_context_id(&mut self, id: u32) {
        self.store.data_mut().current_context_id = id;
        self.store.data_mut().effective_context_id = id;
    }

    /// Call `_start()` when the module exports it (SDK modules register
    /// their context factories there). Absent in dwara's WAT fixtures —
    /// a missing export is skipped, not an error. A trapping `_start`
    /// is PROPAGATED as the instance's error: swallowing it here would
    /// surface later as an unrelated panic inside
    /// `proxy_on_context_create` (the SDK dispatcher finds no
    /// registered root context), hiding the real failure.
    fn call_optional_start(&mut self) -> Result<(), String> {
        let Some(export) = self.instance.get_export(&mut self.store, "_start") else {
            return Ok(());
        };
        let Some(func) = export.into_func() else {
            return Ok(());
        };
        let Ok(typed) = func.typed::<(), ()>(&self.store) else {
            return Ok(());
        };
        typed
            .call(&mut self.store, ())
            .map_err(|e| format!("_start: {e}"))
    }

    /// Call `proxy_on_context_create(context_id, root_context_id)` when
    /// the module exports it (SDK modules build their contexts there).
    /// Absent in dwara's WAT fixtures — a missing export is skipped.
    fn call_optional_context_create(&mut self, context_id: i32, root_context_id: i32) {
        let Some(export) = self
            .instance
            .get_export(&mut self.store, "proxy_on_context_create")
        else {
            return;
        };
        let Some(func) = export.into_func() else {
            return;
        };
        let Ok(typed) = func.typed::<(i32, i32), ()>(&self.store) else {
            return;
        };
        let _: () = typed
            .call(&mut self.store, (context_id, root_context_id))
            .unwrap_or_default();
    }

    /// Ensure the per-request HTTP context exists before a phase call:
    /// SDK modules panic inside `proxy_on_*` for a context they were
    /// never told to create, so the first phase (or `on_done`) for
    /// context 2 first calls `proxy_on_context_create(2, 1)`. Modules
    /// without the export (dwara's WAT fixtures) skip it.
    fn ensure_http_context(&mut self) {
        if self.http_context_created {
            return;
        }
        self.http_context_created = true;
        self.call_optional_context_create(2, 1);
    }

    /// Call `proxy_on_request_headers(context_id, num_headers, end_of_stream)`.
    /// Sets the request headers in the context before calling.
    pub fn on_request_headers(&mut self, headers: Vec<(String, String)>) -> PhaseResult {
        self.store.data_mut().request_headers = headers;
        let num_headers = self.store.data().request_headers.len() as i32;
        self.set_context_id(2);
        self.ensure_http_context();
        self.call_phase_export("proxy_on_request_headers", (2, num_headers, 1))
    }

    /// Call `proxy_on_request_body(context_id, body_size, end_of_stream)`.
    /// Sets the request body in the context before calling.
    pub fn on_request_body(&mut self, body: Vec<u8>) -> PhaseResult {
        self.store.data_mut().request_body = body;
        let body_size = self.store.data().request_body.len() as i32;
        self.set_context_id(2);
        self.ensure_http_context();
        self.call_phase_export("proxy_on_request_body", (2, body_size, 1))
    }

    /// Call `proxy_on_response_headers(context_id, num_headers, end_of_stream)`.
    /// Sets the response headers in the context before calling.
    pub fn on_response_headers(&mut self, headers: Vec<(String, String)>) -> PhaseResult {
        self.store.data_mut().response_headers = headers;
        let num_headers = self.store.data().response_headers.len() as i32;
        self.set_context_id(2);
        self.ensure_http_context();
        self.call_phase_export("proxy_on_response_headers", (2, num_headers, 1))
    }

    /// Call `proxy_on_response_body(context_id, body_size, end_of_stream)`.
    /// Sets the response body in the context before calling.
    pub fn on_response_body(&mut self, body: Vec<u8>) -> PhaseResult {
        self.store.data_mut().response_body = body;
        let body_size = self.store.data().response_body.len() as i32;
        self.set_context_id(2);
        self.ensure_http_context();
        self.call_phase_export("proxy_on_response_body", (2, body_size, 1))
    }

    /// Get the (possibly modified) request headers from the context.
    pub fn request_headers(&self) -> &[(String, String)] {
        &self.store.data().request_headers
    }

    /// Get the (possibly modified) response headers from the context.
    pub fn response_headers(&self) -> &[(String, String)] {
        &self.store.data().response_headers
    }

    /// Get the (possibly modified) request body from the context.
    pub fn request_body(&self) -> &[u8] {
        &self.store.data().request_body
    }

    /// Get the (possibly modified) response body from the context.
    pub fn response_body(&self) -> &[u8] {
        &self.store.data().response_body
    }

    /// Get the logs emitted by the plugin.
    pub fn logs(&self) -> &[(u32, String)] {
        &self.store.data().logs
    }

    /// Read `len` bytes of the plugin's linear memory at `offset`
    /// (test support: asserting a callback's in-memory side effects).
    pub fn memory_bytes(&mut self, offset: usize, len: usize) -> Option<Vec<u8>> {
        let export = self.instance.get_export(&mut self.store, "memory")?;
        let memory = export.into_memory()?;
        memory
            .data(&self.store)
            .get(offset..offset.checked_add(len)?)
            .map(|s| s.to_vec())
    }

    /// A snapshot of the VM-scoped shared-data map (test support: the
    /// cross-instance store DW-167 introduced).
    pub fn shared_data_snapshot(&self) -> SharedData {
        self.store
            .data()
            .shared_data
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Drain the callouts registered since the last phase/callback
    /// invocation (DW-167). The dispatch driver performs them in FIFO
    /// order (one round each).
    pub fn take_pending_callouts(&mut self) -> Vec<PendingCallout> {
        std::mem::take(&mut self.store.data_mut().pending_callouts)
    }

    /// Re-enqueue callouts the dispatch driver drained but did NOT
    /// perform (DW-167): when the first of several queued deliveries
    /// re-dispatches from its callback, the un-performed remainder
    /// goes back AHEAD of the newly registered queue — preserving the
    /// global dispatch order and guaranteeing every dispatched callout
    /// is eventually performed (or the loop guard trips).
    pub fn requeue_callouts(&mut self, pending: Vec<PendingCallout>) {
        if pending.is_empty() {
            return;
        }
        let ctx = self.store.data_mut();
        let mut merged = pending;
        merged.append(&mut ctx.pending_callouts);
        ctx.pending_callouts = merged;
    }

    /// Deliver a completed callout response and collect the plugin's
    /// resumed outcome (DW-167): the response's headers (`:status`
    /// first, hop-by-hop stripped) and body land in the context's
    /// callout-response stores, then the host calls
    /// `proxy_on_http_call_response(context_id, token, num_headers,
    /// body_size, num_trailers)` — the 5-parameter shape the Rust SDK
    /// 0.2.5 exports (its first parameter is the ABI's context slot,
    /// which the SDK ignores; it routes by token inside the module).
    /// The export returns nothing in the SDK: the plugin's decision is
    /// expressed through what it does inside the callback
    /// (`send_http_response`, header mutations, another dispatch, or
    /// nothing = resume Continue). A module without the export resumes
    /// Continue (nothing to tell).
    pub fn deliver_callout_response(&mut self, token: u32, resp: &CalloutResponse) -> PhaseResult {
        {
            let ctx = self.store.data_mut();
            ctx.callout_response_headers =
                std::iter::once((":status".to_string(), resp.status.to_string()))
                    .chain(resp.headers.iter().cloned())
                    .collect();
            ctx.callout_response_body = resp.body.clone();
        }
        let num_headers = self.store.data().callout_response_headers.len() as i32;
        let body_size = self.store.data().callout_response_body.len() as i32;
        self.set_context_id(2);
        self.ensure_http_context();
        let Some(export) = self
            .instance
            .get_export(&mut self.store, "proxy_on_http_call_response")
        else {
            return PhaseResult::Continue;
        };
        let Some(func) = export.into_func() else {
            return PhaseResult::Continue;
        };
        let args = (2, token as i32, num_headers, body_size, 0);
        // The SDK's export returns (); a hand-written fixture may
        // return an action — tolerate both shapes (the value is
        // recorded but the outcome comes from the instance state
        // below, matching the SDK's hostcall-driven resume model).
        let result: Result<u32, wasmtime::Error> =
            if let Ok(typed) = func.typed::<(i32, i32, i32, i32, i32), ()>(&self.store) {
                typed
                    .call(&mut self.store, args)
                    .map(|()| abi::ACTION_CONTINUE)
            } else if let Ok(typed) = func.typed::<(i32, i32, i32, i32, i32), i32>(&self.store) {
                typed.call(&mut self.store, args).map(|a| a as u32)
            } else {
                return PhaseResult::Trap(
                    "proxy_on_http_call_response has an unusable signature".to_string(),
                );
            };
        match result {
            Ok(action) => {
                let ctx = self.store.data_mut();
                ctx.action = action;
                if let Some(resp) = ctx.local_response.take() {
                    PhaseResult::LocalResponse(resp)
                } else if !ctx.pending_callouts.is_empty() {
                    // The callback dispatched another callout: pause
                    // again (the driver's next round picks it up).
                    PhaseResult::Pause
                } else {
                    PhaseResult::Continue
                }
            }
            Err(e) => {
                let fuel_left = self.store.get_fuel().unwrap_or(0);
                if fuel_left == 0 {
                    PhaseResult::Trap(format!("proxy_on_http_call_response: fuel exhausted: {e}"))
                } else {
                    PhaseResult::Trap(format!("proxy_on_http_call_response: {e}"))
                }
            }
        }
    }

    /// Call `proxy_on_done` and `proxy_on_log` (the cleanup path).
    /// The SDK's `proxy_on_done` returns a bool while the WAT fixtures
    /// return nothing — the result is ignored either way, so both
    /// shapes are accepted.
    pub fn on_done(&mut self) {
        self.set_context_id(2);
        self.ensure_http_context();
        let _ = self.call_optional_i32_export("proxy_on_done", 2);
        let _ = self.call_optional_i32_export("proxy_on_log", 2);
        let _ = self.call_optional_i32_export("proxy_on_delete", 2);
    }

    /// Call an optional `(i32) -> ()`-or-`(i32) -> i32` export with
    /// `arg`, tolerating either return shape (fixtures return nothing;
    /// the SDK returns a bool). Missing exports are skipped.
    fn call_optional_i32_export(&mut self, name: &str, arg: i32) -> Result<(), String> {
        let Some(export) = self.instance.get_export(&mut self.store, name) else {
            return Ok(());
        };
        let Some(func) = export.into_func() else {
            return Ok(());
        };
        if let Ok(typed) = func.typed::<(i32,), ()>(&self.store) {
            return typed
                .call(&mut self.store, (arg,))
                .map_err(|e| format!("{name}: {e}"));
        }
        if let Ok(typed) = func.typed::<(i32,), i32>(&self.store) {
            return typed
                .call(&mut self.store, (arg,))
                .map(|_| ())
                .map_err(|e| format!("{name}: {e}"));
        }
        Ok(())
    }

    /// Call a phase export that takes (context_id, a, b) and returns an action.
    fn call_phase_export(&mut self, name: &str, args: (i32, i32, i32)) -> PhaseResult {
        let export = match self.instance.get_export(&mut self.store, name) {
            Some(e) => e,
            None => return PhaseResult::Continue,
        };
        let func = match export.into_func() {
            Some(f) => f,
            None => return PhaseResult::Continue,
        };
        let typed: wasmtime::TypedFunc<(i32, i32, i32), i32> = match func.typed(&self.store) {
            Ok(t) => t,
            Err(e) => return PhaseResult::Trap(format!("{name} typed: {e}")),
        };
        match typed.call(&mut self.store, args) {
            Ok(action) => {
                let ctx = self.store.data_mut();
                ctx.action = action as u32;
                if let Some(resp) = ctx.local_response.take() {
                    PhaseResult::LocalResponse(resp)
                } else if action == abi::ACTION_END_STREAM as i32 {
                    PhaseResult::LocalResponse(LocalResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: Vec::new(),
                    })
                } else if !ctx.pending_callouts.is_empty() {
                    // The phase registered callouts (proxy_http_call)
                    // and did not short-circuit: pause for the host to
                    // perform them (DW-167). The returned action value
                    // is advisory — a plugin that dispatches a callout
                    // and returns Continue still pauses, because the
                    // phase's outcome cannot be known until the
                    // callout's callback ran.
                    PhaseResult::Pause
                } else {
                    PhaseResult::Continue
                }
            }
            Err(e) => {
                // Detect fuel exhaustion: wasmtime's trap Display does
                // not include the word "fuel", so check the remaining
                // fuel budget and annotate the message when it is zero.
                let fuel_left = self.store.get_fuel().unwrap_or(0);
                if fuel_left == 0 {
                    PhaseResult::Trap(format!("{name}: fuel exhausted: {e}"))
                } else {
                    PhaseResult::Trap(format!("{name}: {e}"))
                }
            }
        }
    }
}

// --- Helper functions ----------------------------------------------------

/// Validate and register one `proxy_http_call` dispatch (DW-167) into
/// the instance's pending list, handing out the next token. `None`
/// maps to `Status::BadArgument` at the import (the Rust SDK surfaces
/// that as `Err(Status::BadArgument)` from `dispatch_http_call`).
///
/// Validation: the URI must parse with an `http://`/`https://` scheme
/// and a host — the URI is the whole callout target (scheme,
/// authority, and optionally its own path+query), and the callout's
/// `Host` header derives from it. The dispatch header map's
/// pseudo-headers steer what they can: `:method` (default `GET`) and
/// `:path` (applied only when the URI carries no path of its own —
/// the URI-embedded target wins, and must be origin-form). `:authority`
/// and unknown pseudo-headers are advisory here and dropped (the
/// plugin shapes neither the dial target nor the Host; the same
/// authority-shapes-Host-only posture the request-path rewrite
/// enforces would need a cluster abstraction dwara does not have).
///
/// Request-head integrity (fail-closed BEFORE any network work): the
/// callout request head interpolates the method, the header names and
/// values, and the map `:path` verbatim, so each must be
/// splitting-safe — the method and every header name an RFC 7230
/// token, and no CR, LF, or NUL anywhere in a name, value, or the map
/// `:path`. A plugin reflecting client data into a callout cannot
/// smuggle a second request into the gateway-initiated connection;
/// violations register nothing and answer BadArgument.
fn register_callout(
    ctx: &mut PluginContext,
    uri: &str,
    headers_bytes: &[u8],
    body: Vec<u8>,
    timeout_ms: i32,
) -> Option<u32> {
    let parsed: http::Uri = uri.parse().ok()?;
    let scheme = match parsed.scheme_str() {
        Some("http") | Some("https") => parsed.scheme_str().unwrap(),
        _ => return None,
    };
    let host = parsed.host()?;
    let map = abi::deserialize_header_map_spec(headers_bytes)?;
    let mut method = "GET".to_string();
    let mut map_path: Option<String> = None;
    let mut headers = Vec::with_capacity(map.len());
    for (name, value) in map {
        match name.as_str() {
            ":method" if !value.is_empty() => method = value,
            ":path" if !value.is_empty() => map_path = Some(value),
            n if n.starts_with(':') => {} // :authority and unknown pseudo-headers dropped
            _ => headers.push((name, value)),
        }
    }
    if !super::callout::is_rfc7230_token(&method) {
        return None;
    }
    if let Some(p) = &map_path {
        if !super::callout::is_head_safe(p) {
            return None;
        }
    }
    for (name, value) in &headers {
        if !super::callout::is_rfc7230_token(name) || !super::callout::is_head_safe(name) {
            return None;
        }
        if !super::callout::is_head_safe(value) {
            return None;
        }
    }
    let mut effective = format!("{scheme}://{host}");
    if let Some(port) = parsed.port_u16() {
        effective.push_str(&format!(":{port}"));
    }
    let target = match parsed.path_and_query() {
        Some(pq) if pq.as_str() != "/" => pq.as_str().to_string(),
        _ => match map_path {
            Some(p) if p.starts_with('/') => p,
            _ => "/".to_string(),
        },
    };
    effective.push_str(&target);
    ctx.callout_token_counter = ctx.callout_token_counter.saturating_add(1);
    let token = ctx.callout_token_counter;
    ctx.pending_callouts.push(PendingCallout {
        token,
        uri: effective,
        method,
        headers,
        body,
        timeout_ms: timeout_ms.max(0) as u32,
    });
    Some(token)
}

// Unsupported-hostcall stubs, one per proxy-wasm spec ARITY (wasmtime's
// typed linking requires the import signature to match exactly; the
// Rust SDK declares every import with its spec signature even when the
// plugin never calls it). All return Status::InternalFailure (10).
// SDK 0.2.5 mapping of that status, exactly (hostcalls.rs):
//   - clean Err(Status::InternalFailure): the two remaining callout
//     dispatchers — dispatch_grpc_call and open_grpc_stream
//     (dispatch_http_call is implemented, DW-167).
//   - panic! on any non-Ok status: every other wrapper, including
//     send_grpc_stream_message and cancel_grpc_call/cancel_grpc_stream
//     (they map only BadArgument/NotFound to Err), set_tick_period,
//     the shared-queue calls, and call_foreign_function.
// A panicking wrapper traps the module, which the host reports as a
// plugin failure (trap -> 500 on the referencing route) — host-safe
// either way; the point of returning InternalFailure rather than some
// other status is that it is the one status the largest set of SDK
// wrappers handles without trapping. It is NOT a general "clean Err"
// for all callers.
fn stub_unsupported_1(_: wasmtime::Caller<PluginContext>, _a: i32) -> i32 {
    10 // Status::InternalFailure
}

fn stub_unsupported_3(_: wasmtime::Caller<PluginContext>, _a: i32, _b: i32, _c: i32) -> i32 {
    10 // Status::InternalFailure
}

fn stub_unsupported_4(
    _: wasmtime::Caller<PluginContext>,
    _a: i32,
    _b: i32,
    _c: i32,
    _d: i32,
) -> i32 {
    10 // Status::InternalFailure
}

fn stub_unsupported_5(
    _: wasmtime::Caller<PluginContext>,
    _a: i32,
    _b: i32,
    _c: i32,
    _d: i32,
    _e: i32,
) -> i32 {
    10 // Status::InternalFailure
}

fn stub_unsupported_6(
    _: wasmtime::Caller<PluginContext>,
    _a: i32,
    _b: i32,
    _c: i32,
    _d: i32,
    _e: i32,
    _f: i32,
) -> i32 {
    10 // Status::InternalFailure
}

#[allow(clippy::too_many_arguments)]
fn stub_unsupported_9(
    _: wasmtime::Caller<PluginContext>,
    _a: i32,
    _b: i32,
    _c: i32,
    _d: i32,
    _e: i32,
    _f: i32,
    _g: i32,
    _h: i32,
    _i: i32,
) -> i32 {
    10 // Status::InternalFailure
}

#[allow(clippy::too_many_arguments)]
fn stub_unsupported_12(
    _: wasmtime::Caller<PluginContext>,
    _a: i32,
    _b: i32,
    _c: i32,
    _d: i32,
    _e: i32,
    _f: i32,
    _g: i32,
    _h: i32,
    _i: i32,
    _j: i32,
    _k: i32,
    _l: i32,
) -> i32 {
    10 // Status::InternalFailure
}

/// The body of dwara's original `proxy_send_http_response` hostcall
/// (7 params; the WAT fixtures and host tests use this spelling). The
/// spec name `proxy_send_local_response` has a different signature and
/// is registered separately in [`WasmEngine::new`]. The header
/// argument here deliberately keeps dwara's LEGACY big-endian map
/// layout (abi::deserialize_header_map): modules written against this
/// spelling (dwara's example plugins) serialize that way, while the
/// spec-named hostcalls speak the SDK layout. The additive rule: the
/// legacy spelling keeps the legacy wire format.
#[allow(clippy::too_many_arguments)]
fn send_http_response_impl(
    mut caller: wasmtime::Caller<PluginContext>,
    status: i32,
    headers_ptr: i32,
    headers_size: i32,
    body_ptr: i32,
    body_size: i32,
    _trailers_ptr: i32,
    _trailers_size: i32,
) -> i32 {
    let memory = match caller.get_export("memory") {
        Some(wasmtime::Extern::Memory(m)) => m,
        _ => return 1,
    };
    let headers = if headers_ptr > 0 && headers_size > 0 {
        let data = match memory
            .data(&caller)
            .get(headers_ptr as usize..(headers_ptr as usize + headers_size as usize))
        {
            Some(slice) => slice.to_vec(),
            None => return 1,
        };
        match abi::deserialize_header_map(&data) {
            Some(h) => h,
            None => return 1,
        }
    } else {
        Vec::new()
    };
    let body = if body_ptr > 0 && body_size > 0 {
        match memory
            .data(&caller)
            .get(body_ptr as usize..(body_ptr as usize + body_size as usize))
        {
            Some(slice) => slice.to_vec(),
            None => return 1,
        }
    } else {
        Vec::new()
    };
    let ctx = caller.data_mut();
    ctx.local_response = Some(LocalResponse {
        status: status as u16,
        headers,
        body,
    });
    ctx.action = abi::ACTION_END_STREAM;
    0
}

/// The shared body of `proxy_get_current_time` /
/// `proxy_get_current_time_nanoseconds` (dwara's spelling and the
/// proxy-wasm spec spelling): nanoseconds since the Unix epoch.
fn get_current_time_impl(
    mut caller: wasmtime::Caller<PluginContext>,
    return_value_ptr: i32,
) -> i32 {
    let memory = match caller.get_export("memory") {
        Some(wasmtime::Extern::Memory(m)) => m,
        _ => return 1,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let bytes = now.to_le_bytes();
    if memory
        .data_mut(&mut caller)
        .get_mut(return_value_ptr as usize..(return_value_ptr as usize + 8))
        .map(|dst| dst.copy_from_slice(&bytes))
        .is_none()
    {
        return 1;
    }
    0
}

/// Seed for the WASI `random_get` stub: wall-clock nanoseconds mixed
/// with a process-global counter (two plugins seeded in the same
/// nanosecond still diverge). Not cryptographic.
fn wasi_random_seed() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    now ^ COUNTER
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_mul(0x9E3779B97F4A7C15)
}

/// Write an i32 value to a pointer in plugin memory.
fn write_i32_to_memory(
    memory: &wasmtime::Memory,
    mut store: impl wasmtime::AsContextMut,
    ptr: i32,
    value: i32,
) -> Result<(), String> {
    if ptr < 0 {
        return Err("negative pointer".to_string());
    }
    let bytes = value.to_le_bytes();
    let mut ctx = store.as_context_mut();
    memory
        .data_mut(&mut ctx)
        .get_mut(ptr as usize..(ptr as usize + 4))
        .ok_or("pointer out of bounds")?
        .copy_from_slice(&bytes);
    Ok(())
}

/// Allocate `size` bytes in the plugin's linear memory by calling the
/// plugin's `proxy_on_memory_allocate` export (the standard proxy-wasm
/// allocation pattern). Falls back to `memory.grow` if the export is
/// not present.
fn allocate_in_plugin(
    caller: &mut wasmtime::Caller<PluginContext>,
    memory: &wasmtime::Memory,
    size: usize,
) -> Result<usize, String> {
    // Try the standard proxy_on_memory_allocate export first.
    if let Some(wasmtime::Extern::Func(alloc_func)) = caller.get_export("proxy_on_memory_allocate")
    {
        if let Ok(typed) = alloc_func.typed::<(i32,), i32>(&mut *caller) {
            let ptr = typed
                .call(&mut *caller, (size as i32,))
                .map_err(|e| format!("proxy_on_memory_allocate: {e}"))?;
            if ptr > 0 {
                return Ok(ptr as usize);
            }
        }
    }
    // Fallback: grow the memory by one page and use the new space.
    let current = memory.data_size(&mut *caller);
    let needed = current + size;
    let pages_needed = (needed - current).div_ceil(65536);
    if pages_needed > 0 {
        memory
            .grow(&mut *caller, pages_needed as u64)
            .map_err(|e| format!("memory.grow: {e}"))?;
    }
    Ok(current)
}
