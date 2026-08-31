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

use std::collections::HashMap;
use std::sync::Arc;

use wasmtime::{Engine, Linker, Module, ResourceLimiter, Store};

use super::abi;

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
    /// Shared data store (cross-instance, within one plugin module).
    /// Keys are strings; values are bytes with a CAS version for
    /// optimistic concurrency.
    pub shared_data: HashMap<String, (Vec<u8>, u32)>,
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

/// Metric types (proxy-wasm §2.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PluginMetricType {
    Counter,
    Gauge,
    Histogram,
}

impl PluginContext {
    fn new(plugin_config: Vec<u8>, vm_config: Vec<u8>, memory_cap: usize) -> Self {
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
            shared_data: HashMap::new(),
            metrics: HashMap::new(),
            current_context_id: 0,
            effective_context_id: 0,
            done: false,
            memory_used: 0,
            memory_cap,
        }
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
                    caller.data_mut().logs.push((level as u32, msg));
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
                            _ => return 1,
                        }
                    };
                    let encoded = abi::serialize_header_map(&headers);
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    if encoded.is_empty() {
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
                    let headers = match abi::deserialize_header_map(&data) {
                        Some(h) => h,
                        None => return 1,
                    };
                    let ctx = caller.data_mut();
                    match bt as u32 {
                        abi::BUFFER_REQUEST_HEADERS => ctx.request_headers = headers,
                        abi::BUFFER_RESPONSE_HEADERS => ctx.response_headers = headers,
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
                        let headers = match bt as u32 {
                            abi::BUFFER_REQUEST_HEADERS => &ctx.request_headers,
                            abi::BUFFER_RESPONSE_HEADERS => &ctx.response_headers,
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
        linker
            .func_wrap(
                "env",
                "proxy_send_http_response",
                |mut caller: wasmtime::Caller<PluginContext>,
                 status: i32,
                 headers_ptr: i32,
                 headers_size: i32,
                 body_ptr: i32,
                 body_size: i32,
                 _trailers_ptr: i32,
                 _trailers_size: i32|
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
                },
            )
            .map_err(|e| format!("linker proxy_send_http_response: {e}"))?;

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
                    let (value, cas) = {
                        let ctx = caller.data();
                        match ctx.shared_data.get(&key) {
                            Some((v, c)) => (v.clone(), *c),
                            None => {
                                // Not found: return OK with zero values.
                                if write_i32_to_memory(&memory, &mut caller, value_ptr_ptr, 0)
                                    .is_err()
                                {
                                    return 1;
                                }
                                if write_i32_to_memory(&memory, &mut caller, value_size_ptr, 0)
                                    .is_err()
                                {
                                    return 1;
                                }
                                if write_i32_to_memory(&memory, &mut caller, cas_ptr, 0).is_err() {
                                    return 1;
                                }
                                return 0;
                            }
                        }
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
                    let current_cas = ctx.shared_data.get(&key).map(|(_, c)| *c).unwrap_or(0);
                    if cas > 0 && cas != current_cas as i32 {
                        return 1; // CAS mismatch
                    }
                    let new_cas = current_cas + 1;
                    ctx.shared_data.insert(key, (value, new_cas));
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
        linker
            .func_wrap(
                "env",
                "proxy_get_current_time",
                |mut caller: wasmtime::Caller<PluginContext>, return_value_ptr: i32| -> i32 {
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
                },
            )
            .map_err(|e| format!("linker proxy_get_current_time: {e}"))?;

        // Stub imports for functions we don't implement but the plugin
        // may call (returns error to signal unsupported).
        for name in [
            "proxy_register_shared_queue",
            "proxy_resolve_shared_queue",
            "proxy_dequeue_shared_queue",
            "proxy_enqueue_shared_queue",
            "proxy_http_call",
            "proxy_grpc_call",
            "proxy_grpc_stream",
            "proxy_grpc_cancel",
            "proxy_grpc_close",
            "proxy_grpc_send",
            "proxy_set_tick_period_milliseconds",
            "proxy_call_foreign_function",
        ] {
            linker
                .func_wrap("env", name, |_: wasmtime::Caller<PluginContext>| -> i32 {
                    1
                })
                .map_err(|e| format!("linker {name}: {e}"))?;
        }

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

        let mut inst = PluginInstance { store, instance };

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
}

impl PluginInstance {
    /// Set the current context ID (used by exports that receive a
    /// context_id parameter).
    fn set_context_id(&mut self, id: u32) {
        self.store.data_mut().current_context_id = id;
        self.store.data_mut().effective_context_id = id;
    }

    /// Call `proxy_on_request_headers(context_id, num_headers, end_of_stream)`.
    /// Sets the request headers in the context before calling.
    pub fn on_request_headers(&mut self, headers: Vec<(String, String)>) -> PhaseResult {
        self.store.data_mut().request_headers = headers;
        let num_headers = self.store.data().request_headers.len() as i32;
        self.set_context_id(2);
        self.call_phase_export("proxy_on_request_headers", (2, num_headers, 1))
    }

    /// Call `proxy_on_request_body(context_id, body_size, end_of_stream)`.
    /// Sets the request body in the context before calling.
    pub fn on_request_body(&mut self, body: Vec<u8>) -> PhaseResult {
        self.store.data_mut().request_body = body;
        let body_size = self.store.data().request_body.len() as i32;
        self.set_context_id(2);
        self.call_phase_export("proxy_on_request_body", (2, body_size, 1))
    }

    /// Call `proxy_on_response_headers(context_id, num_headers, end_of_stream)`.
    /// Sets the response headers in the context before calling.
    pub fn on_response_headers(&mut self, headers: Vec<(String, String)>) -> PhaseResult {
        self.store.data_mut().response_headers = headers;
        let num_headers = self.store.data().response_headers.len() as i32;
        self.set_context_id(2);
        self.call_phase_export("proxy_on_response_headers", (2, num_headers, 1))
    }

    /// Call `proxy_on_response_body(context_id, body_size, end_of_stream)`.
    /// Sets the response body in the context before calling.
    pub fn on_response_body(&mut self, body: Vec<u8>) -> PhaseResult {
        self.store.data_mut().response_body = body;
        let body_size = self.store.data().response_body.len() as i32;
        self.set_context_id(2);
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

    /// Call `proxy_on_done` and `proxy_on_log` (the cleanup path).
    pub fn on_done(&mut self) {
        self.set_context_id(2);
        let _ = self.call_phase_export_no_result("proxy_on_done", (2,));
        let _ = self.call_phase_export_no_result("proxy_on_log", (2,));
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

    /// Call a phase export that takes (context_id,) and returns nothing.
    fn call_phase_export_no_result(&mut self, name: &str, args: (i32,)) -> Result<(), String> {
        let export = match self.instance.get_export(&mut self.store, name) {
            Some(e) => e,
            None => return Ok(()),
        };
        let func = match export.into_func() {
            Some(f) => f,
            None => return Ok(()),
        };
        let typed: wasmtime::TypedFunc<(i32,), ()> = match func.typed(&self.store) {
            Ok(t) => t,
            Err(e) => return Err(format!("{name} typed: {e}")),
        };
        typed
            .call(&mut self.store, args)
            .map_err(|e| format!("{name}: {e}"))
    }
}

// --- Helper functions ----------------------------------------------------

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
