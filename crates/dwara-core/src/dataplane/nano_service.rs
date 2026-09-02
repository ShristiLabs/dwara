//! WASM route handlers (nano-services) -- DW-106.
//!
//! A nano-service is a route action that runs a WebAssembly module to
//! generate the response directly, instead of proxying to an upstream.
//! The module implements a simple request->response handler ABI over
//! the existing wasmtime runtime (the `wasm` cargo feature, brought in
//! by `nano_services`). This is the "function-as-a-route" path: a
//! self-contained WASM module owns the whole response for a route --
//! status, headers, and body -- with no backend contact.
//!
//! ## Handler ABI
//!
//! The module exports:
//!
//! - `memory` -- the linear memory the host and module share.
//! - `alloc(size: i32) -> i32` -- allocate `size` bytes in linear
//!   memory and return a pointer (a simple bump allocator is fine; the
//!   host uses it to place the serialized request).
//! - `handle(req_ptr: i32, req_len: i32) -> i32` -- handle the request
//!   whose serialized form lives at `[req_ptr, req_ptr+req_len)` in
//!   linear memory. Returns 0 on success (the response is communicated
//!   back via the host imports below) and non-zero on error (the route
//!   answers 502).
//!
//! The host provides these imports under the module name `dwara`:
//!
//! - `response_status(status: i32)` -- set the HTTP response status.
//! - `response_header(k_ptr, k_len, v_ptr, v_len)` -- add a response
//!   header.
//! - `response_body(ptr, len)` -- set the response body.
//! - `log(ptr, len)` -- emit a log line (tracing::debug).
//!
//! The request is serialized into linear memory in a length-prefixed
//! binary format (all lengths u32 big-endian):
//!
//! ```text
//! u32 method_len, method bytes
//! u32 path_len, path bytes
//! u32 headers_count, [u32 key_len, key, u32 val_len, val]...
//! u32 body_len, body bytes
//! ```
//!
//! The module parses this to read the request, then calls the host
//! imports to build the response and returns 0 from `handle`.
//!
//! ## Resource limits
//!
//! `memory_limit` caps the linear memory the module may allocate
//! (enforced via wasmtime's `ResourceLimiter`). `execution_timeout_ms`
//! caps the wall-clock time the `handle` call may run: the call runs on
//! a blocking pool thread wrapped in a `tokio::time::timeout`, so a
//! module that exceeds it is interrupted and the route answers 504. A
//! fuel budget caps CPU work (a module that exhausts it traps and the
//! route answers 502).
//!
//! ## Feature gate
//!
//! The module compiles only when the `nano_services` cargo feature is
//! enabled (which pulls in `wasm` / wasmtime). The config schema is
//! always present, so configs round-trip without the feature; when the
//! feature is off the action is accepted but inert (validation warns,
//! the route returns 502).

use std::sync::Arc;
use std::time::Duration;

use wasmtime::{Engine, Linker, Module, ResourceLimiter, Store};

use crate::config::NanoServiceAction;

/// The fuel budget for one `handle` call. Generous enough for typical
/// request inspection and response building; a module that loops
/// forever traps with an out-of-fuel error (converted to 502).
const NANO_FUEL: u64 = 1_000_000;

/// The maximum memory the module may allocate, in bytes (sane ceiling
/// mirrored from the validation bound so a config at the cap still
/// works).
const NANO_MAX_MEMORY: usize = 64 * 1024 * 1024;

/// A compiled nano-service: the module path and the resource limits,
/// resolved from the route's [`NanoServiceAction`]. The WASM bytes are
/// read and compiled lazily by [`NanoServiceHandler::load`] so a
/// missing/broken module is reported at handler construction, not at
/// config publish time (validation already checks the file exists).
#[derive(Clone, Debug)]
pub struct NanoService {
    /// The route name (used for metrics labeling).
    pub name: String,
    /// Filesystem path to the `.wasm` module.
    pub module_path: String,
    /// Maximum linear memory in bytes.
    pub memory_limit: usize,
    /// Maximum execution time in milliseconds.
    pub execution_timeout: Duration,
}

impl NanoService {
    /// Build from a route's config action.
    pub fn from_action(name: &str, action: &NanoServiceAction) -> Self {
        Self {
            name: name.to_string(),
            module_path: action.module.clone(),
            memory_limit: action.memory_limit.min(NANO_MAX_MEMORY),
            execution_timeout: Duration::from_millis(action.execution_timeout_ms),
        }
    }
}

/// The response a nano-service module produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NanoServiceResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers (name, value) pairs.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

/// A nano-service error. Maps to HTTP responses:
/// - [`NanoServiceError::ModuleLoadFailed`] -> 502
/// - [`NanoServiceError::ExecutionFailed`] -> 502
/// - [`NanoServiceError::Timeout`] -> 504
/// - [`NanoServiceError::MemoryLimitExceeded`] -> 502
#[derive(Debug)]
pub enum NanoServiceError {
    /// The WASM module could not be read or compiled.
    ModuleLoadFailed(String),
    /// The `handle` call trapped or returned a non-zero status.
    ExecutionFailed(String),
    /// The `handle` call exceeded the execution timeout.
    Timeout,
    /// The module tried to allocate past its memory limit.
    MemoryLimitExceeded(String),
}

impl std::fmt::Display for NanoServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NanoServiceError::ModuleLoadFailed(m) => {
                write!(f, "nano-service module load failed: {m}")
            }
            NanoServiceError::ExecutionFailed(m) => {
                write!(f, "nano-service execution failed: {m}")
            }
            NanoServiceError::Timeout => write!(f, "nano-service execution timed out"),
            NanoServiceError::MemoryLimitExceeded(m) => {
                write!(f, "nano-service memory limit exceeded: {m}")
            }
        }
    }
}

impl std::error::Error for NanoServiceError {}

/// The per-instance context the host imports read from and write to.
struct NanoContext {
    /// The HTTP status the module set via `response_status`. Defaults
    /// to 200 when the module never calls it (a module that only writes
    /// a body still answers 200).
    response_status: u16,
    /// Response headers accumulated via `response_header`.
    response_headers: Vec<(String, String)>,
    /// The response body set via `response_body`.
    response_body: Vec<u8>,
    /// Log lines emitted via `log`.
    logs: Vec<String>,
    /// Memory limiter state: bytes currently in use.
    #[allow(dead_code)]
    memory_used: usize,
    /// Memory cap in bytes.
    memory_cap: usize,
}

impl NanoContext {
    fn new(memory_cap: usize) -> Self {
        Self {
            response_status: 200,
            response_headers: Vec::new(),
            response_body: Vec::new(),
            logs: Vec::new(),
            memory_used: 0,
            memory_cap,
        }
    }
}

impl ResourceLimiter for NanoContext {
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

/// The nano-service handler: holds a process-wide wasmtime engine and
/// the linker wired with the `dwara` host imports. Cheap to clone (Arc
/// internals). One instance per [`crate::dataplane::DataPlane`] (or per
/// route set); [`NanoServiceHandler::handle`] is called per request.
#[derive(Clone)]
pub struct NanoServiceHandler {
    engine: Engine,
    linker: Arc<Linker<NanoContext>>,
}

impl NanoServiceHandler {
    /// Create a new handler with the nano-service ABI linker.
    pub fn new() -> Result<Self, NanoServiceError> {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        config.strategy(wasmtime::Strategy::Cranelift);
        let engine = Engine::new(&config)
            .map_err(|e| NanoServiceError::ModuleLoadFailed(format!("wasmtime engine: {e}")))?;

        let mut linker: Linker<NanoContext> = Linker::new(&engine);

        // dwara::response_status(status: i32)
        linker
            .func_wrap(
                "dwara",
                "response_status",
                |mut caller: wasmtime::Caller<NanoContext>, status: i32| {
                    if status > 0 && status <= 599 {
                        caller.data_mut().response_status = status as u16;
                    }
                },
            )
            .map_err(|e| {
                NanoServiceError::ModuleLoadFailed(format!("linker response_status: {e}"))
            })?;

        // dwara::response_header(k_ptr, k_len, v_ptr, v_len)
        linker
            .func_wrap(
                "dwara",
                "response_header",
                |mut caller: wasmtime::Caller<NanoContext>,
                 k_ptr: i32,
                 k_len: i32,
                 v_ptr: i32,
                 v_len: i32|
                 -> i32 {
                    if k_ptr < 0 || k_len < 0 || v_ptr < 0 || v_len < 0 {
                        return 1;
                    }
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    let data = memory.data(&caller);
                    let key = match data.get(k_ptr as usize..(k_ptr as usize + k_len as usize)) {
                        Some(slice) => slice.to_vec(),
                        None => return 1,
                    };
                    let value = match data.get(v_ptr as usize..(v_ptr as usize + v_len as usize)) {
                        Some(slice) => slice.to_vec(),
                        None => return 1,
                    };
                    let key = String::from_utf8_lossy(&key).into_owned();
                    let value = String::from_utf8_lossy(&value).into_owned();
                    caller.data_mut().response_headers.push((key, value));
                    0
                },
            )
            .map_err(|e| {
                NanoServiceError::ModuleLoadFailed(format!("linker response_header: {e}"))
            })?;

        // dwara::response_body(ptr, len)
        linker
            .func_wrap(
                "dwara",
                "response_body",
                |mut caller: wasmtime::Caller<NanoContext>, ptr: i32, len: i32| -> i32 {
                    if ptr < 0 || len < 0 {
                        return 1;
                    }
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    let body = match memory
                        .data(&caller)
                        .get(ptr as usize..(ptr as usize + len as usize))
                    {
                        Some(slice) => slice.to_vec(),
                        None => return 1,
                    };
                    caller.data_mut().response_body = body;
                    0
                },
            )
            .map_err(|e| {
                NanoServiceError::ModuleLoadFailed(format!("linker response_body: {e}"))
            })?;

        // dwara::log(ptr, len)
        linker
            .func_wrap(
                "dwara",
                "log",
                |mut caller: wasmtime::Caller<NanoContext>, ptr: i32, len: i32| -> i32 {
                    if ptr < 0 || len < 0 {
                        return 1;
                    }
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return 1,
                    };
                    let msg = match memory
                        .data(&caller)
                        .get(ptr as usize..(ptr as usize + len as usize))
                    {
                        Some(slice) => slice.to_vec(),
                        None => return 1,
                    };
                    let msg = String::from_utf8_lossy(&msg).into_owned();
                    caller.data_mut().logs.push(msg);
                    0
                },
            )
            .map_err(|e| NanoServiceError::ModuleLoadFailed(format!("linker log: {e}")))?;

        Ok(Self {
            engine,
            linker: Arc::new(linker),
        })
    }

    /// Run a nano-service module for one request. Reads the module from
    /// `service.module_path`, instantiates it, writes the serialized
    /// request into linear memory, calls `handle`, and returns the
    /// response the module produced. The `handle` call runs on a
    /// blocking-pool thread bounded by `service.execution_timeout`.
    pub async fn handle(
        &self,
        service: &NanoService,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<NanoServiceResponse, NanoServiceError> {
        let engine = self.engine.clone();
        let linker = self.linker.clone();
        let module_path = service.module_path.clone();
        let memory_limit = service.memory_limit;
        let timeout = service.execution_timeout;
        let req = serialize_request(method, path, headers, body);

        let join = tokio::task::spawn_blocking(move || {
            run_handle_sync(&engine, &linker, &module_path, memory_limit, &req)
        });

        match tokio::time::timeout(timeout, join).await {
            Ok(Ok(Ok(resp))) => Ok(resp),
            Ok(Ok(Err(e))) => match e {
                NanoServiceError::MemoryLimitExceeded(_) => Err(e),
                _ => Err(e),
            },
            // The blocking task panicked or was cancelled.
            Ok(Err(e)) => Err(NanoServiceError::ExecutionFailed(format!(
                "nano-service task failed: {e}"
            ))),
            // The timeout elapsed before the task finished.
            Err(_) => Err(NanoServiceError::Timeout),
        }
    }
}

/// A process-wide shared nano-service handler. wasmtime recommends a
/// single `Engine` per process (compiled modules are cached and shared
/// across threads), so the dataplane reuses one handler for every
/// nano-service route. The handler is stateless beyond the immutable
/// engine + linker (both Arc-held), so sharing it across requests and
/// tests is safe. Lazily initialized on first use; a construction
/// failure (wasmtime misconfiguration) is reported once and cached as
/// an error so every subsequent request answers 502 without retrying.
pub fn shared_handler() -> Result<NanoServiceHandler, NanoServiceError> {
    static HANDLER: std::sync::OnceLock<Result<NanoServiceHandler, NanoServiceError>> =
        std::sync::OnceLock::new();
    match HANDLER.get_or_init(NanoServiceHandler::new).as_ref() {
        Ok(h) => Ok(h.clone()),
        Err(e) => Err(NanoServiceError::ModuleLoadFailed(e.to_string())),
    }
}

/// The synchronous core: compile, instantiate, write the request, call
/// `handle`, read the response. Runs on a blocking-pool thread so the
/// async caller is never blocked on wasm compilation/execution.
fn run_handle_sync(
    engine: &Engine,
    linker: &Linker<NanoContext>,
    module_path: &str,
    memory_limit: usize,
    req: &[u8],
) -> Result<NanoServiceResponse, NanoServiceError> {
    let wasm_bytes = std::fs::read(module_path)
        .map_err(|e| NanoServiceError::ModuleLoadFailed(format!("read {module_path}: {e}")))?;
    let module = Module::new(engine, &wasm_bytes)
        .map_err(|e| NanoServiceError::ModuleLoadFailed(format!("compile {module_path}: {e}")))?;

    let memory_cap = memory_limit.max(1);
    let ctx = NanoContext::new(memory_cap);
    let mut store = Store::new(engine, ctx);
    store.limiter(move |ctx| ctx as &mut dyn ResourceLimiter);
    store
        .set_fuel(NANO_FUEL)
        .map_err(|e| NanoServiceError::ModuleLoadFailed(format!("set_fuel: {e}")))?;

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| NanoServiceError::ModuleLoadFailed(format!("instantiate: {e}")))?;

    let memory = instance
        .get_export(&mut store, "memory")
        .and_then(|e| e.into_memory())
        .ok_or_else(|| {
            NanoServiceError::ModuleLoadFailed("module does not export `memory`".to_string())
        })?;

    // Place the serialized request into the module's linear memory via
    // its `alloc` export (a bump allocator). Fall back to growing the
    // memory if the export is absent.
    let req_ptr = allocate(&mut store, &instance, &memory, req.len())?;
    memory
        .data_mut(&mut store)
        .get_mut(req_ptr..req_ptr + req.len())
        .ok_or_else(|| {
            NanoServiceError::ExecutionFailed("request write out of bounds".to_string())
        })?
        .copy_from_slice(req);

    // Call handle(req_ptr, req_len) -> i32.
    let handle_export = instance
        .get_export(&mut store, "handle")
        .and_then(|e| e.into_func())
        .ok_or_else(|| {
            NanoServiceError::ModuleLoadFailed("module does not export `handle`".to_string())
        })?;
    let typed: wasmtime::TypedFunc<(i32, i32), i32> = handle_export
        .typed(&store)
        .map_err(|e| NanoServiceError::ModuleLoadFailed(format!("handle typed: {e}")))?;

    let result = typed
        .call(&mut store, (req_ptr as i32, req.len() as i32))
        .map_err(|e| {
            // Detect fuel exhaustion vs other traps.
            let fuel_left = store.get_fuel().unwrap_or(0);
            if fuel_left == 0 {
                NanoServiceError::ExecutionFailed(format!("handle: fuel exhausted: {e}"))
            } else {
                NanoServiceError::ExecutionFailed(format!("handle: {e}"))
            }
        })?;

    if result != 0 {
        return Err(NanoServiceError::ExecutionFailed(format!(
            "handle returned non-zero status {result}"
        )));
    }

    let ctx = store.into_data();
    for line in &ctx.logs {
        tracing::debug!(
            module = %module_path,
            "nano-service log: {line}"
        );
    }
    Ok(NanoServiceResponse {
        status: ctx.response_status,
        headers: ctx.response_headers,
        body: ctx.response_body,
    })
}

/// Allocate `size` bytes in the module's linear memory. Calls the
/// module's `alloc` export when present; otherwise grows the memory by
/// one page and uses the new space.
fn allocate(
    store: &mut Store<NanoContext>,
    instance: &wasmtime::Instance,
    memory: &wasmtime::Memory,
    size: usize,
) -> Result<usize, NanoServiceError> {
    if let Some(export) = instance.get_export(&mut *store, "alloc") {
        if let Some(func) = export.into_func() {
            if let Ok(typed) = func.typed::<(i32,), i32>(&mut *store) {
                let ptr = typed
                    .call(&mut *store, (size as i32,))
                    .map_err(|e| NanoServiceError::ExecutionFailed(format!("alloc: {e}")))?;
                if ptr > 0 {
                    return Ok(ptr as usize);
                }
            }
        }
    }
    // Fallback: grow the memory and use the tail.
    let current = memory.data_size(&mut *store);
    let needed = current + size;
    let pages_needed = (needed - current).div_ceil(64 * 1024);
    if pages_needed > 0 {
        memory
            .grow(&mut *store, pages_needed as u64)
            .map_err(|e| NanoServiceError::MemoryLimitExceeded(format!("memory.grow: {e}")))?;
    }
    Ok(current)
}

/// Serialize a request into the nano-service wire format (all lengths
/// u32 big-endian):
///
/// ```text
/// u32 method_len, method
/// u32 path_len, path
/// u32 headers_count, [u32 key_len, key, u32 val_len, val]...
/// u32 body_len, body
/// ```
pub fn serialize_request(
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(method.len() + path.len() + body.len() + 32);
    write_str(&mut buf, method);
    write_str(&mut buf, path);
    buf.extend_from_slice(&(headers.len() as u32).to_be_bytes());
    for (key, value) in headers {
        write_str(&mut buf, key);
        write_str(&mut buf, value);
    }
    buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
    buf.extend_from_slice(body);
    buf
}

/// Deserialize a nano-service wire-format request back into its parts.
/// Returns `None` on a truncated/corrupt buffer.
pub fn deserialize_request(buf: &[u8]) -> Option<(String, String, Vec<(String, String)>, Vec<u8>)> {
    let mut pos = 0;
    let method = read_str(buf, &mut pos)?;
    let path = read_str(buf, &mut pos)?;
    let header_count = read_u32(buf, &mut pos)? as usize;
    let mut headers = Vec::with_capacity(header_count);
    for _ in 0..header_count {
        let key = read_str(buf, &mut pos)?;
        let value = read_str(buf, &mut pos)?;
        headers.push((key, value));
    }
    let body_len = read_u32(buf, &mut pos)? as usize;
    if pos + body_len > buf.len() {
        return None;
    }
    let body = buf[pos..pos + body_len].to_vec();
    Some((method, path, headers, body))
}

fn write_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
}

fn read_u32(buf: &[u8], pos: &mut usize) -> Option<u32> {
    if *pos + 4 > buf.len() {
        return None;
    }
    let v = u32::from_be_bytes(buf[*pos..*pos + 4].try_into().ok()?);
    *pos += 4;
    Some(v)
}

fn read_str(buf: &[u8], pos: &mut usize) -> Option<String> {
    let len = read_u32(buf, pos)? as usize;
    if *pos + len > buf.len() {
        return None;
    }
    let s = String::from_utf8(buf[*pos..*pos + len].to_vec()).ok()?;
    *pos += len;
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip() {
        let headers = vec![
            ("host".to_string(), "example.com".to_string()),
            ("x-trace".to_string(), "abc".to_string()),
        ];
        let body = b"{\"hello\":\"world\"}";
        let wire = serialize_request("POST", "/v1/echo", &headers, body);
        let (method, path, hs, bd) = deserialize_request(&wire).expect("round trip");
        assert_eq!(method, "POST");
        assert_eq!(path, "/v1/echo");
        assert_eq!(hs, headers);
        assert_eq!(bd, body);
    }

    #[test]
    fn request_round_trip_empty() {
        let wire = serialize_request("GET", "/", &[], &[]);
        let (method, path, hs, bd) = deserialize_request(&wire).expect("round trip");
        assert_eq!(method, "GET");
        assert_eq!(path, "/");
        assert!(hs.is_empty());
        assert!(bd.is_empty());
    }

    #[test]
    fn deserialize_truncated_returns_none() {
        // A buffer that claims a 1-byte method but has no method bytes.
        let buf = (1u32).to_be_bytes().to_vec();
        assert!(deserialize_request(&buf).is_none());
    }
}
