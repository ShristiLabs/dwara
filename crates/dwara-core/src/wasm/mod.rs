//! proxy-wasm host (DW-055).
//!
//! This module implements a proxy-wasm ABI host on top of wasmtime,
//! allowing dwara to run community Kong/Envoy proxy-wasm filters
//! unmodified. The host compiles unconditionally in the OSS build
//! (there are no cargo features for it): `dataplane::plugin_dispatch`
//! (DW-157) drives it on the live request path for routes that
//! reference plugins.
//!
//! ## Architecture
//!
//! - [`abi`] — proxy-wasm ABI constants and header map serialization.
//! - [`host`] — the wasmtime host: engine, linker (ABI imports), plugin
//!   module, and per-request instance.
//!
//! ## Phase contract (§9.3)
//!
//! dwara's request pipeline calls plugin phase callbacks at defined
//! points. Each plugin declares which phase(s) it hooks. The phases
//! relevant to HTTP filters are:
//!
//! 1. `request_headers` — after route resolution, before authn.
//! 2. `request_body` — after authn/authz/rate-limit, before upstream.
//! 3. `response_headers` — after the upstream responds, before masking.
//! 4. `response_body` — after masking, before compression.
//!
//! A plugin can short-circuit the request by calling
//! `proxy_send_http_response` (returns a local response instead of
//! forwarding to the upstream). The host catches this and returns the
//! stored response immediately.
//!
//! ## Fuel and epoch preemption (decision 4; §9.3)
//!
//! Each plugin instance gets a fuel budget ([`PluginLimits::fuel`]).
//! wasmtime consumes fuel on every operation; exhaustion traps the
//! plugin, which the host converts to a 500. Memory is capped via
//! wasmtime's `ResourceLimiter`. Time caps use epoch interruption.
//!
//! ## Done-when
//!
//! A community Kong/Envoy proxy-wasm filter runs unmodified. The test
//! suite includes a minimal proxy-wasm filter compiled from Rust source
//! that exercises the core ABI surface (header inspection, response
//! short-circuit, body modification).

pub mod abi;
pub mod host;
pub mod lifecycle;
pub mod runner;
// DW-119: the WASM-to-unified-chain adapter. Bridges the proxy-wasm
// host's per-request instances into the unified plugin chain (plugins
// domain) so native filters and WASM plugins share the same phase
// slot; compiles unconditionally alongside the rest of the host.
pub mod adapter;
// DW-165: registry plugin source resolution (cache-first fetch,
// SHA-256 digest + Ed25519 signature verification, atomic digest-
// named cache) — the step before `lifecycle` loads the bytes.
pub mod source;
// DW-167: the plugin HTTP callout transport (proxy_http_call). The
// pause/resume driver lives at the async plugin_dispatch boundary in
// the dataplane; this module is the synchronous exchange itself.
pub mod callout;

pub use abi::{deserialize_header_map, serialize_header_map, ACTION_CONTINUE, ACTION_END_STREAM};
pub use callout::{
    perform_callout, CalloutError, CalloutRequest, CalloutResponse, CALLOUT_BODY_CAP_BYTES,
    CALLOUT_TIMEOUT_MAX_MS, CALLOUT_TIMEOUT_MIN_MS, MAX_CALLOUT_ROUNDS,
};
pub use host::{
    LocalResponse, PendingCallout, PhaseResult, PluginContext, PluginInstance, PluginLimits,
    PluginMetric, PluginMetricType, PluginModule, WasmEngine,
};
pub use lifecycle::{LoadError, LoadedPlugin, PluginHealth, PluginLifecycle, ValidationError};
pub use runner::{PhaseOutcome, PluginInstances, PluginRunner};
pub use source::{resolve_sources, SourceError, SourceResolutions, DEFAULT_CACHE_DIR};
