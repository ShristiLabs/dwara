//! Native plugin filters and the unified plugin dispatch chain (DW-119).
//!
//! This module provides the compile-in extension path for filters written
//! in Rust and linked into the gateway binary at build time -- the
//! convenience/performance counterpart to the proxy-wasm host (DW-055).
//! A native filter and a WASM plugin attach identically from config's
//! point of view: both are entries in the top-level `plugins` list,
//! referenced by name from routes, and both declare the same phase
//! contract. Only the implementation differs -- a native filter is a
//! Rust type implementing [`NativeFilter`] and registered with
//! [`NativeRegistry`], while a WASM plugin is a `.wasm` module loaded by
//! the `wasm` host.
//!
//! ## Phase contract (section 9.3)
//!
//! The phases and their outcome semantics mirror the proxy-wasm host
//! exactly (see [`wasm::runner::PhaseOutcome`] when the `wasm` feature is
//! enabled). The four HTTP filter phases are:
//!
//! 1. `request_headers` -- after route resolution, before authn.
//! 2. `request_body` -- after authn/authz/rate-limit, before upstream.
//! 3. `response_headers` -- after the upstream responds, before masking.
//! 4. `response_body` -- after masking, before compression.
//!
//! A native filter can short-circuit with a [`LocalResponse`] at any
//! phase, exactly as a WASM plugin can via `proxy_send_http_response`.
//!
//! ## Unified dispatch
//!
//! [`PluginChain`] is the single integration seam the dataplane calls.
//! Given a route's plugin names, the loaded WASM runner (when the `wasm`
//! feature is on), and the native registry, it builds the per-request
//! execution list combining native filters and WASM instances IN PHASE
//! ORDER (deterministic, using the same ordering logic as
//! `wasm::lifecycle::PluginLifecycle::phase_order`). It exposes the same
//! phase methods and dispatches to each plugin in order, threading
//! headers/body through and short-circuiting on `LocalResponse`/`Error`.
//!
//! ## Dependency direction
//!
//! `plugins` depends on `config` only. It does NOT depend on `wasm`:
//! the unified chain is generic over a [`WasmDispatch`] adapter so the
//! `wasm` domain (which may depend on `plugins`) can bridge its
//! per-request instances into the chain without an upward import. This
//! keeps the dependency direction strictly downward.
//!
//! ## Feature gate
//!
//! The module is feature-gated behind the `plugins` cargo feature
//! (default OFF). When `plugins` is on but `wasm` is off, only native
//! filters work; when both are on, both work. The unified dispatch
//! handles both.

pub mod chain;
pub mod filter;
pub mod registry;
// DW-109: Extism PDK plugin runtime. Feature-gated behind the
// `extism` cargo feature (default OFF). The scaffold types
// (ExtismHost, ExtismPlugin, ExtismDispatch) allow Extism plugins to
// be registered alongside native and WASM plugins in the unified
// dispatch chain. The actual extism runtime calls are STUBBED.
#[cfg(feature = "extism")]
pub mod extism;

pub use chain::{ChainOutcome, NoWasm, PluginChain, WasmDispatch};
pub use filter::{FilterOutcome, LocalResponse, NativeFilter};
pub use registry::{NativeFilterFactory, NativeRegistry, RegistryError};
