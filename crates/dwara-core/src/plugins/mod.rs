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
//! exactly (see `wasm::runner::PhaseOutcome`). The four HTTP filter
//! phases are:
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
//! Given a route's plugin names, the loaded WASM runner, and the native
//! registry, it builds the per-request
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
//! `wasm` domain (which depends on `plugins`) can bridge its per-request
//! instances into the chain without an upward import. This keeps the
//! dependency direction strictly downward.
//!
//! ## Dispatch wiring (DW-157)
//!
//! Both filter paths compile unconditionally in the OSS build (there
//! are no cargo features for plugins): the dataplane builds one
//! [`PluginChain`] per request on routes that reference plugins
//! (`dataplane::plugin_dispatch`) and drives it at the four phase
//! points above, always through the `wasm` domain's `WasmChainAdapter`
//! (native-only chains carry an EMPTY instance set, so every per-name
//! WASM dispatch passes through). [`NoWasm`] remains the no-op adapter
//! for tests.

pub mod chain;
pub mod filter;
pub mod registry;

pub use chain::{ChainOutcome, NativeCreateFailure, NoWasm, PluginChain, WasmDispatch};
pub use filter::{FilterOutcome, LocalResponse, NativeFilter};
pub use registry::{NativeFilterFactory, NativeRegistry, RegistryError};
