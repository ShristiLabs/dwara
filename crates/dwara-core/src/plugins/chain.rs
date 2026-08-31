//! The unified plugin dispatch chain (DW-119).
//!
//! [`PluginChain`] is the single integration seam the dataplane calls.
//! Given a route's plugin names, the gateway's plugin configs, the
//! native registry, and an optional WASM dispatch adapter, it builds
//! the per-request execution list combining native filters and WASM
//! instances IN PHASE ORDER (deterministic, using the same ordering
//! logic as `wasm::lifecycle::PluginLifecycle::phase_order`). It
//! exposes the same phase methods as the WASM runner
//! (`on_request_headers`, `on_request_body`, `on_response_headers`,
//! `on_response_body`) and dispatches to each plugin in order, threading
//! headers/body through and short-circuiting on `LocalResponse`/`Error`.
//!
//! ## Why a generic WasmDispatch adapter
//!
//! `plugins` must not depend on `wasm` (that would be an upward import
//! once `wasm` depends on `plugins` for the adapter). Instead, the
//! chain is generic over a [`WasmDispatch`] trait -- a minimal
//! per-request interface the `wasm` domain implements to bridge its
//! `PluginInstances` into the unified chain. When the `wasm` feature is
//! off, the chain is constructed with [`NoWasm`] and only native filters
//! run.
//!
//! ## Attachment semantics equivalence
//!
//! A native filter and a WASM plugin occupy the same phase slot on the
//! same route, selected by config. The chain orders them by their
//! position in the route's `plugins` list within each phase (the same
//! deterministic order `phase_order` produces), so there is no
//! dataplane-visible difference in attachment semantics -- only the
//! implementation differs (compiled-in vs sandboxed).

use std::collections::HashMap;

use crate::config::{PluginConfig, PluginPhase};

use super::filter::{FilterOutcome, LocalResponse, NativeFilter};
use super::registry::NativeRegistry;

/// The per-request outcome of a unified chain phase, mirroring
/// `wasm::runner::PhaseOutcome` so the dataplane treats native and WASM
/// plugins identically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainOutcome {
    /// All plugins in the phase returned Continue. The request proceeds
    /// normally; the (possibly modified) headers/body are returned.
    Continue,
    /// A plugin short-circuited with a local response. The proxy should
    /// return this response immediately.
    LocalResponse(LocalResponse),
    /// A plugin errored (native filter error or WASM trap). The proxy
    /// should return a 500.
    Error(String),
}

/// A minimal per-request WASM dispatch interface the `wasm` domain
/// implements to bridge its `PluginInstances` into the unified chain.
///
/// The chain calls these methods on the adapter for each WASM plugin in
/// the phase, in order. The adapter holds the per-request WASM
/// instances and delegates to `PluginInstances`'s phase methods. When
/// the `wasm` feature is off, [`NoWasm`] is a no-op adapter that always
/// returns [`ChainOutcome::Continue`].
pub trait WasmDispatch {
    /// Run `on_request_headers` for the named WASM plugin. Returns the
    /// outcome and the (possibly modified) headers.
    fn on_request_headers(
        &mut self,
        name: &str,
        headers: Vec<(String, String)>,
    ) -> (ChainOutcome, Vec<(String, String)>);

    /// Run `on_request_body` for the named WASM plugin. Returns the
    /// outcome and the (possibly modified) body.
    fn on_request_body(&mut self, name: &str, body: Vec<u8>) -> (ChainOutcome, Vec<u8>);

    /// Run `on_response_headers` for the named WASM plugin. Returns the
    /// outcome and the (possibly modified) headers.
    fn on_response_headers(
        &mut self,
        name: &str,
        headers: Vec<(String, String)>,
    ) -> (ChainOutcome, Vec<(String, String)>);

    /// Run `on_response_body` for the named WASM plugin. Returns the
    /// outcome and the (possibly modified) body.
    fn on_response_body(&mut self, name: &str, body: Vec<u8>) -> (ChainOutcome, Vec<u8>);

    /// Call `on_done` for all WASM instances (the cleanup path).
    fn on_done(&mut self) {}
}

/// A no-op WASM dispatch adapter for builds without the `wasm` feature
/// (or routes with no WASM plugins). Every method returns
/// [`ChainOutcome::Continue`] with the input unchanged.
#[derive(Default)]
pub struct NoWasm;

impl WasmDispatch for NoWasm {
    fn on_request_headers(
        &mut self,
        _name: &str,
        headers: Vec<(String, String)>,
    ) -> (ChainOutcome, Vec<(String, String)>) {
        (ChainOutcome::Continue, headers)
    }

    fn on_request_body(&mut self, _name: &str, body: Vec<u8>) -> (ChainOutcome, Vec<u8>) {
        (ChainOutcome::Continue, body)
    }

    fn on_response_headers(
        &mut self,
        _name: &str,
        headers: Vec<(String, String)>,
    ) -> (ChainOutcome, Vec<(String, String)>) {
        (ChainOutcome::Continue, headers)
    }

    fn on_response_body(&mut self, _name: &str, body: Vec<u8>) -> (ChainOutcome, Vec<u8>) {
        (ChainOutcome::Continue, body)
    }
}

/// One entry in the per-request execution list: either a native filter
/// or a reference to a WASM plugin by name (dispatched via the
/// [`WasmDispatch`] adapter).
enum ChainEntry {
    Native(Box<dyn NativeFilter>),
    Wasm(String),
}

/// The unified per-request plugin chain.
///
/// Built from a route's plugin names + the gateway's plugin configs +
/// the native registry + a WASM dispatch adapter. Holds the native
/// filter instances for this request and the names of the WASM plugins
/// (the adapter owns the WASM instances). Dispatches each phase to the
/// plugins in deterministic phase order, short-circuiting on
/// `LocalResponse`/`Error`.
pub struct PluginChain<W: WasmDispatch = NoWasm> {
    /// The plugins active in each phase, in route-declaration order
    /// within the phase (deterministic, matching `phase_order`).
    phases: HashMap<PluginPhase, Vec<ChainEntry>>,
    /// The WASM dispatch adapter (owns per-request WASM instances).
    wasm: W,
}

impl<W: WasmDispatch> PluginChain<W> {
    /// Build a chain for a route's plugin names.
    ///
    /// `plugin_names` is the route's `plugins` list (declaration order).
    /// `configs` is the gateway's top-level `plugins` list keyed by
    /// name. `registry` provides native filter factories. `wasm` is the
    /// per-request WASM dispatch adapter (use [`NoWasm`] when the
    /// `wasm` feature is off or the route has no WASM plugins).
    ///
    /// A plugin name that is neither a native filter in the registry nor
    /// a WASM plugin in `configs` is silently skipped (it was already
    /// flagged by validation as an unknown reference). A native filter
    /// whose factory errors is also skipped (construction failure is
    /// logged by the caller via validation/health, not the request path).
    pub fn new(
        plugin_names: &[String],
        configs: &HashMap<String, PluginConfig>,
        registry: &NativeRegistry,
        wasm: W,
    ) -> Self {
        // The deterministic phase order: for each phase, the plugins
        // that declare it, in route-declaration order. This matches
        // wasm::lifecycle::PluginLifecycle::phase_order exactly.
        let phase_list = [
            PluginPhase::RequestHeaders,
            PluginPhase::RequestBody,
            PluginPhase::ResponseHeaders,
            PluginPhase::ResponseBody,
        ];

        let mut phases: HashMap<PluginPhase, Vec<ChainEntry>> = HashMap::new();
        for phase in &phase_list {
            let mut entries = Vec::new();
            for name in plugin_names {
                let Some(config) = configs.get(name) else {
                    continue;
                };
                if !config.phases.contains(phase) {
                    continue;
                }
                if let Some(native_name) = &config.native {
                    if let Ok(filter) = registry.create(native_name, &config.config) {
                        entries.push(ChainEntry::Native(filter));
                    }
                } else if config.wasm.is_some() {
                    entries.push(ChainEntry::Wasm(name.clone()));
                }
            }
            if !entries.is_empty() {
                phases.insert(*phase, entries);
            }
        }

        Self { phases, wasm }
    }

    /// Whether the chain has any plugins at all.
    pub fn is_empty(&self) -> bool {
        self.phases.is_empty()
    }

    /// Run the `request_headers` phase across all plugins in order.
    /// Returns the outcome and the (possibly modified) headers.
    pub fn on_request_headers(
        &mut self,
        headers: Vec<(String, String)>,
    ) -> (ChainOutcome, Vec<(String, String)>) {
        let Some(entries) = self.phases.get_mut(&PluginPhase::RequestHeaders) else {
            return (ChainOutcome::Continue, headers);
        };
        let mut current = headers;
        for entry in entries.iter_mut() {
            match entry {
                ChainEntry::Native(filter) => match filter.on_request_headers(current.clone()) {
                    FilterOutcome::Continue { headers, .. } => current = headers,
                    FilterOutcome::LocalResponse(resp) => {
                        return (ChainOutcome::LocalResponse(resp), current);
                    }
                    FilterOutcome::Error(e) => {
                        return (ChainOutcome::Error(e), current);
                    }
                },
                ChainEntry::Wasm(name) => {
                    let (outcome, h) = self.wasm.on_request_headers(name.as_str(), current);
                    match outcome {
                        ChainOutcome::Continue => current = h,
                        ChainOutcome::LocalResponse(resp) => {
                            return (ChainOutcome::LocalResponse(resp), h);
                        }
                        ChainOutcome::Error(e) => return (ChainOutcome::Error(e), h),
                    }
                }
            }
        }
        (ChainOutcome::Continue, current)
    }

    /// Run the `request_body` phase across all plugins in order.
    /// Returns the outcome and the (possibly modified) body.
    pub fn on_request_body(&mut self, body: Vec<u8>) -> (ChainOutcome, Vec<u8>) {
        let Some(entries) = self.phases.get_mut(&PluginPhase::RequestBody) else {
            return (ChainOutcome::Continue, body);
        };
        let mut current = body;
        for entry in entries.iter_mut() {
            match entry {
                ChainEntry::Native(filter) => match filter.on_request_body(current.clone()) {
                    FilterOutcome::Continue { body, .. } => current = body,
                    FilterOutcome::LocalResponse(resp) => {
                        return (ChainOutcome::LocalResponse(resp), current);
                    }
                    FilterOutcome::Error(e) => return (ChainOutcome::Error(e), current),
                },
                ChainEntry::Wasm(name) => {
                    let (outcome, b) = self.wasm.on_request_body(name.as_str(), current);
                    match outcome {
                        ChainOutcome::Continue => current = b,
                        ChainOutcome::LocalResponse(resp) => {
                            return (ChainOutcome::LocalResponse(resp), b);
                        }
                        ChainOutcome::Error(e) => return (ChainOutcome::Error(e), b),
                    }
                }
            }
        }
        (ChainOutcome::Continue, current)
    }

    /// Run the `response_headers` phase across all plugins in order.
    /// Returns the outcome and the (possibly modified) headers.
    pub fn on_response_headers(
        &mut self,
        headers: Vec<(String, String)>,
    ) -> (ChainOutcome, Vec<(String, String)>) {
        let Some(entries) = self.phases.get_mut(&PluginPhase::ResponseHeaders) else {
            return (ChainOutcome::Continue, headers);
        };
        let mut current = headers;
        for entry in entries.iter_mut() {
            match entry {
                ChainEntry::Native(filter) => match filter.on_response_headers(current.clone()) {
                    FilterOutcome::Continue { headers, .. } => current = headers,
                    FilterOutcome::LocalResponse(resp) => {
                        return (ChainOutcome::LocalResponse(resp), current);
                    }
                    FilterOutcome::Error(e) => return (ChainOutcome::Error(e), current),
                },
                ChainEntry::Wasm(name) => {
                    let (outcome, h) = self.wasm.on_response_headers(name.as_str(), current);
                    match outcome {
                        ChainOutcome::Continue => current = h,
                        ChainOutcome::LocalResponse(resp) => {
                            return (ChainOutcome::LocalResponse(resp), h);
                        }
                        ChainOutcome::Error(e) => return (ChainOutcome::Error(e), h),
                    }
                }
            }
        }
        (ChainOutcome::Continue, current)
    }

    /// Run the `response_body` phase across all plugins in order.
    /// Returns the outcome and the (possibly modified) body.
    pub fn on_response_body(&mut self, body: Vec<u8>) -> (ChainOutcome, Vec<u8>) {
        let Some(entries) = self.phases.get_mut(&PluginPhase::ResponseBody) else {
            return (ChainOutcome::Continue, body);
        };
        let mut current = body;
        for entry in entries.iter_mut() {
            match entry {
                ChainEntry::Native(filter) => match filter.on_response_body(current.clone()) {
                    FilterOutcome::Continue { body, .. } => current = body,
                    FilterOutcome::LocalResponse(resp) => {
                        return (ChainOutcome::LocalResponse(resp), current);
                    }
                    FilterOutcome::Error(e) => return (ChainOutcome::Error(e), current),
                },
                ChainEntry::Wasm(name) => {
                    let (outcome, b) = self.wasm.on_response_body(name.as_str(), current);
                    match outcome {
                        ChainOutcome::Continue => current = b,
                        ChainOutcome::LocalResponse(resp) => {
                            return (ChainOutcome::LocalResponse(resp), b);
                        }
                        ChainOutcome::Error(e) => return (ChainOutcome::Error(e), b),
                    }
                }
            }
        }
        (ChainOutcome::Continue, current)
    }

    /// Call `on_done` on the WASM adapter (the cleanup path). Native
    /// filters have no explicit done callback; they are dropped when the
    /// chain is dropped.
    pub fn on_done(&mut self) {
        self.wasm.on_done();
    }

    /// Borrow the WASM adapter (for callers that need to drive it
    /// directly, e.g. to instantiate per-request WASM instances before
    /// the chain runs).
    pub fn wasm(&self) -> &W {
        &self.wasm
    }

    /// Mutably borrow the WASM adapter.
    pub fn wasm_mut(&mut self) -> &mut W {
        &mut self.wasm
    }
}
