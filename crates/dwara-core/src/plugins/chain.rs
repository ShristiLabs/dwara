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
//! `PluginInstances` into the unified chain. The proxy-wasm host
//! always compiles (DW-157); [`NoWasm`] serves native-only chains and
//! tests.
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
    /// should return a 500. `plugin` names the failing entry so the
    /// dataplane can attribute the failure in logs and metrics
    /// (`dwara_plugin_failures_total{name,reason}`, DW-157).
    Error { plugin: String, message: String },
    /// A WASM plugin registered HTTP callouts and paused (DW-167).
    /// Native filters never produce this. The caller (the async
    /// plugin_dispatch boundary) performs the callouts through the
    /// adapter, delivers the responses, and then continues the phase
    /// with the matching `resume_*` method — entries BEFORE (and the
    /// paused one itself) do not run again.
    CalloutPending,
}

/// A minimal per-request WASM dispatch interface the `wasm` domain
/// implements to bridge its `PluginInstances` into the unified chain.
///
/// The chain calls these methods on the adapter for each WASM plugin in
/// the phase, in order, passing the plugin's NAME: the adapter holds
/// the per-request WASM instances keyed by name and dispatches to
/// exactly that instance (so a chain interleaving native filters and
/// WASM plugins in one phase runs each entry exactly once). [`NoWasm`]
/// is a no-op adapter that always returns [`ChainOutcome::Continue`].
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

/// A no-op WASM dispatch adapter for native-only chains (and tests).
/// Every method returns [`ChainOutcome::Continue`] with the input
/// unchanged.
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
/// (with its plugin name, for failure attribution) or a reference to a
/// WASM plugin by name (dispatched via the [`WasmDispatch`] adapter).
enum ChainEntry {
    Native(String, Box<dyn NativeFilter>),
    Wasm(String),
}

/// A native filter whose factory errored while the chain was being
/// built (DW-157). The configured filter could not be constructed, so
/// it NEVER runs; the chain reports the failure instead of silently
/// skipping the entry, and the caller must fail closed (a request the
/// gate admitted must not proceed without a plugin its route
/// configures).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeCreateFailure {
    /// The config-declared plugin name (failure attribution).
    pub plugin: String,
    /// The factory's error message.
    pub message: String,
}

/// The fail-closed outcome for a `resume_*` call whose recorded pause
/// does not match the resumed phase (or records no pause at all):
/// unreachable with today's driver (every `CalloutPending` sets the
/// record; every matching resume consumes it), and silently falling
/// back to `start = 0` would RE-RUN the phase — plugins before the
/// pause would execute twice. A driver bug fails closed instead.
fn callout_resume_mismatch(phase: &str) -> ChainOutcome {
    ChainOutcome::Error {
        plugin: "plugin_chain".to_string(),
        message: format!(
            "callout resume on {phase} without a matching recorded pause; failing closed"
        ),
    }
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
    /// The phase-list index of the WASM entry that paused for callouts
    /// (DW-167), set when a phase drive returns
    /// [`ChainOutcome::CalloutPending`] and consumed by the matching
    /// `resume_*` method (which continues from the entry AFTER it).
    paused_entry: Option<(PluginPhase, usize)>,
}

impl<W: WasmDispatch> PluginChain<W> {
    /// Build a chain for a route's plugin names.
    ///
    /// `plugin_names` is the route's `plugins` list (declaration order).
    /// `configs` is the gateway's top-level `plugins` list keyed by
    /// name. `registry` provides native filter factories. `wasm` is the
    /// per-request WASM dispatch adapter (use [`NoWasm`] for native-only
    /// chains).
    ///
    /// Returns the chain and the list of native entries whose factory
    /// ERRORED ([`NativeCreateFailure`]) — fail-closed material (DW-157):
    /// the configured filter never runs, so the caller must answer the
    /// request with the fail-closed 500 rather than proceed without it;
    /// the chain deliberately does NOT silently skip a reported entry.
    /// A plugin name that is neither a native filter in the registry nor
    /// a WASM plugin in `configs` is silently skipped (it was already
    /// flagged by validation as an unknown reference, and the
    /// dataplane's health gate fails closed on it before the chain is
    /// built).
    pub fn new(
        plugin_names: &[String],
        configs: &HashMap<String, PluginConfig>,
        registry: &NativeRegistry,
        wasm: W,
    ) -> (Self, Vec<NativeCreateFailure>) {
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
        let mut create_failures = Vec::new();
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
                    match registry.create(native_name, &config.config) {
                        Ok(filter) => entries.push(ChainEntry::Native(name.clone(), filter)),
                        Err(e) => create_failures.push(NativeCreateFailure {
                            plugin: name.clone(),
                            message: e.to_string(),
                        }),
                    }
                } else if config.wasm.is_some() || config.source.is_some() {
                    // DW-165: a registry `source:` plugin is a WASM
                    // plugin whose artifact resolved to a verified
                    // local file; it occupies the same phase slot.
                    entries.push(ChainEntry::Wasm(name.clone()));
                }
            }
            if !entries.is_empty() {
                phases.insert(*phase, entries);
            }
        }

        (
            Self {
                phases,
                wasm,
                paused_entry: None,
            },
            create_failures,
        )
    }

    /// Whether the chain has any plugins at all.
    pub fn is_empty(&self) -> bool {
        self.phases.is_empty()
    }

    /// Whether at least one plugin declares the given phase. The
    /// dataplane uses this to decide whether a body phase requires
    /// buffering (DW-157): a route whose plugins declare no body phase
    /// keeps its zero-buffering streaming path.
    pub fn has_phase(&self, phase: PluginPhase) -> bool {
        self.phases.contains_key(&phase)
    }

    /// Run the `request_headers` phase across all plugins in order.
    /// Returns the outcome and the (possibly modified) headers.
    pub fn on_request_headers(
        &mut self,
        headers: Vec<(String, String)>,
    ) -> (ChainOutcome, Vec<(String, String)>) {
        self.request_headers_from(headers, 0)
    }

    /// Continue the `request_headers` phase AFTER the paused entry
    /// (DW-167): `headers` is the resumed plugin's post-callout
    /// output. Plugins before (and including) the paused entry do not
    /// run again.
    pub fn resume_request_headers(
        &mut self,
        headers: Vec<(String, String)>,
    ) -> (ChainOutcome, Vec<(String, String)>) {
        let start = match self.paused_entry.take() {
            Some((PluginPhase::RequestHeaders, idx)) => idx + 1,
            _ => return (callout_resume_mismatch("request_headers"), headers),
        };
        self.request_headers_from(headers, start)
    }

    fn request_headers_from(
        &mut self,
        headers: Vec<(String, String)>,
        start: usize,
    ) -> (ChainOutcome, Vec<(String, String)>) {
        let Some(entries) = self.phases.get_mut(&PluginPhase::RequestHeaders) else {
            return (ChainOutcome::Continue, headers);
        };
        let mut current = headers;
        for (idx, entry) in entries.iter_mut().enumerate().skip(start) {
            match entry {
                ChainEntry::Native(name, filter) => {
                    match filter.on_request_headers(current.clone()) {
                        FilterOutcome::Continue { headers, .. } => current = headers,
                        FilterOutcome::LocalResponse(resp) => {
                            return (ChainOutcome::LocalResponse(resp), current);
                        }
                        FilterOutcome::Error(e) => {
                            return (
                                ChainOutcome::Error {
                                    plugin: name.clone(),
                                    message: e,
                                },
                                current,
                            );
                        }
                    }
                }
                ChainEntry::Wasm(name) => {
                    let (outcome, h) = self.wasm.on_request_headers(name.as_str(), current);
                    match outcome {
                        ChainOutcome::Continue => current = h,
                        ChainOutcome::LocalResponse(resp) => {
                            return (ChainOutcome::LocalResponse(resp), h);
                        }
                        ChainOutcome::Error { .. } => return (outcome, h),
                        ChainOutcome::CalloutPending => {
                            self.paused_entry = Some((PluginPhase::RequestHeaders, idx));
                            return (ChainOutcome::CalloutPending, h);
                        }
                    }
                }
            }
        }
        (ChainOutcome::Continue, current)
    }

    /// Run the `request_body` phase across all plugins in order.
    /// Returns the outcome and the (possibly modified) body.
    pub fn on_request_body(&mut self, body: Vec<u8>) -> (ChainOutcome, Vec<u8>) {
        self.request_body_from(body, 0)
    }

    /// Continue the `request_body` phase AFTER the paused entry
    /// (DW-167): `body` is the resumed plugin's post-callout output.
    pub fn resume_request_body(&mut self, body: Vec<u8>) -> (ChainOutcome, Vec<u8>) {
        let start = match self.paused_entry.take() {
            Some((PluginPhase::RequestBody, idx)) => idx + 1,
            _ => return (callout_resume_mismatch("request_body"), body),
        };
        self.request_body_from(body, start)
    }

    fn request_body_from(&mut self, body: Vec<u8>, start: usize) -> (ChainOutcome, Vec<u8>) {
        let Some(entries) = self.phases.get_mut(&PluginPhase::RequestBody) else {
            return (ChainOutcome::Continue, body);
        };
        let mut current = body;
        for (idx, entry) in entries.iter_mut().enumerate().skip(start) {
            match entry {
                ChainEntry::Native(name, filter) => match filter.on_request_body(current.clone()) {
                    FilterOutcome::Continue { body, .. } => current = body,
                    FilterOutcome::LocalResponse(resp) => {
                        return (ChainOutcome::LocalResponse(resp), current);
                    }
                    FilterOutcome::Error(e) => {
                        return (
                            ChainOutcome::Error {
                                plugin: name.clone(),
                                message: e,
                            },
                            current,
                        );
                    }
                },
                ChainEntry::Wasm(name) => {
                    let (outcome, b) = self.wasm.on_request_body(name.as_str(), current);
                    match outcome {
                        ChainOutcome::Continue => current = b,
                        ChainOutcome::LocalResponse(resp) => {
                            return (ChainOutcome::LocalResponse(resp), b);
                        }
                        ChainOutcome::Error { .. } => return (outcome, b),
                        ChainOutcome::CalloutPending => {
                            self.paused_entry = Some((PluginPhase::RequestBody, idx));
                            return (ChainOutcome::CalloutPending, b);
                        }
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
        self.response_headers_from(headers, 0)
    }

    /// Continue the `response_headers` phase AFTER the paused entry
    /// (DW-167): `headers` is the resumed plugin's post-callout
    /// output.
    pub fn resume_response_headers(
        &mut self,
        headers: Vec<(String, String)>,
    ) -> (ChainOutcome, Vec<(String, String)>) {
        let start = match self.paused_entry.take() {
            Some((PluginPhase::ResponseHeaders, idx)) => idx + 1,
            _ => return (callout_resume_mismatch("response_headers"), headers),
        };
        self.response_headers_from(headers, start)
    }

    fn response_headers_from(
        &mut self,
        headers: Vec<(String, String)>,
        start: usize,
    ) -> (ChainOutcome, Vec<(String, String)>) {
        let Some(entries) = self.phases.get_mut(&PluginPhase::ResponseHeaders) else {
            return (ChainOutcome::Continue, headers);
        };
        let mut current = headers;
        for (idx, entry) in entries.iter_mut().enumerate().skip(start) {
            match entry {
                ChainEntry::Native(name, filter) => {
                    match filter.on_response_headers(current.clone()) {
                        FilterOutcome::Continue { headers, .. } => current = headers,
                        FilterOutcome::LocalResponse(resp) => {
                            return (ChainOutcome::LocalResponse(resp), current);
                        }
                        FilterOutcome::Error(e) => {
                            return (
                                ChainOutcome::Error {
                                    plugin: name.clone(),
                                    message: e,
                                },
                                current,
                            );
                        }
                    }
                }
                ChainEntry::Wasm(name) => {
                    let (outcome, h) = self.wasm.on_response_headers(name.as_str(), current);
                    match outcome {
                        ChainOutcome::Continue => current = h,
                        ChainOutcome::LocalResponse(resp) => {
                            return (ChainOutcome::LocalResponse(resp), h);
                        }
                        ChainOutcome::Error { .. } => return (outcome, h),
                        ChainOutcome::CalloutPending => {
                            self.paused_entry = Some((PluginPhase::ResponseHeaders, idx));
                            return (ChainOutcome::CalloutPending, h);
                        }
                    }
                }
            }
        }
        (ChainOutcome::Continue, current)
    }

    /// Run the `response_body` phase across all plugins in order.
    /// Returns the outcome and the (possibly modified) body.
    pub fn on_response_body(&mut self, body: Vec<u8>) -> (ChainOutcome, Vec<u8>) {
        self.response_body_from(body, 0)
    }

    /// Continue the `response_body` phase AFTER the paused entry
    /// (DW-167): `body` is the resumed plugin's post-callout output.
    pub fn resume_response_body(&mut self, body: Vec<u8>) -> (ChainOutcome, Vec<u8>) {
        let start = match self.paused_entry.take() {
            Some((PluginPhase::ResponseBody, idx)) => idx + 1,
            _ => return (callout_resume_mismatch("response_body"), body),
        };
        self.response_body_from(body, start)
    }

    fn response_body_from(&mut self, body: Vec<u8>, start: usize) -> (ChainOutcome, Vec<u8>) {
        let Some(entries) = self.phases.get_mut(&PluginPhase::ResponseBody) else {
            return (ChainOutcome::Continue, body);
        };
        let mut current = body;
        for (idx, entry) in entries.iter_mut().enumerate().skip(start) {
            match entry {
                ChainEntry::Native(name, filter) => {
                    match filter.on_response_body(current.clone()) {
                        FilterOutcome::Continue { body, .. } => current = body,
                        FilterOutcome::LocalResponse(resp) => {
                            return (ChainOutcome::LocalResponse(resp), current);
                        }
                        FilterOutcome::Error(e) => {
                            return (
                                ChainOutcome::Error {
                                    plugin: name.clone(),
                                    message: e,
                                },
                                current,
                            );
                        }
                    }
                }
                ChainEntry::Wasm(name) => {
                    let (outcome, b) = self.wasm.on_response_body(name.as_str(), current);
                    match outcome {
                        ChainOutcome::Continue => current = b,
                        ChainOutcome::LocalResponse(resp) => {
                            return (ChainOutcome::LocalResponse(resp), b);
                        }
                        ChainOutcome::Error { .. } => return (outcome, b),
                        ChainOutcome::CalloutPending => {
                            self.paused_entry = Some((PluginPhase::ResponseBody, idx));
                            return (ChainOutcome::CalloutPending, b);
                        }
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
