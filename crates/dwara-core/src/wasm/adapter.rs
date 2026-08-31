//! The WASM-to-unified-chain adapter (DW-119).
//!
//! [`WasmChainAdapter`] bridges the proxy-wasm host's per-request
//! [`PluginInstances`] into the unified [`crate::plugins::PluginChain`]
//! by implementing [`crate::plugins::WasmDispatch`]. The dataplane
//! constructs one adapter per request (holding the `PluginInstances`)
//! and passes it to `PluginChain::new`; the chain calls back into the
//! adapter for each WASM plugin at each phase.
//!
//! This module is gated behind both the `wasm` and `plugins` features:
//! the adapter only exists when both the proxy-wasm host and the native
//! filter trait are compiled in. When only `plugins` is on, the chain
//! uses [`crate::plugins::NoWasm`] instead.
//!
//! Dependency direction: `wasm` depends on `plugins` (downward —
//! `plugins` sits below `wasm` in the dependency table). The adapter
//! converts `wasm::host::LocalResponse` to
//! `plugins::LocalResponse` at the dispatch boundary.

use crate::plugins::{ChainOutcome, LocalResponse, WasmDispatch};
use crate::wasm::runner::{PhaseOutcome, PluginInstances};

/// Convert a `wasm::host::LocalResponse` to the shared
/// `plugins::LocalResponse` (structurally identical; the canonical
/// type lives in the lower `plugins` domain).
fn convert_local(resp: crate::wasm::host::LocalResponse) -> LocalResponse {
    LocalResponse {
        status: resp.status,
        headers: resp.headers,
        body: resp.body,
    }
}

/// The per-request WASM dispatch adapter.
///
/// Holds the proxy-wasm host's [`PluginInstances`] for the route's WASM
/// plugins and implements [`WasmDispatch`] so the unified
/// [`crate::plugins::PluginChain`] can drive them alongside native
/// filters with no dataplane-visible difference in attachment semantics.
pub struct WasmChainAdapter {
    instances: PluginInstances,
}

impl WasmChainAdapter {
    /// Wrap a per-request [`PluginInstances`] (created by
    /// [`crate::wasm::runner::PluginRunner::instantiate`]).
    pub fn new(instances: PluginInstances) -> Self {
        Self { instances }
    }
}

impl WasmDispatch for WasmChainAdapter {
    fn on_request_headers(
        &mut self,
        _name: &str,
        headers: Vec<(String, String)>,
    ) -> (ChainOutcome, Vec<(String, String)>) {
        // PluginInstances runs all its WASM instances for the phase in
        // declaration order; the chain calls this once per phase (not
        // once per plugin), so the name is unused -- the adapter owns
        // the full instance set and dispatches to all of them.
        match self.instances.on_request_headers(headers) {
            (PhaseOutcome::Continue, h) => (ChainOutcome::Continue, h),
            (PhaseOutcome::LocalResponse(r), h) => {
                (ChainOutcome::LocalResponse(convert_local(r)), h)
            }
            (PhaseOutcome::Trap(e), h) => (ChainOutcome::Error(e), h),
        }
    }

    fn on_request_body(&mut self, _name: &str, body: Vec<u8>) -> (ChainOutcome, Vec<u8>) {
        match self.instances.on_request_body(body) {
            (PhaseOutcome::Continue, b) => (ChainOutcome::Continue, b),
            (PhaseOutcome::LocalResponse(r), b) => {
                (ChainOutcome::LocalResponse(convert_local(r)), b)
            }
            (PhaseOutcome::Trap(e), b) => (ChainOutcome::Error(e), b),
        }
    }

    fn on_response_headers(
        &mut self,
        _name: &str,
        headers: Vec<(String, String)>,
    ) -> (ChainOutcome, Vec<(String, String)>) {
        match self.instances.on_response_headers(headers) {
            (PhaseOutcome::Continue, h) => (ChainOutcome::Continue, h),
            (PhaseOutcome::LocalResponse(r), h) => {
                (ChainOutcome::LocalResponse(convert_local(r)), h)
            }
            (PhaseOutcome::Trap(e), h) => (ChainOutcome::Error(e), h),
        }
    }

    fn on_response_body(&mut self, _name: &str, body: Vec<u8>) -> (ChainOutcome, Vec<u8>) {
        match self.instances.on_response_body(body) {
            (PhaseOutcome::Continue, b) => (ChainOutcome::Continue, b),
            (PhaseOutcome::LocalResponse(r), b) => {
                (ChainOutcome::LocalResponse(convert_local(r)), b)
            }
            (PhaseOutcome::Trap(e), b) => (ChainOutcome::Error(e), b),
        }
    }

    fn on_done(&mut self) {
        self.instances.on_done();
    }
}
