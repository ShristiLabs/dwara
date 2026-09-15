//! The WASM-to-unified-chain adapter (DW-119).
//!
//! [`WasmChainAdapter`] bridges the proxy-wasm host's per-request
//! [`PluginInstances`] into the unified [`crate::plugins::PluginChain`]
//! by implementing [`crate::plugins::WasmDispatch`]. The dataplane
//! constructs one adapter per request (holding the `PluginInstances`
//! for the route's WASM plugins) and passes it to `PluginChain::new`;
//! the chain calls back into the adapter once per WASM entry per phase,
//! passing the entry's NAME, and the adapter dispatches to exactly that
//! plugin's instance (so a chain interleaving native filters and WASM
//! plugins in one phase runs each entry exactly once, in config order).
//!
//! This module (and the whole proxy-wasm host) compiles unconditionally
//! in the OSS build — there are no cargo features for it. The unified
//! chain's no-wasm adapter (`crate::plugins::NoWasm`) exists for
//! native-only chains and tests.
//!
//! Dependency direction: `wasm` depends on `plugins` (downward —
//! `plugins` sits below `wasm` in the dependency table). The adapter
//! converts `wasm::host::LocalResponse` to
//! `plugins::LocalResponse` at the dispatch boundary, and attributes
//! traps to the named plugin so the dataplane can record
//! `dwara_plugin_failures_total{name,reason}` (DW-157).

use crate::plugins::{ChainOutcome, LocalResponse, WasmDispatch};
use crate::wasm::host::PhaseResult;
use crate::wasm::runner::PluginInstances;

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
        name: &str,
        headers: Vec<(String, String)>,
    ) -> (ChainOutcome, Vec<(String, String)>) {
        // Per-NAME dispatch: the chain interleaves native filters and
        // WASM entries within a phase and calls this once per WASM
        // entry, so the adapter must run exactly the named plugin's
        // instance (running the whole set per call would execute each
        // plugin once per WASM entry on the route). A name with no
        // instance (a native-only name filtered out at instantiation)
        // passes through unchanged.
        let Some(inst) = self.instances.instance_mut(name) else {
            return (ChainOutcome::Continue, headers);
        };
        match inst.on_request_headers(headers) {
            PhaseResult::Continue => (ChainOutcome::Continue, inst.request_headers().to_vec()),
            PhaseResult::LocalResponse(r) => {
                (ChainOutcome::LocalResponse(convert_local(r)), Vec::new())
            }
            PhaseResult::Trap(e) => (
                ChainOutcome::Error {
                    plugin: name.to_string(),
                    message: e,
                },
                Vec::new(),
            ),
        }
    }

    fn on_request_body(&mut self, name: &str, body: Vec<u8>) -> (ChainOutcome, Vec<u8>) {
        let Some(inst) = self.instances.instance_mut(name) else {
            return (ChainOutcome::Continue, body);
        };
        match inst.on_request_body(body) {
            PhaseResult::Continue => (ChainOutcome::Continue, inst.request_body().to_vec()),
            PhaseResult::LocalResponse(r) => {
                (ChainOutcome::LocalResponse(convert_local(r)), Vec::new())
            }
            PhaseResult::Trap(e) => (
                ChainOutcome::Error {
                    plugin: name.to_string(),
                    message: e,
                },
                Vec::new(),
            ),
        }
    }

    fn on_response_headers(
        &mut self,
        name: &str,
        headers: Vec<(String, String)>,
    ) -> (ChainOutcome, Vec<(String, String)>) {
        let Some(inst) = self.instances.instance_mut(name) else {
            return (ChainOutcome::Continue, headers);
        };
        match inst.on_response_headers(headers) {
            PhaseResult::Continue => (ChainOutcome::Continue, inst.response_headers().to_vec()),
            PhaseResult::LocalResponse(r) => {
                (ChainOutcome::LocalResponse(convert_local(r)), Vec::new())
            }
            PhaseResult::Trap(e) => (
                ChainOutcome::Error {
                    plugin: name.to_string(),
                    message: e,
                },
                Vec::new(),
            ),
        }
    }

    fn on_response_body(&mut self, name: &str, body: Vec<u8>) -> (ChainOutcome, Vec<u8>) {
        let Some(inst) = self.instances.instance_mut(name) else {
            return (ChainOutcome::Continue, body);
        };
        match inst.on_response_body(body) {
            PhaseResult::Continue => (ChainOutcome::Continue, inst.response_body().to_vec()),
            PhaseResult::LocalResponse(r) => {
                (ChainOutcome::LocalResponse(convert_local(r)), Vec::new())
            }
            PhaseResult::Trap(e) => (
                ChainOutcome::Error {
                    plugin: name.to_string(),
                    message: e,
                },
                Vec::new(),
            ),
        }
    }

    fn on_done(&mut self) {
        self.instances.on_done();
    }
}
