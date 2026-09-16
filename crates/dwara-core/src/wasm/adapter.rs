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
//!
//! ## HTTP callouts: the pause/resume seam (DW-167)
//!
//! When a phase dispatch ends with the plugin having registered
//! `proxy_http_call` callouts ([`PhaseResult::Pause`]), the adapter
//! records WHICH plugin paused and reports
//! [`ChainOutcome::CalloutPending`] up the chain; the chain stops and
//! the async driver in `dataplane::plugin_dispatch` takes over:
//!
//! 1. [`WasmChainAdapter::pending_callouts`] drains the paused
//!    instance's queue (FIFO) as transport-ready [`CalloutRequest`]s;
//! 2. the driver performs each exchange off-thread
//!    (`spawn_blocking` around the synchronous client) and records the
//!    `dwara_plugin_callouts_total{name,outcome}` metric;
//! 3. [`WasmChainAdapter::deliver_callout`] re-enters the instance
//!    (synchronous wasmtime) with `proxy_on_http_call_response` and
//!    returns the plugin's resumed outcome — Continue, a local
//!    response, a trap, or another `CalloutPending` (the plugin
//!    dispatched again; the driver loops, bounded);
//! 4. on Continue the driver reads the resumed plugin's phase payload
//!    back through this adapter and continues the chain from the entry
//!    AFTER the paused one (`PluginChain::resume_*`).
//!
//! The wasm runner stays fully synchronous; only the driver awaits.

use crate::config::PluginPhase;
use crate::plugins::{ChainOutcome, LocalResponse, WasmDispatch};
use crate::wasm::callout::CalloutRequest;
use crate::wasm::callout::CalloutResponse;
use crate::wasm::host::PendingCallout;
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
    /// The plugin that paused for callouts (DW-167): the driver
    /// performs its pending exchanges, delivers the responses to it,
    /// and reads its resumed phase payload back. `None` between
    /// phases.
    paused: Option<(String, PluginPhase)>,
}

impl WasmChainAdapter {
    /// Wrap a per-request [`PluginInstances`] (created by
    /// [`crate::wasm::runner::PluginRunner::instantiate`]).
    pub fn new(instances: PluginInstances) -> Self {
        Self {
            instances,
            paused: None,
        }
    }

    /// Whether a plugin is paused for callouts (the driver's loop
    /// condition, DW-167).
    pub fn has_pause(&self) -> bool {
        self.paused.is_some()
    }

    /// The paused plugin's name (failure attribution for the loop
    /// guard and callout errors; falls back to the caller's choice).
    pub fn paused_plugin(&self) -> Option<&str> {
        self.paused.as_ref().map(|(name, _)| name.as_str())
    }

    /// Drain the paused plugin's pending callouts as transport-ready
    /// requests (FIFO — the order the plugin dispatched them). `None`
    /// when nothing is paused (the driver's defensive path).
    pub fn pending_callouts(&mut self) -> Option<(String, Vec<CalloutRequest>)> {
        let (name, _) = self.paused.as_ref()?;
        let name = name.clone();
        let pending: Vec<PendingCallout> = match self.instances.instance_mut(&name) {
            Some(inst) => inst.take_pending_callouts(),
            None => Vec::new(),
        };
        let requests = pending
            .into_iter()
            .map(|p| CalloutRequest {
                plugin: name.clone(),
                token: p.token,
                uri: p.uri,
                method: p.method,
                headers: p.headers,
                body: p.body,
                timeout_ms: p.timeout_ms,
            })
            .collect();
        Some((name, requests))
    }

    /// Re-enqueue callouts the driver drained but did not perform: a
    /// mid-delivery re-dispatch (`ChainOutcome::CalloutPending` while
    /// queued requests remain) must not abandon them — the remainder
    /// goes back AHEAD of the new queue, preserving dispatch order,
    /// so every dispatched callout is eventually performed (or the
    /// loop guard trips). No-op when nothing is paused.
    pub fn requeue_callouts(&mut self, requests: Vec<CalloutRequest>) {
        let Some((name, _)) = self.paused.as_ref() else {
            return;
        };
        let name = name.clone();
        let pending = requests
            .into_iter()
            .map(|r| PendingCallout {
                token: r.token,
                uri: r.uri,
                method: r.method,
                headers: r.headers,
                body: r.body,
                timeout_ms: r.timeout_ms,
            })
            .collect();
        if let Some(inst) = self.instances.instance_mut(&name) {
            inst.requeue_callouts(pending);
        }
    }

    /// Deliver a completed callout response to the paused plugin
    /// (synchronous wasmtime re-entry) and collect its resumed
    /// outcome. [`ChainOutcome::CalloutPending`] means the plugin
    /// dispatched another callout inside the callback — keep driving.
    /// On every terminal outcome the pause record is cleared.
    pub fn deliver_callout(&mut self, token: u32, resp: &CalloutResponse) -> ChainOutcome {
        let Some((name, _)) = self.paused.clone() else {
            return ChainOutcome::Continue;
        };
        let outcome = match self.instances.instance_mut(&name) {
            Some(inst) => inst.deliver_callout_response(token, resp),
            None => PhaseResult::Continue,
        };
        self.map_resumed(&name, outcome)
    }

    /// The paused plugin's resumed `request_headers` payload (its
    /// post-callout header map) — what the chain resumes from.
    pub fn paused_request_headers(&self) -> Vec<(String, String)> {
        self.paused
            .as_ref()
            .and_then(|(name, _)| self.instances.instance_request_headers(name))
            .unwrap_or_default()
    }

    /// The paused plugin's resumed `response_headers` payload.
    pub fn paused_response_headers(&self) -> Vec<(String, String)> {
        self.paused
            .as_ref()
            .and_then(|(name, _)| self.instances.instance_response_headers(name))
            .unwrap_or_default()
    }

    /// The paused plugin's resumed `request_body` payload.
    pub fn paused_request_body(&self) -> Vec<u8> {
        self.paused
            .as_ref()
            .and_then(|(name, _)| self.instances.instance_request_body(name))
            .unwrap_or_default()
    }

    /// The paused plugin's resumed `response_body` payload.
    pub fn paused_response_body(&self) -> Vec<u8> {
        self.paused
            .as_ref()
            .and_then(|(name, _)| self.instances.instance_response_body(name))
            .unwrap_or_default()
    }

    /// Clear the pause record after the driver collected the resumed
    /// plugin's phase payload (the record survives the Continue
    /// delivery so `paused_*` can read the payload afterwards).
    pub fn clear_pause(&mut self) {
        self.paused = None;
    }

    /// Map a resumed [`PhaseResult`] from a callout callback to the
    /// chain vocabulary. On Continue the pause record STAYS (the
    /// driver reads the resumed payload through `paused_*` next and
    /// clears it with [`WasmChainAdapter::clear_pause`]); terminal
    /// outcomes clear it; another pending round keeps it.
    fn map_resumed(&mut self, name: &str, result: PhaseResult) -> ChainOutcome {
        match result {
            PhaseResult::Continue => ChainOutcome::Continue,
            PhaseResult::LocalResponse(r) => {
                self.paused = None;
                ChainOutcome::LocalResponse(convert_local(r))
            }
            PhaseResult::Trap(e) => {
                self.paused = None;
                ChainOutcome::Error {
                    plugin: name.to_string(),
                    message: e,
                }
            }
            PhaseResult::Pause => ChainOutcome::CalloutPending,
        }
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
            PhaseResult::Pause => {
                self.paused = Some((name.to_string(), PluginPhase::RequestHeaders));
                (
                    ChainOutcome::CalloutPending,
                    inst.request_headers().to_vec(),
                )
            }
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
            PhaseResult::Pause => {
                self.paused = Some((name.to_string(), PluginPhase::RequestBody));
                (ChainOutcome::CalloutPending, inst.request_body().to_vec())
            }
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
            PhaseResult::Pause => {
                self.paused = Some((name.to_string(), PluginPhase::ResponseHeaders));
                (
                    ChainOutcome::CalloutPending,
                    inst.response_headers().to_vec(),
                )
            }
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
            PhaseResult::Pause => {
                self.paused = Some((name.to_string(), PluginPhase::ResponseBody));
                (ChainOutcome::CalloutPending, inst.response_body().to_vec())
            }
        }
    }

    fn on_done(&mut self) {
        self.paused = None;
        self.instances.on_done();
    }
}
