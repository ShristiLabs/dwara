//! Plugin runner — the integration layer between the proxy pipeline
//! and the proxy-wasm host (DW-055).
//!
//! The [`PluginRunner`] holds compiled plugin modules keyed by name and
//! provides per-request methods to run each phase. The proxy pipeline
//! calls these methods at the appropriate points in the request path.
//!
//! When the `wasm` feature is not enabled, this module is not compiled
//! and the proxy pipeline skips plugin calls entirely (the config
//! `plugins` block is accepted but inert).

use std::collections::HashMap;
use std::sync::Arc;

use super::host::{PhaseResult, PluginInstance, PluginLimits, PluginModule, WasmEngine};

/// Holds compiled plugin modules and runs them per-request.
///
/// Created at config publish time from the gateway's `plugins` list.
/// Cheap to clone (Arc internals). Each route's `plugins` field names
/// the plugins to run; the proxy pipeline calls the runner's phase
/// methods with those names.
#[derive(Clone)]
pub struct PluginRunner {
    engine: WasmEngine,
    modules: Arc<HashMap<String, PluginModule>>,
}

/// The result of running a phase across all plugins on a route.
#[derive(Debug)]
pub enum PhaseOutcome {
    /// All plugins returned Continue. The request proceeds normally.
    /// The (possibly modified) headers/body are available from the
    /// instances.
    Continue,
    /// A plugin short-circuited with a local response. The proxy should
    /// return this response immediately.
    LocalResponse(super::host::LocalResponse),
    /// A plugin trapped (out of fuel, memory error, or panic). The
    /// proxy should return a 500.
    Trap(String),
}

/// Per-request plugin state — holds the instances for all plugins on
/// the route. Created at the start of request processing and dropped
/// at the end.
pub struct PluginInstances {
    instances: Vec<(String, PluginInstance)>,
}

impl PluginRunner {
    /// Build a runner from the gateway's `plugins` list. Compiles each
    /// plugin's .wasm module and stores it keyed by name. Plugins that
    /// fail to compile are skipped (with a log warning); the gateway
    /// starts even if a plugin is broken.
    pub fn new(plugins: &[crate::config::PluginConfig]) -> Result<Self, String> {
        let engine = WasmEngine::new()?;
        let mut modules = HashMap::new();

        for plugin in plugins {
            let wasm_bytes = match std::fs::read(&plugin.wasm) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::warn!(
                        plugin = %plugin.name,
                        path = %plugin.wasm,
                        error = %e,
                        "DW-055: failed to read plugin wasm file; skipping"
                    );
                    continue;
                }
            };

            let limits = plugin
                .limits
                .as_ref()
                .map(|l| PluginLimits {
                    fuel: l.fuel.unwrap_or(1_000_000),
                    memory_mb: l.memory_mb.unwrap_or(32),
                    timeout_ms: l.timeout_ms.unwrap_or(100),
                })
                .unwrap_or_default();

            let plugin_config = plugin
                .config
                .as_ref()
                .map(|c| c.as_bytes().to_vec())
                .unwrap_or_default();
            let vm_config = Vec::new();

            match engine.compile(&wasm_bytes, limits, plugin_config, vm_config) {
                Ok(module) => {
                    modules.insert(plugin.name.clone(), module);
                }
                Err(e) => {
                    tracing::warn!(
                        plugin = %plugin.name,
                        error = %e,
                        "DW-055: failed to compile plugin wasm; skipping"
                    );
                }
            }
        }

        Ok(Self {
            engine,
            modules: Arc::new(modules),
        })
    }

    /// Create per-request instances for all plugins named on a route.
    /// Returns `None` if no plugins are configured or the `wasm`
    /// feature is not enabled.
    pub fn instantiate(&self, plugin_names: &[String]) -> Option<PluginInstances> {
        if plugin_names.is_empty() {
            return None;
        }
        let mut instances = Vec::new();
        for name in plugin_names {
            if let Some(module) = self.modules.get(name) {
                match module.instantiate(&self.engine) {
                    Ok(inst) => instances.push((name.clone(), inst)),
                    Err(e) => {
                        tracing::warn!(
                            plugin = %name,
                            error = %e,
                            "DW-055: failed to instantiate plugin"
                        );
                    }
                }
            }
        }
        if instances.is_empty() {
            None
        } else {
            Some(PluginInstances { instances })
        }
    }

    /// Whether any plugins are configured.
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }
}

impl PluginInstances {
    /// Run `proxy_on_request_headers` on all instances. Returns the
    /// outcome and the (possibly modified) headers.
    pub fn on_request_headers(
        &mut self,
        headers: Vec<(String, String)>,
    ) -> (PhaseOutcome, Vec<(String, String)>) {
        let mut current_headers = headers;
        for (_, instance) in &mut self.instances {
            match instance.on_request_headers(current_headers.clone()) {
                PhaseResult::Continue => {
                    current_headers = instance.request_headers().to_vec();
                }
                PhaseResult::LocalResponse(resp) => {
                    return (PhaseOutcome::LocalResponse(resp), current_headers);
                }
                PhaseResult::Trap(e) => {
                    return (PhaseOutcome::Trap(e), current_headers);
                }
            }
        }
        (PhaseOutcome::Continue, current_headers)
    }

    /// Run `proxy_on_request_body` on all instances. Returns the
    /// outcome and the (possibly modified) body.
    pub fn on_request_body(&mut self, body: Vec<u8>) -> (PhaseOutcome, Vec<u8>) {
        let mut current_body = body;
        for (_, instance) in &mut self.instances {
            match instance.on_request_body(current_body.clone()) {
                PhaseResult::Continue => {
                    current_body = instance.request_body().to_vec();
                }
                PhaseResult::LocalResponse(resp) => {
                    return (PhaseOutcome::LocalResponse(resp), current_body);
                }
                PhaseResult::Trap(e) => {
                    return (PhaseOutcome::Trap(e), current_body);
                }
            }
        }
        (PhaseOutcome::Continue, current_body)
    }

    /// Run `proxy_on_response_headers` on all instances. Returns the
    /// outcome and the (possibly modified) headers.
    pub fn on_response_headers(
        &mut self,
        headers: Vec<(String, String)>,
    ) -> (PhaseOutcome, Vec<(String, String)>) {
        let mut current_headers = headers;
        for (_, instance) in &mut self.instances {
            match instance.on_response_headers(current_headers.clone()) {
                PhaseResult::Continue => {
                    current_headers = instance.response_headers().to_vec();
                }
                PhaseResult::LocalResponse(resp) => {
                    return (PhaseOutcome::LocalResponse(resp), current_headers);
                }
                PhaseResult::Trap(e) => {
                    return (PhaseOutcome::Trap(e), current_headers);
                }
            }
        }
        (PhaseOutcome::Continue, current_headers)
    }

    /// Run `proxy_on_response_body` on all instances. Returns the
    /// outcome and the (possibly modified) body.
    pub fn on_response_body(&mut self, body: Vec<u8>) -> (PhaseOutcome, Vec<u8>) {
        let mut current_body = body;
        for (_, instance) in &mut self.instances {
            match instance.on_response_body(current_body.clone()) {
                PhaseResult::Continue => {
                    current_body = instance.response_body().to_vec();
                }
                PhaseResult::LocalResponse(resp) => {
                    return (PhaseOutcome::LocalResponse(resp), current_body);
                }
                PhaseResult::Trap(e) => {
                    return (PhaseOutcome::Trap(e), current_body);
                }
            }
        }
        (PhaseOutcome::Continue, current_body)
    }

    /// Call `proxy_on_done` and `proxy_on_log` on all instances (the
    /// cleanup path).
    pub fn on_done(&mut self) {
        for (_, instance) in &mut self.instances {
            instance.on_done();
        }
    }
}
