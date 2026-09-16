//! Plugin runner — the integration layer between the proxy pipeline
//! and the proxy-wasm host (DW-055).
//!
//! The [`PluginRunner`] holds compiled plugin modules keyed by name and
//! provides per-request methods to run each phase. The proxy pipeline
//! calls these methods at the appropriate points in the request path
//! (wired end-to-end by `dataplane::plugin_dispatch`, DW-157). This
//! module compiles unconditionally in the OSS build — there are no
//! cargo features for the plugin runtime.

use std::collections::HashMap;
use std::path::PathBuf;
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
    /// Build a runner from the gateway's `plugins` list, compiling
    /// each WASM plugin's module. A local plugin loads from its
    /// `wasm:` path; a registry `source:` plugin (DW-165) has no
    /// `wasm` field and loads from its resolved, verified artifact
    /// path in `resolved` (see [`crate::wasm::source`]). Plugins that
    /// fail to compile are skipped (with a log warning); the gateway
    /// starts even if a plugin is broken.
    pub fn new(
        plugins: &[crate::config::PluginConfig],
        resolved: &HashMap<String, PathBuf>,
    ) -> Result<Self, String> {
        let engine = WasmEngine::new()?;
        let mut modules = HashMap::new();

        for plugin in plugins {
            // DW-119: a plugin is either `wasm:` or `native:`. The
            // runner only compiles WASM plugins; native filters are
            // handled by the unified plugin chain (plugins domain).
            let wasm_path: String = if let Some(p) = &plugin.wasm {
                p.clone()
            } else if plugin.source.is_some() {
                // DW-165: registry-sourced plugin — the verified local
                // artifact path from the resolver.
                match resolved.get(&plugin.name) {
                    Some(p) => p.display().to_string(),
                    // No resolved path = resolution failed and the
                    // lifecycle already marked the plugin Crashed;
                    // nothing to compile here.
                    None => continue,
                }
            } else {
                continue;
            };
            let wasm_bytes = match std::fs::read(&wasm_path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::warn!(
                        plugin = %plugin.name,
                        path = %wasm_path,
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
    /// Returns `None` when no named plugin has a compiled module (the
    /// caller treats that as fail-closed unavailability when the route
    /// does reference WASM plugins — DW-157). A plugin whose module
    /// fails to instantiate is skipped here with a warn; the caller is
    /// expected to verify coverage via [`PluginInstances::contains`].
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

    /// Whether a compiled module exists for `name` (DW-157). The
    /// lifecycle manager uses this at load time to mark plugins whose
    /// .wasm failed to read or compile as crashed (fail-closed),
    /// instead of leaving them reading as healthy with no module
    /// behind them.
    pub fn has(&self, name: &str) -> bool {
        self.modules.contains_key(name)
    }
}

impl PluginInstances {
    /// The empty instance set (DW-157): the adapter for chains with no
    /// WASM plugins (native-only routes) — every per-name dispatch
    /// passes through unchanged.
    pub fn empty() -> Self {
        Self {
            instances: Vec::new(),
        }
    }

    /// Whether an instance exists for `name`. The dataplane's
    /// fail-closed gate (DW-157) uses this to verify that instantiation
    /// covered every WASM plugin a route references before the request
    /// proceeds.
    pub fn contains(&self, name: &str) -> bool {
        self.instances.iter().any(|(n, _)| n == name)
    }

    /// The named plugin's instance (DW-157). The unified-chain adapter
    /// dispatches per plugin NAME (the chain interleaves native filters
    /// between WASM entries), so it needs mutable access to exactly one
    /// instance at a time. `None` when no instance exists for `name`.
    pub fn instance_mut(&mut self, name: &str) -> Option<&mut PluginInstance> {
        self.instances
            .iter_mut()
            .find(|(n, _)| n == name)
            .map(|(_, inst)| inst)
    }

    /// The named plugin's current request header map (DW-167): the
    /// callout driver reads the resumed plugin's phase payload back
    /// through the adapter after delivering a callout response.
    pub fn instance_request_headers(&self, name: &str) -> Option<Vec<(String, String)>> {
        self.instances
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, inst)| inst.request_headers().to_vec())
    }

    /// The named plugin's current response header map (DW-167; see
    /// [`PluginInstances::instance_request_headers`]).
    pub fn instance_response_headers(&self, name: &str) -> Option<Vec<(String, String)>> {
        self.instances
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, inst)| inst.response_headers().to_vec())
    }

    /// The named plugin's current request body (DW-167; see
    /// [`PluginInstances::instance_request_headers`]).
    pub fn instance_request_body(&self, name: &str) -> Option<Vec<u8>> {
        self.instances
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, inst)| inst.request_body().to_vec())
    }

    /// The named plugin's current response body (DW-167; see
    /// [`PluginInstances::instance_request_headers`]).
    pub fn instance_response_body(&self, name: &str) -> Option<Vec<u8>> {
        self.instances
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, inst)| inst.response_body().to_vec())
    }

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
                PhaseResult::Pause => {
                    return (
                        PhaseOutcome::Trap(
                            "proxy_http_call is not supported on this \
                             execution path (no callout driver)"
                                .to_string(),
                        ),
                        current_headers,
                    );
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
                PhaseResult::Pause => {
                    return (
                        PhaseOutcome::Trap(
                            "proxy_http_call is not supported on this \
                             execution path (no callout driver)"
                                .to_string(),
                        ),
                        current_body,
                    );
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
                PhaseResult::Pause => {
                    return (
                        PhaseOutcome::Trap(
                            "proxy_http_call is not supported on this \
                             execution path (no callout driver)"
                                .to_string(),
                        ),
                        current_headers,
                    );
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
                PhaseResult::Pause => {
                    return (
                        PhaseOutcome::Trap(
                            "proxy_http_call is not supported on this \
                             execution path (no callout driver)"
                                .to_string(),
                        ),
                        current_body,
                    );
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
