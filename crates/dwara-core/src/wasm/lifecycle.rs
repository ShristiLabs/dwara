//! Plugin lifecycle (DW-056).
//!
//! Load from config (path/registry ref, checksums); hot-swap on
//! reload; plugin config schema validation; failure isolation.
//!
//! Attachment: config selects plugins per route/service/global,
//! applied in phase order per the DW-055 phase contract (section 9.3)
//! -- a route's plugin chain is deterministic from its config, not
//! load-order-dependent.
//!
//! ## Failure isolation
//!
//! A crashed plugin returns 500 on affected routes only, never
//! gateway-wide. The plugin lifecycle manager tracks which plugins
//! are healthy and which routes use them. When a plugin crashes, only
//! the routes that reference that plugin are affected. The dataplane
//! reloads plugins with every config generation (DW-157): a plugin
//! whose .wasm fails to read or compile is marked Crashed HERE, at
//! load time, so routes referencing it fail closed from the first
//! request of the new generation.
//!
//! ## Hot-swap on reload
//!
//! When the config is reloaded, the lifecycle manager recompiles
//! plugins that changed (by checksum) and swaps them in atomically.
//! Plugins that did not change are reused (no recompilation).
//!
//! This module compiles unconditionally in the OSS build — there are
//! no cargo features for the plugin runtime.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use crate::config::{PluginConfig, PluginPhase};
use crate::wasm::runner::PluginRunner;

/// A plugin's health status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PluginHealth {
    /// The plugin is healthy and ready to serve.
    Healthy,
    /// The plugin has crashed; routes referencing it get 500.
    Crashed { error: String, crash_count: u32 },
    /// The plugin is disabled (manually or by circuit breaker).
    Disabled { reason: String },
}

/// A loaded plugin: its config, checksum, and health.
#[derive(Clone, Debug)]
pub struct LoadedPlugin {
    pub config: PluginConfig,
    pub checksum: String,
    pub health: PluginHealth,
}

/// The plugin lifecycle manager: tracks loaded plugins, their health,
/// and which routes use them.
pub struct PluginLifecycle {
    /// Loaded plugins, keyed by name.
    plugins: RwLock<HashMap<String, LoadedPlugin>>,
    /// Route -> plugin names mapping (for failure isolation).
    route_plugins: RwLock<HashMap<String, Vec<String>>>,
    /// The plugin runner (compiled modules).
    runner: RwLock<Option<PluginRunner>>,
}

impl PluginLifecycle {
    /// Create a new plugin lifecycle manager.
    pub fn new() -> Self {
        Self {
            plugins: RwLock::new(HashMap::new()),
            route_plugins: RwLock::new(HashMap::new()),
            runner: RwLock::new(None),
        }
    }

    /// Load plugins from config. Compiles each plugin's .wasm module
    /// and stores it. `sources` carries the DW-165 registry-source
    /// resolutions (built by [`crate::wasm::source::resolve_sources`]):
    /// a resolved `source:` plugin loads from its verified local
    /// artifact exactly like a `wasm:` plugin; an unresolved one is
    /// marked Crashed with the step-named resolution error. Failure
    /// isolation is per plugin (DW-157): a .wasm that cannot be read
    /// or compiled — or a `source:` that could not be resolved or
    /// verified — marks THAT plugin Crashed (logged, visible to the
    /// operator at publish time) instead of failing the whole publish
    /// — routes referencing a crashed plugin answer 500 fail-closed,
    /// every other plugin keeps serving. The only whole-load failure
    /// is engine construction ([`LoadError::Compile`]).
    pub fn load(
        &self,
        configs: &[PluginConfig],
        sources: &crate::wasm::source::SourceResolutions,
    ) -> Result<(), LoadError> {
        let mut plugins = HashMap::new();
        // DW-165: effective local artifact paths for the runner (a
        // `source:` plugin has no `wasm` field; it loads from its
        // resolved cache path).
        let mut effective_paths: HashMap<String, PathBuf> = HashMap::new();

        for config in configs {
            // DW-119: a plugin is either `wasm:` or `native:`. The
            // lifecycle manager only loads WASM plugins here; native
            // filters are registered with the NativeRegistry and
            // dispatched by the unified plugin chain (plugins domain).
            let wasm_path: String = if let Some(p) = &config.wasm {
                p.clone()
            } else if let Some(_source) = &config.source {
                // DW-165: registry-sourced plugin. Resolution ran
                // before this step; its outcome decides whether there
                // are verified bytes to load at all.
                match sources.get(&config.name) {
                    Some(Ok(path)) => {
                        effective_paths.insert(config.name.clone(), path.clone());
                        path.display().to_string()
                    }
                    Some(Err(e)) => {
                        // Fail-closed (DW-157/165): never a partial
                        // load. The error names the exact resolution
                        // step (digest mismatch, download, signature).
                        let crash_count = self.next_crash_count(&config.name);
                        tracing::error!(
                            code = "plugin_source_failed",
                            plugin = %config.name,
                            "DW-165: registry source could not be resolved: {e}; \
                             routes referencing it fail closed (500)"
                        );
                        plugins.insert(
                            config.name.clone(),
                            LoadedPlugin {
                                config: config.clone(),
                                checksum: String::new(),
                                health: PluginHealth::Crashed {
                                    error: format!("source resolution failed: {e}"),
                                    crash_count,
                                },
                            },
                        );
                        continue;
                    }
                    None => {
                        // Defensive: the resolver covers every source
                        // plugin; absence means an internal wiring bug,
                        // and the safe answer is still fail-closed.
                        let crash_count = self.next_crash_count(&config.name);
                        tracing::error!(
                            code = "plugin_source_failed",
                            plugin = %config.name,
                            "DW-165: registry source was not resolved (internal \
                             error: resolver skipped this plugin); routes referencing \
                             it fail closed (500)"
                        );
                        plugins.insert(
                            config.name.clone(),
                            LoadedPlugin {
                                config: config.clone(),
                                checksum: String::new(),
                                health: PluginHealth::Crashed {
                                    error: "source was not resolved (internal resolver \
                                            error)"
                                        .to_string(),
                                    crash_count,
                                },
                            },
                        );
                        continue;
                    }
                }
            } else {
                continue;
            };
            // Read the .wasm file and compute checksum. A read failure
            // is recorded with an EMPTY checksum (never produced by a
            // successful read) so a persistently broken file keeps
            // incrementing its crash count across reloads.
            let (checksum, health) = match std::fs::read(&wasm_path) {
                Ok(wasm_bytes) => {
                    let checksum = sha256_hex(&wasm_bytes);
                    // DW-165 review parity re-check: the resolver
                    // verified the bytes IT read; this load re-reads
                    // the file (and an async reload may hand in a
                    // resolution computed a moment earlier). If the
                    // artifact changed in that window, the checksum
                    // diverges from the pin: fail closed rather than
                    // load unverified bytes.
                    if let Some(src) = &config.source {
                        if checksum != src.digest.to_ascii_lowercase() {
                            let crash_count = self.next_crash_count(&config.name);
                            tracing::error!(
                                code = "plugin_source_digest_recheck_failed",
                                plugin = %config.name,
                                path = %wasm_path,
                                "DW-165: the artifact changed between verification \
                                 and load (pinned digest does not match the loaded \
                                 bytes); routes referencing it fail closed (500)"
                            );
                            (
                                String::new(),
                                PluginHealth::Crashed {
                                    error: format!(
                                        "digest re-check failed: source.digest pins \
                                         {} but the loaded module hashes to {checksum} \
                                         (the artifact changed between verification \
                                         and load)",
                                        src.digest
                                    ),
                                    crash_count,
                                },
                            )
                        } else {
                            let health = self.health_for_checksum(&config.name, &checksum);
                            (checksum, health)
                        }
                    } else {
                        let health = self.health_for_checksum(&config.name, &checksum);
                        (checksum, health)
                    }
                }
                Err(e) => {
                    let crash_count = self.next_crash_count(&config.name);
                    tracing::error!(
                        code = "plugin_load_failed",
                        plugin = %config.name,
                        path = %wasm_path,
                        error = %e,
                        "DW-157: plugin .wasm unreadable; routes referencing it fail closed (500)"
                    );
                    (
                        String::new(),
                        PluginHealth::Crashed {
                            error: format!("cannot read {wasm_path}: {e}"),
                            crash_count,
                        },
                    )
                }
            };

            plugins.insert(
                config.name.clone(),
                LoadedPlugin {
                    config: config.clone(),
                    checksum,
                    health,
                },
            );
        }

        // Build the plugin runner.
        let runner = PluginRunner::new(configs, &effective_paths)
            .map_err(|e| LoadError::Compile { error: e })?;

        // A WASM plugin (local `wasm:` or resolved registry `source:`,
        // DW-165) with no compiled module (read failed above, or the
        // module failed to compile inside the runner) must read as
        // Crashed, not Healthy: a Healthy entry with no module would
        // otherwise pass the request-path health gate and then silently
        // skip dispatch. Fail closed (DW-157).
        {
            for (name, lp) in plugins.iter_mut() {
                if (lp.config.wasm.is_some() || lp.config.source.is_some())
                    && !runner.has(name)
                    && matches!(lp.health, PluginHealth::Healthy)
                {
                    tracing::error!(
                        code = "plugin_compile_failed",
                        plugin = %name,
                        "DW-157: plugin .wasm failed to compile; routes referencing it fail closed (500)"
                    );
                    lp.health = PluginHealth::Crashed {
                        error: "plugin failed to compile".to_string(),
                        crash_count: 1,
                    };
                }
            }
        }

        *self.plugins.write().unwrap() = plugins;
        *self.runner.write().unwrap() = Some(runner);

        Ok(())
    }

    /// Replace the route -> plugins mapping wholesale (DW-157). The
    /// dataplane calls this on every generation swap so routes removed
    /// from the config stop mapping to plugin names (a per-route
    /// `register_route` insert-only API would leak stale routes).
    pub fn set_route_plugins(&self, routes: HashMap<String, Vec<String>>) {
        *self.route_plugins.write().unwrap() = routes;
    }

    /// Register which plugins a route uses (for failure isolation).
    pub fn register_route(&self, route_name: &str, plugin_names: &[String]) {
        let mut route_plugins = self.route_plugins.write().unwrap();
        route_plugins.insert(route_name.to_string(), plugin_names.to_vec());
    }

    /// Next crash count for `name`: the previous Crashed count + 1, or
    /// 1 for a plugin that was healthy or absent (crash counts grow
    /// across reloads of the same broken plugin — pinned by
    /// `load_marks_unreadable_wasm_crashed_and_succeeds`). Extracted
    /// from the load paths that each duplicated the bookkeeping.
    fn next_crash_count(&self, name: &str) -> u32 {
        let existing = self.plugins.read().unwrap();
        match existing.get(name) {
            Some(prev) => match &prev.health {
                PluginHealth::Crashed { crash_count, .. } => crash_count + 1,
                _ => 1,
            },
            None => 1,
        }
    }

    /// Hot-swap health for a successfully read module (DW-157):
    /// unchanged bytes keep the previous health, changed bytes reset
    /// to Healthy (the recompile-on-change contract).
    fn health_for_checksum(&self, name: &str, checksum: &str) -> PluginHealth {
        let existing = self.plugins.read().unwrap();
        if let Some(prev) = existing.get(name) {
            if prev.checksum == checksum {
                // Unchanged: keep the previous health.
                return prev.health.clone();
            }
        }
        PluginHealth::Healthy
    }

    /// Mark a plugin as crashed.
    pub fn mark_crashed(&self, plugin_name: &str, error: &str) {
        let mut plugins = self.plugins.write().unwrap();
        if let Some(plugin) = plugins.get_mut(plugin_name) {
            let crash_count = match &plugin.health {
                PluginHealth::Crashed { crash_count, .. } => crash_count + 1,
                _ => 1,
            };
            plugin.health = PluginHealth::Crashed {
                error: error.to_string(),
                crash_count,
            };
        }
    }

    /// Mark a plugin as healthy (after recovery).
    pub fn mark_healthy(&self, plugin_name: &str) {
        let mut plugins = self.plugins.write().unwrap();
        if let Some(plugin) = plugins.get_mut(plugin_name) {
            plugin.health = PluginHealth::Healthy;
        }
    }

    /// Disable a plugin (manually or by circuit breaker).
    pub fn disable(&self, plugin_name: &str, reason: &str) {
        let mut plugins = self.plugins.write().unwrap();
        if let Some(plugin) = plugins.get_mut(plugin_name) {
            plugin.health = PluginHealth::Disabled {
                reason: reason.to_string(),
            };
        }
    }

    /// Check if a route is affected by a crashed plugin.
    /// Returns the list of crashed plugins on this route.
    pub fn crashed_plugins_for_route(&self, route_name: &str) -> Vec<String> {
        let route_plugins = self.route_plugins.read().unwrap();
        let plugins = self.plugins.read().unwrap();

        route_plugins
            .get(route_name)
            .map(|names| {
                names
                    .iter()
                    .filter(|name| {
                        plugins
                            .get(*name)
                            .map(|p| matches!(p.health, PluginHealth::Crashed { .. }))
                            .unwrap_or(false)
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Whether a route should get a 500 (has crashed plugins).
    pub fn route_should_500(&self, route_name: &str) -> bool {
        !self.crashed_plugins_for_route(route_name).is_empty()
    }

    /// Get a loaded plugin.
    pub fn get_plugin(&self, name: &str) -> Option<LoadedPlugin> {
        self.plugins.read().unwrap().get(name).cloned()
    }

    /// Get all loaded plugins.
    pub fn plugins(&self) -> Vec<LoadedPlugin> {
        self.plugins.read().unwrap().values().cloned().collect()
    }

    /// Get the plugin runner.
    pub fn runner(&self) -> Option<PluginRunner> {
        self.runner.read().unwrap().clone()
    }

    /// The number of loaded plugins.
    pub fn plugin_count(&self) -> usize {
        self.plugins.read().unwrap().len()
    }

    /// The number of healthy plugins.
    pub fn healthy_count(&self) -> usize {
        self.plugins
            .read()
            .unwrap()
            .values()
            .filter(|p| matches!(p.health, PluginHealth::Healthy))
            .count()
    }

    /// The number of crashed plugins.
    pub fn crashed_count(&self) -> usize {
        self.plugins
            .read()
            .unwrap()
            .values()
            .filter(|p| matches!(p.health, PluginHealth::Crashed { .. }))
            .count()
    }

    /// Validate a plugin config: check that the .wasm file exists,
    /// phases are non-empty, and limits are within bounds. Only
    /// validates WASM plugins (those with `wasm` set); native filters
    /// are validated by the snapshot pipeline (exactly-one-of
    /// wasm/native, phases non-empty) and the registry at startup.
    pub fn validate_config(config: &PluginConfig) -> Result<(), ValidationError> {
        // Check .wasm path is non-empty (only for WASM plugins).
        let wasm_path = match &config.wasm {
            Some(p) => p,
            None => return Ok(()),
        };
        if wasm_path.is_empty() {
            return Err(ValidationError::EmptyWasmPath {
                plugin: config.name.clone(),
            });
        }

        // Check phases are non-empty.
        if config.phases.is_empty() {
            return Err(ValidationError::NoPhases {
                plugin: config.name.clone(),
            });
        }

        // Check limits are within bounds.
        if let Some(limits) = &config.limits {
            if let Some(fuel) = limits.fuel {
                if fuel == 0 {
                    return Err(ValidationError::ZeroFuel {
                        plugin: config.name.clone(),
                    });
                }
            }
            if let Some(memory_mb) = limits.memory_mb {
                if memory_mb == 0 {
                    return Err(ValidationError::ZeroMemory {
                        plugin: config.name.clone(),
                    });
                }
            }
            if let Some(timeout_ms) = limits.timeout_ms {
                if timeout_ms == 0 {
                    return Err(ValidationError::ZeroTimeout {
                        plugin: config.name.clone(),
                    });
                }
            }
        }

        // Check .wasm file exists (last -- the other checks are cheaper).
        if !Path::new(wasm_path).exists() {
            return Err(ValidationError::WasmNotFound {
                plugin: config.name.clone(),
                path: wasm_path.clone(),
            });
        }

        Ok(())
    }

    /// Get the phase order for a set of plugins (deterministic, not
    /// load-order-dependent).
    pub fn phase_order(
        plugin_names: &[String],
        plugins: &HashMap<String, PluginConfig>,
    ) -> Vec<(PluginPhase, Vec<String>)> {
        let phases = [
            PluginPhase::RequestHeaders,
            PluginPhase::RequestBody,
            PluginPhase::ResponseHeaders,
            PluginPhase::ResponseBody,
        ];

        phases
            .iter()
            .map(|phase| {
                let phase_plugins: Vec<String> = plugin_names
                    .iter()
                    .filter(|name| {
                        plugins
                            .get(*name)
                            .map(|p| p.phases.contains(phase))
                            .unwrap_or(false)
                    })
                    .cloned()
                    .collect();
                (*phase, phase_plugins)
            })
            .filter(|(_, ps)| !ps.is_empty())
            .collect()
    }
}

impl Default for PluginLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

/// An error loading plugins. Per-plugin failures (an unreadable or
/// uncompilable .wasm) do NOT appear here — they mark that plugin
/// Crashed and the load succeeds (DW-157); only a failure that takes
/// the whole plugin runtime down (wasmtime engine construction) does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// The plugin runtime could not be constructed (engine failure).
    Compile { error: String },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Compile { error } => {
                write!(f, "plugin compile error: {error}")
            }
        }
    }
}

impl std::error::Error for LoadError {}

/// A validation error for a plugin config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// The .wasm path is empty.
    EmptyWasmPath { plugin: String },
    /// The .wasm file does not exist.
    WasmNotFound { plugin: String, path: String },
    /// The plugin has no phases declared.
    NoPhases { plugin: String },
    /// The fuel limit is zero.
    ZeroFuel { plugin: String },
    /// The memory limit is zero.
    ZeroMemory { plugin: String },
    /// The timeout limit is zero.
    ZeroTimeout { plugin: String },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::EmptyWasmPath { plugin } => {
                write!(f, "plugin '{plugin}': wasm path is empty")
            }
            ValidationError::WasmNotFound { plugin, path } => {
                write!(f, "plugin '{plugin}': wasm file not found: {path}")
            }
            ValidationError::NoPhases { plugin } => {
                write!(f, "plugin '{plugin}': no phases declared")
            }
            ValidationError::ZeroFuel { plugin } => {
                write!(f, "plugin '{plugin}': fuel limit is zero")
            }
            ValidationError::ZeroMemory { plugin } => {
                write!(f, "plugin '{plugin}': memory limit is zero")
            }
            ValidationError::ZeroTimeout { plugin } => {
                write!(f, "plugin '{plugin}': timeout limit is zero")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// Compute a SHA-256 hex digest of a byte slice. pub(crate): the
/// DW-165 source resolver reuses it for artifact digest verification
/// (one digest spelling across the plugin surface).
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    // Real SHA-256 (DW-158): the digest is exposed on the plugin
    // status surface (`GET /plugins`, `dwara-cli status`), where an
    // operator compares digests across a fleet and against a registry
    // pin's sha256 — a private hash would not survive that comparison.
    // The value is also the hot-swap change-detection key (two loads of
    // the same bytes always produce the same digest, which is all that
    // comparison needs).
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest.iter() {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

// White-box tests staying in src/ per AGENTS.md: these tests directly
// manipulate the private `plugins` map and call the private `sha256_hex`
// helper, which the public API (`load`, `register_route`) does not
// expose without a real WASM runtime.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PluginConfig, PluginLimitsConfig, PluginPhase};

    fn make_plugin_config(name: &str, wasm: &str) -> PluginConfig {
        PluginConfig {
            name: name.to_string(),
            wasm: Some(wasm.to_string()),
            source: None,
            native: None,
            phases: vec![PluginPhase::RequestHeaders],
            config: None,
            limits: None,
        }
    }

    #[test]
    fn lifecycle_new_is_empty() {
        let lifecycle = PluginLifecycle::new();
        assert_eq!(lifecycle.plugin_count(), 0);
        assert_eq!(lifecycle.healthy_count(), 0);
        assert_eq!(lifecycle.crashed_count(), 0);
        assert!(lifecycle.runner().is_none());
    }

    #[test]
    fn validate_empty_wasm_path() {
        let config = PluginConfig {
            name: "test".to_string(),
            wasm: Some("".to_string()),
            source: None,
            native: None,
            phases: vec![PluginPhase::RequestHeaders],
            config: None,
            limits: None,
        };
        let err = PluginLifecycle::validate_config(&config).unwrap_err();
        assert!(matches!(err, ValidationError::EmptyWasmPath { .. }));
    }

    #[test]
    fn validate_wasm_not_found() {
        let config = PluginConfig {
            name: "test".to_string(),
            wasm: Some("/nonexistent/path.wasm".to_string()),
            source: None,
            native: None,
            phases: vec![PluginPhase::RequestHeaders],
            config: None,
            limits: None,
        };
        let err = PluginLifecycle::validate_config(&config).unwrap_err();
        assert!(matches!(err, ValidationError::WasmNotFound { .. }));
    }

    #[test]
    fn validate_no_phases() {
        let config = PluginConfig {
            name: "test".to_string(),
            wasm: Some("/tmp/test.wasm".to_string()),
            source: None,
            native: None,
            phases: vec![],
            config: None,
            limits: None,
        };
        let err = PluginLifecycle::validate_config(&config).unwrap_err();
        assert!(matches!(err, ValidationError::NoPhases { .. }));
    }

    #[test]
    fn validate_zero_fuel() {
        let config = PluginConfig {
            name: "test".to_string(),
            wasm: Some("/tmp/test.wasm".to_string()),
            source: None,
            native: None,
            phases: vec![PluginPhase::RequestHeaders],
            config: None,
            limits: Some(PluginLimitsConfig {
                fuel: Some(0),
                memory_mb: None,
                timeout_ms: None,
            }),
        };
        let err = PluginLifecycle::validate_config(&config).unwrap_err();
        assert!(matches!(err, ValidationError::ZeroFuel { .. }));
    }

    #[test]
    fn validate_zero_memory() {
        let config = PluginConfig {
            name: "test".to_string(),
            wasm: Some("/tmp/test.wasm".to_string()),
            source: None,
            native: None,
            phases: vec![PluginPhase::RequestHeaders],
            config: None,
            limits: Some(PluginLimitsConfig {
                fuel: None,
                memory_mb: Some(0),
                timeout_ms: None,
            }),
        };
        let err = PluginLifecycle::validate_config(&config).unwrap_err();
        assert!(matches!(err, ValidationError::ZeroMemory { .. }));
    }

    #[test]
    fn validate_zero_timeout() {
        let config = PluginConfig {
            name: "test".to_string(),
            wasm: Some("/tmp/test.wasm".to_string()),
            source: None,
            native: None,
            phases: vec![PluginPhase::RequestHeaders],
            config: None,
            limits: Some(PluginLimitsConfig {
                fuel: None,
                memory_mb: None,
                timeout_ms: Some(0),
            }),
        };
        let err = PluginLifecycle::validate_config(&config).unwrap_err();
        assert!(matches!(err, ValidationError::ZeroTimeout { .. }));
    }

    #[test]
    fn mark_plugin_crashed() {
        let lifecycle = PluginLifecycle::new();
        // Manually insert a plugin for testing.
        {
            let mut plugins = lifecycle.plugins.write().unwrap();
            plugins.insert(
                "test-plugin".to_string(),
                LoadedPlugin {
                    config: make_plugin_config("test-plugin", "/tmp/test.wasm"),
                    checksum: "abc123".to_string(),
                    health: PluginHealth::Healthy,
                },
            );
        }

        assert_eq!(lifecycle.healthy_count(), 1);
        assert_eq!(lifecycle.crashed_count(), 0);

        lifecycle.mark_crashed("test-plugin", "out of fuel");
        assert_eq!(lifecycle.healthy_count(), 0);
        assert_eq!(lifecycle.crashed_count(), 1);

        let plugin = lifecycle.get_plugin("test-plugin").unwrap();
        match &plugin.health {
            PluginHealth::Crashed { error, crash_count } => {
                assert_eq!(error, "out of fuel");
                assert_eq!(*crash_count, 1);
            }
            other => panic!("expected Crashed, got {other:?}"),
        }
    }

    #[test]
    fn mark_plugin_healthy_after_crash() {
        let lifecycle = PluginLifecycle::new();
        {
            let mut plugins = lifecycle.plugins.write().unwrap();
            plugins.insert(
                "test-plugin".to_string(),
                LoadedPlugin {
                    config: make_plugin_config("test-plugin", "/tmp/test.wasm"),
                    checksum: "abc123".to_string(),
                    health: PluginHealth::Crashed {
                        error: "out of fuel".to_string(),
                        crash_count: 2,
                    },
                },
            );
        }

        assert_eq!(lifecycle.crashed_count(), 1);
        lifecycle.mark_healthy("test-plugin");
        assert_eq!(lifecycle.healthy_count(), 1);
        assert_eq!(lifecycle.crashed_count(), 0);
    }

    #[test]
    fn disable_plugin() {
        let lifecycle = PluginLifecycle::new();
        {
            let mut plugins = lifecycle.plugins.write().unwrap();
            plugins.insert(
                "test-plugin".to_string(),
                LoadedPlugin {
                    config: make_plugin_config("test-plugin", "/tmp/test.wasm"),
                    checksum: "abc123".to_string(),
                    health: PluginHealth::Healthy,
                },
            );
        }

        lifecycle.disable("test-plugin", "circuit breaker");
        let plugin = lifecycle.get_plugin("test-plugin").unwrap();
        match &plugin.health {
            PluginHealth::Disabled { reason } => {
                assert_eq!(reason, "circuit breaker");
            }
            other => panic!("expected Disabled, got {other:?}"),
        }
    }

    #[test]
    fn failure_isolation_route_with_crashed_plugin() {
        let lifecycle = PluginLifecycle::new();
        {
            let mut plugins = lifecycle.plugins.write().unwrap();
            plugins.insert(
                "broken-plugin".to_string(),
                LoadedPlugin {
                    config: make_plugin_config("broken-plugin", "/tmp/test.wasm"),
                    checksum: "abc123".to_string(),
                    health: PluginHealth::Crashed {
                        error: "panic".to_string(),
                        crash_count: 1,
                    },
                },
            );
            plugins.insert(
                "good-plugin".to_string(),
                LoadedPlugin {
                    config: make_plugin_config("good-plugin", "/tmp/test.wasm"),
                    checksum: "def456".to_string(),
                    health: PluginHealth::Healthy,
                },
            );
        }

        lifecycle.register_route("route-1", &["broken-plugin".to_string()]);
        lifecycle.register_route("route-2", &["good-plugin".to_string()]);
        lifecycle.register_route(
            "route-3",
            &["broken-plugin".to_string(), "good-plugin".to_string()],
        );

        // Route 1 has a crashed plugin -> should 500.
        assert!(lifecycle.route_should_500("route-1"));
        assert_eq!(
            lifecycle.crashed_plugins_for_route("route-1"),
            vec!["broken-plugin"]
        );

        // Route 2 has only healthy plugins -> should not 500.
        assert!(!lifecycle.route_should_500("route-2"));
        assert!(lifecycle.crashed_plugins_for_route("route-2").is_empty());

        // Route 3 has a crashed plugin -> should 500.
        assert!(lifecycle.route_should_500("route-3"));
    }

    #[test]
    fn failure_isolation_unaffected_route() {
        let lifecycle = PluginLifecycle::new();
        {
            let mut plugins = lifecycle.plugins.write().unwrap();
            plugins.insert(
                "broken-plugin".to_string(),
                LoadedPlugin {
                    config: make_plugin_config("broken-plugin", "/tmp/test.wasm"),
                    checksum: "abc123".to_string(),
                    health: PluginHealth::Crashed {
                        error: "panic".to_string(),
                        crash_count: 1,
                    },
                },
            );
        }

        lifecycle.register_route("route-with-plugin", &["broken-plugin".to_string()]);
        lifecycle.register_route("route-without-plugin", &[]);

        // Route with the crashed plugin -> 500.
        assert!(lifecycle.route_should_500("route-with-plugin"));

        // Route without any plugins -> not 500 (failure isolation).
        assert!(!lifecycle.route_should_500("route-without-plugin"));
    }

    #[test]
    fn crash_count_increments() {
        let lifecycle = PluginLifecycle::new();
        {
            let mut plugins = lifecycle.plugins.write().unwrap();
            plugins.insert(
                "test-plugin".to_string(),
                LoadedPlugin {
                    config: make_plugin_config("test-plugin", "/tmp/test.wasm"),
                    checksum: "abc123".to_string(),
                    health: PluginHealth::Healthy,
                },
            );
        }

        lifecycle.mark_crashed("test-plugin", "error 1");
        lifecycle.mark_crashed("test-plugin", "error 2");
        lifecycle.mark_crashed("test-plugin", "error 3");

        let plugin = lifecycle.get_plugin("test-plugin").unwrap();
        match &plugin.health {
            PluginHealth::Crashed { crash_count, .. } => assert_eq!(*crash_count, 3),
            other => panic!("expected Crashed, got {other:?}"),
        }
    }

    #[test]
    fn phase_order_deterministic() {
        let mut plugins = HashMap::new();
        plugins.insert(
            "plugin-a".to_string(),
            PluginConfig {
                name: "plugin-a".to_string(),
                wasm: Some("/tmp/a.wasm".to_string()),
                source: None,
                native: None,
                phases: vec![PluginPhase::RequestHeaders, PluginPhase::ResponseBody],
                config: None,
                limits: None,
            },
        );
        plugins.insert(
            "plugin-b".to_string(),
            PluginConfig {
                name: "plugin-b".to_string(),
                wasm: Some("/tmp/b.wasm".to_string()),
                source: None,
                native: None,
                phases: vec![PluginPhase::RequestHeaders, PluginPhase::RequestBody],
                config: None,
                limits: None,
            },
        );

        let order = PluginLifecycle::phase_order(
            &["plugin-b".to_string(), "plugin-a".to_string()],
            &plugins,
        );

        // Phase order should be deterministic (not load-order-dependent).
        assert_eq!(order.len(), 3); // RequestHeaders, RequestBody, ResponseBody
        assert_eq!(order[0].0, PluginPhase::RequestHeaders);
        assert!(order[0].1.contains(&"plugin-a".to_string()));
        assert!(order[0].1.contains(&"plugin-b".to_string()));
        assert_eq!(order[1].0, PluginPhase::RequestBody);
        assert_eq!(order[1].1, vec!["plugin-b"]);
        assert_eq!(order[2].0, PluginPhase::ResponseBody);
        assert_eq!(order[2].1, vec!["plugin-a"]);
    }

    #[test]
    fn phase_order_skips_empty_phases() {
        let mut plugins = HashMap::new();
        plugins.insert(
            "plugin-a".to_string(),
            PluginConfig {
                name: "plugin-a".to_string(),
                wasm: Some("/tmp/a.wasm".to_string()),
                source: None,
                native: None,
                phases: vec![PluginPhase::ResponseHeaders],
                config: None,
                limits: None,
            },
        );

        let order = PluginLifecycle::phase_order(&["plugin-a".to_string()], &plugins);

        // Only ResponseHeaders should appear (the other 3 phases are empty).
        assert_eq!(order.len(), 1);
        assert_eq!(order[0].0, PluginPhase::ResponseHeaders);
    }

    #[test]
    fn sha256_hex_is_deterministic() {
        let data = b"hello world";
        let hash1 = sha256_hex(data);
        let hash2 = sha256_hex(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn sha256_hex_differs_for_different_data() {
        let hash1 = sha256_hex(b"hello");
        let hash2 = sha256_hex(b"world");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn sha256_hex_is_real_sha256_full_width() {
        // DW-158: the digest is exposed on the plugin status surface and
        // compared against registry pins, so it must be a true SHA-256
        // (64 lowercase hex chars, the standard "hello world" vector).
        let digest = sha256_hex(b"hello world");
        assert_eq!(digest.len(), 64);
        assert_eq!(
            digest,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn load_marks_unreadable_wasm_crashed_and_succeeds() {
        // DW-157: a per-plugin failure must not fail the whole load —
        // the plugin reads as Crashed (fail-closed for routes
        // referencing it) and the crash count keeps growing across
        // reloads of the same broken file.
        let lifecycle = PluginLifecycle::new();
        let configs = vec![make_plugin_config("broken", "/nonexistent/dwara-test.wasm")];
        lifecycle
            .load(&configs, &HashMap::new())
            .expect("load succeeds with per-plugin isolation");
        assert_eq!(lifecycle.plugin_count(), 1);
        assert_eq!(lifecycle.crashed_count(), 1);
        let plugin = lifecycle
            .get_plugin("broken")
            .expect("broken plugin tracked");
        match plugin.health {
            PluginHealth::Crashed { crash_count, .. } => assert_eq!(crash_count, 1),
            other => panic!("expected Crashed, got {other:?}"),
        }
        // Reload the same broken file: still Ok, crash count grows.
        lifecycle
            .load(&configs, &HashMap::new())
            .expect("reload succeeds");
        let plugin = lifecycle.get_plugin("broken").unwrap();
        match plugin.health {
            PluginHealth::Crashed { crash_count, .. } => assert_eq!(crash_count, 2),
            other => panic!("expected Crashed, got {other:?}"),
        }
    }

    #[test]
    fn set_route_plugins_replaces_wholesale() {
        let lifecycle = PluginLifecycle::new();
        {
            let mut plugins = lifecycle.plugins.write().unwrap();
            plugins.insert(
                "broken-plugin".to_string(),
                LoadedPlugin {
                    config: make_plugin_config("broken-plugin", "/tmp/test.wasm"),
                    checksum: "abc123".to_string(),
                    health: PluginHealth::Crashed {
                        error: "panic".to_string(),
                        crash_count: 1,
                    },
                },
            );
        }
        lifecycle.register_route("stale", &["broken-plugin".to_string()]);
        assert!(lifecycle.route_should_500("stale"));
        let mut next = HashMap::new();
        next.insert("fresh".to_string(), vec!["broken-plugin".to_string()]);
        lifecycle.set_route_plugins(next);
        assert!(
            !lifecycle.route_should_500("stale"),
            "the replaced mapping no longer exists"
        );
        assert!(lifecycle.route_should_500("fresh"));
    }

    #[test]
    fn load_error_compile_display() {
        let err = LoadError::Compile {
            error: "wasmtime engine failed".to_string(),
        };
        let s = format!("{err}");
        assert!(s.contains("compile"));
        assert!(s.contains("wasmtime engine failed"));
    }

    // --- DW-165: registry source plugins ---------------------------------

    fn make_source_plugin(name: &str) -> PluginConfig {
        PluginConfig {
            name: name.to_string(),
            wasm: None,
            native: None,
            source: Some(crate::config::PluginSourceConfig {
                url: "https://registry.example.com/plugins/p.wasm".to_string(),
                digest: "a".repeat(64),
                signature: None,
                public_key: None,
                cache_path: None,
            }),
            phases: vec![PluginPhase::RequestHeaders],
            config: None,
            limits: None,
        }
    }

    #[test]
    fn load_marks_unresolved_source_crashed_and_succeeds() {
        // DW-165: a source plugin whose resolution FAILED is Crashed
        // with the step-named error — never a partial load — and the
        // load (and publish) still succeeds for every other plugin.
        let lifecycle = PluginLifecycle::new();
        let configs = vec![make_source_plugin("remote")];
        let mut sources = HashMap::new();
        sources.insert(
            "remote".to_string(),
            Err(crate::wasm::source::SourceError::DigestMismatch {
                plugin: "remote".to_string(),
                origin: "downloaded",
                expected: "a".repeat(64),
                actual: "b".repeat(64),
            }),
        );
        lifecycle
            .load(&configs, &sources)
            .expect("load succeeds with per-plugin isolation");
        assert_eq!(lifecycle.crashed_count(), 1);
        let plugin = lifecycle.get_plugin("remote").unwrap();
        match &plugin.health {
            PluginHealth::Crashed { error, crash_count } => {
                assert_eq!(*crash_count, 1);
                assert!(
                    error.contains("digest verification failed"),
                    "error names the step: {error}"
                );
                assert!(error.contains("remote"), "error names the plugin: {error}");
            }
            other => panic!("expected Crashed, got {other:?}"),
        }
        // An empty checksum means the artifact never loaded.
        assert_eq!(plugin.checksum, "");
    }

    #[test]
    fn load_marks_unresolved_entry_source_crashed() {
        // Defensive branch: a source plugin missing from the resolver
        // output entirely still fails closed (internal wiring bug, not
        // a silent skip).
        let lifecycle = PluginLifecycle::new();
        let configs = vec![make_source_plugin("remote")];
        lifecycle
            .load(&configs, &HashMap::new())
            .expect("load succeeds");
        let plugin = lifecycle.get_plugin("remote").unwrap();
        match &plugin.health {
            PluginHealth::Crashed { error, .. } => {
                assert!(error.contains("not resolved"), "got: {error}");
            }
            other => panic!("expected Crashed, got {other:?}"),
        }
    }

    #[test]
    fn validation_error_display() {
        let err = ValidationError::NoPhases {
            plugin: "test".to_string(),
        };
        let s = format!("{err}");
        assert!(s.contains("test"));
        assert!(s.contains("no phases"));
    }
}
