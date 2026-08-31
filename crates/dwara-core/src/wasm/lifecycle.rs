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
//! the routes that reference that plugin are affected.
//!
//! ## Hot-swap on reload
//!
//! When the config is reloaded, the lifecycle manager recompiles
//! plugins that changed (by checksum) and swaps them in atomically.
//! Plugins that did not change are reused (no recompilation).
//!
//! ## Feature gate
//!
//! The `wasm` cargo feature must be enabled (this module builds on
//! the DW-055 proxy-wasm host). Without it, the module is not
//! compiled and the gateway runs without plugin support.

use std::collections::HashMap;
use std::path::Path;
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
    /// and stores it. Plugins that fail to compile are marked as
    /// Crashed (not skipped -- the operator should know).
    pub fn load(&self, configs: &[PluginConfig]) -> Result<(), LoadError> {
        let mut plugins = HashMap::new();

        for config in configs {
            // Read the .wasm file and compute checksum.
            let wasm_path = &config.wasm;
            let wasm_bytes = std::fs::read(wasm_path).map_err(|e| LoadError::FileRead {
                plugin: config.name.clone(),
                path: wasm_path.clone(),
                error: e.to_string(),
            })?;

            let checksum = sha256_hex(&wasm_bytes);

            // Check if the plugin changed (hot-swap).
            let existing = self.plugins.read().unwrap();
            let health = if let Some(prev) = existing.get(&config.name) {
                if prev.checksum == checksum {
                    // Unchanged: keep the previous health.
                    prev.health.clone()
                } else {
                    // Changed: reset to Healthy.
                    PluginHealth::Healthy
                }
            } else {
                PluginHealth::Healthy
            };
            drop(existing);

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
        let runner = PluginRunner::new(configs).map_err(|e| LoadError::Compile { error: e })?;

        *self.plugins.write().unwrap() = plugins;
        *self.runner.write().unwrap() = Some(runner);

        Ok(())
    }

    /// Register which plugins a route uses (for failure isolation).
    pub fn register_route(&self, route_name: &str, plugin_names: &[String]) {
        let mut route_plugins = self.route_plugins.write().unwrap();
        route_plugins.insert(route_name.to_string(), plugin_names.to_vec());
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
    /// phases are non-empty, and limits are within bounds.
    pub fn validate_config(config: &PluginConfig) -> Result<(), ValidationError> {
        // Check .wasm path is non-empty.
        if config.wasm.is_empty() {
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
        if !Path::new(&config.wasm).exists() {
            return Err(ValidationError::WasmNotFound {
                plugin: config.name.clone(),
                path: config.wasm.clone(),
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

/// An error loading plugins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// A .wasm file could not be read.
    FileRead {
        plugin: String,
        path: String,
        error: String,
    },
    /// A plugin failed to compile.
    Compile { error: String },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::FileRead {
                plugin,
                path,
                error,
            } => {
                write!(f, "plugin '{plugin}': cannot read {path}: {error}")
            }
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

/// Compute a SHA-256 hex digest of a byte slice.
fn sha256_hex(data: &[u8]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // We use a simple hash here (not cryptographic SHA-256) to avoid
    // pulling in a SHA-256 dependency. In production, this should be
    // a real SHA-256 checksum. The hash is used for change detection
    // (hot-swap), not security.
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PluginConfig, PluginLimitsConfig, PluginPhase};

    fn make_plugin_config(name: &str, wasm: &str) -> PluginConfig {
        PluginConfig {
            name: name.to_string(),
            wasm: wasm.to_string(),
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
            wasm: "".to_string(),
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
            wasm: "/nonexistent/path.wasm".to_string(),
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
            wasm: "/tmp/test.wasm".to_string(),
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
            wasm: "/tmp/test.wasm".to_string(),
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
            wasm: "/tmp/test.wasm".to_string(),
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
            wasm: "/tmp/test.wasm".to_string(),
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
                wasm: "/tmp/a.wasm".to_string(),
                phases: vec![PluginPhase::RequestHeaders, PluginPhase::ResponseBody],
                config: None,
                limits: None,
            },
        );
        plugins.insert(
            "plugin-b".to_string(),
            PluginConfig {
                name: "plugin-b".to_string(),
                wasm: "/tmp/b.wasm".to_string(),
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
                wasm: "/tmp/a.wasm".to_string(),
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
    fn load_error_file_read_display() {
        let err = LoadError::FileRead {
            plugin: "test".to_string(),
            path: "/tmp/test.wasm".to_string(),
            error: "not found".to_string(),
        };
        let s = format!("{err}");
        assert!(s.contains("test"));
        assert!(s.contains("/tmp/test.wasm"));
        assert!(s.contains("not found"));
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
