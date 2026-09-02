//! Extism PDK plugin runtime scaffold (DW-109).
//!
//! Extism is an alternative plugin runtime that uses the Extism PDK
//! (Plugin Development Kit) ABI, allowing plugins written in any
//! language that compiles to WebAssembly (Rust, Go, C, Zig, ...) to
//! run inside the gateway. Like the proxy-wasm host (DW-055), an
//! Extism plugin is a `.wasm` module loaded at startup; unlike
//! proxy-wasm, the Extism ABI is simpler (a single `call` entry point
//! with input/output buffers, not a multi-phase stream contract).
//!
//! This module provides the scaffold for the Extism runtime so that
//! Extism plugins can be registered alongside native and WASM plugins
//! in the unified dispatch chain (DW-119). The scaffold is
//! feature-gated behind the `extism` cargo feature (default OFF).
//!
//! ## STUBBED
//!
//! The actual `extism` crate (which wraps the Extism C SDK via FFI)
//! is NOT a dependency yet. The runtime calls in [`ExtismHost`] are
//! scaffolded as documented no-ops: they return [`FilterOutcome::Continue`]
//! with the input unchanged. When the integration is production-ready,
//! the `extism` crate would be added as an optional dependency and the
//! stubbed calls would be replaced with real Extism SDK invocations.
//! The config schema, validation, and dispatch trait are designed so
//! the real wiring lands here without touching the rest of the
//! gateway.
//!
//! ## Dependency direction
//!
//! `plugins` depends on `config` only. The Extism scaffold does not
//! import `wasm` (the proxy-wasm host) -- the two runtimes are
//! independent. The unified dispatch chain (DW-119) treats an Extism
//! plugin identically to a native filter or a WASM plugin: it occupies
//! the same phase slot on the same route, selected by config.
//!
//! ## Feature gate
//!
//! The module is feature-gated behind the `extism` cargo feature
//! (default OFF). When `extism` is on but `plugins` is off, the
//! scaffold compiles but is not wired into the dispatch chain (the
//! chain requires the `plugins` feature). When both are on, Extism
//! plugins can be registered alongside native and WASM plugins.

use std::fmt;

use crate::config::PluginPhase;

use super::filter::{FilterOutcome, LocalResponse, NativeFilter};

/// An Extism PDK plugin definition (DW-109).
///
/// Mirrors [`crate::config::PluginConfig`] but specialized for the
/// Extism runtime: a `.wasm` module path, a plugin name, and an
/// opaque config string passed to the plugin's `call` entry point.
/// The module is loaded by [`ExtismHost`] at startup; the host
/// creates a per-request instance for each route that references the
/// plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtismPlugin {
    /// Unique plugin name. Referenced by routes' `plugins` field.
    pub name: String,
    /// Path to the .wasm module file. Must be readable at startup.
    pub module_path: String,
    /// Plugin-specific configuration, passed to the plugin's `call`
    /// entry point as a byte string. Typically a JSON or YAML blob
    /// the plugin parses itself.
    pub config: Option<String>,
    /// Phases this plugin hooks. Must be a non-empty subset of:
    /// `request_headers`, `request_body`, `response_headers`,
    /// `response_body`. The host calls the plugin's `call` function
    /// at each declared phase with the phase name as the input.
    pub phases: Vec<PluginPhase>,
}

/// The Extism PDK host: loads .wasm modules and creates per-request
/// instances (DW-109).
///
/// The host is the Extism equivalent of the proxy-wasm
/// [`crate::wasm::host::WasmEngine`]. It loads Extism plugins at
/// startup and creates per-request instances for each route that
/// references them. The instances are dispatched via the
/// [`ExtismDispatch`] trait, which the unified plugin chain
/// (DW-119) calls at each phase.
///
/// ## STUBBED
///
/// The actual Extism SDK calls (plugin creation, instance creation,
/// function calls) are STUBBED. [`ExtismHost::load`] records the
/// plugin definition but does not create a real Extism plugin;
/// [`ExtismHost::instance`] returns an [`ExtismInstance`] whose
/// phase methods are no-ops (they return [`FilterOutcome::Continue`]
/// with the input unchanged). When the `extism` crate is added, these
/// stubs would be replaced with real SDK calls.
pub struct ExtismHost {
    /// Loaded plugin definitions, keyed by name.
    plugins: std::collections::HashMap<String, ExtismPlugin>,
}

impl ExtismHost {
    /// Create an empty host.
    pub fn new() -> Self {
        Self {
            plugins: std::collections::HashMap::new(),
        }
    }

    /// Load an Extism plugin definition. The module file is NOT
    /// actually loaded yet (STUBBED); the definition is recorded for
    /// later instance creation. When the `extism` crate is added,
    /// this would call `extism::Plugin::new(module_path)` to compile
    /// and instantiate the plugin module.
    ///
    /// Returns an error if a plugin with the same name is already
    /// loaded.
    pub fn load(&mut self, plugin: ExtismPlugin) -> Result<(), ExtismLoadError> {
        if self.plugins.contains_key(&plugin.name) {
            return Err(ExtismLoadError::Duplicate {
                name: plugin.name.clone(),
            });
        }
        self.plugins.insert(plugin.name.clone(), plugin);
        Ok(())
    }

    /// Whether a plugin is loaded under this name.
    pub fn contains(&self, name: &str) -> bool {
        self.plugins.contains_key(name)
    }

    /// The number of loaded plugins.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Whether the host has no loaded plugins.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// The loaded plugin names (sorted for determinism).
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.plugins.keys().cloned().collect();
        names.sort();
        names
    }

    /// Create a per-request instance for the named plugin. The
    /// instance implements [`NativeFilter`] so it can be dispatched
    /// by the unified plugin chain (DW-119) alongside native and
    /// WASM plugins.
    ///
    /// ## STUBBED
    ///
    /// The actual Extism SDK instance creation is STUBBED. The
    /// returned [`ExtismInstance`] holds the plugin definition but
    /// its phase methods are no-ops. When the `extism` crate is
    /// added, this would call `extism::Plugin::new_instance()` or
    /// the equivalent SDK call.
    pub fn instance(&self, name: &str) -> Result<ExtismInstance, ExtismLoadError> {
        let plugin = self
            .plugins
            .get(name)
            .ok_or_else(|| ExtismLoadError::NotFound {
                name: name.to_string(),
            })?;
        Ok(ExtismInstance {
            plugin: plugin.clone(),
        })
    }
}

impl Default for ExtismHost {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ExtismHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtismHost")
            .field("plugins", &self.names())
            .finish()
    }
}

/// An error from the Extism host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtismLoadError {
    /// No plugin loaded under this name.
    NotFound { name: String },
    /// A plugin is already loaded under this name.
    Duplicate { name: String },
}

impl fmt::Display for ExtismLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtismLoadError::NotFound { name } => {
                write!(f, "extism plugin '{name}' is not loaded")
            }
            ExtismLoadError::Duplicate { name } => {
                write!(f, "extism plugin '{name}' is already loaded")
            }
        }
    }
}

impl std::error::Error for ExtismLoadError {}

/// A per-request Extism plugin instance (DW-109).
///
/// Implements [`NativeFilter`] so the unified plugin chain (DW-119)
/// can dispatch to it at each phase, identically to a native filter
/// or a WASM plugin. The instance holds the plugin definition and
/// (when the Extism SDK is integrated) the per-request Extism
/// instance handle.
///
/// ## STUBBED
///
/// The phase methods are no-ops: they return
/// [`FilterOutcome::Continue`] with the input unchanged. When the
/// `extism` crate is added, each method would call the Extism
/// instance's `call` function with the phase name and the current
/// headers/body as input, then parse the output to produce the
/// outcome.
pub struct ExtismInstance {
    plugin: ExtismPlugin,
}

impl ExtismInstance {
    /// The plugin definition backing this instance.
    pub fn plugin(&self) -> &ExtismPlugin {
        &self.plugin
    }
}

impl NativeFilter for ExtismInstance {
    fn on_request_headers(&mut self, headers: Vec<(String, String)>) -> FilterOutcome {
        // STUBBED: when the extism crate is added, this would call
        // the Extism instance's `call` function with "request_headers"
        // and the serialized headers as input, then parse the output.
        FilterOutcome::Continue {
            headers,
            body: Vec::new(),
        }
    }

    fn on_request_body(&mut self, body: Vec<u8>) -> FilterOutcome {
        // STUBBED: when the extism crate is added, this would call
        // the Extism instance's `call` function with "request_body"
        // and the body bytes as input.
        FilterOutcome::Continue {
            headers: Vec::new(),
            body,
        }
    }

    fn on_response_headers(&mut self, headers: Vec<(String, String)>) -> FilterOutcome {
        // STUBBED: when the extism crate is added, this would call
        // the Extism instance's `call` function with "response_headers"
        // and the serialized headers as input.
        FilterOutcome::Continue {
            headers,
            body: Vec::new(),
        }
    }

    fn on_response_body(&mut self, body: Vec<u8>) -> FilterOutcome {
        // STUBBED: when the extism crate is added, this would call
        // the Extism instance's `call` function with "response_body"
        // and the body bytes as input.
        FilterOutcome::Continue {
            headers: Vec::new(),
            body,
        }
    }
}

impl fmt::Debug for ExtismInstance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtismInstance")
            .field("plugin", &self.plugin.name)
            .finish()
    }
}

/// A dispatch trait for Extism plugins in the unified chain (DW-109).
///
/// Mirrors [`super::WasmDispatch`] but for the Extism runtime. The
/// unified plugin chain (DW-119) calls these methods for each Extism
/// plugin in the phase, in order. When the `extism` feature is off,
/// the chain does not include Extism plugins.
///
/// This trait is separate from [`NativeFilter`] because, like the
/// WASM dispatch adapter, the Extism host owns the per-request
/// instances and dispatches to them as a group (not one-by-one as
/// the chain does for native filters). The chain calls the adapter
/// once per phase; the adapter dispatches to all its Extism instances
/// in declaration order.
pub trait ExtismDispatch {
    /// Run `on_request_headers` for the named Extism plugin. Returns
    /// the outcome and the (possibly modified) headers.
    fn on_request_headers(
        &mut self,
        name: &str,
        headers: Vec<(String, String)>,
    ) -> (super::chain::ChainOutcome, Vec<(String, String)>);

    /// Run `on_request_body` for the named Extism plugin. Returns the
    /// outcome and the (possibly modified) body.
    fn on_request_body(
        &mut self,
        name: &str,
        body: Vec<u8>,
    ) -> (super::chain::ChainOutcome, Vec<u8>);

    /// Run `on_response_headers` for the named Extism plugin. Returns
    /// the outcome and the (possibly modified) headers.
    fn on_response_headers(
        &mut self,
        name: &str,
        headers: Vec<(String, String)>,
    ) -> (super::chain::ChainOutcome, Vec<(String, String)>);

    /// Run `on_response_body` for the named Extism plugin. Returns
    /// the outcome and the (possibly modified) body.
    fn on_response_body(
        &mut self,
        name: &str,
        body: Vec<u8>,
    ) -> (super::chain::ChainOutcome, Vec<u8>);

    /// Call `on_done` for all Extism instances (the cleanup path).
    fn on_done(&mut self) {}
}

/// A no-op Extism dispatch adapter for builds without any Extism
/// plugins on a route. Every method returns
/// [`super::chain::ChainOutcome::Continue`] with the input unchanged.
#[derive(Default)]
pub struct NoExtism;

impl ExtismDispatch for NoExtism {
    fn on_request_headers(
        &mut self,
        _name: &str,
        headers: Vec<(String, String)>,
    ) -> (super::chain::ChainOutcome, Vec<(String, String)>) {
        (super::chain::ChainOutcome::Continue, headers)
    }

    fn on_request_body(
        &mut self,
        _name: &str,
        body: Vec<u8>,
    ) -> (super::chain::ChainOutcome, Vec<u8>) {
        (super::chain::ChainOutcome::Continue, body)
    }

    fn on_response_headers(
        &mut self,
        _name: &str,
        headers: Vec<(String, String)>,
    ) -> (super::chain::ChainOutcome, Vec<(String, String)>) {
        (super::chain::ChainOutcome::Continue, headers)
    }

    fn on_response_body(
        &mut self,
        _name: &str,
        body: Vec<u8>,
    ) -> (super::chain::ChainOutcome, Vec<u8>) {
        (super::chain::ChainOutcome::Continue, body)
    }
}

/// A per-request Extism dispatch adapter that drives [`ExtismInstance`]s
/// via the [`ExtismDispatch`] trait. The dataplane constructs one
/// adapter per request (holding the instances) and passes it to the
/// unified plugin chain; the chain calls back into the adapter for
/// each Extism plugin at each phase.
///
/// ## STUBBED
///
/// The adapter holds [`ExtismInstance`]s whose phase methods are
/// no-ops (they return [`FilterOutcome::Continue`]). When the Extism
/// SDK is integrated, the instances would call the real Extism
/// runtime.
pub struct ExtismChainAdapter {
    instances: std::collections::HashMap<String, ExtismInstance>,
}

impl ExtismChainAdapter {
    /// Build an adapter from the route's Extism plugin names and the
    /// host. Creates a per-request instance for each named plugin.
    pub fn new(plugin_names: &[String], host: &ExtismHost) -> Self {
        let mut instances = std::collections::HashMap::new();
        for name in plugin_names {
            if let Ok(instance) = host.instance(name) {
                instances.insert(name.clone(), instance);
            }
        }
        Self { instances }
    }
}

impl ExtismDispatch for ExtismChainAdapter {
    fn on_request_headers(
        &mut self,
        name: &str,
        headers: Vec<(String, String)>,
    ) -> (super::chain::ChainOutcome, Vec<(String, String)>) {
        let Some(instance) = self.instances.get_mut(name) else {
            return (super::chain::ChainOutcome::Continue, headers);
        };
        match instance.on_request_headers(headers) {
            FilterOutcome::Continue { headers, .. } => {
                (super::chain::ChainOutcome::Continue, headers)
            }
            FilterOutcome::LocalResponse(resp) => {
                (super::chain::ChainOutcome::LocalResponse(resp), Vec::new())
            }
            FilterOutcome::Error(e) => (super::chain::ChainOutcome::Error(e), Vec::new()),
        }
    }

    fn on_request_body(
        &mut self,
        name: &str,
        body: Vec<u8>,
    ) -> (super::chain::ChainOutcome, Vec<u8>) {
        let Some(instance) = self.instances.get_mut(name) else {
            return (super::chain::ChainOutcome::Continue, body);
        };
        match instance.on_request_body(body) {
            FilterOutcome::Continue { body, .. } => (super::chain::ChainOutcome::Continue, body),
            FilterOutcome::LocalResponse(resp) => {
                (super::chain::ChainOutcome::LocalResponse(resp), Vec::new())
            }
            FilterOutcome::Error(e) => (super::chain::ChainOutcome::Error(e), Vec::new()),
        }
    }

    fn on_response_headers(
        &mut self,
        name: &str,
        headers: Vec<(String, String)>,
    ) -> (super::chain::ChainOutcome, Vec<(String, String)>) {
        let Some(instance) = self.instances.get_mut(name) else {
            return (super::chain::ChainOutcome::Continue, headers);
        };
        match instance.on_response_headers(headers) {
            FilterOutcome::Continue { headers, .. } => {
                (super::chain::ChainOutcome::Continue, headers)
            }
            FilterOutcome::LocalResponse(resp) => {
                (super::chain::ChainOutcome::LocalResponse(resp), Vec::new())
            }
            FilterOutcome::Error(e) => (super::chain::ChainOutcome::Error(e), Vec::new()),
        }
    }

    fn on_response_body(
        &mut self,
        name: &str,
        body: Vec<u8>,
    ) -> (super::chain::ChainOutcome, Vec<u8>) {
        let Some(instance) = self.instances.get_mut(name) else {
            return (super::chain::ChainOutcome::Continue, body);
        };
        match instance.on_response_body(body) {
            FilterOutcome::Continue { body, .. } => (super::chain::ChainOutcome::Continue, body),
            FilterOutcome::LocalResponse(resp) => {
                (super::chain::ChainOutcome::LocalResponse(resp), Vec::new())
            }
            FilterOutcome::Error(e) => (super::chain::ChainOutcome::Error(e), Vec::new()),
        }
    }
}
