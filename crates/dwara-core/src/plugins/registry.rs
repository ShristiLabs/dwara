//! The native filter registry (DW-119).
//!
//! [`NativeRegistry`] maps a registered implementation name to a
//! [`NativeFilterFactory`]. Compiled-in filters register themselves at
//! startup (the binary or test calls [`NativeRegistry::register`]); the
//! registry is dependency-free -- no inventory/linkme, just a function
//! the caller invokes. The unified [`super::PluginChain`] looks up a
//! plugin's `native` name in the registry to build the per-request
//! filter list.
//!
//! The registry is `Send + Sync` (an `RwLock<HashMap<...>>`) so it can
//! be shared across the dataplane's worker tasks.

use std::collections::HashMap;
use std::sync::RwLock;

use super::filter::NativeFilter;

/// A factory function: given the plugin's opaque `config` string (from
/// [`crate::config::PluginConfig::config`]), produce a boxed native
/// filter. The config is the same blob a WASM plugin receives via
/// `proxy_on_configure`; a native filter parses it itself (typically
/// JSON or YAML).
pub type NativeFilterFactory =
    Box<dyn Fn(&Option<String>) -> Result<Box<dyn NativeFilter>, String> + Send + Sync>;

/// An error from the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// No factory registered under this name.
    NotFound { name: String },
    /// The factory returned an error constructing the filter.
    Construction { name: String, error: String },
    /// A factory is already registered under this name.
    Duplicate { name: String },
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::NotFound { name } => {
                write!(f, "native filter '{name}' is not registered")
            }
            RegistryError::Construction { name, error } => {
                write!(f, "native filter '{name}' construction failed: {error}")
            }
            RegistryError::Duplicate { name } => {
                write!(f, "native filter '{name}' is already registered")
            }
        }
    }
}

impl std::error::Error for RegistryError {}

/// The native filter registry: implementation name -> factory.
///
/// Created once at startup and shared (via `Arc<NativeRegistry>` or a
/// clone, which shares the inner map through `Arc<RwLock<...>>`).
/// Compiled-in filters register themselves by name; config selects one
/// with `native: <name>` on a [`crate::config::PluginConfig`].
#[derive(Clone)]
pub struct NativeRegistry {
    factories: std::sync::Arc<RwLock<HashMap<String, NativeFilterFactory>>>,
}

impl NativeRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            factories: std::sync::Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a factory under a name. Returns
    /// [`RegistryError::Duplicate`] if the name is already taken.
    pub fn register(
        &self,
        name: impl Into<String>,
        factory: NativeFilterFactory,
    ) -> Result<(), RegistryError> {
        let name = name.into();
        let mut factories = self.factories.write().unwrap();
        if factories.contains_key(&name) {
            return Err(RegistryError::Duplicate { name });
        }
        factories.insert(name, factory);
        Ok(())
    }

    /// Whether a factory is registered under this name.
    pub fn contains(&self, name: &str) -> bool {
        self.factories.read().unwrap().contains_key(name)
    }

    /// The number of registered factories.
    pub fn len(&self) -> usize {
        self.factories.read().unwrap().len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.factories.read().unwrap().is_empty()
    }

    /// The registered implementation names (sorted for determinism).
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.factories.read().unwrap().keys().cloned().collect();
        names.sort();
        names
    }

    /// Construct a native filter by name, passing the plugin's config
    /// string. Returns [`RegistryError::NotFound`] if no factory is
    /// registered, or [`RegistryError::Construction`] if the factory
    /// errors.
    pub fn create(
        &self,
        name: &str,
        config: &Option<String>,
    ) -> Result<Box<dyn NativeFilter>, RegistryError> {
        let factories = self.factories.read().unwrap();
        let factory = factories.get(name).ok_or_else(|| RegistryError::NotFound {
            name: name.to_string(),
        })?;
        // Clone the name out so the read guard can drop before calling
        // the factory (the factory may itself call register/lookup).
        let factory_ref: &NativeFilterFactory = factory;
        // The factory borrows the map's value; to avoid holding the
        // read lock across a potentially slow construction, we cannot
        // clone a Box<dyn Fn>. Instead we accept the lock duration --
        // construction is expected to be cheap (parse a config string).
        // The RwLock read guard does not block other readers, only
        // writers, and register happens only at startup.
        factory_ref(config).map_err(|e| RegistryError::Construction {
            name: name.to_string(),
            error: e,
        })
    }
}

impl Default for NativeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for NativeRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names = self.names();
        f.debug_struct("NativeRegistry")
            .field("registered", &names)
            .finish()
    }
}
