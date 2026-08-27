//! Configuration source extension point.
//!
//! # Contract: [`ConfigSource`]
//!
//! **Purpose:** produce the current [`Gateway`] configuration on demand.
//!
//! **Semantics:** `load` is a full read of the current configuration
//! generation. It may be called on startup, on demand, and (once DW-006
//! lands) whenever the source signals a change. Implementations should be
//! cheap to call repeatedly but need not cache. `load` is not expected to
//! run on the request hot path.
//!
//! **Watch contract (documented, NOT implemented here — DW-006):** an
//! OSS file-watch source will notify the runtime on file change; the trait
//! deliberately keeps `load` pull-only so watch mechanics (tokio watch
//! channel, notify crate) can be layered by the consumer without a
//! signature change. Future revisions may add an optional `subscribe`
//! method with a default no-op implementation, which is backward compatible.
//!
//! **Failure model:** unreadable source maps to [`ExtensionsError::Io`];
//! malformed configuration maps to [`ExtensionsError::Invalid`] (wrapping
//! the path-precise [`crate::config::ConfigError`] message). No retries.
//!
//! **Editions:** OSS ships [`FileConfigSource`] (single YAML file).
//! Additional remote/control-plane sources may be provided separately in
//! future editions.

use async_trait::async_trait;

use crate::config::{parse_gateway, Gateway};

use super::ExtensionsError;

/// Swappable configuration origin.
#[async_trait]
pub trait ConfigSource: Send + Sync {
    /// Load the current configuration generation.
    async fn load(&self) -> Result<Gateway, ExtensionsError>;
}

/// Single-file YAML configuration source (OSS).
#[derive(Debug, Clone)]
pub struct FileConfigSource {
    path: std::path::PathBuf,
}

impl FileConfigSource {
    /// Source reading configuration from `path` on each [`ConfigSource::load`].
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[async_trait]
impl ConfigSource for FileConfigSource {
    async fn load(&self) -> Result<Gateway, ExtensionsError> {
        // The io site keeps the file path (context the blanket
        // From<std::io::Error> cannot provide); the config site uses the
        // From<ConfigError> conversion (#128) — ConfigError's Display is
        // already path-precise.
        let text = std::fs::read_to_string(&self.path)
            .map_err(|e| ExtensionsError::Io(format!("{}: {e}", self.path.display())))?;
        parse_gateway(&text).map_err(ExtensionsError::from)
    }
}
