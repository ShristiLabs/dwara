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
        let text = std::fs::read_to_string(&self.path)
            .map_err(|e| ExtensionsError::Io(format!("{}: {e}", self.path.display())))?;
        parse_gateway(&text).map_err(|e| ExtensionsError::Invalid(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loads_gateway_from_yaml_file() {
        let dir = std::env::temp_dir().join("dwara-dw004-config-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("gw.yaml");
        std::fs::write(&path, "listeners: []\n").unwrap();
        let source = FileConfigSource::new(&path);
        let gateway = source.load().await.unwrap();
        assert!(gateway.listeners.is_empty());
    }

    const VALID_MINIMAL_YAML: &str = include_str!("../../tests/fixtures/valid_minimal.yaml");
    const INVALID_UNKNOWN_FIELD_YAML: &str =
        include_str!("../../tests/fixtures/invalid_unknown_field.yaml");

    fn unique_temp_file(name: &str) -> std::path::PathBuf {
        let unique = format!(
            "dwara-dw004-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::env::temp_dir().join(unique)
    }

    #[tokio::test]
    async fn loads_minimal_fixture_gateway_from_yaml_file() {
        let path = unique_temp_file("valid.yaml");
        std::fs::write(&path, VALID_MINIMAL_YAML).unwrap();
        let source = FileConfigSource::new(&path);
        let gateway = source.load().await;
        std::fs::remove_file(&path).ok();
        let gateway = gateway.unwrap();
        assert_eq!(
            gateway.listeners.len(),
            1,
            "minimal fixture has one listener"
        );
        assert_eq!(gateway.listeners[0].name, "main");
    }

    #[tokio::test]
    async fn nonexistent_path_maps_to_io_error_carrying_path() {
        let path = unique_temp_file("missing.yaml");
        let err = FileConfigSource::new(&path).load().await.unwrap_err();
        std::fs::remove_file(&path).ok();
        assert!(
            matches!(err, ExtensionsError::Io(ref m) if m.contains(&path.display().to_string())),
            "expected Io variant carrying the path, got: {err}"
        );
    }

    #[tokio::test]
    async fn invalid_yaml_maps_to_invalid_error_with_parse_detail() {
        let path = unique_temp_file("invalid.yaml");
        std::fs::write(&path, INVALID_UNKNOWN_FIELD_YAML).unwrap();
        let err = FileConfigSource::new(&path).load().await.unwrap_err();
        std::fs::remove_file(&path).ok();
        match err {
            ExtensionsError::Invalid(m) => assert!(
                m.contains("unknown field") || m.contains("protocool"),
                "message should carry the parse detail, got: {m}"
            ),
            other => panic!("expected Invalid variant, got: {other}"),
        }
    }
}
