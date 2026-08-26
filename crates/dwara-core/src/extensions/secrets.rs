//! Secret source extension point.
//!
//! # Contract: [`SecretSource`]
//!
//! **Purpose:** resolve named secrets (TLS key passphrases, upstream
//! credentials, plugin tokens) at runtime without baking values into
//! configuration.
//!
//! **Semantics:** `resolve` is a single lookup, `None` meaning "this source
//! does not know this secret" (callers may chain sources). Resolution is
//! not on the request hot path for M1; implementations must never log the
//! resolved value.
//!
//! **Failure model:** a source that knows where the secret lives but cannot
//! read it (backend sealed, file unreadable) returns [`ExtensionsError::Io`]
//! or [`ExtensionsError::Backend`] — distinguishable from a plain miss
//! (`Ok(None)`). No retries.
//!
//! **Editions:** OSS ships [`EnvSecretSource`] (environment variables) and
//! [`StaticSecretSource`] (in-process map, for tests). Additional managed
//! secret-store backends may be provided separately in future editions. A
//! file-based OSS source may be added later as another impl.
//!
//! # Secret handling
//!
//! [`Secret`] wraps the value as a newtype over `String`. Its `Debug` impl
//! is redacted so values cannot leak into logs. Zeroization on drop is a
//! future hardening step; adopting the `secrecy` crate then would change
//! the wrapper's internals, not the trait.

use std::collections::HashMap;

use async_trait::async_trait;

use super::ExtensionsError;

/// A resolved secret value.
///
/// `Debug` is deliberately redacted; `Display` is not implemented.
#[derive(Clone, Default)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Expose the raw value. Callers must not log or persist it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret([{} bytes redacted])", self.0.len())
    }
}

/// Swappable secret resolution backend.
#[async_trait]
pub trait SecretSource: Send + Sync {
    /// Resolve `name`; `Ok(None)` means this source has no such secret.
    async fn resolve(&self, name: &str) -> Result<Option<Secret>, ExtensionsError>;
}

/// Environment-variable secret source (OSS): `name` maps to the identical
/// environment variable name. An unset variable is a miss (`Ok(None)`); a
/// variable that is set but not valid Unicode is reported as
/// [`ExtensionsError::Invalid`] (present but unreadable), never a silent miss.
#[derive(Debug, Clone, Default)]
pub struct EnvSecretSource;

#[async_trait]
impl SecretSource for EnvSecretSource {
    async fn resolve(&self, name: &str) -> Result<Option<Secret>, ExtensionsError> {
        match std::env::var(name) {
            Ok(value) => Ok(Some(Secret::new(value))),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(ExtensionsError::Invalid(format!(
                "environment variable {name} is set but not valid Unicode"
            ))),
        }
    }
}

/// Static in-process map of secrets, primarily for tests and examples.
#[derive(Debug, Clone, Default)]
pub struct StaticSecretSource {
    secrets: HashMap<String, String>,
}

impl StaticSecretSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the value stored under `name`.
    pub fn with(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.secrets.insert(name.into(), value.into());
        self
    }
}

#[async_trait]
impl SecretSource for StaticSecretSource {
    async fn resolve(&self, name: &str) -> Result<Option<Secret>, ExtensionsError> {
        Ok(self.secrets.get(name).cloned().map(Secret::new))
    }
}
