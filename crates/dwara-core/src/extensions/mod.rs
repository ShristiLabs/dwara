//! Extension points: the OSS/Ent edition boundary as a type boundary (DW-004).
//!
//! dwara is open-core. The five traits in this module ([`rate_limiter::RateLimiter`],
//! [`config_source::ConfigSource`], [`cache::CacheStore`],
//! [`analytics::AnalyticsSink`], [`secrets::SecretSource`]) are the swappable
//! state backend contracts. The OSS edition ships the local in-memory /
//! file / env implementations that live alongside each trait; additional
//! backends may be provided separately in future editions and must
//! implement the same traits and slot in
//! via `dyn` injection WITHOUT changing trait signatures or call sites.
//!
//! Because every trait is used as `Arc<dyn Trait>` at runtime, all of them
//! are dyn-compatible (object safe). They are `async` via the `async-trait`
//! crate: native RPITIT is not yet dyn-compatible on stable Rust, and
//! dyn-compatibility is the load-bearing requirement here.
//!
//! # Failure model
//!
//! All trait methods share one error type, [`ExtensionsError`]. It is
//! non-exhaustive and carries a human-readable message; the variants map to
//! failure classes (I/O, invalid data, backend failure) rather than to
//! per-trait taxonomies, so a new backend can express its failures without
//! a breaking change to the shared enum. Transient-vs-permanent and retry
//! expectations are documented per trait.

pub mod analytics;
pub mod cache;
pub mod config_source;
pub mod rate_limiter;
pub mod secrets;

/// Shared error type for all extension traits.
///
/// Non-exhaustive by design: Ent backends may surface new failure classes
/// via [`ExtensionsError::Backend`] rather than new variants.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtensionsError {
    /// The backing store or file could not be read/written.
    Io(String),
    /// Input or stored data was malformed (e.g. config parse failure).
    Invalid(String),
    /// The backend itself failed (connection lost, sealed, ...).
    Backend(String),
    /// The operation is not supported by this implementation.
    Unsupported(String),
}

impl std::fmt::Display for ExtensionsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtensionsError::Io(m) => write!(f, "extension io error: {m}"),
            ExtensionsError::Invalid(m) => write!(f, "extension invalid-data error: {m}"),
            ExtensionsError::Backend(m) => write!(f, "extension backend error: {m}"),
            ExtensionsError::Unsupported(m) => write!(f, "extension unsupported operation: {m}"),
        }
    }
}

impl std::error::Error for ExtensionsError {}
