//! io_uring engine experiment for dwara (DW-096).
//!
//! This crate is an EXPERIMENT SCAFFOLD -- it defines the
//! engine-selection trait and documents the integration point for a
//! future io_uring-backed runtime, but links no io_uring runtime. See
//! [`docs/adr/0003-io-uring-engine.md`] for the decision (defer
//! adoption; tokio remains the default and only engine).
//!
//! Linux-only: io_uring requires Linux 5.1+. This crate is excluded
//! from the default workspace build and CI matrix.
//!
//! # Integration point
//!
//! The dataplane boundary in `crates/dwara-bin/src/listeners.rs` selects
//! the async runtime at startup. Today the only engine is tokio. When
//! this experiment advances to adoption, the selection becomes:
//!
//! 1. An env/build knob (`DWARA_ENGINE=tokio|uring`) read at startup,
//!    not a config-schema field (per the issue's implementation notes:
//!    "no schema change").
//! 2. A `uring` cargo feature on `dwara-bin` that links `monoio` under
//!    a `cfg(target_os = "linux")` gate.
//! 3. An [`EngineAdapter`] impl backed by monoio's thread-per-core
//!    runtime, sitting alongside the tokio adapter.
//!
//! The trait-based boundary keeps the core dataplane (hyper, the proxy,
//! the upstream connector) runtime-agnostic at the type level; the
//! adapter is the seam where the runtime choice is made.

/// The async runtime engine the gateway runs on.
///
/// Today only [`Engine::Tokio`] is implemented. [`Engine::IoUring`] is
/// reserved for the future io_uring-backed engine (monoio); it is not
/// wired and selecting it at startup is a no-op that falls back to
/// tokio with a warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// The tokio multi-threaded runtime (the default and only
    /// implemented engine). Portable across Linux, macOS, Windows.
    Tokio,
    /// The monoio thread-per-core io_uring runtime (Linux 5.1+).
    /// Reserved for future adoption; not implemented today. See
    /// ADR-0003 for the deferral rationale.
    IoUring,
}

impl Default for Engine {
    fn default() -> Self {
        Engine::Tokio
    }
}

impl Engine {
    /// Parse an engine name from an env-var value (case-insensitive).
    /// Unknown values fall back to [`Engine::Tokio`] (the safe default)
    /// rather than erroring, so a typo never prevents the gateway from
    /// starting.
    pub fn from_env_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "tokio" => Engine::Tokio,
            "uring" | "io_uring" | "iouring" => Engine::IoUring,
            _ => Engine::Tokio,
        }
    }

    /// Whether this engine is available on the current platform.
    /// io_uring is Linux-only; tokio is always available.
    pub fn is_available(&self) -> bool {
        match self {
            Engine::Tokio => true,
            Engine::IoUring => cfg!(target_os = "linux"),
        }
    }
}

/// The adapter trait an async runtime implements so the dataplane
/// boundary can select an engine at startup.
///
/// The adapter owns the runtime's lifecycle: it builds the runtime,
/// drives the listener accept loops, and shuts down gracefully. The
/// core dataplane (hyper, the proxy, the upstream connector) is
/// runtime-agnostic at the type level; the adapter is the seam where
/// the runtime choice is made.
///
/// Today only the tokio adapter exists (in `dwara-bin`, not here). A
/// future monoio adapter would implement this trait behind the `uring`
/// feature.
pub trait EngineAdapter: Send + Sync + 'static {
    /// The engine this adapter wraps.
    fn engine(&self) -> Engine;

    /// Run the gateway on this engine until shutdown is requested.
    /// Returns Ok(()) on clean shutdown, Err on a fatal runtime error.
    fn run(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), EngineError>> + Send + 'static>>;
}

/// An error from the engine adapter (runtime startup or shutdown
/// failure).
#[derive(Debug, Clone)]
pub enum EngineError {
    /// The selected engine is not available on this platform (e.g.
    /// io_uring on macOS).
    Unavailable {
        engine: Engine,
        reason: String,
    },
    /// The runtime failed to start (e.g. io_uring setup failed because
        /// the kernel is too old).
    StartupFailed {
        engine: Engine,
        reason: String,
    },
    /// The runtime failed during operation.
    RuntimeError {
        engine: Engine,
        reason: String,
    },
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Unavailable { engine, reason } => {
                write!(f, "engine {engine:?} unavailable: {reason}")
            }
            EngineError::StartupFailed { engine, reason } => {
                write!(f, "engine {engine:?} startup failed: {reason}")
            }
            EngineError::RuntimeError { engine, reason } => {
                write!(f, "engine {engine:?} runtime error: {reason}")
            }
        }
    }
}

impl std::error::Error for EngineError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_tokio() {
        assert_eq!(Engine::default(), Engine::Tokio);
    }

    #[test]
    fn from_env_str_tokio() {
        assert_eq!(Engine::from_env_str("tokio"), Engine::Tokio);
        assert_eq!(Engine::from_env_str("TOKIO"), Engine::Tokio);
        assert_eq!(Engine::from_env_str("Tokio"), Engine::Tokio);
    }

    #[test]
    fn from_env_str_uring() {
        assert_eq!(Engine::from_env_str("uring"), Engine::IoUring);
        assert_eq!(Engine::from_env_str("io_uring"), Engine::IoUring);
        assert_eq!(Engine::from_env_str("IO_URING"), Engine::IoUring);
        assert_eq!(Engine::from_env_str("iouring"), Engine::IoUring);
    }

    #[test]
    fn from_env_str_unknown_falls_back_to_tokio() {
        assert_eq!(Engine::from_env_str("monoio"), Engine::Tokio);
        assert_eq!(Engine::from_env_str(""), Engine::Tokio);
        assert_eq!(Engine::from_env_str("garbage"), Engine::Tokio);
    }

    #[test]
    fn tokio_always_available() {
        assert!(Engine::Tokio.is_available());
    }

    #[test]
    fn iouring_available_only_on_linux() {
        assert_eq!(
            Engine::IoUring.is_available(),
            cfg!(target_os = "linux")
        );
    }
}
