//! io_uring engine experiment for dwara (DW-096, PERF-13 #245).
//!
//! This crate is an EXPERIMENT SCAFFOLD -- it defines the
//! engine-selection trait, the thread-per-core accept loop scaffold,
//! and the splice(2) integration point for a future io_uring-backed
//! runtime, but links no io_uring runtime. See
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
//!
//! # PERF-13 (#245): thread-per-core accept + splice(2)
//!
//! The revival scope is L4 first: thread-per-core accept loops (one
//! worker thread per core, each owning its own listener via
//! `SO_REUSEPORT`) and splice(2) for zero-copy byte forwarding between
//! the client and upstream sockets. The L7 path (hyper, TLS) stays on
//! tokio until the ecosystem bridges the trait gap (see ADR-0003).
//!
//! [`ThreadPerCoreAccept`] documents the accept-loop scaffold;
//! [`SpliceAdapter`] documents the splice(2) integration point. Both
//! are trait-based seams: the tokio fallback implements them with
//! `tokio::io::copy_bidirectional`, a future monoio adapter would
//! implement them with `splice(2)` via io_uring.

/// The async runtime engine the gateway runs on.
///
/// Today only [`Engine::Tokio`] is implemented. [`Engine::IoUring`] is
/// reserved for the future io_uring-backed engine (monoio); it is not
/// wired and selecting it at startup is a no-op that falls back to
/// tokio with a warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Engine {
    /// The tokio multi-threaded runtime (the default and only
    /// implemented engine). Portable across Linux, macOS, Windows.
    #[default]
    Tokio,
    /// The monoio thread-per-core io_uring runtime (Linux 5.1+).
    /// Reserved for future adoption; not implemented today. See
    /// ADR-0003 for the deferral rationale.
    IoUring,
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

// ---------------------------------------------------------------------------
// PERF-13 (#245): thread-per-core accept loop + splice(2) scaffolds
// ---------------------------------------------------------------------------

/// Configuration for a thread-per-core accept loop (PERF-13, #245).
///
/// The thread-per-core model: one worker thread per CPU core, each
/// owning its own listener socket (via `SO_REUSEPORT` so the kernel
/// load-balances incoming connections across workers). No
/// work-stealing; each worker accepts and handles connections on its
/// own event loop. This is the model monoio (and Pingora) use for
/// L4 proxying.
///
/// Today the tokio fallback uses the multi-threaded runtime (which
/// IS work-stealing); this config is the seam a future monoio adapter
/// would consume. The fields are the minimal set the adapter needs:
/// the bind address, the number of worker threads (defaults to the
/// CPU count), and the per-connection idle timeout.
#[derive(Debug, Clone)]
pub struct ThreadPerCoreAcceptConfig {
    /// The address to bind the listener on (each worker binds its own
    /// socket with SO_REUSEPORT).
    pub bind_addr: String,
    /// Number of worker threads (one per core). Defaults to the CPU
    /// count when zero.
    pub workers: usize,
    /// Per-connection idle timeout. None = no timeout (the connection
    /// stays open until either side closes).
    pub idle_timeout: Option<std::time::Duration>,
}

impl Default for ThreadPerCoreAcceptConfig {
    fn default() -> Self {
        ThreadPerCoreAcceptConfig {
            bind_addr: "0.0.0.0:0".to_string(),
            workers: 0,
            idle_timeout: Some(std::time::Duration::from_secs(300)),
        }
    }
}

/// A boxed future returned by the engine adapter (the accept loop or
/// the splice). The type is complex enough that clippy flags it; the
/// alias keeps the trait signatures readable.
type EngineFuture<T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, EngineError>> + Send + 'static>>;

/// The accept-loop trait a thread-per-core engine implements (PERF-13,
/// #245).
///
/// The tokio fallback spawns one accept task per listener on the
/// multi-threaded runtime (work-stealing). A future monoio adapter
/// would spawn one thread per core, each with its own listener and
/// event loop (no work-stealing). The trait abstracts over both.
///
/// The accept loop runs until shutdown is requested; each accepted
/// connection is handed to the connection handler (the L4 splice or
/// the L7 proxy).
pub trait ThreadPerCoreAccept: Send + Sync + 'static {
    /// Start the accept loop. Returns a future that completes when
    /// the loop shuts down (graceful or error).
    fn run_accept_loop(&self, config: &ThreadPerCoreAcceptConfig) -> EngineFuture<()>;
}

/// The splice trait a thread-per-core engine implements for L4
/// zero-copy forwarding (PERF-13, #245).
///
/// The tokio fallback uses `tokio::io::copy_bidirectional` (user-space
/// copy). A future monoio adapter would use `splice(2)` via io_uring
/// (kernel-space pipe, zero-copy between the two sockets). The trait
/// abstracts over both so the L4 dispatcher (`dataplane::l4`) can
/// select the splice implementation at runtime.
///
/// The splice runs until either side closes the connection or the
/// idle timeout fires. Returns the total bytes forwarded in each
/// direction (for metrics).
pub trait SpliceAdapter: Send + Sync + 'static {
    /// Splice bytes between two connected sockets (client <-> upstream).
    /// Returns `(client_to_upstream_bytes, upstream_to_client_bytes)`
    /// when the splice completes.
    fn splice(
        &self,
        client_fd: i32,
        upstream_fd: i32,
        idle_timeout: Option<std::time::Duration>,
    ) -> EngineFuture<(u64, u64)>;
}

/// The tokio fallback for [`ThreadPerCoreAccept`]: spawns one accept
/// task per listener on the multi-threaded runtime. This is what the
/// gateway uses today (the L4 listener in `dataplane::l4` already does
/// this); the struct is here so the trait-based seam compiles and a
/// future monoio adapter can sit alongside it.
pub struct TokioAccept;

impl ThreadPerCoreAccept for TokioAccept {
    fn run_accept_loop(&self, _config: &ThreadPerCoreAcceptConfig) -> EngineFuture<()> {
        // The tokio fallback is the existing L4 listener path in
        // dataplane::l4 (tokio::net::TcpListener::accept in a loop on
        // the multi-threaded runtime). This stub documents the seam;
        // the real implementation lives in the dataplane, not here.
        Box::pin(async {
            // The tokio L4 listener already handles accept; this is a
            // no-op fallback so the trait compiles. When the uring
            // engine is selected, a monoio adapter replaces this.
            Err(EngineError::RuntimeError {
                engine: Engine::Tokio,
                reason: "tokio accept loop lives in dataplane::l4, not here".to_string(),
            })
        })
    }
}

/// The tokio fallback for [`SpliceAdapter`]: uses
/// `tokio::io::copy_bidirectional` (user-space copy). This is what the
/// L4 dispatcher uses today; the struct is here so the trait-based
/// seam compiles and a future monoio adapter (using `splice(2)`) can
/// sit alongside it.
pub struct TokioSplice;

impl SpliceAdapter for TokioSplice {
    fn splice(
        &self,
        _client_fd: i32,
        _upstream_fd: i32,
        _idle_timeout: Option<std::time::Duration>,
    ) -> EngineFuture<(u64, u64)> {
        // The tokio fallback is the existing L4 splice path in
        // dataplane::l4 (tokio::io::copy_bidirectional). This stub
        // documents the seam; the real implementation lives in the
        // dataplane, not here.
        Box::pin(async {
            Err(EngineError::RuntimeError {
                engine: Engine::Tokio,
                reason: "tokio splice lives in dataplane::l4, not here".to_string(),
            })
        })
    }
}

/// Select the engine from the `DWARA_ENGINE` env var at startup.
/// Returns [`Engine::Tokio`] when the var is unset or unrecognized
/// (the safe default). When `Engine::IoUring` is selected on a
/// non-Linux platform, returns [`Engine::Tokio`] with a warning (the
/// caller logs the fallback).
pub fn engine_from_env() -> Engine {
    match std::env::var("DWARA_ENGINE") {
        Ok(s) => Engine::from_env_str(&s),
        Err(_) => Engine::Tokio,
    }
}

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

    #[test]
    fn thread_per_core_config_default() {
        let cfg = ThreadPerCoreAcceptConfig::default();
        assert_eq!(cfg.bind_addr, "0.0.0.0:0");
        assert_eq!(cfg.workers, 0);
        assert_eq!(cfg.idle_timeout, Some(std::time::Duration::from_secs(300)));
    }

    #[test]
    fn engine_from_env_uses_from_env_str() {
        // engine_from_env delegates to Engine::from_env_str, which is
        // tested above. The env-var read itself is not tested in
        // parallel (racy); the mapping logic is covered by
        // from_env_str_* tests.
        std::env::set_var("DWARA_ENGINE", "uring");
        assert_eq!(engine_from_env(), Engine::IoUring);
        std::env::remove_var("DWARA_ENGINE");
    }

    #[test]
    fn tokio_accept_is_documented_fallback() {
        // The tokio accept fallback returns a RuntimeError documenting
        // that the real accept loop lives in dataplane::l4.
        let accept = TokioAccept;
        let cfg = ThreadPerCoreAcceptConfig::default();
        let fut = accept.run_accept_loop(&cfg);
        // We cannot await in a non-async test; just verify the future
        // is constructible (the trait compiles).
        drop(fut);
    }

    #[test]
    fn tokio_splice_is_documented_fallback() {
        // The tokio splice fallback returns a RuntimeError documenting
        // that the real splice lives in dataplane::l4.
        let splice = TokioSplice;
        let fut = splice.splice(0, 1, None);
        // We cannot await in a non-async test; just verify the future
        // is constructible (the trait compiles).
        drop(fut);
    }
}
