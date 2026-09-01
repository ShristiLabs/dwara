//! Facade-level aggregate error.
//!
//! Each domain owns a typed error describing the failures it knows how
//! to express. This module adds [`Error`]: a single non-exhaustive enum
//! over those domain errors, so the bin/admin/cli crates (and future API
//! surfaces) get one match surface at their boundaries instead of eight.
//!
//! The domains keep their typed errors — a call site that can recover
//! from a specific failure should keep matching the domain error (a
//! quota-aware path matches [`StoreError::QuotaExceeded`], a retry
//! decision matches [`UpstreamError::ConnectTimeout`]). [`Error`] is for
//! boundary propagation, where the remaining actions are to log, report,
//! or terminate: the bin/admin entry points and future API surfaces. The
//! conversion is lossless — [`From`] wraps the domain error unchanged,
//! [`Display`](std::fmt::Display) forwards its message, and
//! [`source`](std::error::Error::source) returns the inner error, so
//! error chains and `downcast_ref` on that `&dyn Error` keep working.
//!
//! # Example
//!
//! ```
//! use dwara_core::error::Error;
//! use dwara_core::security::tls::TlsError;
//!
//! let e: Error = TlsError::NoCertificates.into();
//! assert!(matches!(e, Error::Tls(_)));
//! // Display delegates to the domain error's message verbatim:
//! assert_eq!(e.to_string(), "tls terminate block has no certificate material");
//! // and source() yields the inner error for chains/downcasting:
//! assert!(std::error::Error::source(&e).is_some());
//! ```

use crate::ai::adapter::AiError;
use crate::dataplane::hardening::InboundBodyError;
use crate::dataplane::upstream::{UpstreamBodyError, UpstreamError};
use crate::extensions::ExtensionsError;
use crate::security::authn::AuthError;
use crate::security::tls::TlsError;
use crate::snapshot::CompileError;
use crate::state::store::StoreError;

/// The facade-level aggregate over the domain errors: one type to
/// propagate across crate boundaries (bin/admin entry points, future API
/// surfaces). See the [module docs](self) for when to match a domain
/// error instead.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Config compile pipeline failure (validate/compile).
    Compile(CompileError),
    /// TLS material load/build/reload failure.
    Tls(TlsError),
    /// Durable state store failure.
    Store(StoreError),
    /// Upstream request failure (dial, handshake, headers).
    Upstream(UpstreamError),
    /// Upstream streamed response-body failure.
    UpstreamBody(UpstreamBodyError),
    /// Inbound request-body wrapper failure.
    InboundBody(InboundBodyError),
    /// Authentication failure.
    Auth(AuthError),
    /// Extension subsystem failure.
    Extensions(ExtensionsError),
    /// AI domain failure (request translation or provider error, DW-075).
    Ai(AiError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Delegates verbatim: the domain errors already carry their
        // context, and the wrapped error stays reachable via source().
        match self {
            Error::Compile(e) => e.fmt(f),
            Error::Tls(e) => e.fmt(f),
            Error::Store(e) => e.fmt(f),
            Error::Upstream(e) => e.fmt(f),
            Error::UpstreamBody(e) => e.fmt(f),
            Error::InboundBody(e) => e.fmt(f),
            Error::Auth(e) => e.fmt(f),
            Error::Extensions(e) => e.fmt(f),
            Error::Ai(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Compile(e) => Some(e),
            Error::Tls(e) => Some(e),
            Error::Store(e) => Some(e),
            Error::Upstream(e) => Some(e),
            Error::UpstreamBody(e) => Some(e),
            Error::InboundBody(e) => Some(e),
            Error::Auth(e) => Some(e),
            Error::Extensions(e) => Some(e),
            Error::Ai(e) => Some(e),
        }
    }
}

impl From<CompileError> for Error {
    fn from(e: CompileError) -> Self {
        Error::Compile(e)
    }
}

impl From<TlsError> for Error {
    fn from(e: TlsError) -> Self {
        Error::Tls(e)
    }
}

impl From<StoreError> for Error {
    fn from(e: StoreError) -> Self {
        Error::Store(e)
    }
}

impl From<UpstreamError> for Error {
    fn from(e: UpstreamError) -> Self {
        Error::Upstream(e)
    }
}

impl From<UpstreamBodyError> for Error {
    fn from(e: UpstreamBodyError) -> Self {
        Error::UpstreamBody(e)
    }
}

impl From<InboundBodyError> for Error {
    fn from(e: InboundBodyError) -> Self {
        Error::InboundBody(e)
    }
}

impl From<AuthError> for Error {
    fn from(e: AuthError) -> Self {
        Error::Auth(e)
    }
}

impl From<ExtensionsError> for Error {
    fn from(e: ExtensionsError) -> Self {
        Error::Extensions(e)
    }
}

impl From<AiError> for Error {
    fn from(e: AiError) -> Self {
        Error::Ai(e)
    }
}
// retrigger CI after a lost push event (path-filtered workflows
// need a real file change; empty commits do not qualify).
