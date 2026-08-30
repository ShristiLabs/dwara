//! Gateway core: the shared config model, routing types, swappable trait
//! definitions, listener/TLS machinery, and dataplane assembly consumed by
//! the bin/admin/cli crates.
//!
//! # Organization
//!
//! This crate is organized as a set of domain directories (bounded
//! contexts) behind this facade:
//!
//! - [`config`] — configuration schema and the `parse_gateway` entry point
//! - [`extensions`] — the OSS/Ent edition boundary as a type boundary
//! - [`snapshot`] — the config compile pipeline (validate -> compile -> publish)
//! - [`observability`] — tracing, metrics, and access logging
//! - [`events`] — the in-process event bus and webhook delivery (DW-044)
//! - [`state`] — SQLite-backed durable state and schema migrations
//! - [`security`] — TLS, authentication, authorization
//! - [`resilience`] — passive health, retries, circuit breaker
//! - [`dataplane`] — the reverse-proxy request path, its upstreams, and
//!   active health probing
//! - [`supervision`] — bounded panic-respawn supervision for accept
//!   loops, shared by the bin and admin accept surfaces
//! - [`error`] — the facade-level aggregate [`error::Error`] over the
//!   domain error types, for boundary propagation
//!
//! # Dependency direction
//!
//! Dependencies point downward only; a domain may never be depended on by
//! a domain above it:
//!
//! | Domain | May depend on |
//! |---|---|
//! | `config` | (nothing) |
//! | `extensions` | `config` |
//! | `observability` | (nothing) |
//! | `events` | `config`, `observability` |
//! | `snapshot` | `config`, `events` |
//! | `state` | `config` |
//! | `security` | `config`, `state`, `observability` |
//! | `resilience` | `config`, `snapshot`, `extensions`, `observability`, `events` |
//! | `dataplane` | all of the above |
//! | `supervision` | (nothing — pure task plumbing, no domain imports) |
//!
//! (`dwara-bin`, `dwara-admin`, and `dwara-cli` depend on this crate.)
//!
//! # Path compatibility
//!
//! The modules were originally flat at the crate root. To keep every
//! pre-restructure path (e.g. `dwara_core::proxy::handle`,
//! `dwara_core::config::parse_gateway`, `dwara_core::tls`) compiling
//! unchanged, the crate root re-exports each moved module as a path alias:
//! `dwara_core::proxy` and `dwara_core::dataplane::proxy` (and likewise
//! for `upstream`, `balance`, `hardening`, `health`, `active`, `retries`,
//! `breaker`, `tls`, `authn`, `authz`, `store`, `migrations`) denote the
//! same module. The aliases are `#[doc(hidden)]`: they still compile but
//! stay out of the rendered docs. Use the domain-qualified path in new
//! code (`dwara_core::dataplane::proxy`, `dwara_core::security::tls`).

pub mod analytics;
pub mod config;
pub mod dataplane;
pub mod error;
pub mod events;
pub mod extensions;
pub mod observability;
pub mod resilience;
pub mod security;
pub mod snapshot;
pub mod state;
pub mod supervision;

// Path-compatibility aliases: these re-exports keep the historical
// top-level module paths (`dwara_core::proxy`, `dwara_core::tls`, ...)
// resolving after the move into domain directories. They are hidden
// from docs so new code gravitates to the canonical domain paths. See
// "Path compatibility" above.
#[doc(hidden)]
pub use dataplane::active;
#[doc(hidden)]
pub use dataplane::balance;
#[doc(hidden)]
pub use dataplane::hardening;
#[doc(hidden)]
pub use dataplane::proxy;
#[doc(hidden)]
pub use dataplane::upstream;
#[doc(hidden)]
pub use resilience::breaker;
#[doc(hidden)]
pub use resilience::health;
#[doc(hidden)]
pub use resilience::retries;
#[doc(hidden)]
pub use security::authn;
#[doc(hidden)]
pub use security::authz;
#[doc(hidden)]
pub use security::tls;
#[doc(hidden)]
pub use state::migrations;
#[doc(hidden)]
pub use state::store;
