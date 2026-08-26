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
//! - [`state`] — SQLite-backed durable state and schema migrations
//! - [`security`] — TLS, authentication, authorization
//! - [`resilience`] — passive/active health, retries, circuit breaker
//! - [`dataplane`] — the reverse-proxy request path and its upstreams
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
//! | `snapshot` | `config` |
//! | `observability` | (nothing) |
//! | `state` | `config` |
//! | `security` | `config`, `state`, `observability` |
//! | `resilience` | `config`, `snapshot`, `extensions`, `observability` |
//! | `dataplane` | all of the above |
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
//! same module. Prefer the domain-qualified path in new code.
//!
//! Future work: mark the root-level compatibility aliases
//! `#[doc(hidden)]` and/or fold item-level re-exports into this facade
//! once downstream consumers have migrated to the domain-qualified paths.
//! Deferred in this pass so intra-doc links and existing doc references
//! keep resolving throughout the move.

pub mod config;
pub mod dataplane;
pub mod extensions;
pub mod observability;
pub mod resilience;
pub mod security;
pub mod snapshot;
pub mod state;

// Path-compatibility aliases: these re-exports keep the historical
// top-level module paths (`dwara_core::proxy`, `dwara_core::tls`, ...)
// resolving after the move into domain directories. See "Path
// compatibility" above.
pub use dataplane::balance;
pub use dataplane::hardening;
pub use dataplane::proxy;
pub use dataplane::upstream;
pub use resilience::active;
pub use resilience::breaker;
pub use resilience::health;
pub use resilience::retries;
pub use security::authn;
pub use security::authz;
pub use security::tls;
pub use state::migrations;
pub use state::store;
