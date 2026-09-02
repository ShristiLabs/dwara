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
//! - [`resilience`] — passive health, retries, circuit breaker,
//!   adaptive + origin-driven rate-limit tuning (DW-089)
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
//! | `analytics` | `config`, `observability`, `extensions` |
//! | `security` | `config`, `state`, `observability` |
//! | `resilience` | `config`, `snapshot`, `extensions`, `observability`, `events` |
//! | `plugins` | `config` (native filter trait + unified dispatch chain;
//!   the `wasm` domain bridges its instances in via a generic adapter,
//!   so `plugins` never imports `wasm` — see DW-119) |
//! | `ai` | `config` (provider-adapter pack, DW-075: the canonical chat
//!   vocabulary, the pure-translation [`ai::adapter::ProviderAdapter`]
//!   seam, and the compiled alias table; the transport lives in
//!   `dataplane`, which calls into it) |
//! | `lifecycle` | `config`, `observability`, `analytics` (DW-110: API
//!   lifecycle management -- developer portal, environment profiles,
//!   API journey recorder; feature-gated behind `api_lifecycle`) |
//! | `mesh` | `config`, `observability` (DW-107: service mesh mode --
//!   sidecar traffic interception + SPIFFE/SPIRE mTLS identity; the
//!   mTLS TLS integration point is a documented seam into `security`,
//!   kept as a hand-off so the dependency direction stays downward;
//!   feature-gated behind `mesh`, Ent-only) |
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

pub mod ai;
pub mod analytics;
// DW-058: CEL engine. Feature-gated behind the `cel` cargo feature
// (default OFF) because cel-interpreter adds binary size.
#[cfg(feature = "cel")]
pub mod cel;
pub mod config;
pub mod dataplane;
pub mod error;
pub mod events;
pub mod extensions;
pub mod observability;
// DW-119: native plugin filter trait + unified dispatch chain.
// Feature-gated behind the `plugins` cargo feature (default OFF)
// because it is the compile-in extension path (compiled-in Rust
// filters); the proxy-wasm host (DW-055) is the portable ABI path.
#[cfg(feature = "plugins")]
pub mod plugins;
// DW-070: OpenAPI response validation. Feature-gated behind the
// `openapi_validation` cargo feature (default OFF).
#[cfg(feature = "openapi_validation")]
pub mod openapi;
pub mod resilience;
pub mod security;
pub mod snapshot;
pub mod state;
pub mod supervision;
// DW-071: Synthetic monitoring. Built-in probes per route that
// measure latency and uptime, feeding results into analytics and
// webhooks.
pub mod synthetic;
// DW-061: API aggregation plugin pack. Feature-gated behind the
// `aggregation` cargo feature (default OFF).
#[cfg(feature = "aggregation")]
pub mod aggregation;
// DW-112: Agent-operable administration via MCP. Feature-gated
// behind the `mcp` cargo feature (default OFF).
#[cfg(feature = "mcp")]
pub mod mcp;
// DW-067: Workspaces + RBAC + audit (Enterprise). Feature-gated
// behind the `ent` cargo feature (default OFF).
#[cfg(feature = "ent")]
pub mod workspace;
// DW-066: CP/DP split (Enterprise). Feature-gated behind the `ent`
// cargo feature (default OFF).
#[cfg(feature = "ent")]
pub mod cp_dp;
// DW-064: Kubernetes Gateway API translator. Feature-gated behind
// the `k8s` cargo feature (default OFF).
#[cfg(feature = "k8s")]
pub mod k8s_gateway;
// DW-055: proxy-wasm host. Feature-gated behind the `wasm` cargo
// feature (default OFF) because wasmtime + cranelift are significant
// binary size against the DW-026 25MB budget.
#[cfg(feature = "wasm")]
pub mod wasm;
// DW-107: Service mesh mode (sidecar + SPIFFE/SPIRE mTLS identity).
// Feature-gated behind the `mesh` cargo feature (default OFF). The
// sidecar controller and SPIFFE Workload API client are SCAFFOLDED
// (documented no-ops); the `spiffe` crate would be added when
// production-ready. Ent-only.
#[cfg(feature = "mesh")]
pub mod mesh;
// DW-110: API lifecycle management (developer portal, environment
// profiles, API journey recorder). Feature-gated behind the
// `api_lifecycle` cargo feature (default OFF, flag-only). The config
// schema (the top-level `lifecycle` block) is always present so configs
// round-trip without the feature; when the feature is off the block is
// accepted but inert (validation warns).
#[cfg(feature = "api_lifecycle")]
pub mod lifecycle;

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
pub use resilience::adaptive;
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
pub use security::fips;
#[doc(hidden)]
pub use security::oidc;
#[doc(hidden)]
pub use security::pq;
#[doc(hidden)]
pub use security::tls;
#[doc(hidden)]
pub use state::migrations;
#[doc(hidden)]
pub use state::store;
