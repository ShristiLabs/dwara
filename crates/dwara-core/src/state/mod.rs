//! State bounded context: durable gateway state.
//!
//! The SQLite-backed state store with its in-memory hot cache
//! ([`store`]) and the versioned, transactional schema migrations that
//! gate store open ([`migrations`]). May depend on config.

pub mod migrations;
pub mod store;
