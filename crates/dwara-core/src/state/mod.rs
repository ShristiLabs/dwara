//! State bounded context: durable gateway state.
//!
//! The SQLite-backed state store with its in-memory hot cache
//! ([`store`]), the versioned, transactional schema migrations that
//! gate store open ([`migrations`]), and the consumer request-budget
//! policy over the store's quota counters ([`quotas`], DW-033). May
//! depend on config.

pub mod migrations;
pub mod quotas;
pub mod store;
