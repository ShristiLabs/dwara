//! Resilience bounded context: keeping upstream traffic alive and shed.
//!
//! Passive health/outlier detection ([`health`]), active probing
//! ([`active`]), retry parameters and budgets ([`retries`]), and the
//! per-upstream circuit breaker ([`breaker`]). May depend on config,
//! snapshot, extensions, and observability.

pub mod active;
pub mod breaker;
pub mod health;
pub mod retries;
