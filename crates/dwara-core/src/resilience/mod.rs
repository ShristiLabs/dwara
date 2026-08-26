//! Resilience bounded context: keeping upstream traffic alive and shed.
//!
//! Passive health/outlier detection ([`health`]), retry parameters and
//! budgets ([`retries`]), and the per-upstream circuit breaker
//! ([`breaker`]). Active health probing lives in the dataplane domain
//! (`dataplane::active`) — it drives the upstream registry's balancer
//! trackers, which is dataplane lifecycle. May depend on config, snapshot,
//! extensions, and observability.

pub mod breaker;
pub mod health;
pub mod retries;
