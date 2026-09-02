//! Resilience bounded context: keeping upstream traffic alive and shed.
//!
//! Passive health/outlier detection ([`health`]), retry parameters and
//! budgets ([`retries`]), the per-upstream circuit breaker
//! ([`breaker`]), and adaptive + origin-driven rate-limit tuning
//! ([`adaptive`], DW-089). Active health probing lives in the dataplane
//! domain (`dataplane::active`) — it drives the upstream registry's
//! balancer trackers, which is dataplane lifecycle. May depend on
//! config, snapshot, extensions, observability, and events.

pub mod adaptive;
pub mod breaker;
pub mod health;
pub mod retries;
