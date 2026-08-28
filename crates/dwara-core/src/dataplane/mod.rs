//! Dataplane bounded context: the request-serving path.
//!
//! Assembles the reverse-proxy core ([`proxy`]), pooled upstream clients
//! ([`upstream`]), per-upstream load balancing ([`balance`]), active
//! health probing ([`active`] — it drives the upstream registry's
//! balancer trackers, which is dataplane lifecycle), the protocol
//! hardening applied to every serving surface ([`hardening`], plus the
//! route-scoped request limits of DW-027), the route-scoped response
//! edge policies of DW-027 ([`cors`], [`compression`]), and the API
//! versioning aids of DW-048 ([`versioning`]). This is the top
//! of the core dependency graph: it may depend on every other domain;
//! nothing depends on it.

pub mod active;
pub mod balance;
pub mod compression;
pub mod cors;
pub mod hardening;
pub mod proxy;
pub mod upstream;
pub mod versioning;
