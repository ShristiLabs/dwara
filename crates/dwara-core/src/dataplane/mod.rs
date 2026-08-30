//! Dataplane bounded context: the request-serving path.
//!
//! Assembles the reverse-proxy core ([`proxy`]), pooled upstream clients
//! ([`upstream`], with the RFC 8305 happy-eyeballs dial of DW-030),
//! per-upstream load balancing ([`balance`]), active health probing
//! ([`active`] — it drives the upstream registry's balancer trackers,
//! which is dataplane lifecycle), the protocol hardening applied to
//! every serving surface ([`hardening`], plus the route-scoped request
//! limits of DW-027), the PROXY protocol acceptance of DW-030
//! ([`proxy_proto`]), the route-scoped response edge policies of DW-027
//! ([`cors`], [`compression`]), the API versioning aids of DW-048
//! ([`versioning`]), the request/response transforms and
//! security-header injection of DW-028 ([`transforms`]), and the local
//! response cache of DW-037 ([`response_cache`], behind the
//! `extensions::cache::CacheStore` seam). This is the top of the core
//! dependency graph: it may depend on every other domain; nothing
//! depends on it.

pub mod active;
pub mod balance;
pub mod compression;
pub mod cors;
pub mod hardening;
pub mod proxy;
pub mod proxy_proto;
pub mod response_cache;
pub mod split;
pub mod transforms;
pub mod upstream;
pub mod versioning;
pub mod websocket;
