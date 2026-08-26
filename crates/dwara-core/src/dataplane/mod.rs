//! Dataplane bounded context: the request-serving path.
//!
//! Assembles the reverse-proxy core ([`proxy`]), pooled upstream clients
//! ([`upstream`]), per-upstream load balancing ([`balance`]), and the
//! protocol hardening applied to every serving surface ([`hardening`]).
//! This is the top of the core dependency graph: it may depend on every
//! other domain; nothing depends on it.

pub mod balance;
pub mod hardening;
pub mod proxy;
pub mod upstream;
