//! Gateway core: M1 role is to host the shared config model, routing types,
//! swappable trait definitions, and listener/TLS machinery consumed by the
//! dataplane and admin crates.

pub mod active;
pub mod authn;
pub mod authz;
pub mod balance;
pub mod breaker;
pub mod config;
pub mod extensions;
pub mod hardening;
pub mod health;
pub mod migrations;
pub mod observability;
pub mod proxy;
pub mod retries;
pub mod snapshot;
pub mod store;
pub mod tls;
pub mod upstream;
