//! Gateway core: M1 role is to host the shared config model, routing types,
//! swappable trait definitions, and listener/TLS machinery consumed by the
//! dataplane and admin crates.

pub mod config;
pub mod extensions;
pub mod snapshot;
pub mod tls;
pub mod upstream;
