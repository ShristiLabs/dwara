//! Security bounded context: establishing and enforcing caller identity.
//!
//! Listener/upstream TLS machinery ([`tls`]), request authentication
//! ([`authn`]), and request authorization ([`authz`]). May depend on
//! config, state, and observability.

pub mod authn;
pub mod authz;
pub mod tls;
