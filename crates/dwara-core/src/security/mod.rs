//! Security bounded context: establishing and enforcing caller identity.
//!
//! Listener/upstream TLS machinery ([`tls`]), request authentication
//! ([`authn`]), request authorization ([`authz`]), and OAuth2
//! client-credentials proxying ([`oauth2`], DW-035). May depend on
//! config, state, and observability.

pub mod authn;
pub mod authz;
pub mod geoip;
pub mod oauth2;
pub mod tls;
