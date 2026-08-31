//! Security bounded context: establishing and enforcing caller identity.
//!
//! Listener/upstream TLS machinery ([`tls`]), request authentication
//! ([`authn`]), request authorization ([`authz`]), OAuth2
//! client-credentials proxying ([`oauth2`], DW-035), and OpenID Connect
//! discovery / introspection / token exchange / auth-code+PKCE
//! ([`oidc`], DW-034). May depend on config, state, and observability.

pub mod authn;
pub mod authz;
// DW-060: Cedar + OPA authorization. Feature-gated behind the
// `cedar` cargo feature (default OFF).
#[cfg(feature = "cedar")]
pub mod cedar;
pub mod geoip;
pub mod oauth2;
pub mod oidc;
pub mod tls;
