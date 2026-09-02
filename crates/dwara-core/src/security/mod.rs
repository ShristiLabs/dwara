//! Security bounded context: establishing and enforcing caller identity.
//!
//! Listener/upstream TLS machinery ([`tls`]), request authentication
//! ([`authn`]), request authorization ([`authz`]), OAuth2
//! client-credentials proxying ([`oauth2`], DW-035), OpenID Connect
//! discovery / introspection / token exchange / auth-code+PKCE
//! ([`oidc`], DW-034), FIPS 140-3 mode enforcement ([`fips`],
//! DW-111), post-quantum TLS hybrid key exchange ([`pq`], DW-105),
//! bot detection hooks ([`bot_hooks`], DW-109), signed URL request
//! authentication ([`signed_url`], DW-109), and upstream TLS
//! certificate pinning ([`cert_pinning`], DW-109). May depend on
//! config, state, and observability.

pub mod authn;
pub mod authz;
// DW-060: Cedar + OPA authorization. Feature-gated behind the
// `cedar` cargo feature (default OFF).
#[cfg(feature = "cedar")]
pub mod cedar;
// DW-111: FIPS 140-3 mode enforcement. The module compiles in every
// build; when the `fips` cargo feature is OFF, all functions are inert
// (FipsMode::Disabled, no self-test, no primitive restriction).
pub mod fips;
pub mod geoip;
pub mod oauth2;
pub mod oidc;
// DW-105: Post-quantum TLS (X25519+ML-KEM hybrid key exchange). The
// module compiles in every build; when the `pq` cargo feature is OFF,
// all functions are inert (PqMode::Disabled, no kx group manipulation).
pub mod pq;
pub mod tls;
// DW-109: Bot detection hooks. Part of the default build (no feature
// gate): a simple regex-based pre-request and post-response check,
// like WAF-lite (DW-051). The engine compiles bot hooks from config
// and evaluates requests against them.
pub mod bot_hooks;
// DW-109: Signed URL request authentication. Feature-gated behind
// the `signed_url` cargo feature (default OFF). The verifier
// extracts the signature from the query string, recomputes the
// HMAC-SHA256 over the canonical request, and checks the expiry.
#[cfg(feature = "signed_url")]
pub mod signed_url;
// DW-109: Upstream TLS certificate pinning (SPKI hash). Feature-gated
// behind the `cert_pinning` cargo feature (default OFF). The verifier
// computes SHA-256 of the upstream cert's SubjectPublicKeyInfo and
// compares against the configured pin.
#[cfg(feature = "cert_pinning")]
pub mod cert_pinning;
