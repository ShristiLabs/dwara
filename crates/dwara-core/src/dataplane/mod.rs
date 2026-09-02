//! Dataplane bounded context: the request-serving path.
//!
//! Assembles the reverse-proxy core ([`proxy`]), pooled upstream clients
//! ([`upstream`], with the RFC 8305 happy-eyeballs dial of DW-030),
//! per-upstream load balancing ([`balance`]), active health probing
//! ([`active`] — it drives the upstream registry's balancer trackers,
//! which is dataplane lifecycle), DNS-based dynamic upstream discovery
//! ([`discovery`] — DW-042, background tasks that resolve and watch
//! DNS records, updating the endpoint set live), config convergence
//! (`convergence` — DW-054, ent feature only, background task that
//! polls a shared backend so instances converge to the highest
//! generation and drift is reported), the protocol
//! hardening applied to
//! every serving surface ([`hardening`], plus the route-scoped request
//! limits of DW-027), the PROXY protocol acceptance of DW-030
//! ([`proxy_proto`]), the route-scoped response edge policies of DW-027
//! ([`cors`], [`compression`]), the API versioning aids of DW-048
//! ([`versioning`]), the request/response transforms and
//! security-header injection of DW-028 ([`transforms`]), and the local
//! response cache of DW-037 ([`response_cache`], behind the
//! `extensions::cache::CacheStore` seam), and the AI proxy action of
//! DW-075 ([`ai_proxy`], which drives the `ai` domain's adapters over
//! the provider's upstream). This is the top of the core
//! dependency graph: it may depend on every other domain; nothing
//! depends on it.

pub mod active;
pub mod ai_proxy;
pub mod anomaly;
pub mod balance;
pub mod canary;
pub mod compression;
pub mod cors;
// DW-054: config convergence coordinator (ent feature only). The
// module compiles only when the `ent` cargo feature is enabled; OSS
// builds never pull in the redis dependency. Lives in the dataplane
// (the top of the core dependency graph) because it orchestrates the
// snapshot publish pipeline + the convergence backend trait +
// observability, and `snapshot` may not import `extensions`.
#[cfg(feature = "ent")]
pub mod convergence;
// DW-099: GraphQL awareness (query depth/complexity limits +
// persisted-query enforcement). Feature-gated behind the `graphql`
// cargo feature; the module compiles only when the feature is enabled.
// The config schema is always present (so configs round-trip without
// the feature), but the runtime check is feature-gated.
pub mod discovery;
// DW-101: gRPC-Web framing translation + JSON-to-gRPC transcoding.
// Feature-gated behind the `grpc_web` cargo feature; the module
// compiles only when the feature is enabled. The config schema is
// always present (so configs round-trip without the feature), but the
// runtime translation is feature-gated.
#[cfg(feature = "graphql")]
pub mod graphql;
#[cfg(feature = "grpc_web")]
pub mod grpc_web;
pub mod hardening;
// DW-106: WASM route handlers (nano-services). Feature-gated behind
// the `nano_services` cargo feature (which pulls in `wasm`); the module
// compiles only when the feature is enabled. The config schema is
// always present (so configs round-trip without the feature), but the
// runtime handler is feature-gated. When the feature is off the action
// is accepted but inert (validation warns, the route returns 502).
#[cfg(feature = "nano_services")]
pub mod nano_service;
pub mod proxy;
pub mod proxy_proto;
// DW-102: replay time-travel debugging (pure decision replayer).
pub mod replay;
pub mod response_cache;
pub mod split;
// DW-100: protocol translation framework. The general
// ProtocolTranslator trait + the REST<->GraphQL translator compile
// under the `protocol_translation` cargo feature (which implies
// `grpc_web` so the REST<->gRPC translator reuses the DW-101 engine).
// The SOAP/XML translator is further gated behind the `soap` feature
// for binary size. The config schema is always present (so configs
// round-trip without the feature), but the runtime translation is
// feature-gated.
pub mod transforms;
#[cfg(feature = "protocol_translation")]
pub mod translation;
#[cfg(feature = "protocol_translation")]
pub mod translation_graphql;
#[cfg(feature = "soap")]
pub mod translation_soap;
// DW-103: L4 TCP/UDP proxying with SNI routing reuse. Feature-gated
// behind the `l4` cargo feature; the module compiles only when the
// feature is enabled. The config schema (ListenerProtocol::Tcp/Udp +
// L4Config) is always present so configs round-trip without the
// feature, but the runtime dispatcher is feature-gated. When the
// feature is off, validation warns that the listener is inert.
#[cfg(feature = "l4")]
pub mod l4;
pub mod upstream;
// DW-108: HTTP/3 (QUIC) upstream transport. Feature-gated behind the
// `h3` cargo feature; the module compiles only when the feature is
// enabled (it pulls in quinn + h3 + h3-quinn). When the feature is off,
// `protocol: h3` upstreams are accepted at validation but inert (every
// dispatch fails closed with UpstreamError::H3Unavailable).
#[cfg(feature = "h3")]
pub mod upstream_h3;
pub mod versioning;
pub mod waf;
pub mod websocket;
