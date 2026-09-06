//! Service mesh mode (DW-107): sidecar traffic interception plus
//! SPIFFE/SPIRE mTLS identity.
//!
//! This module is SCAFFOLDED behind the `mesh` cargo feature. The
//! service mesh mode runs dwara as a SIDECAR in each pod: an init
//! container configures iptables (or TPROXY) redirects so all inbound
//! traffic to the local application and all outbound traffic from the
//! local application to remote services flows through the sidecar. The
//! sidecar then terminates mTLS on inbound connections (verifying the
//! peer's SPIFFE SVID, applying policies, then forwarding to the local
//! app over loopback) and wraps outbound connections in mTLS (applying
//! policies, then dialing the remote service's sidecar with the local
//! workload's SVID).
//!
//! Identity is provided by SPIFFE/SPIRE: each workload fetches X.509
//! SVIDs (SPIFFE Verifiable Identity Documents) from the SPIRE Workload
//! API over a Unix domain socket. The SVID certificate's URI SAN carries
//! the SPIFFE ID (`spiffe://<trust-domain>/<path>`), which is the
//! authentication identity used for policy decisions. The trust bundle
//! (the SPIRE signing CAs) is used to verify peer SVIDs.
//!
//! # What is implemented today
//!
//! The scaffold compiles and the config schema is always present so
//! configs round-trip without the feature. What is implemented:
//!
//! - [`spiffe::SpiffeClient`]: the Workload API client is implemented
//!   behind a transport abstraction ([`spiffe::WorkloadApiTransport`]).
//!   The production gRPC transport ([`spiffe::grpc::GrpcWorkloadApi`])
//!   uses tonic over a Unix domain socket (ent-gated); a test fake
//!   ([`spiffe::FakeWorkloadApi`]) is provided for deterministic tests.
//!   The client fetches X.509 SVIDs and the trust bundle, and exposes
//!   the refresh-result metric seam. The SVID material (cert chain,
//!   private key, expiry) and the trust bundle (CA certs) are the
//!   integration point for `security::tls`.
//!
//! What is STUBBED (documented no-ops pending production hardening):
//!
//! - [`sidecar::SidecarController`]: the inbound/outbound listener
//!   configuration and the iptables/TPROXY redirect bootstrap are
//!   scaffolded. The controller records the configured listeners and
//!   documents the redirect setup, but does NOT install iptables rules
//!   or open sockets (that wiring lands when the sidecar bootstrap is
//!   production-ready).
//! - The full gRPC client wiring in [`spiffe::grpc::GrpcWorkloadApi`]:
//!   the transport abstraction and the trait-based seam are landed; the
//!   full gRPC call (proto-generated client, codec, path) is the
//!   remaining wiring. The `connect()` method establishes the tonic
//!   channel over the Unix socket; the fetch methods return a clear
//!   "not yet connected" error until the proto client is wired.
//!
//! # Feature gate
//!
//! The `mesh` cargo feature is flag-only (no new deps). When it is OFF,
//! the `mesh` config block is accepted but inert: validation warns, and
//! no sidecar listeners or SPIFFE client are wired. When it is ON, the
//! scaffold compiles; the actual iptables/Workload API wiring lands
//! when production-ready. Ent-only: validation warns when mesh is
//! configured without the `ent` feature (mirrors the FIPS/credential-
//! pool ent-gate pattern).
//!
//! # Dependency direction
//!
//! `mesh` depends on `config` (the config schema) and `observability`
//! (the mesh/SPIFFE metrics). It does NOT import `security` directly:
//! the TLS integration point is a documented seam (the mTLS TLS config
//! in `security::tls` would consume the SVID cert/key and trust bundle
//! produced here), kept as a seam so the dependency direction stays
//! downward (mesh is a peer of security, both above config).

pub mod sidecar;
pub mod spiffe;

pub use sidecar::{SidecarConfig, SidecarController, SidecarMode, SidecarRedirectMode};
pub use spiffe::{
    FakeWorkloadApi, SpiffeClient, SpiffeConfig, SpiffeError, SpiffeIdentity, SpiffeSvid,
    SpiffeTrustBundle, SvidRefreshResult, WorkloadApiTransport,
};
