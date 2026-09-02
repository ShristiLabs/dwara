//! Service mesh config schema (DW-107).
//!
//! The top-level `mesh` block configures service mesh mode: dwara runs
//! as a sidecar in each pod, intercepting traffic via iptables/TPROXY
//! redirect, with mTLS identity provided by SPIFFE/SPIRE (X.509 SVIDs).
//! The schema is always present so configs round-trip without the
//! `mesh` cargo feature; when the feature is off the block is accepted
//! but inert (validation warns). Ent-only: validation warns when mesh
//! is configured without the `ent` feature.
//!
//! See the `mesh` domain module (`crate::mesh`) for the sidecar
//! controller and SPIFFE client scaffolds.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The service mesh mode. v1 ships `sidecar` (dwara runs as a sidecar
/// in each pod). Future modes (node-level, CNI-based) are deferred;
/// validation rejects any value other than `sidecar`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum MeshMode {
    /// Sidecar mode: dwara runs as a sidecar in each pod, intercepting
    /// traffic via iptables/TPROXY redirect. Inbound terminates mTLS
    /// and forwards to the local app; outbound wraps in mTLS and dials
    /// the remote sidecar.
    Sidecar,
}

impl MeshMode {
    /// The lowercase wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            MeshMode::Sidecar => "sidecar",
        }
    }
}

impl std::fmt::Display for MeshMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Top-level service mesh config (DW-107, `gateway.mesh`).
///
/// When present and the `mesh` cargo feature is compiled in, the
/// gateway runs as a sidecar in each pod: an init container configures
/// iptables/TPROXY redirects so all traffic to and from the local
/// application flows through the sidecar, which terminates mTLS
/// (inbound) and wraps mTLS (outbound) using SPIFFE/SPIRE X.509 SVIDs.
/// When the `mesh` feature is NOT compiled in, the block is accepted
/// but inert (validation warns, no sidecar listeners or SPIFFE client
/// are wired). Ent-only: validation warns when mesh is configured
/// without the `ent` feature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeshConfig {
    /// Master switch. Default false: the mesh is inert even when the
    /// `mesh` cargo feature is compiled in. This lets operators stage
    /// the config ahead of activating the surface.
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,
    /// The mesh mode. v1 ships `sidecar`; validation rejects any other
    /// value.
    pub mode: MeshMode,
    /// Sidecar listener and redirect configuration. Required when
    /// `mode` is `sidecar`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sidecar: Option<MeshSidecarConfig>,
    /// SPIFFE/SPIRE identity configuration. Required when the mesh is
    /// enabled (mTLS identity is mandatory, not optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spiffe: Option<MeshSpiffeConfig>,
}

/// Sidecar listener and redirect config (DW-107, `gateway.mesh.sidecar`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeshSidecarConfig {
    /// The inbound listener port (traffic to the local app). Default
    /// 15006 (the Istio convention). Must be > 0 and distinct from the
    /// outbound port.
    #[serde(
        default = "default_sidecar_inbound_port",
        skip_serializing_if = "is_default_sidecar_inbound_port"
    )]
    pub inbound_port: u16,
    /// The outbound listener port (traffic from the local app to
    /// remote services). Default 15001 (the Istio convention). Must be
    /// > 0 and distinct from the inbound port.
    #[serde(
        default = "default_sidecar_outbound_port",
        skip_serializing_if = "is_default_sidecar_outbound_port"
    )]
    pub outbound_port: u16,
    /// The redirect mode: `iptables` (REDIRECT rules, the default) or
    /// `tproxy` (TPROXY with original-destination preservation).
    /// Validation rejects any value other than `iptables` or `tproxy`.
    #[serde(
        default = "default_sidecar_redirect_mode",
        skip_serializing_if = "is_default_sidecar_redirect_mode"
    )]
    pub redirect_mode: String,
}

fn default_sidecar_inbound_port() -> u16 {
    15006
}

fn is_default_sidecar_inbound_port(v: &u16) -> bool {
    *v == 15006
}

fn default_sidecar_outbound_port() -> u16 {
    15001
}

fn is_default_sidecar_outbound_port(v: &u16) -> bool {
    *v == 15001
}

fn default_sidecar_redirect_mode() -> String {
    "iptables".to_string()
}

fn is_default_sidecar_redirect_mode(v: &str) -> bool {
    v == "iptables"
}

/// SPIFFE/SPIRE identity config (DW-107, `gateway.mesh.spiffe`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeshSpiffeConfig {
    /// The trust domain this workload belongs to (e.g. `example.org`).
    /// Must be non-empty. Forms the SPIFFE ID prefix
    /// (`spiffe://<trust-domain>/...`).
    pub trust_domain: String,
    /// The filesystem path of the SPIRE Workload API Unix socket
    /// (e.g. `/tmp/spire-agent/public/api.sock`). Must be non-empty.
    /// The sidecar connects to this socket to fetch X.509 SVIDs.
    pub workload_api_socket: String,
    /// The SVID refresh interval in seconds (default 300). The client
    /// refreshes the SVID (and trust bundle) before expiry, at half
    /// the remaining lifetime by default; this is the upper bound on
    /// the refresh cadence. Validated to be > 0.
    #[serde(
        default = "default_spiffe_svid_refresh_interval_secs",
        skip_serializing_if = "is_default_spiffe_svid_refresh_interval_secs"
    )]
    pub svid_refresh_interval_secs: u64,
}

fn default_spiffe_svid_refresh_interval_secs() -> u64 {
    300
}

fn is_default_spiffe_svid_refresh_interval_secs(v: &u64) -> bool {
    *v == 300
}

fn is_false(b: &bool) -> bool {
    !b
}
