//! Sidecar traffic interception (DW-107).
//!
//! dwara runs as a sidecar in each pod. An init container (or the
//! sidecar bootstrap) configures the network so all traffic to and from
//! the local application flows through the sidecar:
//!
//! - INBOUND: traffic destined for the local app is redirected to the
//!   sidecar's inbound listener. The sidecar terminates mTLS (verifying
//!   the peer's SPIFFE SVID against the trust bundle), applies policies,
//!   then forwards the plaintext request to the local app over
//!   loopback.
//! - OUTBOUND: traffic the local app sends to a remote service is
//!   redirected to the sidecar's outbound listener. The sidecar applies
//!   policies, wraps the request in mTLS (presenting the local
//!   workload's SVID), then dials the remote service's sidecar.
//!
//! # Redirect modes
//!
//! Two redirect modes are scaffolded:
//!
//! - [`SidecarRedirectMode::Iptables`]: the init container installs
//!   iptables REDIRECT rules that send traffic to the inbound/outbound
//!   listener ports. This is the default and the most common mode
//!   (used by Istio/Linkerd-style sidecars).
//! - [`SidecarRedirectMode::Tproxy`]: TPROXY (transparent proxy) mode
//!   uses iptables TPROXY + IP_TRANSPARENT so the sidecar receives the
//!   original destination address (no REDIRECT port rewrite), enabling
//!   the sidecar to know the intended upstream without parsing the
//!   SO_ORIGINAL_DST socket option.
//!
//! # Stubbed
//!
//! The actual iptables/TPROXY rule installation is STUBBED. The
//! [`SidecarController`] records the configured inbound/outbound
//! listeners and documents the redirect setup, but does NOT install
//! iptables rules or open sockets. The sidecar bootstrap (the init
//! container that runs as root and configures the network namespace)
//! would land here when production-ready. Today the controller is the
//! compile-time scaffold: it validates the configuration shape and
//! exposes the listener configuration the runtime would bind.

use crate::config::mesh::MeshSidecarConfig;

/// The redirect mode the sidecar bootstrap uses to capture traffic.
///
/// [`SidecarRedirectMode::Iptables`] is the default (iptables REDIRECT
/// rules); [`SidecarRedirectMode::Tproxy`] uses TPROXY for transparent
/// interception with original-destination preservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidecarRedirectMode {
    /// iptables REDIRECT: traffic is rewritten to the sidecar's
    /// inbound/outbound listener port. The sidecar recovers the
    /// original destination via `SO_ORIGINAL_DST`.
    Iptables,
    /// TPROXY (transparent proxy): the sidecar receives the connection
    /// with the original destination address preserved (no port
    /// rewrite), via `IP_TRANSPARENT` + iptables TPROXY.
    Tproxy,
}

impl SidecarRedirectMode {
    /// The lowercase wire name used in config and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            SidecarRedirectMode::Iptables => "iptables",
            SidecarRedirectMode::Tproxy => "tproxy",
        }
    }

    /// Parse a wire-name string into a redirect mode. Returns None for
    /// an unknown name (the config parser rejects unknown variants
    /// before this is reached; this is the runtime helper).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "iptables" => Some(SidecarRedirectMode::Iptables),
            "tproxy" => Some(SidecarRedirectMode::Tproxy),
            _ => None,
        }
    }
}

impl std::fmt::Display for SidecarRedirectMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The direction of traffic a sidecar listener handles.
///
/// [`SidecarMode::Inbound`] intercepts traffic TO the local app
/// (terminate mTLS, apply policies, forward to loopback).
/// [`SidecarMode::Outbound`] intercepts traffic FROM the local app to
/// remote services (apply policies, wrap in mTLS, dial the remote
/// sidecar).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidecarMode {
    /// Intercept traffic destined for the local application:
    /// terminate the peer's mTLS, verify the peer's SPIFFE SVID, apply
    /// policies, then forward the plaintext request to the local app
    /// over loopback.
    Inbound,
    /// Intercept traffic the local application sends to a remote
    /// service: apply policies, wrap the request in mTLS using the
    /// local workload's SVID, then dial the remote service's sidecar.
    Outbound,
}

impl SidecarMode {
    /// The lowercase wire name used in metrics labels and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            SidecarMode::Inbound => "inbound",
            SidecarMode::Outbound => "outbound",
        }
    }
}

impl std::fmt::Display for SidecarMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The resolved sidecar configuration: the listener ports and redirect
/// mode the controller binds. Built from the config schema
/// ([`MeshSidecarConfig`]) at compile time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarConfig {
    /// Whether the sidecar is enabled.
    pub enabled: bool,
    /// The inbound listener port (traffic to the local app). Must be
    /// > 0 and distinct from the outbound port.
    pub inbound_port: u16,
    /// The outbound listener port (traffic from the local app to
    /// remote services). Must be > 0 and distinct from the inbound
    /// port.
    pub outbound_port: u16,
    /// The redirect mode (iptables REDIRECT or TPROXY).
    pub redirect_mode: SidecarRedirectMode,
}

impl SidecarConfig {
    /// Build a [`SidecarConfig`] from the config schema. The redirect
    /// mode string is parsed here; an unknown value yields the default
    /// (iptables) -- the config parser rejects unknown variants before
    /// this is reached, so this is a defensive fallback. `enabled` is
    /// inherited from the parent `MeshConfig.enabled` (the sidecar
    /// block itself has no separate enabled flag).
    pub fn from_config(cfg: &MeshSidecarConfig, enabled: bool) -> Self {
        SidecarConfig {
            enabled,
            inbound_port: cfg.inbound_port,
            outbound_port: cfg.outbound_port,
            redirect_mode: SidecarRedirectMode::parse(&cfg.redirect_mode)
                .unwrap_or(SidecarRedirectMode::Iptables),
        }
    }
}

/// The sidecar controller: configures the inbound and outbound
/// listeners and (when production-ready) the iptables/TPROXY redirect
/// bootstrap.
///
/// # Stubbed
///
/// The controller is a SCAFFOLD today. It records the resolved
/// [`SidecarConfig`] and exposes the listener configuration the runtime
/// would bind, but does NOT:
///
/// - install iptables REDIRECT/TPROXY rules (the init-container
///   bootstrap that runs as root and configures the pod's network
///   namespace would land here when production-ready),
/// - open the inbound/outbound listener sockets,
/// - terminate or wrap mTLS (the mTLS wiring lives in `security::tls`,
///   which would consume the SVID cert/key and trust bundle from
///   [`crate::mesh::spiffe::SpiffeClient`]).
///
/// The controller is the compile-time seam: it validates the
/// configuration shape and documents the runtime contract so the
/// production wiring lands here without touching config, validation, or
/// metrics.
#[derive(Debug, Clone)]
pub struct SidecarController {
    config: SidecarConfig,
}

impl SidecarController {
    /// Build a controller from the resolved sidecar config.
    pub fn new(config: SidecarConfig) -> Self {
        SidecarController { config }
    }

    /// The resolved sidecar configuration.
    pub fn config(&self) -> &SidecarConfig {
        &self.config
    }

    /// The inbound listener configuration: the port the sidecar binds
    /// to receive traffic destined for the local app, and the redirect
    /// mode used to capture it. Inbound terminates mTLS, applies
    /// policies, and forwards to the local app over loopback.
    pub fn inbound_listener(&self) -> (SidecarMode, u16, SidecarRedirectMode) {
        (
            SidecarMode::Inbound,
            self.config.inbound_port,
            self.config.redirect_mode,
        )
    }

    /// The outbound listener configuration: the port the sidecar binds
    /// to receive traffic the local app sends to remote services, and
    /// the redirect mode used to capture it. Outbound applies policies,
    /// wraps the request in mTLS, and dials the remote sidecar.
    pub fn outbound_listener(&self) -> (SidecarMode, u16, SidecarRedirectMode) {
        (
            SidecarMode::Outbound,
            self.config.outbound_port,
            self.config.redirect_mode,
        )
    }

    /// Install the iptables/TPROXY redirect rules that capture traffic
    /// into the inbound and outbound listeners.
    ///
    /// # Stubbed
    ///
    /// This is a documented no-op today. The sidecar bootstrap (the
    /// init container that runs as root and configures the pod's
    /// network namespace with iptables REDIRECT or TPROXY rules) would
    /// land here when production-ready. Today the controller records
    /// the configured redirect mode and logs that the bootstrap is
    /// stubbed, so an operator who builds with `--features mesh` sees
    /// the configuration is accepted and the redirect is scaffolded.
    pub fn install_redirects(&self) {
        tracing::info!(
            code = "mesh_sidecar_redirect_stubbed",
            mode = %self.config.redirect_mode,
            inbound_port = self.config.inbound_port,
            outbound_port = self.config.outbound_port,
            "the sidecar redirect bootstrap is stubbed (DW-107): the iptables/TPROXY rule \
             installation would land here when production-ready. The controller records the \
             configured listeners; no redirect rules are installed."
        );
    }
}
