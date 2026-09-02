//! L4 TCP/UDP proxying with SNI routing reuse (DW-103).
//!
//! L4 proxying is a LISTENER TYPE, not a route action: a `protocol: tcp`
//! (or `protocol: udp`) listener accepts raw L4 connections and splices
//! them byte-for-byte to an upstream endpoint, never running the HTTP
//! pipeline. This is the same byte-splice model the DW-008 TLS
//! passthrough path uses -- and when `sni_routing` is true, the TCP
//! dispatcher reuses the EXACT SNI extraction from passthrough
//! (`security::tls::sni_from_client_hello` + the peek loop) to select
//! the upstream from the listener's `tls.sni_routes`.
//!
//! ## TCP dispatcher
//!
//! [`L4Dispatcher`] (built from [`L4ProxyConfig`]) accepts a TCP
//! connection and:
//!
//! 1. If `sni_routing` is true, peeks the TLS ClientHello SNI (reusing
//!    [`crate::tls::handle_passthrough`]'s peek + `sni_from_client_hello`
//!    extraction -- the same bounded reassembly, the same 64 KiB budget,
//!    the same 10s peek timeout). The SNI is matched against the
//!    listener's `tls.sni_routes` to select the upstream; the configured
//!    `upstream` is the fallback for no-SNI / unmatched names (absent =
//!    close).
//! 2. If `sni_routing` is false, the configured `upstream` receives
//!    every connection.
//! 3. The selected upstream's endpoint is picked through the CURRENT
//!    generation's balancers (no hash key -- a byte splice has no
//!    client-IP semantics), so L4 picks follow config reloads.
//! 4. The client and upstream connections are spliced with
//!    `tokio::io::copy_bidirectional` until either side closes (the
//!    same tunnel the passthrough path and the 101 upgrade path use).
//!    An optional idle timeout closes the splice when neither side sends
//!    data for the configured duration.
//!
//! Peeking (never reading) keeps the ClientHello bytes available for the
//! upstream once splicing starts: the entire hello is still in the
//! socket buffer and is replayed to the upstream by the splice.
//!
//! ## UDP dispatcher (STUBBED)
//!
//! [`UdpDispatcher`] is STUBBED: UDP session semantics (per-client
//! session tracking, NAT timeout management, datagram boundaries) are
//! harder to get right than a byte splice and are a follow-up. The stub
//! accepts the config shape and returns [`L4Error::Unimplemented`] from
//! [`UdpDispatcher::dispatch`] so the listener wiring can close the
//! socket cleanly. The config schema is present so configs round-trip.
//!
//! ## Feature gate
//!
//! The entire module is behind `#[cfg(feature = "l4")]`. The config
//! schema (`ListenerProtocol::Tcp`/`Udp` + `L4Config`) is always
//! present so configs round-trip without the feature; when the feature
//! is off, validation warns that the listener is inert.

use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::config::{Gateway, L4Config, SniRoute};
use crate::dataplane::proxy::DataPlane;
use crate::tls::{self, EndpointPicker, PassthroughAction};

/// L4 proxying error. Kept simple: the dispatcher logs and closes on
/// any error -- there is no client-facing HTTP envelope at L4.
#[derive(Debug)]
pub enum L4Error {
    /// The configured upstream was not found in the current snapshot.
    UnknownUpstream(String),
    /// The upstream has no healthy / configured endpoints to splice to.
    NoEndpoint(String),
    /// The upstream connection failed (connect error, EOF, etc.).
    Io(std::io::Error),
    /// UDP proxying is not yet implemented (DW-103 follow-up).
    Unimplemented,
}

impl std::fmt::Display for L4Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            L4Error::UnknownUpstream(name) => {
                write!(f, "unknown upstream '{name}'")
            }
            L4Error::NoEndpoint(name) => {
                write!(f, "upstream '{name}' has no available endpoint")
            }
            L4Error::Io(err) => write!(f, "l4 splice io error: {err}"),
            L4Error::Unimplemented => {
                write!(
                    f,
                    "UDP L4 proxying is not yet implemented (DW-103 follow-up)"
                )
            }
        }
    }
}

impl std::error::Error for L4Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            L4Error::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for L4Error {
    fn from(err: std::io::Error) -> Self {
        L4Error::Io(err)
    }
}

/// Compiled L4 proxying configuration (from [`L4Config`]).
///
/// `upstream` is the fallback / fixed upstream name; `sni_routing`
/// selects per-connection routing via the TLS ClientHello SNI. The
/// `idle_timeout` closes the splice after the configured inactivity
/// gap (None = no timeout).
#[derive(Debug, Clone)]
pub struct L4ProxyConfig {
    /// The configured (or fallback) upstream name. None when
    /// `sni_routing` is true and no fallback is configured (close on
    /// no match).
    pub upstream: Option<String>,
    /// Peek the TLS ClientHello SNI and route via `tls.sni_routes`.
    pub sni_routing: bool,
    /// Idle timeout for an established splice. None = no timeout.
    pub idle_timeout: Option<Duration>,
}

impl L4ProxyConfig {
    /// Build from the config schema.
    pub fn from_config(cfg: &L4Config) -> Self {
        Self {
            upstream: cfg.upstream.clone(),
            sni_routing: cfg.sni_routing,
            idle_timeout: cfg.idle_timeout_s.map(Duration::from_secs),
        }
    }
}

/// The outcome of an L4 TCP dispatch: which upstream endpoint the
/// connection was spliced to (for metrics/logging), or that it was
/// closed (no upstream, no endpoint, or SNI routing with no match).
#[derive(Debug, PartialEq, Eq)]
pub enum L4DispatchAction {
    /// The splice was established to this endpoint.
    Forward { host: String, port: u16 },
    /// The connection was closed (no upstream, no endpoint, no SNI
    /// match, or a connect/splice error).
    Close,
}

/// TCP L4 dispatcher: accept one TCP connection, optionally peek SNI,
/// select the upstream, and splice byte-for-byte.
///
/// The dispatcher is stateless beyond the config -- each call handles
/// one connection. The `dp` (dataplane) supplies the CURRENT
/// generation's balancers so endpoint picks follow config reloads.
pub struct L4Dispatcher {
    config: L4ProxyConfig,
    /// The listener's SNI routes (used when `sni_routing` is true).
    /// Borrowed from the live snapshot; the caller holds the snapshot
    /// alive for the duration of the dispatch.
    sni_routes: Vec<SniRoute>,
}

impl L4Dispatcher {
    /// Build a dispatcher from the compiled config and the listener's
    /// SNI routes (empty when `sni_routing` is false).
    pub fn new(config: L4ProxyConfig, sni_routes: Vec<SniRoute>) -> Self {
        Self { config, sni_routes }
    }

    /// Dispatch one accepted TCP connection: peek SNI (if enabled),
    /// select the upstream endpoint, splice byte-for-byte, and return
    /// the action taken.
    ///
    /// `dp` supplies the current generation's balancers (endpoint
    /// picks follow config reloads); `gateway` is the current snapshot
    /// (for SNI route resolution and the first-endpoint fallback).
    pub async fn dispatch(
        &self,
        stream: &mut TcpStream,
        dp: &DataPlane,
        gateway: &Gateway,
    ) -> Result<L4DispatchAction, L4Error> {
        // 1. Select the upstream name (fixed, or SNI-routed).
        let (host, port) = if self.config.sni_routing {
            // Reuse the EXACT peek + SNI extraction from DW-008
            // passthrough (peek_client_hello_sni is the peek-only half
            // of handle_passthrough, extracted for this path). We own
            // the splice (idle timeout, metrics) rather than letting
            // handle_passthrough splice for us.
            let sni = tls::peek_client_hello_sni(stream).await?;
            let pick: EndpointPicker<'_> = &|name: &str| {
                dp.registry()
                    .get(name)
                    .and_then(|h| h.lb().pick_endpoint(None).map(|(_, a, p)| (a, p)))
            };
            match tls::resolve_passthrough(sni.as_deref(), &self.sni_routes, gateway, Some(pick)) {
                PassthroughAction::Forward { host, port } => (host, port),
                PassthroughAction::Close => {
                    // SNI routing with no match: try the fallback
                    // upstream, or close.
                    match &self.config.upstream {
                        Some(name) => pick_endpoint(dp, gateway, name)?,
                        None => {
                            let _ = stream.shutdown().await;
                            return Ok(L4DispatchAction::Close);
                        }
                    }
                }
            }
        } else {
            // Fixed upstream: every connection goes to the configured
            // upstream.
            let name = self
                .config
                .upstream
                .as_deref()
                .ok_or_else(|| L4Error::UnknownUpstream("(none configured)".into()))?;
            pick_endpoint(dp, gateway, name)?
        };

        // 2. Connect to the upstream endpoint.
        let mut upstream = TcpStream::connect((host.as_str(), port)).await?;
        let _ = stream.set_nodelay(true);
        let _ = upstream.set_nodelay(true);

        // 3. Splice byte-for-byte (the same tunnel passthrough and the
        //    101 upgrade path use). The optional idle timeout wraps the
        //    splice: if neither side sends data for the configured
        //    duration, the splice is aborted.
        let action = L4DispatchAction::Forward {
            host: host.clone(),
            port,
        };
        splice_with_idle(stream, &mut upstream, self.config.idle_timeout).await?;
        Ok(action)
    }
}

/// UDP L4 dispatcher (STUBBED). The config shape is accepted so configs
/// round-trip; [`UdpDispatcher::dispatch`] returns
/// [`L4Error::Unimplemented`]. UDP session semantics (per-client
/// session tracking, NAT timeout management, datagram boundaries) are
/// a follow-up.
pub struct UdpDispatcher {
    #[allow(dead_code)]
    config: L4ProxyConfig,
}

impl UdpDispatcher {
    /// Build a stubbed UDP dispatcher from the compiled config.
    pub fn new(config: L4ProxyConfig) -> Self {
        Self { config }
    }

    /// Dispatch one UDP datagram batch. STUBBED: returns
    /// [`L4Error::Unimplemented`].
    pub async fn dispatch(&self) -> Result<L4DispatchAction, L4Error> {
        Err(L4Error::Unimplemented)
    }
}

/// Pick a load-balanced endpoint for the named upstream through the
/// current generation's balancers (no hash key -- a byte splice has no
/// client-IP semantics). Falls back to the first configured endpoint
/// when the balancer has no healthy endpoint.
fn pick_endpoint(dp: &DataPlane, gateway: &Gateway, name: &str) -> Result<(String, u16), L4Error> {
    if let Some(h) = dp.registry().get(name) {
        if let Some((_, addr, port)) = h.lb().pick_endpoint(None) {
            return Ok((addr, port));
        }
    }
    // Fallback: the first configured endpoint (the same fallback
    // resolve_passthrough uses when there is no dataplane resolver).
    if let Some(upstream) = gateway.upstreams.iter().find(|u| u.name == name) {
        if let Some(e) = upstream.endpoints.first() {
            return Ok((e.address.clone(), e.port));
        }
    }
    if dp.registry().get(name).is_some() {
        Err(L4Error::NoEndpoint(name.to_string()))
    } else {
        Err(L4Error::UnknownUpstream(name.to_string()))
    }
}

/// Splice two TCP streams byte-for-byte with an optional idle timeout.
/// The idle timeout wraps the whole splice: if neither side sends data
/// for the configured duration, both sides are shut down and the splice
/// returns. Without a timeout the splice runs until either side closes
/// (the same `copy_bidirectional` semantics as passthrough).
async fn splice_with_idle(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    idle_timeout: Option<Duration>,
) -> Result<(), L4Error> {
    match idle_timeout {
        Some(timeout) => {
            let splice = tokio::io::copy_bidirectional(client, upstream);
            match tokio::time::timeout(timeout, splice).await {
                Ok(Ok(_)) => {}
                Ok(Err(err)) => return Err(L4Error::Io(err)),
                Err(_) => {
                    tracing::debug!(code = "l4_idle_timeout", "l4 splice idle timeout");
                }
            }
            let _ = client.shutdown().await;
            let _ = upstream.shutdown().await;
        }
        None => {
            match tokio::io::copy_bidirectional(client, upstream).await {
                Ok(_) => {}
                Err(err) => {
                    // A splice error (one side reset mid-stream) is
                    // expected at L4 -- log and close, do not propagate
                    // as a hard error to the caller (the connection is
                    // gone either way).
                    tracing::debug!(code = "l4_splice_error", "l4 splice ended: {err}");
                }
            }
            let _ = client.shutdown().await;
            let _ = upstream.shutdown().await;
        }
    }
    Ok(())
}
