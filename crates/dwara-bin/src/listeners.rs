//! Listener binding and serving.
//!
//! Listener modes (DW-007, feature analysis 4.10 / 4.13):
//! - `http` listener: cleartext; hyper-util's auto builder sniffs the
//!   HTTP/2 preface, so HTTP/1.1 and h2c (prior knowledge) both work.
//! - `https` + `tls.mode terminate`: rustls (aws-lc-rs provider) with
//!   TLS 1.3 + 1.2, ALPN `h2`/`http/1.1`, SNI certificate selection
//!   (single pair = fallback; `certificates` entries matched by SNI).
//! - `https` + `tls.mode passthrough`: the ClientHello is peeked, SNI is
//!   matched against `tls.sni_routes`, and the raw TLS bytes are spliced
//!   bidirectionally to the first endpoint of the matched upstream
//!   (load balancing is DW-011). A non-TLS client, missing SNI, or an
//!   unmatched name has its connection closed.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dwara_core::config::{Listener, ListenerProtocol, TlsMode};
use dwara_core::hardening::HttpHardening;
use dwara_core::proxy::{self, DataPlane};
use dwara_core::snapshot::ConfigState;
use dwara_core::tls::{self, TlsTermination};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::TcpListener;
use tokio::sync::watch;

/// Runtime face of one bound listener: what to do with each accepted
/// connection.
pub(crate) enum ListenerMode {
    /// Cleartext HTTP (HTTP/1.1 + h2c via preface sniffing).
    Cleartext,
    /// TLS termination; the `ArcSwap`-backed config hot-reloads.
    Terminate(Arc<TlsTermination>),
    /// TLS passthrough routed by SNI against the current snapshot.
    Passthrough,
}

pub(crate) struct BoundListener {
    pub(crate) name: String,
    pub(crate) addr: String,
    pub(crate) mode: ListenerMode,
}

/// Bind one configured listener into its runtime face. Fails startup on
/// bind errors or unusable TLS material (a gateway must not boot serving
/// the wrong certificates).
pub(crate) async fn bind_listener(
    l: &Listener,
) -> Result<(TcpListener, BoundListener), Box<dyn std::error::Error + Send + Sync>> {
    let addr = format!("{}:{}", l.address, l.port);
    let listener = TcpListener::bind(&addr).await?;
    let mode = match l.protocol {
        ListenerProtocol::Http => ListenerMode::Cleartext,
        ListenerProtocol::Https => match &l.tls.as_ref().map(|t| (t.mode, t)).map(|(m, _)| m) {
            Some(TlsMode::Passthrough) => ListenerMode::Passthrough,
            _ => {
                let tls_cfg = l.tls.as_ref().expect("validated config has tls for https");
                let term = TlsTermination::build(tls_cfg)?;
                ListenerMode::Terminate(Arc::new(term))
            }
        },
    };
    Ok((
        listener,
        BoundListener {
            name: l.name.clone(),
            addr,
            mode,
        },
    ))
}

/// Per-listener accept loop with its own backlog flush (the DW-006 drain
/// sequence, per listener). Returns when shutdown is signalled and the
/// backlog is flushed.
#[allow(clippy::too_many_arguments)] // fixed accept-loop plumbing, DW-023 added the hardening handle
pub(crate) async fn run_listener(
    bound: BoundListener,
    listener: TcpListener,
    state: Arc<ConfigState>,
    dp: Arc<DataPlane>,
    graceful: Arc<GracefulShutdown>,
    mut shutdown: watch::Receiver<()>,
    timeout: Duration,
    hardening: Arc<HttpHardening>,
) {
    loop {
        let (mut stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(err) => {
                    tracing::warn!(code = "accept_error", listener = %bound.name, "accept error on {}: {err}", bound.addr);
                    continue;
                }
            },
            _ = shutdown.changed() => break,
        };
        match &bound.mode {
            ListenerMode::Cleartext => serve_http_tls(
                graceful.watcher(),
                Arc::clone(&dp),
                stream,
                peer,
                std::sync::Arc::from(bound.name.as_str()),
                Arc::clone(&hardening),
            ),
            ListenerMode::Passthrough => {
                // Consult the CURRENT snapshot: SNI routes reload live.
                // Passthrough splices are not part of hyper graceful
                // shutdown; they run until the process exits (documented
                // limitation: no drain signaling through a raw TLS pipe).
                let snapshot = state.snapshot();
                let tls_cfg = snapshot
                    .gateway()
                    .listeners
                    .iter()
                    .find(|l| l.name == bound.name)
                    .and_then(|l| l.tls.clone());
                let name = bound.name.clone();
                let dp = Arc::clone(&dp);
                tokio::spawn(async move {
                    match tls_cfg {
                        Some(tls_cfg) => {
                            // The dataplane owns endpoint selection: the
                            // resolver picks through the CURRENT
                            // generation's balancers (no hash key — a byte
                            // splice has no client-IP semantics), so
                            // passthrough picks follow config reloads.
                            let registry = dp.registry();
                            let pick = |name: &str| {
                                registry.get(name).and_then(|h| {
                                    h.lb().pick_endpoint(None).map(|(_, a, p)| (a, p))
                                })
                            };
                            if let Err(err) = tls::handle_passthrough(
                                &mut stream,
                                &tls_cfg,
                                snapshot.gateway(),
                                Some(&pick),
                            )
                            .await
                            {
                                tracing::warn!(
                                    code = "passthrough_error",
                                    "passthrough error: {err}"
                                );
                            }
                        }
                        None => tracing::warn!(
                            code = "passthrough_listener_missing",
                            listener = %name,
                            "passthrough listener missing from current config; closing connection"
                        ),
                    }
                });
            }
            ListenerMode::Terminate(term) => {
                // Snapshot the CURRENT ServerConfig for this handshake;
                // a reload only affects handshakes started after it.
                let acceptor = tokio_rustls::TlsAcceptor::from(term.config());
                let watcher = graceful.watcher();
                let dp = Arc::clone(&dp);
                let hardening = Arc::clone(&hardening);
                let listener: std::sync::Arc<str> = std::sync::Arc::from(bound.name.as_str());
                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            serve_http_tls(watcher, dp, tls_stream, peer, listener, hardening);
                        }
                        Err(err) => tracing::warn!("tls handshake error: {err}"),
                    }
                });
            }
        }
    }

    // Backlog flush (DW-006): connections that completed the TCP
    // handshake into the kernel backlog but were not yet accepted would
    // be reset when the listener drops. Accept what is queued and serve
    // it; passthrough backlog connections are closed (documented
    // limitation: shutdown-time passthrough splices are not established).
    let Ok(std_listener) = listener.into_std() else {
        return;
    };
    let _ = std_listener.set_nonblocking(true);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let mut accepted = 0usize;
        loop {
            match std_listener.accept() {
                Ok((std_stream, peer)) => {
                    accepted += 1;
                    if std_stream.set_nonblocking(true).is_err() {
                        continue;
                    }
                    let Ok(stream) = tokio::net::TcpStream::from_std(std_stream) else {
                        continue;
                    };
                    match &bound.mode {
                        ListenerMode::Passthrough => {}
                        ListenerMode::Cleartext => serve_http_tls(
                            graceful.watcher(),
                            Arc::clone(&dp),
                            stream,
                            peer,
                            std::sync::Arc::from(bound.name.as_str()),
                            Arc::clone(&hardening),
                        ),
                        ListenerMode::Terminate(term) => {
                            let acceptor = tokio_rustls::TlsAcceptor::from(term.config());
                            let watcher = graceful.watcher();
                            let dp = Arc::clone(&dp);
                            let hardening = Arc::clone(&hardening);
                            let listener: std::sync::Arc<str> =
                                std::sync::Arc::from(bound.name.as_str());
                            tokio::spawn(async move {
                                match acceptor.accept(stream).await {
                                    Ok(tls_stream) => serve_http_tls(
                                        watcher, dp, tls_stream, peer, listener, hardening,
                                    ),
                                    Err(err) => {
                                        tracing::warn!("tls handshake error: {err}")
                                    }
                                }
                            });
                        }
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => {
                    tracing::warn!(
                        code = "accept_error_flush",
                        "accept error during backlog flush: {err}"
                    );
                    break;
                }
            }
        }
        if accepted == 0 {
            break;
        }
        while graceful.count() > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
    }
    drop(std_listener);
}

/// Serve one (possibly TLS-terminated) connection with the proxy dataplane.
/// Upgrades are enabled on the inbound connection so WebSocket-style 101
/// tunnels can be spliced (generic tunneling; see dwara-core's proxy docs).
fn serve_http_tls<S>(
    watcher: hyper_util::server::graceful::Watcher,
    dp: Arc<DataPlane>,
    stream: S,
    peer: SocketAddr,
    listener: std::sync::Arc<str>,
    hardening: Arc<HttpHardening>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // The auto Connection borrows its Builder, so both live inside the
    // spawned task.
    tokio::spawn(async move {
        // Pre-parse smuggling guard (DW-023): rejects a first request head
        // carrying both Content-Length and Transfer-Encoding before hyper
        // normalizes it away. Rejected connections were already answered.
        let Some(stream) = hardening.guard_connection(stream).await else {
            return;
        };
        let mut auto = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
        // Protocol hardening (DW-023): parser/amplification bounds and the
        // slowloris header timeout on every serving connection. See
        // dwara-core's hardening module for the knob table.
        hardening.apply(&mut auto);
        let conn = watcher.watch(auto.serve_connection_with_upgrades(
            TokioIo::new(stream),
            service_fn(move |mut req| {
                let dp = Arc::clone(&dp);
                let hardening = Arc::clone(&hardening);
                let peer_ip = peer.ip();
                let listener = Arc::clone(&listener);
                // The listener label rides the request extensions so
                // the per-request metrics/logs can attribute traffic
                // to the accepting listener (DW-021).
                req.extensions_mut()
                    .insert(dwara_core::observability::ListenerLabel(listener));
                async move {
                    // Slow-body defense (DW-023): the inbound body is
                    // wrapped with the inactivity-gap timeout BEFORE
                    // the dataplane sees it, so every downstream
                    // consumer (streaming passthrough, retry
                    // buffering) is bounded by the same gap.
                    let (parts, body) = req.into_parts();
                    let req = hyper::Request::from_parts(parts, hardening.wrap_request_body(body));
                    Ok::<_, std::convert::Infallible>(proxy::handle(&dp, peer_ip, req).await)
                }
            }),
        ));
        if let Err(err) = conn.await {
            tracing::warn!("connection error: {err}");
        }
    });
}
