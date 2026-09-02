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
//!
//! Every accept task runs under panic supervision (#120): a panicked
//! accept loop is respawned on the same bound socket, up to
//! [`MAX_LISTENER_RESPAWNS`] times, after which the listener is given up
//! on with an ERROR log (the process and the other listeners keep
//! running). The supervisor itself lives in
//! [`dwara_core::supervision`] and is shared with the admin accept loop
//! (#130); only the listener budget and wiring live here.
//!
//! PROXY protocol (DW-030): a listener with `proxy_protocol: true` has
//! a v1/v2 header read as the first bytes of every connection — before
//! the TLS handshake in terminate mode (the L4 LB wraps the whole
//! stream) — and the header's source address becomes the peer the whole
//! pipeline sees (ACL, rate keys, XFF/X-Real-IP). Malformed headers fail
//! closed with a 400 envelope; see [`proxy_phase`] and
//! `dwara_core::dataplane::proxy_proto` for the frozen policy.

use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};
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
#[derive(Clone)]
pub(crate) enum ListenerMode {
    /// Cleartext HTTP (HTTP/1.1 + h2c via preface sniffing).
    Cleartext,
    /// TLS termination; the `ArcSwap`-backed config hot-reloads.
    Terminate(Arc<TlsTermination>),
    /// TLS passthrough routed by SNI against the current snapshot.
    Passthrough,
}

/// Cloneable so the panic supervisor (#120) can hand a fresh copy to
/// every respawned incarnation of the accept loop.
#[derive(Clone)]
pub(crate) struct BoundListener {
    pub(crate) name: String,
    pub(crate) addr: String,
    pub(crate) mode: ListenerMode,
    /// PROXY protocol v1/v2 acceptance (DW-030): read a PROXY header as
    /// the first bytes of every connection and use its source address as
    /// the effective peer. Part of the restart-only bind set: the flag is
    /// captured at bind time and is NOT hot-reloaded (toggling it takes a
    /// restart, exactly like address/port).
    pub(crate) proxy_protocol: bool,
    /// DW-088: Alt-Svc header value to advertise on H1/H2 responses
    /// (tells clients that HTTP/3 is available). None = no alt-svc
    /// header. Hot-reloaded (read from the current snapshot at bind
    /// time; a config reload rebinds with the new value).
    pub(crate) alt_svc: Option<Arc<str>>,
}

/// Bind one configured listener into its runtime face. Fails startup on
/// bind errors or unusable TLS material (a gateway must not boot serving
/// the wrong certificates).
///
/// The socket is bound with `SO_REUSEPORT` (DW-049) so a new process can
/// bind the same port during a zero-downtime upgrade hand-off. The bind
/// helper lives in `upgrade::bind_with_reuse_port`.
pub(crate) async fn bind_listener(
    l: &Listener,
) -> Result<(TcpListener, BoundListener), Box<dyn std::error::Error + Send + Sync>> {
    let addr = format!("{}:{}", l.address, l.port);
    let parsed: SocketAddr = addr
        .parse()
        .map_err(|err| format!("invalid listener address {addr}: {err}"))?;
    let listener = crate::upgrade::bind_with_reuse_port(parsed)?;
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
        // DW-088: H3 listeners are handled separately in main.rs (they
        // bind UDP, not TCP). bind_listener is never called for H3
        // listeners; this arm is unreachable (main.rs skips H3 before
        // calling bind_listener). If reached, return an error.
        ListenerProtocol::H3 => {
            return Err(format!(
                "h3 listener {} should not reach bind_listener (handled in main.rs)",
                l.name
            )
            .into());
        }
    };
    Ok((
        listener,
        BoundListener {
            name: l.name.clone(),
            addr,
            mode,
            proxy_protocol: l.proxy_protocol,
            alt_svc: l.alt_svc.as_ref().map(|s| Arc::from(s.as_str())),
        },
    ))
}

/// Per-listener accept loop with its own backlog flush (the DW-006 drain
/// sequence, per listener). Returns when shutdown is signalled and the
/// backlog is flushed. Takes the socket behind an `Arc` shared with the
/// panic supervisor (#120): a respawned incarnation accepts on the SAME
/// bound socket instead of re-binding (no port-loss window, no bind
/// race with lingering state).
#[allow(clippy::too_many_arguments)] // fixed accept-loop plumbing, DW-023 added the hardening handle
pub(crate) async fn run_listener(
    bound: BoundListener,
    listener: Arc<TcpListener>,
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
        // DW-088: clone alt_svc once per iteration so it can be moved
        // into spawned tasks without borrowing bound across the spawn.
        let alt_svc = bound.alt_svc.clone();
        match &bound.mode {
            ListenerMode::Cleartext => {
                // DW-030: on a proxy_protocol listener the header phase
                // runs BEFORE the smuggling sniff / HTTP parsing; the
                // non-PROXY path stays byte-for-byte what it was.
                if bound.proxy_protocol {
                    let watcher = graceful.watcher();
                    let dp = Arc::clone(&dp);
                    let hardening_phase = Arc::clone(&hardening);
                    let listener: std::sync::Arc<str> = std::sync::Arc::from(bound.name.as_str());
                    let hardening = Arc::clone(&hardening);
                    let alt_svc = alt_svc.clone();
                    tokio::spawn(async move {
                        let mut stream = stream;
                        let Some((peer, prefix)) = proxy_phase(
                            &mut stream,
                            peer,
                            hardening_phase.http1_header_read_timeout,
                        )
                        .await
                        else {
                            return;
                        };
                        let stream =
                            dwara_core::dataplane::hardening::PrefixedStream::new(stream, prefix);
                        serve_http_tls(
                            watcher, dp, stream, peer, listener, hardening, None, alt_svc,
                        );
                    });
                } else {
                    serve_http_tls(
                        graceful.watcher(),
                        Arc::clone(&dp),
                        stream,
                        peer,
                        std::sync::Arc::from(bound.name.as_str()),
                        Arc::clone(&hardening),
                        None,
                        alt_svc.clone(),
                    );
                }
            }
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
                let hardening_phase = Arc::clone(&hardening);
                let hardening = Arc::clone(&hardening);
                let listener: std::sync::Arc<str> = std::sync::Arc::from(bound.name.as_str());
                let proxy_protocol = bound.proxy_protocol;
                tokio::spawn(async move {
                    // DW-030: the PROXY header (when the listener expects
                    // one) wraps the WHOLE stream — the L4 LB sits in
                    // front of the TLS handshake, so the header is read
                    // before rustls sees a byte. Bytes read past the
                    // header are replayed in front of the TLS records.
                    let mut stream = stream;
                    let (peer, prefix) = if proxy_protocol {
                        let Some(derived) = proxy_phase(
                            &mut stream,
                            peer,
                            hardening_phase.http1_header_read_timeout,
                        )
                        .await
                        else {
                            return;
                        };
                        derived
                    } else {
                        (peer, Vec::new())
                    };
                    let stream =
                        dwara_core::dataplane::hardening::PrefixedStream::new(stream, prefix);
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            // #124 mTLS authn: when the listener carries a
                            // client_ca_file, rustls has VERIFIED any
                            // presented certificate against it (an
                            // unverified one fails the handshake above).
                            // Extract the verified leaf's match values
                            // once per connection; the request service
                            // inserts them into the extensions so the
                            // authenticator's ambient mTLS family can map
                            // the certificate to a consumer.
                            let client_cert = tls_stream
                                .get_ref()
                                .1
                                .peer_certificates()
                                .and_then(|certs| certs.first())
                                .map(|cert| {
                                    Arc::new(dwara_core::authn::ClientCertificate::from_cert(cert))
                                });
                            serve_http_tls(
                                watcher,
                                dp,
                                tls_stream,
                                peer,
                                listener,
                                hardening,
                                client_cert,
                                alt_svc.clone(),
                            );
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
    // The socket stays behind the shared Arc (the supervisor may respawn
    // this loop), so instead of into_std the flush drains it with
    // poll_accept under a no-op waker: that is a non-blocking accept
    // with identical semantics to the old std nonblocking loop.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let mut accepted = 0usize;
        // The poll Context is scoped to the non-async drain below: it is
        // not Send (raw waker pointer) and must not be live across the
        // awaits in the wait loops.
        {
            let waker = std::task::Waker::noop();
            let mut cx = Context::from_waker(waker);
            loop {
                match listener.poll_accept(&mut cx) {
                    Poll::Ready(Ok((stream, peer))) => {
                        accepted += 1;
                        let alt_svc = bound.alt_svc.clone();
                        match &bound.mode {
                            ListenerMode::Passthrough => {}
                            ListenerMode::Cleartext => {
                                if bound.proxy_protocol {
                                    let watcher = graceful.watcher();
                                    let dp = Arc::clone(&dp);
                                    let hardening_phase = Arc::clone(&hardening);
                                    let hardening = Arc::clone(&hardening);
                                    let listener: std::sync::Arc<str> =
                                        std::sync::Arc::from(bound.name.as_str());
                                    let alt_svc = alt_svc.clone();
                                    tokio::spawn(async move {
                                        let mut stream = stream;
                                        let Some((peer, prefix)) = proxy_phase(
                                            &mut stream,
                                            peer,
                                            hardening_phase.http1_header_read_timeout,
                                        )
                                        .await
                                        else {
                                            return;
                                        };
                                        let stream =
                                            dwara_core::dataplane::hardening::PrefixedStream::new(
                                                stream, prefix,
                                            );
                                        serve_http_tls(
                                            watcher, dp, stream, peer, listener, hardening, None,
                                            alt_svc,
                                        );
                                    });
                                } else {
                                    serve_http_tls(
                                        graceful.watcher(),
                                        Arc::clone(&dp),
                                        stream,
                                        peer,
                                        std::sync::Arc::from(bound.name.as_str()),
                                        Arc::clone(&hardening),
                                        None,
                                        alt_svc.clone(),
                                    );
                                }
                            }
                            ListenerMode::Terminate(term) => {
                                let acceptor = tokio_rustls::TlsAcceptor::from(term.config());
                                let watcher = graceful.watcher();
                                let dp = Arc::clone(&dp);
                                let hardening_phase = Arc::clone(&hardening);
                                let hardening = Arc::clone(&hardening);
                                let listener: std::sync::Arc<str> =
                                    std::sync::Arc::from(bound.name.as_str());
                                let proxy_protocol = bound.proxy_protocol;
                                tokio::spawn(async move {
                                    let mut stream = stream;
                                    let (peer, prefix) = if proxy_protocol {
                                        let Some(derived) = proxy_phase(
                                            &mut stream,
                                            peer,
                                            hardening_phase.http1_header_read_timeout,
                                        )
                                        .await
                                        else {
                                            return;
                                        };
                                        derived
                                    } else {
                                        (peer, Vec::new())
                                    };
                                    let stream =
                                        dwara_core::dataplane::hardening::PrefixedStream::new(
                                            stream, prefix,
                                        );
                                    match acceptor.accept(stream).await {
                                        Ok(tls_stream) => {
                                            let client_cert = tls_stream
                                                .get_ref()
                                                .1
                                                .peer_certificates()
                                                .and_then(|certs| certs.first())
                                                .map(|cert| {
                                                    Arc::new(
                                                        dwara_core::authn::ClientCertificate::from_cert(
                                                            cert,
                                                        ),
                                                    )
                                                });
                                            serve_http_tls(
                                                watcher,
                                                dp,
                                                tls_stream,
                                                peer,
                                                listener,
                                                hardening,
                                                client_cert,
                                                alt_svc.clone(),
                                            )
                                        }
                                        Err(err) => {
                                            tracing::warn!("tls handshake error: {err}")
                                        }
                                    }
                                });
                            }
                        }
                    }
                    Poll::Pending => break,
                    Poll::Ready(Err(err)) if err.kind() == std::io::ErrorKind::Interrupted => {
                        continue;
                    }
                    Poll::Ready(Err(err)) => {
                        tracing::warn!(
                            code = "accept_error_flush",
                            "accept error during backlog flush: {err}"
                        );
                        break;
                    }
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
}

/// #120 panic policy: how many times a listener whose accept loop
/// panicked is respawned before the listener is given up on. Total per
/// listener for the process lifetime (a simple bounded budget; a
/// crash-looping listener stops after this many respawns instead of
/// spinning forever).
pub(crate) const MAX_LISTENER_RESPAWNS: u32 = 8;

/// PROXY protocol phase for one accepted connection (DW-030). Reads the
/// v1/v2 header (when the listener is a `proxy_protocol` listener) and
/// returns the EFFECTIVE peer address plus any bytes read past the
/// header (a sender pipelining TLS records / the HTTP head behind the
/// PROXY line) for replay in front of the stream. Returns None when the
/// connection was rejected and closed: a malformed header is answered
/// with the 400 error envelope (fail closed — never handed to HTTP
/// parsing), a stalled or dropped header read closes silently. The
/// deadline is the DW-023 slowloris header timeout — the same attack
/// class, one layer earlier (a partial PROXY line cannot be handed on,
/// so this is a WHOLE-header bound, not per-read).
async fn proxy_phase<S>(
    stream: &mut S,
    real: SocketAddr,
    header_timeout: Duration,
) -> Option<(SocketAddr, Vec<u8>)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match dwara_core::dataplane::proxy_proto::read_client_addr(stream, real, header_timeout).await {
        Ok(h) => Some((h.client, h.prefix)),
        Err(e @ dwara_core::dataplane::proxy_proto::ProxyProtoError::Malformed(_)) => {
            tracing::warn!(
                code = "proxy_protocol_malformed",
                "closing connection with a malformed PROXY header: {e}"
            );
            let _ = dwara_core::dataplane::proxy_proto::reject_malformed(stream).await;
            None
        }
        Err(e) => {
            // Incomplete (deadline) or IO (EOF/reset) mid-header:
            // nothing parseable to answer; close.
            tracing::debug!(
                code = "proxy_protocol_incomplete",
                "closing connection whose PROXY header did not complete: {e}"
            );
            None
        }
    }
}

/// Bind the supervision of one listener's accept task (#120): every
/// respawn reuses the same bound socket (shared `Arc`) and clones of
/// the serve plumbing, so a panicked accept loop cannot kill a listener
/// silently. The supervisor is [`dwara_core::supervision::supervise_panics`]
/// (shared with the admin accept loop since #130); its semantics tests
/// live beside it in dwara-core.
#[allow(clippy::too_many_arguments)] // mirrors run_listener's fixed plumbing
pub(crate) async fn run_listener_supervised(
    bound: BoundListener,
    listener: Arc<TcpListener>,
    state: Arc<ConfigState>,
    dp: Arc<DataPlane>,
    graceful: Arc<GracefulShutdown>,
    // Pin: never poll this outer receiver (changed()/borrow_and_update) —
    // each clone inherits its seen version, and only the never-updated
    // initial version makes a respawned incarnation's changed() fire
    // immediately for an already-sent shutdown.
    shutdown: watch::Receiver<()>,
    timeout: Duration,
    hardening: Arc<HttpHardening>,
) {
    dwara_core::supervision::supervise_panics(
        "listener",
        &bound.name,
        MAX_LISTENER_RESPAWNS,
        || {
            tokio::spawn(run_listener(
                bound.clone(),
                Arc::clone(&listener),
                Arc::clone(&state),
                Arc::clone(&dp),
                Arc::clone(&graceful),
                shutdown.clone(),
                timeout,
                Arc::clone(&hardening),
            ))
        },
    )
    .await;
}

/// Serve one (possibly TLS-terminated) connection with the proxy dataplane.
/// Upgrades are enabled on the inbound connection so WebSocket-style 101
/// tunnels can be spliced (generic tunneling; see dwara-core's proxy docs).
/// `client_cert` is the VERIFIED client certificate when the TLS layer
/// requested one (#124); it rides the request extensions to the
/// authenticator's ambient mTLS family.
#[allow(clippy::too_many_arguments)] // fixed accept-loop plumbing, #124 added the client cert
fn serve_http_tls<S>(
    watcher: hyper_util::server::graceful::Watcher,
    dp: Arc<DataPlane>,
    stream: S,
    peer: SocketAddr,
    listener: std::sync::Arc<str>,
    hardening: Arc<HttpHardening>,
    client_cert: Option<Arc<dwara_core::authn::ClientCertificate>>,
    alt_svc: Option<std::sync::Arc<str>>,
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
                let client_cert = client_cert.clone();
                let alt_svc = alt_svc.clone();
                // The listener label rides the request extensions so
                // the per-request metrics/logs can attribute traffic
                // to the accepting listener (DW-021); the verified
                // client certificate rides the same way (#124).
                req.extensions_mut()
                    .insert(dwara_core::observability::ListenerLabel(listener));
                if let Some(cert) = client_cert {
                    req.extensions_mut().insert(cert);
                }
                async move {
                    // Slow-body defense (DW-023): the inbound body is
                    // wrapped with the inactivity-gap timeout BEFORE
                    // the dataplane sees it, so every downstream
                    // consumer (streaming passthrough, retry
                    // buffering) is bounded by the same gap.
                    let (parts, body) = req.into_parts();
                    let req = hyper::Request::from_parts(parts, hardening.wrap_request_body(body));
                    let mut resp = proxy::handle(&dp, peer_ip, req).await;
                    // DW-088: inject the Alt-Svc header on every
                    // response from this listener (the listener's
                    // alt_svc config advertises the H3 port).
                    if let Some(alt_svc) = &alt_svc {
                        if let Ok(value) = hyper::header::HeaderValue::from_str(alt_svc) {
                            resp.headers_mut().insert(hyper::header::ALT_SVC, value);
                        }
                    }
                    Ok::<_, std::convert::Infallible>(resp)
                }
            }),
        ));
        if let Err(err) = conn.await {
            tracing::warn!("connection error: {err}");
        }
    });
}
