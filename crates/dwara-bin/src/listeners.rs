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
//! running).

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
        match &bound.mode {
            ListenerMode::Cleartext => serve_http_tls(
                graceful.watcher(),
                Arc::clone(&dp),
                stream,
                peer,
                std::sync::Arc::from(bound.name.as_str()),
                Arc::clone(&hardening),
                None,
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
                        match &bound.mode {
                            ListenerMode::Passthrough => {}
                            ListenerMode::Cleartext => serve_http_tls(
                                graceful.watcher(),
                                Arc::clone(&dp),
                                stream,
                                peer,
                                std::sync::Arc::from(bound.name.as_str()),
                                Arc::clone(&hardening),
                                None,
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

/// Supervise one listener's accept task for panics (#120): when an
/// incarnation ends cleanly (shutdown flush completed) supervision is
/// done; when it panics it is respawned up to `max_respawns` times with
/// a warning per respawn, and after the cap an ERROR is logged and the
/// listener is left down — loudly, but without aborting the process (a
/// dead listener must not take the other listeners and in-flight work
/// with it; that is not the shutdown idiom anywhere else either).
///
/// `spawn` builds one incarnation; it is called once immediately and
/// once per respawn, so it must hand each incarnation fresh clones of
/// everything the accept loop consumes.
async fn supervise_panics(
    label: &str,
    max_respawns: u32,
    mut spawn: impl FnMut() -> tokio::task::JoinHandle<()>,
) {
    let mut respawns = 0u32;
    loop {
        let task = spawn();
        match task.await {
            // Clean return: the shutdown flush finished (or the task
            // ended deliberately). Nothing to supervise anymore.
            Ok(()) => return,
            Err(err) if err.is_panic() => {
                if respawns >= max_respawns {
                    tracing::error!(
                        code = "listener_respawn_exhausted",
                        listener = %label,
                        respawns,
                        "accept loop panicked again after {respawns} respawns; giving up: listener is DOWN, other listeners keep serving"
                    );
                    return;
                }
                respawns += 1;
                tracing::warn!(
                    code = "listener_respawn",
                    listener = %label,
                    respawns,
                    "accept task panicked ({err}); respawning listener accept loop"
                );
            }
            // JoinError without a panic only occurs on cancellation,
            // which this code never does: treat it as a clean end.
            Err(_) => return,
        }
    }
}

/// Bind the supervision of one listener's accept task (#120): every
/// respawn reuses the same bound socket (shared `Arc`) and clones of
/// the serve plumbing, so a panicked accept loop cannot kill a listener
/// silently.
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
    supervise_panics(&bound.name, MAX_LISTENER_RESPAWNS, || {
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
    })
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
                    Ok::<_, std::convert::Infallible>(proxy::handle(&dp, peer_ip, req).await)
                }
            }),
        ));
        if let Err(err) = conn.await {
            tracing::warn!("connection error: {err}");
        }
    });
}

#[cfg(test)]
mod tests {
    // White-box tests staying in src/ per AGENTS.md: the panic
    // supervisor is pub(crate) inside the binary crate, so the panic
    // boundary (JoinHandle::is_panic + bounded respawn) cannot be
    // exercised through the binary's public surface from tests/ —
    // inducing a real accept-loop panic is not expressible externally.

    use std::sync::atomic::{AtomicU32, Ordering};

    use super::supervise_panics;

    /// Silences (and counts) the default panic hook for spawned-task
    /// panics so these tests do not spray backtraces into the log; the
    /// original hook is restored on drop.
    struct PanicHookQuiet {
        prev: Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync>,
    }

    impl PanicHookQuiet {
        fn install() -> Self {
            let prev = std::panic::take_hook();
            std::panic::set_hook(Box::new(|_info| {}));
            PanicHookQuiet { prev }
        }
    }

    impl Drop for PanicHookQuiet {
        fn drop(&mut self) {
            let prev = std::mem::replace(
                &mut self.prev,
                Box::new(|_info: &std::panic::PanicHookInfo| {}),
            );
            std::panic::set_hook(prev);
        }
    }

    #[tokio::test]
    async fn panicking_incarnations_are_respawned_up_to_the_cap_then_given_up() {
        let _quiet = PanicHookQuiet::install();
        let spawns = AtomicU32::new(0);
        supervise_panics("test-listener", 3, || {
            spawns.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async { panic!("induced accept-loop panic") })
        })
        .await;
        // One initial incarnation plus three respawns; the fourth panic
        // exhausts the budget and supervision returns (listener left
        // down loudly, process keeps running).
        assert_eq!(spawns.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn clean_incarnation_ends_supervision_without_respawn() {
        let spawns = AtomicU32::new(0);
        supervise_panics("test-listener", 3, || {
            spawns.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async {})
        })
        .await;
        assert_eq!(spawns.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn respawned_incarnation_ending_cleanly_stops_supervision() {
        let _quiet = PanicHookQuiet::install();
        let spawns = AtomicU32::new(0);
        supervise_panics("test-listener", 3, || {
            let n = spawns.fetch_add(1, Ordering::SeqCst);
            // First incarnation panics; the respawn recovers and ends
            // cleanly (the real-world recovery path: respawn serves the
            // shutdown flush and returns Ok).
            if n == 0 {
                tokio::spawn(async { panic!("induced accept-loop panic") })
            } else {
                tokio::spawn(async {})
            }
        })
        .await;
        assert_eq!(spawns.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn exhausted_respawn_budget_leaves_sibling_listeners_serving() {
        // Process-stays-up analog (#120): inducing a REAL accept-loop
        // panic in the spawned binary is not externally expressible, so
        // the containment property is pinned here — while one listener
        // panics through its entire respawn budget (and supervision
        // gives up on it), an independent sibling accept loop keeps
        // serving both during and after the failure. The process-level
        // guarantee this models: a dead listener never takes the other
        // listeners down with it.
        let _quiet = PanicHookQuiet::install();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let sibling = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut served = 0usize;
            while served < 2 {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let mut one = [0u8; 1];
                if sock.read(&mut one).await.is_ok() {
                    let _ = sock.write_all(b"up").await;
                    served += 1;
                }
            }
        });
        // Budget of one: initial incarnation panics, one respawn panics
        // again, supervision logs the give-up and RETURNS.
        supervise_panics("doomed", 1, || {
            tokio::spawn(async { panic!("induced accept-loop panic") })
        })
        .await;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for _ in 0..2 {
            let mut sock = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                tokio::net::TcpStream::connect(addr),
            )
            .await
            .expect("sibling connect within timeout")
            .expect("sibling listener is still up");
            sock.write_all(b"x").await.expect("probe write");
            let mut got = [0u8; 2];
            tokio::time::timeout(std::time::Duration::from_secs(2), sock.read_exact(&mut got))
                .await
                .expect("sibling reply within timeout")
                .expect("sibling reply read");
            assert_eq!(&got, b"up", "sibling listener still serves");
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), sibling)
            .await
            .expect("sibling task finishes")
            .expect("sibling task ended cleanly");
    }
}
