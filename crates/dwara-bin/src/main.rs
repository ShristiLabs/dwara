//! Gateway server binary.
//!
//! M1 role: bind listeners, proxy traffic off the published config
//! snapshot (DW-009), keep that snapshot hot (DW-006), and terminate or
//! pass through TLS (DW-007). Every request is served by
//! [`dwara_core::proxy::handle`] against the generation pair (snapshot +
//! upstream registry) current at request time; a reload swaps the pair
//! under the accept loop without ever interrupting accept, and in-flight
//! requests keep their old pair alive until they complete.
//!
//! Runtime controls (environment):
//! - `DWARA_BIND`: when set, overrides the config listeners with a
//!   single cleartext HTTP listener on that address (test/dev escape
//!   hatch; e.g. `127.0.0.1:8080`). When unset, the gateway binds every
//!   listener defined by the config snapshot.
//! - `DWARA_CONFIG`: path to the gateway YAML config, default `./dwara.yaml`.
//!   Startup fails (exit code 1) if the file cannot be read or does not
//!   validate; every validation issue is printed.
//! - `DWARA_STATE_DB`: path to a SQLite state store (DW-018). When set,
//!   the gateway opens/creates the store at startup and seeds consumers
//!   and credentials from the config into it (see `store::sync_consumers_from_config`
//!   for the interim config-credential hashing story). When unset (the
//!   default), the gateway runs purely on config — behavior identical to
//!   pre-DW-018. Nothing on the request path reads the store yet; the
//!   authenticator (DW-019) wires it in.
//! - `DWARA_SHUTDOWN_TIMEOUT_SECS`: graceful-drain budget on SIGTERM/SIGINT,
//!   default 10. In-flight requests that exceed the budget are dropped when
//!   the process exits.
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
//! Hot reload semantics:
//! - Config file watch + SIGHUP: re-read, validate, `compile_and_publish`
//!   (DW-006 semantics unchanged). On success, terminate listeners'
//!   TLS configurations are rebuilt from the new snapshot and the active
//!   health probe loops (DW-013) are respawned against the new generation
//!   (endpoints persisting across the swap keep their health trackers).
//! - Certificate hot reload: cert/key files of terminate listeners are
//!   watched; a change rebuilds the `ServerConfig` behind an `ArcSwap`
//!   WITHOUT dropping connections. New handshakes use the new material;
//!   in-flight sessions keep the configuration they negotiated.
//! - Documented v1 limitation: the LISTENER BIND SET is taken from the
//!   startup snapshot; adding/removing listeners or changing
//!   address/port takes effect on restart. Only route/config changes
//!   and certificate material reload live.
//!
//! Shutdown: SIGTERM/SIGINT stop accepting on every listener, each
//! listener flushes its kernel backlog (established connections are
//! served), HTTP connections drain via hyper graceful shutdown, and
//! passthrough splices are NOT drained (documented limitation: no drain
//! signaling through a raw TLS pipe; they run until the process exits);
//! whatever remains at the deadline is force-closed by process exit.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use dwara_core::config::{Listener, ListenerProtocol, TlsMode};
use dwara_core::extensions::config_source::{ConfigSource, FileConfigSource};
use dwara_core::proxy::{self, DataPlane};
use dwara_core::snapshot::{ConfigState, Snapshot};
use dwara_core::store::{sync_consumers_from_config, StateStore};
use dwara_core::tls::{self, TlsTermination};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::graceful::GracefulShutdown;
use notify::Watcher;
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, watch};

const DEFAULT_BIND: &str = "127.0.0.1:8080";
const DEFAULT_CONFIG_PATH: &str = "dwara.yaml";
const DEFAULT_SHUTDOWN_TIMEOUT_SECS: u64 = 10;
/// Coalescing window for watcher events: editors and atomic saves emit a
/// burst (write + rename + remove); we wait out the burst, drain the queue,
/// then do exactly one reload.
const RELOAD_DEBOUNCE: Duration = Duration::from_millis(250);

/// Runtime face of one bound listener: what to do with each accepted
/// connection.
enum ListenerMode {
    /// Cleartext HTTP (HTTP/1.1 + h2c via preface sniffing).
    Cleartext,
    /// TLS termination; the `ArcSwap`-backed config hot-reloads.
    Terminate(Arc<TlsTermination>),
    /// TLS passthrough routed by SNI against the current snapshot.
    Passthrough,
}

struct BoundListener {
    name: String,
    addr: String,
    mode: ListenerMode,
}

/// One reload attempt: re-read from disk, validate, publish atomically.
/// Never fatal: on any failure the published snapshot is untouched and the
/// process keeps running. On success, the dataplane's (snapshot, registry)
/// pair is rebuilt (routes and upstream pools hot-swap together; in-flight
/// requests keep the old pair) and terminate listeners' TLS configs are
/// rebuilt from the new snapshot (certificate material follows the config
/// generation it belongs to).
async fn reload(
    state: &ConfigState,
    dp: &DataPlane,
    source: &FileConfigSource,
    trigger: &str,
    tls_states: &BTreeMap<String, Arc<TlsTermination>>,
    probes: &mut dwara_core::active::ActiveProbes,
) {
    let old = state.snapshot();
    match source.load().await {
        Ok(gateway) => match state.compile_and_publish(&gateway) {
            Ok(info) => {
                println!(
                    "config reloaded ({trigger}): generation {} -> {} content_hash={:#x} routes={} \
                     [retiring generation {}; freed when its last in-flight request completes]",
                    old.generation(),
                    info.generation,
                    info.content_hash,
                    info.route_count,
                    old.generation(),
                );
                dp.refresh();
                refresh_tls_states(&state.snapshot(), tls_states, trigger);
                // Active health checks (DW-013): probe loops are per
                // generation — cancel the old tasks and spawn against the
                // new registry. Endpoints whose address:port persists keep
                // their health trackers (carried by the balancer), so an
                // ejection streak survives the swap.
                probes.respawn(&dp.registry(), &state.snapshot());
            }
            Err(err) => {
                // CompileError::Validation's Display lists every issue.
                eprintln!("config reload rejected ({trigger}): {err}");
                eprintln!(
                    "keeping running generation {} (content_hash={:#x})",
                    old.generation(),
                    old.content_hash()
                );
            }
        },
        Err(err) => {
            eprintln!("config reload failed to read source ({trigger}): {err}");
            eprintln!(
                "keeping running generation {} (content_hash={:#x})",
                old.generation(),
                old.content_hash()
            );
        }
    }
}

/// Rebuild every known terminate listener's TLS config from `snapshot`.
/// Listeners are matched by name (the bind set is fixed at startup); a
/// listener that changed mode or vanished from the config keeps its
/// current certificate material until restart (documented limitation).
/// Failures log and keep the previous config.
fn refresh_tls_states(
    snapshot: &Snapshot,
    tls_states: &BTreeMap<String, Arc<TlsTermination>>,
    trigger: &str,
) {
    for (name, term) in tls_states {
        let Some(l) = snapshot
            .gateway()
            .listeners
            .iter()
            .find(|l| &l.name == name)
        else {
            continue;
        };
        let Some(tls_cfg) = &l.tls else {
            continue;
        };
        match term.reload(tls_cfg) {
            Ok(()) => println!("tls config reloaded ({trigger}) for listener {name}"),
            Err(err) => eprintln!(
                "tls reload rejected ({trigger}) for listener {name}: {err}; keeping previous certificates"
            ),
        }
    }
}

/// Notify watcher over a set of directories, forwarding events that touch
/// any of `names` into the async channel. Mirrors the config-watcher
/// pattern (directory watch so atomic rename saves are observed).
fn spawn_file_watcher(
    dirs: Vec<PathBuf>,
    names: Vec<std::ffi::OsString>,
) -> Result<mpsc::UnboundedReceiver<()>, notify::Error> {
    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher =
        notify::recommended_watcher(move |event: Result<notify::Event, notify::Error>| {
            let Ok(event) = event else { return };
            let touches_target = event
                .paths
                .iter()
                .any(|p| p.file_name().is_some_and(|n| names.contains(&n.to_owned())));
            if touches_target {
                let _ = tx.send(());
            }
        })?;
    for dir in &dirs {
        watcher.watch(dir, notify::RecursiveMode::NonRecursive)?;
    }
    let (out_tx, out_rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        let _watcher = watcher;
        while rx.recv().is_ok() {
            let _ = out_tx.send(());
        }
    });
    Ok(out_rx)
}

fn shutdown_timeout() -> Duration {
    std::env::var("DWARA_SHUTDOWN_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(DEFAULT_SHUTDOWN_TIMEOUT_SECS))
}

/// Bind one configured listener into its runtime face. Fails startup on
/// bind errors or unusable TLS material (a gateway must not boot serving
/// the wrong certificates).
async fn bind_listener(
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
async fn run_listener(
    bound: BoundListener,
    listener: TcpListener,
    state: Arc<ConfigState>,
    dp: Arc<DataPlane>,
    graceful: Arc<GracefulShutdown>,
    mut shutdown: watch::Receiver<()>,
    timeout: Duration,
) {
    loop {
        let (mut stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(err) => {
                    eprintln!("accept error on {}: {err}", bound.addr);
                    continue;
                }
            },
            _ = shutdown.changed() => break,
        };
        match &bound.mode {
            ListenerMode::Cleartext => {
                serve_http_tls(graceful.watcher(), Arc::clone(&dp), stream, peer)
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
                            if let Err(err) = tls::handle_passthrough(
                                &mut stream,
                                &tls_cfg,
                                snapshot.gateway(),
                                Some(&dp.registry()),
                            )
                            .await
                            {
                                eprintln!("passthrough error: {err}");
                            }
                        }
                        None => eprintln!(
                            "passthrough listener '{name}' missing from current config; closing connection"
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
                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            serve_http_tls(watcher, dp, tls_stream, peer);
                        }
                        Err(err) => eprintln!("tls handshake error: {err}"),
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
                        ListenerMode::Cleartext => {
                            serve_http_tls(graceful.watcher(), Arc::clone(&dp), stream, peer);
                        }
                        ListenerMode::Terminate(term) => {
                            let acceptor = tokio_rustls::TlsAcceptor::from(term.config());
                            let watcher = graceful.watcher();
                            let dp = Arc::clone(&dp);
                            tokio::spawn(async move {
                                match acceptor.accept(stream).await {
                                    Ok(tls_stream) => serve_http_tls(watcher, dp, tls_stream, peer),
                                    Err(err) => eprintln!("tls handshake error: {err}"),
                                }
                            });
                        }
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => {
                    eprintln!("accept error during backlog flush: {err}");
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
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // The auto Connection borrows its Builder, so both live inside the
    // spawned task.
    tokio::spawn(async move {
        let auto = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
        let conn =
            watcher.watch(auto.serve_connection_with_upgrades(
                TokioIo::new(stream),
                service_fn(move |req| {
                    let dp = Arc::clone(&dp);
                    let peer_ip = peer.ip();
                    async move {
                        Ok::<_, std::convert::Infallible>(proxy::handle(&dp, peer_ip, req).await)
                    }
                }),
            ));
        if let Err(err) = conn.await {
            eprintln!("connection error: {err}");
        }
    });
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tls::install_aws_lc_rs_provider();
    let config_path = PathBuf::from(
        std::env::var("DWARA_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string()),
    );

    let source = FileConfigSource::new(&config_path);
    let state = Arc::new(ConfigState::new());

    // Startup load: a gateway that boots with a bad config must not serve at
    // all. Print every issue, exit non-zero.
    let gateway = match source.load().await {
        Ok(g) => g,
        Err(err) => {
            eprintln!(
                "dwara: startup config load failed for {}: {err}",
                config_path.display()
            );
            std::process::exit(1);
        }
    };
    let info = match state.compile_and_publish(&gateway) {
        Ok(info) => info,
        Err(err) => {
            eprintln!(
                "dwara: startup config invalid for {}: {err}",
                config_path.display()
            );
            std::process::exit(1);
        }
    };

    // Optional SQLite state store (DW-018): opened and seeded from the
    // config when DWARA_STATE_DB is set. Held alive for the process
    // lifetime; the request path does not touch it yet (DW-019 wires the
    // authenticator against it). Unset = pure-config operation (default).
    let _state_store = match std::env::var("DWARA_STATE_DB") {
        Ok(path) if !path.is_empty() => {
            let store = match tokio::task::spawn_blocking({
                let path = path.clone();
                let gateway = gateway.clone();
                move || {
                    StateStore::open(std::path::Path::new(&path)).and_then(|s| {
                        sync_consumers_from_config(&s, &gateway)?;
                        Ok(s)
                    })
                }
            })
            .await
            {
                Ok(inner) => inner,
                Err(err) => {
                    eprintln!("dwara: state store task failed for {path}: {err}");
                    std::process::exit(1);
                }
            };
            match store {
                Ok(store) => {
                    println!(
                        "dwara: state store opened at {path} (schema v1, seeded {} consumer(s) from config)",
                        gateway.consumers.len()
                    );
                    Some(Arc::new(store))
                }
                Err(err) => {
                    eprintln!("dwara: state store init failed for {path}: {err}");
                    std::process::exit(1);
                }
            }
        }
        _ => None,
    };

    // Listener set: DWARA_BIND overrides with one cleartext listener;
    // otherwise bind every configured listener (fixed at startup).
    let env_bind = std::env::var("DWARA_BIND").ok();
    let configured: Vec<Listener> = match &env_bind {
        Some(addr) => {
            let addr = if addr.contains(':') {
                addr.clone()
            } else {
                format!("{addr}:{DEFAULT_BIND_PORT}")
            };
            let (address, port) = addr
                .rsplit_once(':')
                .and_then(|(a, p)| Some((a.to_string(), p.parse().ok()?)))
                .unwrap_or_else(|| (DEFAULT_BIND.to_string(), DEFAULT_BIND_PORT));
            vec![Listener {
                name: "env-bind".into(),
                address,
                port,
                protocol: ListenerProtocol::Http,
                tls: None,
            }]
        }
        None => state.snapshot().gateway().listeners.clone(),
    };
    if configured.is_empty() {
        eprintln!("dwara: config defines no listeners and DWARA_BIND is unset; nothing to serve");
        std::process::exit(1);
    }

    let mut tls_states: BTreeMap<String, Arc<TlsTermination>> = BTreeMap::new();
    let mut bound_listeners = Vec::new();
    for l in &configured {
        let (tcp, bound) = bind_listener(l).await?;
        if let ListenerMode::Terminate(term) = &bound.mode {
            tls_states.insert(bound.name.clone(), Arc::clone(term));
        }
        println!(
            "dwara listening on {} (listener {}, mode {}) [config {} generation {} content_hash={:#x} routes={}]",
            bound.addr,
            bound.name,
            match bound.mode {
                ListenerMode::Cleartext => "cleartext http/1.1+h2c",
                ListenerMode::Terminate(_) => "tls terminate",
                ListenerMode::Passthrough => "tls passthrough",
            },
            config_path.display(),
            info.generation,
            info.content_hash,
            info.route_count
        );
        bound_listeners.push((bound, tcp));
    }

    // Config watcher (DW-006 pattern).
    let watcher_rx = match spawn_file_watcher(
        vec![config_dir(&config_path)],
        vec![config_path
            .file_name()
            .map(std::ffi::OsStr::to_owned)
            .expect("config path has a file name")],
    ) {
        Ok(rx) => rx,
        Err(err) => {
            eprintln!("dwara: config file watch unavailable ({err}); SIGHUP reload still active");
            mpsc::unbounded_channel().1
        }
    };

    // Certificate watcher: one watcher over every parent directory of a
    // terminate listener's cert/key files.
    let mut cert_dirs: Vec<PathBuf> = Vec::new();
    let mut cert_names: Vec<std::ffi::OsString> = Vec::new();
    for term in tls_states.values() {
        for p in &term.watched_paths {
            if let (Some(dir), Some(name)) = (p.parent(), p.file_name()) {
                if !cert_dirs.contains(&dir.to_path_buf()) {
                    cert_dirs.push(dir.to_path_buf());
                }
                if !cert_names.contains(&name.to_owned()) {
                    cert_names.push(name.to_owned());
                }
            }
        }
    }
    let cert_rx = if cert_dirs.is_empty() {
        mpsc::unbounded_channel().1
    } else {
        match spawn_file_watcher(cert_dirs, cert_names) {
            Ok(rx) => rx,
            Err(err) => {
                eprintln!("dwara: certificate watch unavailable ({err}); config reload still refreshes TLS");
                mpsc::unbounded_channel().1
            }
        }
    };

    let graceful = Arc::new(GracefulShutdown::new());
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let mut sighup = signal(SignalKind::hangup())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    // Reload driver: config file events (debounced) and SIGHUP. Owns the
    // active-probe task set (DW-013): initial spawn against the startup
    // generation, respawn on every successful reload, abort-all when the
    // driver returns (graceful shutdown drops it).
    let reload_state = Arc::clone(&state);
    let dp = DataPlane::new(Arc::clone(&state));
    let reload_dp = Arc::clone(&dp);
    let reload_tls = tls_states.clone();
    let reload_shutdown = shutdown_rx.clone();
    let reload_task = tokio::spawn(async move {
        let mut probes = dwara_core::active::ActiveProbes::new();
        probes.respawn(&reload_dp.registry(), &reload_state.snapshot());
        let mut watcher_rx = watcher_rx;
        let mut shutting_down = reload_shutdown;
        loop {
            tokio::select! {
                _ = sighup.recv() => {
                    reload(&reload_state, &reload_dp, &source, "sighup", &reload_tls, &mut probes).await;
                }
                maybe_event = watcher_rx.recv() => {
                    let Some(()) = maybe_event else { break };
                    tokio::select! {
                        _ = tokio::time::sleep(RELOAD_DEBOUNCE) => {}
                        _ = shutting_down.changed() => return,
                    }
                    while watcher_rx.try_recv().is_ok() {}
                    reload(&reload_state, &reload_dp, &source, "file-watch", &reload_tls, &mut probes).await;
                }
                _ = shutting_down.changed() => return,
            }
        }
    });

    // Certificate hot-reload driver: debounce, then rebuild every
    // terminate listener from the current snapshot's TLS config.
    let cert_state = Arc::clone(&state);
    let cert_tls = tls_states.clone();
    let cert_shutdown = shutdown_rx.clone();
    let cert_task = tokio::spawn(async move {
        let mut cert_rx = cert_rx;
        let mut shutting_down = cert_shutdown;
        loop {
            tokio::select! {
                maybe_event = cert_rx.recv() => {
                    let Some(()) = maybe_event else { break };
                    tokio::select! {
                        _ = tokio::time::sleep(RELOAD_DEBOUNCE) => {}
                        _ = shutting_down.changed() => return,
                    }
                    while cert_rx.try_recv().is_ok() {}
                    refresh_tls_states(&cert_state.snapshot(), &cert_tls, "cert-watch");
                }
                _ = shutting_down.changed() => return,
            }
        }
    });

    // Signal waiter: SIGTERM/SIGINT stop accepting everywhere and unblock
    // main for the drain sequence.
    let signal_shutdown_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = sigterm.recv() => println!("dwara: SIGTERM received, draining connections"),
            _ = sigint.recv() => println!("dwara: SIGINT received, draining connections"),
        }
        let _ = signal_shutdown_tx.send(());
    });

    // One accept task per listener; each runs its own backlog flush.
    let timeout = shutdown_timeout();
    let mut tasks = Vec::new();
    for (bound, tcp) in bound_listeners {
        let state = Arc::clone(&state);
        let dp = Arc::clone(&dp);
        let graceful = Arc::clone(&graceful);
        let rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(run_listener(
            bound, tcp, state, dp, graceful, rx, timeout,
        )));
    }

    // Wait for the shutdown signal, then the per-listener backlog flushes.
    let mut main_shutdown = shutdown_rx.clone();
    let _ = main_shutdown.changed().await;
    let shutdown_deadline = tokio::time::Instant::now() + timeout;
    for t in tasks {
        if let Err(err) = t.await {
            eprintln!("dwara: listener task ended with an error: {err}");
        }
    }

    println!(
        "dwara: graceful shutdown ({} live connection(s), timeout {}s)",
        graceful.count(),
        timeout.as_secs()
    );
    reload_task.abort();
    cert_task.abort();

    // Final drain within the shutdown budget; whatever is left when the
    // deadline passes is force-closed by process exit. The deadline is
    // measured from the shutdown signal (the accept tasks already spent
    // part of it flushing their backlogs).
    let deadline = shutdown_deadline;
    let graceful =
        Arc::try_unwrap(graceful).expect("all listener tasks joined; no Arc clones remain");
    let drain = graceful.shutdown();
    let drained = tokio::select! {
        _ = drain => true,
        _ = tokio::time::sleep_until(deadline) => false,
    };
    if !drained {
        eprintln!("dwara: shutdown timeout with connection(s) still draining; forcing exit");
    } else {
        println!("dwara: drained, exiting");
    }
    std::process::exit(0);
}

const DEFAULT_BIND_PORT: u16 = 8080;

fn config_dir(path: &Path) -> PathBuf {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}
