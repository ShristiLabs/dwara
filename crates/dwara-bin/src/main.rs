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
//!   and credentials from the config into it (hashed at seed time; see
//!   `store::sync_consumers_from_config`). When unset (the default), the
//!   gateway runs purely on config — credentials hashed in memory at
//!   startup. The authenticator (DW-019) consults the store when it is
//!   set and config credentials otherwise.
//! - `DWARA_SHUTDOWN_TIMEOUT_SECS`: graceful-drain budget on SIGTERM/SIGINT,
//!   default 10. In-flight requests that exceed the budget are dropped when
//!   the process exits.
//! - `DWARA_LOG` (DW-021): RUST_LOG-syntax filter for the tracing
//!   subscriber, default `dwara=info`. Output is JSON on STDOUT (spans,
//!   structured logs, and the per-request `dwara::access` access-log
//!   lines).
//! - `DWARA_ACCESS_LOG_SAMPLE` (DW-021): fraction of non-error access
//!   lines emitted, 0.0-1.0, default 1.0; 5xx responses are always
//!   logged (see dwara-core's observability docs).
//! - `DWARA_OTLP_ENDPOINT` (DW-021): RESERVED but inert in v1 — the
//!   opentelemetry exporter was deliberately not linked (dep weight vs
//!   the DW-026 musl size budget); the span structure it would export
//!   ships today and is verified in-process by dwara-core's span-capture
//!   test. See dwara-core::observability for the full decision.
//! - `DWARA_ADMIN_DEV` (DW-022): "1" serves the admin API as PLAINTEXT
//!   on 127.0.0.1 — DEV ONLY, refuses to start for a non-loopback
//!   admin bind, and must never be set in production (mTLS is the
//!   admin surface's only authentication). Default: unset = mTLS-only.
//!   See the `dwara-admin` crate docs for the endpoint set.
//! - Protocol hardening (DW-023, feature analysis 4.20): every serving
//!   surface (data-plane listeners AND the admin listener) applies the
//!   knob set documented in dwara-core's `hardening` module — HTTP/1
//!   header-count / read-buffer caps and the slowloris header-read
//!   timeout (`DWARA_HTTP1_MAX_HEADERS`, `DWARA_HTTP1_MAX_BUF_KIB`,
//!   `DWARA_HTTP1_HEADER_TIMEOUT_MS`), HTTP/2 stream/window/send-buffer
//!   caps (`DWARA_H2_MAX_CONCURRENT_STREAMS`, `DWARA_H2_STREAM_WINDOW_KIB`,
//!   `DWARA_H2_CONNECTION_WINDOW_KIB`, `DWARA_H2_MAX_SEND_BUF_KIB`), and
//!   the inbound request-body inactivity gap
//!   (`DWARA_REQUEST_BODY_TIMEOUT_MS`, 0 disables). CL+TE smuggling needs
//!   no knob: hyper 1.x rejects such requests and the gateway rebuilds
//!   every forwarded request from parsed parts (never raw passthrough);
//!   both properties are pinned by dwara-bin's protocol-hardening tests.
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
use dwara_core::hardening::HttpHardening;
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
use tracing_subscriber::EnvFilter;

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
                tracing::info!(
                    code = "config_reloaded",
                    trigger,
                    from_generation = old.generation(),
                    generation = info.generation,
                    routes = info.route_count,
                    "config reloaded: generation {} -> {} content_hash={:#x} routes={} [retiring generation {}; freed when its last in-flight request completes]",
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
                tracing::error!(
                    code = "config_reload_rejected",
                    trigger,
                    "config reload rejected: {err}"
                );
                tracing::error!(
                    code = "config_reload_kept_previous",
                    generation = old.generation(),
                    "keeping running generation {} (content_hash={:#x})",
                    old.generation(),
                    old.content_hash()
                );
            }
        },
        Err(err) => {
            tracing::error!(
                code = "config_reload_read_failed",
                trigger,
                "config reload failed to read source: {err}"
            );
            tracing::error!(
                code = "config_reload_kept_previous",
                generation = old.generation(),
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
            Ok(()) => {
                tracing::info!(code = "tls_reloaded", trigger, listener = %name, "tls config reloaded")
            }
            Err(err) => tracing::warn!(
                code = "tls_reload_rejected",
                trigger,
                listener = %name,
                "tls reload rejected: {err}; keeping previous certificates"
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
#[allow(clippy::too_many_arguments)] // fixed accept-loop plumbing, DW-023 added the hardening handle
async fn run_listener(
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
                            if let Err(err) = tls::handle_passthrough(
                                &mut stream,
                                &tls_cfg,
                                snapshot.gateway(),
                                Some(&dp.registry()),
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Observability init (DW-021): JSON on STDOUT, filtered by DWARA_LOG
    // (RUST_LOG syntax; default dwara=info). Installed FIRST so startup
    // logs flow through the same pipeline as request logs.
    let filter =
        EnvFilter::new(std::env::var("DWARA_LOG").unwrap_or_else(|_| "dwara=info".to_string()));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_target(true)
        .init();
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
            tracing::error!(
                code = "startup_config_load_failed",
                "startup config load failed for {}: {err}",
                config_path.display()
            );
            std::process::exit(1);
        }
    };
    let info = match state.compile_and_publish(&gateway) {
        Ok(info) => info,
        Err(err) => {
            tracing::error!(
                code = "startup_config_invalid",
                "startup config invalid for {}: {err}",
                config_path.display()
            );
            std::process::exit(1);
        }
    };

    // Optional SQLite state store (DW-018): opened and seeded from the
    // config when DWARA_STATE_DB is set. Held alive for the process
    // lifetime and handed to the dataplane's authenticator (DW-019):
    // credentials then resolve from the store's hot cache instead of
    // in-memory config hashes. Unset = pure-config operation (default).
    let state_store = match std::env::var("DWARA_STATE_DB") {
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
                    tracing::error!(
                        code = "state_store_task_failed",
                        "state store task failed for {path}: {err}"
                    );
                    std::process::exit(1);
                }
            };
            match store {
                Ok(store) => {
                    tracing::info!(
                        code = "state_store_opened",
                        consumers = gateway.consumers.len(),
                        "state store opened at {path} (schema v1, seeded consumers from config)"
                    );
                    Some(Arc::new(store))
                }
                Err(err) => {
                    tracing::error!(
                        code = "state_store_init_failed",
                        "state store init failed for {path}: {err}"
                    );
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
        tracing::error!("config defines no listeners and DWARA_BIND is unset; nothing to serve");
        std::process::exit(1);
    }

    let mut tls_states: BTreeMap<String, Arc<TlsTermination>> = BTreeMap::new();
    let mut bound_listeners = Vec::new();
    for l in &configured {
        let (tcp, bound) = bind_listener(l).await?;
        if let ListenerMode::Terminate(term) = &bound.mode {
            tls_states.insert(bound.name.clone(), Arc::clone(term));
        }
        tracing::info!(
            code = "listening",
            addr = %bound.addr,
            listener = %bound.name,
            mode = match bound.mode {
                ListenerMode::Cleartext => "cleartext http/1.1+h2c",
                ListenerMode::Terminate(_) => "tls terminate",
                ListenerMode::Passthrough => "tls passthrough",
            },
            config = %config_path.display().to_string(),
            generation = info.generation,
            routes = info.route_count,
            "dwara listening"
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
            tracing::warn!("config file watch unavailable ({err}); SIGHUP reload still active");
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
                tracing::warn!(
                    "certificate watch unavailable ({err}); config reload still refreshes TLS"
                );
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
    // DW-019: with a state store configured, the authenticator consults
    // the store's hot-cached credential records (config consumers are
    // still its seed source; the store adds admin-managed credentials
    // and Basic-auth records).
    if let Some(store) = &state_store {
        dp.set_state_store(Arc::clone(store));
    }

    // Admin listener (DW-022): started ONLY when the config carries an
    // `admin` block (default: no admin block, no admin listener). The
    // production shape is mTLS-only (decision 6); DWARA_ADMIN_DEV=1 is
    // the plaintext loopback escape hatch for developer machines and is
    // refused outright for non-loopback binds.
    if let Some(admin_cfg) = state.snapshot().gateway().admin.clone() {
        let dev_mode = std::env::var("DWARA_ADMIN_DEV").ok().as_deref() == Some("1");
        let mode = if dev_mode {
            dwara_admin::ListenMode::dev(&admin_cfg)?
        } else {
            dwara_admin::ListenMode::mtls(&admin_cfg)?
        };
        let admin_tcp = tokio::net::TcpListener::bind(&admin_cfg.bind).await?;
        let admin_ctx = Arc::new(dwara_admin::AdminContext::new(
            Arc::clone(&state),
            Arc::clone(&dp),
            config_path.clone(),
        ));
        let admin_shutdown = shutdown_rx.clone();
        let bind_label = admin_cfg.bind.clone();
        tracing::info!(
            code = "admin_listening",
            bind = %bind_label,
            mode = if dev_mode { "DEV PLAINTEXT (loopback only)" } else { "mTLS (client certificate required)" },
            "admin API listening on {bind_label}"
        );
        tokio::spawn(async move {
            if let Err(err) = dwara_admin::serve(admin_ctx, admin_tcp, mode, admin_shutdown).await {
                tracing::error!(code = "admin_server_failed", "admin server ended: {err}");
            }
        });
    }
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
            _ = sigterm.recv() => tracing::info!("SIGTERM received, draining connections"),
            _ = sigint.recv() => tracing::info!("SIGINT received, draining connections"),
        }
        let _ = signal_shutdown_tx.send(());
    });

    // One accept task per listener; each runs its own backlog flush.
    let timeout = shutdown_timeout();
    // Protocol hardening (DW-023): read once, shared by every serving
    // surface (data-plane listeners; the admin listener reads the same
    // env knobs itself — see the dwara-admin serve path).
    let hardening = Arc::new(HttpHardening::from_env());
    tracing::info!(
        code = "protocol_hardening",
        http1_max_headers = hardening.http1_max_headers,
        http1_max_buf_bytes = hardening.http1_max_buf_size,
        http1_header_timeout_ms = hardening.http1_header_read_timeout.as_millis() as u64,
        h2_max_concurrent_streams = hardening.h2_max_concurrent_streams,
        request_body_gap_ms = hardening
            .request_body_gap
            .map(|g| g.as_millis() as u64)
            .unwrap_or(0),
        "protocol hardening enabled (DW-023)"
    );
    let mut tasks = Vec::new();
    for (bound, tcp) in bound_listeners {
        let state = Arc::clone(&state);
        let dp = Arc::clone(&dp);
        let graceful = Arc::clone(&graceful);
        let rx = shutdown_rx.clone();
        let hardening = Arc::clone(&hardening);
        tasks.push(tokio::spawn(run_listener(
            bound, tcp, state, dp, graceful, rx, timeout, hardening,
        )));
    }

    // Wait for the shutdown signal, then the per-listener backlog flushes.
    let mut main_shutdown = shutdown_rx.clone();
    let _ = main_shutdown.changed().await;
    let shutdown_deadline = tokio::time::Instant::now() + timeout;
    for t in tasks {
        if let Err(err) = t.await {
            tracing::warn!("listener task ended with an error: {err}");
        }
    }

    tracing::info!(
        live_connections = graceful.count(),
        timeout_s = timeout.as_secs(),
        "graceful shutdown"
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
        tracing::warn!("shutdown timeout with connection(s) still draining; forcing exit");
    } else {
        tracing::info!("drained, exiting");
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
