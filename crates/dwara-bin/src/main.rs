//! Gateway server binary.
//!
//! M1 role: bind a listener, serve traffic off the published config
//! snapshot, and keep that snapshot hot (DW-006). The response body is
//! still the hello placeholder (real proxying lands with the dataplane
//! issues), but every request is served from the current `Snapshot`
//! obtained per-request from [`ConfigState`], so a reload swaps the
//! generation under the accept loop without ever interrupting accept.
//!
//! Runtime controls (environment):
//! - `DWARA_BIND`: listen address, default `127.0.0.1:8080`.
//! - `DWARA_CONFIG`: path to the gateway YAML config, default `./dwara.yaml`.
//!   Startup fails (exit code 1) if the file cannot be read or does not
//!   validate; every validation issue is printed.
//! - `DWARA_SHUTDOWN_TIMEOUT_SECS`: graceful-drain budget on SIGTERM/SIGINT,
//!   default 10. In-flight requests that exceed the budget are dropped when
//!   the process exits.
//!
//! Reload semantics (feature analysis 4.18 / 9.2):
//! - File watch (notify, watching the config file's directory so atomic
//!   rename/replace is observed) and SIGHUP both re-read the file from disk,
//!   validate, and `compile_and_publish`. Success logs the generation
//!   transition; the previous generation retires when the last in-flight
//!   request holding its `Arc<Snapshot>` completes (retirement here means
//!   the old `Arc` is dropped; the process never waits on it).
//! - A rejected reload (parse or validation failure) logs every
//!   `ValidationIssue` and keeps serving the currently published snapshot.
//!   The process does not exit on a bad reload.
//! - SIGTERM/SIGINT: stop accepting, signal every live connection to drain
//!   (hyper graceful shutdown), wait up to the timeout, then exit 0.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use dwara_core::extensions::config_source::{ConfigSource, FileConfigSource};
use dwara_core::snapshot::ConfigState;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::CONTENT_TYPE;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
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

/// Serve the hello response from the snapshot generation current at request
/// time. Holding the `Arc<Snapshot>` for the request's lifetime is what
/// makes generation retirement safe: the old snapshot is freed only after
/// the last request referencing it completes.
async fn hello(
    state: Arc<ConfigState>,
    _: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let _current_generation = state.snapshot();
    Ok(Response::builder()
        .header(CONTENT_TYPE, "text/plain")
        .body(Full::new(Bytes::from_static(b"dwara")))
        .expect("static response is valid"))
}

/// One reload attempt: re-read from disk, validate, publish atomically.
/// Never fatal: on any failure the published snapshot is untouched and the
/// process keeps running.
async fn reload(state: &ConfigState, source: &FileConfigSource, trigger: &str) {
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

fn spawn_config_watcher(config_path: &Path) -> Result<mpsc::UnboundedReceiver<()>, notify::Error> {
    // Watch the parent directory, not the file: atomic config deployment
    // (write temp + rename) never mutates the watched inode, it replaces the
    // directory entry, so a file-only watch would miss it.
    let watch_dir = config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let file_name = config_path
        .file_name()
        .map(std::ffi::OsStr::to_owned)
        .expect("config path has a file name");

    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher =
        notify::recommended_watcher(move |event: Result<notify::Event, notify::Error>| {
            let Ok(event) = event else { return };
            let touches_target = event
                .paths
                .iter()
                .any(|p| p.file_name() == Some(&file_name));
            if touches_target {
                let _ = tx.send(());
            }
        })?;
    watcher.watch(&watch_dir, notify::RecursiveMode::NonRecursive)?;

    let (out_tx, out_rx) = mpsc::unbounded_channel();
    // Keep the watcher alive for the process lifetime; forward filtered
    // events into the async world.
    std::thread::spawn(move || {
        let _watcher = watcher; // moved here so it stays alive
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = std::env::var("DWARA_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
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

    let listener = TcpListener::bind(&addr).await?;
    println!(
        "dwara listening on {addr} (config {} generation {} content_hash={:#x} routes={})",
        config_path.display(),
        info.generation,
        info.content_hash,
        info.route_count
    );

    let watcher_rx = match spawn_config_watcher(&config_path) {
        Ok(rx) => rx,
        Err(err) => {
            // Watching is an availability optimization, not a correctness
            // requirement: SIGHUP reload still works without it.
            eprintln!("dwara: config file watch unavailable ({err}); SIGHUP reload still active");
            mpsc::unbounded_channel().1
        }
    };

    let graceful = GracefulShutdown::new();
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let mut sighup = signal(SignalKind::hangup())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    // Reload driver: multiplexes watcher events (debounced) and SIGHUP into
    // the single reload path.
    let reload_state = Arc::clone(&state);
    let reload_shutdown = shutdown_rx.clone();
    let reload_task = tokio::spawn(async move {
        let mut watcher_rx = watcher_rx;
        let mut shutting_down = reload_shutdown;
        loop {
            tokio::select! {
                _ = sighup.recv() => {
                    reload(&reload_state, &source, "sighup").await;
                }
                maybe_event = watcher_rx.recv() => {
                    let Some(()) = maybe_event else { break };
                    // Debounce: wait out the event burst, drain the queue,
                    // reload once.
                    tokio::select! {
                        _ = tokio::time::sleep(RELOAD_DEBOUNCE) => {}
                        _ = shutting_down.changed() => return,
                    }
                    while watcher_rx.try_recv().is_ok() {}
                    reload(&reload_state, &source, "file-watch").await;
                }
                _ = shutting_down.changed() => return,
            }
        }
    });

    // Accept loop: never blocked by reloads; exits only on shutdown signal.
    let serve_state = Arc::clone(&state);
    let mut accept_shutdown = shutdown_rx.clone();
    let serve = |stream: tokio::net::TcpStream| {
        let state = Arc::clone(&serve_state);
        let conn = graceful.watch(hyper::server::conn::http1::Builder::new().serve_connection(
            TokioIo::new(stream),
            service_fn(move |req| {
                let state = Arc::clone(&state);
                async move { hello(state, req).await }
            }),
        ));
        tokio::spawn(async move {
            if let Err(err) = conn.await {
                eprintln!("connection error: {err}");
            }
        });
    };

    // Signal waiter: SIGTERM/SIGINT stop accepting (via the watch channel)
    // and unblock main for the drain sequence.
    let signal_shutdown_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = sigterm.recv() => println!("dwara: SIGTERM received, draining connections"),
            _ = sigint.recv() => println!("dwara: SIGINT received, draining connections"),
        }
        let _ = signal_shutdown_tx.send(());
    });

    loop {
        let (stream, _peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(err) => {
                    eprintln!("accept error: {err}");
                    continue;
                }
            },
            _ = accept_shutdown.changed() => break,
        };
        serve(stream);
    }

    let timeout = shutdown_timeout();
    println!(
        "dwara: graceful shutdown ({} live connection(s), timeout {}s)",
        graceful.count(),
        timeout.as_secs()
    );
    reload_task.abort();

    // Backlog flush: connections that completed TCP handshake into the
    // kernel backlog but were not yet accepted would be reset when the
    // listener drops. Loop "accept what is queued, wait for it to finish"
    // until a pass accepts nothing: SYNs already in flight when shutdown
    // began still get served, so no established connection is dropped.
    let std_listener = listener.into_std()?;
    std_listener.set_nonblocking(true)?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let mut accepted = 0usize;
        loop {
            match std_listener.accept() {
                Ok((stream, _)) => {
                    accepted += 1;
                    stream.set_nonblocking(true)?;
                    serve(tokio::net::TcpStream::from_std(stream)?);
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

    // Final drain within the remaining budget; whatever is left when the
    // deadline passes is force-closed by process exit.
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    let drain = graceful.shutdown();
    let drained = tokio::select! {
        _ = drain => true,
        _ = tokio::time::sleep(remaining) => false,
    };
    if !drained {
        eprintln!("dwara: shutdown timeout with connection(s) still draining; forcing exit");
    } else {
        println!("dwara: drained, exiting");
    }
    std::process::exit(0);
}
