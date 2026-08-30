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
//! - `DWARA_OTLP_ENDPOINT` (DW-021, #126): base OTLP collector endpoint
//!   (e.g. `http://collector:4318`; `/v1/traces` is appended). LIVE only
//!   when the binary is built with the default-off `otlp` cargo feature —
//!   the opentelemetry stack is real megabytes against the DW-026 musl
//!   size budget, so the default build keeps this variable reserved but
//!   INERT (spans still exist; only the wire exporter is absent —
//!   dwara-core::observability documents the decision, the bin's `otlp`
//!   module the wiring). With the feature enabled and the variable set,
//!   the root/phase spans export over http/protobuf and are flushed
//!   (bounded) on the SIGTERM/SIGINT drain path; feature enabled with
//!   the variable unset = one INFO line and no exporter.
//! - `DWARA_ADMIN_DEV` (DW-022): "1" serves the admin API as PLAINTEXT
//!   on 127.0.0.1 — DEV ONLY, refuses to start for a non-loopback
//!   admin bind, and must never be set in production (mTLS is the
//!   admin surface's only authentication). Default: unset = mTLS-only.
//!   See the `dwara-admin` crate docs for the endpoint set.
//! - `DWARA_CREDENTIAL_PEPPER` (#124): per-deployment SECRET that peppers
//!   every NEW stored API-key/Basic hash (`hmac-sha256:<hex>`), so a
//!   state-DB leak alone cannot verify guesses. Resolved at startup
//!   through the SecretSource extension seam (EnvSecretSource for the
//!   OSS edition; a managed backend may be swapped in separately).
//!   Unset = legacy-only mode (legacy `sha256:` entries keep verifying;
//!   peppered entries fail closed with one ERROR log). An EMPTY value is
//!   treated as unset. A SET-but-unreadable value refuses startup. The
//!   value is never logged.
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
//! Shutdown: SIGTERM/SIGINT stop accepting on every listener, each
//! listener flushes its kernel backlog (established connections are
//! served), HTTP connections drain via hyper graceful shutdown, and
//! passthrough splices are NOT drained (documented limitation: no drain
//! signaling through a raw TLS pipe; they run until the process exits);
//! whatever remains at the deadline is force-closed by process exit.
//! With the `otlp` feature, the exporter flush is the LAST bounded step
//! before exit (see the DWARA_OTLP_ENDPOINT bullet).

mod listeners;
mod reload;

// #126: OTLP trace export lives behind the default-off `otlp` cargo
// feature (musl size budget; see the module docs). Feature OFF = the
// module does not exist and DWARA_OTLP_ENDPOINT stays inert.
#[cfg(feature = "otlp")]
mod otlp;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use dwara_core::config::{Listener, ListenerProtocol};
use dwara_core::extensions::config_source::{ConfigSource, FileConfigSource};
use dwara_core::extensions::secrets::{EnvSecretSource, SecretSource};
use dwara_core::hardening::HttpHardening;
use dwara_core::proxy::DataPlane;
use dwara_core::snapshot::ConfigState;
use dwara_core::store::{sync_consumers_from_config, StateStore};
use dwara_core::tls::{self, TlsTermination};
use hyper_util::server::graceful::GracefulShutdown;
use listeners::{bind_listener, run_listener_supervised, ListenerMode};
use reload::{refresh_tls_states, reload, spawn_file_watcher};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, watch};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

const DEFAULT_BIND: &str = "127.0.0.1:8080";
const DEFAULT_CONFIG_PATH: &str = "dwara.yaml";
const DEFAULT_SHUTDOWN_TIMEOUT_SECS: u64 = 10;
/// Coalescing window for watcher events: editors and atomic saves emit a
/// burst (write + rename + remove); we wait out the burst, drain the queue,
/// then do exactly one reload.
const RELOAD_DEBOUNCE: Duration = Duration::from_millis(250);

fn shutdown_timeout() -> Duration {
    std::env::var("DWARA_SHUTDOWN_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(DEFAULT_SHUTDOWN_TIMEOUT_SECS))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Observability init (DW-021): JSON on STDOUT, filtered by DWARA_LOG
    // (RUST_LOG syntax; default dwara=info). Installed FIRST so startup
    // logs flow through the same pipeline as request logs.
    //
    // #126: with the `otlp` feature, DWARA_OTLP_ENDPOINT additionally
    // bridges the span tree into an OTLP exporter — the provider must be
    // built BEFORE the subscriber (the bridge is a subscriber layer), so
    // the status line is logged after init, not here. The composition is
    // registry + EnvFilter + JSON fmt (identical to the fmt()-builder
    // form) so the OTLP layer can join the chain when compiled in;
    // feature OFF compiles the exact same subscriber as before.
    #[cfg(feature = "otlp")]
    let otlp = otlp::Otlp::from_env();
    let filter =
        EnvFilter::new(std::env::var("DWARA_LOG").unwrap_or_else(|_| "dwara=info".to_string()));
    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json().with_target(true));
    #[cfg(feature = "otlp")]
    let subscriber = subscriber.with(otlp.layer());
    subscriber.init();
    #[cfg(feature = "otlp")]
    otlp.log_status();
    tls::install_aws_lc_rs_provider();
    let config_path = PathBuf::from(
        std::env::var("DWARA_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string()),
    );

    let source = FileConfigSource::new(&config_path);
    // DW-044: the process's event bus exists BEFORE the first publish, so
    // the startup publish's `config_published` event is queued for the
    // deliverer spawned below (bounded queue; overflow drops and counts,
    // never blocks startup).
    let event_bus = Arc::new(dwara_core::events::EventBus::new());
    let state = Arc::new(ConfigState::with_event_bus(Arc::clone(&event_bus)));

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

    // DW-032: enterprise license gate. Built from the config's `license`
    // block at startup; the gate controls access to enterprise features
    // (Redis rate limiter, config convergence, etc. — not yet
    // implemented; the gate provides the check mechanism). The public
    // key is NEVER in the YAML — it comes from the
    // DWARA_LICENSE_PUBLIC_KEY env var (or the compiled-in dev key when
    // unset), so an operator cannot substitute their own key to forge a
    // license. When the `ent` cargo feature is NOT compiled in, the
    // block is accepted but inert (the gate is always none()).
    let license_gate = build_license_gate(&gateway);

    // Credential pepper (#124): resolved through the SecretSource
    // extension seam BEFORE the state store is seeded (the pepper
    // selects the stored-hash format for config-seeded keys) and handed
    // to the dataplane, which threads the raw bytes down to the security
    // domain (security must not import extensions — check_deps.py). The
    // value is SECRET: it is never logged and never rendered.
    const PEPPER_SECRET_NAME: &str = "DWARA_CREDENTIAL_PEPPER";
    let credential_pepper: Option<Vec<u8>> = match EnvSecretSource.resolve(PEPPER_SECRET_NAME).await
    {
        Ok(Some(secret)) => {
            let value = secret.expose();
            if value.is_empty() {
                tracing::warn!(
                    code = "credential_pepper_empty",
                    "{PEPPER_SECRET_NAME} is set but empty; running in legacy-only mode \
                     (legacy sha256 stored hashes keep verifying, peppered entries fail closed)"
                );
                None
            } else {
                Some(value.as_bytes().to_vec())
            }
        }
        Ok(None) => None,
        // Set-but-unreadable (e.g. non-Unicode bytes): refuse startup.
        // Silently degrading to legacy-only mode would quietly break
        // verification of every peppered credential after a restart.
        // The error text names the variable, never the value.
        Err(err) => {
            tracing::error!(
                code = "credential_pepper_unreadable",
                "secret {PEPPER_SECRET_NAME} could not be read: {err}; refusing to start"
            );
            std::process::exit(1);
        }
    };
    if credential_pepper.is_some() {
        tracing::info!(
            code = "credential_pepper_active",
            "credential pepper configured; new credential writes use the peppered \
             hmac-sha256 stored-hash format"
        );
    }

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
                // The seed closure needs its own copy while `main` keeps
                // the original for the dataplane: hold the copy in a
                // Zeroizing buffer so it is zeroized as soon as the seed
                // finishes hashing (no plain copy outlives the work).
                let pepper = credential_pepper.clone().map(Zeroizing::new);
                move || {
                    StateStore::open(std::path::Path::new(&path)).and_then(|s| {
                        sync_consumers_from_config(
                            &s,
                            &gateway,
                            pepper.as_deref().map(|p| p.as_slice()),
                        )?;
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
                policies: Vec::new(),
                authorization: None,
                proxy_protocol: false,
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
    // and Basic-auth records). #124: the credential pepper is attached
    // the same way — bytes resolved above, threaded down to the
    // authenticator.
    dp.set_credential_pepper(credential_pepper);
    if let Some(store) = &state_store {
        dp.set_state_store(Arc::clone(store));
    }
    // DW-032: publish the license status metric once the dataplane
    // (which owns the observability registry) is constructed.
    dp.set_license_status(license_gate.status().as_metric());

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
    // DW-044: the webhook deliverer — one task draining the event bus and
    // POSTing matching events to the configured targets. Runs even with
    // no webhooks configured (it just drains); stops on shutdown, where
    // its pending queue is abandoned (the gateway is not a durable
    // queue).
    let webhook_task = dp.spawn_webhook_deliverer(shutdown_rx.clone());
    // DW-121: the access-record stream — constructed ALWAYS (an
    // unconfigured stream is disabled by its enabled flag, so a live
    // reload can arm the pipeline without a restart; only the channel
    // CAPACITY is a boot-time property, taken from the config when the
    // block is present at boot), with the flusher spawned against the
    // same shutdown watch. The flusher delivers batches inline and in
    // order; on shutdown it drains what is queued into one final
    // flush attempt (the gateway is not a durable queue).
    let stream_cfg_buffer = state
        .snapshot()
        .gateway()
        .analytics_stream
        .as_ref()
        .and_then(|c| c.buffer)
        .unwrap_or(dwara_core::config::DEFAULT_STREAM_BUFFER);
    let record_stream =
        dwara_core::events::stream::AccessRecordStream::with_capacity(stream_cfg_buffer as usize);
    dp.set_record_stream(std::sync::Arc::clone(&record_stream));
    let stream_task = dp.spawn_record_stream_flusher(shutdown_rx.clone());
    // DW-120: the usage-report export worker — same background machinery
    // as the analytics rollup cascade, reading the live config each
    // tick. Runs even without an analytics store or an exports block
    // (both checks are per-tick); aborted on shutdown (each export is
    // an atomic file write plus an idempotent record — nothing to
    // drain).
    let export_task = dp.spawn_export_worker(shutdown_rx.clone());
    // DW-043: the embedded analytics store — opened when the config
    // carries an `analytics` block, workers spawned against the same
    // shutdown watch as every other background task (the writer drains
    // and takes a final rollup/retention pass on stop). Held alive for
    // the process lifetime alongside the state store handle.
    let analytics_handles = state
        .snapshot()
        .gateway()
        .analytics
        .as_ref()
        .map(|cfg| {
            let retention = cfg
                .retention
                .as_ref()
                .map(|r| r.effective())
                .unwrap_or(dwara_core::config::ANALYTICS_DEFAULT_RETENTION_MS);
            let flush = cfg.flush_ms.unwrap_or(1000);
            match dwara_core::analytics::EmbeddedAnalytics::open(&cfg.path, retention, flush) {
                Ok(store) => {
                    dp.set_analytics(Arc::clone(&store));
                    let handles = store.spawn_workers(shutdown_rx.clone());
                    tracing::info!(
                        code = "analytics_open",
                        path = %cfg.path,
                        "embedded analytics store open; recording request outcomes"
                    );
                    handles
                }
                Err(e) => {
                    // Fail LOUD, serve WITHOUT analytics: traffic must
                    // not stop because a data file is unwritable — the
                    // same posture as the state store's advisory modes.
                    tracing::error!(
                        code = "analytics_open_failed",
                        path = %cfg.path,
                        "analytics store failed to open ({e}); serving WITHOUT analytics"
                    );
                    Vec::new()
                }
            }
        })
        .unwrap_or_default();

    // DW-050: the GeoIP database — opened at startup when the config
    // carries a `geoip` block (fail LOUD, serve geo-UNKNOWN without
    // it), then a watcher polls the file's mtime and hot-swaps the
    // reader (no restart). In-flight lookups keep the reader they
    // loaded; the swap is atomic.
    let geoip_task = state.snapshot().gateway().geoip.as_ref().map(|cfg| {
        let path = cfg.path.clone();
        match dwara_core::security::geoip::GeoipDb::open(&path) {
            Ok(db) => {
                dp.set_geoip(std::sync::Arc::new(db));
                tracing::info!(
                    code = "geoip_open",
                    path = %path,
                    "geoip database open; geo rules evaluating"
                );
            }
            Err(e) => tracing::error!(
                code = "geoip_open_failed",
                path = %path,
                "geoip database failed to open ({e}); geo lookups resolve UNKNOWN"
            ),
        }
        let dp_geoip = Arc::clone(&dp);
        let mut shutdown_geoip = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut last = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                        let mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
                        if mtime != last {
                            last = mtime;
                            match dwara_core::security::geoip::GeoipDb::open(&path) {
                                Ok(db) => {
                                    dp_geoip.set_geoip(Arc::new(db));
                                    tracing::info!(
                                        code = "geoip_reloaded",
                                        path = %path,
                                        "geoip database hot-reloaded"
                                    );
                                }
                                Err(e) => tracing::warn!(
                                    code = "geoip_reload_failed",
                                    path = %path,
                                    "geoip reload kept the previous reader ({e})"
                                ),
                            }
                        }
                    }
                    _ = shutdown_geoip.changed() => return,
                }
            }
        })
    });
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
        // #120: each accept task runs under panic supervision — a
        // panicked accept loop is respawned (bounded) on the same bound
        // socket instead of silently killing its listener.
        tasks.push(tokio::spawn(run_listener_supervised(
            bound,
            Arc::new(tcp),
            state,
            dp,
            graceful,
            rx,
            timeout,
            hardening,
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
    webhook_task.abort();
    export_task.abort();
    if let Some(t) = &geoip_task {
        t.abort();
    }
    // DW-043: analytics workers are NOT aborted — the shutdown watch
    // tells the writer to drain, flush, and take a final rollup/retention
    // pass (a clean restart loses nothing); give them a bounded moment
    // inside the shutdown budget.
    for h in analytics_handles {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), h).await;
    }
    // DW-121: the record-stream flusher drains the same way — its
    // shutdown handler flushes one final batch (bounded by the sink's
    // delivery timeout, and by this 5 s window whichever is shorter).
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), stream_task).await;

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

    // #126: OTLP flush on the shutdown path — the exporter drains its
    // batch and posts the remaining spans, bounded by whatever is left
    // of the drain budget (the SDK caps itself at 5s). Feature OFF or
    // endpoint unset = nothing here.
    #[cfg(feature = "otlp")]
    otlp.shutdown(deadline.saturating_duration_since(tokio::time::Instant::now()))
        .await;

    std::process::exit(0);
}

const DEFAULT_BIND_PORT: u16 = 8080;

fn config_dir(path: &Path) -> PathBuf {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Build the enterprise license gate from the config's `license` block
/// (DW-032). Returns a `LicenseGate` reflecting the verification
/// outcome. Startup behavior:
///
/// - No `license` block: OSS mode, logs "running in OSS mode".
/// - `license` block + valid: enterprise mode, logs customer/plan/features.
/// - `license` block + expired + within grace: enterprise mode, warns.
/// - `license` block + expired + past grace: degrades to OSS, logs.
/// - `license` block + invalid signature: refuses to start (exit 1).
/// - `license` block + file not found: refuses to start (exit 1).
///
/// When the `ent` cargo feature is NOT compiled in, the block is
/// accepted but inert (the gate is always `none()`); a present block
/// logs a one-line notice that the ent feature is not compiled in.
fn build_license_gate(
    gateway: &dwara_core::config::Gateway,
) -> dwara_core::extensions::licensing::LicenseGate {
    use dwara_core::extensions::licensing::LicenseGate;

    let Some(lic_cfg) = &gateway.license else {
        tracing::info!(
            code = "license_oss_mode",
            "running in OSS mode (no license configured)"
        );
        return LicenseGate::none();
    };

    #[cfg(not(feature = "ent"))]
    {
        tracing::info!(
            code = "license_block_inert",
            file = %lic_cfg.file,
            "license block present but the ent cargo feature is not compiled in; \
             running in OSS mode (the block is accepted but inert)"
        );
        LicenseGate::none()
    }

    #[cfg(feature = "ent")]
    {
        use dwara_core::extensions::licensing::LicenseStatus;
        let grace = lic_cfg.grace_period_days;
        match LicenseGate::from_file(std::path::Path::new(&lic_cfg.file), grace) {
            Ok(gate) => {
                match gate.status() {
                    LicenseStatus::Valid => {
                        tracing::info!(
                            code = "license_verified",
                            customer = gate.customer().unwrap_or("?"),
                            plan = gate.plan().unwrap_or("?"),
                            features = ?gate.features(),
                            "enterprise license verified: customer={}, plan={}, features={:?}",
                            gate.customer().unwrap_or("?"),
                            gate.plan().unwrap_or("?"),
                            gate.features(),
                        );
                    }
                    LicenseStatus::ExpiredWithinGrace => {
                        tracing::warn!(
                            code = "license_expired_within_grace",
                            expires_at = gate.expires_at().as_deref().unwrap_or("?"),
                            grace_period_days = grace,
                            "license expired but within grace period (expires_at={}); \
                             enterprise features still active — renew before the grace window ends",
                            gate.expires_at().as_deref().unwrap_or("?"),
                        );
                    }
                    LicenseStatus::ExpiredPastGrace => {
                        tracing::warn!(
                            code = "license_expired_past_grace",
                            "license expired past grace period, degrading to OSS"
                        );
                    }
                    LicenseStatus::NoLicense => {
                        // Unreachable: from_file always sets a status
                        // when it returns Ok. Defensive log.
                        tracing::warn!(
                            code = "license_unexpected_status",
                            "license gate returned no-license status after from_file"
                        );
                    }
                }
                gate
            }
            Err(err) => {
                tracing::error!(
                    code = "license_load_failed",
                    "license verification failed: {err}; refusing to start"
                );
                std::process::exit(1);
            }
        }
    }
}
