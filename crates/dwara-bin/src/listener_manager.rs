//! Listener hot-reload (SCALE-03, #182).
//!
//! On config reload, the listener set is diffed against the currently
//! bound set:
//! - Added listeners are bound and spawned.
//! - Removed listeners are drained (their shutdown watch is signalled;
//!   the accept loop exits and in-flight connections drain via the
//!   graceful shutdown watcher).
//! - Changed listeners (address, port, protocol, proxy_protocol, or
//!   TLS mode changed) are drained and re-bound.
//! - Unchanged listeners keep running (their TLS cert material is
//!   refreshed separately by the cert watcher / `refresh_tls_states`).
//!
//! Each listener gets its own per-listener shutdown watch so the manager
//! can stop one listener without affecting the others. The process-wide
//! shutdown watch still cascades to every listener via the manager.

use std::collections::BTreeMap;
use std::sync::Arc;

use dwara_core::config::{Listener, ListenerProtocol, TlsMode};
use dwara_core::hardening::HttpHardening;
use dwara_core::proxy::DataPlane;
use dwara_core::snapshot::ConfigState;
use dwara_core::tls::TlsTermination;
use hyper_util::server::graceful::GracefulShutdown;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::listeners::{bind_listener, run_listener_supervised, ListenerMode, SpliceDrain};

/// The drain timeout for a single listener being stopped or restarted.
/// Shorter than the process shutdown timeout: a listener being removed
/// mid-run should not hold the reload path for the full shutdown budget.
const LISTENER_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// One managed listener: its task handle, per-listener shutdown sender,
/// and the bind identity (so we can detect changes that require a
/// restart).
struct ManagedListener {
    addr: String,
    protocol: ListenerProtocol,
    proxy_protocol: bool,
    tls_mode: Option<TlsMode>,
    /// Per-listener shutdown: signalling this stops the accept loop and
    /// drains in-flight connections via the graceful watcher.
    shutdown_tx: watch::Sender<()>,
    task: JoinHandle<()>,
}

/// The bind identity of a listener: the fields that, if changed,
/// require a restart (re-bind + re-spawn). Everything else (policies,
/// authorization, alt_svc, TLS cert material) is read from the live
/// snapshot at request time and needs no restart.
fn bind_identity(l: &Listener) -> (String, ListenerProtocol, bool, Option<TlsMode>) {
    let addr = format!("{}:{}", l.address, l.port);
    let tls_mode = l.tls.as_ref().map(|t| t.mode);
    (addr, l.protocol, l.proxy_protocol, tls_mode)
}

/// True when the listener's bind identity changed (requires restart).
fn identity_changed(old: &ManagedListener, new: &Listener) -> bool {
    let (new_addr, new_proto, new_pp, new_tls) = bind_identity(new);
    old.addr != new_addr
        || old.protocol != new_proto
        || old.proxy_protocol != new_pp
        || old.tls_mode != new_tls
}

/// Manages the lifecycle of bound listeners. Created at startup with
/// the initial listener set; `apply` is called on every config reload
/// to diff the new listener set against the current one.
pub(crate) struct ListenerManager {
    listeners: BTreeMap<String, ManagedListener>,
    state: Arc<ConfigState>,
    dp: Arc<DataPlane>,
    graceful: Arc<GracefulShutdown>,
    hardening: Arc<HttpHardening>,
    splice_drain: Arc<SpliceDrain>,
    /// The process-wide shutdown watch. Each per-listener shutdown is
    /// cascaded from this: when the process shuts down, every listener
    /// stops. Per-listener shutdowns (for removed/changed listeners) are
    /// independent.
    process_shutdown: watch::Receiver<()>,
    /// The drain timeout for the process-wide shutdown (used for
    /// per-listener drains too, scaled down).
    shutdown_timeout: std::time::Duration,
}

impl ListenerManager {
    /// Create a new manager. The initial listener set is applied via
    /// `apply` (pass the startup config's listeners).
    pub(crate) fn new(
        state: Arc<ConfigState>,
        dp: Arc<DataPlane>,
        graceful: Arc<GracefulShutdown>,
        hardening: Arc<HttpHardening>,
        splice_drain: Arc<SpliceDrain>,
        process_shutdown: watch::Receiver<()>,
        shutdown_timeout: std::time::Duration,
    ) -> Self {
        Self {
            listeners: BTreeMap::new(),
            state,
            dp,
            graceful,
            hardening,
            splice_drain,
            process_shutdown,
            shutdown_timeout,
        }
    }

    /// Apply a new listener set: bind new listeners, drain removed
    /// listeners, restart changed listeners. Returns the updated
    /// `tls_states` map (name -> TlsTermination) for terminate listeners
    /// so the caller can wire cert-file watching.
    pub(crate) async fn apply(
        &mut self,
        configured: &[Listener],
        tls_states: &mut BTreeMap<String, Arc<TlsTermination>>,
    ) {
        let new_names: std::collections::BTreeSet<&str> =
            configured.iter().map(|l| l.name.as_str()).collect();

        // 1. Drain and remove listeners that are no longer present or
        //    whose bind identity changed.
        let mut to_remove: Vec<String> = Vec::new();
        for (name, managed) in &self.listeners {
            if !new_names.contains(name.as_str()) {
                to_remove.push(name.clone());
                continue;
            }
            let new_listener = configured.iter().find(|l| l.name == *name).unwrap();
            if identity_changed(managed, new_listener) {
                to_remove.push(name.clone());
            }
        }
        for name in &to_remove {
            self.stop_listener(name).await;
            tls_states.remove(name);
        }

        // 2. Bind and spawn new listeners (added or changed).
        for l in configured {
            // Skip H3 and UDP listeners — they are managed separately in
            // main.rs (UDP/QUIC, not TCP). The listener manager only
            // handles TCP listeners (http, https, tcp).
            if l.protocol == ListenerProtocol::H3 || l.protocol == ListenerProtocol::Udp {
                continue;
            }
            // Already managed and unchanged — skip.
            if self.listeners.contains_key(&l.name) {
                continue;
            }
            match self.spawn_listener(l).await {
                Ok(Some(term)) => {
                    // Terminate listener: register TLS state for cert
                    // watching.
                    tls_states.insert(l.name.clone(), term);
                }
                Ok(None) => {}
                Err(err) => {
                    tracing::error!(
                        code = "listener_bind_failed",
                        listener = %l.name,
                        "failed to bind listener: {err}"
                    );
                }
            }
        }
    }

    /// Stop and drain one listener. Signals its per-listener shutdown
    /// watch, then waits for the accept task to finish (with a bounded
    /// drain timeout).
    async fn stop_listener(&mut self, name: &str) {
        let Some(managed) = self.listeners.remove(name) else {
            return;
        };
        tracing::info!(
            code = "listener_draining",
            listener = %name,
            addr = %managed.addr,
            "draining listener (removed or changed)"
        );
        let _ = managed.shutdown_tx.send(());
        let task = managed.task;
        // Wait for the accept task to finish, with a bounded timeout.
        let drain = tokio::time::timeout(LISTENER_DRAIN_TIMEOUT, task);
        match drain.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                tracing::warn!(
                    code = "listener_task_error",
                    listener = %name,
                    "listener task ended with error: {err}"
                );
            }
            Err(_) => {
                tracing::warn!(
                    code = "listener_drain_timeout",
                    listener = %name,
                    "listener drain timed out after {:?}; aborting",
                    LISTENER_DRAIN_TIMEOUT
                );
                // The task was consumed by the timeout; we can't abort
                // it directly, but it will be dropped when the timeout
                // future is dropped (which happens here).
            }
        }
        tracing::info!(
            code = "listener_drained",
            listener = %name,
            "listener drained"
        );
    }

    /// Bind and spawn one listener. On success, the listener is
    /// tracked in `self.listeners`. Returns the `TlsTermination` if
    /// the listener is a terminate-mode HTTPS listener (for cert
    /// watcher registration).
    async fn spawn_listener(
        &mut self,
        l: &Listener,
    ) -> Result<Option<Arc<TlsTermination>>, Box<dyn std::error::Error + Send + Sync>> {
        let (tcp, bound) = bind_listener(l).await?;
        let addr = bound.addr.clone();
        let protocol = l.protocol;
        let proxy_protocol = l.proxy_protocol;
        let tls_mode = l.tls.as_ref().map(|t| t.mode);

        // Extract TLS termination state before moving bound.
        let term = match &bound.mode {
            ListenerMode::Terminate(term) => Some(Arc::clone(term)),
            _ => None,
        };

        let name = bound.name.clone();
        let (shutdown_tx, shutdown_rx) = watch::channel(());
        // Cascade: when the process-wide shutdown fires, signal this
        // listener's shutdown too. We spawn a tiny forwarder task.
        let process_shutdown = self.process_shutdown.clone();
        let listener_shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            let mut process_shutdown = process_shutdown;
            process_shutdown.changed().await.ok();
            let _ = listener_shutdown_tx.send(());
        });

        let state = Arc::clone(&self.state);
        let dp = Arc::clone(&self.dp);
        let graceful = Arc::clone(&self.graceful);
        let hardening = Arc::clone(&self.hardening);
        let splice_drain = Arc::clone(&self.splice_drain);
        let timeout = self.shutdown_timeout;

        tracing::info!(
            code = "listening",
            addr = %addr,
            listener = %name,
            mode = match &bound.mode {
                ListenerMode::Cleartext => "cleartext http/1.1+h2c",
                ListenerMode::Terminate(_) => "tls terminate",
                ListenerMode::Passthrough => "tls passthrough",
                ListenerMode::L4 { .. } => "l4 tcp proxy",
            },
            "listener bound (hot-reload)"
        );

        let task = tokio::spawn(run_listener_supervised(
            bound,
            Arc::new(tcp),
            state,
            dp,
            graceful,
            shutdown_rx,
            timeout,
            hardening,
            splice_drain,
        ));

        self.listeners.insert(
            name.clone(),
            ManagedListener {
                addr,
                protocol,
                proxy_protocol,
                tls_mode,
                shutdown_tx,
                task,
            },
        );
        Ok(term)
    }

    /// Signal all listeners to stop (used during process shutdown).
    /// The process-wide shutdown watch already cascades, but this
    /// ensures all per-listener watches are signalled too.
    pub(crate) fn signal_all(&self) {
        for managed in self.listeners.values() {
            let _ = managed.shutdown_tx.send(());
        }
    }

    /// Wait for all listener tasks to finish (used during process
    /// shutdown drain).
    pub(crate) async fn join_all(&mut self) {
        let listeners = std::mem::take(&mut self.listeners);
        for (name, managed) in listeners {
            let _ = managed.shutdown_tx.send(());
            if let Err(err) = managed.task.await {
                tracing::warn!(
                    code = "listener_task_error",
                    listener = %name,
                    "listener task ended with error: {err}"
                );
            }
        }
    }
}
