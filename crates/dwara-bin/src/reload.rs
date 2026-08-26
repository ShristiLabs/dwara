//! Hot reload: config snapshot and TLS certificate reloads.
//!
//! Hot reload semantics:
//! - Config file watch + SIGHUP: re-read, validate, `compile_and_publish`
//!   (DW-006 semantics unchanged). A file-watch reload of UNCHANGED
//!   content is a no-op (the generation only moves when content changes);
//!   SIGHUP always re-publishes (forced reload). Watch events limited to
//!   create/modify-data/remove/rename — metadata churn (atime) from the
//!   reload's own reads must not re-trigger it. On success, terminate
//!   listeners' TLS configurations are rebuilt from the new snapshot and
//!   the active health probe loops (DW-013) are respawned against the new
//!   generation (endpoints persisting across the swap keep their health
//!   trackers).
//! - Certificate hot reload: cert/key files of terminate listeners are
//!   watched; a change rebuilds the `ServerConfig` behind an `ArcSwap`
//!   WITHOUT dropping connections. New handshakes use the new material;
//!   in-flight sessions keep the configuration they negotiated.
//! - Documented v1 limitation: the LISTENER BIND SET is taken from the
//!   startup snapshot; adding/removing listeners or changing
//!   address/port takes effect on restart. Only route/config changes
//!   and certificate material reload live.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use dwara_core::extensions::config_source::{ConfigSource, FileConfigSource};
use dwara_core::proxy::DataPlane;
use dwara_core::snapshot::{ConfigState, Snapshot};
use dwara_core::tls::TlsTermination;
use notify::Watcher;
use tokio::sync::mpsc;

/// One reload attempt: re-read from disk, validate, publish atomically.
/// Never fatal: on any failure the published snapshot is untouched and the
/// process keeps running. On success, the dataplane's (snapshot, registry)
/// pair is rebuilt (routes and upstream pools hot-swap together; in-flight
/// requests keep the old pair) and terminate listeners' TLS configs are
/// rebuilt from the new snapshot (certificate material follows the config
/// generation it belongs to).
pub(crate) async fn reload(
    state: &ConfigState,
    dp: &DataPlane,
    source: &FileConfigSource,
    trigger: &str,
    tls_states: &BTreeMap<String, Arc<TlsTermination>>,
    probes: &mut dwara_core::active::ActiveProbes,
) {
    let old = state.snapshot();
    match source.load().await {
        Ok(gateway) => {
            // File-watch reloads of identical content are no-ops: the
            // generation only moves when content changes (editors and
            // the admin API's atomic rename both re-deliver events for
            // already-current content). SIGHUP stays a forced reload —
            // operators use it to re-publish and reset per-generation
            // state. Compile failures fall through to the publish path,
            // which reports them without touching the running snapshot.
            if trigger == "file-watch" {
                if let Ok(compiled) = dwara_core::snapshot::compile(&gateway) {
                    if compiled.content_hash() == old.content_hash() {
                        tracing::info!(
                            code = "config_reload_unchanged",
                            trigger,
                            generation = old.generation(),
                            "config reload skipped: content unchanged"
                        );
                        return;
                    }
                }
            }
            match state.compile_and_publish(&gateway) {
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
            }
        }
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
pub(crate) fn refresh_tls_states(
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
pub(crate) fn spawn_file_watcher(
    dirs: Vec<PathBuf>,
    names: Vec<std::ffi::OsString>,
) -> Result<mpsc::UnboundedReceiver<()>, notify::Error> {
    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher =
        notify::recommended_watcher(move |event: Result<notify::Event, notify::Error>| {
            let Ok(event) = event else { return };
            // Metadata-only churn (atime/ctime) and access events must
            // not trigger reloads: on Linux inotify, a reload re-reads
            // the file, the read bumps atime, IN_ATTRIB re-fires the
            // watcher — a self-sustaining reload loop at the debounce
            // cadence. Only creation, data modification, removal, and
            // rename events count.
            match event.kind {
                notify::EventKind::Modify(notify::event::ModifyKind::Metadata(_))
                | notify::EventKind::Access(_)
                | notify::EventKind::Other => return,
                _ => {}
            }
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
