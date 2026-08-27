//! Panic supervision for accept loops (#120, #130).
//!
//! One place for the bounded respawn policy every accept surface uses:
//! the gateway's data-plane listeners (dwara-bin) and the admin API's
//! accept loop (dwara-admin). A panicked accept task is respawned on
//! the SAME bound socket (callers share their `TcpListener` behind an
//! `Arc`), up to a per-caller cap, after which the surface is given up
//! on with a loud ERROR log — the process itself keeps running (a dead
//! accept surface must not take sibling listeners and in-flight work
//! with it; that is not the shutdown idiom anywhere else either).
//!
//! This module depends on no other domain: it is pure task plumbing
//! over tokio handles plus tracing.

/// Supervise one accept task for panics: when an incarnation ends
/// cleanly (shutdown flush completed) supervision is done; when it
/// panics it is respawned up to `max_respawns` times with a warning per
/// respawn, and after the cap an ERROR is logged and the surface is
/// left down — loudly, but without aborting the process.
///
/// `kind` names the supervised surface in the log codes ("listener",
/// "admin"); `label` identifies the instance (listener name, bind
/// address). `spawn` builds one incarnation; it is called once
/// immediately and once per respawn, so it must hand each incarnation
/// fresh clones of everything the accept loop consumes.
pub async fn supervise_panics(
    kind: &str,
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
                        code = format!("{kind}_respawn_exhausted"),
                        kind,
                        name = %label,
                        respawns,
                        "accept loop panicked again after {respawns} respawns; giving up: {kind} '{label}' is DOWN, the rest of the process keeps serving"
                    );
                    return;
                }
                respawns += 1;
                tracing::warn!(
                    code = format!("{kind}_respawn"),
                    kind,
                    name = %label,
                    respawns,
                    "accept task panicked ({err}); respawning {kind} accept loop"
                );
            }
            // JoinError without a panic only occurs on cancellation,
            // which this code never does: treat it as a clean end.
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    // White-box tests in src/ per AGENTS.md: the panic boundary
    // (JoinHandle::is_panic + bounded respawn) is exercised by inducing
    // real task panics, which is not expressible through any consumer's
    // public surface. Moved here from dwara-bin's listeners.rs when the
    // supervisor was extracted (#130) so both accept surfaces test the
    // one implementation they share.

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
        supervise_panics("listener", "test-listener", 3, || {
            spawns.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async { panic!("induced accept-loop panic") })
        })
        .await;
        // One initial incarnation plus three respawns; the fourth panic
        // exhausts the budget and supervision returns (surface left
        // down loudly, process keeps running).
        assert_eq!(spawns.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn clean_incarnation_ends_supervision_without_respawn() {
        let spawns = AtomicU32::new(0);
        supervise_panics("listener", "test-listener", 3, || {
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
        supervise_panics("admin", "127.0.0.1:0", 3, || {
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
    async fn exhausted_respawn_budget_leaves_sibling_surfaces_serving() {
        // Process-stays-up analog (#120): inducing a REAL accept-loop
        // panic in a served binary is not externally expressible, so
        // the containment property is pinned here — while one surface
        // panics through its entire respawn budget (and supervision
        // gives up on it), an independent sibling accept loop keeps
        // serving both during and after the failure. The process-level
        // guarantee this models: a dead accept surface never takes the
        // other listeners down with it.
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
        supervise_panics("listener", "doomed", 1, || {
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
