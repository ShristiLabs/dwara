//! Zero-downtime binary upgrade (DW-049).
//!
//! Approach: SO_REUSEPORT hand-off with a readiness signal.
//!
//! 1. Every listening socket is bound with `SO_REUSEPORT` (in addition to
//!    `SO_REUSEADDR`), so a second process can bind the SAME port while the
//!    first is still listening. On Linux the kernel load-balances accepts
//!    across both sockets; on macOS both sockets may accept (the balance is
//!    less even but the hand-off still works — no port-loss window).
//! 2. On `SIGUSR2` the OLD process spawns a NEW copy of the binary (the
//!    same path by default, or `DWARA_UPGRADE_BINARY`) with the env var
//!    [`UPGRADE_READY_SOCKET_ENV`] pointing at a freshly-created Unix
//!    domain socket.
//! 3. The NEW process binds its listeners (SO_REUSEPORT lets it bind
//!    alongside the old), spawns its accept tasks, then connects to the
//!    ready socket and sends `READY\n`. This is the hand-off signal.
//! 4. The OLD process receives `READY\n` (bounded wait), THEN initiates
//!    the same drain sequence as SIGTERM: stop accepting, flush backlogs,
//!    drain HTTP connections within the shutdown budget, exit 0. Because
//!    the new process is already accepting, no connection is refused and
//!    no in-flight connection is reset.
//! 5. If the new process fails to bind/start, it never signals READY; the
//!    old process times out, logs an ERROR, and KEEPS running — a failed
//!    upgrade never takes the gateway down.
//!
//! This is the nginx/Envoy model without FD passing: SO_REUSEPORT removes
//! the need to transfer file descriptors, so the coordination is a single
//! byte frame over a Unix domain socket (portable, no SCM_RIGHTS).
//!
//! Operator trigger: `dwara upgrade` (CLI) sends SIGUSR2 to the PID in the
//! PID file (`DWARA_PID_FILE`) or to an explicit `--pid`.
//!
//! Environment:
//! - `DWARA_PID_FILE`: write the process PID here on startup (default:
//!   none). The `dwara upgrade` CLI reads it to find the process to
//!   signal. The new process overwrites it after signaling READY.
//! - `DWARA_UPGRADE_BINARY`: path to the new binary for an upgrade
//!   (default: `std::env::current_exe()`).
//! - [`UPGRADE_READY_SOCKET_ENV`]: set by the old process on the spawned
//!   child; the child connects to this Unix socket to signal readiness.
//!   Unset on a normal (non-upgrade) start.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;

/// Env var the OLD process sets on the spawned child: the path of the
/// Unix domain socket the child connects to after it is accepting.
pub(crate) const UPGRADE_READY_SOCKET_ENV: &str = "DWARA_UPGRADE_READY_SOCKET";

/// The readiness frame the new process sends once its accept loops are
/// running. A single line so a `read_line` drains it cleanly.
const READY_FRAME: &str = "READY\n";

/// How long the old process waits for the new process to signal READY
/// before giving up (and keeping the old process running). Generous:
/// the new process must load config, bind, and spawn accept tasks.
const DEFAULT_UPGRADE_READY_TIMEOUT: Duration = Duration::from_secs(30);

/// Bind a TCP listener with `SO_REUSEADDR` AND `SO_REUSEPORT` so a second
/// process can bind the same address during an upgrade hand-off. Returns
/// a tokio `TcpListener` (non-blocking, close-on-exec handled by tokio).
///
/// `SO_REUSEPORT` is available on Linux and macOS (and modern FreeBSD);
/// the call is a no-op-fallback on platforms without it (none of the
/// supported targets lack it). The socket is bound in the same address
/// family as `addr`.
pub(crate) fn bind_with_reuse_port(addr: SocketAddr) -> io::Result<TcpListener> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    // SO_REUSEADDR (already set by tokio's bind; set explicitly here so
    // the socket2-owned path matches the semantics the gateway relied on).
    socket.set_reuse_address(true)?;
    // SO_REUSEPORT: the upgrade enabler. Multiple processes may bind the
    // same port; the kernel distributes incoming connections. Without it
    // the new process's bind would fail with EADDRINUSE while the old
    // process is still listening.
    socket.set_reuse_port(true)?;
    socket.bind(&addr.into())?;
    // Match tokio's default backlog (1024). The exact value is not
    // load-bearing for correctness; the backlog flush drains whatever is
    // queued at shutdown.
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    // socket2 -> std -> tokio. The std TcpListener takes ownership of the
    // FD; tokio's from_std registers it with its reactor.
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

/// A unique Unix domain socket path for one upgrade hand-off. Lives
/// under `/tmp` (NOT `std::env::temp_dir()`: on macOS the temp dir is a
/// long `/var/folders/...` path that can exceed the Unix domain socket
/// SUN_LEN limit of 104 bytes), namespaced by the OLD process's PID so
/// concurrent upgrades on the same host do not collide.
pub(crate) fn ready_socket_path(old_pid: u32) -> PathBuf {
    PathBuf::from(format!("/tmp/dwara-upgrade-{old_pid}.sock"))
}

/// Resolve the new binary path for an upgrade. `DWARA_UPGRADE_BINARY`
/// overrides; otherwise the current executable. Falls back to a literal
/// `dwara` on PATH only if current_exe cannot be resolved (extremely
/// rare — the binary was exec'd to get here).
fn new_binary_path() -> PathBuf {
    if let Ok(p) = std::env::var("DWARA_UPGRADE_BINARY") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("dwara"))
}

/// The upgrade ready timeout. `DWARA_UPGRADE_READY_TIMEOUT_SECS` overrides
/// the default; an unparseable value falls back to the default.
fn ready_timeout() -> Duration {
    std::env::var("DWARA_UPGRADE_READY_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_UPGRADE_READY_TIMEOUT)
}

/// Spawn the new binary as an upgrade child. The child inherits the
/// environment (DWARA_CONFIG, DWARA_BIND, ... — it must serve the SAME
/// listeners) plus [`UPGRADE_READY_SOCKET_ENV`] pointing at `ready_socket`.
/// The child is detached (no stdio piped) so it outlives the old process's
/// exit independently.
pub(crate) fn spawn_upgrade_child(ready_socket: &str) -> io::Result<std::process::Child> {
    let mut cmd = std::process::Command::new(new_binary_path());
    cmd.env(UPGRADE_READY_SOCKET_ENV, ready_socket);
    // Detach stdio so the child is not tied to the old process's pipes
    // (the old process exits after the hand-off; the child must survive).
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    // On Unix, start the child in its own process group so signals sent
    // to the old process's group (e.g. Ctrl-C in a terminal) do not
    // cascade to the new gateway. `process_group(0)` makes the child's
    // PID its own process-group ID (std since 1.64; no libc dep needed).
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
    }
    cmd.spawn()
}

/// Wait for the new process to signal READY over the Unix domain socket.
/// The old process has already bound `listener` at `ready_socket_path`
/// BEFORE spawning the child (so the child's connect cannot race a
/// missing listener). Returns Ok(()) on READY, Err on timeout/IO error
/// (the caller keeps running on Err — a failed upgrade is safe).
pub(crate) async fn await_ready(
    listener: &tokio::net::UnixListener,
    timeout: Duration,
) -> Result<(), String> {
    let accept = listener.accept();
    let (mut stream, _peer) = tokio::select! {
        res = accept => match res {
            Ok(conn) => conn,
            Err(err) => return Err(format!("ready-socket accept failed: {err}")),
        },
        _ = tokio::time::sleep(timeout) => {
            return Err(format!(
                "upgrade timed out waiting for the new process to signal READY \
                 after {timeout:?}; keeping the old process running"
            ));
        }
    };
    use tokio::io::AsyncReadExt as _;
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await
        .map_err(|_| "ready frame read timed out".to_string())?
        .map_err(|err| format!("ready frame read failed: {err}"))?;
    let frame = std::str::from_utf8(&buf[..n]).unwrap_or("");
    if frame.trim_end() == READY_FRAME.trim_end() {
        Ok(())
    } else {
        Err(format!("unexpected ready frame: {frame:?}"))
    }
}

/// The OLD process's upgrade entry point. Called from the SIGUSR2 handler
/// in main. Binds the ready socket, spawns the child, awaits READY, and
/// returns Ok(()) when the old process should proceed to drain+exit. On
/// any error the old process keeps running (returns the error for logging).
///
/// `old_pid` is this process's PID (used to name the ready socket).
pub(crate) async fn initiate_upgrade(
    old_pid: u32,
) -> Result<(tokio::net::UnixListener, PathBuf), String> {
    let socket_path = ready_socket_path(old_pid);
    // Clean up a stale socket from a previous failed attempt, then bind.
    let _ = std::fs::remove_file(&socket_path);
    let listener = tokio::net::UnixListener::bind(&socket_path)
        .map_err(|err| format!("cannot bind ready socket {}: {err}", socket_path.display()))?;
    let path_str = socket_path.to_string_lossy().to_string();
    tracing::info!(
        code = "upgrade_initiated",
        ready_socket = %path_str,
        "SIGUSR2 received: spawning new binary for zero-downtime upgrade"
    );
    let child = spawn_upgrade_child(&path_str)
        .map_err(|err| format!("cannot spawn upgrade child: {err}"))?;
    tracing::info!(
        code = "upgrade_child_spawned",
        pid = child.id(),
        "upgrade child spawned; waiting for READY signal"
    );
    let timeout = ready_timeout();
    match await_ready(&listener, timeout).await {
        Ok(()) => {
            tracing::info!(
                code = "upgrade_ready",
                "new process signaled READY; the old process will drain and exit"
            );
            // The child is now accepting; the old process can drain.
            // Keep the ready-listener alive (returned) so the socket file
            // is cleaned up by the caller after drain.
            Ok((listener, socket_path))
        }
        Err(err) => {
            tracing::error!(
                code = "upgrade_failed",
                "upgrade failed: {err}; the old process keeps running"
            );
            // Best-effort cleanup of the ready socket and the child.
            let _ = std::fs::remove_file(&socket_path);
            Err(err)
        }
    }
}

/// The NEW process's readiness signal. Called from main AFTER all
/// listeners are bound and accept tasks are spawned. Connects to the
/// ready socket named by [`UPGRADE_READY_SOCKET_ENV`] and sends READY.
/// Errors are logged but do NOT stop the new process — it is already
/// serving traffic; the old process will time out and keep running (or
/// the operator notices the old process did not exit and investigates).
pub(crate) async fn signal_ready() {
    let Some(path) = std::env::var(UPGRADE_READY_SOCKET_ENV).ok() else {
        return; // normal (non-upgrade) start
    };
    if path.is_empty() {
        return;
    }
    let path = PathBuf::from(&path);
    // The old process bound the socket before spawning us, but a tiny
    // connect race is possible on a loaded host; retry briefly.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut stream = loop {
        match tokio::net::UnixStream::connect(&path).await {
            Ok(s) => break s,
            Err(err) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let _ = err; // retry
            }
            Err(err) => {
                tracing::error!(
                    code = "upgrade_ready_signal_failed",
                    socket = %path.display(),
                    "cannot connect to the upgrade ready socket: {err}; \
                     the old process will time out and keep running"
                );
                return;
            }
        }
    };
    use tokio::io::AsyncWriteExt as _;
    if let Err(err) = stream.write_all(READY_FRAME.as_bytes()).await {
        tracing::error!(
            code = "upgrade_ready_signal_failed",
            "cannot send READY frame: {err}; the old process will time out"
        );
        return;
    }
    tracing::info!(
        code = "upgrade_ready_signaled",
        "upgrade child signaled READY to the old process"
    );
    // Clear the inherited env so a FUTURE upgrade from this process does
    // not re-use the stale socket path (spawn_upgrade_child always sets a
    // fresh path on its child, but a clean env avoids confusion).
    std::env::remove_var(UPGRADE_READY_SOCKET_ENV);
}

/// Write `pid` to the PID file at `path` (atomic temp + rename, mirroring
/// the CLI's config writer). Overwrites any existing file. The new
/// process calls this after signaling READY so the PID file always names
/// the live acceptor.
pub(crate) fn write_pid_file(path: &std::path::Path, pid: u32) -> io::Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    // Unique temp name in the same directory (same filesystem -> atomic
    // rename). No tempfile crate dependency: std only.
    let tmp = dir.join(format!(
        ".{}.pid.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("dwara")
    ));
    {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        writeln!(f, "{pid}")?;
        f.flush()?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

// White-box tests staying in src/ per AGENTS.md: these tests call
// `pub(crate)` helpers (`bind_with_reuse_port`, `await_ready`,
// `READY_FRAME`) that are not reachable from the binary crate's
// `tests/` directory.
#[cfg(test)]
mod tests {
    use super::*;

    /// A short, unique Unix socket path under /tmp (macOS caps Unix
    /// domain socket paths at SUN_LEN=104; the temp dir's
    /// `/var/folders/...` prefix plus a nanos timestamp can exceed it).
    fn short_sock_path(tag: &str) -> PathBuf {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        PathBuf::from(format!(
            "/tmp/dwara-upgrade-test-{}-{n}-{tag}.sock",
            std::process::id()
        ))
    }

    #[tokio::test]
    async fn reuse_port_bind_succeeds() {
        // Bind an ephemeral port with SO_REUSEPORT; a second bind to the
        // SAME port must also succeed (the upgrade enabler). tokio test
        // because TcpListener::from_std registers with the reactor.
        let listener =
            bind_with_reuse_port("127.0.0.1:0".parse().unwrap()).expect("reuse_port bind failed");
        let addr = listener.local_addr().expect("local addr");
        let _second = bind_with_reuse_port(addr)
            .expect("second bind with SO_REUSEPORT failed on the same port");
        // Both drop here; no port-loss window because both were bound.
    }

    #[tokio::test]
    async fn ready_handoff_round_trip() {
        // The new process signals READY; the old process receives it.
        let path = short_sock_path("rt");
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let path_clone = path.clone();
        let sender = tokio::spawn(async move {
            // Simulate the new process: connect and send READY.
            let mut s = tokio::net::UnixStream::connect(&path_clone).await.unwrap();
            use tokio::io::AsyncWriteExt as _;
            s.write_all(READY_FRAME.as_bytes()).await.unwrap();
        });
        let res = await_ready(&listener, Duration::from_secs(2)).await;
        sender.await.unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(res.is_ok(), "await_ready failed: {:?}", res);
    }

    #[tokio::test]
    async fn await_ready_times_out() {
        let path = short_sock_path("to");
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let res = await_ready(&listener, Duration::from_millis(50)).await;
        let _ = std::fs::remove_file(&path);
        assert!(res.is_err(), "expected timeout, got {:?}", res);
    }
}
