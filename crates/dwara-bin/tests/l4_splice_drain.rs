//! L4 TCP splice graceful drain on shutdown (#175, REL-04, feature `l4`).
//!
//! Feature-gated exactly like the otlp suite: with the default feature
//! set this file compiles empty -- the L4 dispatcher module does not
//! exist in that build. Run with:
//!
//! ```sh
//! cargo test -p dwara-bin --features l4 --test l4_splice_drain
//! ```
//!
//! Method: a plain TCP backend (no TLS -- the L4 path is a raw byte
//! relay) stands in for the upstream. The REAL gateway binary runs with
//! a `protocol: tcp` listener splicing to that backend; a plain TCP
//! client drives one connection through it; SIGTERM triggers the
//! process-wide SpliceDrain; the test asserts the in-flight splice is
//! drained (response arrives, exit 0), force-closed at the deadline
//! (process exits on time, client read terminates), and that an idle
//! shutdown with no splices is immediate. These mirror the passthrough
//! drain tests in `tls_listener.rs` but exercise the L4 accept arm
//! (`ListenerMode::L4`), which registers splices through the same
//! `SpliceDrain` tracker.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct ServerGuard(std::process::Child);

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("addr").port()
}

fn temp_dir(tag: &str) -> PathBuf {
    // #128: a process-global counter instead of clock nanos -- nanosecond
    // stamps collide across parallel test threads.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("dwara-l4-drain-{}-{n}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Start dwara with piped stdout (the JSON subscriber writes to stdout)
/// and extra env.
fn start_server_captured_with_env(
    config_path: &std::path::Path,
    extra_env: &[(&str, &str)],
) -> (ServerGuard, Option<std::process::ChildStdout>) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dwara"));
    cmd.env("DWARA_CONFIG", config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn dwara");
    let stdout = child.stdout.take();
    (ServerGuard(child), stdout)
}

fn wait_tcp(addr: &str, deadline: Instant) {
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("dwara did not listen on {addr}");
}

fn read_stdout(stdout: &mut Option<std::process::ChildStdout>) -> String {
    let mut out = String::new();
    if let Some(mut s) = stdout.take() {
        let _ = std::io::Read::read_to_string(&mut s, &mut out);
    }
    out
}

fn wait_child_exit(child: &mut std::process::Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().expect("try_wait failed") {
            Some(status) => return status,
            None if Instant::now() > deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("dwara did not exit within {:?}", timeout)
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// Plain TCP backend (no TLS -- the L4 path is a raw byte relay) that
/// reads the client's bytes, waits `delay`, then writes a fixed
/// response and closes. The delay keeps the splice in-flight when
/// SIGTERM arrives so the drain must keep the relay alive for the
/// response to flow back through the gateway.
async fn spawn_delayed_tcp_backend(delay: Duration) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => return,
            };
            tokio::spawn(async move {
                // Drain whatever the client sent.
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf).await;
                // Hold the connection open past the SIGTERM so the
                // splice is in-flight when the drain begins.
                tokio::time::sleep(delay).await;
                let _ = stream.write_all(b"l4-drained\n").await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (port, task)
}

/// Plain TCP backend that reads the client's bytes then HOLDS the
/// connection open for `hold` without ever responding or closing. Used
/// by the drain-timeout force-close test: the splice is still in-flight
/// when the shutdown deadline expires, so the process must force-close
/// it and exit on time.
async fn spawn_holding_tcp_backend(hold: Duration) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf).await;
                tokio::time::sleep(hold).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (port, task)
}

/// Build a minimal `protocol: tcp` L4 listener config splicing every
/// connection to `back_port` (no SNI routing).
fn l4_config(dir: &std::path::Path, port: u16, back_port: u16) -> PathBuf {
    let config = dir.join("dwara.yaml");
    std::fs::write(
        &config,
        format!(
            "\
listeners:
  - name: l4-edge
    address: 127.0.0.1
    port: {port}
    protocol: tcp
    l4:
      upstream: backends
upstreams:
  - name: backends
    endpoints:
      - address: 127.0.0.1
        port: {back_port}
allow_empty_routes: true
"
        ),
    )
    .unwrap();
    config
}

/// #175 (REL-04): an in-flight L4 TCP splice must be drained (not
/// dropped) on SIGTERM. The backend delays its response past the
/// SIGTERM; the gateway's splice drain keeps the relay alive so the
/// response still arrives at the client and the process exits 0.
#[tokio::test]
async fn l4_splice_drains_on_sigterm() {
    let dir = temp_dir("drain");
    let (back_port, _backend) = spawn_delayed_tcp_backend(Duration::from_millis(400)).await;

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let config = l4_config(&dir, port, back_port);
    // Generous drain budget so the 400 ms backend delay is well inside
    // the window; the test asserts the splice completes (not that the
    // timeout fires).
    let (mut guard, mut stdout) = start_server_captured_with_env(
        &config,
        &[
            ("DWARA_SHUTDOWN_TIMEOUT_SECS", "5"),
            ("DWARA_ACCESS_LOG_SAMPLE", "0.0"),
        ],
    );
    wait_tcp(&addr, Instant::now() + Duration::from_secs(30));

    // Establish the L4 splice and send bytes so the backend is
    // mid-delay when SIGTERM arrives.
    let mut tcp = TcpStream::connect(&addr).await.expect("tcp connect");
    tcp.write_all(b"ping\n").await.unwrap();

    // SIGTERM while the splice is in-flight (backend has not responded).
    let pid = guard.0.id();
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .expect("kill -TERM");
    assert!(status.success(), "kill -TERM failed");

    // The response must still arrive through the drained splice.
    let mut resp = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(10), tcp.read_to_end(&mut resp)).await;
    assert!(
        read.is_ok(),
        "l4 response did not arrive within 10s (splice was dropped, not drained)"
    );
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.ends_with("l4-drained\n"),
        "expected drained l4 response, got: {text}"
    );

    // Close the client side so the bidirectional splice completes
    // naturally (copy_bidirectional waits for both directions to EOF).
    drop(tcp);

    // The process must exit 0 (clean drain, not a forced exit).
    let exit = wait_child_exit(&mut guard.0, Duration::from_secs(15));
    assert!(exit.success(), "expected clean exit 0, got {exit}");
    let out = read_stdout(&mut stdout);
    assert!(
        out.contains("drained, exiting"),
        "missing drain log in:\n{out}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// #175 (REL-04): when the shutdown deadline expires with an in-flight
/// L4 splice that never completes, the process must force-close it and
/// exit on time (not hang waiting for the backend). The holding backend
/// keeps the splice alive past the deadline; the drain budget is small
/// so the force-close happens promptly.
#[tokio::test]
async fn l4_splice_drain_timeout_force_closes() {
    let dir = temp_dir("drain-timeout");
    // Hold far longer than the shutdown budget so the splice is
    // provably still in-flight when the deadline expires.
    let (back_port, _backend) = spawn_holding_tcp_backend(Duration::from_secs(60)).await;

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let config = l4_config(&dir, port, back_port);
    // Small drain budget: the splice cannot complete in 2s (the
    // backend holds for 60s), so the deadline must fire and force-close.
    // stdout is not read here: the force-close log at the exact deadline
    // is a select! race (see the assertion rationale below), so the
    // reliable signal is exit timing + client read termination.
    let (mut guard, _stdout) = start_server_captured_with_env(
        &config,
        &[
            ("DWARA_SHUTDOWN_TIMEOUT_SECS", "2"),
            ("DWARA_ACCESS_LOG_SAMPLE", "0.0"),
        ],
    );
    wait_tcp(&addr, Instant::now() + Duration::from_secs(30));

    // Establish the L4 splice and send bytes so the backend is in its
    // hold loop when SIGTERM arrives.
    let mut tcp = TcpStream::connect(&addr).await.expect("tcp connect");
    tcp.write_all(b"ping\n").await.unwrap();

    // SIGTERM while the splice is in-flight (backend is holding).
    let pid = guard.0.id();
    let start = Instant::now();
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .expect("kill -TERM");
    assert!(status.success(), "kill -TERM failed");

    // The process must exit on time (force-close at the 2s deadline,
    // not hang for the backend's 60s hold). A 10s ceiling covers the
    // backlog flush + 2s drain + margin on a loaded box. The reliable
    // signal is the EXIT TIMING: the splice never completes (the
    // backend holds for 60s), so the process must exit at the ~2s
    // deadline, not before (which would mean the splice drained) and
    // not after (which would mean the drain hung). The "forcing exit"
    // vs "drained, exiting" log at the exact deadline is a select!
    // race (both branches fire at the deadline) and is NOT a reliable
    // assertion, so the test relies on timing + the client read
    // terminating + no response body.
    let exit = wait_child_exit(&mut guard.0, Duration::from_secs(10));
    assert!(
        exit.success(),
        "expected exit 0 after force-close, got {exit}"
    );
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(8),
        "shutdown took {elapsed:?}; the drain deadline did not force-close the in-flight l4 splice"
    );
    assert!(
        elapsed >= Duration::from_millis(1500),
        "shutdown took {elapsed:?}; the in-flight l4 splice was drained before the 2s deadline (force-close path not exercised)"
    );

    // The client side of the force-closed splice must terminate: the
    // read returns (with an error/empty) rather than blocking for the
    // backend's 60s hold.
    let mut resp = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut resp)).await;
    assert!(
        read.is_ok(),
        "force-closed l4 splice should terminate the client read within 5s"
    );
    assert!(
        !String::from_utf8_lossy(&resp).contains("l4-drained"),
        "force-close must not deliver the held-back response: {resp:?}"
    );
    drop(tcp);
    std::fs::remove_dir_all(&dir).ok();
}

/// #175 (REL-04): with NO in-flight L4 splices, SIGTERM must drain
/// immediately and exit 0 well inside the shutdown budget. The
/// SpliceDrain counter is zero, so `drain` returns at once and the
/// process exits without waiting for the deadline.
#[tokio::test]
async fn l4_shutdown_immediate_with_no_splices() {
    let dir = temp_dir("drain-immediate");
    // The backend is never contacted (no client connects), but the
    // config still needs a valid upstream target.
    let (back_port, _backend) = spawn_delayed_tcp_backend(Duration::from_millis(100)).await;

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let config = l4_config(&dir, port, back_port);
    // Generous budget so the test proves the drain does NOT wait for
    // it: with zero in-flight splices the exit must be near-instant.
    let (mut guard, mut stdout) = start_server_captured_with_env(
        &config,
        &[
            ("DWARA_SHUTDOWN_TIMEOUT_SECS", "30"),
            ("DWARA_ACCESS_LOG_SAMPLE", "0.0"),
        ],
    );
    wait_tcp(&addr, Instant::now() + Duration::from_secs(30));

    // The wait_tcp readiness probe connects to the L4 listener, which
    // spawns a real L4 splice (the gateway accepts the probe and dials
    // the backend). That splice must complete before SIGTERM so the
    // drain starts with zero in-flight splices. The backend task runs
    // on this test's current-thread runtime, so yield to it: the probe
    // dropped immediately (client EOF), the backend accepts, reads EOF,
    // sleeps its delay, writes, and closes -- the splice drains within
    // a few hundred ms. A blocking sync wait here would starve the
    // runtime and the backend would never accept.
    tokio::time::sleep(Duration::from_millis(800)).await;

    // No connection is established now: the probe's splice has drained
    // and the splice tracker is empty.
    let pid = guard.0.id();
    let start = Instant::now();
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .expect("kill -TERM");
    assert!(status.success(), "kill -TERM failed");

    // Must exit 0 quickly -- well under the 30s budget. A 10s ceiling is
    // generous for backlog flush + drain on a loaded CI box while still
    // proving the drain did not wait for the deadline.
    let exit = wait_child_exit(&mut guard.0, Duration::from_secs(10));
    let out = read_stdout(&mut stdout);
    assert!(
        exit.success(),
        "expected clean exit 0, got {exit}\nstdout:\n{out}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "shutdown took {:?} with no in-flight l4 splices (drain waited for the deadline)\nstdout:\n{out}",
        start.elapsed()
    );
    assert!(
        out.contains("drained, exiting"),
        "missing drain log in:\n{out}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// #175 (REL-04): several concurrent in-flight L4 splices must ALL
/// drain within the shutdown budget. Each delayed backend responds
/// after the SIGTERM; the process-wide SpliceDrain counter tracks every
/// splice and the drain waits for all of them before exiting 0.
#[tokio::test]
async fn l4_multiple_splices_all_drain() {
    let dir = temp_dir("drain-multi");
    // One shared delayed backend serves every splice; each connection
    // is handled in its own task, so all splices are in-flight at once.
    let (back_port, _backend) = spawn_delayed_tcp_backend(Duration::from_millis(400)).await;

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let config = l4_config(&dir, port, back_port);
    let (mut guard, mut stdout) = start_server_captured_with_env(
        &config,
        &[
            ("DWARA_SHUTDOWN_TIMEOUT_SECS", "5"),
            ("DWARA_ACCESS_LOG_SAMPLE", "0.0"),
        ],
    );
    wait_tcp(&addr, Instant::now() + Duration::from_secs(30));

    // Open N concurrent L4 splices and send bytes so all are in-flight
    // when SIGTERM arrives.
    const N: usize = 4;
    let mut streams = Vec::with_capacity(N);
    for _ in 0..N {
        let mut tcp = TcpStream::connect(&addr).await.expect("tcp connect");
        tcp.write_all(b"ping\n").await.unwrap();
        streams.push(tcp);
    }

    // SIGTERM while every splice is in-flight (backends are mid-delay).
    let pid = guard.0.id();
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .expect("kill -TERM");
    assert!(status.success(), "kill -TERM failed");

    // Every drained splice must deliver its response through the relay.
    let mut all_ok = true;
    for mut tcp in streams {
        let mut resp = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(10), tcp.read_to_end(&mut resp)).await;
        if read.is_err() || !String::from_utf8_lossy(&resp).ends_with("l4-drained\n") {
            all_ok = false;
        }
        drop(tcp);
    }
    assert!(
        all_ok,
        "at least one of {N} concurrent l4 splices was dropped, not drained"
    );

    // The process must exit 0 (all splices drained within the budget).
    let exit = wait_child_exit(&mut guard.0, Duration::from_secs(15));
    assert!(exit.success(), "expected clean exit 0, got {exit}");
    let out = read_stdout(&mut stdout);
    assert!(
        out.contains("drained, exiting"),
        "missing drain log in:\n{out}"
    );
    std::fs::remove_dir_all(&dir).ok();
}
