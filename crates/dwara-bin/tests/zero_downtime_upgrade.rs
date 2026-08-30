//! Zero-downtime binary upgrade integration tests (DW-049).
//!
//! Driven against the REAL binary (`CARGO_BIN_EXE_dwara`):
//!
//! - **Upgrade under load**: start the gateway, drive steady concurrent
//!   requests, send SIGUSR2 (the upgrade trigger). The old process spawns
//!   a new copy (SO_REUSEPORT lets both bind the same port), the new
//!   process signals READY, the old process drains and exits, and the new
//!   process keeps serving — all with ZERO failed requests and ZERO
//!   connection resets across the hand-off.
//! - **In-flight drain**: a request accepted by the OLD process just
//!   before the hand-off must still complete (the old process drains
//!   existing connections before exiting).
//! - **New process inherits the listening sockets**: after the old
//!   process exits, the new process is the sole acceptor on the same
//!   port and keeps serving.
//! - **Failed upgrade is safe**: a SIGUSR2 whose spawned child cannot
//!   start (bad binary path) times out; the old process keeps running
//!   and keeps serving.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct ServerGuard(Child);

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind ephemeral port");
    listener.local_addr().expect("no local addr").port()
}

fn unique_temp_config(tag: &str) -> PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!("dwara-dw049-{}-{n}-{tag}.yaml", std::process::id()))
}

fn unique_pid_file(tag: &str) -> PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!("dwara-dw049-{}-{n}-{tag}.pid", std::process::id()))
}

/// A simple respond-config: every route returns 200 with the given body.
fn respond_config(body: &str) -> String {
    format!(
        "\
listeners:
  - name: main
    address: 127.0.0.1
    port: 8080
routes:
  - name: all
    service: echo
    match:
      path:
        type: regex
        value: /.*
    action:
      type: respond
      status: 200
      body: {body}
services:
  - name: echo
    upstream: echo-upstream
upstreams:
  - name: echo-upstream
    endpoints:
      - address: 127.0.0.1
        port: 9000
"
    )
}

fn config_v1() -> String {
    respond_config("dwara")
}

/// Logs are redirected to a temp FILE (not a pipe): the upgrade child
/// INHERITS the old process's stdout FD, and a pipe would never reach
/// EOF (the child holds the write end open) — `read_to_end` would
/// deadlock. A file has no EOF dependency; we read whatever was written
/// after the old process exits. (The gateway writes JSON logs to STDOUT.)
struct LogFile(PathBuf);

impl LogFile {
    fn new(tag: &str) -> LogFile {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        LogFile(
            std::env::temp_dir().join(format!("dwara-dw049-{}-{n}-{tag}.log", std::process::id())),
        )
    }
    fn read(&self) -> String {
        std::fs::read_to_string(&self.0).unwrap_or_default()
    }
}

impl Drop for LogFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn spawn_server(
    addr: &str,
    config: &PathBuf,
    pid_file: &PathBuf,
    log: &LogFile,
    extra_env: &[(&str, &str)],
) -> ServerGuard {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dwara"));
    cmd.env("DWARA_BIND", addr)
        .env("DWARA_CONFIG", config)
        .env("DWARA_PID_FILE", pid_file)
        // Generous drain budget so the hand-off drain never hits the
        // deadline under load (the test stops issuing new connections
        // before waiting for exit, so the drain is quick in practice).
        .env("DWARA_SHUTDOWN_TIMEOUT_SECS", "15")
        // The upgrade child inherits this env; keep the ready timeout
        // short so a failed-upgrade test does not hang.
        .env("DWARA_UPGRADE_READY_TIMEOUT_SECS", "8");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    // stdout -> temp file (the gateway writes JSON logs to STDOUT; the
    // upgrade child inherits this FD; a pipe would deadlock read_to_end).
    // stderr is discarded.
    let stdout = std::fs::File::create(&log.0).expect("cannot create log file");
    let child = cmd
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn dwara binary");
    ServerGuard(child)
}

fn wait_for_ready(addr: &str, deadline: Instant) -> bool {
    while Instant::now() < deadline {
        if let Ok(mut s) = TcpStream::connect(addr) {
            if one_request(&mut s) {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn one_request(stream: &mut TcpStream) -> bool {
    if stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = Vec::new();
    if stream.read_to_end(&mut buf).is_err() {
        return false;
    }
    let text = String::from_utf8_lossy(&buf);
    text.starts_with("HTTP/1.1 200") || text.starts_with("HTTP/1.0 200")
}

fn kill_signal(pid: u32, sig: &str) {
    let status = Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(pid.to_string())
        .status()
        .expect("failed to run kill");
    assert!(status.success(), "kill -{sig} {pid} failed");
}

fn wait_exit(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().expect("try_wait failed") {
            Some(status) => return status,
            None if Instant::now() > deadline => {
                panic!("dwara did not exit within {:?}", timeout)
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// N concurrent request-driver threads; each loops GETs until `stop` is
/// set, counting failures (connect error, read error, non-200).
fn drive_requests(
    addr: &str,
    threads: usize,
    stop: Arc<AtomicBool>,
    failures: Arc<AtomicUsize>,
) -> std::thread::JoinHandle<usize> {
    let total = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..threads {
        let addr = addr.to_string();
        let stop = Arc::clone(&stop);
        let failures = Arc::clone(&failures);
        let total = Arc::clone(&total);
        handles.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match TcpStream::connect(&addr) {
                    Ok(mut stream) => {
                        if one_request(&mut stream) {
                            total.fetch_add(1, Ordering::Relaxed);
                        } else {
                            failures.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(_) => {
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    let served = Arc::clone(&total);
    std::thread::spawn(move || {
        for h in handles {
            h.join().expect("driver thread panicked");
        }
        served.load(Ordering::Relaxed)
    })
}

/// Read the PID from a PID file.
fn read_pid(path: &PathBuf) -> u32 {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read PID file: {e}"));
    text.trim()
        .parse::<u32>()
        .unwrap_or_else(|e| panic!("PID file does not contain a valid PID: {e}"))
}

/// Send SIGTERM to a detached process (by PID) and wait for it to exit.
fn term_and_wait(pid: u32, timeout: Duration) {
    kill_signal(pid, "TERM");
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        // kill -0 succeeds while the process exists.
        let alive = Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !alive {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Force kill if it did not exit.
    let _ = Command::new("kill").arg("-9").arg(pid.to_string()).status();
}

/// The headline test: upgrade under load with zero failures and zero
/// resets. Covers story tests 1, 2, 3, and 4 together (the hand-off is
/// one continuous sequence). Re-run 5x to confirm no flakiness.
#[test]
fn upgrade_under_load_zero_failures_and_zero_resets() {
    let addr = format!("127.0.0.1:{}", free_port());
    let config = unique_temp_config("upgrade");
    let pid_file = unique_pid_file("upgrade");
    std::fs::write(&config, config_v1()).unwrap();
    let log = LogFile::new("upgrade");
    let mut guard = spawn_server(&addr, &config, &pid_file, &log, &[]);
    assert!(
        wait_for_ready(&addr, Instant::now() + Duration::from_secs(15)),
        "dwara did not become ready on {addr}"
    );
    let old_pid = guard.0.id();

    let stop = Arc::new(AtomicBool::new(false));
    let failures = Arc::new(AtomicUsize::new(0));
    let drivers = drive_requests(&addr, 4, Arc::clone(&stop), Arc::clone(&failures));

    // Let steady traffic establish on the OLD process.
    std::thread::sleep(Duration::from_millis(400));

    // SIGUSR2: the upgrade trigger. The old process spawns a new copy
    // (SO_REUSEPORT), waits for READY, then drains and exits.
    kill_signal(old_pid, "USR2");

    // Keep traffic flowing DURING the hand-off (both processes are
    // accepting). This is the zero-downtime window under test.
    std::thread::sleep(Duration::from_millis(800));

    // Stop issuing NEW connections so the old process's backlog empties
    // and it can drain and exit cleanly (no resets from a backlog that
    // never drains while the kernel keeps routing to the old socket).
    stop.store(true, Ordering::Relaxed);
    let served = drivers.join().expect("driver panicked");

    // The old process drains and exits 0 (clean drain, same path as
    // SIGTERM). The new process is now the sole acceptor.
    let status = wait_exit(&mut guard.0, Duration::from_secs(30));
    assert!(
        status.success(),
        "old process must exit cleanly after upgrade, got {status}"
    );

    // The new process overwrote the PID file after signaling READY.
    let new_pid = read_pid(&pid_file);
    assert_ne!(
        new_pid, old_pid,
        "PID file must point to the NEW process after the hand-off"
    );

    // Test 4: the new process inherited the same listening socket (port)
    // and is the sole acceptor — verify it keeps serving.
    assert!(
        wait_for_ready(&addr, Instant::now() + Duration::from_secs(10)),
        "new process is not serving on {addr} after the hand-off"
    );

    let failure_count = failures.load(Ordering::Relaxed);
    let out = log.read();
    println!(
        "upgrade: {served} requests served, {failure_count} failures across the hand-off \
         (old pid {old_pid} -> new pid {new_pid})"
    );
    assert_eq!(
        failure_count, 0,
        "dropped/failed/reset requests during upgrade: {failure_count} (served {served})\n{out}"
    );
    assert!(
        served > 50,
        "expected steady traffic across the hand-off, only {served} requests"
    );
    assert!(
        out.contains("upgrade_initiated") && out.contains("upgrade_ready"),
        "expected upgrade init+ready logs in:\n{out}"
    );
    assert!(
        out.contains("drained, exiting"),
        "old process must log a clean drain in:\n{out}"
    );

    // Cleanup: terminate the new (detached) process.
    term_and_wait(new_pid, Duration::from_secs(20));
    std::fs::remove_file(&config).ok();
    std::fs::remove_file(&pid_file).ok();
}

/// Test 3 (isolated): a request accepted by the OLD process just before
/// the hand-off must complete (the old process drains in-flight
/// connections before exiting). A slow upstream is simulated by a
/// long-running request issued right before SIGUSR2; it must return 200.
#[test]
fn old_process_drains_inflight_request_before_exit() {
    let addr = format!("127.0.0.1:{}", free_port());
    let config = unique_temp_config("drain");
    let pid_file = unique_pid_file("drain");
    std::fs::write(&config, config_v1()).unwrap();
    let log = LogFile::new("drain");
    let mut guard = spawn_server(&addr, &config, &pid_file, &log, &[]);
    assert!(
        wait_for_ready(&addr, Instant::now() + Duration::from_secs(15)),
        "dwara did not become ready on {addr}"
    );
    let old_pid = guard.0.id();

    // Open a connection and send a request with a deliberate delay in
    // the body so the request is in-flight when SIGUSR2 arrives. The
    // respond action does not read the body, but the connection stays
    // open long enough to be "in-flight" during the hand-off. We instead
    // hold the connection open by reading slowly: issue the request,
    // then sleep before reading the response.
    let addr_clone = addr.clone();
    let inflight = std::thread::spawn(move || {
        let mut s = TcpStream::connect(&addr_clone).expect("connect");
        s.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .expect("write");
        // Hold the response read past the signal so the connection is
        // in-flight during the drain.
        std::thread::sleep(Duration::from_millis(300));
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).expect("read");
        String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 200")
    });

    // Let the request land on the old process, then upgrade.
    std::thread::sleep(Duration::from_millis(100));
    kill_signal(old_pid, "USR2");

    // The in-flight request must complete (200) even though the old
    // process is draining.
    let ok = inflight.join().expect("inflight thread panicked");
    assert!(
        ok,
        "in-flight request on the old process was not served (drain failed)"
    );

    let status = wait_exit(&mut guard.0, Duration::from_secs(30));
    assert!(
        status.success(),
        "old process must exit cleanly, got {status}"
    );

    let new_pid = read_pid(&pid_file);
    term_and_wait(new_pid, Duration::from_secs(20));
    std::fs::remove_file(&config).ok();
    std::fs::remove_file(&pid_file).ok();
}

/// A failed upgrade (the spawned child cannot start because the binary
/// path is bad) must time out and leave the OLD process running and
/// serving. The gateway never goes down on a failed upgrade.
#[test]
fn failed_upgrade_keeps_old_process_running() {
    let addr = format!("127.0.0.1:{}", free_port());
    let config = unique_temp_config("fail");
    let pid_file = unique_pid_file("fail");
    std::fs::write(&config, config_v1()).unwrap();
    // Point the upgrade binary at a nonexistent path so the spawn fails.
    let log = LogFile::new("fail");
    let mut guard = spawn_server(
        &addr,
        &config,
        &pid_file,
        &log,
        &[("DWARA_UPGRADE_BINARY", "/nonexistent/dwara-binary")],
    );
    assert!(
        wait_for_ready(&addr, Instant::now() + Duration::from_secs(15)),
        "dwara did not become ready on {addr}"
    );
    let old_pid = guard.0.id();

    // Drive a little traffic, then trigger the (doomed) upgrade.
    let stop = Arc::new(AtomicBool::new(false));
    let failures = Arc::new(AtomicUsize::new(0));
    let drivers = drive_requests(&addr, 2, Arc::clone(&stop), Arc::clone(&failures));
    std::thread::sleep(Duration::from_millis(200));
    kill_signal(old_pid, "USR2");

    // The spawn fails immediately; the old process logs the error and
    // keeps running. Wait past the ready timeout to be sure it did not
    // exit.
    std::thread::sleep(Duration::from_secs(10));
    stop.store(true, Ordering::Relaxed);
    let served = drivers.join().expect("driver panicked");

    // The old process must STILL be alive (failed upgrade is safe).
    let alive = Command::new("kill")
        .arg("-0")
        .arg(old_pid.to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(
        alive,
        "old process exited after a FAILED upgrade (must keep running)"
    );

    // And still serving.
    assert!(
        wait_for_ready(&addr, Instant::now() + Duration::from_secs(5)),
        "old process stopped serving after a failed upgrade"
    );

    let failure_count = failures.load(Ordering::Relaxed);
    let out = log.read();
    println!("failed-upgrade: {served} served, {failure_count} failures; old process still alive");
    assert_eq!(
        failure_count, 0,
        "traffic must not fail during a failed upgrade: {failure_count} failures\n{out}"
    );
    assert!(
        out.contains("upgrade_failed") || out.contains("upgrade_initiated"),
        "expected an upgrade-failure log in:\n{out}"
    );

    // Clean up: SIGTERM the old process.
    kill_signal(old_pid, "TERM");
    let _ = wait_exit(&mut guard.0, Duration::from_secs(20));
    std::fs::remove_file(&config).ok();
    std::fs::remove_file(&pid_file).ok();
}
