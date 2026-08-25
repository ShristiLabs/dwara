//! End-to-end hot-reload and shutdown tests (DW-006).
//!
//! The main test mirrors the manual verification: start the binary with a
//! temp config, drive steady concurrent requests, and WHILE requests flow:
//! write an invalid config (reload rejected, generation unchanged), write a
//! valid change (reload succeeds, generation advances), send SIGHUP, then
//! SIGTERM; assert zero failed requests across the whole run and a clean
//! exit 0.

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
    std::env::temp_dir().join(format!(
        "dwara-dw006-{}-{}-{tag}.yaml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

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

/// Valid change flipping the route's served content: the reload visibly
/// hot-swaps route behavior mid-traffic (DW-009 headline).
fn config_v2() -> String {
    respond_config("dwara-v2")
}

fn config_invalid() -> String {
    // Semantic error: route references an unknown service.
    config_v1().replace("service: echo", "service: missing")
}

/// Captured process output (stdout + stderr), merged after exit.
struct CapturedOutput {
    stdout: Option<std::process::ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
}

impl CapturedOutput {
    fn read_all(&mut self) -> String {
        let mut out = String::new();
        if let Some(mut s) = self.stdout.take() {
            let _ = s.read_to_string(&mut out);
        }
        let mut err = String::new();
        if let Some(mut s) = self.stderr.take() {
            let _ = s.read_to_string(&mut err);
        }
        out.push_str(&err);
        out
    }
}

fn spawn_server(addr: &str, config: &PathBuf) -> (ServerGuard, CapturedOutput) {
    let child = Command::new(env!("CARGO_BIN_EXE_dwara"))
        .env("DWARA_BIND", addr)
        .env("DWARA_CONFIG", config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn dwara binary");
    let mut guard = ServerGuard(child);
    let captured = CapturedOutput {
        stdout: guard.0.stdout.take(),
        stderr: guard.0.stderr.take(),
    };
    (guard, captured)
}

fn wait_for_ready(addr: &str, deadline: Instant) -> bool {
    while Instant::now() < deadline {
        if let Ok(mut s) = TcpStream::connect(addr) {
            if one_request(&mut s).0 {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// One GET with connection: close. Returns (ok, v1_body, v2_body): the
/// response is a 200 whose body is the pre-reload or post-reload content.
fn one_request(stream: &mut TcpStream) -> (bool, bool, bool) {
    if stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return (false, false, false);
    }
    let mut buf = Vec::new();
    if stream.read_to_end(&mut buf).is_err() {
        return (false, false, false);
    }
    let text = String::from_utf8_lossy(&buf);
    let ok = text.starts_with("HTTP/1.1 200") || text.starts_with("HTTP/1.0 200");
    (
        ok,
        text.ends_with("dwara\r\n") || text.ends_with("dwara"),
        text.ends_with("dwara-v2"),
    )
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
/// set, counting failures. Returns (total served, v1 bodies, v2 bodies).
/// Failures include any connect error, read error, non-200, or an
/// unexpected body (neither the pre- nor the post-reload content).
fn drive_requests(
    addr: &str,
    threads: usize,
    stop: Arc<AtomicBool>,
    failures: Arc<AtomicUsize>,
) -> std::thread::JoinHandle<(usize, usize, usize)> {
    let total = Arc::new(AtomicUsize::new(0));
    let v1 = Arc::new(AtomicUsize::new(0));
    let v2 = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..threads {
        let addr = addr.to_string();
        let stop = Arc::clone(&stop);
        let failures = Arc::clone(&failures);
        let total = Arc::clone(&total);
        let v1 = Arc::clone(&v1);
        let v2 = Arc::clone(&v2);
        handles.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match TcpStream::connect(&addr) {
                    Ok(mut stream) => {
                        let (ok, body_v1, body_v2) = one_request(&mut stream);
                        if ok && (body_v1 || body_v2) {
                            total.fetch_add(1, Ordering::Relaxed);
                            if body_v1 {
                                v1.fetch_add(1, Ordering::Relaxed);
                            } else {
                                v2.fetch_add(1, Ordering::Relaxed);
                            }
                        } else {
                            failures.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    // A connect refused between accept-stop and process exit
                    // would count as a failure; the server must not stop
                    // accepting until SIGTERM, so treat any error as one.
                    Err(_) => {
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    let served = Arc::clone(&total);
    let v1_out = Arc::clone(&v1);
    let v2_out = Arc::clone(&v2);
    std::thread::spawn(move || {
        for h in handles {
            h.join().expect("driver thread panicked");
        }
        (
            served.load(Ordering::Relaxed),
            v1_out.load(Ordering::Relaxed),
            v2_out.load(Ordering::Relaxed),
        )
    })
}

#[test]
fn reload_under_load_keeps_generation_safe_and_shuts_down_cleanly() {
    let addr = format!("127.0.0.1:{}", free_port());
    let config = unique_temp_config("e2e");
    std::fs::write(&config, config_v1()).unwrap();
    let (mut guard, mut stdout) = spawn_server(&addr, &config);
    assert!(
        wait_for_ready(&addr, Instant::now() + Duration::from_secs(10)),
        "dwara did not become ready on {addr}"
    );

    let stop = Arc::new(AtomicBool::new(false));
    let failures = Arc::new(AtomicUsize::new(0));
    let drivers = drive_requests(&addr, 4, Arc::clone(&stop), Arc::clone(&failures));

    // WHILE requests flow: invalid change -> rejected, generation unchanged.
    std::fs::write(&config, config_invalid()).unwrap();
    std::thread::sleep(Duration::from_millis(900));
    // Valid change -> file-watch reload succeeds, generation advances.
    std::fs::write(&config, config_v2()).unwrap();
    std::thread::sleep(Duration::from_millis(900));
    // SIGHUP: manual reload of the (unchanged, valid) file succeeds again.
    kill_signal(guard.0.id(), "HUP");
    std::thread::sleep(Duration::from_millis(500));
    // SIGTERM: graceful drain. Stop issuing NEW connections at the signal;
    // each driver's in-flight request must still complete (that is the
    // drain guarantee under test).
    kill_signal(guard.0.id(), "TERM");
    stop.store(true, Ordering::Relaxed);
    let (served, v1_count, v2_count) = drivers.join().expect("driver panicked");
    let status = wait_exit(&mut guard.0, Duration::from_secs(15));
    assert!(status.success(), "expected clean exit, got {status}");

    let out = stdout.read_all();
    let failure_count = failures.load(Ordering::Relaxed);
    println!(
        "e2e: {served} requests served ({v1_count} pre-reload bodies, {v2_count} post-reload bodies), \
         {failure_count} failures across reloads + shutdown"
    );
    assert_eq!(
        failure_count, 0,
        "dropped/failed requests during reload+shutdown: {failure_count} (served {served})"
    );
    assert!(
        served > 50,
        "expected steady traffic, only {served} requests"
    );
    assert!(
        v1_count > 0 && v2_count > 0,
        "route hot-swap must be visible: {v1_count} pre-reload and {v2_count} post-reload bodies"
    );
    assert!(
        out.contains("config reloaded (file-watch): generation 1 -> 2"),
        "expected file-watch reload log advancing to generation 2 in:\n{out}"
    );
    assert!(
        out.contains("config reload rejected"),
        "expected rejected-reload log in:\n{out}"
    );
    assert!(
        out.contains("config reloaded (sighup): generation 2 -> 3"),
        "expected SIGHUP reload to generation 3 in:\n{out}"
    );
    assert!(
        out.contains("drained, exiting"),
        "missing drain log in:\n{out}"
    );
    std::fs::remove_file(&config).ok();
}

#[test]
fn invalid_startup_config_exits_nonzero() {
    let addr = format!("127.0.0.1:{}", free_port());
    let config = unique_temp_config("bad-start");
    std::fs::write(&config, config_invalid()).unwrap();
    let (mut guard, mut stdout) = spawn_server(&addr, &config);
    let status = wait_exit(&mut guard.0, Duration::from_secs(10));
    assert!(
        !status.success(),
        "invalid startup config must exit non-zero, got {status}"
    );
    let out = stdout.read_all();
    assert!(
        out.contains("startup config invalid"),
        "missing startup failure log in:\n{out}"
    );
    assert!(
        out.contains("references unknown service"),
        "startup failure should print the validation issue in:\n{out}"
    );
    std::fs::remove_file(&config).ok();
}

#[test]
fn missing_explicit_config_exits_nonzero() {
    let addr = format!("127.0.0.1:{}", free_port());
    let config = unique_temp_config("missing");
    let (mut guard, mut stdout) = spawn_server(&addr, &config);
    let status = wait_exit(&mut guard.0, Duration::from_secs(10));
    assert!(
        !status.success(),
        "missing explicit config must exit non-zero, got {status}"
    );
    let out = stdout.read_all();
    assert!(
        out.contains("startup config load failed"),
        "missing startup log in:\n{out}"
    );
}
