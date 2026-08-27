//! Feature-inert behavior for DWARA_OTLP_ENDPOINT (#126).
//!
//! NOT feature-gated: this runs under every build. In the DEFAULT build
//! (otlp feature off) it pins the #126 contract that DWARA_OTLP_ENDPOINT
//! stays reserved-but-inert — set or not, the gateway starts, proxies,
//! and shuts down exactly as before. Under a feature-ON test pass it
//! additionally proves the enabled build degrades gracefully when the
//! collector is unreachable (background export failures never take down
//! serving). The assertions are deliberately feature-agnostic: start,
//! serve, drain, exit 0, in both worlds.
//!
//! The dedicated export-path E2E lives in `otlp_export.rs`, gated on the
//! feature like the loom suite.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
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

/// A dead port: bound then dropped so nothing listens (the collector
/// endpoint points here; connects are refused).
fn dead_port() -> u16 {
    free_port()
}

fn respond_config(tag: &str) -> std::path::PathBuf {
    // #128: counter suffix — clock nanos collide across parallel threads.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "dwara-126-inert-{}-{n}-{tag}.yaml",
        std::process::id()
    ));
    std::fs::write(
        &path,
        "routes:\n\
         - name: catch\n\
         \x20 service: local\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: regex\n\
         \x20     value: /.*\n\
         \x20 action:\n\
         \x20   type: respond\n\
         \x20   status: 200\n\
         \x20   body: dwara\n\
         services:\n\
         - name: local\n\
         \x20 upstream: local-up\n\
         upstreams:\n\
         - name: local-up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 9\n",
    )
    .unwrap();
    path
}

fn wait_ready(addr: &str, deadline: Instant) -> bool {
    while Instant::now() < deadline {
        if let Ok(mut s) = TcpStream::connect(addr) {
            if get_once(&mut s).starts_with("HTTP/1.1 200") {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// One GET attempt on an established stream; a transport failure (a
/// reset racing the exchange under parallel load — the #128 class)
/// yields the empty string so the caller can tell "nothing arrived"
/// from a real answer.
fn get_once(stream: &mut TcpStream) -> String {
    if stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return String::new();
    }
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// Connect + GET, retrying the WHOLE exchange while ZERO response bytes
/// have arrived (#128 item-H class, the same tolerance as
/// tls_listener::tls_get_retrying_reset: under parallel load the
/// kernel's FIN-to-RST replacement can discard the in-flight answer
/// before any byte lands). Once a byte has arrived the result is final —
/// no partial-data truncation is ever masked. Callers assert on response
/// CONTENT, so an exhausted 10 s budget with zero bytes is a failure.
fn get(addr: &str) -> String {
    let started = Instant::now();
    loop {
        let response = match TcpStream::connect(addr) {
            Ok(mut stream) => get_once(&mut stream),
            Err(_) => String::new(),
        };
        if !response.is_empty() {
            return response;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "no response bytes within the 10s retry budget (repeated resets or a dead listener)"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
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
                panic!("dwara did not exit within {timeout:?}")
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// DWARA_OTLP_ENDPOINT set (to an unreachable collector) must change
/// nothing observable: the gateway starts, proxies, drains on SIGTERM,
/// and exits 0. In the default build the variable is inert; in a
/// feature build the unreachable collector must degrade silently
/// instead of failing startup or serving.
#[test]
fn endpoint_set_changes_nothing_in_the_default_build() {
    let addr = format!("127.0.0.1:{}", free_port());
    let config = respond_config("inert");
    let child = Command::new(env!("CARGO_BIN_EXE_dwara"))
        .env("DWARA_BIND", &addr)
        .env("DWARA_CONFIG", &config)
        .env(
            "DWARA_OTLP_ENDPOINT",
            format!("http://127.0.0.1:{}", dead_port()),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn dwara binary");
    let mut guard = ServerGuard(child);
    assert!(
        wait_ready(&addr, Instant::now() + Duration::from_secs(10)),
        "gateway must start with DWARA_OTLP_ENDPOINT set"
    );

    for _ in 0..3 {
        let response = get(&addr);
        assert!(
            response.starts_with("HTTP/1.1 200") && response.ends_with("dwara"),
            "proxying unaffected: {response}"
        );
    }

    kill_signal(guard.0.id(), "TERM");
    let status = wait_exit(&mut guard.0, Duration::from_secs(20));
    assert!(status.success(), "clean exit regardless of OTLP state");
    drop(guard);
    std::fs::remove_file(&config).ok();
}
