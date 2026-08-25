//! Integration test for the M1 hello-listener: spawns the `dwara` binary
//! and asserts it serves a 200 text/plain "dwara" response.
//!
//! Each test binds its own ephemeral port (via DWARA_BIND) so the suite is
//! parallel-safe: no shared fixed port, no test interdependency.

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

/// Discover a free ephemeral port on 127.0.0.1 by binding to port 0 and
/// reading the OS-assigned port. The socket is dropped before the server
/// spawns; the bounded readiness poll covers the brief race window.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind ephemeral port");
    listener.local_addr().expect("no local addr").port()
}

fn wait_for_ready(addr: &str, deadline: Instant) -> bool {
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn start_server() -> (String, ServerGuard) {
    let addr = format!("127.0.0.1:{}", free_port());
    let child = Command::new(env!("CARGO_BIN_EXE_dwara"))
        .env("DWARA_BIND", &addr)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn dwara binary");
    let guard = ServerGuard(child);
    assert!(
        wait_for_ready(&addr, Instant::now() + Duration::from_secs(10)),
        "dwara did not become ready on {addr} within 10s"
    );
    (addr, guard)
}

fn get_response(stream: &mut TcpStream) -> String {
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("failed to write request");
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .expect("failed to read response");
    String::from_utf8_lossy(&buf).into_owned()
}

#[test]
fn hello_listener_serves_200_with_dwara_body() {
    let (addr, _server) = start_server();
    let mut stream = TcpStream::connect(&addr).expect("failed to connect");
    let response = get_response(&mut stream);

    let status_line = response.lines().next().unwrap_or_default();
    assert!(
        status_line.starts_with("HTTP/1.1 200"),
        "unexpected status line: {status_line}"
    );
    assert!(
        response
            .to_ascii_lowercase()
            .contains("content-type: text/plain"),
        "missing text/plain content-type in: {response}"
    );
    assert!(
        response.ends_with("dwara"),
        "body should be exactly 'dwara': {response}"
    );
}

#[test]
fn hello_listener_handles_multiple_connections() {
    let (addr, _server) = start_server();
    for i in 0..3 {
        let mut stream = TcpStream::connect(&addr).expect("failed to connect");
        let response = get_response(&mut stream);
        assert!(
            response.ends_with("dwara"),
            "request {i}: unexpected body: {response}"
        );
    }
}
