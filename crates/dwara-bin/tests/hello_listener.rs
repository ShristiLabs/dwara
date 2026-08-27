//! Integration test for the M1 listener serving real config-driven
//! responses. The hello placeholder is gone (DW-009): the binary now runs
//! the proxy dataplane, so these tests drive it with a `respond` route —
//! no backend process needed — and assert the configured body comes back.
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

/// Config with a catch-all `respond` route; exercises the full listener ->
/// dataplane -> route-action path without needing a backend.
fn config_path(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "dwara-dw009-hello-{}-{}-{tag}.yaml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
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

fn start_server(tag: &str) -> (String, ServerGuard) {
    let addr = format!("127.0.0.1:{}", free_port());
    let child = Command::new(env!("CARGO_BIN_EXE_dwara"))
        .env("DWARA_BIND", &addr)
        .env("DWARA_CONFIG", config_path(tag))
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
fn listener_serves_configured_respond_route_body() {
    let (addr, _server) = start_server("single");
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
        "body should be exactly the configured 'dwara' body: {response}"
    );
}

#[test]
fn listener_handles_multiple_connections() {
    let (addr, _server) = start_server("multi");
    for i in 0..3 {
        let mut stream = TcpStream::connect(&addr).expect("failed to connect");
        let response = get_response(&mut stream);
        assert!(
            response.ends_with("dwara"),
            "request {i}: unexpected body: {response}"
        );
    }
}

#[test]
fn unmatched_path_is_served_404_by_the_dataplane() {
    // The catch-all regex matches everything, so use a config where the
    // route only covers /v1 to prove the 404 path through the real binary.
    let addr = format!("127.0.0.1:{}", free_port());
    let config = std::env::temp_dir().join(format!("dwara-dw009-404-{}.yaml", std::process::id()));
    std::fs::write(
        &config,
        "routes:\n\
         - name: v1\n\
         \x20 service: local\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /v1\n\
         \x20 action:\n\
         \x20   type: respond\n\
         \x20   status: 200\n\
         \x20   body: ok\n\
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
    let child = Command::new(env!("CARGO_BIN_EXE_dwara"))
        .env("DWARA_BIND", &addr)
        .env("DWARA_CONFIG", &config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn dwara binary");
    let _guard = ServerGuard(child);
    assert!(wait_for_ready(
        &addr,
        Instant::now() + Duration::from_secs(10)
    ));

    let mut stream = TcpStream::connect(&addr).expect("failed to connect");
    let response = get_response(&mut stream);
    assert!(
        response.starts_with("HTTP/1.1 404"),
        "no-route path must be 404: {response}"
    );
    std::fs::remove_file(&config).ok();
}

// ---------------------------------------------------------------------------
// #124: DWARA_CREDENTIAL_PEPPER through the real binary
// ---------------------------------------------------------------------------

/// Unique scratch path for one test invocation (the config_path pattern).
fn scratch_path(tag: &str, suffix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "dwara-124-pepper-{}-{}-{tag}{suffix}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// Config with one API-key consumer: presenting the key must pass auth
/// (then hit the respond action), a wrong key must 401 even on a route
/// that does not require it.
fn pepper_config(tag: &str) -> std::path::PathBuf {
    let path = scratch_path(tag, ".yaml");
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
         \x20     port: 9\n\
         consumers:\n\
         - name: acme\n\
         \x20 credentials:\n\
         \x20   - type: api_key\n\
         \x20     key: pepper-key-1\n",
    )
    .unwrap();
    path
}

fn start_server_with_env(tag: &str, envs: &[(&str, &str)]) -> (String, ServerGuard) {
    let addr = format!("127.0.0.1:{}", free_port());
    let config = pepper_config(tag);
    let mut command = Command::new(env!("CARGO_BIN_EXE_dwara"));
    command
        .env("DWARA_BIND", &addr)
        .env("DWARA_CONFIG", &config)
        .env_remove("DWARA_CREDENTIAL_PEPPER")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (name, value) in envs {
        command.env(name, value);
    }
    let guard = ServerGuard(command.spawn().expect("failed to spawn dwara binary"));
    assert!(
        wait_for_ready(&addr, Instant::now() + Duration::from_secs(10)),
        "dwara did not become ready on {addr} within 10s"
    );
    (addr, guard)
}

fn get_with_api_key(addr: &str, key: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("failed to connect");
    stream
        .write_all(
            format!(
                "GET / HTTP/1.1\r\nHost: localhost\r\nX-API-Key: {key}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .expect("failed to write request");
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .expect("failed to read response");
    String::from_utf8_lossy(&buf).into_owned()
}

#[test]
fn pepper_env_round_trips_through_the_real_binary() {
    // DWARA_CREDENTIAL_PEPPER set: the store seeds the config key with
    // the PEPPERED hash (EnvSecretSource -> sync) and the authenticator
    // verifies it with the same pepper — the full binary path.
    let db = scratch_path("set", ".state.db");
    let (addr, _server) = start_server_with_env(
        "set",
        &[
            ("DWARA_STATE_DB", db.to_str().unwrap()),
            ("DWARA_CREDENTIAL_PEPPER", "binary-test-pepper-A"),
        ],
    );
    let ok = get_with_api_key(&addr, "pepper-key-1");
    assert!(ok.starts_with("HTTP/1.1 200"), "correct key: {ok}");
    let bad = get_with_api_key(&addr, "wrong-key");
    assert!(bad.starts_with("HTTP/1.1 401"), "wrong key: {bad}");

    // Empty value = unset (legacy-only mode, warned at startup): the
    // binary must start and the config key must still verify (seeded
    // legacy-sha256 by the empty-pepper sync).
    let db_empty = scratch_path("empty", ".state.db");
    let (addr, _server) = start_server_with_env(
        "empty",
        &[
            ("DWARA_STATE_DB", db_empty.to_str().unwrap()),
            ("DWARA_CREDENTIAL_PEPPER", ""),
        ],
    );
    let ok = get_with_api_key(&addr, "pepper-key-1");
    assert!(
        ok.starts_with("HTTP/1.1 200"),
        "empty pepper must behave as legacy mode: {ok}"
    );

    // Restart the PEPPERED database WITHOUT the pepper: the persisted
    // hmac-sha256 row fails closed (401 with the CORRECT key) — a
    // pepper lost at restart cannot silently weaken verification.
    let (addr, _server) =
        start_server_with_env("lost", &[("DWARA_STATE_DB", db.to_str().unwrap())]);
    let closed = get_with_api_key(&addr, "pepper-key-1");
    assert!(
        closed.starts_with("HTTP/1.1 401"),
        "peppered row without pepper must fail closed: {closed}"
    );
}
