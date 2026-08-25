//! Cross-plane coherence e2e (DW-022): the admin API, the config file
//! watcher, and the dataplane as ONE process (the real `dwara` binary).
//!
//! - PATCH /config publishes (+1 generation) and the file watcher then
//!   re-publishes the identical renamed file (+1 more, coalesced): the
//!   documented watcher-driven double bump, pinned here as exactly +2.
//! - GET /config reflects a change made via a plain FILE EDIT picked up
//!   by the watcher (file -> watcher -> publish -> admin reads it back).
//! - A proxy request already IN FLIGHT when a PATCH publishes completes
//!   on the generation it started on; the NEXT request sees the new one.
//! - Admin-plane traffic never shows up in the dataplane's /metrics
//!   route counters (separate planes).
//!
//! The admin listener runs in DWARA_ADMIN_DEV=1 (plaintext loopback)
//! here: the mTLS gate itself is exhaustively covered in
//! dwara-admin/tests/admin_api.rs; this file targets watcher/admin/
//! dataplane coherence, not the TLS handshake.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
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
    let l = TcpListener::bind("127.0.0.1:0").expect("ephemeral port");
    l.local_addr().expect("addr").port()
}

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "dwara-admin-coh-{}-{}-{tag}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A respond-route config bound to `data_port` with a plaintext admin
/// listener on `admin_port` and body text `body`.
fn respond_config(body: &str, data_port: u16, admin_port: u16) -> String {
    format!(
        "listeners:\n  - name: main\n    address: 127.0.0.1\n    port: {data_port}\n\
         routes:\n  - name: all\n    service: echo\n\
         \x20   match:\n      path:\n        type: regex\n        value: /.*\n\
         \x20   action:\n      type: respond\n      status: 200\n      body: {body}\n\
         services:\n  - name: echo\n    upstream: echo-upstream\n\
         upstreams:\n  - name: echo-upstream\n    endpoints:\n      - address: 127.0.0.1\n        port: 1\n\
         admin:\n  bind: 127.0.0.1:{admin_port}\n\
         \x20 tls:\n    cert_file: /dev/null\n    key_file: /dev/null\n    client_ca_file: /dev/null\n"
    )
}

/// A proxy-route config sending everything to `upstream_port`.
fn proxy_config(data_port: u16, admin_port: u16, upstream_port: u16) -> String {
    format!(
        "listeners:\n  - name: main\n    address: 127.0.0.1\n    port: {data_port}\n\
         routes:\n  - name: all\n    service: echo\n\
         \x20   match:\n      path:\n        type: regex\n        value: /.*\n\
         \x20   action:\n      type: proxy\n\
         services:\n  - name: echo\n    upstream: echo-upstream\n\
         upstreams:\n  - name: echo-upstream\n    endpoints:\n      - address: 127.0.0.1\n        port: {upstream_port}\n\
         admin:\n  bind: 127.0.0.1:{admin_port}\n\
         \x20 tls:\n    cert_file: /dev/null\n    key_file: /dev/null\n    client_ca_file: /dev/null\n"
    )
}

fn spawn_server(config_path: &PathBuf, admin_port: u16) -> ServerGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_dwara"))
        .env("DWARA_CONFIG", config_path)
        .env("DWARA_ADMIN_DEV", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawns dwara");
    let _ = admin_port;
    ServerGuard(child)
}

/// One plaintext HTTP/1.1 request; returns (status, headers, body).
fn http(port: u16, req: &str) -> (u16, String, String) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let attempt = (|| -> std::io::Result<(u16, String, String)> {
            let mut s = TcpStream::connect(("127.0.0.1", port))?;
            s.set_read_timeout(Some(Duration::from_secs(10)))?;
            s.write_all(req.as_bytes())?;
            let mut buf = Vec::new();
            s.read_to_end(&mut buf)?;
            let text = String::from_utf8_lossy(&buf).to_string();
            let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
            let status = head
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|c| c.parse().ok())
                .unwrap_or(0);
            Ok((status, head.to_string(), body.to_string()))
        })();
        match attempt {
            // An empty/early-close read before the server is listening
            // fully: retry until the deadline.
            Ok((0, _, _)) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50))
            }
            Ok(r) => return r,
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("request to port {port} failed: {e}"),
        }
    }
}

fn admin_get(path: &str, admin_port: u16) -> (u16, String, String) {
    http(
        admin_port,
        &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    )
}

fn admin_patch(body: &str, admin_port: u16) -> (u16, String, String) {
    http(
        admin_port,
        &format!(
            "PATCH /config HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
             Content-Type: application/yaml\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        ),
    )
}

fn generation(admin_port: u16) -> u64 {
    let (status, _, body) = admin_get("/health", admin_port);
    assert_eq!(status, 200, "admin /health: {body}");
    serde_json::from_str::<serde_json::Value>(&body).unwrap()["config_generation"]
        .as_u64()
        .unwrap()
}

/// Poll until the admin-reported generation reaches `want` (watcher
/// reloads land asynchronously after a 250 ms debounce).
fn wait_generation(admin_port: u16, want: u64) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while generation(admin_port) < want {
        assert!(Instant::now() < deadline, "generation never reached {want}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn write_atomic(path: &std::path::Path, contents: &str) {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

#[test]
fn patch_publishes_and_watcher_republishes_file_edit_reaches_admin() {
    let dir = temp_dir("coherence");
    let data_port = free_port();
    let admin_port = free_port();
    let config_path = dir.join("dwara.yaml");
    std::fs::write(&config_path, respond_config("v1", data_port, admin_port)).unwrap();
    let _guard = spawn_server(&config_path, admin_port);

    let gen0 = generation(admin_port);
    // Confirm the dataplane serves v1 before touching anything.
    let (status, _, body) = http(
        data_port,
        "GET /anything HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert_eq!(body, "v1");

    // PATCH to v2: the admin publish (+1) and the watcher's re-publish
    // of the renamed file (+1, coalesced) — pinned total of exactly +2.
    let (status, headers, resp) =
        admin_patch(&respond_config("v2", data_port, admin_port), admin_port);
    assert_eq!(status, 200, "resp: {resp}");
    assert!(headers.contains(&format!("x-dwara-config-generation: {}", gen0 + 1)));
    wait_generation(admin_port, gen0 + 2);
    // The double bump stops at +2 (coalesced), never more.
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(
        generation(admin_port),
        gen0 + 2,
        "watcher burst must coalesce"
    );

    // Cross-plane coherence: admin GET /config shows the PATCHed content.
    let (status, _, cfg) = admin_get("/config", admin_port);
    assert_eq!(status, 200);
    assert!(
        cfg.contains("body: v2"),
        "admin /config must reflect the PATCH"
    );
    // The dataplane serves the new generation too.
    let (_, _, body) = http(
        data_port,
        "GET /anything HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body, "v2");

    // Now a plain FILE EDIT (the file-watch plane): watcher publishes,
    // and the admin plane reads it back.
    write_atomic(&config_path, &respond_config("v3", data_port, admin_port));
    wait_generation(admin_port, gen0 + 3);
    let (_, _, cfg) = admin_get("/config", admin_port);
    assert!(
        cfg.contains("body: v3"),
        "admin /config must reflect the file edit"
    );
    let (_, _, body) = http(
        data_port,
        "GET /anything HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body, "v3");
}

#[test]
fn patch_during_inflight_request_old_generation_completes() {
    // A slow upstream: accepts, waits out the request, answers late.
    let slow = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_port = slow.local_addr().unwrap().port();
    let upstream = std::thread::spawn(move || {
        if let Ok((mut s, _)) = slow.accept() {
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            std::thread::sleep(Duration::from_millis(700));
            let _ = s.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nslow-v1",
            );
        }
    });

    let dir = temp_dir("inflight");
    let data_port = free_port();
    let admin_port = free_port();
    let config_path = dir.join("dwara.yaml");
    std::fs::write(
        &config_path,
        proxy_config(data_port, admin_port, upstream_port),
    )
    .unwrap();
    let _guard = spawn_server(&config_path, admin_port);
    let _ = generation(admin_port); // ready

    // Fire the proxy request, then PATCH to a different config while it
    // is in flight (the upstream is sleeping).
    let mut dp = TcpStream::connect(("127.0.0.1", data_port)).unwrap();
    dp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    dp.write_all(b"GET /slow HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let (status, _, resp) = admin_patch(
        &respond_config("patched", data_port, admin_port),
        admin_port,
    );
    assert_eq!(status, 200, "resp: {resp}");

    // The in-flight request completes on the OLD generation (proxied to
    // the slow upstream), not the PATCHed respond route.
    let mut buf = Vec::new();
    dp.read_to_end(&mut buf).unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "old request completes: {text}"
    );
    assert!(
        text.ends_with("slow-v1"),
        "served by old generation: {text}"
    );

    // New requests see the NEW generation (respond route).
    let (status, _, body) = http(
        data_port,
        "GET /slow HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert_eq!(body, "patched");
    let _ = upstream.join();
}

#[test]
fn admin_traffic_absent_from_dataplane_metrics() {
    let dir = temp_dir("isolation");
    let data_port = free_port();
    let admin_port = free_port();
    let config_path = dir.join("dwara.yaml");
    std::fs::write(&config_path, respond_config("v1", data_port, admin_port)).unwrap();
    let _guard = spawn_server(&config_path, admin_port);
    let _ = generation(admin_port);

    // A burst of admin-plane traffic.
    for _ in 0..3 {
        let _ = admin_get("/stats", admin_port);
        let _ = admin_get("/config", admin_port);
        let _ = admin_get("/health", admin_port);
    }
    // Dataplane /metrics carries no admin route labels: the planes are
    // separate, admin requests never traverse the proxy accounting.
    let (status, _, metrics) = http(
        data_port,
        "GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status, 200);
    for admin_path in ["/config", "/stats", "/health", "route=\"all\""] {
        assert!(
            !metrics.contains(&format!("route=\"{admin_path}\"")),
            "admin traffic leaked into dataplane metrics ({admin_path})"
        );
    }
}
