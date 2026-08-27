//! Boundary-condition tests for the DW-006 reload and shutdown paths that
//! the load-bearing e2e (`reload_shutdown.rs`) does not exercise:
//!
//! - watcher edge cases: config DELETED, config replaced via atomic
//!   rename (write tmp + rename), config truncated to empty mid-write
//!   (a torn write — #129 REJECTS the zero-route reload unless
//!   `allow_empty_routes: true` opts in; both paths are pinned here),
//! - debounce correctness: a burst of writes inside the 250 ms window
//!   must coalesce to ONE reload,
//! - shutdown edge: a half-open connection (partial request, held) with
//!   `DWARA_SHUTDOWN_TIMEOUT_SECS=1` must not prevent exit,
//! - startup matrix: no config anywhere, config path pointing at a
//!   directory, a relative config path, and a zero-route config
//!   refusing cold start (#129),
//! - single keepalive connection issuing sequential requests across a
//!   reload (connection reuse under generation swap).

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
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind ephemeral port");
    listener.local_addr().expect("no local addr").port()
}

fn unique_temp_dir(tag: &str) -> PathBuf {
    // #128: counter suffix — clock nanos collide across parallel threads.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "dwara-dw006-edges-{}-{n}-{tag}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
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

/// Valid change flipping the route's served content (DW-009 hot-swap).
fn config_v2() -> String {
    respond_config("dwara-v2")
}

struct Output {
    stdout: Option<std::process::ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
}

impl Output {
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

fn spawn_server(
    addr: &str,
    config: &PathBuf,
    extra_env: &[(&str, &str)],
    cwd: Option<&PathBuf>,
) -> (ServerGuard, Output) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dwara"));
    cmd.env("DWARA_BIND", addr)
        .env("DWARA_CONFIG", config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let child = cmd.spawn().expect("failed to spawn dwara binary");
    let mut guard = ServerGuard(child);
    let out = Output {
        stdout: guard.0.stdout.take(),
        stderr: guard.0.stderr.take(),
    };
    (guard, out)
}

fn wait_for_ready(addr: &str, deadline: Instant) -> bool {
    while Instant::now() < deadline {
        if let Ok(mut s) = TcpStream::connect(addr) {
            if one_shot_request(&mut s) {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// One GET with `Connection: close`; returns the full response text, or
/// None on any transport failure.
fn one_shot_text(stream: &mut TcpStream) -> Option<String> {
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// True iff the text is an HTTP 200 carrying the pre- or post-reload
/// respond body.
fn served_ok(text: &str) -> bool {
    (text.starts_with("HTTP/1.1 200") || text.starts_with("HTTP/1.0 200"))
        && (text.ends_with("dwara") || text.ends_with("dwara-v2"))
}

/// One GET; true iff HTTP 200 with the pre- or post-reload respond body.
fn one_shot_request(stream: &mut TcpStream) -> bool {
    one_shot_text(stream).is_some_and(|text| served_ok(&text))
}

/// Connect + GET, retrying the WHOLE exchange while ZERO response bytes
/// have arrived (#128 item-H class, the same tolerance as
/// tls_listener::tls_get_retrying_reset: under parallel load the
/// kernel's FIN-to-RST replacement can discard the in-flight answer
/// before any byte lands). Once a byte has arrived the result is final —
/// no partial-data truncation is ever masked. Callers assert on response
/// CONTENT, so an exhausted 10 s budget with zero bytes is a failure.
fn one_shot_retrying(addr: &str) -> String {
    let started = Instant::now();
    loop {
        let text = TcpStream::connect(addr)
            .ok()
            .and_then(|mut stream| one_shot_text(&mut stream))
            .unwrap_or_default();
        if !text.is_empty() {
            return text;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "no response bytes within the 10s retry budget (repeated resets or a dead listener)"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// One keepalive GET (no `Connection: close`): read headers until the
/// blank line, parse Content-Length, then read exactly that many body
/// bytes. The body is the pre- or post-reload respond content.
fn keepalive_request(stream: &mut TcpStream) -> bool {
    if stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => return false,
            Ok(_) => {
                header.push(byte[0]);
                if header.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => return false,
        }
    }
    let head = String::from_utf8_lossy(&header);
    if !(head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200")) {
        return false;
    }
    let len: usize = head
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find_map(|(k, v)| {
            (k.trim().eq_ignore_ascii_case("content-length"))
                .then(|| v.trim().parse().ok())
                .flatten()
        })
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    if stream.read_exact(&mut body).is_err() {
        return false;
    }
    &body == b"dwara" || &body == b"dwara-v2"
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

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.match_indices(needle).count()
}

#[test]
fn config_deleted_while_running_keeps_serving_last_snapshot() {
    let addr = format!("127.0.0.1:{}", free_port());
    let dir = unique_temp_dir("deleted");
    let config = dir.join("dwara.yaml");
    std::fs::write(&config, config_v1()).unwrap();
    let (mut guard, mut out) = spawn_server(&addr, &config, &[], None);
    assert!(
        wait_for_ready(&addr, Instant::now() + Duration::from_secs(10)),
        "dwara did not become ready on {addr}"
    );

    std::fs::remove_file(&config).unwrap();
    // Generous margin for watcher delivery + 250 ms debounce.
    std::thread::sleep(Duration::from_millis(1500));

    // Running snapshot is kept: still serving.
    assert!(
        served_ok(&one_shot_retrying(&addr)),
        "server must keep serving after config deletion"
    );

    kill_signal(guard.0.id(), "TERM");
    let status = wait_exit(&mut guard.0, Duration::from_secs(15));
    assert!(status.success(), "expected clean exit, got {status}");
    let text = out.read_all();
    assert!(
        text.contains("config reload failed to read source"),
        "expected read-failure log for deleted config in:\n{text}"
    );
    assert!(
        text.contains("keeping running generation"),
        "expected keep-running log in:\n{text}"
    );
    assert_eq!(
        count_occurrences(&text, r#""code":"config_reloaded""#),
        0,
        "a deleted config must not produce a successful reload:\n{text}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn config_replaced_via_atomic_rename_triggers_reload() {
    let addr = format!("127.0.0.1:{}", free_port());
    let dir = unique_temp_dir("rename");
    let config = dir.join("dwara.yaml");
    std::fs::write(&config, config_v1()).unwrap();
    let (mut guard, mut out) = spawn_server(&addr, &config, &[], None);
    assert!(
        wait_for_ready(&addr, Instant::now() + Duration::from_secs(10)),
        "dwara did not become ready on {addr}"
    );

    // Atomic-save pattern: write a sibling temp file, rename over the
    // config. The watched inode is never mutated; only the directory
    // entry changes — the directory watch must observe it.
    let tmp = dir.join("dwara.yaml.tmp");
    std::fs::write(&tmp, config_v2()).unwrap();
    std::fs::rename(&tmp, &config).unwrap();
    std::thread::sleep(Duration::from_millis(1500));

    assert!(
        served_ok(&one_shot_retrying(&addr)),
        "server must keep serving after atomic config replace"
    );

    kill_signal(guard.0.id(), "TERM");
    let status = wait_exit(&mut guard.0, Duration::from_secs(15));
    assert!(status.success(), "expected clean exit, got {status}");
    let text = out.read_all();
    assert!(
        text.contains("config reloaded: generation 1 -> 2")
            && text.contains(r#""trigger":"file-watch""#),
        "atomic rename replace must trigger a file-watch reload:\n{text}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn torn_write_to_empty_config_is_rejected_and_old_generation_keeps_serving() {
    // #129 (maintainer decision): an empty document parses as a valid
    // empty Gateway (DW-003 serde defaults), which is exactly the shape
    // a truncated/torn write (truncate-then-save) leaves on disk. The
    // reload must be REJECTED naming the guard, and the old generation
    // keeps serving — a torn write can never drop all routing mid-run.
    let addr = format!("127.0.0.1:{}", free_port());
    let dir = unique_temp_dir("empty");
    let config = dir.join("dwara.yaml");
    std::fs::write(&config, config_v1()).unwrap();
    let (mut guard, mut out) = spawn_server(&addr, &config, &[], None);
    assert!(
        wait_for_ready(&addr, Instant::now() + Duration::from_secs(10)),
        "dwara did not become ready on {addr}"
    );

    // The torn write: config truncated to an empty document mid-run.
    std::fs::write(&config, "").unwrap();
    std::thread::sleep(Duration::from_millis(1500));

    // Rejected reload = rollback-is-not-published: the old generation
    // still routes and serves the pre-tear body.
    let text = one_shot_retrying(&addr);
    assert!(
        served_ok(&text),
        "old generation keeps serving after the rejected torn-write reload: {text}"
    );

    kill_signal(guard.0.id(), "TERM");
    let status = wait_exit(&mut guard.0, Duration::from_secs(15));
    assert!(status.success(), "expected clean exit, got {status}");
    let text = out.read_all();
    assert!(
        text.contains("config reload rejected"),
        "the torn write must be rejected at validation:\n{text}"
    );
    assert!(
        text.contains("routes is empty") && text.contains("allow_empty_routes"),
        "the rejection names the guard and the opt-in:\n{text}"
    );
    assert!(
        text.contains("keeping running generation 1"),
        "the keep-running log pins which generation survived:\n{text}"
    );
    assert_eq!(
        count_occurrences(&text, r#""code":"config_reloaded""#),
        0,
        "a rejected reload must not publish a generation:\n{text}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn opted_in_empty_config_reload_publishes_empty_generation_serving_404() {
    // The deliberate side of #129: the same zero-route shape WITH
    // `allow_empty_routes: true` publishes. The empty route set is then
    // live: unrouted requests stop at route resolution with a clean 404
    // (listener/global policies would rate-limit first per the
    // request-path order; none are configured here).
    let addr = format!("127.0.0.1:{}", free_port());
    let dir = unique_temp_dir("optin");
    let config = dir.join("dwara.yaml");
    std::fs::write(&config, config_v1()).unwrap();
    let (mut guard, mut out) = spawn_server(&addr, &config, &[], None);
    assert!(
        wait_for_ready(&addr, Instant::now() + Duration::from_secs(10)),
        "dwara did not become ready on {addr}"
    );

    std::fs::write(&config, "allow_empty_routes: true\n").unwrap();
    std::thread::sleep(Duration::from_millis(1500));

    // The published empty generation has no routes: the dataplane
    // answers a clean 404 — still an HTTP response from generation 2.
    let text = one_shot_retrying(&addr);
    assert!(
        text.starts_with("HTTP/1.1 404"),
        "opted-in empty generation serves 404 no-route: {text}"
    );

    kill_signal(guard.0.id(), "TERM");
    let status = wait_exit(&mut guard.0, Duration::from_secs(15));
    assert!(status.success(), "expected clean exit, got {status}");
    let text = out.read_all();
    assert!(
        text.contains("config reloaded: generation 1 -> 2")
            && text.contains(r#""trigger":"file-watch""#),
        "the opted-in config must reload in:\n{text}"
    );
    assert!(
        text.contains(r#""routes":0"#),
        "the empty generation must report zero routes:\n{text}"
    );
    assert!(
        !text.contains("config reload rejected"),
        "the explicit opt-in suppresses the guard:\n{text}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn rapid_write_burst_within_debounce_window_coalesces_to_one_reload() {
    // Contract: the reload driver waits out the 250 ms debounce window
    // from the FIRST event, drains the queue, then reloads exactly once.
    // Three writes at ~0/50/100 ms all land inside the window (>=100 ms
    // of slack against event-delivery latency), so exactly one
    // "config reloaded (file-watch)" line must appear.
    let addr = format!("127.0.0.1:{}", free_port());
    let dir = unique_temp_dir("debounce");
    let config = dir.join("dwara.yaml");
    std::fs::write(&config, config_v1()).unwrap();
    let (mut guard, mut out) = spawn_server(&addr, &config, &[], None);
    assert!(
        wait_for_ready(&addr, Instant::now() + Duration::from_secs(10)),
        "dwara did not become ready on {addr}"
    );

    for _ in 0..3 {
        std::fs::write(&config, config_v2()).unwrap();
        std::thread::sleep(Duration::from_millis(50));
    }
    // Wait well past the debounce window before shutting down so all
    // pending events have been drained.
    std::thread::sleep(Duration::from_millis(2000));

    kill_signal(guard.0.id(), "TERM");
    let status = wait_exit(&mut guard.0, Duration::from_secs(15));
    assert!(status.success(), "expected clean exit, got {status}");
    let text = out.read_all();
    let reloads = count_occurrences(&text, r#""code":"config_reloaded","trigger":"file-watch""#);
    assert_eq!(
        reloads, 1,
        "3 writes inside the debounce window must coalesce to exactly 1 reload, got {reloads}:\n{text}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn shutdown_with_half_open_connection_exits_within_short_timeout() {
    // A slow CLIENT: connect, send a partial request (no terminating
    // blank line), and hold the connection open. With a 1 s shutdown
    // budget the process must still exit (forced if necessary), quickly
    // and with its documented exit code 0.
    let addr = format!("127.0.0.1:{}", free_port());
    let dir = unique_temp_dir("halfopen");
    let config = dir.join("dwara.yaml");
    std::fs::write(&config, config_v1()).unwrap();
    let (mut guard, mut out) = spawn_server(
        &addr,
        &config,
        &[("DWARA_SHUTDOWN_TIMEOUT_SECS", "1")],
        None,
    );
    assert!(
        wait_for_ready(&addr, Instant::now() + Duration::from_secs(10)),
        "dwara did not become ready on {addr}"
    );

    let mut held = TcpStream::connect(&addr).expect("connect for half-open request");
    held.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n") // no final CRLF
        .unwrap();
    held.set_read_timeout(Some(Duration::from_millis(200))).ok();
    std::thread::sleep(Duration::from_millis(200));

    kill_signal(guard.0.id(), "TERM");
    let started = Instant::now();
    let status = wait_exit(&mut guard.0, Duration::from_secs(10));
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "process must exit promptly (well under 5 s) despite a half-open connection; took {elapsed:?}"
    );
    assert!(
        status.success(),
        "documented forced-exit path uses exit code 0, got {status}"
    );
    drop(held);
    let text = out.read_all();
    assert!(
        text.contains("forcing exit"),
        "a held half-open connection should hit the timeout-forced-exit log:\n{text}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn no_config_anywhere_in_clean_cwd_exits_nonzero() {
    // No DWARA_CONFIG and no ./dwara.yaml in the process cwd: startup
    // must fail with exit 1 (verified placement of the default-path
    // failure — the cwd is forced to an empty temp dir because the
    // repo's crates/dwara-bin contains a sample dwara.yaml).
    let addr = format!("127.0.0.1:{}", free_port());
    let dir = unique_temp_dir("nocfg");
    let child = Command::new(env!("CARGO_BIN_EXE_dwara"))
        .env("DWARA_BIND", &addr)
        .env_remove("DWARA_CONFIG")
        .current_dir(&dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn dwara binary");
    let mut guard = ServerGuard(child);
    let mut out = Output {
        stdout: guard.0.stdout.take(),
        stderr: guard.0.stderr.take(),
    };
    let status = wait_exit(&mut guard.0, Duration::from_secs(10));
    assert!(
        !status.success(),
        "missing default config must exit non-zero, got {status}"
    );
    let text = out.read_all();
    assert!(
        text.contains("startup config load failed"),
        "missing startup log in:\n{text}"
    );
    assert!(
        text.contains("dwara.yaml"),
        "failure log should name the default config path in:\n{text}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn config_path_pointing_at_directory_exits_nonzero() {
    let addr = format!("127.0.0.1:{}", free_port());
    let dir = unique_temp_dir("dircfg");
    let (mut guard, mut out) = spawn_server(&addr, &dir, &[], None);
    let status = wait_exit(&mut guard.0, Duration::from_secs(10));
    assert!(
        !status.success(),
        "DWARA_CONFIG pointing at a directory must exit non-zero, got {status}"
    );
    let text = out.read_all();
    assert!(
        text.contains("startup config load failed"),
        "expected startup load failure for directory path in:\n{text}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn zero_route_config_refuses_cold_start_and_names_the_guard() {
    // #129: the cold-start half of the zero-route guard. A config that
    // PARSES (empty Gateway, the torn-write shape) but carries no routes
    // and no opt-in must fail validation at startup: exit non-zero, the
    // startup-invalid log present, and the issue text naming routes and
    // the allow_empty_routes remedy. The JSON error line lands on the
    // process's log stream (stdout); Output::read_all covers both.
    let addr = format!("127.0.0.1:{}", free_port());
    let dir = unique_temp_dir("noroutes");
    let config = dir.join("dwara.yaml");
    std::fs::write(&config, "listeners: []\n").unwrap();
    let (mut guard, mut out) = spawn_server(&addr, &config, &[], None);
    let status = wait_exit(&mut guard.0, Duration::from_secs(10));
    assert!(
        !status.success(),
        "a zero-route config without the opt-in must refuse to start, got {status}"
    );
    let text = out.read_all();
    assert!(
        text.contains("startup config invalid"),
        "expected the startup-invalid failure log in:\n{text}"
    );
    assert!(
        text.contains("routes is empty") && text.contains("allow_empty_routes"),
        "the startup failure must carry the validation issue naming the guard:\n{text}"
    );
    assert!(
        !wait_for_ready(&addr, Instant::now() + Duration::from_millis(300)),
        "nothing may listen when startup is refused"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn relative_config_path_boots_and_serves() {
    let addr = format!("127.0.0.1:{}", free_port());
    let dir = unique_temp_dir("relcfg");
    std::fs::write(dir.join("dwara.yaml"), config_v1()).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_dwara"))
        .env("DWARA_BIND", &addr)
        .env("DWARA_CONFIG", "dwara.yaml") // relative to cwd
        .current_dir(&dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn dwara binary");
    let mut guard = ServerGuard(child);
    let _out = Output {
        stdout: guard.0.stdout.take(),
        stderr: guard.0.stderr.take(),
    };
    assert!(
        wait_for_ready(&addr, Instant::now() + Duration::from_secs(10)),
        "dwara must boot with a relative config path (cwd = temp dir)"
    );
    kill_signal(guard.0.id(), "TERM");
    let status = wait_exit(&mut guard.0, Duration::from_secs(15));
    assert!(status.success(), "expected clean exit, got {status}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn single_keepalive_connection_survives_reload() {
    // The single-connection case the 4-thread e2e can mask: ONE
    // keepalive connection issuing sequential requests across a config
    // generation swap, with zero failures and no connection reset.
    let addr = format!("127.0.0.1:{}", free_port());
    let dir = unique_temp_dir("keepalive");
    let config = dir.join("dwara.yaml");
    std::fs::write(&config, config_v1()).unwrap();
    // DW-021: 200 requests emit 200 JSON access-log lines — more than a
    // piped stdout's kernel buffer holds. Sample access logs down to
    // zero (this test asserts connection survival, not logging; the
    // reload events it greps are error/info events, always emitted).
    let (mut guard, mut out) =
        spawn_server(&addr, &config, &[("DWARA_ACCESS_LOG_SAMPLE", "0.0")], None);
    assert!(
        wait_for_ready(&addr, Instant::now() + Duration::from_secs(10)),
        "dwara did not become ready on {addr}"
    );

    let mut stream = TcpStream::connect(&addr).expect("keepalive connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut served = 0usize;
    let mut failed = 0usize;
    for i in 0..200 {
        if keepalive_request(&mut stream) {
            served += 1;
        } else {
            failed += 1;
        }
        // Trigger the reload partway through the keepalive burst.
        if i == 50 {
            std::fs::write(&config, config_v2()).unwrap();
        }
    }
    assert_eq!(
        failed, 0,
        "keepalive connection must survive the reload ({served} served)"
    );
    assert!(served > 100, "expected a full burst, served {served}");

    // Let the debounce window elapse before signaling shutdown: the
    // reload driver is aborted on SIGTERM, so a pending (debouncing)
    // reload would legitimately never fire.
    std::thread::sleep(Duration::from_millis(1500));
    kill_signal(guard.0.id(), "TERM");
    let status = wait_exit(&mut guard.0, Duration::from_secs(15));
    assert!(status.success(), "expected clean exit, got {status}");
    let text = out.read_all();
    assert!(
        text.contains("config reloaded: generation 1 -> 2")
            && text.contains(r#""trigger":"file-watch""#),
        "expected the mid-burst write to reload:\n{text}"
    );
    std::fs::remove_dir_all(&dir).ok();
}
