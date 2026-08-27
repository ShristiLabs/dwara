//! Captured-log secret redaction through the REAL binary (DW-045
//! done-when): a canary secret written through config must never appear
//! in the process's captured stdout/stderr — across startup, live
//! traffic that authenticates WITH the canary, a successful reload, and
//! a rejected reload whose validation output names the secret's field.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Inline canary carried verbatim in the config file.
const INLINE_CANARY: &str = "sk-live-canary-dw045-inline-3fa1c9";
/// Canary that only ever exists inside the referenced secret FILE.
const FILE_CANARY: &str = "sk-live-canary-dw045-file-b7d2e4";

struct ServerGuard(Child);

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
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("dwara-dw045-bin-{}-{n}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One config generation: a respond route plus a consumer holding BOTH
/// secret shapes (inline canary + `${file:...}` reference). `body` varies
/// per generation so file-watch reloads see a real content change;
/// `extra_consumer` appends a credential (used to make one generation
/// invalid).
fn config_yaml(port: u16, secret_file: &str, body: &str, extra_consumer: &str) -> String {
    format!(
        "listeners:\n  - name: edge\n    address: 127.0.0.1\n    port: {port}\n\
         routes:\n  - name: catch\n    service: local\n    match:\n      path:\n        \
         type: regex\n        value: /.*\n    action:\n        type: respond\n        \
         status: 200\n        body: {body}\nservices:\n  - name: local\n    \
         upstream: local-up\nupstreams:\n  - name: local-up\n    endpoints:\n      \
         - address: 127.0.0.1\n        port: 9\nconsumers:\n  - name: acme\n    \
         credentials:\n      - type: api_key\n        key: {INLINE_CANARY}\n      \
         - type: api_key\n        key: ${{file:{secret_file}}}\n{extra_consumer}"
    )
}

fn wait_tcp(addr: &str, deadline: Instant) {
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("dwara did not listen on {addr}");
}

/// One GET with an X-API-Key header; returns the response text.
fn http_get_with_key(addr: &str, key: &str) -> String {
    let Ok(mut stream) = TcpStream::connect(addr) else {
        return String::new();
    };
    let _ = stream.write_all(
        format!(
            "GET /x HTTP/1.1\r\nHost: localhost\r\nX-API-Key: {key}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    );
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// Poll a captured-output file until it contains `marker` (bounded).
fn wait_log_contains(path: &std::path::Path, marker: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if std::fs::read_to_string(path)
            .map(|t| t.contains(marker))
            .unwrap_or(false)
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "log never contained {marker}: {}",
        std::fs::read_to_string(path).unwrap_or_default()
    );
}

#[test]
fn canary_secrets_never_appear_in_captured_logs() {
    let dir = temp_dir("logs");
    let port = free_port();
    let secret_file = dir.join("acme.secret");
    std::fs::write(&secret_file, format!("{FILE_CANARY}\n")).unwrap();
    let config_path = dir.join("dwara.yaml");
    std::fs::write(
        &config_path,
        config_yaml(port, &secret_file.display().to_string(), "v1", ""),
    )
    .unwrap();
    // The missing-env reference must be guaranteed absent even if the
    // developer's shell happens to carry similarly-named variables.
    std::env::remove_var("DWARA_TEST_SECRET_DW045_BIN_MISSING_60d1");

    let stdout = dir.join("stdout.log");
    let stderr = dir.join("stderr.log");
    let out = std::fs::File::create(&stdout).unwrap();
    let err = std::fs::File::create(&stderr).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_dwara"))
        .env("DWARA_CONFIG", &config_path)
        // Debug level: the canary grep must hold across EVERY log level
        // an operator can turn on, not just the info default — debug
        // is where subsystems dump the most context.
        .env("DWARA_LOG", "debug")
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("spawn dwara");
    let guard = ServerGuard(child);
    let addr = format!("127.0.0.1:{port}");
    wait_tcp(&addr, Instant::now() + Duration::from_secs(10));

    // Live traffic authenticating WITH both canaries: the authn and
    // access-log paths run with the secrets in hand and must still never
    // render them.
    for key in [INLINE_CANARY, FILE_CANARY] {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let response = http_get_with_key(&addr, key);
            if response.contains("200 OK") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "no 200 for an authenticated request: {response}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    // A SUCCESSFUL reload of a changed generation still carrying the
    // secrets (validation resolves the file reference again).
    std::fs::write(
        &config_path,
        config_yaml(port, &secret_file.display().to_string(), "v2", ""),
    )
    .unwrap();
    wait_log_contains(&stdout, "config_reloaded");

    // A REJECTED reload: the same secrets plus a consumer whose env
    // reference does not resolve. The rejection log carries every
    // validation issue for the generation — the sharpest echo surface —
    // and must still never render a secret value.
    let invalid_extra = "  - name: bad\n    credentials:\n      - type: api_key\n        key: \
         ${DWARA_TEST_SECRET_DW045_BIN_MISSING_60d1}\n"
        .to_string();
    std::fs::write(
        &config_path,
        config_yaml(
            port,
            &secret_file.display().to_string(),
            "v3",
            &invalid_extra,
        ),
    )
    .unwrap();
    wait_log_contains(&stdout, "config_reload_rejected");

    // The rejection must have named the offending reference (the issue
    // text) — proof the validation path actually ran over the secret-
    // bearing generation, making the canary grep below meaningful.
    let logged = std::fs::read_to_string(&stdout).unwrap();
    assert!(
        logged.contains("DWARA_TEST_SECRET_DW045_BIN_MISSING_60d1"),
        "the rejected reload must name the unresolvable reference"
    );

    drop(guard); // SIGKILL-equivalent cleanup; the files are complete on disk

    // THE GREP: neither canary's exact bytes appear anywhere in the
    // process's captured output.
    for (name, path) in [("stdout", &stdout), ("stderr", &stderr)] {
        let captured = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            !captured.contains(INLINE_CANARY),
            "{name}: inline canary leaked into logs"
        );
        assert!(
            !captured.contains(FILE_CANARY),
            "{name}: file-secret canary leaked into logs"
        );
    }
}
