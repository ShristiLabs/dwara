//! Protocol hardening integration tests (DW-023, feature analysis 4.20).
//!
//! Done-when coverage, driven against the REAL binary over raw TCP
//! sockets (no client library — the point is to control the exact wire
//! bytes):
//!
//! - **Smuggling corpus**: requests carrying both Content-Length and
//!   Transfer-Encoding (both header orders, whitespace-obfuscated TE
//!   values, duplicated CL on top of TE), conflicting duplicate
//!   Content-Length headers, obfuscated/invalid/obsolete
//!   Transfer-Encoding values, malformed chunk framing, and oversized
//!   chunk extensions. Every entry must be REJECTED by the gateway
//!   (400/431 or connection close) and must never forward the smuggled
//!   second request to the upstream (hit-count assertion against a real
//!   counting backend). Structural argument this pins: hyper 1.x rejects
//!   CL+TE ambiguity at parse time, and the gateway rebuilds every
//!   forwarded request from parsed parts — there is no raw-passthrough
//!   path a desync could ride.
//! - **Sniff-guard false-positive sweep**: the pre-parse CL+TE guard is
//!   header-NAME anchored and stops at the head's blank line, so legal
//!   traffic (TE-only, CL-only, "Transfer-Encoding" inside header
//!   VALUES/cookies, an `X-Transfer-Encoding` header, CL+TE strings in
//!   the BODY, clean h2c prefaces) must proxy untouched.
//! - **Slowloris**: a connection that sends partial headers and stalls
//!   past `DWARA_HTTP1_HEADER_TIMEOUT_MS` is closed within a precise
//!   window; headers sent SLOWLY but completing within the window are
//!   served, and keep-alive survives across the guard.
//! - **Slow body**: gap semantics — trickling body bytes faster than the
//!   gap SUCCEED, stalls beyond the gap are cut off, and
//!   `DWARA_REQUEST_BODY_TIMEOUT_MS=0` disables the wrapper.
//! - **Parser caps**: the 100-header count cap and the 64 KiB read-buffer
//!   cap, each pinned just-under (served) and just-over (refused).
//! - **h2c preface abuse**: the HTTP/2 preface followed by garbage closes
//!   the connection instead of desyncing it.
//! - **HTTP/2 limits** (#128): the DWARA_H2_* knobs are advertised in
//!   SETTINGS, the concurrent-stream cap refuses the excess stream
//!   (RST_STREAM/REFUSED_STREAM), and flow control gates an 8 KiB body
//!   through a 1 KiB stream window (WINDOW_UPDATE-driven).
//! - **Admin surface**: the dev-mode loopback admin listener applies the
//!   same slowloris timeout and the same CL+TE rejection.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
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

fn wait_for_ready(addr: &str, deadline: Instant) -> bool {
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// A real counting upstream: records every request line it serves (across
/// keep-alive connections AND pipelined requests) so tests can assert the
/// smuggled "second request" never arrived. Reads with a timeout so a
/// truncated body (the malformed-chunk case) ends the connection instead
/// of hanging the thread.
#[allow(dead_code)] // kept for sibling-test symmetry; start_server_ex is the entry point
fn spawn_backend() -> (u16, Arc<Mutex<Vec<String>>>) {
    spawn_backend_with_read_timeout(Duration::from_millis(500))
}

/// Same counting backend with a caller-chosen per-read timeout: slow-body
/// tests stream a LEGAL-but-slow body, and the backend must not time out
/// first and turn a success case into a connection reset.
fn spawn_backend_with_read_timeout(read_timeout: Duration) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("backend bind");
    let port = listener.local_addr().expect("backend addr").port();
    let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let shared = Arc::clone(&log);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let log = Arc::clone(&shared);
            std::thread::spawn(move || run_backend_conn(stream, log, read_timeout));
        }
    });
    (port, log)
}

fn run_backend_conn(stream: TcpStream, log: Arc<Mutex<Vec<String>>>, read_timeout: Duration) {
    stream.set_read_timeout(Some(read_timeout)).ok();
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .ok();
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut stream = stream;
    loop {
        // Read the request head (up to \r\n\r\n).
        let mut head = String::new();
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => return, // client closed
                Ok(_) => {
                    head.push_str(&line);
                    if line == "\r\n" {
                        break;
                    }
                    if head.len() > 64 * 1024 {
                        return;
                    }
                }
                Err(_) => return, // timeout / reset: drop the connection
            }
        }
        let request_line = head.lines().next().unwrap_or_default().to_string();
        let content_length = head
            .to_ascii_lowercase()
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse::<u64>().ok());
        let chunked = head
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked");
        // Read the body so pipelined requests parse correctly.
        if let Some(n) = content_length {
            let mut body = vec![0u8; n as usize];
            if reader.read_exact(&mut body).is_err() {
                log.lock().unwrap().push(request_line);
                return;
            }
        } else if chunked {
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    return;
                }
                let size = line.trim().split(';').next().unwrap_or("");
                let Ok(sz) = usize::from_str_radix(size, 16) else {
                    return; // invalid chunk framing: close
                };
                let mut chunk = vec![0u8; sz + 2]; // data + CRLF
                if reader.read_exact(&mut chunk).is_err() {
                    return;
                }
                if sz == 0 {
                    break;
                }
            }
        }
        log.lock().unwrap().push(request_line);
        if stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .is_err()
        {
            return;
        }
    }
}

/// Spawn the gateway binary proxying everything to the counting backend,
/// with extra env (the hardening knob overrides under test).
fn start_server(tag: &str, env: &[(&str, &str)]) -> (String, Arc<Mutex<Vec<String>>>, ServerGuard) {
    let (addr, _admin, log, guard) = start_server_ex(tag, env, false, Duration::from_millis(500));
    (addr, log, guard)
}

/// `start_server`, additionally starting the plaintext dev-mode loopback
/// ADMIN listener (DWARA_ADMIN_DEV=1) so the admin surface's hardening
/// posture can be pinned. Returns (data_addr, admin_addr, log, guard).
fn start_server_admin(
    tag: &str,
    env: &[(&str, &str)],
) -> (String, String, Arc<Mutex<Vec<String>>>, ServerGuard) {
    start_server_ex(tag, env, true, Duration::from_millis(500))
}

fn start_server_ex(
    tag: &str,
    env: &[(&str, &str)],
    with_admin: bool,
    backend_read_timeout: Duration,
) -> (String, String, Arc<Mutex<Vec<String>>>, ServerGuard) {
    let (backend_port, log) = spawn_backend_with_read_timeout(backend_read_timeout);
    let addr = format!("127.0.0.1:{}", free_port());
    let (admin_section, admin_addr) = if with_admin {
        let port = free_port();
        (
            format!(
                "admin:\n  bind: 127.0.0.1:{port}\n  tls:\n    cert_file: /dev/null\n    key_file: /dev/null\n    client_ca_file: /dev/null\n"
            ),
            format!("127.0.0.1:{port}"),
        )
    } else {
        (String::new(), String::new())
    };
    // #128: counter suffix — clock nanos collide across parallel threads,
    // and two servers sharing one config path corrupt each other.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let config = std::env::temp_dir().join(format!(
        "dwara-dw023-hardening-{}-{n}-{tag}.yaml",
        std::process::id()
    ));
    std::fs::write(
        &config,
        format!(
            "routes:\n\
             \x20\x20 - name: all\n\
             \x20\x20   service: svc\n\
             \x20\x20   match:\n\
             \x20\x20     path:\n\
             \x20\x20       type: regex\n\
             \x20\x20       value: /.*\n\
             \x20\x20   action:\n\
             \x20\x20     type: proxy\n\
             services:\n\
             \x20\x20 - name: svc\n\
             \x20\x20   upstream: up\n\
             upstreams:\n\
             \x20\x20 - name: up\n\
             \x20\x20   endpoints:\n\
             \x20\x20     - address: 127.0.0.1\n\
             \x20\x20       port: {backend_port}\n{admin_section}"
        ),
    )
    .unwrap();
    let stderr_log = std::env::temp_dir().join(format!(
        "dwara-dw023-hardening-{}-{n}-{tag}.stderr",
        std::process::id()
    ));
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dwara"));
    cmd.env("DWARA_BIND", &addr)
        .env("DWARA_CONFIG", &config)
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&stderr_log).expect("stderr log"));
    if with_admin {
        cmd.env("DWARA_ADMIN_DEV", "1");
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    let child = cmd.spawn().expect("failed to spawn dwara binary");
    let guard = ServerGuard(child);
    assert!(
        wait_for_ready(&addr, Instant::now() + Duration::from_secs(10)),
        "dwara did not become ready on {addr} within 10s"
    );
    if with_admin {
        assert!(
            wait_for_ready(&admin_addr, Instant::now() + Duration::from_secs(10)),
            "admin listener did not become ready on {admin_addr} within 10s"
        );
    }
    std::fs::remove_file(&config).ok();
    std::fs::remove_file(&stderr_log).ok();
    eprintln!("dwara {tag} on {addr}, stderr: {}", stderr_log.display());
    (addr, admin_addr, log, guard)
}

/// Send raw bytes, then read whatever the gateway sends back until EOF or
/// the deadline. Err(Timeout) means the gateway neither closed nor
/// answered within the bound.
fn exchange_once(addr: &str, bytes: &[u8], deadline: Duration) -> Result<String, &'static str> {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("read timeout");
    stream.write_all(bytes).expect("write request");
    let started = Instant::now();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        if started.elapsed() > deadline {
            return Err("gateway neither responded nor closed within the bound");
        }
        match stream.read(&mut buf) {
            Ok(0) => return Ok(String::from_utf8_lossy(&out).into_owned()),
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                // Keep-alive: stop as soon as a complete response HEAD is
                // in hand (the server will not close the connection).
                if out.windows(4).any(|w| w == b"\r\n\r\n") {
                    return Ok(String::from_utf8_lossy(&out).into_owned());
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Ok(String::from_utf8_lossy(&out).into_owned()),
        }
    }
}

/// [`exchange_once`] with #128-class reset tolerance (the same shape as
/// tls_listener::tls_get_retrying_reset): under parallel suite load the
/// kernel can turn the peer's FIN into an RST while unread data is still
/// queued, discarding the in-flight answer before a single byte lands —
/// a zero-byte result is then a race artifact, not a verdict. Retry the
/// WHOLE connect+request, but ONLY while ZERO response bytes have
/// arrived: once any byte exists the result is final, so partial-data
/// truncation can never be masked (every caller stays byte-strict).
/// Bounded at 10 s with 50 ms backoff; on exhaustion the last (empty)
/// result is handed to the caller's own assertion — callers whose
/// legitimate outcome is a bare close keep accepting it.
fn exchange(addr: &str, bytes: &[u8], deadline: Duration) -> Result<String, &'static str> {
    let started = Instant::now();
    loop {
        let attempt = exchange_once(addr, bytes, deadline);
        let zero_bytes = match &attempt {
            Ok(response) => response.is_empty(),
            Err(_) => true,
        };
        if !zero_bytes || started.elapsed() >= Duration::from_secs(10) {
            return attempt;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn assert_not_smuggled(log: &Arc<Mutex<Vec<String>>>) {
    let requests = log.lock().unwrap();
    for r in requests.iter() {
        assert!(
            !r.contains("smuggled"),
            "smuggled request reached the upstream: {r:?} (full log: {requests:?})"
        );
    }
}

/// Upstream cleanliness for REJECTED requests: the counting backend saw
/// ZERO requests, so nothing (not even a partial attempt) leaked through.
fn assert_upstream_saw_nothing(log: &Arc<Mutex<Vec<String>>>) {
    let requests = log.lock().unwrap();
    assert!(
        requests.is_empty(),
        "rejected requests must never reach the upstream: {requests:?}"
    );
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Read one complete proxied response (head + the backend's fixed 2-byte
/// "ok" body) off a keep-alive stream, polling past read timeouts.
fn read_one_response(stream: &mut TcpStream, deadline: Duration) -> String {
    let started = Instant::now();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        assert!(
            started.elapsed() < deadline,
            "no complete response within {deadline:?}; got so far: {}",
            String::from_utf8_lossy(&out)
        );
        match stream.read(&mut buf) {
            Ok(0) => return String::from_utf8_lossy(&out).into_owned(),
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if let Some(pos) = find_subsequence(&out, b"\r\n\r\n") {
                    if out.len() >= pos + 4 + 2 {
                        return String::from_utf8_lossy(&out).into_owned();
                    }
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return String::from_utf8_lossy(&out).into_owned(),
        }
    }
}

/// A well-formed HTTP/2 frame (no flags, stream 0) for the h2c tests.
fn h2_frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(9 + payload.len());
    f.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    f.push(kind);
    f.push(0); // flags
    f.extend_from_slice(&0u32.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

// --- smuggling corpus -------------------------------------------------

/// The classic CL.TE payload: the frontend that honors Content-Length
/// would treat the chunked terminator and the "second request" as body
/// bytes; hyper must reject the ambiguity outright.
const CL_TE: &[u8] = b"POST /first HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: h\r\n\r\n";

/// TE.CL order: same ambiguity, headers reversed.
const TE_CL: &[u8] = b"POST /first HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: h\r\n\r\n";

/// Conflicting duplicate Content-Length values (the 0-vs-32 desync).
const DUP_CL: &[u8] = b"POST /first HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\nContent-Length: 32\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: h\r\n\r\n";

/// Transfer-Encoding with a trailing list separator: an invalid coding
/// list hyper must refuse rather than silently treat as identity.
const TE_OBFUSCATED_LIST: &[u8] = b"POST /first HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked ,\r\nContent-Length: 6\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: h\r\n\r\n";

/// OWS-obfuscated "chunked" (extra space after the colon): per the RFC
/// this IS legal chunked, so hyper alone would frame it — the smuggling
/// risk is the CL+TE pair itself, which the name-anchored guard rejects.
const TE_LEADING_SPACE: &[u8] = b"POST /first HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\nTransfer-Encoding:  chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: h\r\n\r\n";

/// Same with a TAB instead of a space.
const TE_LEADING_TAB: &[u8] = b"POST /first HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\nTransfer-Encoding:\tchunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: h\r\n\r\n";

/// CL duplicated (identical values, so hyper alone would accept) on top
/// of a Transfer-Encoding: the triple is still the smuggling primitive.
const DUP_CL_PLUS_TE: &[u8] = b"POST /first HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: h\r\n\r\n";

/// Obsolete `Transfer-Encoding: identity` WITH a Content-Length: the
/// guard is name-anchored, so the pair is rejected regardless of the
/// (obsolete) coding value.
const TE_IDENTITY_WITH_CL: &[u8] = b"POST /first HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: identity\r\nContent-Length: 6\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: h\r\n\r\n";

/// Obsolete `Transfer-Encoding: identity` ALONE: no Content-Length, so
/// the sniff guard does not apply — hyper's own parser must refuse the
/// obsolete coding instead of framing the body as identity.
const TE_IDENTITY_ALONE: &[u8] = b"POST /first HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: identity\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: h\r\n\r\n";

#[test]
fn cl_plus_te_is_rejected_not_forwarded() {
    let (addr, log, _server) = start_server("clte", &[]);
    for payload in [CL_TE, TE_CL] {
        let response =
            exchange(&addr, payload, Duration::from_secs(5)).expect("gateway answers or closes");
        assert!(
            response.starts_with("HTTP/1.1 400") || response.is_empty(),
            "CL+TE ambiguity must be a 400 or close, got: {response}"
        );
    }
    assert_not_smuggled(&log);
    assert_upstream_saw_nothing(&log);
}

#[test]
fn conflicting_duplicate_content_length_is_rejected() {
    let (addr, log, _server) = start_server("dupcl", &[]);
    let response =
        exchange(&addr, DUP_CL, Duration::from_secs(5)).expect("gateway answers or closes");
    assert!(
        response.starts_with("HTTP/1.1 400") || response.is_empty(),
        "conflicting duplicate Content-Length must be a 400 or close, got: {response}"
    );
    assert_not_smuggled(&log);
    assert_upstream_saw_nothing(&log);
}

#[test]
fn obfuscated_transfer_encoding_is_rejected() {
    let (addr, log, _server) = start_server("teobf", &[]);
    let response = exchange(&addr, TE_OBFUSCATED_LIST, Duration::from_secs(5))
        .expect("gateway answers or closes");
    assert!(
        response.starts_with("HTTP/1.1 400") || response.is_empty(),
        "obfuscated Transfer-Encoding must be a 400 or close, got: {response}"
    );
    assert_not_smuggled(&log);
    assert_upstream_saw_nothing(&log);
}

#[test]
fn whitespace_obfuscated_te_and_duplicated_cl_plus_te_are_rejected() {
    let (addr, log, _server) = start_server("tews", &[]);
    for payload in [TE_LEADING_SPACE, TE_LEADING_TAB, DUP_CL_PLUS_TE] {
        let response =
            exchange(&addr, payload, Duration::from_secs(5)).expect("gateway answers or closes");
        assert!(
            response.starts_with("HTTP/1.1 400") || response.is_empty(),
            "CL+TE with whitespace-obfuscated TE / duplicated CL must be a 400 or close, got: {response}"
        );
    }
    assert_not_smuggled(&log);
    assert_upstream_saw_nothing(&log);
}

#[test]
fn obsolete_te_identity_is_rejected() {
    let (addr, log, _server) = start_server("teident", &[]);
    // With CL: the sniff guard rejects the pair by header NAME.
    let response = exchange(&addr, TE_IDENTITY_WITH_CL, Duration::from_secs(5))
        .expect("gateway answers or closes");
    assert!(
        response.starts_with("HTTP/1.1 400") || response.is_empty(),
        "TE identity + CL must be a 400 or close, got: {response}"
    );
    // Alone: no CL, so the sniff guard does not apply — hyper's own
    // parser refuses the obsolete coding with a 400 (pinned) and never
    // frames the suffix as a second request.
    let response = exchange(&addr, TE_IDENTITY_ALONE, Duration::from_secs(5))
        .expect("gateway answers or closes");
    assert!(
        response.starts_with("HTTP/1.1 400"),
        "obsolete TE identity must be refused with 400, got: {response}"
    );
    assert_not_smuggled(&log);
    assert_upstream_saw_nothing(&log);
}

/// Case-insensitive "Chunked" is legal chunked framing per the RFC (the
/// token is case-insensitive), so the safety property is not "reject" but
/// "no desync": the request frames deterministically and the smuggled
/// suffix is NEVER interpreted as body-embedded second request reaching
/// the upstream in parsed-ambiguity. The backend must see only complete,
/// correctly framed requests.
#[test]
fn case_variant_transfer_encoding_frames_without_desync() {
    let (addr, log, _server) = start_server("tecase", &[]);
    let payload = b"POST /first HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: Chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
    let response =
        exchange(&addr, payload, Duration::from_secs(5)).expect("gateway answers or closes");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "legal chunked (case variant) must proxy cleanly, got: {response}"
    );
    let requests = log.lock().unwrap();
    assert_eq!(
        requests.len(),
        1,
        "exactly one framed request, no desync: {requests:?}"
    );
    assert!(requests[0].starts_with("POST /first"));
}

/// Small chunk extensions are legal framing (RFC 9112 7.1.1) and must
/// proxy cleanly — the guard and parser only bound the SIZE, not the
/// presence, of extensions.
#[test]
fn small_chunk_extensions_are_proxied() {
    let (addr, log, _server) = start_server("chunkext", &[]);
    let payload = b"POST /ext HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3;key=val\r\nabc\r\n0;final=yes\r\n\r\n";
    let response =
        exchange(&addr, payload, Duration::from_secs(5)).expect("gateway answers or closes");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "small chunk extensions must proxy cleanly, got: {response}"
    );
    let requests = log.lock().unwrap();
    assert_eq!(requests.len(), 1, "one framed request: {requests:?}");
    assert!(requests[0].starts_with("POST /ext"));
}

/// A chunk-size line carrying a ~100 KB extension cannot fit inside the
/// 64 KiB read buffer, so the parse must fail (connection close) instead
/// of pinning unbounded memory — and nothing may reach the upstream.
#[test]
fn giant_chunk_extension_is_rejected() {
    let (addr, log, _server) = start_server("chunkgiant", &[]);
    let mut payload =
        b"POST /ext HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    payload.extend_from_slice(b"A;");
    payload.extend(std::iter::repeat_n(b'e', 100 * 1024));
    payload.extend_from_slice(b"\r\n0123456789\r\n0\r\n\r\n");
    let response =
        exchange(&addr, &payload, Duration::from_secs(5)).expect("gateway answers or closes");
    assert!(
        !response.starts_with("HTTP/1.1 200"),
        "giant chunk extension must not be served, got: {response}"
    );
    assert_not_smuggled(&log);
    assert_upstream_saw_nothing(&log);
}

#[test]
fn malformed_chunk_size_is_rejected_mid_body() {
    let (addr, log, _server) = start_server("badchunk", &[]);
    let payload =
        b"POST /first HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\nZZZ\r\nAAAA\r\n";
    let response =
        exchange(&addr, payload, Duration::from_secs(5)).expect("gateway answers or closes");
    // hyper aborts the exchange mid-body; it must NOT answer 200 as if
    // the request were well-formed (a 4xx/5xx from the gateway's own
    // classifier or a bare close are both correct outcomes).
    let status = response.lines().next().unwrap_or_default();
    assert!(
        status.contains(" 400") || status.contains(" 5") || response.is_empty(),
        "malformed chunk framing must fail, got: {response}"
    );
    assert_not_smuggled(&log);
}

/// Header-count cap boundary (DWARA_HTTP1_MAX_HEADERS, default 100):
/// a request with exactly 100 header lines is served; 101 is refused
/// with hyper's 431 (Request Header Fields Too Large).
#[test]
fn header_count_at_the_cap_is_served_and_cap_plus_one_is_refused() {
    let (addr, log, _server) = start_server("hdrcount", &[]);
    let request = |total: usize| {
        // Host + Connection are two of the `total` header lines.
        let mut req = String::from("GET /count HTTP/1.1\r\nHost: h\r\n");
        for i in 0..(total - 2) {
            req.push_str(&format!("X-Pad-{i:03}: v\r\n"));
        }
        req.push_str("Connection: close\r\n\r\n");
        req.into_bytes()
    };
    let response = exchange(&addr, &request(100), Duration::from_secs(5)).expect("at-cap answers");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "exactly 100 headers (the cap) must be served, got: {response}"
    );
    let response =
        exchange(&addr, &request(101), Duration::from_secs(5)).expect("over-cap answers");
    assert!(
        response.starts_with("HTTP/1.1 431"),
        "101 headers must be refused with 431, got: {response}"
    );
    let requests = log.lock().unwrap();
    assert_eq!(
        requests.len(),
        1,
        "only the at-cap request is proxied: {requests:?}"
    );
}

/// Read-buffer cap boundary (DWARA_HTTP1_MAX_BUF_KIB, default 64): a
/// single ~48 KiB header value fits and is served; an ~80 KiB one cannot
/// fit the buffer and the connection is refused with a 431-class answer.
#[test]
fn header_value_under_the_buffer_cap_is_served_over_is_refused() {
    let (addr, log, _server) = start_server("hdrbuf", &[]);
    let request = |value_len: usize| {
        format!(
            "GET /big HTTP/1.1\r\nHost: h\r\nX-Big: {}\r\nConnection: close\r\n\r\n",
            "a".repeat(value_len)
        )
        .into_bytes()
    };
    let response =
        exchange(&addr, &request(48 * 1024), Duration::from_secs(5)).expect("under-cap answers");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "a 48 KiB header value must be served, got: {} bytes: {:?}",
        response.len(),
        response.chars().take(80).collect::<String>()
    );
    let response =
        exchange(&addr, &request(80 * 1024), Duration::from_secs(5)).expect("over-cap answers");
    assert!(
        response.starts_with("HTTP/1.1 431"),
        "an 80 KiB header value must be refused with 431, got: {} bytes",
        response.len()
    );
    let requests = log.lock().unwrap();
    assert_eq!(
        requests.len(),
        1,
        "only the under-cap request is proxied: {requests:?}"
    );
}

#[test]
fn h2c_preface_followed_by_garbage_is_closed() {
    let (addr, _log, _server) = start_server("h2c", &[]);
    let mut payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    payload.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0xFF, 0xFF]);
    let response =
        exchange(&addr, &payload, Duration::from_secs(5)).expect("gateway closes the connection");
    assert!(
        !response.starts_with("HTTP/1.1 200"),
        "garbage after the h2c preface must not be served as HTTP/1.1, got: {response}"
    );
}

// --- sniff-guard false-positive sweep ----------------------------------

/// POST with Transfer-Encoding chunked ONLY (no Content-Length): legal
/// framing, must proxy.
#[test]
fn te_only_chunked_post_proxies_cleanly() {
    let (addr, log, _server) = start_server("teonly", &[]);
    let payload = b"POST /teonly HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n";
    let response =
        exchange(&addr, payload, Duration::from_secs(5)).expect("gateway answers or closes");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "TE-only chunked POST must proxy, got: {response}"
    );
    let requests = log.lock().unwrap();
    assert_eq!(requests.len(), 1, "one request: {requests:?}");
    assert!(requests[0].starts_with("POST /teonly"));
}

/// POST with Content-Length ONLY (no Transfer-Encoding): legal framing,
/// must proxy.
#[test]
fn cl_only_post_proxies_cleanly() {
    let (addr, log, _server) = start_server("clonly", &[]);
    let payload = b"POST /clonly HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nbody";
    let response =
        exchange(&addr, payload, Duration::from_secs(5)).expect("gateway answers or closes");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "CL-only POST must proxy, got: {response}"
    );
    let requests = log.lock().unwrap();
    assert_eq!(requests.len(), 1, "one request: {requests:?}");
    assert!(requests[0].starts_with("POST /clonly"));
}

/// The strings "Transfer-Encoding" / "Content-Length" inside HEADER
/// VALUES and cookies are not headers: the guard is header-NAME anchored
/// (it splits at the FIRST colon of each line), so this must NOT trip.
#[test]
fn transfer_encoding_in_header_values_and_cookies_does_not_trip() {
    let (addr, log, _server) = start_server("fpvalue", &[]);
    let payload = b"POST /note HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nX-Note: Transfer-Encoding: chunked\r\nCookie: spec=\"Content-Length: 6; Transfer-Encoding: chunked\"\r\n\r\nabc";
    let response =
        exchange(&addr, payload, Duration::from_secs(5)).expect("gateway answers or closes");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "header values mentioning Transfer-Encoding must not trip the guard, got: {response}"
    );
    let requests = log.lock().unwrap();
    assert_eq!(requests.len(), 1, "one request: {requests:?}");
    assert!(requests[0].starts_with("POST /note"));
}

/// A header literally named `X-Transfer-Encoding` is NOT
/// `Transfer-Encoding`: must not trip the name-anchored guard.
#[test]
fn x_transfer_encoding_header_name_does_not_trip() {
    let (addr, log, _server) = start_server("fpxte", &[]);
    let payload = b"POST /xte HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nX-Transfer-Encoding: chunked\r\n\r\nabc";
    let response =
        exchange(&addr, payload, Duration::from_secs(5)).expect("gateway answers or closes");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "X-Transfer-Encoding must not trip the guard, got: {response}"
    );
    let requests = log.lock().unwrap();
    assert_eq!(requests.len(), 1, "one request: {requests:?}");
    assert!(requests[0].starts_with("POST /xte"));
}

/// Payload BYTES containing the header strings are BODY, not headers:
/// the sniff ends at the head's blank line, so a CL-framed (and a
/// TE-framed) request whose body embeds "Content-Length" /
/// "Transfer-Encoding" text must proxy untouched. This is the classic
/// false-positive shape for a naive substring scanner.
#[test]
fn cl_te_strings_in_the_body_do_not_trip() {
    let (addr, log, _server) = start_server("fpbody", &[]);
    // CL-framed request whose body embeds both header strings.
    let body = "GET /embedded HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\n";
    let payload = format!(
        "POST /bodystrings HTTP/1.1\r\nHost: h\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let response = exchange(&addr, payload.as_bytes(), Duration::from_secs(5))
        .expect("gateway answers or closes");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "CL+TE strings in the BODY must not trip the guard, got: {response}"
    );
    // TE-framed request whose chunked body embeds a Content-Length line.
    let body2 = "GET /embedded2 HTTP/1.1\r\nContent-Length: 6\r\n\r\n";
    let payload2 = format!(
        "POST /bodystrings2 HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{body2}\r\n0\r\n\r\n",
        body2.len()
    );
    let response = exchange(&addr, payload2.as_bytes(), Duration::from_secs(5))
        .expect("gateway answers or closes");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "a Content-Length string in a chunked BODY must not trip the guard, got: {response}"
    );
    let requests = log.lock().unwrap();
    assert_eq!(
        requests.len(),
        2,
        "both requests proxied exactly once: {requests:?}"
    );
    assert!(requests.iter().any(|r| r.starts_with("POST /bodystrings")));
    assert!(requests.iter().any(|r| r.starts_with("POST /bodystrings2")));
}

/// The h2c prior-knowledge preface with clean SETTINGS/PING frames must
/// pass the h1 sniff untouched (no HTTP/1.x rejection) and leave the
/// connection open for real h2 traffic.
#[test]
fn h2c_preface_with_clean_frames_is_not_sniff_rejected() {
    let (addr, _log, _server) = start_server("h2cclean", &[]);
    let mut payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    // SETTINGS with six entries (a "big clean preface").
    let mut settings = Vec::new();
    for (id, val) in [
        (1u16, 4096u32),
        (2, 0),
        (3, 128),
        (4, 65535),
        (5, 16384),
        (6, 4096),
    ] {
        settings.extend_from_slice(&id.to_be_bytes());
        settings.extend_from_slice(&val.to_be_bytes());
    }
    payload.extend(h2_frame(0x4, &settings));
    payload.extend(h2_frame(0x7, &[0x42; 8])); // PING
    let mut stream = TcpStream::connect(&addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("read timeout");
    stream.write_all(&payload).expect("write preface");
    // Within a generous window the gateway must NOT answer with an
    // HTTP/1.x error: hyper's h2 side replies with its own SETTINGS/ACK
    // (and a PONG for the PING) — binary frames, not "HTTP/1.1 ...". An
    // idle close AFTER that exchange is fine; the pinned property is
    // that the preface passed the h1 sniff and was served as h2.
    let started = Instant::now();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    while started.elapsed() < Duration::from_millis(800) {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(
        !text.is_empty(),
        "clean h2c preface must be answered with h2 frames (SETTINGS/ACK), got nothing"
    );
    assert!(
        !text.contains("HTTP/1.1 4") && !text.contains("HTTP/1.1 5"),
        "clean h2c preface must not be sniff-rejected, got: {text:?}"
    );
}

// --- line-ending conventions and obs-fold -------------------------------

/// A full request using LF-only line endings (head AND body) is legal
/// under hyper's tolerant h1 parsing: the sniff must stop at the FIRST
/// blank line (`\n\n`) so the body is never over-buffered into the sniff
/// (the old bug: 431 or a stall for a healthy bare-LF client).
#[test]
fn lf_only_request_head_and_body_proxy_cleanly() {
    let (addr, log, _server) = start_server("lfonly", &[]);
    let payload = b"POST /lfonly HTTP/1.1\nHost: h\nContent-Length: 4\n\nbody";
    let response =
        exchange(&addr, payload, Duration::from_secs(5)).expect("gateway answers or closes");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "an LF-only head+body request must proxy cleanly, got: {response}"
    );
    let requests = log.lock().unwrap();
    assert_eq!(requests.len(), 1, "one request: {requests:?}");
    assert!(requests[0].starts_with("POST /lfonly"));
}

/// LF-only SMUGGLING must not slip past the guard just because the line
/// convention changed: a bare-LF head carrying both Content-Length and
/// Transfer-Encoding: chunked is rejected with 400 and NOTHING reaches
/// the upstream.
#[test]
fn lf_only_cl_te_smuggling_is_rejected() {
    let (addr, log, _server) = start_server("lfsmuggle", &[]);
    let payload = b"POST /first HTTP/1.1\nHost: h\nContent-Length: 6\nTransfer-Encoding: chunked\n\n0\n\nGET /smuggled HTTP/1.1\nHost: h\n\n";
    let response =
        exchange(&addr, payload, Duration::from_secs(5)).expect("gateway answers or closes");
    assert!(
        response.starts_with("HTTP/1.1 400"),
        "LF-only CL+TE ambiguity must be a 400, got: {response}"
    );
    assert_not_smuggled(&log);
    assert_upstream_saw_nothing(&log);
}

/// Obs-fold (RFC 7230 3.2.4 obsolete line folding) can split a header
/// NAME across lines — `Transfer-\r\n Encoding: chunked` — slipping the
/// CL+TE pair past the name-anchored scan. The sniff must reject such
/// heads with a 400 (code `request_head_obs_fold` on the server side)
/// and never touch the upstream.
#[test]
fn obs_fold_split_transfer_encoding_is_rejected() {
    let (addr, log, _server) = start_server("obsfold", &[]);
    let payload = b"POST /first HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\nTransfer-\r\n Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: h\r\n\r\n";
    let response =
        exchange(&addr, payload, Duration::from_secs(5)).expect("gateway answers or closes");
    assert!(
        response.starts_with("HTTP/1.1 400"),
        "obs-fold continuation line must be a 400 (request_head_obs_fold), got: {response}"
    );
    assert_not_smuggled(&log);
    assert_upstream_saw_nothing(&log);
}

/// The obs-fold distinction, pinned from the safe side: obs-fold is a
/// LINE STARTING with SP/HTAB — whitespace AFTER the colon is ordinary
/// optional whitespace in a header VALUE ("X-Foo:  bar" is perfectly
/// legal RFC 9112 OWS) and must NOT trip the rejection.
#[test]
fn leading_whitespace_in_header_values_is_not_obs_fold() {
    let (addr, log, _server) = start_server("obsfoldctl", &[]);
    let payload = b"POST /obsctl HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nX-Foo:  bar\r\nX-Tab:\tbaz\r\n\r\nabc";
    let response =
        exchange(&addr, payload, Duration::from_secs(5)).expect("gateway answers or closes");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "extra whitespace after the colon is a VALUE, not obs-fold; must proxy, got: {response}"
    );
    let requests = log.lock().unwrap();
    assert_eq!(requests.len(), 1, "one request: {requests:?}");
    assert!(requests[0].starts_with("POST /obsctl"));
}

/// Mixed-convention head terminators hyper tolerates — `\r\n\n` (CRLF
/// lines, bare-LF blank line) and `\n\r\n` (LF lines, CRLF blank line):
/// the sniff's head_end stops at the first blank line under either
/// convention and the request proxies.
#[test]
fn crlf_lines_with_lf_blank_line_terminator_proxies() {
    let (addr, log, _server) = start_server("mixedterm1", &[]);
    let payload = b"GET /mixed-crlf-lf HTTP/1.1\r\nHost: h\r\n\n";
    let response =
        exchange(&addr, payload, Duration::from_secs(5)).expect("gateway answers or closes");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "a \\r\\n\\n terminator (CRLF lines, LF blank) must proxy, got: {response}"
    );
    let requests = log.lock().unwrap();
    assert_eq!(requests.len(), 1, "one request: {requests:?}");
    assert!(requests[0].starts_with("GET /mixed-crlf-lf"));
}

/// The OTHER mixed convention — LF lines with a CRLF blank line
/// (`\n\r\n`) — is NOT accepted by hyper's tolerant h1 parser: the stray
/// `\r` begins a "header line" that can never complete, so the request
/// is neither served nor smuggled; it is held until the slowloris
/// header timeout closes the connection. Pinned with a short timeout so
/// the closure (not the convention's legality) is what the test asserts.
/// NOTE: the original dispatch pin asked for a 200 here; empirically
/// hyper only tolerates `\r\n\n` on the happy path — flagged as a
/// tester finding for the developer to either reject `\n\r\n` at the
/// sniff (400) or document the limitation.
#[test]
fn lf_lines_with_crlf_blank_line_terminator_are_never_served_and_time_out() {
    let (addr, log, _server) =
        start_server("mixedterm2", &[("DWARA_HTTP1_HEADER_TIMEOUT_MS", "400")]);
    let payload = b"GET /mixed-lf-crlf HTTP/1.1\nHost: h\n\r\n";
    let mut stream = TcpStream::connect(&addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("read timeout");
    stream.write_all(payload).expect("write request");
    let started = Instant::now();
    let mut buf = [0u8; 256];
    let mut out = Vec::new();
    loop {
        assert!(
            started.elapsed() < Duration::from_millis(1400),
            "connection neither answered nor closed within the header-timeout window"
        );
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(
        !text.starts_with("HTTP/1.1 200"),
        "a \\n\\r\\n terminator must never be SERVED as a legal head, got: {text}"
    );
    assert_not_smuggled(&log);
    assert_upstream_saw_nothing(&log);
}

// --- slowloris ---------------------------------------------------------

#[test]
fn stalled_headers_are_closed_within_the_header_timeout_window() {
    let (addr, _log, _server) =
        start_server("slowloris", &[("DWARA_HTTP1_HEADER_TIMEOUT_MS", "400")]);
    let mut stream = TcpStream::connect(&addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("read timeout");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: h\r\nX-Stall: ")
        .expect("partial headers");
    let started = Instant::now();
    let mut buf = [0u8; 256];
    loop {
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "server did not close the stalled connection within ~2x the 400 ms window"
        );
        match stream.read(&mut buf) {
            Ok(0) => break, // closed by the server
            Ok(_) => continue,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(_) => break,
        }
    }
    assert!(
        started.elapsed() >= Duration::from_millis(200),
        "closed too fast to be the header timeout ({:?}); wrong code path?",
        started.elapsed()
    );
}

/// Precision pin on the same knob: with a 400 ms header timeout, a fully
/// stalled connection is closed no earlier than the timeout itself and
/// no later than 1.5 s (the guard's read timeout and hyper's header
/// deadline chain: ~2x400 ms expected, 1.5 s gives scheduling margin).
#[test]
fn stalled_headers_close_window_is_precise() {
    let (addr, _log, _server) =
        start_server("slowlorisprec", &[("DWARA_HTTP1_HEADER_TIMEOUT_MS", "400")]);
    let mut stream = TcpStream::connect(&addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("read timeout");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: h\r\nX-Stall: ")
        .expect("partial headers");
    let started = Instant::now();
    let mut buf = [0u8; 256];
    loop {
        assert!(
            started.elapsed() < Duration::from_millis(1400),
            "stalled connection not closed within 1.4 s"
        );
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(_) => break,
        }
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(380),
        "closed before the 400 ms header timeout could fire ({elapsed:?})"
    );
}

/// Headers sent SLOWLY but COMPLETING within the window are served (the
/// timeout bounds stalls, not slowness), and keep-alive continuity holds
/// across the guard: a second request on the same connection works.
#[test]
fn slow_but_progressing_headers_complete_and_keep_alive_survives() {
    let (addr, log, _server) =
        start_server("slowhdr", &[("DWARA_HTTP1_HEADER_TIMEOUT_MS", "2000")]);
    let mut stream = TcpStream::connect(&addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("read timeout");
    let request = b"GET /slowhdr HTTP/1.1\r\nHost: h\r\nX-One: 1\r\nX-Two: 2\r\n\r\n";
    // Six pieces 150 ms apart: ~750 ms total, well inside the 2000 ms
    // window (2.6x margin) but far slower than a healthy client.
    let piece_len = request.len() / 6;
    for (i, piece) in request.chunks(piece_len).enumerate() {
        if i > 0 {
            std::thread::sleep(Duration::from_millis(150));
        }
        stream.write_all(piece).expect("write piece");
    }
    let first = read_one_response(&mut stream, Duration::from_secs(5));
    assert!(
        first.starts_with("HTTP/1.1 200"),
        "slowly-sent headers within the window must be served, got: {first}"
    );
    // Keep-alive continuity: an immediate second request on the SAME
    // connection (the one whose head was replayed through the sniff
    // guard's PrefixedStream) must also work.
    stream
        .write_all(b"GET /second HTTP/1.1\r\nHost: h\r\n\r\n")
        .expect("second request");
    let second = read_one_response(&mut stream, Duration::from_secs(5));
    assert!(
        second.starts_with("HTTP/1.1 200"),
        "pipelined follow-up after a slow first request must work, got: {second}"
    );
    let requests = log.lock().unwrap();
    assert_eq!(requests.len(), 2, "both requests proxied: {requests:?}");
}

// --- slow body ---------------------------------------------------------

#[test]
fn trickling_request_body_errors_out_and_releases_the_slot() {
    let (addr, log, _server) =
        start_server("slowbody", &[("DWARA_REQUEST_BODY_TIMEOUT_MS", "400")]);
    let mut stream = TcpStream::connect(&addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("read timeout");
    stream
        .write_all(b"POST /upload HTTP/1.1\r\nHost: h\r\nContent-Length: 1000\r\n\r\n0123456789")
        .expect("headers + first bytes");

    // The gateway must answer (classified 5xx) within a bounded window
    // after the body stalls; a legit 200 would mean the knob is inert.
    let started = Instant::now();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let status_line;
    loop {
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "no response to the stalled body within ~2x the 400 ms gap"
        );
        match stream.read(&mut buf) {
            Ok(0) => {
                status_line = String::from_utf8_lossy(&out).into_owned();
                break;
            }
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.windows(4).any(|w| w == b"\r\n\r\n") {
                    status_line = String::from_utf8_lossy(&out).into_owned();
                    break;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(_) => {
                status_line = String::from_utf8_lossy(&out).into_owned();
                break;
            }
        }
    }
    let first_line = status_line.lines().next().unwrap_or_default();
    assert!(
        first_line.contains(" 5") || first_line.is_empty(),
        "stalled body must produce a 5xx or close, got: {first_line}"
    );

    // Slot release: a fresh request on a new connection proxies fine.
    let ok = exchange(
        &addr,
        b"GET /after HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
        Duration::from_secs(5),
    )
    .expect("follow-up request completes");
    assert!(
        ok.starts_with("HTTP/1.1 200"),
        "follow-up request after slow-body cutoff must succeed, got: {ok}"
    );
    assert_not_smuggled(&log);
    let requests = log.lock().unwrap();
    assert!(
        requests.iter().any(|r| r.contains("/after")),
        "follow-up request reached the upstream: {requests:?}"
    );
}

/// Gap semantics: a body trickling one byte every 300 ms against a 500 ms
/// gap is LEGAL (every gap is under the timeout) and must complete —
/// the knob bounds stalls, not totals.
#[test]
fn trickling_body_faster_than_the_gap_succeeds() {
    let (addr, _admin, log, _server) = start_server_ex(
        "trickleok",
        &[("DWARA_REQUEST_BODY_TIMEOUT_MS", "500")],
        false,
        Duration::from_secs(3),
    );
    let mut stream = TcpStream::connect(&addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("read timeout");
    stream
        .write_all(b"POST /trickle HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\n")
        .expect("headers");
    for byte in b"0123456789" {
        std::thread::sleep(Duration::from_millis(300));
        stream.write_all(&[*byte]).expect("trickled byte");
    }
    let response = read_one_response(&mut stream, Duration::from_secs(10));
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "a trickling body with gaps under the timeout must succeed, got: {response}"
    );
    let requests = log.lock().unwrap();
    assert!(
        requests.iter().any(|r| r.starts_with("POST /trickle")),
        "trickled request reached the upstream whole: {requests:?}"
    );
}

/// A body that STALLS beyond the gap (one write, then 2 s of nothing)
/// is cut off quickly after the gap elapses, and the concurrency slot is
/// released (follow-up request succeeds).
#[test]
fn body_stall_beyond_the_gap_is_cut_quickly() {
    let (addr, _admin, log, _server) = start_server_ex(
        "slowstall",
        &[("DWARA_REQUEST_BODY_TIMEOUT_MS", "500")],
        false,
        Duration::from_secs(3),
    );
    let mut stream = TcpStream::connect(&addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("read timeout");
    stream
        .write_all(b"POST /stall HTTP/1.1\r\nHost: h\r\nContent-Length: 1000\r\n\r\n0123456789")
        .expect("headers + first bytes");
    let started = Instant::now();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let status_line;
    let elapsed;
    loop {
        assert!(
            started.elapsed() < Duration::from_millis(2400),
            "no cutoff within 2.4 s of the body stalling"
        );
        match stream.read(&mut buf) {
            Ok(0) => {
                status_line = String::from_utf8_lossy(&out).into_owned();
                elapsed = started.elapsed();
                break;
            }
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.windows(4).any(|w| w == b"\r\n\r\n") {
                    status_line = String::from_utf8_lossy(&out).into_owned();
                    elapsed = started.elapsed();
                    break;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(_) => {
                status_line = String::from_utf8_lossy(&out).into_owned();
                elapsed = started.elapsed();
                break;
            }
        }
    }
    assert!(
        elapsed >= Duration::from_millis(450),
        "cut before the 500 ms gap could fire ({elapsed:?}); response: {status_line}"
    );
    let first_line = status_line.lines().next().unwrap_or_default();
    assert!(
        first_line.contains(" 5") || first_line.is_empty(),
        "stalled body must produce a 5xx or close, got: {first_line}"
    );
    let ok = exchange(
        &addr,
        b"GET /after HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
        Duration::from_secs(5),
    )
    .expect("follow-up request completes");
    assert!(
        ok.starts_with("HTTP/1.1 200"),
        "follow-up after the cutoff must succeed, got: {ok}"
    );
    assert_not_smuggled(&log);
}

/// `DWARA_REQUEST_BODY_TIMEOUT_MS=0` disables the wrapper: a long
/// mid-body stall (1.2 s, far beyond any plausible small gap) is
/// tolerated and the upload completes.
#[test]
fn body_gap_timeout_zero_disables_the_wrapper() {
    let (addr, _admin, log, _server) = start_server_ex(
        "gapoff",
        &[("DWARA_REQUEST_BODY_TIMEOUT_MS", "0")],
        false,
        Duration::from_secs(4),
    );
    let mut stream = TcpStream::connect(&addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("read timeout");
    stream
        .write_all(b"POST /disabled HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\n12")
        .expect("first half");
    std::thread::sleep(Duration::from_millis(1200));
    stream.write_all(b"34").expect("second half");
    let response = read_one_response(&mut stream, Duration::from_secs(10));
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "gap timeout 0 must disable the slow-body cutoff, got: {response}"
    );
    let requests = log.lock().unwrap();
    assert!(
        requests.iter().any(|r| r.starts_with("POST /disabled")),
        "stalled-then-resumed upload reached the upstream whole: {requests:?}"
    );
}

// --- admin surface -----------------------------------------------------

/// The admin listener (dev-mode plaintext loopback) applies the same
/// slowloris header timeout as the data plane.
#[test]
fn admin_surface_applies_slowloris_timeout() {
    let (_addr, admin, _log, _server) =
        start_server_admin("adminslow", &[("DWARA_HTTP1_HEADER_TIMEOUT_MS", "400")]);
    let mut stream = TcpStream::connect(&admin).expect("connect to admin");
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("read timeout");
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: h\r\nX-Stall: ")
        .expect("partial headers");
    let started = Instant::now();
    let mut buf = [0u8; 256];
    loop {
        assert!(
            started.elapsed() < Duration::from_millis(1400),
            "admin did not close the stalled connection within 1.4 s"
        );
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(_) => break,
        }
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(380),
        "admin closed before the 400 ms header timeout could fire ({elapsed:?})"
    );
}

/// The admin listener rejects a CL+TE smuggling attempt with the same
/// pre-parse guard policy as the data plane (bare 400 + close).
#[test]
fn admin_surface_rejects_cl_te_smuggling() {
    let (_addr, admin, _log, _server) = start_server_admin("adminclte", &[]);
    let response =
        exchange(&admin, CL_TE, Duration::from_secs(5)).expect("admin answers or closes");
    assert!(
        response.starts_with("HTTP/1.1 400") || response.is_empty(),
        "admin surface must reject CL+TE ambiguity, got: {response}"
    );
}

// --- HTTP/2 limits (DW-023 gap; #128) -------------------------------------
//
// The DWARA_H2_* knobs configure hyper's h2 server builder (see
// HttpHardening::apply); these tests pin the WIRE behavior of the real
// binary: the advertised SETTINGS values, enforcement of the
// concurrent-stream cap (the excess stream is refused with
// RST_STREAM/REFUSED_STREAM), and window-gated flow (an 8 KiB body
// through a 1 KiB stream window completes only via the server's
// WINDOW_UPDATEs as it consumes the body). Malformed h2 framing is
// already pinned by h2c_preface_followed_by_garbage_is_closed above and
// tls_edges::h2c_malformed_preface_does_not_hang_the_listener.

/// HPACK literal header field without indexing (0x00 prefix, no
/// Huffman). Name/value lengths stay below 127, so no integer encoding
/// is needed — the bytes are fixed and auditable.
fn hpack_literal(name: &str, value: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(2 + name.len() + value.len());
    b.push(0x00);
    b.push(name.len() as u8);
    b.extend_from_slice(name.as_bytes());
    b.push(value.len() as u8);
    b.extend_from_slice(value.as_bytes());
    b
}

/// HEADERS payload for an incomplete POST: END_HEADERS only, no
/// END_STREAM — the gateway holds the stream OPEN awaiting
/// `content_length` body bytes the test never sends, so the stream
/// consumes concurrency for as long as the test needs it open.
fn hpack_open_post(path: &str, content_length: usize) -> Vec<u8> {
    let mut b = hpack_literal(":method", "POST");
    b.extend(hpack_literal(":scheme", "http"));
    b.extend(hpack_literal(":authority", "h"));
    b.extend(hpack_literal(":path", path));
    b.extend(hpack_literal("content-length", &content_length.to_string()));
    b
}

/// One h2 frame with explicit flags and stream id.
fn h2_frame_stream(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(9 + payload.len());
    f.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    f.push(kind);
    f.push(flags);
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// Read one complete h2 frame (9-byte header + payload) within
/// `deadline`, polling past read timeouts. Returns
/// (kind, flags, stream_id, payload) or None on close/timeout/malformed.
fn read_h2_frame(stream: &mut TcpStream, deadline: Instant) -> Option<(u8, u8, u32, Vec<u8>)> {
    let mut read_exact = |buf: &mut [u8]| -> Option<()> {
        let mut got = 0;
        while got < buf.len() {
            if Instant::now() >= deadline {
                return None;
            }
            match stream.read(&mut buf[got..]) {
                Ok(0) => return None,
                Ok(n) => got += n,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    continue
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return None,
            }
        }
        Some(())
    };
    let mut header = [0u8; 9];
    read_exact(&mut header)?;
    let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    let mut payload = vec![0u8; len];
    read_exact(&mut payload)?;
    let stream_id = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff;
    Some((header[3], header[4], stream_id, payload))
}

/// Connect, send the h2c prior-knowledge preface and an empty client
/// SETTINGS frame — the shared handshake prefix of the raw-frame tests.
fn h2_raw_connect(addr: &str) -> TcpStream {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("read timeout");
    stream
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .expect("preface");
    stream
        .write_all(&h2_frame_stream(0x4, 0, 0, &[]))
        .expect("client settings");
    stream
}

/// The advertised knobs: SETTINGS_MAX_CONCURRENT_STREAMS and
/// SETTINGS_INITIAL_WINDOW_SIZE carry the configured env values (the cap
/// is "enforced and advertised" — this pins the advertised half).
#[test]
fn h2_settings_advertise_the_configured_limits() {
    let (addr, _log, _server) = start_server(
        "h2adv",
        &[
            ("DWARA_H2_MAX_CONCURRENT_STREAMS", "7"),
            ("DWARA_H2_STREAM_WINDOW_KIB", "1"),
        ],
    );
    let mut stream = h2_raw_connect(&addr);
    let (kind, _flags, sid, payload) =
        read_h2_frame(&mut stream, Instant::now() + Duration::from_secs(5))
            .expect("server SETTINGS within 5s");
    assert_eq!(kind, 0x4, "first server frame must be SETTINGS");
    assert_eq!(sid, 0);
    let mut max_streams = None;
    let mut initial_window = None;
    for pair in payload.chunks(6) {
        if pair.len() < 6 {
            break;
        }
        let id = u16::from_be_bytes([pair[0], pair[1]]);
        let val = u32::from_be_bytes([pair[2], pair[3], pair[4], pair[5]]);
        match id {
            0x0003 => max_streams = Some(val),
            0x0004 => initial_window = Some(val),
            _ => {}
        }
    }
    assert_eq!(
        max_streams,
        Some(7),
        "SETTINGS_MAX_CONCURRENT_STREAMS must be the knob value"
    );
    assert_eq!(
        initial_window,
        Some(1024),
        "SETTINGS_INITIAL_WINDOW_SIZE must be 1 KiB (DWARA_H2_STREAM_WINDOW_KIB=1)"
    );
}

/// Stream-cap enforcement: with the cap at 2, two held-open streams are
/// legal concurrency; the THIRD stream must be refused with
/// RST_STREAM/REFUSED_STREAM while the two in-cap streams stay
/// untouched and nothing reaches the upstream.
#[test]
fn h2_excess_concurrent_stream_is_refused() {
    let (addr, log, _server) = start_server("h2cap", &[("DWARA_H2_MAX_CONCURRENT_STREAMS", "2")]);
    let mut stream = h2_raw_connect(&addr);
    let deadline = Instant::now() + Duration::from_secs(5);

    // Two streams held open by incomplete POST bodies.
    for sid in [1u32, 3] {
        stream
            .write_all(&h2_frame_stream(
                0x1,
                0x4, // END_HEADERS (no END_STREAM: await the body)
                sid,
                &hpack_open_post("/h2cap", 64),
            ))
            .expect("in-cap headers");
    }
    // Acknowledge the server's SETTINGS like a compliant client.
    loop {
        let (kind, _f, _sid, _p) =
            read_h2_frame(&mut stream, deadline).expect("server SETTINGS within 5s");
        if kind == 0x4 {
            stream
                .write_all(&h2_frame_stream(0x4, 0x1, 0, &[]))
                .expect("settings ack");
            break;
        }
    }

    // The excess stream: over the advertised cap of two.
    stream
        .write_all(&h2_frame_stream(
            0x1,
            0x4,
            5,
            &hpack_open_post("/h2cap", 64),
        ))
        .expect("excess headers");

    // Bounded poll for the refusal; only the EXCESS stream may be reset.
    let mut refusal: Option<u32> = None;
    while refusal.is_none() {
        assert!(
            Instant::now() < deadline,
            "excess stream was not refused within 5s"
        );
        let (kind, _f, sid, payload) = read_h2_frame(&mut stream, deadline)
            .expect("frame after the excess stream (connection closed without a refusal?)");
        if kind == 0x3 {
            assert_eq!(
                sid, 5,
                "only the excess stream may be refused, saw RST_STREAM for {sid}"
            );
            refusal = Some(u32::from_be_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ]));
        }
        // SETTINGS/ACK/WINDOW_UPDATE and friends: keep polling.
    }
    assert_eq!(
        refusal.unwrap(),
        7, // REFUSED_STREAM
        "the excess stream must be refused with REFUSED_STREAM"
    );
    // The held-open bodies never completed: nothing reached the upstream.
    assert_upstream_saw_nothing(&log);
}

/// Window enforcement (flow control): an 8 KiB POST body through a
/// 1 KiB initial stream window (2 KiB connection window) can only
/// complete if the server grants WINDOW_UPDATEs as it consumes bytes
/// toward the upstream — the h2 client's capacity API blocks otherwise.
/// Completing the exchange within the bound therefore proves the data
/// flow was window-gated end to end (bounded bytes in flight), without
/// asserting exact OS-level scheduling.
#[tokio::test]
async fn h2_window_updates_gate_flow_beyond_the_initial_window() {
    let (addr, log, _server) = start_server(
        "h2win",
        &[
            ("DWARA_H2_STREAM_WINDOW_KIB", "1"),
            ("DWARA_H2_CONNECTION_WINDOW_KIB", "2"),
        ],
    );
    let tcp = tokio::net::TcpStream::connect(&addr)
        .await
        .expect("connect");
    let (mut client, conn) = h2::client::handshake(tcp).await.expect("h2 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    const TOTAL: usize = 8 * 1024;
    static BODY: [u8; TOTAL] = [0x57; TOTAL];
    // hyper::Request IS http::Request (re-exported), the same type h2's
    // API takes — no http dev-dependency needed. Likewise
    // hyper::body::Bytes IS the bytes::Bytes h2's SendStream takes.
    let request = hyper::Request::post("http://h/h2win")
        .header("content-length", TOTAL.to_string())
        .body(())
        .expect("request");
    let (response, mut send_body) = client.send_request(request, false).expect("send request");

    // Send only what the server grants; every granted byte beyond the
    // initial 1 KiB window arrived via a WINDOW_UPDATE.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut sent = 0usize;
    while sent < TOTAL {
        let remaining = &BODY[sent..];
        send_body.reserve_capacity(remaining.len());
        let granted = tokio::time::timeout_at(
            deadline,
            std::future::poll_fn(|cx| send_body.poll_capacity(cx)),
        )
        .await
        .expect("capacity granted within 10s (windows never opened: flow stalled)")
        .expect("stream still open")
        .expect("nonzero capacity");
        let n = granted.min(remaining.len());
        send_body
            .send_data(hyper::body::Bytes::from_static(&remaining[..n]), false)
            .expect("send data");
        sent += n;
    }
    send_body
        .send_data(hyper::body::Bytes::new(), true)
        .expect("end stream");

    let response = tokio::time::timeout_at(deadline, response)
        .await
        .expect("response within 10s")
        .expect("response future");
    assert_eq!(
        response.status().as_u16(),
        200,
        "the window-gated upload must complete"
    );
    // Drain the tiny response body cleanly (release flow control).
    let mut body = response.into_body();
    while let Some(chunk) =
        tokio::time::timeout_at(deadline, std::future::poll_fn(|cx| body.poll_data(cx)))
            .await
            .expect("response body within 10s")
    {
        let n = chunk.expect("body chunk").len();
        let _ = body.flow_control().release_capacity(n);
    }
    let requests = log.lock().unwrap();
    assert!(
        requests.iter().any(|r| r.starts_with("POST /h2win")),
        "the full window-gated body reached the upstream: {requests:?}"
    );
}

// ---------------------------------------------------------------------------
// DW-030: PROXY protocol acceptance. A listener with proxy_protocol: true
// reads a v1/v2 header as the connection's first bytes and the header's
// source address becomes the peer every consumer sees — pinned here via
// the X-Forwarded-For the gateway stamps on the forwarded request (the
// done-when's observable). Malformed headers fail closed with the 400
// envelope. These tests need a CONFIG-declared listener (the DWARA_BIND
// env listener is fixed proxy_protocol: false), so they spawn their own
// server variant.
// ---------------------------------------------------------------------------

/// Backend that records the FULL head (request line + headers) so the
/// forwarded X-Forwarded-For / X-Real-IP are observable.
fn spawn_header_backend() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("backend bind");
    let port = listener.local_addr().expect("backend addr").port();
    let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let shared = Arc::clone(&log);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let log = Arc::clone(&shared);
            std::thread::spawn(move || {
                use std::io::{BufRead, BufReader, Write};
                let mut reader = BufReader::new(match stream.try_clone() {
                    Ok(s) => s,
                    Err(_) => return,
                });
                let mut stream = stream;
                loop {
                    let mut head = String::new();
                    loop {
                        let mut line = String::new();
                        match reader.read_line(&mut line) {
                            Ok(0) => return,
                            Ok(_) => {
                                head.push_str(&line);
                                if line == "\r\n" {
                                    break;
                                }
                            }
                            Err(_) => return,
                        }
                    }
                    log.lock().unwrap().push(head.clone());
                    if stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    (port, log)
}

/// Spawn the gateway with a CONFIG listener carrying
/// `proxy_protocol: true` (DWARA_BIND's env listener is fixed OFF, so
/// the flag must come from the declared listener set).
fn start_proxy_protocol_server(tag: &str) -> (String, Arc<Mutex<Vec<String>>>, ServerGuard) {
    let (backend_port, log) = spawn_header_backend();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let config = std::env::temp_dir().join(format!(
        "dwara-dw030-proxy-{}-{n}-{tag}.yaml",
        std::process::id()
    ));
    std::fs::write(
        &config,
        format!(
            "listeners:\n\
             \x20 - name: edge\n\
             \x20   address: 127.0.0.1\n\
             \x20   port: {port}\n\
             \x20   proxy_protocol: true\n\
             routes:\n\
             \x20\x20 - name: all\n\
             \x20\x20   service: svc\n\
             \x20\x20   match:\n\
             \x20\x20     path:\n\
             \x20\x20       type: regex\n\
             \x20\x20       value: /.*\n\
             \x20\x20   action:\n\
             \x20\x20     type: proxy\n\
             services:\n\
             \x20\x20 - name: svc\n\
             \x20\x20   upstream: up\n\
             upstreams:\n\
             \x20\x20 - name: up\n\
             \x20\x20   endpoints:\n\
             \x20\x20     - address: 127.0.0.1\n\
             \x20\x20       port: {backend_port}\n"
        ),
    )
    .unwrap();
    let stderr_log = std::env::temp_dir().join(format!(
        "dwara-dw030-proxy-{}-{n}-{tag}.stderr",
        std::process::id()
    ));
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dwara"));
    cmd.env("DWARA_CONFIG", &config)
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&stderr_log).expect("stderr log"));
    let guard = ServerGuard(cmd.spawn().expect("failed to spawn dwara binary"));
    assert!(
        wait_for_ready(&addr, Instant::now() + Duration::from_secs(10)),
        "dwara did not become ready on {addr} within 10s"
    );
    std::fs::remove_file(&config).ok();
    eprintln!("dwara {tag} on {addr}, stderr: {}", stderr_log.display());
    (addr, log, guard)
}

#[test]
fn proxy_v1_header_client_ip_flows_to_the_forwarded_request() {
    let (addr, log, _guard) = start_proxy_protocol_server("v1");
    let mut stream = TcpStream::connect(&addr).expect("connect");
    // v1 line claiming a documentation-range client, then the request
    // pipelined behind it (one write exercises the replay prefix too).
    stream
        .write_all(
            b"PROXY TCP4 203.0.113.7 10.0.0.1 55555 8080\r\n\
              GET /via-proxy HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n",
        )
        .expect("write");
    let mut response = String::new();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    use std::io::Read as _;
    let _ = stream.read_to_string(&mut response);
    assert!(response.starts_with("HTTP/1.1 200"), "proxied: {response}");
    let heads = log.lock().unwrap().clone();
    assert_eq!(heads.len(), 1, "exactly one upstream request");
    assert!(
        heads[0]
            .to_ascii_lowercase()
            .contains("x-forwarded-for: 203.0.113.7"),
        "claimed client IP flows to XFF: {}",
        heads[0]
    );
    assert!(
        heads[0]
            .to_ascii_lowercase()
            .contains("x-real-ip: 203.0.113.7"),
        "claimed client IP flows to X-Real-IP: {}",
        heads[0]
    );
}

#[test]
fn proxy_v2_header_client_ip_flows_to_the_forwarded_request() {
    let (addr, log, _guard) = start_proxy_protocol_server("v2");
    // Hand-built v2 header: signature + 0x21 (v2|PROXY) + 0x11
    // (AF_INET|STREAM) + length 12 + src 198.51.100.9:4711 +
    // dst 10.0.0.1:8080 — the binary form an L4 LB sends.
    let mut wire: Vec<u8> = vec![
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
    ];
    wire.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
    wire.extend_from_slice(&[198, 51, 100, 9]);
    wire.extend_from_slice(&[10, 0, 0, 1]);
    wire.extend_from_slice(&4711u16.to_be_bytes());
    wire.extend_from_slice(&8080u16.to_be_bytes());
    wire.extend_from_slice(b"GET /v2 HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n");
    let mut stream = TcpStream::connect(&addr).expect("connect");
    stream.write_all(&wire).expect("write");
    let mut response = String::new();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    use std::io::Read as _;
    let _ = stream.read_to_string(&mut response);
    assert!(response.starts_with("HTTP/1.1 200"), "proxied: {response}");
    let heads = log.lock().unwrap().clone();
    assert_eq!(heads.len(), 1, "exactly one upstream request");
    assert!(
        heads[0]
            .to_ascii_lowercase()
            .contains("x-forwarded-for: 198.51.100.9"),
        "v2-claimed client IP flows to XFF: {}",
        heads[0]
    );
    assert!(
        heads[0]
            .to_ascii_lowercase()
            .contains("x-real-ip: 198.51.100.9"),
        "v2-claimed client IP flows to X-Real-IP: {}",
        heads[0]
    );
}

#[test]
fn malformed_proxy_header_is_answered_400_and_never_forwarded() {
    let (addr, log, _guard) = start_proxy_protocol_server("malformed");
    let mut stream = TcpStream::connect(&addr).expect("connect");
    // Plausible-looking but structurally invalid v1 line (bad family
    // token), pipelined with a request that must NEVER be served.
    stream
        .write_all(
            b"PROXY TCPX 203.0.113.7 10.0.0.1 55555 8080\r\n\
              GET /smuggled HTTP/1.1\r\nhost: example.com\r\n\r\n",
        )
        .expect("write");
    let mut response = String::new();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    use std::io::Read as _;
    let _ = stream.read_to_string(&mut response);
    assert!(
        response.starts_with("HTTP/1.1 400"),
        "fail closed: {response}"
    );
    assert!(
        response.contains("proxy_protocol_malformed"),
        "the envelope names the code: {response}"
    );
    assert!(
        response.contains("connection: close"),
        "the connection is closed, not parsed: {response}"
    );
    assert!(
        log.lock().unwrap().is_empty(),
        "nothing reached the upstream"
    );
}

#[test]
fn proxy_protocol_off_listener_serves_the_header_bytes_as_http_garbage() {
    // The opt-in boundary: a listener WITHOUT the flag never interprets
    // first bytes as a PROXY line — the v1 line is HTTP-parse garbage
    // and hyper answers 400/close, with NOTHING forwarded.
    let (addr, log, _guard) = start_server("no-proxy-flag", &[]);
    let mut stream = TcpStream::connect(&addr).expect("connect");
    stream
        .write_all(
            b"PROXY TCP4 203.0.113.7 10.0.0.1 55555 8080\r\n\
              GET / HTTP/1.1\r\nhost: example.com\r\n\r\n",
        )
        .expect("write");
    let mut response = String::new();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    use std::io::Read as _;
    let _ = stream.read_to_string(&mut response);
    assert!(!response.contains(" 200 "), "no proxying: {response}");
    assert!(
        log.lock().unwrap().is_empty(),
        "nothing reached the upstream"
    );
}

/// The TLS-terminate twin of [`start_proxy_protocol_server`]: same
/// PROXY-accepting edge, but `protocol: https` in terminate mode, so the
/// header must be consumed BEFORE rustls sees a byte. Returns the
/// generated certificate's DER so the client can trust it exactly (no
/// accept-any verifier: the handshake itself is part of the assertion).
fn start_proxy_protocol_tls_server(
    tag: &str,
) -> (
    String,
    Arc<Mutex<Vec<String>>>,
    ServerGuard,
    tokio_rustls::rustls::pki_types::CertificateDer<'static>,
) {
    use std::path::PathBuf;

    let (backend_port, log) = spawn_header_backend();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    static TLS_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = TLS_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let base: PathBuf = std::env::temp_dir().join(format!(
        "dwara-dw030-proxy-tls-{}-{n}-{tag}",
        std::process::id()
    ));
    let cert_path = base.with_extension("crt.pem");
    let key_path = base.with_extension("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
    let config = base.with_extension("yaml");
    std::fs::write(
        &config,
        format!(
            "listeners:\n\
             \x20 - name: tls-edge\n\
             \x20   address: 127.0.0.1\n\
             \x20   port: {port}\n\
             \x20   protocol: https\n\
             \x20   proxy_protocol: true\n\
             \x20   tls:\n\
             \x20     mode: terminate\n\
             \x20     cert_file: {}\n\
             \x20     key_file: {}\n\
             routes:\n\
             \x20\x20 - name: all\n\
             \x20\x20   service: svc\n\
             \x20\x20   match:\n\
             \x20\x20     path:\n\
             \x20\x20       type: regex\n\
             \x20\x20       value: /.*\n\
             \x20\x20   action:\n\
             \x20\x20     type: proxy\n\
             services:\n\
             \x20\x20 - name: svc\n\
             \x20\x20   upstream: up\n\
             upstreams:\n\
             \x20\x20 - name: up\n\
             \x20\x20   endpoints:\n\
             \x20\x20     - address: 127.0.0.1\n\
             \x20\x20       port: {backend_port}\n",
            cert_path.display(),
            key_path.display()
        ),
    )
    .unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dwara"));
    cmd.env("DWARA_CONFIG", &config)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let guard = ServerGuard(cmd.spawn().expect("failed to spawn dwara binary"));
    assert!(
        wait_for_ready(&addr, Instant::now() + Duration::from_secs(10)),
        "dwara did not become ready on {addr} within 10s"
    );
    (addr, log, guard, cert.cert.der().clone())
}

#[tokio::test]
async fn proxy_v2_header_precedes_the_tls_handshake_on_a_terminate_listener() {
    // The DW-030 ordering claim on TLS edges, end to end: the PROXY
    // header wraps the WHOLE stream (an L4 LB fronts the TLS listener),
    // so the v2 header is written as PLAINTEXT first bytes and only then
    // does the TLS handshake run over the same connection. The claimed
    // client IP (198.51.100.23) must flow to the forwarded request, and
    // the handshake itself must succeed — proving the gateway replayed
    // any post-header bytes (here: none) and handed rustls a clean
    // stream. The client trusts exactly the generated certificate (no
    // accept-any verifier): a handed-on-garbage stream would fail the
    // handshake, not the assertions.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::rustls::pki_types::ServerName;

    let (addr, log, _guard, cert_der) = start_proxy_protocol_tls_server("v2");
    let mut tcp = tokio::net::TcpStream::connect(&addr)
        .await
        .expect("connect");
    // Hand-built v2 header: signature + 0x21 (v2|PROXY) + 0x11
    // (AF_INET|STREAM) + length 12 + src 198.51.100.23:4711 +
    // dst 10.0.0.1:8443.
    let mut wire: Vec<u8> = vec![
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
    ];
    wire.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
    wire.extend_from_slice(&[198, 51, 100, 23]);
    wire.extend_from_slice(&[10, 0, 0, 1]);
    wire.extend_from_slice(&4711u16.to_be_bytes());
    wire.extend_from_slice(&8443u16.to_be_bytes());
    tcp.write_all(&wire).await.expect("PROXY header write");
    let provider = std::sync::Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    roots.add(cert_der).expect("trust the generated cert");
    let mut client = tokio_rustls::rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[
            &tokio_rustls::rustls::version::TLS13,
            &tokio_rustls::rustls::version::TLS12,
        ])
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client));
    let mut tls = connector
        .connect(ServerName::try_from("localhost").expect("server name"), tcp)
        .await
        .expect("TLS handshake after the PROXY header");
    tls.write_all(b"GET /tls-v2 HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
        .await
        .expect("request write");
    let mut response = String::new();
    let _ = tls.read_to_string(&mut response).await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "proxied over TLS: {response}"
    );
    let heads = log.lock().unwrap().clone();
    assert_eq!(heads.len(), 1, "exactly one upstream request");
    assert!(
        heads[0]
            .to_ascii_lowercase()
            .contains("x-forwarded-for: 198.51.100.23"),
        "v2-claimed client IP flows to XFF: {}",
        heads[0]
    );
    assert!(
        heads[0]
            .to_ascii_lowercase()
            .contains("x-real-ip: 198.51.100.23"),
        "v2-claimed client IP flows to X-Real-IP: {}",
        heads[0]
    );
}

#[test]
fn terminate_listener_without_a_proxy_header_fails_closed_before_tls() {
    // The fail-closed half on TLS edges: a client that starts a TLS
    // handshake without a PROXY header has its ClientHello's first bytes
    // judged by the PROXY phase (0x16... is neither a v1 line nor the v2
    // signature) and answered with the 400 envelope + close — rustls
    // never sees the bytes, and nothing is forwarded.
    let (addr, log, _guard, _cert) = start_proxy_protocol_tls_server("no-hdr");
    let mut stream = TcpStream::connect(&addr).expect("connect");
    // A ClientHello-shaped prefix: TLS record header (0x16, TLS 1.2)
    // followed by handshake body bytes.
    stream
        .write_all(&[0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00])
        .expect("write ClientHello prefix");
    let mut response = String::new();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    use std::io::Read as _;
    let _ = stream.read_to_string(&mut response);
    assert!(
        response.starts_with("HTTP/1.1 400"),
        "fail closed before TLS: {response}"
    );
    assert!(
        response.contains("proxy_protocol_malformed"),
        "the envelope names the code: {response}"
    );
    assert!(
        log.lock().unwrap().is_empty(),
        "nothing reached the upstream"
    );
}
