//! OTLP export E2E (#126, feature `otlp`).
//!
//! Feature-gated exactly like the loom suite (dwara-core): with the
//! default feature set this file compiles empty — the exporter does not
//! exist in that build. Run with:
//!
//! ```sh
//! cargo test -p dwara-bin --features otlp --test otlp_export
//! ```
//!
//! Method: no collector dependency — a minimal std-only OTLP HTTP sink
//! (plain TcpListener thread, one POST per connection, dumping the
//! request line, headers, and protobuf body) stands in for one. The REAL
//! gateway binary runs with `DWARA_OTLP_ENDPOINT` pointing at the sink;
//! one proxied request is driven through it; SIGTERM triggers the
//! graceful drain plus the bounded exporter flush; the test then asserts
//! the export arrived on the wire: POST to `/v1/traces`,
//! `application/x-protobuf`, a nonzero body carrying the root span name
//! (`request`), a phase span name (`authn`), and the `service.name`
//! resource. Beyond fragments, a minimal protobuf decoder (below) proves
//! the payload structurally decodes as ExportTraceServiceRequest with
//! the expected span count, names, trace ids, and parent links — the
//! exact structure a collector ingests.

#![cfg(feature = "otlp")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// One POST captured by the sink.
#[derive(Debug, Clone)]
struct Captured {
    request_line: String,
    content_type: Option<String>,
    host: Option<String>,
    body: Vec<u8>,
}

/// Find the blank line ending an HTTP/1.x head (CRLFCRLF).
fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| {
        l.split_once(':')
            .filter(|(n, _)| n.trim().eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim())
    })
}

/// Read exactly one HTTP/1.x request off `stream` and capture it. Reads
/// are bounded (timeout + size cap); `None` on any malformed exchange.
fn read_one_request(stream: &mut TcpStream) -> Option<Captured> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(p) = head_end(&buf) {
            break p;
        }
        if buf.len() > 1024 * 1024 {
            return None;
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let mut body = buf[end + 4..].to_vec();
    let content_length: usize = header_value(&head, "content-length")?.parse().ok()?;
    while body.len() < content_length {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);
    Some(Captured {
        request_line: head.lines().next().unwrap_or_default().to_string(),
        content_type: header_value(&head, "content-type").map(str::to_string),
        host: header_value(&head, "host").map(str::to_string),
        body,
    })
}

/// A std-only OTLP HTTP sink on an ephemeral port. Accepts connections
/// for the sink's lifetime; each connection serves ONE POST (the
/// exporter's client uses connection: close) and answers `status` with
/// an empty body — 200 is exactly what a collector answers for an
/// accepted batch (ExportTraceServiceResponse{} encodes to zero bytes),
/// 5xx stands in for a failing collector. `None` when `bind` cannot be
/// served on this host (e.g. `[::1]` without IPv6 loopback).
fn spawn_sink_on(bind: &str, status: &str) -> Option<(u16, Arc<Mutex<Vec<Captured>>>)> {
    let listener = TcpListener::bind(bind).ok()?;
    let port = listener.local_addr().expect("sink addr").port();
    let captured: Arc<Mutex<Vec<Captured>>> = Arc::new(Mutex::new(Vec::new()));
    let sink_captured = Arc::clone(&captured);
    let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n");
    std::thread::spawn(move || {
        listener.set_nonblocking(false).expect("sink blocking mode");
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let cap = Arc::clone(&sink_captured);
            let response = response.clone();
            std::thread::spawn(move || {
                if let Some(record) = read_one_request(&mut stream) {
                    cap.lock().unwrap().push(record);
                }
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            });
        }
    });
    Some((port, captured))
}

fn spawn_sink_with_status(status: &str) -> (u16, Arc<Mutex<Vec<Captured>>>) {
    spawn_sink_on("127.0.0.1:0", status).expect("sink bind on 127.0.0.1:0")
}

/// The sink as a healthy collector: 200 for every export POST.
fn spawn_sink() -> (u16, Arc<Mutex<Vec<Captured>>>) {
    spawn_sink_with_status("200 OK")
}

/// A `Transfer-Encoding: chunked` answer whose SECOND chunk declares a
/// near-`usize::MAX` hex size. The pairing is deliberate: a lone absurd
/// size was already rejected by the body cap, but 4 bytes of decoded
/// data plus `0xFFFFFFFFFFFFFFFC` WRAPPED the old unchecked
/// `decoded.len() + size` to 0, sailed past the cap, and panicked the
/// data slice (`start > end`) — on the SDK batch thread, which would
/// silently stop every later export. The fixed client must turn this
/// into an ordinary export error.
const ABSURD_CHUNK_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndwara\r\nFFFFFFFFFFFFFFFC\r\n";

/// Sink answering the FIRST connection with [`ABSURD_CHUNK_RESPONSE`]
/// and every later one with the healthy 200 (a collector that served
/// one malformed answer, then recovered). Lets a test prove both
/// halves of the contract: the malformed answer is an export error,
/// not a batch-thread panic, and subsequent exports still work.
fn spawn_poison_then_healthy_sink() -> (u16, Arc<Mutex<Vec<Captured>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("sink bind on 127.0.0.1:0");
    let port = listener.local_addr().expect("sink addr").port();
    let captured: Arc<Mutex<Vec<Captured>>> = Arc::new(Mutex::new(Vec::new()));
    let sink_captured = Arc::clone(&captured);
    let connections = Arc::new(AtomicUsize::new(0));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let first = connections.fetch_add(1, Ordering::SeqCst) == 0;
            let cap = Arc::clone(&sink_captured);
            std::thread::spawn(move || {
                if let Some(record) = read_one_request(&mut stream) {
                    cap.lock().unwrap().push(record);
                }
                let response: &[u8] = if first {
                    ABSURD_CHUNK_RESPONSE
                } else {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                };
                let _ = stream.write_all(response);
                let _ = stream.flush();
            });
        }
    });
    (port, captured)
}

// --- minimal OTLP protobuf decoding ------------------------------------------
//
// The sink proves the wire bytes; this decoder proves the bytes are the
// structure a collector ingests (ExportTraceServiceRequest) rather than
// any payload carrying the right fragments. Field numbers are from the
// vendored opentelemetry-proto-0.32.0 protos:
//
//   ExportTraceServiceRequest { resource_spans = 1 }
//   ResourceSpans { resource = 1, scope_spans = 2 }
//   ScopeSpans { scope = 1, spans = 2 }
//   Span { trace_id = 1, span_id = 2, parent_span_id = 4, name = 5 }
//   Resource { attributes = 1 } / KeyValue { key = 1, value = 2 } /
//   AnyValue { string_value = 1 }

/// One decoded Span message.
struct WireSpan {
    trace_id: Vec<u8>,
    span_id: Vec<u8>,
    parent_span_id: Vec<u8>,
    name: String,
}

/// Read one base-128 varint at `pos`; `None` on truncation.
fn varint(buf: &[u8], pos: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    let mut at = pos;
    while at < buf.len() && shift < 64 {
        let byte = buf[at];
        at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, at - pos));
        }
        shift += 7;
    }
    None
}

/// Invoke `f(field_number, bytes)` for every length-delimited field in
/// `buf`, skipping varint/fixed32/fixed64 fields. Returns early (and
/// silently) on a truncated or malformed tail — callers assert on what
/// they needed, not on decoder totality.
fn for_each_len_field(buf: &[u8], mut f: impl FnMut(u32, &[u8])) {
    let mut pos = 0;
    while pos < buf.len() {
        let Some((key, n)) = varint(buf, pos) else {
            return;
        };
        pos += n;
        let field = (key >> 3) as u32;
        match key & 7 {
            0 => {
                let Some((_, n)) = varint(buf, pos) else {
                    return;
                };
                pos += n;
            }
            1 => pos += 8,
            2 => {
                let Some((len, n)) = varint(buf, pos) else {
                    return;
                };
                pos += n;
                let len = len as usize;
                if pos + len > buf.len() {
                    return;
                }
                f(field, &buf[pos..pos + len]);
                pos += len;
            }
            5 => pos += 4,
            // SGROUP/EGROUP (3/4) never appear in OTLP payloads.
            _ => return,
        }
    }
}

/// Decode every Span from one ExportTraceServiceRequest body.
fn decode_spans(body: &[u8]) -> Vec<WireSpan> {
    let mut spans = Vec::new();
    for_each_len_field(body, |f_resource_spans, resource_spans| {
        if f_resource_spans != 1 {
            return;
        }
        for_each_len_field(resource_spans, |f_scope_spans, scope_spans| {
            if f_scope_spans != 2 {
                return;
            }
            for_each_len_field(scope_spans, |f_span, span| {
                if f_span != 2 {
                    return;
                }
                let mut wire = WireSpan {
                    trace_id: Vec::new(),
                    span_id: Vec::new(),
                    parent_span_id: Vec::new(),
                    name: String::new(),
                };
                for_each_len_field(span, |field, value| match field {
                    1 => wire.trace_id = value.to_vec(),
                    2 => wire.span_id = value.to_vec(),
                    4 => wire.parent_span_id = value.to_vec(),
                    5 => wire.name = String::from_utf8_lossy(value).into_owned(),
                    _ => {}
                });
                spans.push(wire);
            });
        });
    });
    spans
}

/// Extract the `service.name` resource attribute from the first
/// ResourceSpans of an ExportTraceServiceRequest body.
fn decode_service_name(body: &[u8]) -> Option<String> {
    let mut found: Option<String> = None;
    for_each_len_field(body, |f_resource_spans, resource_spans| {
        if f_resource_spans != 1 || found.is_some() {
            return;
        }
        for_each_len_field(resource_spans, |f_resource, resource| {
            if f_resource != 1 {
                return;
            }
            for_each_len_field(resource, |f_attr, key_value| {
                if f_attr != 1 {
                    return;
                }
                let mut key = String::new();
                let mut string_value = None;
                for_each_len_field(key_value, |field, value| match field {
                    1 => key = String::from_utf8_lossy(value).into_owned(),
                    2 => for_each_len_field(value, |f_any, any_value| {
                        if f_any == 1 {
                            string_value = Some(String::from_utf8_lossy(any_value).into_owned());
                        }
                    }),
                    _ => {}
                });
                if key == "service.name" {
                    found = string_value;
                }
            });
        });
    });
    found
}

/// Aggregate all Spans decoded from every `/v1/traces` POST the sink
/// captured (the exporter may batch in several requests).
fn all_decoded_spans(captured: &[Captured]) -> Vec<WireSpan> {
    let mut spans = Vec::new();
    for post in captured
        .iter()
        .filter(|c| c.request_line.starts_with("POST /v1/traces"))
    {
        spans.extend(decode_spans(&post.body));
    }
    spans
}

/// Phase span names the DW-021 request tree emits below its root
/// (a respond-action route never reaches the upstream phases).
const PHASE_NAMES: [&str; 6] = [
    "authn",
    "authz",
    "ratelimit",
    "admission",
    "upstream_pick",
    "upstream_attempt",
];

// --- gateway driver (hello_listener/reload_shutdown patterns) ---------------

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind ephemeral port");
    listener.local_addr().expect("no local addr").port()
}

struct ServerGuard(Child);

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Captured process output (stdout + stderr), read after exit.
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

fn respond_config(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "dwara-126-otlp-{}-{}-{tag}.yaml",
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

fn spawn_gateway(tag: &str, extra_env: &[(&str, &str)]) -> (String, ServerGuard, CapturedOutput) {
    let addr = format!("127.0.0.1:{}", free_port());
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dwara"));
    cmd.env("DWARA_BIND", &addr)
        .env("DWARA_CONFIG", respond_config(tag))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let child = cmd.spawn().expect("failed to spawn dwara binary");
    let mut guard = ServerGuard(child);
    let captured = CapturedOutput {
        stdout: guard.0.stdout.take(),
        stderr: guard.0.stderr.take(),
    };
    assert!(
        wait_ready(&addr, Instant::now() + Duration::from_secs(10)),
        "dwara did not become ready on {addr} within 10s"
    );
    (addr, guard, captured)
}

fn wait_ready(addr: &str, deadline: Instant) -> bool {
    while Instant::now() < deadline {
        if let Ok(mut s) = TcpStream::connect(addr) {
            if get(&mut s).starts_with("HTTP/1.1 200") {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn get(stream: &mut TcpStream) -> String {
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("failed to write request");
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .expect("failed to read response");
    String::from_utf8_lossy(&buf).into_owned()
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

/// Bounded poll until at least one captured POST carries a nonzero body.
fn wait_for_export(captured: &Arc<Mutex<Vec<Captured>>>, deadline: Instant) -> bool {
    while Instant::now() < deadline {
        if captured.lock().unwrap().iter().any(|c| !c.body.is_empty()) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Bounded poll until the sink has captured at least `n` POSTs.
fn wait_for_captures(captured: &Arc<Mutex<Vec<Captured>>>, n: usize, deadline: Instant) -> bool {
    while Instant::now() < deadline {
        if captured.lock().unwrap().len() >= n {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    captured.lock().unwrap().len() >= n
}

// --- tests -------------------------------------------------------------------

/// The done-when: with the feature enabled and DWARA_OTLP_ENDPOINT set,
/// one proxied request's span tree reaches the collector over
/// http/protobuf, flushed on the SIGTERM drain path, and the process
/// still exits cleanly.
#[test]
fn root_span_exports_to_otlp_sink_on_shutdown() {
    let (sink_port, captured) = spawn_sink();
    let (addr, mut guard, mut output) = spawn_gateway(
        "export",
        &[(
            "DWARA_OTLP_ENDPOINT",
            &format!("http://127.0.0.1:{sink_port}"),
        )],
    );

    // One proxied request through the real binary.
    let mut stream = TcpStream::connect(&addr).expect("connect to gateway");
    let response = get(&mut stream);
    assert!(
        response.starts_with("HTTP/1.1 200") && response.ends_with("dwara"),
        "gateway must serve normally with OTLP live: {response}"
    );

    // SIGTERM: graceful drain, then the bounded exporter flush, then
    // exit 0 — the flush happens BEFORE process exit, so by the time the
    // child is reaped the POST is on the wire (the poll below only
    // covers thread-scheduling jitter).
    kill_signal(guard.0.id(), "TERM");
    let status = wait_exit(&mut guard.0, Duration::from_secs(20));
    assert!(status.success(), "clean exit with OTLP flush: {status}");
    drop(guard);

    assert!(
        wait_for_export(&captured, Instant::now() + Duration::from_secs(5)),
        "no nonzero OTLP export arrived; captured: {:?}",
        captured.lock().unwrap()
    );

    let all = captured.lock().unwrap().clone();
    let trace_post = all
        .iter()
        .find(|c| c.request_line.starts_with("POST /v1/traces "))
        .expect("an export POST to /v1/traces");
    assert_eq!(trace_post.request_line, "POST /v1/traces HTTP/1.1");
    assert_eq!(
        trace_post.content_type.as_deref(),
        Some("application/x-protobuf"),
        "protobuf content type: {:?}",
        trace_post.content_type
    );
    assert!(!trace_post.body.is_empty(), "nonzero protobuf body");

    // Span names and the service resource ride the wire as UTF-8 inside
    // the protobuf encoding; their presence proves this is a real span
    // export, not an arbitrary POST.
    let body = &trace_post.body;
    for fragment in ["request", "authn", "dwara"] {
        assert!(
            body.windows(fragment.len())
                .any(|w| w == fragment.as_bytes()),
            "span/resource fragment {fragment:?} missing from {}-byte protobuf body",
            body.len()
        );
    }

    // Startup logged the wiring through the normal JSON pipeline.
    let logs = output.read_all();
    assert!(
        logs.contains("otlp_export_enabled"),
        "no enable line: {logs}"
    );
    assert!(logs.contains("otlp_shutdown"), "no flush line: {logs}");
}

/// Feature enabled, endpoint unset: no-op by design — the gateway runs
/// exactly as the default build, with one INFO line saying so.
#[test]
fn feature_enabled_endpoint_unset_is_a_noop_with_info_line() {
    let (addr, mut guard, mut output) = spawn_gateway("unset", &[]);

    let mut stream = TcpStream::connect(&addr).expect("connect to gateway");
    assert!(get(&mut stream).starts_with("HTTP/1.1 200"));

    kill_signal(guard.0.id(), "TERM");
    let status = wait_exit(&mut guard.0, Duration::from_secs(20));
    assert!(status.success());
    drop(guard);

    let logs = output.read_all();
    assert!(
        logs.contains("otlp_not_configured"),
        "expected the not-configured INFO line: {logs}"
    );
}

/// An https:// endpoint fails fast at startup (the built-in exporter
/// client is http-only) with an ERROR naming why — but the gateway keeps
/// serving; traces are auxiliary, never load-bearing.
#[test]
fn https_endpoint_fails_fast_but_gateway_serves() {
    let (addr, mut guard, mut output) = spawn_gateway(
        "https",
        &[("DWARA_OTLP_ENDPOINT", "https://collector:4318")],
    );

    let mut stream = TcpStream::connect(&addr).expect("connect to gateway");
    assert!(get(&mut stream).starts_with("HTTP/1.1 200"));

    kill_signal(guard.0.id(), "TERM");
    let status = wait_exit(&mut guard.0, Duration::from_secs(20));
    assert!(status.success());
    drop(guard);

    let logs = output.read_all();
    assert!(
        logs.contains("otlp_init_failed"),
        "expected the init-failed ERROR line: {logs}"
    );
}

/// Multi-request export shape: every proxied request becomes its own
/// trace (root `request` span with an empty parent), every phase span
/// decodes as a child of its trace's root, and the service resource
/// identifies the gateway. SIGTERM is sent IMMEDIATELY after the last
/// response — well inside the batch processor's 5s tick — so the export
/// can only have reached the wire through the bounded shutdown flush:
/// the exact race that flush exists for.
#[test]
fn multi_request_traces_export_with_parenting_on_immediate_sigterm() {
    let (sink_port, captured) = spawn_sink();
    let (addr, mut guard, _output) = spawn_gateway(
        "parenting",
        &[(
            "DWARA_OTLP_ENDPOINT",
            &format!("http://127.0.0.1:{sink_port}"),
        )],
    );

    const REQUESTS: usize = 3;
    for _ in 0..REQUESTS {
        let mut stream = TcpStream::connect(&addr).expect("connect to gateway");
        let response = get(&mut stream);
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "gateway must serve with OTLP live: {response}"
        );
    }

    // Shutdown flush race: last span ended milliseconds ago; only the
    // drain-path flush can export it (the poll below only covers
    // thread-scheduling jitter, as in the root test).
    kill_signal(guard.0.id(), "TERM");
    let status = wait_exit(&mut guard.0, Duration::from_secs(20));
    assert!(status.success(), "clean exit with OTLP flush: {status}");
    drop(guard);

    assert!(
        wait_for_export(&captured, Instant::now() + Duration::from_secs(5)),
        "no OTLP export arrived; captured: {:?}",
        captured.lock().unwrap()
    );

    let posts = captured.lock().unwrap().clone();
    let spans = all_decoded_spans(&posts);
    let names: Vec<&str> = spans.iter().map(|s| s.name.as_str()).collect();
    assert!(
        !spans.is_empty(),
        "no decodable spans in {} POST bodies ({} bytes total)",
        posts.len(),
        posts.iter().map(|p| p.body.len()).sum::<usize>()
    );

    // One root per request (readiness probes may add more), each its own
    // trace; the three driven requests must all be present.
    let roots: Vec<&WireSpan> = spans
        .iter()
        .filter(|s| s.name == "request" && s.parent_span_id.is_empty())
        .collect();
    assert!(
        roots.len() >= REQUESTS,
        "expected at least {REQUESTS} root `request` spans, got {}: {names:?}",
        roots.len()
    );
    let distinct_traces: std::collections::HashSet<&[u8]> =
        roots.iter().map(|r| r.trace_id.as_slice()).collect();
    assert_eq!(
        distinct_traces.len(),
        roots.len(),
        "every root request span must carry a distinct trace_id"
    );

    // Phase spans really exported, and parented: same trace as a root,
    // parent_span_id equal to that root's span_id.
    let phases: Vec<&WireSpan> = spans
        .iter()
        .filter(|s| !s.parent_span_id.is_empty())
        .collect();
    assert!(
        phases.len() >= REQUESTS,
        "expected phase spans alongside the roots, got {names:?}"
    );
    for phase in &phases {
        assert!(
            PHASE_NAMES.contains(&phase.name.as_str()),
            "unexpected span name {:?} under the dwara=info filter: {names:?}",
            phase.name
        );
        let parent_is_root = roots
            .iter()
            .any(|r| r.trace_id == phase.trace_id && r.span_id == phase.parent_span_id);
        assert!(
            parent_is_root,
            "span {:?} is not parented under its trace's `request` root: {names:?}",
            phase.name
        );
    }
    // The exported resource identifies the gateway (what a collector
    // would index the batch under).
    let with_resource = posts
        .iter()
        .find(|p| p.request_line.starts_with("POST /v1/traces"))
        .expect("an export POST");
    assert_eq!(
        decode_service_name(&with_resource.body).as_deref(),
        Some("dwara"),
        "service.name resource attribute"
    );
}

/// Endpoint path resolution: a BASE endpoint (with or without a
/// trailing slash) gets `/v1/traces` appended; an endpoint that already
/// ends in `/v1/traces` is used verbatim (the documented rule).
#[test]
fn endpoint_path_resolution_trailing_slash_and_verbatim_full_path() {
    let (sink_port, captured) = spawn_sink();

    // Base with trailing slash -> POST /v1/traces.
    {
        let (addr, mut guard, _output) = spawn_gateway(
            "slash",
            &[(
                "DWARA_OTLP_ENDPOINT",
                &format!("http://127.0.0.1:{sink_port}/"),
            )],
        );
        let mut stream = TcpStream::connect(&addr).expect("connect to gateway");
        assert!(get(&mut stream).starts_with("HTTP/1.1 200"));
        kill_signal(guard.0.id(), "TERM");
        let status = wait_exit(&mut guard.0, Duration::from_secs(20));
        assert!(status.success());
        drop(guard);
    }
    assert!(
        wait_for_export(&captured, Instant::now() + Duration::from_secs(5)),
        "no export for the trailing-slash endpoint"
    );
    assert!(
        captured
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.request_line == "POST /v1/traces HTTP/1.1"),
        "trailing-slash base must resolve to /v1/traces: {:?}",
        captured
            .lock()
            .unwrap()
            .iter()
            .map(|c| &c.request_line)
            .collect::<Vec<_>>()
    );

    // Full trace URL -> used verbatim.
    {
        let (addr, mut guard, _output) = spawn_gateway(
            "verbatim",
            &[(
                "DWARA_OTLP_ENDPOINT",
                &format!("http://127.0.0.1:{sink_port}/custom/v1/traces"),
            )],
        );
        let mut stream = TcpStream::connect(&addr).expect("connect to gateway");
        assert!(get(&mut stream).starts_with("HTTP/1.1 200"));
        kill_signal(guard.0.id(), "TERM");
        let status = wait_exit(&mut guard.0, Duration::from_secs(20));
        assert!(status.success());
        drop(guard);
    }
    assert!(
        wait_for_export(&captured, Instant::now() + Duration::from_secs(5)),
        "no export for the verbatim endpoint"
    );
    assert!(
        captured
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.request_line == "POST /custom/v1/traces HTTP/1.1"),
        "a /v1/traces-suffixed endpoint must be used verbatim: {:?}",
        captured
            .lock()
            .unwrap()
            .iter()
            .map(|c| &c.request_line)
            .collect::<Vec<_>>()
    );
}

/// Fail-fast endpoint forms: a scheme-less `host:port` value, a
/// value with no host after the scheme, and unparseable garbage. Each
/// must fail at STARTUP (one `otlp_init_failed` ERROR) rather than
/// erroring on every export — and none of them may affect serving or
/// the clean exit.
#[test]
fn malformed_endpoints_fail_fast_but_gateway_serves() {
    for endpoint in ["collector:4318", "http://", "not a url"] {
        let (addr, mut guard, mut output) =
            spawn_gateway("malformed", &[("DWARA_OTLP_ENDPOINT", endpoint)]);

        let mut stream = TcpStream::connect(&addr).expect("connect to gateway");
        assert!(
            get(&mut stream).starts_with("HTTP/1.1 200"),
            "gateway must serve with endpoint {endpoint:?}"
        );

        kill_signal(guard.0.id(), "TERM");
        let status = wait_exit(&mut guard.0, Duration::from_secs(20));
        assert!(status.success(), "clean exit for endpoint {endpoint:?}");
        drop(guard);

        let logs = output.read_all();
        assert!(
            logs.contains("otlp_init_failed"),
            "expected the init-failed ERROR line for {endpoint:?}: {logs}"
        );
    }
}

/// Exporter failures DURING serving must never touch the data plane: a
/// collector that answers 5xx to every export gets its first batch after
/// the SDK's 5s tick; the test synchronizes on the sink OBSERVING that
/// POST (no sleeps), then proves the gateway still proxies, still drains
/// clean, and still exits 0 even though the shutdown flush fails too.
#[test]
fn collector_errors_during_serving_never_take_down_the_data_plane() {
    let (sink_port, captured) = spawn_sink_with_status("500 Internal Server Error");
    let (addr, mut guard, _output) = spawn_gateway(
        "failing",
        &[(
            "DWARA_OTLP_ENDPOINT",
            &format!("http://127.0.0.1:{sink_port}"),
        )],
    );

    // One request seeds a span so the batch tick has something to
    // export; the failure is then guaranteed to happen mid-serving.
    let mut stream = TcpStream::connect(&addr).expect("connect to gateway");
    assert!(get(&mut stream).starts_with("HTTP/1.1 200"));

    // Bounded poll for the sink OBSERVING the first (failing) export —
    // the batch processor's scheduled delay is 5s, so allow generous
    // headroom for a loaded runner.
    let saw_export = {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if !captured.lock().unwrap().is_empty() {
                break true;
            }
            if Instant::now() > deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    assert!(
        saw_export,
        "the exporter never attempted its (failing) export"
    );

    // The data plane is unaffected by the export failures.
    for _ in 0..3 {
        let mut stream = TcpStream::connect(&addr).expect("connect to gateway");
        let response = get(&mut stream);
        assert!(
            response.starts_with("HTTP/1.1 200") && response.ends_with("dwara"),
            "serving must continue through collector errors: {response}"
        );
    }

    // Drain + shutdown flush both fail against the 5xx collector; the
    // exit must still be clean and bounded.
    kill_signal(guard.0.id(), "TERM");
    let status = wait_exit(&mut guard.0, Duration::from_secs(20));
    assert!(status.success(), "clean exit despite a failing collector");
    drop(guard);
}

/// A chunked answer declaring an absurd hex chunk size must be an
/// export ERROR, never a panic: the chunked decode runs on the SDK
/// batch thread, where a panic kills the thread and silently stops
/// every later export — and the collector is remote input, so
/// malformed framing is in its threat model. The sink answers the
/// first export with [`ABSURD_CHUNK_RESPONSE`] (see there for why the
/// two-chunk shape matters — it is the exact pre-fix panic input),
/// then recovers to a healthy 200. The discriminating assert is the
/// SECOND export arriving: pre-fix, the wrapped size panicked the
/// batch thread and nothing exported ever again; post-fix it is an
/// ordinary failed export the thread survives. Serving and the clean
/// exit hold throughout, exactly as for a 5xx collector.
#[test]
fn absurd_chunked_size_is_an_export_error_not_a_batch_thread_panic() {
    let (sink_port, captured) = spawn_poison_then_healthy_sink();
    let (addr, mut guard, _output) = spawn_gateway(
        "chunkpoison",
        &[(
            "DWARA_OTLP_ENDPOINT",
            &format!("http://127.0.0.1:{sink_port}"),
        )],
    );

    // Seed spans; bounded poll for the sink OBSERVING the first (poisoned)
    // export — the batch tick is 5s, so generous headroom for load.
    let mut stream = TcpStream::connect(&addr).expect("connect to gateway");
    assert!(get(&mut stream).starts_with("HTTP/1.1 200"));
    assert!(
        wait_for_captures(&captured, 1, Instant::now() + Duration::from_secs(20)),
        "the exporter never attempted the poisoned export"
    );

    // The data plane is untouched by the malformed answer...
    for _ in 0..3 {
        let mut stream = TcpStream::connect(&addr).expect("connect to gateway");
        let response = get(&mut stream);
        assert!(
            response.starts_with("HTTP/1.1 200") && response.ends_with("dwara"),
            "serving must continue through a malformed collector answer: {response}"
        );
    }

    // ...and the batch thread SURVIVED it: a second export arrives
    // against the now-healthy sink (pre-fix the thread had panicked and
    // exports silently stopped).
    assert!(
        wait_for_captures(&captured, 2, Instant::now() + Duration::from_secs(20)),
        "no export after the malformed chunked answer; captured: {:?}",
        captured.lock().unwrap()
    );

    kill_signal(guard.0.id(), "TERM");
    let status = wait_exit(&mut guard.0, Duration::from_secs(20));
    assert!(status.success(), "clean exit after the malformed answer");
    drop(guard);
}

/// IPv6-literal endpoints: `http::Uri::host()` keeps the brackets
/// (`[::1]`) and std resolution rejects a bracketed string, so the
/// exporter client must strip them for RESOLUTION while the Host
/// header keeps the bracketed form the HTTP grammar requires. Pins a
/// full export (real binary, SIGTERM flush) against a sink on `[::1]`;
/// skips itself on hosts without IPv6 loopback, where the white-box
/// unit test of the stripping helper in src/otlp.rs is the coverage.
#[test]
fn ipv6_literal_endpoint_exports_to_loopback_sink() {
    let Some((sink_port, captured)) = spawn_sink_on("[::1]:0", "200 OK") else {
        eprintln!("skipping: no IPv6 loopback on this host");
        return;
    };
    let (addr, mut guard, mut output) = spawn_gateway(
        "ipv6",
        &[("DWARA_OTLP_ENDPOINT", &format!("http://[::1]:{sink_port}"))],
    );

    let mut stream = TcpStream::connect(&addr).expect("connect to gateway");
    let response = get(&mut stream);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "gateway must serve with an IPv6-literal OTLP endpoint: {response}"
    );

    kill_signal(guard.0.id(), "TERM");
    let status = wait_exit(&mut guard.0, Duration::from_secs(20));
    assert!(status.success(), "clean exit with the IPv6 flush: {status}");
    drop(guard);

    assert!(
        wait_for_export(&captured, Instant::now() + Duration::from_secs(5)),
        "no OTLP export arrived over IPv6; captured: {:?}",
        captured.lock().unwrap()
    );

    let all = captured.lock().unwrap().clone();
    let trace_post = all
        .iter()
        .find(|c| c.request_line.starts_with("POST /v1/traces "))
        .expect("an export POST to /v1/traces over IPv6");
    assert_eq!(trace_post.request_line, "POST /v1/traces HTTP/1.1");
    assert!(!trace_post.body.is_empty(), "nonzero protobuf body");
    // The Host header keeps the brackets (resolution-only stripping).
    let expected_host = format!("[::1]:{sink_port}");
    assert_eq!(
        trace_post.host.as_deref(),
        Some(expected_host.as_str()),
        "Host header must stay bracketed: {:?}",
        trace_post.host
    );

    let logs = output.read_all();
    assert!(
        logs.contains("otlp_export_enabled"),
        "no enable line: {logs}"
    );
}
