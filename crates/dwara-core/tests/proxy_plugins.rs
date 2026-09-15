//! Request-path plugin dispatch integration tests (DW-157).
//!
//! Serves a real gateway (`proxy::handle` on a loopback listener)
//! against in-process backends with proxy-wasm plugins compiled from
//! WAT at test time (the same fixture approach as tests/wasm_host.rs),
//! and asserts the wired request-path surface:
//!
//! - a healthy header plugin's effect is visible at the upstream;
//! - the proxy-wasm pseudo-header convention (`:method`/`:path`) is
//!   what plugins see;
//! - `send_http_response` short-circuits with the plugin's status and
//!   the upstream is never dialed;
//! - a trapping plugin (fuel exhaustion) fails closed (500
//!   `plugin_failed`) while other routes keep serving, and the failure
//!   lands in `dwara_plugin_failures_total`;
//! - a route referencing a plugin whose .wasm failed to load answers
//!   500 `plugin_unavailable` (fail-closed) while clean routes serve;
//! - body phases: a `request_body` plugin rewrites the forwarded body,
//!   a `response_headers` plugin stamps the response, a `response_body`
//!   plugin rewrites the response, and an over-cap body answers 500
//!   `plugin_body_too_large`;
//! - a native filter whose factory errors answers the fail-closed 500
//!   `plugin_unavailable` (never a silent skip);
//! - streaming (SSE/chunked) and content-encoded responses skip the
//!   `response_body` phase and stream through intact;
//! - a header phase never corrupts non-UTF-8 header values it did not
//!   touch;
//! - two WASM plugins on one route run exactly once each, in
//!   declaration order;
//! - a plugin-less route on a plugin-carrying config behaves exactly
//!   like the pre-DW-157 path (defined but unreferenced plugins do not
//!   run);
//! - hot reload: a checksum change to the .wasm takes effect on the
//!   next generation, and removing the route reference stops it;
//! - hot reload: a plugin checksum change invalidates cached responses
//!   on every route referencing the plugin (no stale pre-plugin bytes
//!   replay).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use dwara_core::config::parse_gateway;
use dwara_core::proxy::DataPlane;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

mod support;

use support::{
    dataplane_from, envelope_code, h1_client, spawn_backend, spawn_backend_async,
    spawn_backend_full, spawn_gateway, state_from, uri,
};

// --- WAT fixtures ---------------------------------------------------------

/// Compile a WAT source string to .wasm bytes (tests/wasm_host.rs'
/// approach: minimal proxy-wasm modules built at test time).
fn wat_to_wasm(wat: &str) -> Vec<u8> {
    use wast::parser::{parse, ParseBuffer};
    let buf = ParseBuffer::new(wat).expect("WAT parse buffer");
    let mut wat: wast::Wat = parse(&buf).expect("WAT parse");
    wat.encode().expect("WAT encode")
}

/// Build a minimal proxy-wasm filter module. `imports` are WAT import
/// forms, `data` are data segments (placed on page 2, above the bump
/// allocator's start), and the four phase bodies are WAT snippets that
/// must leave the action on the stack.
fn filter_wat(
    imports: &str,
    data: &str,
    request_headers: &str,
    request_body: &str,
    response_headers: &str,
    response_body: &str,
) -> String {
    format!(
        r#"(module
  {imports}
  (memory (export "memory") 2 32)
  (global $alloc_ptr (mut i32) (i32.const 1024))
  (func $proxy_on_memory_allocate (export "proxy_on_memory_allocate") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $alloc_ptr))
    (global.set $alloc_ptr (i32.add (global.get $alloc_ptr) (local.get $size)))
    (local.get $ptr)
  )
  {data}
  (func (export "proxy_on_vm_start") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_configure") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_request_headers") (param $ctx i32) (param $a i32) (param $b i32) (result i32)
    {request_headers})
  (func (export "proxy_on_request_body") (param $ctx i32) (param $size i32) (param $b i32) (result i32)
    {request_body})
  (func (export "proxy_on_response_headers") (param $ctx i32) (param $a i32) (param $b i32) (result i32)
    {response_headers})
  (func (export "proxy_on_response_body") (param $ctx i32) (param $size i32) (param $b i32) (result i32)
    {response_body})
  (func (export "proxy_on_done") (param i32))
  (func (export "proxy_on_log") (param i32))
)"#
    )
}

const ADD_IMPORT: &str = r#"
  (import "env" "proxy_add_header_map_value"
    (func $add_header (param i32 i32 i32 i32 i32) (result i32)))"#;

/// A filter that adds `x-wasm-filter: {value}` to the request headers.
fn add_header_wat(value: &str) -> String {
    let value_len = value.len();
    filter_wat(
        ADD_IMPORT,
        &format!(r#"(data (i32.const 65536) "x-wasm-filter") (data (i32.const 65560) "{value}")"#),
        &format!(
            r#"(drop (call $add_header (i32.const 2) (i32.const 65536) (i32.const 13)
                 (i32.const 65560) (i32.const {value_len})))
               (i32.const 0)"#
        ),
        "(i32.const 0)",
        "(i32.const 0)",
        "(i32.const 0)",
    )
}

/// A filter that copies the `:path` pseudo-header's value into a real
/// `x-seen-path` header, pinning the pseudo-header convention the
/// dataplane exposes to plugins.
const COPY_PATH_IMPORTS: &str = r#"
  (import "env" "proxy_get_header_map_value"
    (func $get_header (param i32 i32 i32 i32 i32) (result i32)))"#;

fn copy_path_wat() -> String {
    filter_wat(
        &(COPY_PATH_IMPORTS.to_string() + ADD_IMPORT),
        r#"(data (i32.const 65536) ":path") (data (i32.const 65552) "x-seen-path")"#,
        r#"(local $vp i32) (local $vs i32)
           (drop (call $get_header (i32.const 2) (i32.const 65536) (i32.const 5)
                 (i32.const 70000) (i32.const 70004)))
           (local.set $vp (i32.load (i32.const 70000)))
           (local.set $vs (i32.load (i32.const 70004)))
           (if (i32.gt_s (local.get $vs) (i32.const 0))
             (then (drop (call $add_header (i32.const 2) (i32.const 65552) (i32.const 11)
                  (local.get $vp) (local.get $vs)))))
           (i32.const 0)"#,
        "(i32.const 0)",
        "(i32.const 0)",
        "(i32.const 0)",
    )
}

/// A filter that short-circuits every request with a 403 via
/// `proxy_send_http_response`.
const SHORT_CIRCUIT_IMPORT: &str = r#"
  (import "env" "proxy_send_http_response"
    (func $send (param i32 i32 i32 i32 i32 i32 i32) (result i32)))"#;

fn short_circuit_wat() -> String {
    filter_wat(
        SHORT_CIRCUIT_IMPORT,
        "",
        r#"(drop (call $send (i32.const 403)
             (i32.const 0) (i32.const 0)
             (i32.const 0) (i32.const 0)
             (i32.const 0) (i32.const 0)))
           (i32.const 2)"#,
        "(i32.const 0)",
        "(i32.const 0)",
        "(i32.const 0)",
    )
}

/// A filter whose `request_headers` never terminates (fuel exhaustion
/// trap; the config pins a tiny fuel budget).
fn trap_wat() -> String {
    filter_wat(
        "",
        "",
        "(loop $l (br $l)) (i32.const 0)",
        "(i32.const 0)",
        "(i32.const 0)",
        "(i32.const 0)",
    )
}

const SET_BUF_IMPORT: &str = r#"
  (import "env" "proxy_set_buffer_bytes"
    (func $set_buf (param i32 i32 i32 i32 i32) (result i32)))"#;

/// A `request_body` filter that appends `suffix` to the body (splicing
/// at the body-size offset the phase receives).
fn append_request_body_wat(suffix: &str) -> String {
    filter_wat(
        SET_BUF_IMPORT,
        &format!(r#"(data (i32.const 65536) "{suffix}")"#),
        "(i32.const 0)",
        &format!(
            r#"(drop (call $set_buf (i32.const 0) (local.get 1) (i32.const 0)
                 (i32.const 65536) (i32.const {})))
               (i32.const 0)"#,
            suffix.len()
        ),
        "(i32.const 0)",
        "(i32.const 0)",
    )
}

/// A `response_body` filter that appends `suffix` to the response body.
fn append_response_body_wat(suffix: &str) -> String {
    filter_wat(
        SET_BUF_IMPORT,
        &format!(r#"(data (i32.const 65536) "{suffix}")"#),
        "(i32.const 0)",
        "(i32.const 0)",
        "(i32.const 0)",
        &format!(
            r#"(drop (call $set_buf (i32.const 1) (local.get 1) (i32.const 0)
                 (i32.const 65536) (i32.const {})))
               (i32.const 0)"#,
            suffix.len()
        ),
    )
}

/// A `response_headers` filter that adds `x-resp-plugin: yes`.
fn add_response_header_wat() -> String {
    filter_wat(
        ADD_IMPORT,
        r#"(data (i32.const 65536) "x-resp-plugin") (data (i32.const 65560) "yes")"#,
        "(i32.const 0)",
        "(i32.const 0)",
        r#"(drop (call $add_header (i32.const 3) (i32.const 65536) (i32.const 13)
             (i32.const 65560) (i32.const 3)))
           (i32.const 0)"#,
        "(i32.const 0)",
    )
}

// --- config helpers --------------------------------------------------------

/// Write a WAT fixture to a .wasm file under `dir`, returning its path.
fn write_plugin(dir: &std::path::Path, file: &str, wat: &str) -> String {
    let path = dir.join(file);
    std::fs::write(&path, wat_to_wasm(wat)).expect("write plugin fixture");
    path.to_string_lossy().into_owned()
}

/// A gateway config: `routes_block` and `plugins_block` are indented
/// YAML fragments; the service/upstream pair targets `backend_port`.
fn gateway_yaml(backend_port: u16, plugins_block: &str, routes_block: &str) -> String {
    format!(
        "routes:\n{routes_block}\
         services:\n  - name: svc\n    upstream: up\n\
         upstreams:\n  - name: up\n    endpoints:\n      - address: 127.0.0.1\n        port: {backend_port}\n\
         plugins:\n{plugins_block}"
    )
}

/// The single plugged route (`/v1`, prefix) shape.
fn plugged_route_yaml(extra_route_fields: &str) -> String {
    format!(
        "  - name: plugged\n    service: svc\n    match:\n      path:\n        type: prefix\n        value: /v1\n    action:\n      type: proxy\n{extra_route_fields}"
    )
}

/// The plugged route PLUS a clean `/v2` route on the same service.
fn plugged_and_clean_routes_yaml(extra_route_fields: &str) -> String {
    format!(
        "{plugged}  - name: clean\n    service: svc\n    match:\n      path:\n        type: prefix\n        value: /v2\n    action:\n      type: proxy\n",
        plugged = plugged_route_yaml(extra_route_fields)
    )
}

async fn body_text<B>(body: B) -> String
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    String::from_utf8_lossy(&body.collect().await.unwrap().to_bytes()).into_owned()
}

fn post_client() -> Client<HttpConnector, Full<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

// --- happy paths -----------------------------------------------------------

#[tokio::test]
async fn healthy_header_plugin_sets_header_seen_upstream() {
    let dir = tempfile::tempdir().unwrap();
    let wasm = write_plugin(dir.path(), "adder.wasm", &add_header_wat("dwara"));
    let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    let backend = spawn_backend_full(Arc::new(move |req: Request<hyper::body::Incoming>| {
        {
            let mut g = recorder.lock().unwrap();
            for (k, v) in req.headers() {
                g.push((k.to_string(), v.to_str().unwrap_or("").to_string()));
            }
        }
        Response::new(Full::new(Bytes::from_static(b"ok")))
    }))
    .await;
    let yaml = gateway_yaml(
        backend,
        &format!("  - name: adder\n    wasm: {wasm}\n    phases: [request_headers]\n"),
        &plugged_route_yaml("    plugins: [adder]\n"),
    );
    let port = spawn_gateway(dataplane_from(&yaml)).await;

    let resp = h1_client().get(uri(port, "/v1/users")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .any(|(k, v)| k == "x-wasm-filter" && v == "dwara"),
        "the plugin's header must reach the upstream, saw: {:?}",
        seen.lock().unwrap()
    );
}

#[tokio::test]
async fn plugin_sees_proxy_wasm_pseudo_headers() {
    // The `:path` pseudo-header (path + query) is what the plugin
    // reads; the plugin copies it into a real header the upstream (and
    // the test) can observe.
    let dir = tempfile::tempdir().unwrap();
    let wasm = write_plugin(dir.path(), "copier.wasm", &copy_path_wat());
    let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    let backend = spawn_backend_full(Arc::new(move |req: Request<hyper::body::Incoming>| {
        {
            let mut g = recorder.lock().unwrap();
            for (k, v) in req.headers() {
                g.push((k.to_string(), v.to_str().unwrap_or("").to_string()));
            }
        }
        Response::new(Full::new(Bytes::from_static(b"ok")))
    }))
    .await;
    let yaml = gateway_yaml(
        backend,
        &format!("  - name: copier\n    wasm: {wasm}\n    phases: [request_headers]\n"),
        &plugged_route_yaml("    plugins: [copier]\n"),
    );
    let port = spawn_gateway(dataplane_from(&yaml)).await;

    let resp = h1_client()
        .get(uri(port, "/v1/items?flag=1"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .any(|(k, v)| k == "x-seen-path" && v == "/v1/items?flag=1"),
        "the :path pseudo-header (path + query) must be visible to the plugin, saw: {:?}",
        seen.lock().unwrap()
    );
}

#[tokio::test]
async fn send_http_response_short_circuits_without_upstream_dial() {
    let dir = tempfile::tempdir().unwrap();
    let wasm = write_plugin(dir.path(), "denier.wasm", &short_circuit_wat());
    let (backend, count) = spawn_backend(
        |_n, _m, _p, _b| Response::new(Full::new(Bytes::from_static(b"upstream-reached"))),
        Duration::from_millis(0),
    )
    .await;
    let yaml = gateway_yaml(
        backend,
        &format!("  - name: denier\n    wasm: {wasm}\n    phases: [request_headers]\n"),
        &plugged_route_yaml("    plugins: [denier]\n"),
    );
    let port = spawn_gateway(dataplane_from(&yaml)).await;

    let resp = h1_client().get(uri(port, "/v1/anything")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "plugin's own status");
    assert_eq!(
        count.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the upstream must never be dialed on a short-circuit"
    );
}

#[tokio::test]
async fn trapping_plugin_fails_closed_and_other_routes_keep_serving() {
    let dir = tempfile::tempdir().unwrap();
    let wasm = write_plugin(dir.path(), "spinner.wasm", &trap_wat());
    let backend = spawn_backend_full(Arc::new(|_req: Request<hyper::body::Incoming>| {
        Response::new(Full::new(Bytes::from_static(b"clean-ok")))
    }))
    .await;
    let yaml = gateway_yaml(
        backend,
        &format!(
            "  - name: spinner\n    wasm: {wasm}\n    phases: [request_headers]\n    limits:\n      fuel: 2000\n"
        ),
        &plugged_and_clean_routes_yaml("    plugins: [spinner]\n"),
    );
    let dp = dataplane_from(&yaml);
    let port = spawn_gateway(Arc::clone(&dp)).await;

    let resp = h1_client().get(uri(port, "/v1/spin")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = body_text(resp.into_body()).await;
    assert_eq!(envelope_code(body.as_bytes()), "plugin_failed");

    // Failure isolation: the clean route keeps serving.
    let resp = h1_client().get(uri(port, "/v2/ok")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_text(resp.into_body()).await, "clean-ok");

    // The failure is attributed in dwara_plugin_failures_total.
    let metrics = dp.observability().render();
    assert!(
        metrics.contains("dwara_plugin_failures_total"),
        "plugin failure family exported: {metrics}"
    );
    assert!(
        metrics.contains("dwara_plugin_failures_total{name=\"spinner\",reason=\"trap\"}"),
        "the trap is attributed to the plugin by name: {metrics}"
    );
}

#[tokio::test]
async fn unloaded_plugin_route_fails_closed_clean_route_serves() {
    // The .wasm path does not exist: publish succeeds (validation
    // deliberately does not check file existence), the load marks the
    // plugin crashed, and the route referencing it answers 500
    // plugin_unavailable.
    let backend = spawn_backend_full(Arc::new(|_req: Request<hyper::body::Incoming>| {
        Response::new(Full::new(Bytes::from_static(b"clean-ok")))
    }))
    .await;
    let yaml = gateway_yaml(
        backend,
        "  - name: ghost\n    wasm: /nonexistent/dwara-test-ghost.wasm\n    phases: [request_headers]\n",
        &plugged_and_clean_routes_yaml("    plugins: [ghost]\n"),
    );
    let dp = dataplane_from(&yaml);
    let port = spawn_gateway(Arc::clone(&dp)).await;

    let resp = h1_client().get(uri(port, "/v1/x")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = body_text(resp.into_body()).await;
    assert_eq!(envelope_code(body.as_bytes()), "plugin_unavailable");

    let resp = h1_client().get(uri(port, "/v2/ok")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let metrics = dp.observability().render();
    assert!(
        metrics.contains("dwara_plugin_failures_total{name=\"ghost\",reason=\"crashed\"}"),
        "the load-time crash state is visible in metrics: {metrics}"
    );
}

// --- body phases -----------------------------------------------------------

#[tokio::test]
async fn request_body_plugin_rewrites_forwarded_body() {
    let dir = tempfile::tempdir().unwrap();
    let wasm = write_plugin(
        dir.path(),
        "appender.wasm",
        &append_request_body_wat("-appended"),
    );
    // Echo backend (spawn_backend collects the request body and hands
    // it to the handler): the test asserts the bytes the upstream
    // received.
    let (backend, _count) = spawn_backend(
        |_n, _m, _p, body| Response::new(Full::new(body)),
        Duration::from_millis(0),
    )
    .await;
    let yaml = gateway_yaml(
        backend,
        &format!("  - name: appender\n    wasm: {wasm}\n    phases: [request_body]\n"),
        &plugged_route_yaml("    plugins: [appender]\n"),
    );
    let port = spawn_gateway(dataplane_from(&yaml)).await;

    let resp = post_client()
        .request(
            Request::post(uri(port, "/v1/echo"))
                .body(Full::new(Bytes::from_static(b"hello")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp.into_body()).await;
    assert_eq!(body, "hello-appended", "the plugin's rewrite is forwarded");
}

#[tokio::test]
async fn response_headers_plugin_stamps_client_response() {
    let dir = tempfile::tempdir().unwrap();
    let wasm = write_plugin(dir.path(), "stamper.wasm", &add_response_header_wat());
    let backend = spawn_backend_full(Arc::new(|_req: Request<hyper::body::Incoming>| {
        Response::new(Full::new(Bytes::from_static(b"resp")))
    }))
    .await;
    let yaml = gateway_yaml(
        backend,
        &format!("  - name: stamper\n    wasm: {wasm}\n    phases: [response_headers]\n"),
        &plugged_route_yaml("    plugins: [stamper]\n"),
    );
    let port = spawn_gateway(dataplane_from(&yaml)).await;

    let resp = h1_client().get(uri(port, "/v1/anything")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-resp-plugin")
            .and_then(|v| v.to_str().ok()),
        Some("yes"),
        "the plugin's response header reaches the client"
    );
}

#[tokio::test]
async fn response_body_plugin_rewrites_client_body() {
    let dir = tempfile::tempdir().unwrap();
    let wasm = write_plugin(
        dir.path(),
        "tailer.wasm",
        &append_response_body_wat("-tail"),
    );
    let backend = spawn_backend_full(Arc::new(|_req: Request<hyper::body::Incoming>| {
        Response::new(Full::new(Bytes::from_static(b"resp")))
    }))
    .await;
    let yaml = gateway_yaml(
        backend,
        &format!("  - name: tailer\n    wasm: {wasm}\n    phases: [response_body]\n"),
        &plugged_route_yaml("    plugins: [tailer]\n"),
    );
    let port = spawn_gateway(dataplane_from(&yaml)).await;

    let resp = h1_client().get(uri(port, "/v1/anything")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Framing is exact: Content-Length was rewritten to the new body.
    assert_eq!(
        resp.headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some("9")
    );
    let body = body_text(resp.into_body()).await;
    assert_eq!(
        body, "resp-tail",
        "the plugin's response rewrite reaches the client"
    );
}

#[tokio::test]
async fn over_cap_request_body_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let wasm = write_plugin(
        dir.path(),
        "appender.wasm",
        &append_request_body_wat("-appended"),
    );
    let (backend, count) = spawn_backend(
        |_n, _m, _p, body| Response::new(Full::new(body)),
        Duration::from_millis(0),
    )
    .await;
    // The route limit is dry-run (the 413 policy is monitor mode) but
    // the plugin buffering cap still uses it — a body-phase plugin
    // must see the body or the request does not proceed.
    let yaml = gateway_yaml(
        backend,
        &format!("  - name: appender\n    wasm: {wasm}\n    phases: [request_body]\n"),
        &plugged_route_yaml(
            "    plugins: [appender]\n    limits:\n      max_body_bytes: 16\n      dry_run: true\n",
        ),
    );
    let dp = dataplane_from(&yaml);
    let port = spawn_gateway(Arc::clone(&dp)).await;

    let resp = post_client()
        .request(
            Request::post(uri(port, "/v1/echo"))
                .body(Full::new(Bytes::from(vec![b'x'; 64])))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = body_text(resp.into_body()).await;
    assert_eq!(envelope_code(body.as_bytes()), "plugin_body_too_large");
    assert_eq!(
        count.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an over-cap body never reaches the upstream"
    );
    let metrics = dp.observability().render();
    assert!(
        metrics
            .contains("dwara_plugin_failures_total{name=\"appender\",reason=\"body_too_large\"}"),
        "over-cap failures are attributed: {metrics}"
    );
}

// --- fast path + hot reload -------------------------------------------------

/// A compile-in native filter (DW-119): adds a request header. Used to
/// exercise the native-only chain path (the WASM instance set is
/// empty; every per-name WASM dispatch passes through).
struct NativeAddHeader;

impl dwara_core::plugins::NativeFilter for NativeAddHeader {
    fn on_request_headers(
        &mut self,
        mut headers: Vec<(String, String)>,
    ) -> dwara_core::plugins::FilterOutcome {
        headers.push(("x-native-plugin".to_string(), "yes".to_string()));
        dwara_core::plugins::FilterOutcome::Continue {
            headers,
            body: Vec::new(),
        }
    }
}

#[tokio::test]
async fn native_only_route_runs_registered_filter() {
    let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    let backend = spawn_backend_full(Arc::new(move |req: Request<hyper::body::Incoming>| {
        {
            let mut g = recorder.lock().unwrap();
            for (k, v) in req.headers() {
                g.push((k.to_string(), v.to_str().unwrap_or("").to_string()));
            }
        }
        Response::new(Full::new(Bytes::from_static(b"ok")))
    }))
    .await;
    let yaml = gateway_yaml(
        backend,
        "  - name: nat\n    native: test-add-header\n    phases: [request_headers]\n",
        &plugged_route_yaml("    plugins: [nat]\n"),
    );
    let dp = dataplane_from(&yaml);
    dp.native_plugin_registry()
        .register(
            "test-add-header",
            Box::new(|_cfg: &Option<String>| {
                Ok(Box::new(NativeAddHeader) as Box<dyn dwara_core::plugins::NativeFilter>)
            }),
        )
        .expect("register native filter");
    let port = spawn_gateway(dp).await;

    let resp = h1_client().get(uri(port, "/v1/x")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .any(|(k, v)| k == "x-native-plugin" && v == "yes"),
        "the native filter ran on the native-only chain, saw: {:?}",
        seen.lock().unwrap()
    );
}

#[tokio::test]
async fn plugin_defined_but_unreferenced_route_unchanged() {
    // A plugin exists in the config; the route does not reference it.
    // The request path must behave exactly like a plugin-free config:
    // no plugin header at the upstream, normal 200.
    let dir = tempfile::tempdir().unwrap();
    let wasm = write_plugin(dir.path(), "adder.wasm", &add_header_wat("dwara"));
    let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    let backend = spawn_backend_full(Arc::new(move |req: Request<hyper::body::Incoming>| {
        {
            let mut g = recorder.lock().unwrap();
            for (k, v) in req.headers() {
                g.push((k.to_string(), v.to_str().unwrap_or("").to_string()));
            }
        }
        Response::new(Full::new(Bytes::from_static(b"ok")))
    }))
    .await;
    let yaml = gateway_yaml(
        backend,
        &format!("  - name: adder\n    wasm: {wasm}\n    phases: [request_headers]\n"),
        &plugged_route_yaml(""),
    );
    let port = spawn_gateway(dataplane_from(&yaml)).await;

    let resp = h1_client().get(uri(port, "/v1/users")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        !seen
            .lock()
            .unwrap()
            .iter()
            .any(|(k, _)| k == "x-wasm-filter"),
        "an unreferenced plugin must not run"
    );
}

#[tokio::test]
async fn hot_reload_swaps_plugin_on_checksum_change_and_removal() {
    let dir = tempfile::tempdir().unwrap();
    let plugin_path = dir.path().join("hot.wasm");
    std::fs::write(&plugin_path, wat_to_wasm(&add_header_wat("gen1"))).unwrap();
    let wasm = plugin_path.to_string_lossy().into_owned();
    let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    let backend = spawn_backend_full(Arc::new(move |req: Request<hyper::body::Incoming>| {
        {
            let mut g = recorder.lock().unwrap();
            for (k, v) in req.headers() {
                g.push((k.to_string(), v.to_str().unwrap_or("").to_string()));
            }
        }
        Response::new(Full::new(Bytes::from_static(b"ok")))
    }))
    .await;

    let yaml_v1 = gateway_yaml(
        backend,
        &format!("  - name: hot\n    wasm: {wasm}\n    phases: [request_headers]\n"),
        &plugged_route_yaml("    plugins: [hot]\n"),
    );
    let gateway_v1 = parse_gateway(&yaml_v1).unwrap();
    let state = state_from(&yaml_v1);
    let dp = DataPlane::new(Arc::clone(&state));
    let port = spawn_gateway(Arc::clone(&dp)).await;

    h1_client().get(uri(port, "/v1/x")).await.unwrap();
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .any(|(k, v)| k == "x-wasm-filter" && v == "gen1"),
        "generation 1's plugin bytes are live"
    );

    // Same config, NEW .wasm bytes (checksum change): the swap takes
    // effect after publish + refresh, with no restart.
    std::fs::write(&plugin_path, wat_to_wasm(&add_header_wat("gen2"))).unwrap();
    state.compile_and_publish(&gateway_v1).expect("republish");
    dp.refresh();
    h1_client().get(uri(port, "/v1/x")).await.unwrap();
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .any(|(k, v)| k == "x-wasm-filter" && v == "gen2"),
        "generation 2's plugin bytes are live after refresh"
    );

    // Removing the route reference stops the plugin entirely.
    let yaml_v3 = gateway_yaml(
        backend,
        &format!("  - name: hot\n    wasm: {wasm}\n    phases: [request_headers]\n"),
        &plugged_route_yaml(""),
    );
    state
        .compile_and_publish(&parse_gateway(&yaml_v3).unwrap())
        .expect("republish without plugins");
    dp.refresh();
    let before = seen.lock().unwrap().len();
    h1_client().get(uri(port, "/v1/x")).await.unwrap();
    let new_headers: Vec<(String, String)> = {
        let g = seen.lock().unwrap();
        g[before..].to_vec()
    };
    assert!(
        !new_headers.iter().any(|(k, _)| k == "x-wasm-filter"),
        "the plugin no longer runs after the route drops the reference"
    );
}

// --- review fixes (DW-157 rework) -------------------------------------------

#[tokio::test]
async fn native_filter_create_failure_fails_closed() {
    // The registry CONTAINS the name (the health gate admits it), but
    // the factory errors at construction: the configured filter never
    // runs, so the request must fail closed (500 plugin_unavailable)
    // — never a silent pass-through — and the failure is attributed in
    // dwara_plugin_failures_total.
    let (backend, count) = spawn_backend(
        |_n, _m, _p, _b| Response::new(Full::new(Bytes::from_static(b"never"))),
        Duration::from_millis(0),
    )
    .await;
    let yaml = gateway_yaml(
        backend,
        "  - name: nat\n    native: broken\n    phases: [request_headers]\n",
        &plugged_route_yaml("    plugins: [nat]\n"),
    );
    let dp = dataplane_from(&yaml);
    dp.native_plugin_registry()
        .register(
            "broken",
            Box::new(|_cfg: &Option<String>| -> Result<
                Box<dyn dwara_core::plugins::NativeFilter>,
                String,
            > {
                Err("construction exploded".to_string())
            }),
        )
        .expect("register failing native factory");
    let port = spawn_gateway(Arc::clone(&dp)).await;

    let resp = h1_client().get(uri(port, "/v1/x")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = body_text(resp.into_body()).await;
    assert_eq!(envelope_code(body.as_bytes()), "plugin_unavailable");
    assert_eq!(
        count.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a create failure must not pass the request through"
    );
    let metrics = dp.observability().render();
    assert!(
        metrics.contains("dwara_plugin_failures_total{name=\"nat\",reason=\"instantiate_failed\"}"),
        "the create failure is attributed: {metrics}"
    );
}

/// A streaming body yielding its chunks one frame at a time — no
/// declared length, so hyper frames it as chunked (the SSE shape).
struct ChunkedBody {
    chunks: std::vec::IntoIter<Bytes>,
}

impl hyper::body::Body for ChunkedBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        std::task::Poll::Ready(
            self.get_mut()
                .chunks
                .next()
                .map(|c| Ok(hyper::body::Frame::data(c))),
        )
    }
}

#[tokio::test]
async fn sse_response_skips_response_body_phase_and_streams() {
    // A text/event-stream response of unknown length: the
    // response_body plugin phase is SKIPPED (buffering an endless
    // stream would stall the route), the body streams through intact,
    // and the skip is not counted as a plugin failure.
    let dir = tempfile::tempdir().unwrap();
    let wasm = write_plugin(
        dir.path(),
        "tailer.wasm",
        &append_response_body_wat("-tail"),
    );
    let backend = spawn_backend_async(|_req: Request<hyper::body::Incoming>| async {
        Ok::<_, std::convert::Infallible>(
            Response::builder()
                .header("content-type", "text/event-stream")
                .body(ChunkedBody {
                    chunks: vec![
                        Bytes::from_static(b"data: one\n\n"),
                        Bytes::from_static(b"data: two\n\n"),
                    ]
                    .into_iter(),
                })
                .unwrap(),
        )
    })
    .await;
    let yaml = gateway_yaml(
        backend,
        &format!("  - name: tailer\n    wasm: {wasm}\n    phases: [response_body]\n"),
        &plugged_route_yaml("    plugins: [tailer]\n"),
    );
    let dp = dataplane_from(&yaml);
    let port = spawn_gateway(Arc::clone(&dp)).await;

    let resp = h1_client().get(uri(port, "/v1/events")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp.into_body()).await;
    assert_eq!(
        body, "data: one\n\ndata: two\n\n",
        "the stream passes through byte-exact, with no plugin rewrite"
    );
    let metrics = dp.observability().render();
    assert!(
        !metrics.contains("dwara_plugin_failures_total"),
        "a documented skip is not a failure: {metrics}"
    );
}

#[tokio::test]
async fn plugin_header_phase_preserves_non_utf8_header_values() {
    // Header values may legally carry non-UTF-8 bytes (obs-text) the
    // sandbox's String view cannot represent. The plugin phases touch
    // only the headers a plugin actually changed: the untouched raw
    // values must survive BOTH directions byte-exact.
    let dir = tempfile::tempdir().unwrap();
    let wasm = write_plugin(dir.path(), "adder.wasm", &add_header_wat("dwara"));
    type RawHeaders = Vec<(String, Vec<u8>)>;
    let seen: Arc<Mutex<RawHeaders>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    let backend = spawn_backend_full(Arc::new(move |req: Request<hyper::body::Incoming>| {
        {
            let mut g = recorder.lock().unwrap();
            for (k, v) in req.headers() {
                g.push((k.to_string(), v.as_bytes().to_vec()));
            }
        }
        let mut resp = Response::new(Full::new(Bytes::from_static(b"ok")));
        resp.headers_mut().insert(
            "x-raw-resp",
            hyper::header::HeaderValue::from_bytes(&[0x80, 0xfe, 0x41]).unwrap(),
        );
        resp
    }))
    .await;
    let yaml = gateway_yaml(
        backend,
        &format!("  - name: adder\n    wasm: {wasm}\n    phases: [request_headers]\n"),
        &plugged_route_yaml("    plugins: [adder]\n"),
    );
    let port = spawn_gateway(dataplane_from(&yaml)).await;

    let resp = h1_client()
        .request(
            Request::builder()
                .uri(uri(port, "/v1/x"))
                .header(
                    "x-raw-req",
                    hyper::header::HeaderValue::from_bytes(&[0xc3, 0x28, 0xff]).unwrap(),
                )
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Response side: the untouched raw header survives the phase.
    assert_eq!(
        resp.headers().get("x-raw-resp").map(|v| v.as_bytes()),
        Some(&[0x80, 0xfe, 0x41][..]),
        "a non-UTF-8 response value the plugin did not touch is never blanked"
    );
    // Request side: the upstream saw the original bytes, plus the
    // plugin's own header (the phase DID apply its change).
    {
        let g = seen.lock().unwrap();
        assert_eq!(
            g.iter()
                .find(|(k, _)| k == "x-raw-req")
                .map(|(_, v)| v.as_slice()),
            Some(&[0xc3, 0x28, 0xff][..]),
            "a non-UTF-8 request value the plugin did not touch is never blanked"
        );
        assert!(
            g.iter().any(|(k, v)| k == "x-wasm-filter" && v == b"dwara"),
            "the plugin's own change is applied: {g:?}"
        );
    }
}

#[tokio::test]
async fn two_wasm_plugins_run_once_each_in_declaration_order() {
    // Two request_body plugins on one route: each appends its own
    // suffix. Declaration order [first, second] must yield
    // "hello-one-two" — both executed, in order, exactly once (a
    // double execution or a swap is visible in the bytes).
    let dir = tempfile::tempdir().unwrap();
    let one = write_plugin(dir.path(), "one.wasm", &append_request_body_wat("-one"));
    let two = write_plugin(dir.path(), "two.wasm", &append_request_body_wat("-two"));
    let (backend, _count) = spawn_backend(
        |_n, _m, _p, body| Response::new(Full::new(body)),
        Duration::from_millis(0),
    )
    .await;
    let yaml = gateway_yaml(
        backend,
        &format!(
            "  - name: first\n    wasm: {one}\n    phases: [request_body]\n  - name: second\n    wasm: {two}\n    phases: [request_body]\n"
        ),
        &plugged_route_yaml("    plugins: [first, second]\n"),
    );
    let port = spawn_gateway(dataplane_from(&yaml)).await;

    let resp = post_client()
        .request(
            Request::post(uri(port, "/v1/echo"))
                .body(Full::new(Bytes::from_static(b"hello")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp.into_body()).await;
    assert_eq!(
        body, "hello-one-two",
        "both plugins ran, in declaration order, exactly once each"
    );
}

#[tokio::test]
async fn plugin_change_invalidates_cached_responses() {
    // Cache replay consistency for PLUGINS: a route whose cached bytes
    // were shaped by the old .wasm must never replay them after the
    // plugin's bytes change — every route referencing the changed
    // plugin bumps its cache epoch on reload (DW-037/DW-157).
    let dir = tempfile::tempdir().unwrap();
    let plugin_path = dir.path().join("hot.wasm");
    std::fs::write(&plugin_path, wat_to_wasm(&append_response_body_wat("-old"))).unwrap();
    let wasm = plugin_path.to_string_lossy().into_owned();
    let (backend, count) = spawn_backend(
        |_n, _m, _p, _b| {
            Response::builder()
                .header("content-type", "text/plain")
                .body(Full::new(Bytes::from_static(b"cache-me")))
                .unwrap()
        },
        Duration::from_millis(0),
    )
    .await;
    let yaml = format!(
        "routes:\n  - name: plugged\n    service: svc\n    match:\n      path:\n        type: prefix\n        value: /v1\n    action:\n      type: proxy\n    cache:\n      ttl_secs: 30\n    plugins: [tailer]\n\
         services:\n  - name: svc\n    upstream: up\n\
         upstreams:\n  - name: up\n    endpoints:\n      - address: 127.0.0.1\n        port: {backend}\n\
         plugins:\n  - name: tailer\n    wasm: {wasm}\n    phases: [response_body]\n"
    );
    let gateway = parse_gateway(&yaml).unwrap();
    let state = state_from(&yaml);
    let dp = DataPlane::new(Arc::clone(&state));
    let port = spawn_gateway(Arc::clone(&dp)).await;

    let x_cache = |h: &hyper::HeaderMap| {
        h.get("x-cache")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("<absent>")
            .to_string()
    };

    // Warm the cache with the OLD plugin's shaping.
    let resp = h1_client().get(uri(port, "/v1/c")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(x_cache(resp.headers()), "miss");
    assert_eq!(body_text(resp.into_body()).await, "cache-me-old");
    let resp = h1_client().get(uri(port, "/v1/c")).await.unwrap();
    assert_eq!(x_cache(resp.headers()), "hit");
    assert_eq!(body_text(resp.into_body()).await, "cache-me-old");
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Replace the plugin's .wasm (different behavior, checksum change)
    // and republish the UNCHANGED route: the cache must not replay the
    // old plugin's bytes.
    std::fs::write(&plugin_path, wat_to_wasm(&append_response_body_wat("-new"))).unwrap();
    state
        .compile_and_publish(&gateway)
        .expect("republish same config");
    dp.refresh();

    let resp = h1_client().get(uri(port, "/v1/c")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        x_cache(resp.headers()),
        "miss",
        "the plugin change invalidates the route's cached entries"
    );
    assert_eq!(
        body_text(resp.into_body()).await,
        "cache-me-new",
        "the next response reflects the NEW plugin, not the cached old bytes"
    );
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
}
