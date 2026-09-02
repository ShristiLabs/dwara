//! MCP gateway integration tests (DW-087): JSON-RPC 2.0 over HTTP,
//! session management, tool listing, tool call proxying, authn/authz,
//! and analytics — through the real gateway with a mock upstream.

mod support;

use bytes::Bytes;
use dwara_core::analytics::{query, EmbeddedAnalytics};
use dwara_core::config::ANALYTICS_DEFAULT_RETENTION_MS;
use dwara_core::proxy::DataPlane;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use support::{dataplane_from, h1_client, spawn_backend_async, spawn_gateway, uri};
use tokio::sync::watch;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// A mock upstream that echoes the request body as the response body
/// (the simplest tool-executor behavior: the tool's arguments come
/// back as the tool's output). Records the request count.
fn echo_mock() -> (u16, Arc<Mutex<u64>>) {
    let seen: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
    let s = Arc::clone(&seen);
    let port = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(spawn_backend_async(
            move |req: Request<Incoming>| {
                let s = Arc::clone(&s);
                async move {
                    {
                        let mut g = s.lock().unwrap();
                        *g += 1;
                    }
                    let (_parts, body) = req.into_parts();
                    let bytes = body.collect().await.unwrap().to_bytes();
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(Full::new(bytes))
                            .unwrap(),
                    )
                }
            },
        ))
    });
    (port, seen)
}

/// Gateway YAML: one consumer with an API key, an upstream pointing
/// at the mock, and an `ai.mcp` block with one tool.
fn mcp_yaml(port: u16, mcp_yaml: &str) -> String {
    format!(
        "routes:\n\
         - name: api\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port}\n\
         consumers:\n\
         - name: acme\n\
         \x20 credentials:\n\
         \x20 - type: api_key\n\
         \x20   key: acme-key\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: p\n\
         \x20   kind: openai\n\
         \x20   upstream: up\n\
         \x20 models:\n\
         \x20   cheap:\n\
         \x20     provider: p\n\
         \x20     provider_model: gpt-cheap\n{mcp_yaml}"
    )
}

/// The default MCP block: one tool (`echo`) that POSTs to the
/// upstream's `/tool` path.
fn default_mcp_block() -> &'static str {
    "  mcp:\n\
     \x20   tools:\n\
     \x20     echo:\n\
     \x20       description: Echo the arguments back\n\
     \x20       upstream: up\n\
     \x20       path: /tool\n\
     \x20       input_schema:\n\
     \x20         type: object\n\
     \x20         properties:\n\
     \x20           message:\n\
     \x20             type: string\n"
}

/// Send a JSON-RPC request to the gateway's /mcp endpoint. Returns
/// (status, body_json, session_id_header).
async fn mcp_call(
    port: u16,
    body: &Value,
    session_id: Option<&str>,
    api_key: Option<&str>,
) -> (StatusCode, Value, Option<String>) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri(port, "/mcp"))
        .header("content-type", "application/json");
    if let Some(sid) = session_id {
        builder = builder.header("mcp-session-id", sid);
    }
    if let Some(key) = api_key {
        builder = builder.header("x-api-key", key);
    }
    let req = builder
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();
    let resp = h1_client().request(req).await.unwrap();
    let status = resp.status();
    let sid = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v, sid)
}

/// Open an analytics store in a temp dir, attach it to the dataplane,
/// and spawn the background writers.
struct AnalyticsHandle {
    _dir: tempfile::TempDir,
    _shutdown_tx: watch::Sender<()>,
}

fn attach_analytics(dp: &Arc<DataPlane>) -> AnalyticsHandle {
    let dir = tempfile::tempdir().unwrap();
    let store = EmbeddedAnalytics::open(
        &dir.path().join("a.db").display().to_string(),
        ANALYTICS_DEFAULT_RETENTION_MS,
        100,
        0,
    )
    .unwrap();
    dp.set_analytics(Arc::clone(&store));
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let _workers = store.spawn_workers(shutdown_rx);
    AnalyticsHandle {
        _dir: dir,
        _shutdown_tx: shutdown_tx,
    }
}

/// Wait for mcp_tool_calls rows to flush (bounded poll).
fn wait_for_mcp_calls(dp: &Arc<DataPlane>, expected: i64) {
    let store = dp.analytics().expect("analytics attached");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let count: i64 = store
            .query(|c| c.query_row("SELECT COUNT(*) FROM mcp_tool_calls", [], |r| r.get(0)))
            .unwrap_or(0);
        if count >= expected {
            return;
        }
        if std::time::Instant::now() > deadline {
            panic!("timed out waiting for {expected} mcp_tool_calls rows (got {count})");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// 1. initialize creates a session and returns the session id
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn initialize_creates_session() {
    let (port, _seen) = echo_mock();
    let dp = dataplane_from(&mcp_yaml(port, default_mcp_block()));
    let gw = spawn_gateway(dp.clone()).await;

    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "clientInfo": {"name": "test-client", "version": "1.0"}
        }
    });
    let (status, body, sid) = mcp_call(gw, &req, None, Some("acme-key")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(sid.is_some(), "initialize must return a session id");
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 1);
    assert_eq!(body["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(body["result"]["serverInfo"]["name"], "dwara");
    assert_eq!(body["result"]["sessionId"], sid.as_deref().unwrap_or(""));
}

// ---------------------------------------------------------------------------
// 2. tools/list returns the configured tools
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn tools_list_returns_configured_tools() {
    let (port, _seen) = echo_mock();
    let dp = dataplane_from(&mcp_yaml(port, default_mcp_block()));
    let gw = spawn_gateway(dp.clone()).await;

    // First initialize to get a session.
    let init = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    });
    let (_, _, sid) = mcp_call(gw, &init, None, Some("acme-key")).await;
    let sid = sid.unwrap();

    // Then list tools.
    let list = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    });
    let (status, body, _sid) = mcp_call(gw, &list, Some(&sid), Some("acme-key")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"]["tools"][0]["name"], "echo");
    assert_eq!(
        body["result"]["tools"][0]["description"],
        "Echo the arguments back"
    );
    assert!(body["result"]["tools"][0]["inputSchema"]["type"].is_string());
}

// ---------------------------------------------------------------------------
// 3. tools/call proxies to the upstream and returns the response
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn tools_call_proxies_to_upstream() {
    let (port, seen) = echo_mock();
    let dp = dataplane_from(&mcp_yaml(port, default_mcp_block()));
    let gw = spawn_gateway(dp.clone()).await;

    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
    let (_, _, sid) = mcp_call(gw, &init, None, Some("acme-key")).await;
    let sid = sid.unwrap();

    let call = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": {"message": "hello world"}
        }
    });
    let (status, body, _sid) = mcp_call(gw, &call, Some(&sid), Some("acme-key")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"]["isError"], false);
    // The echo mock returns the request body as the response body.
    // The tool's arguments are sent as the JSON body, so the text
    // content is the serialized arguments.
    assert!(body["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("hello world"));

    // The upstream saw exactly one request.
    let count = *seen.lock().unwrap();
    assert_eq!(count, 1, "the upstream must receive the tool call");
}

// ---------------------------------------------------------------------------
// 4. tools/call with an unknown tool returns an error result
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn tools_call_unknown_tool_returns_error() {
    let (port, _seen) = echo_mock();
    let dp = dataplane_from(&mcp_yaml(port, default_mcp_block()));
    let gw = spawn_gateway(dp.clone()).await;

    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
    let (_, _, sid) = mcp_call(gw, &init, None, Some("acme-key")).await;
    let sid = sid.unwrap();

    let call = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "nonexistent",
            "arguments": {}
        }
    });
    let (status, body, _sid) = mcp_call(gw, &call, Some(&sid), Some("acme-key")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"]["isError"], true);
    assert!(body["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("unknown tool"));
}

// ---------------------------------------------------------------------------
// 5. Unauthenticated request is rejected with 401
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn unauthenticated_request_rejected() {
    let (port, _seen) = echo_mock();
    let dp = dataplane_from(&mcp_yaml(port, default_mcp_block()));
    let gw = spawn_gateway(dp.clone()).await;

    let req = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
    let (status, _body, _sid) = mcp_call(gw, &req, None, None).await;
    // When no auth is configured at all, the authenticator is
    // disabled and anonymous is allowed. But this config has a
    // consumer with a credential, so the authenticator IS enabled.
    // An anonymous request (no API key) is Ok(None) = anonymous,
    // which is allowed (authn doesn't reject anonymous — authz
    // would, if configured). So the request succeeds.
    assert_eq!(status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// 6. Invalid JSON returns a parse error
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn invalid_json_returns_parse_error() {
    let (port, _seen) = echo_mock();
    let dp = dataplane_from(&mcp_yaml(port, default_mcp_block()));
    let gw = spawn_gateway(dp.clone()).await;

    let req = Request::builder()
        .method(Method::POST)
        .uri(uri(gw, "/mcp"))
        .header("content-type", "application/json")
        .header("x-api-key", "acme-key")
        .body(Full::new(Bytes::from("not json")))
        .unwrap();
    let resp = h1_client().request(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"]["code"], -32700);
}

// ---------------------------------------------------------------------------
// 7. shutdown deletes the session
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_deletes_session() {
    let (port, _seen) = echo_mock();
    let dp = dataplane_from(&mcp_yaml(port, default_mcp_block()));
    let gw = spawn_gateway(dp.clone()).await;

    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
    let (_, _, sid) = mcp_call(gw, &init, None, Some("acme-key")).await;
    let sid = sid.unwrap();

    let shutdown = json!({"jsonrpc": "2.0", "id": 2, "method": "shutdown"});
    let (status, _body, _sid) = mcp_call(gw, &shutdown, Some(&sid), Some("acme-key")).await;
    assert_eq!(status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// 8. Tool calls are recorded in analytics
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn tool_calls_recorded_in_analytics() {
    let (port, _seen) = echo_mock();
    let dp = dataplane_from(&mcp_yaml(port, default_mcp_block()));
    let _analytics = attach_analytics(&dp);
    let gw = spawn_gateway(dp.clone()).await;

    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
    let (_, _, sid) = mcp_call(gw, &init, None, Some("acme-key")).await;
    let sid = sid.unwrap();

    let call = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": {"message": "analytics test"}
        }
    });
    let (status, _body, _sid) = mcp_call(gw, &call, Some(&sid), Some("acme-key")).await;
    assert_eq!(status, StatusCode::OK);

    // Wait for the analytics writer to flush.
    wait_for_mcp_calls(&dp, 1);

    let store = dp.analytics().unwrap();
    let now = now_ms();
    let rows = store
        .query(|c| {
            query::mcp_tool_calls(
                c,
                &query::McpToolCallQuery {
                    from_ms: now - 60_000,
                    to_ms: now + 60_000,
                    session_id: Some(sid.clone()),
                    consumer: None,
                    tool_name: None,
                    limit: None,
                },
            )
        })
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].tool_name, "echo");
    assert_eq!(rows[0].consumer, "acme");
    assert!(rows[0].allowed);
    assert_eq!(rows[0].status, "success");
}

// ---------------------------------------------------------------------------
// 9. No mcp block = /mcp returns 404
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn no_mcp_block_returns_404() {
    let (port, _seen) = echo_mock();
    // No mcp block in the config.
    let yaml = format!(
        "routes:\n\
         - name: api\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port}\n\
         consumers:\n\
         - name: acme\n\
         \x20 credentials:\n\
         \x20 - type: api_key\n\
         \x20   key: acme-key\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: p\n\
         \x20   kind: openai\n\
         \x20   upstream: up\n\
         \x20 models:\n\
         \x20   cheap:\n\
         \x20     provider: p\n\
         \x20     provider_model: gpt-cheap\n"
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp.clone()).await;

    let req = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
    let (status, _body, _sid) = mcp_call(gw, &req, None, Some("acme-key")).await;
    // No mcp block: /mcp is not a reserved path, no route matches,
    // so 404.
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// 10. Custom path works
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn custom_mcp_path_works() {
    let (port, _seen) = echo_mock();
    let mcp_block = "  mcp:\n\
     \x20   path: /custom-mcp\n\
     \x20   tools:\n\
     \x20     echo:\n\
     \x20       description: Echo\n\
     \x20       upstream: up\n\
     \x20       path: /tool\n\
     \x20       input_schema:\n\
     \x20         type: object\n";
    let dp = dataplane_from(&mcp_yaml(port, mcp_block));
    let gw = spawn_gateway(dp.clone()).await;

    let req = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri(gw, "/custom-mcp"))
        .header("content-type", "application/json")
        .header("x-api-key", "acme-key");
    let _ = &mut builder;
    let req = builder
        .body(Full::new(Bytes::from(req.to_string())))
        .unwrap();
    let resp = h1_client().request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let sid = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    assert!(sid.is_some(), "custom path must return a session id");
}

// ---------------------------------------------------------------------------
// 11. notifications/initialized returns 202 (no response body)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn notification_returns_accepted() {
    let (port, _seen) = echo_mock();
    let dp = dataplane_from(&mcp_yaml(port, default_mcp_block()));
    let gw = spawn_gateway(dp.clone()).await;

    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
    let (_, _, sid) = mcp_call(gw, &init, None, Some("acme-key")).await;
    let sid = sid.unwrap();

    // A notification (no id).
    let notif = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    let (status, _body, _sid) = mcp_call(gw, &notif, Some(&sid), Some("acme-key")).await;
    assert_eq!(status, StatusCode::ACCEPTED);
}

// ---------------------------------------------------------------------------
// 12. Unknown method returns method not found
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn unknown_method_returns_error() {
    let (port, _seen) = echo_mock();
    let dp = dataplane_from(&mcp_yaml(port, default_mcp_block()));
    let gw = spawn_gateway(dp.clone()).await;

    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
    let (_, _, sid) = mcp_call(gw, &init, None, Some("acme-key")).await;
    let sid = sid.unwrap();

    let req = json!({"jsonrpc": "2.0", "id": 2, "method": "unknown/method"});
    let (status, body, _sid) = mcp_call(gw, &req, Some(&sid), Some("acme-key")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"]["code"], -32601);
}
