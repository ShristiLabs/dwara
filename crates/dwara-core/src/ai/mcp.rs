//! MCP gateway (DW-087): a hand-rolled Model Context Protocol
//! server/router over JSON-RPC 2.0.
//!
//! dwara exposes configured tools on a reserved HTTP path (default
//! `/mcp`). The gateway is a ROUTER, not a tool executor: each tool
//! names an upstream HTTP endpoint, and `tools/call` proxies the
//! call (POST JSON body, get JSON response). AuthN is enforced on
//! every request (the existing `security/authn` module); AuthZ is
//! per-tool (the existing `security/authz` module). Agent sessions
//! are state-store backed (the `mcp_sessions` table); tool calls are
//! correlated in analytics (the `mcp_tool_calls` table).
//!
//! # Protocol
//!
//! MCP is JSON-RPC 2.0 over HTTP. The lifecycle:
//!
//! 1. `initialize` — the client sends its protocol version and
//!    client info; the server creates a session, responds with its
//!    protocol version, capabilities, and server info, and returns
//!    the session id in the `Mcp-Session-Id` response header.
//! 2. `notifications/initialized` — the client acknowledges (a
//!    notification: no response).
//! 3. `tools/list` — the server returns the tool definitions
//!    (filtered by the caller's authz).
//! 4. `tools/call` — the server authorizes, proxies the call to the
//!    upstream, and returns the result.
//! 5. `shutdown` — the server deletes the session.
//!
//! # Dependency direction
//!
//! `ai` depends on `config` only. The HTTP call reuses the same
//! `hyper_util` client pattern as the DW-083 semantic cache and
//! DW-085 routing policy (no new dependencies). The handler returns
//! results; the dataplane records analytics/observability.

use crate::config::ai::AiMcpConfig;
use crate::config::{Authz, Gateway, UpstreamProtocol};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::{Method, Request};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// JSON-RPC 2.0 error codes (per the spec).
mod error_code {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    #[allow(dead_code)]
    pub const INVALID_PARAMS: i32 = -32602;
    #[allow(dead_code)]
    pub const INTERNAL_ERROR: i32 = -32603;
}

/// The MCP protocol version this server speaks.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// The server name reported in the `initialize` response.
const SERVER_NAME: &str = "dwara";

/// Default session TTL in seconds (1 hour).
const DEFAULT_TTL_SECS: u64 = 3600;

/// Default max concurrent sessions.
const DEFAULT_MAX_CONCURRENT: usize = 1000;

/// Default upstream call timeout in milliseconds (30 s).
const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Per-process session-id counter (disambiguates coarse clocks and
/// same-nanosecond initializations). Session IDs are correlation
/// handles with uniqueness, not cryptographic secrets — the sha256
/// fold over wall-clock nanos + counter + consumer gives 128 bits of
/// collision resistance per process.
static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a 128-bit hex session id: sha256 over (wall-clock nanos,
/// process counter, consumer name), truncated to 32 hex chars (16
/// bytes). Unique per process; no `rand` dependency (the codebase
/// generates all its IDs this way — see `generate_request_id`).
fn generate_session_id(consumer: &str) -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let c = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hasher.update(n.to_le_bytes());
    hasher.update(c.to_le_bytes());
    hasher.update(consumer.as_bytes());
    let hash = hasher.finalize();
    // 16 bytes = 32 hex chars = 128 bits.
    let hex: String = hash.iter().take(16).map(|b| format!("{b:02x}")).collect();
    format!("mcp-{hex}")
}

/// One compiled MCP tool (DW-087): the resolved upstream URL, the
/// HTTP method, the timeout, and the optional authz attachment.
#[derive(Debug, Clone)]
pub struct CompiledMcpTool {
    /// The tool name (the key in `ai.mcp.tools`).
    pub name: String,
    /// Human-readable description (returned in `tools/list`).
    pub description: String,
    /// The JSON Schema for the tool's arguments (returned as
    /// `inputSchema` in `tools/list`).
    pub input_schema: Value,
    /// The resolved upstream URL (scheme + host:port + path).
    pub upstream_url: String,
    /// The HTTP method for the upstream call.
    pub method: String,
    /// The upstream call timeout in milliseconds.
    pub timeout_ms: u64,
    /// Optional per-tool authorization. When present, the tool is
    /// only callable by consumers satisfying the authz rules.
    pub authz: Option<Authz>,
}

/// The compiled MCP gateway (DW-087): the tool table, session
/// policy, and reserved path. Built at `AiRuntime` compile time
/// from the `ai.mcp` config block; immutable once built.
#[derive(Debug, Clone)]
pub struct CompiledMcp {
    /// The compiled tools, keyed by tool name.
    pub tools: BTreeMap<String, CompiledMcpTool>,
    /// Session TTL in seconds.
    pub sessions_ttl_secs: u64,
    /// Max concurrent sessions.
    pub sessions_max_concurrent: usize,
    /// The reserved HTTP path for the MCP endpoint.
    pub path: String,
    /// Per-consumer tool allowlists (DW-113): consumer name -> the
    /// set of tool names that consumer may call. A consumer NOT in
    /// this map has no restriction (may call any tool). Built from
    /// `gateway.consumers[].tool_allowlist` at compile time.
    pub consumer_tool_allowlists: BTreeMap<String, BTreeSet<String>>,
}

/// The outcome of an MCP tool call (DW-087): the result the dataplane
/// records in analytics and returns to the client.
#[derive(Debug, Clone)]
pub struct McpToolCallOutcome {
    /// The tool name that was called.
    pub tool_name: String,
    /// Whether the call was authorized.
    pub allowed: bool,
    /// The call duration in milliseconds.
    pub duration_ms: f64,
    /// An optional error code (for analytics).
    pub error_code: Option<String>,
    /// The status string: `success`, `error`, or `denied`.
    pub status: String,
}

/// The result of handling one JSON-RPC request (DW-087): the
/// response body (JSON) and optional analytics/observability
/// outcomes the dataplane records.
#[derive(Debug, Clone)]
pub struct McpHandleResult {
    /// The JSON-RPC response body (serialized JSON). `None` for
    /// notifications (no response).
    pub response: Option<Value>,
    /// The session id associated with this request (the one used or
    /// the one created by `initialize`).
    pub session_id: Option<String>,
    /// The tool call outcome (for `tools/call` only; the dataplane
    /// records it in analytics).
    pub tool_call: Option<McpToolCallOutcome>,
    /// Whether a session was initialized (for the session counter
    /// metric).
    pub session_initialized: bool,
    /// Whether a session was closed (for the session counter metric).
    pub session_closed: bool,
}

impl CompiledMcp {
    /// Compile from the `ai.mcp` config block. Resolves each tool's
    /// upstream reference to a concrete URL using the gateway's
    /// upstreams. Returns None when a referenced upstream is missing
    /// or has no endpoints (a validate-vs-build race or an authoring
    /// error validation missed — the tool is silently dropped with a
    /// log).
    pub fn compile(config: &AiMcpConfig, gateway: &Gateway) -> Option<Self> {
        let sessions = config.sessions.as_ref();
        let sessions_ttl_secs = sessions
            .and_then(|s| s.ttl_secs)
            .unwrap_or(DEFAULT_TTL_SECS);
        let sessions_max_concurrent = sessions
            .and_then(|s| s.max_concurrent)
            .unwrap_or(DEFAULT_MAX_CONCURRENT);
        let path = config.path.clone().unwrap_or_else(|| "/mcp".to_string());

        let mut tools = BTreeMap::new();
        let mut consumer_tool_allowlists: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        // DW-113: compile per-consumer tool allowlists from the gateway
        // consumers. Only consumers with a non-empty tool_allowlist are
        // inserted; a consumer absent from the map has no restriction.
        for consumer in &gateway.consumers {
            if !consumer.tool_allowlist.is_empty() {
                consumer_tool_allowlists.insert(
                    consumer.name.clone(),
                    consumer.tool_allowlist.iter().cloned().collect(),
                );
            }
        }
        for (name, tool) in &config.tools {
            let Some(upstream) = gateway.upstreams.iter().find(|u| u.name == tool.upstream) else {
                tracing::warn!(
                    code = "mcp_tool_upstream_missing",
                    tool = %name,
                    upstream = %tool.upstream,
                    "mcp tool references unknown upstream; tool dropped"
                );
                continue;
            };
            let Some(endpoint) = upstream.endpoints.first() else {
                tracing::warn!(
                    code = "mcp_tool_upstream_no_endpoints",
                    tool = %name,
                    upstream = %tool.upstream,
                    "mcp tool upstream has no endpoints; tool dropped"
                );
                continue;
            };
            let scheme = match upstream.protocol {
                UpstreamProtocol::Http1 | UpstreamProtocol::Http2 => "http",
                UpstreamProtocol::Https => "https",
            };
            let tool_path = tool.path.clone().unwrap_or_else(|| "/".to_string());
            let upstream_url = format!(
                "{scheme}://{}:{}{}",
                endpoint.address, endpoint.port, tool_path
            );
            let method = tool
                .method
                .clone()
                .unwrap_or_else(|| "POST".to_string())
                .to_ascii_uppercase();
            let timeout_ms = tool.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
            tools.insert(
                name.clone(),
                CompiledMcpTool {
                    name: name.clone(),
                    description: tool.description.clone(),
                    input_schema: tool.input_schema.clone(),
                    upstream_url,
                    method,
                    timeout_ms,
                    authz: tool.authz.clone(),
                },
            );
        }
        Some(CompiledMcp {
            tools,
            sessions_ttl_secs,
            sessions_max_concurrent,
            path,
            consumer_tool_allowlists,
        })
    }

    /// The reserved HTTP path for the MCP endpoint.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The authz attachment for a tool (DW-087). Returns `None` when
    /// the tool has no authz attachment (any authenticated consumer
    /// may call it). The dataplane evaluates this attachment using
    /// the `security::authz` module (the `ai` domain may not import
    /// `security` — see `scripts/check_deps.py`).
    pub fn tool_authz(&self, name: &str) -> Option<&Authz> {
        self.tools.get(name).and_then(|t| t.authz.as_ref())
    }

    /// All tool names (DW-087), for the dataplane's authz-filtered
    /// `tools/list` response.
    pub fn tool_names(&self) -> impl Iterator<Item = &str> {
        self.tools.keys().map(|s| s.as_str())
    }

    /// Whether `consumer` is allowed to call `tool` (DW-113). A
    /// consumer NOT in the allowlist map has no restriction (may call
    /// any tool); a consumer IN the map may call only the tools in its
    /// set. The dataplane checks this BEFORE the authz attachment for
    /// `tools/call` and filters `tools/list` by it.
    pub fn consumer_allowed_tool(&self, consumer: &str, tool: &str) -> bool {
        match self.consumer_tool_allowlists.get(consumer) {
            None => true,
            Some(allowed) => allowed.contains(tool),
        }
    }

    /// Handle one JSON-RPC request. The `session_id` is extracted
    /// from the `Mcp-Session-Id` header (None for `initialize`).
    /// Returns the JSON-RPC response and optional analytics/observability
    /// outcomes.
    ///
    /// **Authz is NOT evaluated here** — the `ai` domain may not
    /// import `security`. The dataplane evaluates each tool's authz
    /// attachment BEFORE calling this method for `tools/call`, and
    /// filters the `tools/list` response after it returns.
    ///
    /// This method is async because `tools/call` makes an HTTP call
    /// to the upstream.
    pub async fn handle_request(
        &self,
        req: &JsonRpcRequest,
        session_id: Option<&str>,
        consumer: &str,
    ) -> McpHandleResult {
        // Notifications (no `id`) get no response.
        let is_notification = req.id.is_none();
        match req.method.as_str() {
            "initialize" => self.handle_initialize(req, consumer, is_notification),
            "notifications/initialized" => {
                // A notification: no response.
                McpHandleResult {
                    response: None,
                    session_id: session_id.map(|s| s.to_string()),
                    tool_call: None,
                    session_initialized: false,
                    session_closed: false,
                }
            }
            "tools/list" => self.handle_tools_list(req, is_notification),
            "tools/call" => {
                self.handle_tools_call(req, session_id, consumer, is_notification)
                    .await
            }
            "shutdown" => self.handle_shutdown(req, session_id, is_notification),
            _ => {
                let response = if is_notification {
                    None
                } else {
                    Some(json_rpc_error(
                        req.id.clone(),
                        error_code::METHOD_NOT_FOUND,
                        "method not found",
                    ))
                };
                McpHandleResult {
                    response,
                    session_id: session_id.map(|s| s.to_string()),
                    tool_call: None,
                    session_initialized: false,
                    session_closed: false,
                }
            }
        }
    }

    fn handle_initialize(
        &self,
        req: &JsonRpcRequest,
        consumer: &str,
        is_notification: bool,
    ) -> McpHandleResult {
        let session_id = generate_session_id(consumer);
        let result = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": env!("CARGO_PKG_VERSION")
            },
            "sessionId": session_id,
        });
        let response = if is_notification {
            None
        } else {
            Some(json_rpc_result(req.id.clone(), result))
        };
        McpHandleResult {
            response,
            session_id: Some(session_id),
            tool_call: None,
            session_initialized: true,
            session_closed: false,
        }
    }

    fn handle_tools_list(&self, req: &JsonRpcRequest, is_notification: bool) -> McpHandleResult {
        let mut tools_list = Vec::new();
        for tool in self.tools.values() {
            tools_list.push(json!({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema,
            }));
        }
        let result = json!({
            "tools": tools_list,
            "nextCursor": null,
        });
        let response = if is_notification {
            None
        } else {
            Some(json_rpc_result(req.id.clone(), result))
        };
        McpHandleResult {
            response,
            session_id: None,
            tool_call: None,
            session_initialized: false,
            session_closed: false,
        }
    }

    async fn handle_tools_call(
        &self,
        req: &JsonRpcRequest,
        session_id: Option<&str>,
        _consumer: &str,
        is_notification: bool,
    ) -> McpHandleResult {
        let started = std::time::Instant::now();
        let params = req.params.clone().unwrap_or(Value::Null);
        let tool_name = params
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);

        let Some(tool) = self.tools.get(&tool_name) else {
            let outcome = McpToolCallOutcome {
                tool_name: tool_name.clone(),
                allowed: true,
                duration_ms: started.elapsed().as_secs_f64() * 1000.0,
                error_code: Some("tool_not_found".to_string()),
                status: "error".to_string(),
            };
            let result = json!({
                "content": [{"type": "text", "text": format!("unknown tool: {tool_name}")}],
                "isError": true,
            });
            let response = if is_notification {
                None
            } else {
                Some(json_rpc_result(req.id.clone(), result))
            };
            return McpHandleResult {
                response,
                session_id: session_id.map(|s| s.to_string()),
                tool_call: Some(outcome),
                session_initialized: false,
                session_closed: false,
            };
        };

        // Proxy the call to the upstream.
        let call_result = call_upstream(tool, &arguments).await;
        let duration_ms = started.elapsed().as_secs_f64() * 1000.0;
        match call_result {
            Ok(text) => {
                let outcome = McpToolCallOutcome {
                    tool_name: tool_name.clone(),
                    allowed: true,
                    duration_ms,
                    error_code: None,
                    status: "success".to_string(),
                };
                let result = json!({
                    "content": [{"type": "text", "text": text}],
                    "isError": false,
                });
                let response = if is_notification {
                    None
                } else {
                    Some(json_rpc_result(req.id.clone(), result))
                };
                McpHandleResult {
                    response,
                    session_id: session_id.map(|s| s.to_string()),
                    tool_call: Some(outcome),
                    session_initialized: false,
                    session_closed: false,
                }
            }
            Err(err) => {
                let outcome = McpToolCallOutcome {
                    tool_name: tool_name.clone(),
                    allowed: true,
                    duration_ms,
                    error_code: Some("upstream_error".to_string()),
                    status: "error".to_string(),
                };
                let result = json!({
                    "content": [{"type": "text", "text": format!("upstream error: {err}")}],
                    "isError": true,
                });
                let response = if is_notification {
                    None
                } else {
                    Some(json_rpc_result(req.id.clone(), result))
                };
                McpHandleResult {
                    response,
                    session_id: session_id.map(|s| s.to_string()),
                    tool_call: Some(outcome),
                    session_initialized: false,
                    session_closed: false,
                }
            }
        }
    }

    fn handle_shutdown(
        &self,
        req: &JsonRpcRequest,
        session_id: Option<&str>,
        is_notification: bool,
    ) -> McpHandleResult {
        let response = if is_notification {
            None
        } else {
            Some(json_rpc_result(req.id.clone(), json!({})))
        };
        McpHandleResult {
            response,
            session_id: session_id.map(|s| s.to_string()),
            tool_call: None,
            session_initialized: false,
            session_closed: true,
        }
    }
}

/// Call the upstream HTTP endpoint for a tool (DW-087). Sends the
/// tool's arguments as the JSON request body and returns the
/// response body as text. Reuses the same `hyper_util` client
/// pattern as the DW-085 routing policy classifier.
async fn call_upstream(tool: &CompiledMcpTool, arguments: &Value) -> Result<String, String> {
    let body_bytes =
        serde_json::to_vec(arguments).map_err(|e| format!("encode request body: {e}"))?;
    let method = match tool.method.as_str() {
        "GET" => Method::GET,
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "PATCH" => Method::PATCH,
        "DELETE" => Method::DELETE,
        _ => Method::POST,
    };
    let req = Request::builder()
        .method(method)
        .uri(&tool.upstream_url)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .body(Full::new(Bytes::from(body_bytes)))
        .map_err(|e| format!("build upstream request: {e}"))?;
    let client = Client::builder(TokioExecutor::new()).build_http();
    let timeout = Duration::from_millis(tool.timeout_ms);
    let resp = tokio::time::timeout(timeout, client.request(req))
        .await
        .map_err(|_| format!("upstream timed out after {} ms", tool.timeout_ms))?
        .map_err(|e| format!("upstream request failed: {e}"))?;
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("read upstream response body: {e}"))?
        .to_bytes();
    if !status.is_success() {
        return Err(format!(
            "upstream returned {status}: {}",
            String::from_utf8_lossy(&bytes)
        ));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

// --- JSON-RPC 2.0 types --------------------------------------------------

/// One JSON-RPC 2.0 request (DW-087). `id` is None for notifications.
#[derive(Debug, Clone)]
pub struct JsonRpcRequest {
    /// The `jsonrpc` version string (must be "2.0").
    pub jsonrpc: String,
    /// The request id (number, string, or null). None for
    /// notifications (no response expected).
    pub id: Option<Value>,
    /// The method name.
    pub method: String,
    /// The optional params.
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    /// Parse a JSON-RPC request from a JSON value. Returns an error
    /// result Value when the input is not a valid JSON-RPC request.
    pub fn parse(body: &Value) -> Result<Self, Value> {
        let obj = body.as_object().ok_or_else(|| {
            json_rpc_error(
                None,
                error_code::INVALID_REQUEST,
                "request must be a JSON object",
            )
        })?;
        let jsonrpc = obj.get("jsonrpc").and_then(|v| v.as_str()).ok_or_else(|| {
            json_rpc_error(
                None,
                error_code::INVALID_REQUEST,
                "missing or invalid 'jsonrpc' field",
            )
        })?;
        if jsonrpc != "2.0" {
            return Err(json_rpc_error(
                None,
                error_code::INVALID_REQUEST,
                "unsupported jsonrpc version (must be '2.0')",
            ));
        }
        let method = obj.get("method").and_then(|v| v.as_str()).ok_or_else(|| {
            json_rpc_error(
                None,
                error_code::INVALID_REQUEST,
                "missing or invalid 'method' field",
            )
        })?;
        let id = obj.get("id").cloned();
        let params = obj.get("params").cloned();
        Ok(JsonRpcRequest {
            jsonrpc: jsonrpc.to_string(),
            id,
            method: method.to_string(),
            params,
        })
    }
}

/// Build a JSON-RPC success response (public, for the dataplane's
/// authz-filtered tools/list and denied tools/call paths).
pub fn json_rpc_result_pub(id: Option<Value>, result: Value) -> Value {
    json_rpc_result(id, result)
}

/// Build a JSON-RPC success response.
fn json_rpc_result(id: Option<Value>, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "result": result,
    })
}

/// Build a JSON-RPC error response.
fn json_rpc_error(id: Option<Value>, code: i32, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": {
            "code": code,
            "message": message,
        },
    })
}

/// Build a JSON-RPC parse error response (no id available).
pub fn parse_error_response() -> Value {
    json_rpc_error(None, error_code::PARSE_ERROR, "parse error")
}

/// Build a JSON-RPC error response (public, for the dataplane's
/// session-management error paths).
pub fn json_rpc_error_pub(id: Option<Value>, code: i32, message: &str) -> Value {
    json_rpc_error(id, code, message)
}
