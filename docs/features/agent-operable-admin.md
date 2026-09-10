# Agent-Operable Administration via MCP (DW-112)

## Overview

dwara exposes its admin API as an MCP (Model Context Protocol) server,
allowing AI agents to operate the gateway. Tools are RBAC-scoped: each
tool requires a permission, and the MCP server checks the agent's
permissions before executing.

## Enabling

Build with the `mcp` feature:

```sh
cargo build
```

## MCP tools

The MCP server exposes the following tools:

| Tool | Permission | Description |
|------|-----------|-------------|
| `list_routes` | Read | List all routes in the current config |
| `get_route` | Read | Get a single route by name |
| `create_route` | Write | Create a new route |
| `update_route` | Write | Update an existing route |
| `delete_route` | Write | Delete a route |
| `list_services` | Read | List all services |
| `get_stats` | Read | Get gateway stats |
| `get_health` | Read | Get gateway health |
| `get_config` | Read | Dump the current config |
| `purge_cache` | Admin | Purge the cache for a route or all routes |

## RBAC

Tool access is RBAC-scoped. Each agent has a set of permissions:

- `Read`: list, get, stats, health, config dump
- `Write`: create, update, delete
- `Admin`: purge cache, reload config

```rust
use dwara_core::mcp::{AgentIdentity, McpServer, MockToolHandler, ToolCallRequest};

let server = McpServer::new();
let agent = AgentIdentity::read_write("my-agent");
let handler = MockToolHandler::new();

// Create a route (Write permission -- succeeds).
let request = ToolCallRequest {
    name: "create_route".to_string(),
    arguments: serde_json::json!({
        "name": "api-v2",
        "service": "backend-v2",
        "path": "/api/v2"
    }),
};
let response = server.execute(&request, &agent, &handler);
assert!(response.success);

// Purge cache (Admin permission -- denied).
let request = ToolCallRequest {
    name: "purge_cache".to_string(),
    arguments: serde_json::json!({"route": "all"}),
};
let response = server.execute(&request, &agent, &handler);
assert!(!response.success);
assert_eq!(response.error_code, Some("permission_denied".to_string()));
```

## Agent identity

```rust
use dwara_core::mcp::AgentIdentity;

// Read-only agent (can list/get, cannot create/delete/purge).
let reader = AgentIdentity::read_only("reader");

// Read-write agent (can create/update/delete, cannot purge).
let writer = AgentIdentity::read_write("writer");

// Admin agent (can do everything).
let admin = AgentIdentity::admin("admin");
```

## API

### McpServer

The MCP server: holds tool definitions and executes tool calls with
RBAC checks.

### ToolDefinition

A tool definition: name, description, input JSON Schema, required
permission.

### ToolCallRequest / ToolCallResponse

MCP protocol types for tool calls.

### Permission

`Read`, `Write`, `Admin`.

### AgentIdentity

An agent's identity: name + permissions.

### ToolHandler

A trait the caller implements to actually execute tools (calling the
admin API, reading config, etc.).

## M10 additions (AI-11, #200)

The admin MCP server gained transport adapters for SSE and stdio in
addition to the existing HTTP JSON-RPC transport. The `McpTransport`
enum (`Http`, `Sse`, `Stdio`) selects the transport at serve time.
SSE encoding helpers (`encode_sse_response`, `encode_sse_error`)
format JSON-RPC responses as SSE frames (`data: <payload>\n\n`) for
streaming responses over HTTP. Stdio transport uses newline-delimited
JSON on stdin/stdout for local agent integrations.

The MCP gateway (DW-087, the AI-side MCP router) gained four new
JSON-RPC primitives: `resources/list`, `resources/read`,
`prompts/list`, and `prompts/get`. Resources and prompts are
configured statically under `ai.mcp.resources` and `ai.mcp.prompts`
and served inline (no upstream proxy). Prompt templates support
`{{arg}}` placeholder substitution from request arguments. See the
[AI provider adapters](./ai-provider-adapters.md#ai-11-200--mcp-transport-and-primitive-breadth--admin-toolhandler)
page for the implementation details.

Code: `crates/dwara-core/src/mcp/mod.rs` (transport adapters),
`crates/dwara-core/src/ai/mcp.rs` (gateway primitives),
`crates/dwara-core/src/config/ai.rs` (resource/prompt config types).

## Feature gate

MCP is compiled into the OSS build. The module is
not compiled.
