# Agent-operable administration

Dwara ships an [MCP](https://modelcontextprotocol.io/) (Model Context
Protocol) server implementation for AI agents that inspect and operate
the gateway: a typed tool surface over the admin data model, per-agent
permissions (RBAC), argument validation against each tool's JSON
Schema, and typed error responses.

::: info Status
The MCP server is a compile-time capability (`mcp`, default OFF; see
[Editions](./editions#compile-time-feature-packs)) and is not included
in the published OSS binaries. It is currently a library surface in
`dwara-core`: the server, protocol types, standard tools, and RBAC
checks are complete and test-covered. Transport adapters for HTTP
JSON-RPC, SSE (server-sent events), and stdio are available so an
embedding (or a future Dwara release) can mount the `McpServer` on
the admin listener or a local stdio bridge. The `McpTransport` enum
selects the transport; SSE helpers (`encode_sse_response`,
`encode_sse_error`) format JSON-RPC responses as SSE frames. Until a
transport is mounted by an embedding, this page documents the tool
surface such an integration exposes.
:::

## When to use this

- You operate the gateway with AI agents (or want to) and need a
  typed, permissioned tool surface instead of agents issuing raw
  admin-API calls.
- An embedding or automation layer mounts the MCP server and you need
  the tool inventory, argument schemas, and RBAC model it exposes.

## The tool surface

`McpServer::new()` registers ten standard tools:

| Tool | Permission | Description |
| --- | --- | --- |
| `list_routes` | `read` | List all routes in the current config. |
| `get_route` | `read` | Get a single route's full config. |
| `list_services` | `read` | List all services. |
| `get_stats` | `read` | Runtime stats (requests, errors, latency). |
| `get_health` | `read` | Gateway health. |
| `get_config` | `read` | The current gateway config. |
| `create_route` | `write` | Create a route. |
| `update_route` | `write` | Update a route. |
| `delete_route` | `write` | Delete a route. |
| `purge_cache` | `admin` | Purge the response cache. |

## Agent identity and permissions

Every tool declares the permission it requires. Permissions are
`read`, `write`, and `admin`, and an agent identity (`AgentIdentity`)
is a name plus a set of permissions:

| Constructor | Permissions | Can call |
| --- | --- | --- |
| `AgentIdentity::read_only(name)` | `read` | read tools only |
| `AgentIdentity::read_write(name)` | `read`, `write` | read + write tools |
| `AgentIdentity::admin(name)` | `read`, `write`, `admin` | all tools |

`McpServer::list_tools_for(agent)` returns only the tools the agent
may call, so an agent's tool listing never advertises operations it
cannot execute.

## Tool calls

Tool calls follow the MCP `tools/call` shape:

```json
{
  "name": "list_routes",
  "arguments": {}
}
```

`McpServer::execute(request, agent, handler)` runs the pure RBAC and
dispatch step:

1. Unknown tool name -> `{"success": false, "error_code": "unknown_tool"}`.
2. Agent lacks the tool's required permission ->
   `error_code: "permission_denied"` (the error names the tool, the
   required permission, and the agent's permissions).
3. Arguments fail the tool's JSON Schema ->
   `error_code: "invalid_arguments"`.
4. Otherwise the call is delegated to the caller-supplied `ToolHandler`,
   which executes the operation (calling the admin API, reading
   config) and returns a `ToolCallResponse`.

A failing tool call returns a typed error response; the server itself
keeps serving subsequent calls. All tool inputs and outputs are JSON.

## Enabling

Build the library with the feature on (for embedding or running the
test suites):

```sh
cargo build -p dwara-core --features mcp
```

See [Admin API](./admin-api) for the underlying operator surface and
[Editions](./editions) for how capabilities are built and licensed.

## Runnable demo

Run this feature against a live gateway: [`demos/09-operations/`](https://github.com/shristilabs/dwara/tree/main/demos/09-operations) (test
script: `test-13-agent-operable-admin.sh`) in the repository.
The demo documents the current limitations alongside what
runs today; see its README.
