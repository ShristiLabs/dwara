# Agent-operable administration

Dwara ships an [MCP](https://modelcontextprotocol.io/) (Model Context
Protocol) server implementation for AI agents that inspect and operate
the gateway: a typed tool surface over the admin data model, per-agent
permissions (RBAC), argument validation against each tool's JSON
Schema, and typed error responses.

::: info Status
The MCP server is a compile-time feature pack (`mcp`, default OFF; see
[Editions](./editions#compile-time-feature-packs)) and is not included
in the published OSS binaries. It is currently a library surface in
`dwara-core`: the server, protocol types, standard tools, and RBAC
checks are complete and test-covered, but no transport is mounted yet
-- there is no `/mcp` endpoint on the admin listener and no stdio
bridge. An embedding (or a future dwara release) constructs the
`McpServer`, connects it to a transport, and supplies a `ToolHandler`
that performs the actual operations. Until a transport ships, this
page documents the tool surface such an integration exposes.
:::

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
[Editions](./editions) for how feature packs are built and licensed.
