# MCP gateway

The MCP gateway turns dwara into an MCP (Model Context Protocol) server
and router. Configured tools are exposed over JSON-RPC 2.0 on a
reserved HTTP path (default `/mcp`); the gateway authenticates every
request, authorizes per-tool access, proxies tool calls to upstream
HTTP endpoints, manages agent sessions in the state store, and
correlates tool calls in analytics.

The gateway is a ROUTER, not a tool executor: each tool names an
upstream HTTP endpoint, and `tools/call` proxies the call (POST JSON
body, get JSON response). The upstream's transport -- endpoint set,
TLS trust, connection pooling, timeouts -- is the same machinery every
other upstream gets.

## When to use this

Use the MCP gateway when:

- You want to expose internal HTTP services as MCP tools that AI
  agents can discover and call through a single JSON-RPC endpoint.
- You want centralized authentication and per-tool authorization for
  tool access, reusing the gateway's existing authn/authz modules.
- You want agent sessions managed and correlated in analytics
  alongside your other AI traffic.

## Configuration

The MCP gateway is configured under the `ai.mcp` block:

```yaml
ai:
  mcp:
    path: /mcp
    sessions:
      ttl_secs: 3600
      max_concurrent: 1000
    tools:
      search-docs:
        description: Search the internal documentation
        upstream: docs-api
        path: /search
        method: POST
        timeout_ms: 30000
        input_schema:
          type: object
          properties:
            query:
              type: string
          required: [query]
        authz:
          groups: [internal]
```

| Field | Default | Description |
|---|---|---|
| `path` | `/mcp` | The reserved HTTP path for the MCP JSON-RPC endpoint. Must start with `/`. Shadows any configured route. |
| `sessions.ttl_secs` | `3600` | Session TTL in seconds. Expired sessions are cleaned up and rejected on use. |
| `sessions.max_concurrent` | `1000` | Maximum concurrent active sessions. New `initialize` requests beyond this limit are rejected. |
| `tools` | (empty) | The tool table, keyed by tool name. |

## Tool configuration

Each tool names an upstream that carries the transport and a path on
that upstream. The tool's arguments are sent as the JSON request body,
and the upstream's response body becomes the tool's output.

| Field | Default | Description |
|---|---|---|
| `description` | (required) | Human-readable description returned to the client in `tools/list`. |
| `upstream` | (required) | Name of the `upstreams[]` entry that carries this tool's transport. |
| `path` | `/` | The path on the upstream (appended to the endpoint's `address:port`). |
| `method` | `POST` | The HTTP method for the upstream call (GET, POST, PUT, PATCH, DELETE). |
| `input_schema` | (required) | The JSON Schema for the tool's arguments (returned as `inputSchema` in `tools/list`). |
| `authz` | (none) | Optional per-tool authorization. When present, the tool is only callable by consumers satisfying the authz rules. |
| `timeout_ms` | `30000` | Upstream call timeout in milliseconds. |

## Session management

The MCP protocol is JSON-RPC 2.0 over HTTP. The lifecycle:

1. `initialize` -- the client sends its protocol version and client
   info; the server creates a session, responds with its protocol
   version, capabilities, and server info, and returns the session id
   in the `Mcp-Session-Id` response header.
2. `notifications/initialized` -- the client acknowledges (a
   notification: no response).
3. `tools/list` -- the server returns the tool definitions (filtered
   by the caller's authz).
4. `tools/call` -- the server authorizes, proxies the call to the
   upstream, and returns the result.
5. `shutdown` -- the server deletes the session.

Sessions are state-store backed (the `mcp_sessions` table) when
`DWARA_STATE_DB` is set. Without a state store, sessions are stateless
(the session id is still returned but not persisted). Session ids are
128-bit hex handles (`mcp-<hex>`), unique per process. The TTL
(default 1 hour) controls expiry; expired sessions are rejected on use
and cleaned up periodically. The max-concurrent limit (default 1000)
rejects new `initialize` requests when the active session count is at
the cap.

## Authentication and authorization

Every MCP request runs through the same `security/authn` module as the
proxy path: API key, Basic, JWT via JWKS, mTLS client-cert, or HMAC
request signing. An unauthenticated request gets 401.

Per-tool authorization uses the same `security/authz` module as the
proxy path. A tool with an `authz` attachment is only callable by
consumers satisfying the rules (consumer/group/scope/claim rules
against the authenticated identity, IP ACLs against the effective
client IP). A tool without an `authz` attachment is open to any
authenticated consumer. The `tools/list` response is filtered to only
show tools the caller is allowed to invoke.

## Analytics

Every `tools/call` is recorded in the `mcp_tool_calls` analytics
table with the session id, consumer, tool name, authorization result,
duration, error code, and status (`success`, `error`, or `denied`).
The session id correlates calls within one agent session. Records are
written fire-and-forget (never blocks the request path).

## Admin API endpoints

- `GET /mcp/sessions` -- list active (non-expired) MCP sessions from
  the state store, ordered by creation time descending.
- `DELETE /mcp/sessions/:id` -- teardown an MCP session by id
  (idempotent: returns 200 regardless of whether a row was deleted).
- `GET /mcp/tools` -- list configured MCP tools from the current
  snapshot's `ai.mcp` config block.
- `GET /mcp/calls?from_ms=...&to_ms=...&session_id=...&consumer=...&tool_name=...`
  -- query MCP tool call analytics. `from_ms` and `to_ms` are
  required; `session_id`, `consumer`, `tool_name`, and `limit` are
  optional filters.

## Metrics

- `dwara_mcp_sessions_total{state}` -- MCP session lifecycle
  transitions. `state` is `initialized` (a new session
  created by `initialize`), `closed` (a session deleted by
  `shutdown`), or `expired` (a session reaped by the TTL cleanup).
- `dwara_mcp_tool_calls_total{tool,status}` -- MCP tool calls.
  `tool` is the config-declared tool name (config-bounded);
  `status` is `success`, `error`, or `denied`. No consumer label
  (cardinality rule).
- `dwara_mcp_tool_duration_seconds{tool}` -- MCP tool call duration
  (authz check through upstream response), by tool (config-bounded
  label).

## See also

- [AI gateway](./ai-gateway)
