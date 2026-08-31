# Agent-operable administration

Dwara exposes an [MCP](https://modelcontextprotocol.io/) (Model
Context Protocol) server on the admin listener, allowing AI agents
and LLM-powered tools to inspect and operate the gateway through a
typed, permissioned tool interface.

## When to use this

Use the MCP server when:

- You want an AI agent (e.g. a coding assistant or ops bot) to
  inspect gateway state as part of a debugging workflow.
- You want to automate gateway operations (create routes, purge
  cache, check health) from an LLM-powered tool.
- You want a structured, typed interface for programmatic access
  (instead of raw HTTP calls to the admin API).

## Enabling

The MCP server is served from the admin listener. Enable the admin
listener with mTLS (see [Admin API](./admin-api)):

```yaml
admin:
  bind: 127.0.0.1:2019
  tls:
    cert_file: /etc/dwara/admin.crt.pem
    key_file: /etc/dwara/admin.key.pem
    client_ca_file: /etc/dwara/admin-clients.ca.pem
```

The MCP endpoint is at `/mcp` on the admin listener:

```
https://127.0.0.1:2019/mcp
```

## Agent identity and permissions

Each agent is identified by its mTLS client certificate subject and
assigned a permission level:

| Permission | Description |
|---|---|
| `read` | Can call read-only tools (list routes, get health, view config). |
| `read_write` | Can call read and write tools (create/modify routes, services, consumers). |
| `admin` | Can call all tools including admin tools (purge cache, delete workspace, reload config). |

The permission level is determined by the agent's mTLS certificate
subject, mapped via the admin API's RBAC (see [Workspaces, RBAC, and
audit](./workspaces-rbac-audit)).

## Tools

The MCP server exposes the following tools:

### Read tools (permission: `read`)

| Tool | Description |
|---|---|
| `list_routes` | List all routes in a workspace. |
| `get_route` | Get a single route's full config. |
| `list_services` | List all services. |
| `list_upstreams` | List all upstreams with endpoints and health. |
| `get_health` | Get health state for an upstream. |
| `get_config` | Get the current gateway config. |
| `get_stats` | Get runtime stats (requests, errors, latency). |
| `list_consumers` | List all consumers. |

### Write tools (permission: `read_write`)

| Tool | Description |
|---|---|
| `create_route` | Create a new route. |
| `update_route` | Update an existing route. |
| `delete_route` | Delete a route. |
| `create_service` | Create a new service. |
| `create_consumer` | Create a new consumer. |
| `create_credential` | Create a credential for a consumer. |

### Admin tools (permission: `admin`)

| Tool | Description |
|---|---|
| `purge_cache` | Purge the response cache. |
| `reload_config` | Trigger a config reload. |
| `delete_workspace` | Delete a workspace. |

## Tool call format

Tools are called via the MCP protocol (JSON-RPC over HTTP). Each
tool call includes:

```json
{
  "method": "tools/call",
  "params": {
    "name": "list_routes",
    "arguments": {
      "workspace": "default"
    }
  }
}
```

The server validates the arguments against the tool's JSON Schema
before executing. Invalid arguments return a typed error.

## Audit

All MCP tool calls are recorded in the audit log (see [Workspaces,
RBAC, and audit](./workspaces-rbac-audit)), with the agent's
identity as the principal. This provides a full trail of what each
agent did and when.

## Failure isolation

A tool call that fails (invalid arguments, permission denied,
internal error) returns a typed error response. The MCP server
itself is not affected -- subsequent tool calls continue to work.
