# MCP gateway and A2A agents

## MCP: Dwara as an MCP server

The `ai.mcp` block turns the gateway into a Model Context Protocol server:
it speaks JSON-RPC 2.0 on a reserved path (default `/mcp`) and translates
`tools/call` into HTTP requests to upstreams. The full policy chain
(authn/authz/rate limits/AI budgets) applies to tool calls.

```yaml
ai:
  mcp:
    path: /mcp                       # reserved: shadows any route on that path
    tools:
      search_docs:
        description: Search the documentation
        upstream: docs-upstream      # transport for tool calls
        path: /search                # default "/"
        method: POST                 # GET|PUT|PATCH|DELETE also allowed
        timeout_ms: 30000
        input_schema:                # JSON Schema, required
          type: object
          properties: { query: { type: string } }
          required: [query]
        # authz: ...                 # per-tool authorization rules
    resources:                       # static resources (resources/list|read)
      - uri: docs://index
        name: index
        description: Doc index
        mime_type: text/markdown
        content: ...
    prompts:                         # prompt templates ({{arg}} placeholders)
      - name: summarize
        template: "Summarize: {{text}}"
        arguments: [text]
    sessions:
      ttl_secs: 3600
      max_concurrent: 1000
```

Client flow: `initialize` -> session id in the `Mcp-Session-Id` response
header (`mcp-<128-bit hex>`) -> `notifications/initialized` -> `tools/list`
(filtered by the caller's authorization) -> `tools/call` (proxied to
`upstream` + `path`) -> `shutdown`. Sessions persist in the state store
when `DWARA_STATE_DB` is set; otherwise stateless.

**Agent guardrails**: consumers of `type: agent` can carry
`tool_allowlist: [search_docs, get_status]` - `tools/list` is filtered to
it and a disallowed call fails with `tool_not_in_agent_allowlist`. Every
allowlisted name must exist in `ai.mcp.tools` (validation error otherwise),
and an allowlist without an `ai.mcp` block is rejected.

Admin/observability: `GET/DELETE /mcp/sessions[/:id]`, `GET /mcp/tools`,
`GET /mcp/calls?from_ms&to_ms&session_id&consumer&tool_name&limit`.

## A2A: agent-to-agent providers

`ai.a2a` registers remote A2A agents as callable providers. An agent then
appears in `ai.providers` with `kind: a2a` + the `agent: <name>` field, and
aliases can route to it like any provider (chat requests become A2A task
submissions; responses map back to chat-completion shape with content,
`finish_reason`, usage; the full policy chain applies).

```yaml
ai:
  a2a:
    enabled: true
    agents:
      - name: research-agent
        url: https://agents.internal:8443/a2a
        card: /etc/dwara/cards/research.json   # file path or inline JSON
    sessions:
      ttl_secs: 3600
      max_concurrent: 1000
```

Status notes: task cancellation/status negotiation for long-running tasks
is stubbed; the gateway does not serve `/.well-known/agent-card.json`.
A2A is compiled into every build (no cargo feature) - an agent alias
routes like any provider.

## When to use which

| Need | Reach for |
| --- | --- |
| Expose internal HTTP services as MCP tools to AI clients | `ai.mcp` + `tools` |
| Constrain an automated agent's tool blast radius | consumer `type: agent` + `tool_allowlist` |
| Route chat traffic to a remote A2A-speaking agent | `ai.a2a` + `kind: a2a` provider |
