# A2A protocol (DW-114, AI-12 #252)

> Implements issue DW-114 (M4, `edition/oss`, effort M) and AI-12
> (#252, M12, the v0.3 JSON-RPC wire format) over the AI gateway
> surface. Sources:
> `crates/dwara-core/src/ai/a2a.rs` (the A2A provider adapter, the
> Agent Card parser, the task lifecycle state machine, the session
> model, the compiled A2A surface -- its module docs carry the full
> contract), the config schema in `config/ai.rs` (`A2aConfig`,
> `A2aAgent`, `A2aAgentCard`, `A2aSessions`), validation in
> `snapshot/mod.rs`. Tests: `crates/dwara-core/tests/a2a.rs` (Agent
> Card parsing, the adapter's canonical <-> A2A v0.3 JSON translation,
> the task lifecycle state machine, config validation, and the
> feature-gate behavior). Operator docs:
> [docs-site AI gateway guide](../../docs-site/guide/ai-gateway.md).

The Agent-to-Agent (A2A) protocol is an emerging standard for
inter-agent communication. DW-114 scaffolds the gateway's A2A surface
compiled into the OSS build; AI-12 (#252) upgrades the adapter to the
v0.3 JSON-RPC wire format (`message/send`, `message/stream`, the
`parts[]`/`kind`-discriminated message shape, and Task/Message result
detection). The task lifecycle state machine is fully implemented
(legal transitions validated, illegal transitions return an
`A2AError`). No new dependencies are introduced (the implementation is
hand-rolled, the same locked M4 decision as MCP).

## The A2A provider adapter

`A2AAdapter` implements `ProviderAdapter` -- a pure translator, like
the OpenAI/Anthropic/Gemini adapters and the MCP gateway. It holds no
state and opens no connections; the transport is the agent's named
upstream, driven from `dataplane::ai_proxy`.

### build_request (v0.3, #252)

Translates a canonical `ChatRequest` into an A2A v0.3 JSON-RPC
`message/send` (or `message/stream` for streaming) body. The latest
user message is folded into `params.message.parts[]` using the
`kind`-discriminated part shape:

- `text` parts carry the text content.
- `file` parts carry inline bytes (base64) or a URI.
- `data` parts carry arbitrary JSON (serialized as text).

System messages are folded as a text preamble (A2A has no system
role). The message carries a generated `messageId` and `role: "user"`.
Prior messages are NOT carried inline -- A2A uses `contextId` for
multi-turn correlation, not an inline history. The JSON-RPC envelope
is `{"jsonrpc":"2.0","id":"...","method":"message/send","params":...}`.

### parse_response (v0.3, #252)

Detects whether the JSON-RPC `result` is a `Message` (has `parts` or
`kind: "message"`) or a `Task` (has `status` or `kind: "task"`). For
Messages, text is extracted from `parts[]` (text, file, data kinds).
For Tasks, text is extracted from `status.message.parts` first, then
`artifacts[].parts`. The task state maps to `FinishReason`:
`completed` -> `Stop`, `failed` -> `Other("failed")`, `canceled` ->
`Other("canceled")`, `rejected` -> `Other("rejected")`.

Backward compat: the adapter still accepts the older `content`/`type`
message shape and the `result.message` wrapper for agents that have
not migrated to v0.3.

### parse_error

Extracts the JSON-RPC 2.0 error envelope
(`{"error":{"code","message","data"}}`).

### parse_stream_event (v0.3, #252)

Handles three stream event shapes:

- **Message** (has `parts`): emits a content delta.
- **TaskStatusUpdateEvent** (has `status`): emits a content delta from
  `status.message` (if present) and a finish delta when the state is
  terminal (`completed`, `failed`, `canceled`, `rejected`).
- **TaskArtifactUpdateEvent** (has `artifact`): emits a content delta
  from `artifact.parts`.

## Agent Card parsing

The `AgentCard` is the JSON-LD-ish discovery doc an A2A agent
publishes to declare its identity, capabilities, and authentication.
`AgentCardParser` parses it from an inline JSON value
(`parse_inline`) or a file path (`parse_path`), or from a config
source that carries either (`parse_source`). Required fields are
`name` and `url`; missing either is a parse error. Optional fields
(`description`, `version`, `capabilities`, `authentication`) are
preserved verbatim -- the spec is not frozen, so unknown fields are
tolerated and the free-form shapes are kept as raw `serde_json::Value`.
The gateway does not act on the `authentication` declaration today
(transport auth comes from the agent's upstream config).

## The task lifecycle state machine

`TaskLifecycle` is the task state machine
(`Submitted`, `Working`, `Completed`, `Failed`, `Canceled`). The wire
names round-trip through `as_str` and `parse_state` (unknown states
are tolerated, not rejected, since the spec is not frozen). Legal
transitions are validated by `TaskStateMachine`:
`Submitted -> Working`, `Submitted -> Failed`, `Submitted -> Canceled`,
`Working -> Completed`, `Working -> Failed`, `Working -> Canceled`.
Illegal transitions return an `A2AError` naming the attempted and
target states. `A2ASession` mirrors MCP's session model (a session id,
TTL, and max-concurrent cap) and owns a `TaskStateMachine` per
session. `handle_a2a_request` routes an A2A call through the existing
`dataplane::ai_proxy` path (the transport is the agent's named
upstream, exactly like a regular provider).

## Compiled A2A and the alias table

`CompiledA2a::compile` builds the compiled A2A surface at `AiRuntime`
compile time from the `ai.a2a` config block. It returns `None` when the
block is absent, `enabled` is false, or the `a2a` feature is off (the
block is inert in all those cases). Each agent's Agent Card is parsed
best-effort: a parse failure logs a warning and the agent compiles
without a card (the loud, attributable failure is the validation issue,
not a compile abort). `a2a_providers` returns the agent entries that
should appear as providers in the model alias table -- each entry is
`(name, upstream)`, and the `AiRuntime` compile path inserts them into
the provider pool with `kind: a2a`, so a model alias can route to an
agent by name.

## Configuration and validation

```yaml
ai:
  a2a:
    enabled: true
    agents:
      - name: research-agent
        url: https://agent.example.com
        upstream: agent-pool
        card:
          inline:
            name: research-agent
            url: https://agent.example.com
            capabilities: { streaming: true }
            authentication: { schemes: [bearer] }
    sessions:
      ttl_secs: 3600
      max_concurrent: 1000
```

`A2aConfig` is the top-level block: `enabled` is the master switch
(default false, allowing staged rollout), `agents` is the agent pool,
and `sessions` is the optional session policy (defaults: TTL 3600s,
max 1000 concurrent, mirroring MCP). Each `A2aAgent` names an upstream
(the transport) and an optional `A2aAgentCard` (inline JSON or a file
path).

Validation (`snapshot/mod.rs`) rejects: empty or duplicate agent names,
non-http(s) URLs, references to unknown upstreams, an inline card that
is not a JSON object, a card with neither inline nor path set, a
session `ttl_secs` of 0, and a session `max_concurrent` of 0. The
config schema is always present regardless of the A2A protocol,
so configs round-trip across builds with and without the feature; when
the feature is off the block is accepted but inert (validation warns,
`CompiledA2a::compile` returns `None`, no A2A providers are wired).

The [AI provider adapters](./ai-provider-adapters.md) page covers the
`ProviderAdapter` trait this adapter implements; the
[extension points](./extension-points.md) page covers the feature-gate
pattern.
