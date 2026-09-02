# A2A protocol scaffold (DW-114)

> Implements issue DW-114 (M4, `edition/oss`, effort M) over the AI
> gateway surface. Sources:
> `crates/dwara-core/src/ai/a2a.rs` (the A2A provider adapter, the
> Agent Card parser, the stubbed task lifecycle, the session model,
> the compiled A2A surface -- its module docs carry the full contract),
> the config schema in `config/ai.rs` (`A2aConfig`, `A2aAgent`,
> `A2aAgentCard`, `A2aSessions`), validation in `snapshot/mod.rs`.
> Tests: `crates/dwara-core/tests/a2a.rs` (Agent Card parsing, the
> adapter's canonical <-> A2A JSON translation, the stubbed task
> lifecycle, config validation, and the feature-gate behavior). The
> white-box unit tests in `src/ai/a2a.rs` cover the private translation
> paths not exercised through a public caller. Operator docs:
> [docs-site AI gateway guide](../../docs-site/guide/ai-gateway.md).

The Agent-to-Agent (A2A) protocol is an emerging standard for
inter-agent communication. DW-114 scaffolds the gateway's A2A surface
behind the `a2a` cargo feature: the spec is NOT yet frozen, so the
task lifecycle is STUBBED (every task-state transition returns an
`A2AStub` error explaining that the spec is not frozen), while the
adapter translation, Agent Card parsing, session model, and config
schema are fully implemented. This keeps the call-site shape stable so
the dataplane path compiles unchanged with or without the feature, and
the actual task wiring lands when the spec freezes. No new
dependencies are introduced (the scaffold is hand-rolled, the same
locked M4 decision as MCP).

## The A2A provider adapter

`A2AAdapter` implements `ProviderAdapter` -- a pure translator, like
the OpenAI/Anthropic/Gemini adapters and the MCP gateway. It holds no
state and opens no connections; the transport is the agent's named
upstream, driven from `dataplane::ai_proxy`.

`build_request` translates a canonical `ChatRequest` into an A2A
task-submit JSON body: the conversation is folded into the task's
`message` field (the latest user message becomes the task message;
prior messages are preserved under `history`). The body is a JSON-RPC
2.0 envelope (`{"jsonrpc":"2.0","method":"tasks/submit","params":...}`)
with the model, message, history, and optional sampling parameters
(temperature, top_p, max_tokens, stop, stream).

`parse_response` parses an A2A task response back into the canonical
`ChatResponse`: it tolerates both the JSON-RPC result envelope
(`result.message`) and a bare `message` field. The task `state`
(`completed`, `failed`, `canceled`) maps to a `FinishReason`.
`parse_error` extracts the JSON-RPC 2.0 error envelope
(`{"error":{"code","message","data"}}`). `parse_stream_event` handles
SSE-ish streaming events (reusing the shared `ai::sse` framer): each
event carries a `delta` with content fragments and an optional terminal
`state`, plus a `usage` object.

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

## The stubbed task lifecycle

`TaskLifecycle` is the task state machine
(`Submitted`, `Working`, `Completed`, `Failed`, `Canceled`). The wire
names round-trip through `as_str` and `parse_state` (unknown states are
tolerated, not rejected, since the spec is not frozen). Every
transition (`submit`, `get_status`, `cancel`) returns an `A2AStub` error
so callers fail loudly and attributably rather than silently no-op'ing.
`A2ASession` mirrors MCP's session model (a session id, TTL, and
max-concurrent cap) and its task methods (`submit_task`,
`get_task_status`, `cancel_task`) are likewise stubbed.
`handle_a2a_request` -- the seam the dataplane calls for an A2A-routed
alias -- is stubbed today, returning `A2AStub` so the caller fails
loudly. The actual wiring lands when the spec freezes.

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
config schema is always present regardless of the `a2a` cargo feature,
so configs round-trip across builds with and without the feature; when
the feature is off the block is accepted but inert (validation warns,
`CompiledA2a::compile` returns `None`, no A2A providers are wired).

The [AI provider adapters](./ai-provider-adapters.md) page covers the
`ProviderAdapter` trait this adapter implements; the
[extension points](./extension-points.md) page covers the feature-gate
pattern.
