# Agent-to-Agent (A2A) protocol

Dwara can act as a gateway for the [Agent-to-Agent (A2A) protocol](https://en.wikipedia.org/wiki/Agent-to-agent_protocol),
an emerging standard for machine-to-machine communication between
autonomous AI agents. In the A2A model, an agent publishes an Agent
Card describing its identity and capabilities, and other agents
submit tasks to it as JSON-RPC messages over HTTP. In Dwara, each
remote A2A agent is registered as an AI provider: a chat request
routed to it is translated into an A2A task-submit call, so clients
keep speaking the OpenAI-shaped chat API while the peer speaks A2A.

**Status: partial.** The provider adapter (routing, task-submit
translation, Agent Card parsing) is wired; the A2A task lifecycle --
long-running task negotiation, cancellation, and status endpoints --
is stubbed pending spec freeze. The block is feature-gated behind the
`a2a` cargo feature: without it, config is accepted but inert
(validation warns). There is no `/.well-known/agent-card.json`
discovery endpoint in this build.

## When to use this

Register A2A agents when a fleet of agents must call each other
through a controlled boundary -- one ingress with the gateway's
authn/authz, rate limits, token budgets, and analytics applied to
agent-to-agent calls, instead of agents dialing each other directly.

If your agents communicate over a single fixed channel with no policy
boundary, an A2A hop adds latency for no benefit.

## Configuration

A2A agents live under `ai.a2a`. Each agent names a base URL (the A2A
endpoint) and an Agent Card (a file path or inline JSON, parsed at
compile time). The agent then appears as a provider of kind `a2a`,
and a model alias routes to it by name:

```yaml
ai:
  a2a:
    enabled: true
    agents:
      - name: mock-agent
        url: http://agent-upstream:8080
        card:
          name: mock-agent
          description: demo A2A agent
          version: "1.0"
  providers:
    - name: agent-pool
      kind: a2a
      agent: mock-agent
  models:
    - alias: a2a-echo
      provider: agent-pool
```

A chat request with `"model": "a2a-echo"` is translated into an A2A
task-submit body and placed through the agent's URL; the response is
mapped back to the chat-completion shape (content, `finish_reason`,
usage). Authn, authz, rate limits, and the rest of the policy chain
apply to the request exactly as they would to any other route --
agent-to-agent calls present the same credentials any client would.

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Master switch: the block is inert until enabled, so config can be staged ahead of activation. |
| `agents[].name` | -- | Unique agent name; referenced by the provider's `agent` field. |
| `agents[].url` | -- | The agent's base URL (`http`/`https`); the adapter builds the task-submit path under it. |
| `agents[].card` | -- | Agent Card: a filesystem path to JSON or an inline JSON object; parsed at compile time. |
| `sessions` | built-in defaults | Session policy (TTL 3600 s, max 1000 concurrent), mirroring the MCP gateway. |

## Notes

- A2A is an emerging standard; the card format and JSON-RPC method
  names track the current draft and may change.
- The Agent Card is a static document (file or inline) parsed at
  compile time. The gateway does not serve cards over HTTP in this
  build.
- The gateway does not itself execute agent tasks -- it translates
  and routes the messages. Long-running task state and streaming are
  handled by the agents at either end; the lifecycle surface is
  stubbed pending spec freeze.

## Runnable demo

[`demos/07-ai-gateway/`](https://github.com/shristilabs/dwara/tree/main/demos/07-ai-gateway) (test script: `test-15-a2a.sh`) in the
repository routes a chat request through an `ai.a2a` agent to a mock
A2A upstream and asserts the full chat-to-task-submit translation,
including the task-completion state and usage accounting. The
category README covers prerequisites and teardown.
