# Agent-to-Agent (A2A) protocol

Dwara can act as a gateway for the [Agent-to-Agent (A2A) protocol](https://en.wikipedia.org/wiki/Agent-to-agent_protocol),
an emerging standard for machine-to-machine communication between
autonomous AI agents. In the A2A model, an agent publishes an Agent Card
describing its identity, capabilities, and endpoint; other agents
discover the card, negotiate a task, and exchange JSON-RPC messages over
HTTP to carry the task to completion. The gateway's role is to route
A2A traffic, enforce authn/authz on agent-to-agent calls, and expose
Agent Card discovery without requiring agents to know each other's
network addresses.

## When to use this

Enable A2A routing when you operate a fleet of AI agents that need to
call each other through a controlled boundary rather than directly. The
gateway gives you:

- A single ingress point for inbound agent calls, with the same authn
  (API key, JWT, mTLS), authz, rate limiting, and observability applied
  to ordinary HTTP traffic.
- Agent Card discovery as a gateway-managed endpoint, so agents do not
  need to know the network address of every peer -- they query the
  gateway for a card by agent identifier.
- Centralized policy over which agents may call which other agents,
  enforced before the first task message is forwarded.

If your agents communicate over a single fixed channel with no policy
boundary, A2A routing adds a hop for no benefit.

## Agent Card discovery

An [Agent Card](https://en.wikipedia.org/wiki/Agent-to-agent_protocol) is
a JSON document describing an agent's identity (`id`, `name`), the
capabilities it exposes (`skills`), its authentication requirements, and
the endpoint where it receives A2A tasks. The gateway serves cards from
config so that an agent can discover a peer by asking the gateway rather
than the peer directly:

```yaml
a2a:
  enabled: true
  agents:
    - id: agent://billing@example.com
      name: billing-agent
      card_file: /etc/dwara/agents/billing.card.json
      upstream: billing-svc
    - id: agent://support@example.com
      name: support-agent
      card_file: /etc/dwara/agents/support.card.json
      upstream: support-svc
```

A discovery request to `/.well-known/agent-card.json?id=<agent-id>`
returns the card for the named agent. A request with no `id` returns the
gateway's index of known agents (their identifiers and card locations,
not the full cards). Cards are loaded at startup and on config reload;
a missing or malformed card file disables that agent's discovery entry
and logs a validation issue, but does not prevent the others from
serving.

## Routing A2A traffic

A2A task messages are JSON-RPC over HTTP. The gateway routes them to the
upstream named in the agent's `upstream` field, so the routing decision
is driven by the agent identifier in the task, not by a path prefix:

```yaml
routes:
  - name: a2a-tasks
    service: a2a-bus
    match:
      path: { type: prefix, value: /a2a }
    a2a:
      enabled: true
    authn:
      jwt:
        jwks_url: https://idp.example.com/.well-known/jwks.json
        audiences: ["dwara-a2a"]
    action: { type: proxy }
```

When `a2a.enabled` is true on a route, the gateway inspects the JSON-RPC
`method` and the agent identifier in the request body, resolves the
identifier to the configured agent, and rewrites the upstream target to
that agent's `upstream`. Authn, authz, rate limits, and the rest of the
policy chain apply to the A2A request exactly as they would to any other
request on the route -- an agent calling another agent presents the
same credentials a human-facing client would.

## Notes

- A2A is an emerging standard; the card format and JSON-RPC method names
  track the current draft. The gateway's card-serving and routing
  behavior follows the published spec at the time of release, but the
  protocol is not yet finalized and may change.
- Agent Cards are static files today. Dynamic card generation from
  upstream health or capability probes is an enterprise seam, not part
  of the OSS A2A routing surface.
- The gateway does not itself execute agent tasks -- it routes the
  JSON-RPC messages between agents. Task state, long-running
  negotiations, and streaming responses are handled by the agents on
  either end of the routed connection.
