# First scenarios

Task-oriented entry points for common operator goals. Each scenario
names the config blocks and guide pages you need and points at a
minimal shape to start from. Read [Concepts and taxonomy](./concepts)
first if the vocabulary is new.

## Protect a public API

Goal: expose an internal service to the internet with rate limiting,
attack filtering, and JWT authentication.

What you need:

- A [listener](./routing) with TLS termination.
- A [route](./routing) matching the public path, proxying to the
  internal service.
- A [policy](./traffic-policy) with `rate_limits` (GCRA, stacked
  windows) and a `waf` block for SQLi/XSS/traversal filtering.
- A [consumer](./concepts#identity-and-access) with a JWT/JWKS
  [credential](./authentication-methods).
- An [authorization](./authorization) rule restricting access to the
  consumer or group.

Guides: [Traffic policy](./traffic-policy), [WAF-lite](./waf-lite),
[Security](./security), [Authorization](./authorization).

## Proxy to LLM providers

Goal: expose one OpenAI-shaped chat-completions endpoint that
translates to OpenAI, Anthropic, or Gemini, with token budgets and
guardrails.

What you need:

- An `ai` block with one or more
  [providers](./ai-gateway) (OpenAI, Anthropic, Gemini, or
  OpenAI-compatible).
- A [model alias](./ai-gateway) mapping the client's `model` value to
  a provider and provider-side model id.
- A route with the `ai` action pointing at the alias.
- A [token budget](./ai-token-budgets) policy for per-consumer caps.
- Optional [guardrails](./ai-guardrails) for prompt-injection, PII, and
  banned-content enforcement.

Guides: [AI gateway](./ai-gateway), [Token budgets](./ai-token-budgets),
[Guardrails](./ai-guardrails), [Semantic caching](./ai-semantic-caching).

## Migrate from NGINX, Kong, or Envoy

Goal: import an existing gateway config and diff it against a native
Dwara config before cutover.

What you need:

- The [config import](./config-import) tool: `dwara import` reads
  NGINX, Kong, or Envoy config and emits a Dwara YAML draft.
- `dwara diff` to compare the imported draft against your hand-tuned
  config.
- `dwara validate` and `dwara lint` to check the result.

Guides: [Config import](./config-import), [CLI](./cli).

## Run on Kubernetes

Goal: translate Kubernetes Gateway API and Ingress resources into
Dwara config and run the controller beside your cluster.

What you need:

- The [Kubernetes Gateway API](./kubernetes-gateway-api) translator,
  which reads Gateway, HTTPRoute, and Ingress resources.
- The controller running as a cluster workload, pushing config
  generations to the gateway.

Guides: [Kubernetes Gateway API](./kubernetes-gateway-api),
[Deployment](./deployment).

## Operate a fleet

Goal: coordinate many gateway instances as one system -- shared
rate-limit budgets, config that converges, a control plane pushing
generations to edges.

What you need (enterprise edition):

- [CP/DP split](./cp-dp-split): a leader-elected `dwara-controller`
  compiling config and pushing it to `dwara-edge` instances over gRPC.
- [Distributed rate limiting](./redis-rate-limiter): shared Redis
  GCRA buckets.
- [Config convergence](./config-convergence): fleet-wide consistent
  config state.
- [Workspaces](./workspaces-rbac-audit): multi-tenant config
  partitioning with RBAC and an audit trail.

Guides: [Enterprise and fleet](./enterprise), [Editions](./editions).

## Add a custom rate-limit backend

Goal: replace the local GCRA rate limiter with a custom or
distributed backend.

What you need:

- An implementation of the `RateLimiter` extension trait; see
  [Extension traits](./extension-traits).
- The enterprise Redis-backed implementation is available with the
  `ent` feature and a `redis_rate_limiter` license claim; see
  [Distributed Redis rate limiter](./redis-rate-limiter).

Guides: [Extension traits](./extension-traits),
[Redis rate limiter](./redis-rate-limiter).

## Where to go next

- [Getting started](./getting-started) - run a gateway locally in under
  a minute.
- [Configuration](./configuration) - the YAML shape and the config
  pipeline.
- [Concepts and taxonomy](./concepts) - the vocabulary every other
  guide assumes.
