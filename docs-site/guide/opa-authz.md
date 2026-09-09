# OPA authorization

OPA (Open Policy Agent) is a general-purpose policy engine with
policies written in Rego. The gateway queries it over HTTP at
request time and honors its boolean decision.

OPA is one of two external policy engines Dwara supports for
authorization; the other, [Cedar authorization](./cedar-authz),
evaluates policies in-process. Both complement the built-in authz
(consumer/route/service policies) -- see
[Authorization](./authorization) -- and sit behind a single
compile-time capability (`cedar`, default OFF, no license) that
covers both engines. See [Editions: OSS vs Enterprise](./editions)
for how capabilities differ from enterprise features.

::: info Status
The pack is not included in the published OSS binaries. The OPA
HTTP client (with decision caching and a `fail_closed` mode), like
the in-process Cedar authorizer, is complete and test-covered as a
library component. The config wiring has not landed yet -- the
`authz:` blocks below illustrate the target surface (the built-in
rules live under `authorization:` today) and the Cedar/OPA keys are
not in the generated
[configuration schema](../reference/configuration-schema).
:::

## When to use this

Use OPA (or Cedar) when the built-in policy model is not expressive
enough:

- Attribute-based access control (ABAC) with complex rules.
- Externalized policy management (policies stored outside the
  gateway config).
- Centralized policy across multiple services.

The built-in authz covers consumer allow/deny lists, IP ACLs, and
route-level method restrictions. Cedar/OPA are for everything beyond
that. Prefer OPA when you already run an OPA server and want one
policy service shared across multiple services; prefer
[Cedar](./cedar-authz) when you want to avoid the extra network hop.

## Enabling

Cedar and OPA support are compiled into the OSS build behind the
`cedar` feature -- the feature compiles in the Cedar authorizer and
the OPA client together:

```sh
cargo build -p dwara-core
```

## Configuration

OPA is queried over HTTP. Configure the OPA endpoint and query
path:

```yaml
authz:
  opa:
    url: http://opa:8181/v1/data/dwara/allow
    timeout_ms: 100
    fail_closed: true
```

| Field | Default | Description |
|---|---|---|
| `url` | (required) | OPA decision endpoint URL. |
| `timeout_ms` | `100` | Query timeout in milliseconds. |
| `fail_closed` | `true` | If true, deny the request when OPA is unreachable or times out. If false, allow the request (fail-open). |

## How it works

1. The gateway sends a POST to the OPA endpoint with the request
   context (method, path, headers, consumer identity) as JSON.
2. OPA evaluates the Rego policy and returns a boolean decision.
3. If the decision is `true`, the request proceeds. If `false`, the
   request is rejected with 403.

## OPA input format

The gateway sends the following JSON to OPA:

```json
{
  "input": {
    "method": "GET",
    "path": "/api/v1/users",
    "host": "example.com",
    "consumer": "alice",
    "headers": {
      "x-api-key": "abc123"
    }
  }
}
```

A minimal Rego policy:

```rego
package dwara

default allow := false

allow {
  input.method == "GET"
  input.consumer == "alice"
}
```

## Fail-closed vs fail-open

Both Cedar and OPA support a `fail_closed` mode:

- **Fail-closed** (default): if the policy engine is unavailable or
  returns an error, the request is denied. This is the safe default
  -- never let a policy engine outage accidentally allow traffic.
- **Fail-open**: if the policy engine is unavailable, the request is
  allowed. Use this only when availability is more important than
  security (e.g. internal tools behind a VPN).

## Interaction with built-in authz

Cedar/OPA run **after** the built-in authz checks. A request must
pass both:

1. Built-in authz (consumer allow/deny, IP ACL, method allowlist).
2. Cedar/OPA (if configured).

If either denies, the request is rejected with 403.
