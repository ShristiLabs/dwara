# Cedar and OPA authorization

Dwara supports two external policy engines for authorization:

- **[Cedar](https://www.cedarpolicy.com/)**: a policy language
  developed by AWS for fine-grained authorization. Policies are
  declarative, composable, and side-effect-free.
- **[OPA](https://www.openpolicyagent.org/)** (Open Policy Agent):
  a general-purpose policy engine with Rego policies, queried over
  HTTP.

Both are behind a single compile-time feature pack (`cedar`, default
OFF, no license) that complements the built-in authz
(consumer/route/service policies). See
[Editions: OSS vs Enterprise](./editions) for how feature packs differ
from enterprise features.

::: info Status
The pack is not included in the published OSS binaries. The in-process
Cedar authorizer and the OPA HTTP client (with decision caching and a
`fail_closed` mode) are complete and test-covered as library
components. The config wiring has not landed yet -- the `authz:`
blocks below illustrate the target surface (the built-in rules live
under `authorization:` today) and the Cedar/OPA keys are not in the
generated [configuration schema](../reference/configuration-schema).
:::

## When to use this

Use Cedar or OPA when the built-in policy model is not expressive
enough:

- Attribute-based access control (ABAC) with complex rules.
- Externalized policy management (policies stored outside the
  gateway config).
- Centralized policy across multiple services.

The built-in authz covers consumer allow/deny lists, IP ACLs, and
route-level method restrictions. Cedar/OPA are for everything beyond
that.

## Enabling

Cedar and OPA support are feature-gated behind the single `cedar`
feature (it compiles in the Cedar authorizer and the OPA client
together):

```sh
cargo build -p dwara-core --features cedar
```

## Cedar

Cedar policies are evaluated in-process (no external service needed).
Configure a Cedar policy set in the config:

```yaml
authz:
  cedar:
    policies: |
      permit(
        principal == User::"alice",
        action == Action::"read",
        resource == Resource::"api"
      );
    schema: |
      {
        "entities": {
          "User": {},
          "Action": {},
          "Resource": {}
        }
      }
```

### How Cedar evaluation works

1. The gateway extracts the principal (consumer identity), action
   (HTTP method mapped to read/write), and resource (route name)
   from the request.
2. The Cedar authorizer evaluates the policy set against the request.
3. If the decision is `Allow`, the request proceeds. If `Deny`, the
   request is rejected with 403.

### Cedar policy format

Cedar policies use a `permit` or `forbid` clause:

```cedar
permit(
  principal == User::"alice",
  action == Action::"read",
  resource == Resource::"api"
);

forbid(
  principal,
  action == Action::"delete",
  resource
)
unless {
  principal has role && principal.role == "admin"
};
```

See the [Cedar docs](https://docs.cedarpolicy.com/) for the full
language reference.

## OPA

OPA is queried over HTTP. Configure the OPA endpoint and query path:

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

### How OPA evaluation works

1. The gateway sends a POST to the OPA endpoint with the request
   context (method, path, headers, consumer identity) as JSON.
2. OPA evaluates the Rego policy and returns a boolean decision.
3. If the decision is `true`, the request proceeds. If `false`, the
   request is rejected with 403.

### OPA input format

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
