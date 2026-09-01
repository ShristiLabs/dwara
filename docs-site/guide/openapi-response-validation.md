# OpenAPI response validation

Dwara can validate upstream responses against OpenAPI response
schemas. When enabled, responses that don't match the schema are
flagged -- either rejected (fail-closed) or logged (dry-run mode).

::: info Status
Response validation is a compile-time feature pack
(`openapi_validation`, default OFF; see
[Editions](./editions#compile-time-feature-packs)) and is not included
in the published OSS binaries. The validation engine is complete and
test-covered as a library component. The route-level config wiring
has not landed yet -- the `openapi_validation:` block below
illustrates the target surface and is not in the generated
[configuration schema](../reference/configuration-schema).
:::

## When to use this

Use response validation when:

- You want to catch upstream contract violations before they reach
  clients.
- You are testing a new upstream and want to verify it conforms to
  its OpenAPI spec.
- You want to enforce response shape as a runtime invariant.

## Enabling

Response validation is configured per-route. Provide the OpenAPI
spec and the response schemas to validate:

```yaml
routes:
  - name: api
    service: api-service
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy }
    openapi_validation:
      spec: ./openapi.yaml
      mode: enforce
```

| Field | Default | Description |
|---|---|---|
| `spec` | (required) | Path to the OpenAPI spec file (YAML or JSON). |
| `mode` | `enforce` | `enforce` rejects non-conforming responses (502). `dry_run` logs violations but forwards the response. |

## How validation works

1. At config load time, the gateway compiles the response schemas
   from the OpenAPI spec into JSON Schema validators.
2. At request time, after the upstream response arrives, the gateway
   selects the schema for the response's status code and content type.
3. The response body is validated against the schema.
4. If validation fails:
   - **`enforce` mode**: the gateway returns 502 with an error
     envelope naming the violated schema.
   - **`dry_run` mode**: the violation is logged and the original
     response is forwarded to the client.

## What is validated

- **Status code**: the response status must be defined in the OpenAPI
  spec. An undefined status code is a violation.
- **Content type**: the response content type must match a defined
  response content type for that status code.
- **Body schema**: the response body (JSON) is validated against the
  JSON Schema for the status code and content type.

## Dry-run mode

Use `dry_run` mode to test validation without impacting traffic:

```yaml
routes:
  - name: api
    service: api-service
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy }
    openapi_validation:
      spec: ./openapi.yaml
      mode: dry_run
```

Violations are logged with the route name, status code, and schema
path. Once you are confident the spec is correct, switch to `enforce`.

## Performance

Schema compilation happens at config load time. At request time,
validation is a JSON Schema check against the compiled validator --
no parsing of the OpenAPI spec. The overhead is proportional to the
response body size and the schema complexity.

For large response bodies, consider validating only a subset of
fields by narrowing the schema to the fields you care about.
