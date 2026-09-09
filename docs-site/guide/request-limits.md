# Request limits and validation

Request limits cap how large a request may be; body validation
checks what a request contains. The `limits` block rejects oversized
payloads (`413`, `431`) right after the route matches, and the
`request_validation` block rejects bodies that do not match a JSON
Schema (`400 validation_failed`) before the route action runs.
Together they protect upstreams against oversized and malformed
requests before any upstream resource is spent.

Both blocks are per-route and off by default. Like
[CORS](./cors) and [compression](./compression), each is a plain
part of the route (exactly one of each per route), not a reusable
`policies` attachment like [retries](./retries) or
[rate limiting](./rate-limiting). For the exhaustive field list see
the [configuration schema](../reference/configuration-schema).

## When to use this

Use size caps on any route exposed to clients you do not fully
control, to protect upstreams against oversized payloads -- huge
bodies, header floods, oversized individual headers. Use body
validation on JSON APIs with a known request shape, to reject
malformed or out-of-contract bodies at the edge instead of inside
the service.

## Configuration

```yaml
routes:
  - name: api
    service: api-service
    match:
      path:
        type: prefix
        value: /api/
    action:
      type: proxy
    limits:
      max_body_bytes: 10485760      # 10 MiB request bodies
      max_header_count: 50
      max_header_bytes: 16384
```

| Field | Default | Description |
|---|---|---|
| `max_body_bytes` | none | Cap on request body size. A request declaring a larger `Content-Length` is rejected `413` immediately; a body of unknown length (chunked uploads) is aborted the moment it crosses the cap. |
| `max_header_count` | none | Cap on the number of header fields (a repeated header counts each time); over the cap is `431`. |
| `max_header_bytes` | none | Cap on the total size of all header names and values; over the cap is `431`. |

Request validation is a separate per-route block:

```yaml
routes:
  - name: create-user
    service: user-backend
    match:
      path: /users
      methods: [POST]
    action:
      type: proxy
    request_validation:
      body_schema:
        type: object
        required: [name, email]
        properties:
          name:
            type: string
            minLength: 1
            maxLength: 100
          email:
            type: string
            maxLength: 255
          age:
            type: integer
            minimum: 0
            maximum: 150
        additionalProperties: false
      dry_run: false
```

| Field | Default | Description |
|---|---|---|
| `body_schema` | none | A minimal JSON Schema subset the parsed request body must satisfy (see below). |
| `dry_run` | `false` | Evaluate the schema and log violations without rejecting requests. |

## How limits are enforced

Per-route caps on request size, enforced right after the route
matches -- before authentication and before any upstream contact
when the size is declared:

- `max_body_bytes` -- a request declaring a larger `Content-Length`
  is rejected `413` immediately. A body of unknown length (chunked
  uploads) is aborted the moment it crosses the cap.
- `max_header_count` -- the number of header fields (a repeated
  header counts each time); over the cap is `431`.
- `max_header_bytes` -- the total size of all header names and
  values; over the cap is `431`.

All rejections use the standard JSON error envelope
(`{error:{code,message,request_id}}`) with codes
`request_body_too_large` and `request_headers_too_large`. These are
route-level limits on top of the process-wide parser bounds -- see
[protocol hardening](./operations#protocol-hardening), which applies
to every listener regardless of routes.

Because a `413`/`431` is generated before the route's action runs,
it carries no CORS headers -- a browser may report a generic
network/CORS error for what is really a size rejection. See
[CORS](./cors).

## Request body JSON Schema validation

Per-route validation of request bodies against a minimal JSON Schema
subset, enforced after the route matches and before the route action
runs. This rejects malformed requests with `400 validation_failed`
before any upstream resource is spent.

### Supported schema subset

The validator implements a minimal subset of JSON Schema:

| Keyword | Description |
|---|---|
| `type` | `object`, `array`, `string`, `integer`, `number`, `boolean`, `null` |
| `required` | List of required property names (objects only). |
| `properties` | Per-property schemas (objects only). |
| `items` | Schema for array elements. |
| `enum` | List of allowed values. |
| `minimum` / `maximum` | Numeric bounds (inclusive). |
| `minLength` / `maxLength` | String length bounds. |
| `additionalProperties` | `false` rejects unknown properties; `true` (default) allows them. |

`$ref`, `oneOf`/`anyOf`/`allOf`, and `format` are NOT supported. Use
inline schemas for complex cases.

### Dry-run mode

Set `dry_run: true` to evaluate the schema and log violations
without rejecting requests. Violations are recorded with the
`validation_failed_dry_run` code and counted in the
`dwara_policy_dry_run_total{phase="request_validation",route}`
metric. This lets you measure the impact of a new schema against
production traffic before switching to enforce mode.

### Runtime behavior

1. The body is buffered up to the route's `limits.max_body_bytes`
   (or 1 MiB default).
2. Parsed as JSON (non-JSON bodies are rejected with
   `validation_failed`).
3. Walked against the schema.
4. On mismatch: `400 validation_failed` with the offending instance
   paths in the JSON error envelope.
5. On match: the buffered bytes are replayed to the route action.

Body buffering adds latency and memory pressure for large bodies.
Configure `limits.max_body_bytes` to bound it. For routes with
streaming bodies (e.g., Server-Sent Events -- see
[Compression](./compression) for the response side of streaming),
avoid request validation or use a generous body cap.

## Ordering and reload

For a matched request the stages run in a fixed order: route limits,
then [CORS](./cors) preflight handling, then authentication,
authorization, rate limiting, and admission, then the route's
action, and finally the response gains [compression](./compression)
and CORS headers. Request validation runs after the route matches
and before the route action. See the
[request pipeline](../architecture/overview#request-pipeline) for
the full picture. Both blocks reload live with the rest of the
config -- an atomic snapshot swap, no restart.
