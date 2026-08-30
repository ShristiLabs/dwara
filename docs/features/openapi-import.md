# OpenAPI Import and Mock Mode (DW-047)

## Overview

Dwara can import an OpenAPI 3.x spec and generate a starter config, and
routes can serve canned mock responses without contacting any upstream.
Together these two features accelerate the "first request" workflow:
scaffold the gateway from an existing spec, mock the endpoints that do
not have a backend yet, and swap in real upstreams as they come online.

## OpenAPI import

### Command

```
dwara import openapi <spec.yaml|json> [--output dwara.yaml]
```

The importer reads an OpenAPI 3.x document (YAML or JSON, auto-detected
by content or file extension) and emits a Dwara config YAML with:

- One route per unique path (Dwara's route table is path-only, so
  multiple methods on the same path share a single route with
  `match.methods` listing them all).
- `match.path.type: exact` with `{param}` segments preserved as Dwara
  path params.
- `action: { type: proxy }` with no rewrite (the operator adds one if
  needed).
- A placeholder upstream `openapi-backend` at `127.0.0.1:9000` and a
  service `openapi-service` referencing it.
- An `openapi` extension field on each route carrying the source
  `operationId`, `summary`, `tags`, `method`, and `path` for
  traceability. This field has no runtime effect; it survives
  round-trips so the operator can audit which spec operation a route
  came from.

### Route naming

The route name is derived from the first operation's `operationId`
(preferred, lowercased and hyphenated) or a `method-path` fallback when
the operation has no `operationId`. Collisions are resolved by
appending a counter (`-2`, `-3`, ...).

### What the importer does NOT do

- It does not import request/response schemas into
  `request_validation` (the operator adds those manually for the
  endpoints that need validation).
- It does not import security schemes (the operator wires
  `auth_required` and `authorization` blocks manually).
- It does not import server URLs as upstreams (the placeholder upstream
  is always `openapi-backend` at `127.0.0.1:9000`).

The import is a scaffolding step, not a spec validator. The generated
config is a starting point that the operator edits.

## Mock mode

A route with `action: { type: mock, ... }` serves a canned response
without contacting any upstream. The mock action supports:

| Field | Type | Description |
|---|---|---|
| `status` | `u16` | HTTP status code (100-599). Required. |
| `body` | `string` | Inline response body. Mutually exclusive with `body_file`. |
| `body_file` | `string` | Path to a file whose contents are served as the body, read at config publish time. Mutually exclusive with `body`. |
| `headers` | `map<string, string>` | Extra response headers, emitted verbatim. |
| `delay_ms` | `u32` | Simulated latency in milliseconds (0-30000). |

### Content-Type inference

When the operator does not set a `Content-Type` header explicitly, the
gateway defaults it to `application/json` if the body parses as JSON,
else `text/plain`. An explicit `Content-Type` header always wins.

### body_file

The `body_file` path is read at config publish time (the bytes are held
in the snapshot). This means a config reload picks up file changes, and
the file is not re-read on every request (zero per-request I/O for mock
routes).

### Example

```yaml
routes:
  - name: mock-pets
    service: mock-service
    match:
      path:
        type: exact
        value: /pets
      methods: [GET]
    action:
      type: mock
      status: 200
      body: '{"pets": [{"id": 1, "name": "Rex"}]}'
      headers:
        X-Mock: true
    request_validation:
      body_schema:
        type: object
        properties:
          limit:
            type: integer
            minimum: 1
            maximum: 100
```

## Request validation

A route with a `request_validation.body_schema` block validates the
request body against a minimal JSON-Schema subset BEFORE the action
runs. A mismatch answers `400 validation_failed` with the offending
instance path in the JSON error envelope; a match proceeds to the
action (proxy, mock, ...).

### Supported keywords

| Keyword | Applies to | Description |
|---|---|---|
| `type` | all | `object`, `array`, `string`, `number`, `integer`, `boolean`, `null` |
| `required` | object | List of required property names |
| `properties` | object | Named property schemas |
| `additionalProperties` | object | `true` (default), `false`, or a schema |
| `items` | array | Schema every element must satisfy |
| `enum` | all | List of allowed values (JSON equality) |
| `minimum` | number/integer | Inclusive numeric minimum |
| `maximum` | number/integer | Inclusive numeric maximum |
| `minLength` | string | Minimum string length |
| `maxLength` | string | Maximum string length |

### What is NOT supported

- `$ref` (inline your schemas).
- `exclusiveMinimum`/`exclusiveMaximum` (use `minimum`/`maximum`).
- `pattern` (regex string matching).
- `minItems`/`maxItems` (array length bounds).
- `uniqueItems`.
- `format`.
- `oneOf`/`anyOf`/`allOf`/`not`.

This is a SIMPLER surface than full OpenAPI parameter/header/query
validation. It covers the body only, the common case for write
endpoints. Unknown keywords are ignored (forward compatibility with
richer specs).

### Placement in the request path

Request validation runs AFTER every policy phase (authn, authz, rate
limiting, admission) and BEFORE the action. A malformed body from an
authenticated, authorized caller is still rejected, and no upstream is
contacted on a mismatch. A cache HIT skips validation (the cached
response was already validated when it was first fetched).

The body is buffered fully for JSON parsing + schema validation, then
replayed to the action below. The route's body limit (if any) is
enforced before validation (413), so the validation buffer is bounded
by the route's cap.
