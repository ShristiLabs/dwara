# OpenAPI Import and Mock Mode

Import an OpenAPI spec to scaffold your gateway config, and mock
endpoints that do not have a backend yet.

## OpenAPI import

Generate a Dwara config from an OpenAPI 3.x spec:

```sh
dwara import openapi petstore.yaml --output dwara.yaml
```

The generated config has one route per unique path, a placeholder
upstream at `127.0.0.1:9000`, and an `openapi` extension field on each
route carrying the source `operationId`, `summary`, `tags`, `method`,
and `path` for traceability.

Edit the generated config to point at your real upstreams, add auth and
policies, and publish.

## Mock mode

Serve canned responses without an upstream:

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

services:
  - name: mock-service
    upstream: mock-backend
upstreams:
  - name: mock-backend
    endpoints:
      - { address: 127.0.0.1, port: 1 }
```

The `body_file` field reads a file at config publish time (zero
per-request I/O):

```yaml
    action:
      type: mock
      status: 200
      body_file: fixtures/pets.json
```

The `delay_ms` field simulates latency (useful for testing timeouts):

```yaml
    action:
      type: mock
      status: 200
      body: delayed
      delay_ms: 500
```

## Request validation

Validate the request body before the action runs:

```yaml
routes:
  - name: create-pet
    service: mock-service
    match:
      path:
        type: exact
        value: /pets
      methods: [POST]
    action:
      type: mock
      status: 201
      body: '{"ok": true}'
    request_validation:
      body_schema:
        type: object
        required: [name]
        properties:
          name:
            type: string
            minLength: 1
          age:
            type: integer
            minimum: 0
            maximum: 150
        additionalProperties: false
```

A mismatch answers `400 validation_failed`; a match proceeds to the
action. The supported JSON-Schema keywords are: `type`, `required`,
`properties`, `items`, `enum`, `minimum`, `maximum`, `minLength`,
`maxLength`, and `additionalProperties`.
