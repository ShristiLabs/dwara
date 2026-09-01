# API aggregation

API aggregation lets a single route fan out to multiple upstream
services, compose the results, and return a single aggregated
response to the client. This is useful for BFF (backend-for-frontend)
patterns, mobile API consolidation, and reducing client-side request
chattiness.

::: info Status
Aggregation is a compile-time feature pack (`aggregation`, default
OFF; see [Editions](./editions#compile-time-feature-packs)) and is
not included in the published OSS binaries. The composition core
(specs, JSONPath shaping, fail policies, size caps) is complete and
test-covered as a library component. The config wiring has not landed
yet -- the `aggregations:` block and `type: aggregate` route action
below illustrate the target surface and are not in the generated
[configuration schema](../reference/configuration-schema).
:::

## When to use this

Use API aggregation when:

- A client needs data from multiple services in one request (e.g. a
  dashboard that loads user profile, orders, and notifications).
- You want to reduce round-trips for mobile clients.
- You want to compose a response from multiple microservices without
  writing a dedicated BFF service.

## Configuration

Define an aggregation spec at the top level and reference it from a
route:

```yaml
aggregations:
  - name: dashboard
    fragments:
      - name: user
        service: user-service
        path: /users/1
        target_field: user
      - name: orders
        service: order-service
        path: /orders?user=1
        target_field: orders
      - name: notifications
        service: notification-service
        path: /notifications?user=1
        target_field: notifications
    fail_policy: fail_open
    max_fragment_bytes: 65536

routes:
  - name: dashboard
    match:
      path: { type: exact, value: /dashboard }
    action:
      type: aggregate
      aggregation: dashboard
```

### Fragment fields

Each fragment defines one upstream fetch:

| Field | Default | Description |
|---|---|---|
| `name` | (required) | Fragment name (used in error reporting). |
| `service` | (required) | The service to fetch from. |
| `path` | (required) | The path on the upstream service. |
| `target_field` | (fragment name) | The field name in the composed response. |
| `jsonpath` | (none) | Optional JSONPath to extract a subset of the response. |
| `max_fragment_bytes` | `65536` | Maximum bytes to read from the upstream response. |

### Fail policy

The `fail_policy` controls what happens when a fragment fetch fails:

| Policy | Description |
|---|---|
| `fail_open` | The failed fragment is omitted from the response; other fragments are still composed. |
| `fail_closed` | The entire aggregation fails and the client receives a 502. |

### Composed response

The composed response is a JSON object with one field per fragment:

```json
{
  "user": { "id": 1, "name": "Alice" },
  "orders": [ { "id": 101, "total": 99.99 } ],
  "notifications": [ { "id": 201, "text": "Welcome" } ]
}
```

If a fragment fails with `fail_open`, the field is set to `null`:

```json
{
  "user": { "id": 1, "name": "Alice" },
  "orders": null,
  "notifications": [ { "id": 201, "text": "Welcome" } ]
}
```

## JSONPath extraction

Use `jsonpath` to extract a subset of an upstream response before
composing:

```yaml
fragments:
  - name: user
    service: user-service
    path: /users/1
    target_field: user
    jsonpath: "$.name"
```

This extracts only the `name` field from the user response, so the
composed response is:

```json
{
  "user": "Alice"
}
```

JSONPath support is deliberately simplified to what fragment shaping
needs: the root (`$`), field access (`$.field`), nested fields
(`$.field.subfield`), and array indexing (`$.items[0]`). Wildcards,
filters, and recursive descent are not supported.

## Size limits

Each fragment has a `max_fragment_bytes` cap (default 64 KB). If the
upstream response exceeds this, the fragment is truncated and treated
as a failure (subject to the fail policy). This prevents a single
large upstream response from exhausting gateway memory.

## Performance

All fragments are fetched in parallel. The gateway waits for all
fragments (or their failures) before composing the response. The
total latency is the maximum of the fragment latencies, not the sum.
