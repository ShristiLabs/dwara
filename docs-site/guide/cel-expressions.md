# CEL expressions

Dwara uses the [Common Expression Language](https://cel.dev/)
(CEL) for dynamic, safely-sandboxed expressions throughout the
config. CEL is a small, side-effect-free expression language
designed for embedding in applications -- it evaluates against a
typed context and produces a typed result, with no I/O, no
allocation beyond a budget, and a compile-time type check.

## When to use this

Use CEL expressions when you need dynamic logic that the static
config cannot express:

- Route conditions based on request headers, query params, or method.
- Header transforms derived from request context.
- Rate-limit key derivation (per-tenant, per-API-key).
- Policy conditions (IP allowlists, method restrictions).

CEL replaces ad-hoc template strings with a typed, sandboxed
expression language that fails fast on type errors at compile time.

## The request context

All CEL expressions evaluate against a `request` context with the
following fields:

| Field | Type | Description |
|---|---|---|
| `request.method` | `string` | HTTP method (GET, POST, etc.) |
| `request.path` | `string` | Request path (after rewrite) |
| `request.host` | `string` | Host header value |
| `request.headers` | `map<string, string>` | Request headers (case-sensitive keys) |
| `request.query` | `map<string, string>` | Query parameters |

## Use sites

### Route conditions

A route condition is a CEL expression that evaluates to a boolean.
The route matches only if the expression returns `true`:

```yaml
routes:
  - name: api-v2
    service: api-v2-service
    match:
      path: { type: prefix, value: /api }
      condition: 'request.headers["x-version"] == "v2"'
    action: { type: proxy }
```

Common patterns:

```cel
// Header check
request.headers["x-version"] == "v2"

// Query param check
request.query["debug"] == "true"

// Method restriction
request.method == "GET" || request.method == "HEAD"

// Host suffix
request.host.endsWith(".internal")
```

### Header transforms

A header transform is a CEL expression that evaluates to a string.
The result is used as the header value:

```yaml
routes:
  - name: api
    service: api-service
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy }
    transforms:
      request_headers:
        set:
          x-forwarded-for: 'request.headers["x-forwarded-for"]'
          x-request-id: 'request.method + "-" + request.path'
```

### Rate-limit keys

A rate-limit key is a CEL expression that evaluates to a string.
The result is used as the rate-limit bucket key:

```yaml
routes:
  - name: api
    service: api-service
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy }
    rate_limit:
      key: 'request.headers["x-api-key"] + ":" + request.path'
      requests_per_second: 100
```

### Policy conditions

A policy condition is a CEL expression that evaluates to a boolean.
The policy applies only if the expression returns `true`:

```yaml
policies:
  - name: internal-only
    condition: 'request.headers["x-real-ip"] == "10.0.0.1"'
    # ... policy fields
```

## Type checking

CEL expressions are type-checked at compile time. If an expression
references a field that doesn't exist or has the wrong type, the
config is rejected at load time:

```
Error: route condition compile: unknown field 'request.headerz'
```

This means typos and type mismatches are caught before the gateway
starts, not at request time.

## Performance

CEL expressions are compiled to an AOT bytecode representation at
config load time. Evaluation at request time is a bytecode
interpretation with a fuel budget -- no parsing, no compilation, no
allocation beyond the result. Typical evaluation is sub-microsecond
for simple expressions.

## AOT compilation

The CEL engine compiles expressions ahead-of-time (AOT) into a
bytecode program. This means:

- Parse errors are caught at config load, not at request time.
- The compiled program is reused across all requests.
- No runtime parsing overhead.

## Expression library

CEL supports the standard library: string methods (`startsWith`,
`endsWith`, `contains`, `matches`), comparison operators, logical
operators (`&&`, `||`, `!`), arithmetic, and macros (`all`, `exists`,
`filter`, `map`).

```cel
// All headers start with "x-"
request.headers.all(k, k.startsWith("x-"))

// Exists a header with value "admin"
request.headers.exists(k, request.headers[k] == "admin")

// String concatenation
request.method + " " + request.path
```

See the [CEL spec](https://cel.dev/docs/spec) for the full language
reference.
