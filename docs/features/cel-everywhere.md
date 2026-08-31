# CEL Everywhere (DW-059)

## Overview

dwara provides one CEL (Common Expression Language) surface across
four use-sites, following the APISIX `expr`/Kong expressions-router
precedent of a single expression language rather than a bespoke DSL
per feature.

## Enabling

Build with the `cel` feature:

```sh
cargo build --features cel
```

## Use-sites

### 1. Expression matchers in routes

A CEL expression that evaluates to a bool. If true, the route matches.

```rust
use dwara_core::cel::everywhere::{RouteCondition, RequestContext};

let cond = RouteCondition::compile("request.path.startsWith(\"/api/\")").unwrap();
let ctx = RequestContext::new("/api/v1/users", "GET", "example.com");
assert!(cond.matches(&ctx).unwrap());
```

### 2. Header/transform logic

A CEL expression that evaluates to a string. The result is used as
the header value.

```rust
use dwara_core::cel::everywhere::{HeaderTransform, RequestContext};

let transform = HeaderTransform::compile(
    "request.path.startsWith(\"/v2/\") ? \"v2\" : \"v1\""
).unwrap();
let ctx = RequestContext::new("/v2/users", "GET", "example.com");
assert_eq!(transform.evaluate(&ctx).unwrap(), "v2");
```

### 3. Rate-limit key derivation

A CEL expression that evaluates to a string. The result is used as
the rate-limit key.

```rust
use dwara_core::cel::everywhere::{RateLimitKey, RequestContext};

let key = RateLimitKey::compile("request.headers[\"x-api-key\"]").unwrap();
let ctx = RequestContext::new("/api", "GET", "example.com")
    .with_header("x-api-key", "abc123");
assert_eq!(key.derive(&ctx).unwrap(), "abc123");
```

### 4. Policy conditions

A CEL expression that evaluates to a bool. If true, the policy
applies.

```rust
use dwara_core::cel::everywhere::{PolicyCondition, RequestContext};

let cond = PolicyCondition::compile(
    "request.path.startsWith(\"/admin/\") && request.method != \"GET\""
).unwrap();
let ctx = RequestContext::new("/admin/settings", "POST", "example.com");
assert!(cond.applies(&ctx).unwrap());
```

## Request context

All four use-sites share the same request context: a `request`
variable with `path`, `method`, `headers`, `query`, and `host`
fields. The gateway populates it per-request.

```rust
use dwara_core::cel::everywhere::RequestContext;

let ctx = RequestContext::new("/api/v1/users", "GET", "example.com")
    .with_header("x-api-key", "abc123")
    .with_query("page", "1");
```

## Unified API

For use-sites that need dynamic dispatch (e.g. config-driven
evaluation), the `compile_for` and `evaluate_for` functions provide a
unified API with type checking per use-site:

```rust
use dwara_core::cel::everywhere::{CelUseSite, compile_for, evaluate_for, RequestContext};

let program = compile_for(CelUseSite::RouteCondition, "request.path == \"/api\"").unwrap();
let ctx = RequestContext::new("/api", "GET", "example.com");
let result = evaluate_for(CelUseSite::RouteCondition, &program, &ctx).unwrap();
```

## Feature gate

The `cel` cargo feature must be enabled. Without it, the module is
not compiled and config fields that reference CEL expressions are
accepted but inert.
