# OpenAPI Response Validation (DW-070)

## Overview

dwara can validate upstream responses against the OpenAPI spec's
response schemas. When a response violates the spec, it is flagged as
drift (with validation error details) and optionally returned as a 502
to the client.

This is the runtime half of section 5-API Mgmt's "OpenAPI-driven
config" item, whose import/request-validation/mock half already
shipped as DW-047 (M2). This is also the concrete implementation of
Tier 3's "Contract testing mode" (section 6-API Craft): verify live
traffic conforms to the spec DW-047 imported, and flag drift.

## Enabling

Build with the `openapi_validation` feature:

```sh
cargo build --features openapi_validation
```

## Scope

This covers per-response schema-conformance drift, not route-set
drift (whether the live route set has grown out of sync with the
spec's endpoint list).

## API

### ResponseValidator

```rust
use dwara_core::openapi::{ResponseValidator, ResponseToValidate, ValidationResult};

// Compile at config publish time from the OpenAPI document.
let validator = ResponseValidator::from_openapi(&openapi_doc)?;

// Validate a response on the request path.
let response = ResponseToValidate {
    path: "/users".to_string(),
    method: "GET".to_string(),
    status: 200,
    content_type: Some("application/json".to_string()),
    body: Some(serde_json::json!({"id": 1, "name": "Alice"})),
};
match validator.validate(&response) {
    ValidationResult::Valid => { /* response conforms to spec */ }
    ValidationResult::Invalid(errors) => {
        // response violates spec -- flag drift or return 502
        for err in &errors {
            eprintln!("drift at {}: {}", err.path, err.message);
        }
    }
    ValidationResult::NoSchema => { /* no schema for this triple */ }
}
```

### From schemas

```rust
use dwara_core::openapi::{ResponseValidator, ResponseKey};
use std::collections::HashMap;
use serde_json::json;

let mut schemas = HashMap::new();
schemas.insert(
    ResponseKey {
        path: "/users".to_string(),
        method: "GET".to_string(),
        status: 200,
    },
    json!({
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string"}
        },
        "required": ["id", "name"]
    }),
);
let validator = ResponseValidator::from_schemas(schemas)?;
```

## Design (section 5-API Mgmt, section 6-API Craft)

Schemas are compiled once at config publish time (using the
`jsonschema` crate's `Validator`) and stored as `Arc<Validator>` in
the `ResponseValidator`. The request path only evaluates -- it never
parses or compiles.

The `ResponseValidator` holds a map of `(path, method, status)` to
compiled schema validators. When a response arrives, the proxy looks
up the schema for the response's triple and validates the body against
it.

## Drift flagging

When a response violates the spec:
1. The validation errors are collected (path + message for each
   error).
2. The errors are logged as drift.
3. If configured, a 502 is returned to the client instead of the
   violating response.

The 502 behavior is opt-in (the proxy can be configured to either
flag-and-pass or flag-and-block).

## Feature gate

The `openapi_validation` cargo feature must be enabled. Without it,
the module is not compiled and config fields that reference OpenAPI
response validation are accepted but inert.

## New dependencies

- `jsonschema` 0.46 (MIT) -- JSON Schema validator. Feature-gated
  behind `openapi_validation`.
