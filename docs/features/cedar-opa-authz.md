# Cedar + OPA Authorization (DW-060)

## Overview

dwara supports fine-grained authorization via two external policy
engines:

- **Cedar** -- AWS's Rust-native policy language. Policies are
  compiled once at config publish time and evaluated on the request
  path. No FFI boundary -- Cedar is pure Rust.
- **OPA** (Open Policy Agent) -- a Go-based policy engine called via
  HTTP. A TTL-based decision cache keeps the callout inside the authz
  latency budget.

Both are feature-gated behind the `cedar` cargo feature (default OFF).

## Enabling

Build with the `cedar` feature:

```sh
cargo build --features cedar
```

## Cedar

### API

```rust
use dwara_core::security::cedar::{CedarAuthorizer, CedarRequest, CedarDecision};

// Compile at config publish time (never on the request path).
let authz = CedarAuthorizer::new(
    "permit(principal == User::\"alice\", action == Action::\"read\", resource == Route::\"api-v1\");",
    Some("[...]"),  // entities JSON
    None,           // optional schema JSON
)?;

// Evaluate on the request path.
let req = CedarRequest {
    principal: r#"User::"alice""#.to_string(),
    action: r#"Action::"read""#.to_string(),
    resource: r#"Route::"api-v1""#.to_string(),
    context: None,
};
let decision = authz.is_authorized(&req)?;
assert_eq!(decision, CedarDecision::Allow);
```

### Policy syntax

Cedar policies use the `permit` and `forbid` keywords:

```
permit (
    principal == User::"alice",
    action == Action::"read",
    resource == Route::"api-v1"
) when {
    context.ip == "10.0.0.1"
};
```

`forbid` takes precedence over `permit` -- if any `forbid` policy
matches, the request is denied.

### Context

The `context` field of `CedarRequest` is a JSON object that gets
passed to the policy evaluation. Policies can reference context
fields in `when` and `unless` clauses.

### Entities

Entities are the subjects and objects of Cedar policies. They are
provided as a JSON array:

```json
[
    {
        "uid": {"__entity": {"type": "User", "id": "alice"}},
        "attrs": {},
        "parents": []
    }
]
```

### Schema (optional)

A Cedar schema defines the entity types, actions, and context
shapes. It is optional but recommended for type-checking at compile
time.

## OPA

### API

```rust
use dwara_core::security::cedar::opa::{OpaClient, OpaRequest, OpaDecision};
use std::time::Duration;

let client = OpaClient::new(
    "http://opa:8181/v1/data/dwara/allow".to_string(),
    Duration::from_secs(60),  // cache TTL
    Duration::from_secs(5),   // HTTP timeout
);

let req = OpaRequest {
    input: serde_json::json!({"user": "alice", "action": "read"}),
};
let decision = client.is_authorized(&req)?;
assert_eq!(decision, OpaDecision::Allow);
```

### Decision cache

The OPA client includes a TTL-based decision cache. On a cache hit,
the decision is returned without any HTTP call. On a cache miss, the
callout is made and the result is cached.

The cache key is derived from the endpoint URL and the serialized
input. The cache is a simple `HashMap` behind a `Mutex` -- no
eviction thread; entries expire on read and are lazily cleaned.

### HTTP callout

The HTTP callout uses a blocking `TcpStream` with a read/write
timeout. In the async proxy pipeline, the callout should be wrapped
in `tokio::task::spawn_blocking`.

The OPA endpoint should return a JSON response with a `result` field:

```json
{"result": true}
```

## Design (section 6-Extensibility)

Cedar is Rust-native (AWS), so authz becomes fine-grained data
(policies), not code, without an FFI boundary. OPA's decision cache
exists specifically to keep the HTTP/bundle callout inside the authz
latency budget rather than dialing out per request.

## Feature gate

The `cedar` cargo feature must be enabled. Without it, the module is
not compiled and config fields that reference Cedar/OPA policies are
accepted but inert.

## New dependencies

- `cedar-policy` 4.12 (Apache-2.0) -- Cedar policy engine. Feature-gated
  behind `cedar`.
