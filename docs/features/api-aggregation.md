# API Aggregation Plugin Pack (DW-061)

## Overview

dwara supports KrakenD-style API aggregation: composing a response
from multiple upstreams with JSONPath fragment shaping and
per-fragment fail-open/closed policies.

## Enabling

Build with the `aggregation` feature:

```sh
cargo build --features aggregation
```

## Constraint (decision 10, section 12.1)

The core dataplane never buffers full bodies to support composition
-- only this plugin's own fragment transforms, with explicit size
caps, touch bodies. Composition stays an extension cost, never a tax
on the zero-buffering proxy path everything else uses.

## KrakenD-style aggregation

An aggregation endpoint composes a response from multiple upstreams.
Each fragment specifies:
- An upstream reference (service name + path)
- A JSONPath expression to extract a fragment from the upstream response
- A target field in the composed response
- A fail-open/closed policy (fail-open = skip on error, fail-closed = return an error)

The aggregator fetches all fragments in parallel, shapes each, and
combines them into a single JSON response.

## API

### AggregationSpec

An aggregation endpoint spec: name, fragments, max response size.

### FragmentSpec

A single fragment: service, path, method, JSONPath, target field,
fail policy, max fragment size.

### FailPolicy

- `FailOpen`: skip the fragment on error (the composed response omits the field). Default.
- `FailClosed`: return an error on failure (the entire composed response fails).

### compose

The pure composition step: takes fragment results (already fetched +
shaped by the plugin runtime) and combines them into a single JSON
object. Fail-open fragments are skipped; fail-closed fragments cause
the entire composition to fail (with a partial response).

### extract_jsonpath

A simplified JSONPath implementation supporting:
- `$` -- the root object
- `$.field` -- a field access
- `$.field.subfield` -- nested field access
- `$.field[0]` -- array index

### make_fragment_result

Parse + shape + size-check a fragment from an upstream response body.

### make_error_fragment_result

Create an error fragment result (for when the upstream fetch fails).

### validate_spec

Validate an aggregation spec: check name, fragments, max sizes, and
duplicate target fields.

## Example: 3 upstreams with failure

```rust
use dwara_core::aggregation::*;

let spec = AggregationSpec {
    name: "user-dashboard".to_string(),
    fragments: vec![
        FragmentSpec {
            name: "user".to_string(),
            service: "user-svc".to_string(),
            path: "/users/1".to_string(),
            ..Default::default()
        },
        FragmentSpec {
            name: "profile".to_string(),
            service: "profile-svc".to_string(),
            path: "/profiles/1".to_string(),
            fail_policy: FailPolicy::FailOpen,
            ..Default::default()
        },
        FragmentSpec {
            name: "settings".to_string(),
            service: "settings-svc".to_string(),
            path: "/settings/1".to_string(),
            fail_policy: FailPolicy::FailOpen,
            ..Default::default()
        },
    ],
    ..Default::default()
};

// Fragment results (fetched by the plugin runtime).
let results = vec![
    make_fragment_result(&spec.fragments[0], r#"{"id":1,"name":"alice"}"#),
    make_fragment_result(&spec.fragments[1], r#"{"bio":"Engineer"}"#),
    make_error_fragment_result(&spec.fragments[2], "503 service unavailable"),
];

match compose(&spec, &results) {
    ComposeResult::Ok { response, warnings } => {
        // user and profile are present; settings is omitted (fail-open).
        assert!(response.get("user").is_some());
        assert!(response.get("profile").is_some());
        assert!(response.get("settings").is_none());
    }
    ComposeResult::Error { error, partial } => {
        // A fail-closed fragment errored.
    }
}
```

## Feature gate

The `aggregation` cargo feature must be enabled. Without it, the
module is not compiled.
