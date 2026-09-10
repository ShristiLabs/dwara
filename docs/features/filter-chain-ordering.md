# Configurable Filter-Chain Ordering (#191, CFG-05)

## Overview

The request pipeline order was previously implicit inside the
7,371-line `proxy.rs` dispatch. This feature formalizes the pipeline
phases with a `FilterPhase` enum and adds a `filter_chain` config
block at both the gateway and route level, supporting per-phase
dry-run mode and optional ordering overrides.

## Motivation

- **Observability:** Makes the pipeline ordering observable and
  testable instead of implicit.
- **Safe policy rollout:** Per-phase dry-run enables operators to
  enable a phase in log-only mode, observe would-be rejections, then
  switch to enforcement.
- **Plugin contract:** Third-party plugins need a formal phase
  contract to know when they run relative to other phases.

## Phase model

The `FilterPhase` enum (`crates/dwara-core/src/config/mod.rs`)
defines eight phases in the default order:

```rust
pub enum FilterPhase {
    Acl,        // 1. ACL / IP allow-deny
    RateLimit,  // 2. Rate limiting
    Authn,      // 3. Authentication
    Authz,      // 4. Authorization
    Validate,   // 5. Request-body validation
    Transform,  // 6. Request transforms
    Cache,      // 7. Response-cache lookup
    Route,      // 8. Route action dispatch
}
```

The `DEFAULT_ORDER` constant is the order the dataplane has always
executed these phases. The `as_str()` method returns the
snake_case identifier used in config (`"acl"`, `"rate_limit"`, etc.).

## Configuration

### `FilterChainConfig`

```rust
pub struct FilterChainConfig {
    pub dry_run: Vec<FilterPhase>,
    pub order: Option<Vec<FilterPhase>>,
}
```

- `dry_run`: phases to run in dry-run mode (log but don't enforce).
  Defaults to empty (all phases enforce).
- `order`: optional ordering override. Must be a permutation of the
  default phase set (all eight phases, no duplicates). Defaults to
  `DEFAULT_ORDER` when absent.

### Gateway-level config

```yaml
filter_chain:
  dry_run:
    - authz
    - rate_limit
  order:
    - acl
    - authn
    - authz
    - rate_limit
    - validate
    - transform
    - cache
    - route
```

### Per-route override

```yaml
routes:
  - name: api
    service: api-service
    match:
      path: { kind: prefix, value: /api }
    filter_chain:
      dry_run:
        - authz
```

Per-route `filter_chain` takes precedence over the global
`gateway.filter_chain`, following the project's consumer > route >
service > listener > global precedence pattern.

## Validation

`validate_filter_chain` in `crates/dwara-core/src/snapshot/mod.rs`
checks:

- `order` must contain exactly eight phases.
- No duplicate phases in `order`.
- All default phases must be present in `order`.
- No duplicate phases in `dry_run`.

Validation is called for both the global `gateway.filter_chain` and
each `route.filter_chain` override. Error paths are
`filter_chain.order` and `filter_chain.dry_run`.

## Design decisions

- **Phase set:** The eight phases map to the existing implicit
  pipeline order in `handle_routed` (ACL, rate limiting, authn,
  authz, validation, transforms, cache, route dispatch). The
  formalization makes the ordering observable and testable.
- **Dry-run mode:** Per-phase dry-run enables safe policy rollout.
  The config and validation infrastructure is in place; the actual
  dry-run enforcement wiring in the dataplane is a follow-up.
- **Ordering override:** The `order` field allows operators to
  reorder phases per-route. Validation ensures the override is a
  valid permutation. The actual reordering execution in the dataplane
  is a follow-up.
- **Per-route overrides:** Per-route `filter_chain` takes precedence
  over the global `gateway.filter_chain`.

## Relationship to plugin phases

`FilterPhase` is distinct from `PluginPhase` (DW-055). `PluginPhase`
defines the four HTTP message phases a plugin hooks
(`request_headers`, `request_body`, `response_headers`,
`response_body`). `FilterPhase` defines the eight gateway pipeline
phases. Plugins run within the `Transform` and `Validate` filter
phases, depending on their `PluginPhase` declarations.

## Source files

- `crates/dwara-core/src/config/mod.rs` — `FilterPhase`,
  `FilterChainConfig`, `DEFAULT_ORDER`.
- `crates/dwara-core/src/snapshot/mod.rs` — `validate_filter_chain`.
- `crates/dwara-core/src/dataplane/proxy.rs` — the implicit pipeline
  order this feature formalizes.
