# Filter-chain ordering

The request pipeline runs through a fixed set of phases in a defined
order. You can configure per-phase dry-run mode (log but don't
enforce) and override the default ordering at both the gateway and
per-route level.

## Default phase order

The gateway executes these phases in order for every request:

1. **acl** -- ACL / IP allow-deny
2. **rate_limit** -- Rate limiting
3. **authn** -- Authentication
4. **authz** -- Authorization
5. **validate** -- Request-body validation
6. **transform** -- Request transforms
7. **cache** -- Response-cache lookup
8. **route** -- Route action dispatch

## Configuring dry-run mode

Dry-run mode runs a phase's checks but does not enforce rejection.
This enables safe policy rollout: enable a phase in dry-run, observe
would-be rejections in logs, then switch to enforcement.

```yaml
filter_chain:
  dry_run:
    - authz
    - rate_limit
```

With this config, the `authz` and `rate_limit` phases log would-be
rejections but allow requests to continue. All other phases enforce
normally.

## Overriding the phase order

The `order` field overrides the default execution order. It must be
a permutation of all eight phases (no duplicates, no missing phases).

```yaml
filter_chain:
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

This moves authentication and authorization before rate limiting.

## Per-route overrides

A route can override the gateway-level `filter_chain` configuration:

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
`gateway.filter_chain`. When a route has no `filter_chain`, the
gateway-level config applies.

## Validation

The gateway validates the `filter_chain` config at snapshot compile
time:

- `order` must contain exactly eight phases.
- No duplicate phases in `order`.
- All eight default phases must be present in `order`.
- No duplicate phases in `dry_run`.

Invalid configs are rejected before publishing.
