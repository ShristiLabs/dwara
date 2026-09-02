# GraphQL awareness

Dwara understands [GraphQL](https://graphql.org/) (a query language for APIs
where a single endpoint accepts arbitrary query shapes) traffic on any HTTP
listener. A GraphQL route is matched like any other path, and the gateway
parses the operation so it can apply depth and complexity limits, enforce
persisted-query mode, and emit per-operation metrics -- without needing a
separate GraphQL server of its own.

## When to use this

Use the GraphQL block when a route fronts a GraphQL upstream and you need to
protect it from expensive queries (deeply nested selections, high fan-out),
restrict ad-hoc queries in production to a pre-registered allowlist, or tag
analytics by operation name rather than by path alone. A route without the
block forwards GraphQL traffic untouched -- the gateway still proxies it, it
just does not parse or police the operation.

## Configuration

Add a `graphql` block to the route. The gateway introspects the request body
of `POST` requests with a GraphQL content type, parses the operation, and
applies the limits before the request reaches the upstream.

```yaml
routes:
  - name: graphql-api
    service: graphql-svc
    match:
      path: { type: exact, value: /graphql }
    graphql:
      max_depth: 10
      max_complexity: 1000
      max_aliases: 50
      persisted_queries:
        enabled: true
        allow_unpersisted: false
        store: /etc/dwara/persisted-queries.json
    action: { type: proxy }
```

## Depth and complexity limits

`max_depth` caps how deeply a selection set may nest. A query that selects
fields beyond the configured depth is rejected with `400` and an error body
shaped like a GraphQL error response -- the upstream never sees it.

`max_complexity` scores a query by assigning each field a cost of one (unless
your schema declares custom cost directives) and summing across the selection
tree; a query over the budget is rejected the same way. `max_aliases` caps the
total number of aliases in a query, the standard guard against
batching/aliasing abuse that bypasses a simple depth check.

All three limits are independent -- set any subset. A rejected query is
logged server-side with the operation name and the limit it tripped; the
client error stays generic.

## Persisted queries

Persisted-query mode trades flexibility for safety: clients send a query hash
instead of the query text, and the gateway resolves the hash to a
pre-registered query before forwarding. This eliminates ad-hoc queries in
production and shrinks request payloads.

With `enabled: true` and `allow_unpersisted: false`, a request that carries
only a hash the gateway cannot resolve is rejected with `400`. Set
`allow_unpersisted: true` to let clients send the full query text alongside
the hash the first time they use it (the gateway caches it for next time) --
useful during rollout, tighten it once every client has registered.

The `store` file is a JSON map of hash to query text, loaded at config
publish and reloaded on config change. A missing or unreadable store fails
validation -- an empty persisted-query mode with no registered queries is an
authoring mistake.

## Observability

GraphQL decisions surface in [`/metrics`](./observability) as
`dwara_graphql_policy_total{route,outcome}` with outcomes `depth_exceeded`,
`complexity_exceeded`, `aliases_exceeded`, and `persisted_miss`. The
operation name, when present, is added to the access log entry for the
request, so analytics can group traffic by operation rather than by the
single `/graphql` path.
