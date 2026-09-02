# GraphQL awareness (DW-099)

> Implements issue DW-099 (M2, `edition/oss`, effort M) over the
> request-phase filter stack. Sources:
> `crates/dwara-core/src/dataplane/graphql.rs` (the depth/complexity
> scanner, the persisted-query enforcement, the body-size cap, the
> body-replay wrapper -- its module docs carry the full contract), the
> config schema in `config/mod.rs` (`RouteGraphql`,
> `GraphqlPersistedQueries`), validation in `snapshot/mod.rs`. Tests:
> `crates/dwara-core/tests/graphql.rs` (depth and complexity limit
> enforcement, the parse-depth cap, persisted-query allow/deny, the
> body-size cap, JSON-body extraction, the disabled-checker path, config
> parsing, and the validation matrix). Operator docs:
> [docs-site gRPC & WebSockets guide](../../docs-site/guide/grpc-websockets.md).

GraphQL endpoints are uniquely abuse-prone: a single small request can
express an arbitrarily deep or wide query that amplifies into expensive
upstream work. DW-099 gives the gateway a request-phase check that
rejects abusive queries BEFORE any resource is spent on auth or rate
limiting, exactly like the WAF-lite (DW-051) and anomaly (DW-090)
phases it sits beside. Two defenses, both feature-gated behind the
`graphql` cargo feature, with zero new dependencies.

## Depth and complexity limits

The checker is a bounded hand-rolled scanner (`scan_depth_complexity`)
that walks the query string counting nesting depth (max brace nesting)
and field count (complexity). It does NOT fully parse GraphQL -- it
only counts braces and field separators, which avoids pulling in an
external GraphQL parser (and the `deny.toml` review that would
require). The scanner is bounded by two internal caps:

- **`PARSE_DEPTH_CAP` (512)**: a hard internal bound on the scanner
  itself. If brace nesting exceeds it, the scan aborts and returns a
  depth of `PARSE_DEPTH_CAP + 1`, which exceeds any reasonable
  `depth_limit` and fails the check closed. This prevents a
  deeply-nested-brace DoS against the scanner.
- **`DEFAULT_GRAPHQL_MAX_BODY_BYTES` (1 MiB)**: oversized bodies are
  rejected with 413 before any parsing begins, so a hostile client
  cannot pin memory or CPU with a huge payload.

Depth is the maximum brace-nesting level reached in the query (the
top-level operation body is depth 1). Complexity is the sum of
per-field costs: each field's cost is `cost_per_field[name]` if
present, else `complexity_coefficient` (default 1). The scanner skips
line comments (`#`), string literals (single and triple-quoted),
fragment spreads (`...Name`), and directives (`@name`) so braces inside
those do not affect the count. Keywords (`query`, `mutation`,
`fragment`, `on`, etc.) are not counted as fields.

The scanner is intentionally conservative: it may over-count fields in
edge cases (fragments, directives, aliases) but never under-count
depth. Over-counting complexity fails closed (a legitimate query
slightly over the limit is denied, which the operator can fix by
raising the limit); under-counting would fail open (an abusive query
slips through), which is the worse failure mode for a security control.

## Persisted queries

When `persisted_queries.enabled` is true, the gateway enforces that
every request's query SHA-256 hash is in the config-supplied `store`
(a map of hash to query text). This is the Apollo APQ (Automatic
Persisted Queries) + GET-by-hash variant: the client sends the query
text, the gateway computes its SHA-256 (`sha256_hex`), and verifies the
hash is known. A hash not in the store is rejected with 400
`graphql_persisted_query_required`. An external store (Redis, etc.) is
a future extension point; v1 uses a config-supplied map.

## Request-path position and body replay

The GraphQL check runs AFTER the WAF-lite filter and anomaly scoring
and BEFORE the route limits (DW-027): it is a content-shape filter that
rejects abusive queries before any resource is spent on auth or rate
limiting. It inspects the ORIGINAL request body (before transforms).
Only routes with a `graphql` block AND the `graphql` cargo feature
compiled in are inspected; routes without the block are never checked,
and when the feature is off the block is accepted but inert (the config
schema is always present, the runtime check is feature-gated).

`check_body` collects the body up to the cap, extracts the `query`
field from the JSON body (via `serde_json`, already a dependency), runs
`check_query`, and returns the collected bytes alongside the result.
The `GraphqlBody` wrapper replays those bytes so the body is not
consumed by the check and can be forwarded to the upstream -- the same
body-replay pattern as the WAF (DW-051).

## Configuration and validation

```yaml
routes:
  - name: graphql-api
    service: backend
    match:
      path: { type: prefix, value: /graphql }
    action: { type: proxy }
    graphql:
      enabled: true
      depth_limit: 10
      complexity_limit: 1000
      complexity_coefficient: 1
      cost_per_field:
        expensiveField: 50
        nested: 5
      persisted_queries:
        enabled: false
        store:
          "<sha256-hex>": "query { user { name } }"
```

Validation (`snapshot/mod.rs`) rejects, when `enabled` is true:
`depth_limit` of 0, `complexity_limit` of 0, and
`complexity_coefficient` of 0 (which would make every query free). For
the persisted-query store, every hash must be a non-empty string and
every query text must be non-empty. A disabled `graphql` block with
zero limits is accepted (the block is inert). The config schema is
always present regardless of the `graphql` cargo feature, so configs
round-trip across builds with and without the feature.

The [dataplane and proxy](./dataplane-proxy.md) page covers the request
path this filter sits on; [protocol hardening](./protocol-hardening.md)
covers the parser bounds that bound the scanner's input.
