#!/bin/bash
# test-04-graphql-awareness.sh — GraphQL awareness (DW-099). FULLY WIRED.
#
# The /graphql route fronts the echo upstream (standing in for a GraphQL
# server) with an ENABLED `graphql` block:
#   depth_limit: 4, complexity_limit: 12
# The /graphql-apq route additionally enables persisted-query
# enforcement with a one-entry store (the SHA-256 of the literal query
# text "{ hello }").
#
# The gateway parses the operation BEFORE the route limits and
# authentication and rejects abusive queries with 400; passing queries
# are proxied to the upstream untouched. All four behaviors below are
# live-enforced (this is the one block in this category whose runtime
# path is dispatched end to end).
set -u
. "$(dirname "$0")/../_shared/helpers.sh"

echo "=== test-04: GraphQL awareness ==="

wait_for http://localhost:8080/healthz 30 || exit 1

# ---------------------------------------------------------------------------
# 1) A shallow, cheap query passes and is proxied to the upstream.
# ---------------------------------------------------------------------------
echo "--- POST /graphql { hello { world } } (depth 2, complexity 2) ---"
status=$(http_status "http://localhost:8080/graphql" -X POST -H "Content-Type: application/json" \
  -d '{"query":"{ hello { world } }"}')
body=$(http_body "http://localhost:8080/graphql" -X POST -H "Content-Type: application/json" \
  -d '{"query":"{ hello { world } }"}')
echo "  status=$status"

assert_status 200 "$status" "query within depth/complexity limits is accepted"
assert_contains "$body" '"query"' \
  "passing query is proxied to the upstream (echo reflects the GraphQL body)"

# ---------------------------------------------------------------------------
# 2) Depth bomb: 5 levels of nesting > depth_limit 4 -> 400.
# ---------------------------------------------------------------------------
echo "--- POST /graphql depth-5 query (limit 4) ---"
deep_query='{ a { b { c { d { e } } } } }'
status=$(http_status "http://localhost:8080/graphql" -X POST -H "Content-Type: application/json" \
  -d "{\"query\":\"$deep_query\"}")
body=$(http_body "http://localhost:8080/graphql" -X POST -H "Content-Type: application/json" \
  -d "{\"query\":\"$deep_query\"}")
echo "  status=$status body=$(echo "$body" | head -c 200)"

assert_status 400 "$status" "query deeper than depth_limit is rejected with 400"
assert_contains "$body" "graphql_depth_exceeded" \
  "rejection code is graphql_depth_exceeded (upstream never sees the query)"

# ---------------------------------------------------------------------------
# 3) Wide query: 13 fields at depth 1 > complexity_limit 12 -> 400.
# ---------------------------------------------------------------------------
echo "--- POST /graphql 13-field query (complexity limit 12) ---"
wide_query='{ f1 f2 f3 f4 f5 f6 f7 f8 f9 f10 f11 f12 f13 }'
status=$(http_status "http://localhost:8080/graphql" -X POST -H "Content-Type: application/json" \
  -d "{\"query\":\"$wide_query\"}")
body=$(http_body "http://localhost:8080/graphql" -X POST -H "Content-Type: application/json" \
  -d "{\"query\":\"$wide_query\"}")
echo "  status=$status body=$(echo "$body" | head -c 200)"

assert_status 400 "$status" "query over the complexity budget is rejected with 400"
assert_contains "$body" "graphql_complexity_exceeded" \
  "rejection code is graphql_complexity_exceeded"

# ---------------------------------------------------------------------------
# 4) Persisted queries: the hash of "{ hello }" is in the store;
#    any other query text is rejected.
# ---------------------------------------------------------------------------
echo "--- POST /graphql-apq { hello } (hash registered in the store) ---"
status=$(http_status "http://localhost:8080/graphql-apq" -X POST -H "Content-Type: application/json" \
  -d '{"query":"{ hello }"}')
echo "  status=$status"
assert_status 200 "$status" "query whose SHA-256 is in the persisted store is accepted"

echo "--- POST /graphql-apq { other } (hash NOT in the store) ---"
status=$(http_status "http://localhost:8080/graphql-apq" -X POST -H "Content-Type: application/json" \
  -d '{"query":"{ other }"}')
body=$(http_body "http://localhost:8080/graphql-apq" -X POST -H "Content-Type: application/json" \
  -d '{"query":"{ other }"}')
echo "  status=$status body=$(echo "$body" | head -c 200)"

assert_status 400 "$status" "query with an unregistered hash is rejected with 400"
assert_contains "$body" "graphql_persisted_query_required" \
  "rejection code is graphql_persisted_query_required"

print_summary
