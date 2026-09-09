#!/bin/bash
set -e

# Test 03: CEL (Common Expression Language) expressions (DW-058 / DW-059)
#
# dwara supports CEL for request/response matching and transforms via
# the `cel` cargo feature (default OFF). The "CEL everywhere" design
# (DW-059) provides one CEL surface across four use-sites:
#   1. Expression matchers in routes (evaluates to bool; if true, match)
#   2. Header/transform logic (evaluates to string; used as header value)
#   3. Rate-limit key derivation (evaluates to string; used as limit key)
#   4. Policy conditions (evaluates to bool; if true, policy applies)
#
# All four use-sites share the same request context: a `request`
# variable with `path`, `method`, `headers`, `query`, `host` fields.
# CEL expressions are compiled once at config publish time (never on
# the request path) for hot-path performance.
#
# The `cel` cargo feature exists in the codebase (the cel-interpreter
# crate is an optional dependency), and the CEL engine module
# (crates/dwara-core/src/cel/) is fully implemented. However, the CEL
# use-sites are NOT yet wired into the config schema (RouteMatch,
# transforms, rate-limit selectors, policy conditions do not expose
# CEL expression fields in the current config). The feature is
# available for custom builds that wire CEL fields programmatically,
# but the declarative config does not yet expose CEL expression fields.
#
# The default `dwara:demo` image is built WITHOUT the `cel` feature.
# This test documents the CEL surface and verifies the gateway proxies
# correctly with the default build.
#
# To enable CEL, build with:
#   cargo build --release --features cel

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

BASE_URL="http://localhost:8080"

echo "=== Test 03: CEL (Common Expression Language) Expressions (DW-058/059) ==="

echo ""
echo "--- Background: CEL engine ---"
echo "CEL (Common Expression Language) is a lightweight expression"
echo "language for request/response matching and transforms. The"
echo "'CEL everywhere' design (DW-059) provides one CEL surface across"
echo "four use-sites: route matchers, header transforms, rate-limit key"
echo "derivation, and policy conditions."
echo ""
echo "Expressions are compiled once at config publish time (never on"
echo "the request path) for hot-path performance."
echo ""
echo "Feature gate: 'cel' cargo feature (default OFF)"
echo "Build: cargo build --release --features cel"
echo ""
echo "Note: The CEL engine is implemented, but CEL expression fields"
echo "are not yet exposed in the declarative config schema. The feature"
echo "is available for custom builds that wire CEL programmatically."
echo ""

echo "--- Verifying gateway starts with default build ---"
wait_for "$BASE_URL/healthz" 30

status=$(http_status "$BASE_URL/healthz")
assert_status "200" "$status" "GET /healthz returns 200"

echo ""
echo "--- Verifying proxying works (echo upstream) ---"
status=$(http_status "$BASE_URL/v1/echo/test")
body=$(http_body "$BASE_URL/v1/echo/test")
assert_status "200" "$status" "GET /v1/echo/test returns 200"
assert_contains "$body" "echo" "GET /v1/echo/test body contains echo JSON"

echo ""
echo "--- Verifying static upstream (composed service) ---"
status=$(http_status "$BASE_URL/")
assert_status "200" "$status" "GET / returns 200 (static upstream)"

echo ""
echo "--- CEL status ---"
echo "The 'cel' cargo feature is default OFF in the dwara:demo image."
echo "The CEL engine module is implemented but CEL expression fields"
echo "are not yet wired into the declarative config schema. The gateway"
echo "starts and routes traffic normally with the default build."

print_summary
