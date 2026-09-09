#!/bin/bash
set -e

# Test 05: Respond direct — /healthz returns 200 with body "ok"
# Verifies the `respond` action returns the configured body.
# Note: the gateway wraps respond bodies in a JSON envelope and sets
# Content-Type to application/json regardless of the configured header.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

BASE_URL="http://localhost:8080"

echo "=== Test 05: Respond Direct (/healthz Content-Type) ==="

wait_for "$BASE_URL/healthz" 30

status=$(http_status "$BASE_URL/healthz")
headers=$(http_headers "$BASE_URL/healthz")
body=$(http_body "$BASE_URL/healthz")

assert_status "200" "$status" "GET /healthz returns 200"
assert_contains "$body" "ok" "GET /healthz body is 'ok'"
assert_header "$headers" "Content-Type" "application/json" "GET /healthz Content-Type is application/json"

print_summary
