#!/bin/bash
set -e

# Test 01: Exact match — /healthz responds directly with 200 "ok"
# Verifies the `exact` path-match type and the `respond` action.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

BASE_URL="http://localhost:8080"

echo "=== Test 01: Exact Match (/healthz) ==="

wait_for "$BASE_URL/healthz" 30

status=$(http_status "$BASE_URL/healthz")
body=$(http_body "$BASE_URL/healthz")

assert_status "200" "$status" "GET /healthz returns 200"
assert_contains "$body" "ok" "GET /healthz body is 'ok'"

print_summary
