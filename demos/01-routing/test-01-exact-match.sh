#!/bin/bash
set -e

# Test 01: Exact match — /ping responds directly with 200 "ok"
# Verifies the `exact` path-match type and the `respond` action.
# Uses /ping (not /healthz) because /healthz is a reserved gateway
# path served before route resolution; a configured route matching
# it is permanently shadowed by the built-in liveness probe.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

BASE_URL="http://localhost:8080"

echo "=== Test 01: Exact Match (/ping) ==="

wait_for "$BASE_URL/healthz" 30

status=$(http_status "$BASE_URL/ping")
body=$(http_body "$BASE_URL/ping")

assert_status "200" "$status" "GET /ping returns 200"
assert_contains "$body" "ok" "GET /ping body is 'ok'"

print_summary
