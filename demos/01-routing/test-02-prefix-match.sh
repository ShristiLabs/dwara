#!/bin/bash
set -e

# Test 02: Prefix match — /v1/test proxies to echo upstream
# Verifies the `prefix` path-match type and the `proxy` action.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

BASE_URL="http://localhost:8080"

echo "=== Test 02: Prefix Match (/v1/test) ==="

wait_for "$BASE_URL/healthz" 30

status=$(http_status "$BASE_URL/v1/test")
body=$(http_body "$BASE_URL/v1/test")

assert_status "200" "$status" "GET /v1/test returns 200"
assert_contains "$body" "echo" "GET /v1/test body contains echo JSON"
assert_contains "$body" "parsed_path" "GET /v1/test body contains parsed_path field"

print_summary
