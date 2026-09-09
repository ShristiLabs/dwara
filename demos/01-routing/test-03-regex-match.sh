#!/bin/bash
set -e

# Test 03: Regex match — /v1/users/42 matches regex /v1/users/[^/]+
# Verifies the `regex` path-match type. Regex beats prefix, so this
# resolves to users-by-id, not the /v1/ prefix routes.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

BASE_URL="http://localhost:8080"

echo "=== Test 03: Regex Match (/v1/users/42) ==="

wait_for "$BASE_URL/healthz" 30

status=$(http_status "$BASE_URL/v1/users/42")
body=$(http_body "$BASE_URL/v1/users/42")

assert_status "200" "$status" "GET /v1/users/42 returns 200"
assert_contains "$body" "echo" "GET /v1/users/42 body contains echo JSON"

print_summary
