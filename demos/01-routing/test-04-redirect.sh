#!/bin/bash
set -e

# Test 04: Redirect — /old redirects to /v1/ with 301
# Verifies the `redirect` action.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

BASE_URL="http://localhost:8080"

echo "=== Test 04: Redirect (/old -> /v1/ 301) ==="

wait_for "$BASE_URL/healthz" 30

headers=$(http_headers "$BASE_URL/old")
status=$(echo "$headers" | head -1 | awk '{print $2}')

assert_status "301" "$status" "GET /old returns 301"
assert_contains "$headers" "[Ll]ocation" "GET /old response has Location header"
assert_contains "$headers" "/v1/" "GET /old Location points to /v1/"

print_summary
