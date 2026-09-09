#!/bin/bash
set -e

# Test 06: Mock response — /v1/mock returns 200 with {"mock": true}
# Verifies the `mock` action with a synthetic body and delay.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

BASE_URL="http://localhost:8080"

echo "=== Test 06: Mock Response (/v1/mock) ==="

wait_for "$BASE_URL/healthz" 30

status=$(http_status "$BASE_URL/v1/mock")
body=$(http_body "$BASE_URL/v1/mock")

assert_status "200" "$status" "GET /v1/mock returns 200"
assert_contains "$body" "mock" "GET /v1/mock body contains 'mock'"

print_summary
