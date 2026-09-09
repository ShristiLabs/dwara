#!/bin/bash
set -e

# Test 07: Path rewrite — /v1/test proxied with strip_prefix
# The echo upstream should receive "/test" (not "/v1/test").
# Verified via the "parsed_path" field in the echo JSON response.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

BASE_URL="http://localhost:8080"

echo "=== Test 07: Path Rewrite (strip_prefix /v1/test -> /test) ==="

wait_for "$BASE_URL/healthz" 30

body=$(http_body "$BASE_URL/v1/test")

assert_contains "$body" "parsed_path" "GET /v1/test body contains parsed_path field"
assert_contains "$body" '"parsed_path": "/test"' "GET /v1/test upstream received '/test' (strip_prefix)"

print_summary
