#!/bin/bash
set -e

# Test 09: API versioning — /v1/test emits Deprecation + Sunset headers
# Verifies the route-level `deprecation` block emits RFC 9745 signal headers.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

BASE_URL="http://localhost:8080"

echo "=== Test 09: API Versioning (Deprecation + Sunset headers) ==="

wait_for "$BASE_URL/healthz" 30

headers=$(curl -s -D - -o /dev/null "$BASE_URL/v1/test")

assert_contains "$headers" "[Dd]eprecation" "GET /v1/test has Deprecation header"
assert_contains "$headers" "[Ss]unset" "GET /v1/test has Sunset header"

print_summary
