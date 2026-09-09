#!/bin/bash
set -e

# Test 08: Method allowlist — /v1/methods allows GET/POST only
# PATCH should return 405 (Method Not Allowed); GET should return 200.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

BASE_URL="http://localhost:8080"

echo "=== Test 08: Method Allowlist (/v1/methods) ==="

wait_for "$BASE_URL/healthz" 30

patch_status=$(http_status "$BASE_URL/v1/methods" -X PATCH)
get_status=$(http_status "$BASE_URL/v1/methods" -X GET)

assert_status "405" "$patch_status" "PATCH /v1/methods returns 405"
assert_status "200" "$get_status" "GET /v1/methods returns 200"

print_summary
