#!/bin/bash
set -e

# Test 05: Respond direct — /ping returns 200 with body "ok"
# Verifies the `respond` action returns the configured body and
# Content-Type. Uses /ping (not /healthz) because /healthz is a
# reserved gateway path whose built-in handler emits a JSON envelope
# with Content-Type application/json, shadowing any configured route.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

BASE_URL="http://localhost:8080"

echo "=== Test 05: Respond Direct (/ping Content-Type) ==="

wait_for "$BASE_URL/healthz" 30

status=$(http_status "$BASE_URL/ping")
headers=$(http_headers "$BASE_URL/ping")
body=$(http_body "$BASE_URL/ping")

assert_status "200" "$status" "GET /ping returns 200"
assert_contains "$body" "ok" "GET /ping body is 'ok'"
assert_header "$headers" "Content-Type" "text/plain" "GET /ping Content-Type is text/plain"

print_summary
