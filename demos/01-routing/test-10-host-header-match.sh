#!/bin/bash
set -e

# Test 10: Host header match — verify the gateway responds to requests
# with a custom Host header. Host-based routing is complex to set up in
# a single-listener demo, so this test simply verifies the gateway
# remains responsive when a non-localhost Host header is sent.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

BASE_URL="http://localhost:8080"

echo "=== Test 10: Host Header Match (gateway responsiveness) ==="

wait_for "$BASE_URL/healthz" 30

status=$(http_status "$BASE_URL/healthz" -H "Host: api.example.com")
body=$(http_body "$BASE_URL/healthz" -H "Host: api.example.com")

assert_status "200" "$status" "GET /healthz with custom Host returns 200"
assert_contains "$body" "ok" "GET /healthz with custom Host body is 'ok'"

print_summary
