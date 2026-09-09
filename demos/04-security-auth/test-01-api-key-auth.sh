#!/bin/bash
# test-01-api-key-auth.sh — API key authentication.
#
# Verifies that a request with a valid X-API-Key header succeeds (200)
# and a request without the key is rejected (401).
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-01-api-key-auth ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/public/ 30 || exit 1

# Valid API key -> 200.
status=$(http_status http://localhost:8080/v1/api/test -H 'X-API-Key: demo-api-key-123')
assert_status 200 "$status" "valid API key returns 200"

# Missing API key -> 401.
status=$(http_status http://localhost:8080/v1/api/test)
assert_status 401 "$status" "missing API key returns 401"

# Invalid API key -> 401.
status=$(http_status http://localhost:8080/v1/api/test -H 'X-API-Key: wrong-key')
assert_status 401 "$status" "invalid API key returns 401"

print_summary
