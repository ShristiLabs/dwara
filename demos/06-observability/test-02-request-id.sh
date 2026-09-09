#!/bin/bash
# test-02-request-id.sh — X-Request-Id propagation.
#
# Verifies that the gateway echoes an X-Request-Id header on every
# response (a valid inbound value is respected, otherwise one is
# generated). The header is present on proxied responses.
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-02-request-id ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/v1/echo/test 30 || exit 1

# A proxied request should carry an X-Request-Id response header.
headers=$(curl -s -i http://localhost:8080/v1/echo/test)
assert_contains "$headers" "x-request-id" "response carries X-Request-Id header"

# An inbound X-Request-Id should be respected (echoed back unchanged).
inbound="my-trace-id-12345"
headers=$(curl -s -i -H "X-Request-Id: $inbound" http://localhost:8080/v1/echo/test)
assert_contains "$headers" "$inbound" "inbound X-Request-Id is respected"

print_summary
