#!/bin/bash
# Test 05: CORS preflight handling.
#
# Sends an OPTIONS preflight request with an Origin and
# Access-Control-Request-Method, and asserts the gateway returns the
# configured Access-Control-Allow-Origin header.
set -euo pipefail
source ../_shared/helpers.sh

BASE="http://localhost:8080"

echo "=== Test 05: CORS ==="

HEADERS=$(curl -s -X OPTIONS \
  -H 'Origin: https://app.example.com' \
  -H 'Access-Control-Request-Method: POST' \
  -D - -o /dev/null "$BASE/v1/cors/test")

assert_contains "$HEADERS" "[Aa]ccess-[Cc]ontrol-[Aa]llow-[Oo]rigin" "Access-Control-Allow-Origin header present"
assert_contains "$HEADERS" "[Aa]ccess-[Cc]ontrol-[Aa]llow-[Mm]ethods" "Access-Control-Allow-Methods header present"
assert_contains "$HEADERS" "[Aa]ccess-[Cc]ontrol-[Aa]llow-[Hh]eaders" "Access-Control-Allow-Headers header present"

print_summary
