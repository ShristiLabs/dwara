#!/bin/bash
# Test 06: Response compression (gzip/brotli negotiation).
#
# Requests a JSON file from the static upstream with Accept-Encoding: gzip
# and asserts the gateway compresses the response (Content-Encoding: gzip).
# The static upstream serves api/users.json as application/json, which is
# above the configured min_size of 100 bytes.
set -euo pipefail
source ../_shared/helpers.sh

BASE="http://localhost:8080"

echo "=== Test 06: Compression ==="

HEADERS=$(curl -s -H 'Accept-Encoding: gzip' -D - -o /dev/null "$BASE/v1/compress/api/users.json")

assert_contains "$HEADERS" "[Cc]ontent-[Ee]ncoding: gzip" "Content-Encoding: gzip present"

print_summary
