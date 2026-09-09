#!/bin/bash
# Test 02: Query transforms (add query params on the forwarded request).
#
# Sends a request with no query string and verifies the gateway adds
# `source=gateway` before forwarding. The echo upstream reflects the
# parsed query string in its JSON body.
set -euo pipefail
source ../_shared/helpers.sh

BASE="http://localhost:8080"

echo "=== Test 02: Query Transforms ==="

BODY=$(curl -s "$BASE/v1/transforms/test")

# The echo body contains a "query" object reflecting parsed query params.
assert_contains "$BODY" "source" "Upstream received added 'source' query param"
assert_contains "$BODY" "gateway" "source param value is gateway"

print_summary
