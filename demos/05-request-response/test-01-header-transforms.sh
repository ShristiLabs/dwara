#!/bin/bash
# Test 01: Header transforms (set / add / remove on request; set on response).
#
# Sends a request carrying X-Internal-Token and verifies that the gateway:
#   - sets X-Forwarded-By: dwara and X-Request-Source: demo on the upstream
#     request (the echo upstream reflects received headers in its JSON body),
#   - adds X-Gateway-Version: v1,
#   - removes X-Internal-Token before forwarding,
#   - sets X-Served-By: dwara-demo on the response.
set -euo pipefail
source ../_shared/helpers.sh

BASE="http://localhost:8080"

echo "=== Test 01: Header Transforms ==="

# Fetch response body and headers together. The echo upstream reflects the
# request headers it received in the JSON "headers" field of the body.
TMP=$(mktemp)
BODY=$(curl -s -D "$TMP" -H 'X-Internal-Token: secret' "$BASE/v1/transforms/test")
HEADERS=$(cat "$TMP")
rm -f "$TMP"

# Response headers: X-Served-By: dwara-demo (set by response transform).
assert_contains "$HEADERS" "[Xx]-[Ss]erved-[Bb]y: dwara-demo" "Response has X-Served-By: dwara-demo"

# Upstream received X-Forwarded-By: dwara (set by request transform).
assert_contains "$BODY" "[Xx]-[Ff]orwarded-[Bb]y" "Echo received X-Forwarded-By header"
assert_contains "$BODY" "[Xx]-[Rr]equest-[Ss]ource" "Echo received X-Request-Source header"
assert_contains "$BODY" "[Xx]-[Gg]ateway-[Vv]ersion" "Echo received X-Gateway-Version header"

# Verify the set values.
assert_contains "$BODY" "dwara" "X-Forwarded-By value is dwara"
assert_contains "$BODY" "demo" "X-Request-Source value is demo"

# X-Internal-Token must NOT be present in the upstream request headers.
assert_not_contains "$BODY" "[Xx]-[Ii]nternal-[Tt]oken" "X-Internal-Token removed before forwarding"

print_summary
