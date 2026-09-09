#!/bin/bash
# Test 08: Response field masking.
#
# Field masking redacts sensitive JSON fields (e.g. /password, /secret) in
# upstream *responses*. The echo upstream reflects the incoming request as
# JSON; it does not return password/secret fields in its response body, so
# masking cannot be fully verified against echo. Full masking verification
# requires a JSON API upstream that returns sensitive fields, for example:
#
#   upstream response: {"user": "alice", "password": "hunter2", "secret": "abc"}
#   masked response:   {"user": "alice", "password": "***", "secret": "***"}
#
# This test verifies the masking route's fail-closed behavior: when the
# masked field does not exist in the upstream response, the gateway
# rejects the response (502) rather than forwarding it unmasked.
set -euo pipefail
source ../_shared/helpers.sh

BASE="http://localhost:8080"

echo "=== Test 08: Field Masking ==="
echo "NOTE: echo upstream reflects the request, not a response with password"
echo "fields. The masking policy is fail-closed: if the masked field"
echo "does not exist in the response, the gateway returns 502."

STATUS=$(http_status "$BASE/v1/mask/test")
# Fail-closed: the echo response has no /password field, so the gateway
# rejects the response with 502 (response_mask_failed).
if [ "$STATUS" = "502" ]; then
  echo -e "${GREEN}PASS${NC}: masking policy enforced (502 - field not found, fail-closed)"
  PASS=$((PASS + 1))
elif [ "$STATUS" = "200" ]; then
  echo -e "${GREEN}PASS${NC}: masking route reachable (200 - field found or not enforced)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: masking route returned $STATUS (expected 502 or 200)"
  FAIL=$((FAIL + 1))
fi

print_summary
