#!/bin/bash
# Test 09: WebSocket proxying.
#
# Full WebSocket testing requires a WebSocket client such as websocat:
#
#   websocat ws://localhost:8080/ws
#   (type a message; the ws-echo upstream echoes it back as "echo: <msg>")
#
# This test only verifies the WS route is reachable. A plain HTTP GET to a
# WebSocket endpoint typically returns 400/426 (upgrade required) rather
# than 404 (no route), which confirms the route is wired up.
set -euo pipefail
source ../_shared/helpers.sh

BASE="http://localhost:8080"

echo "=== Test 09: WebSocket ==="
echo "NOTE: Full WebSocket testing requires websocat:"
echo "  websocat ws://localhost:8080/ws"
echo "Verifying WS route reachability only."

STATUS=$(http_status "$BASE/ws")

# A plain GET to a WS endpoint should not 404. 400/426 (upgrade required)
# or any non-404 status means the route matched.
if [ "$STATUS" = "404" ]; then
  echo -e "${RED}FAIL${NC}: WS route returned 404 (route not matched)"
  FAIL=$((FAIL + 1))
else
  echo -e "${GREEN}PASS${NC}: WS route reachable (status $STATUS, not 404)"
  PASS=$((PASS + 1))
fi

print_summary
