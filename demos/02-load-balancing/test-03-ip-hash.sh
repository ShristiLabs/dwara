#!/bin/bash
# Test 03: IP-hash load balancing.
#
# Sends 5 requests to /lb/hash/test from the same client IP and asserts
# that every response names the same echo instance. IP-hash maps a
# client IP to a deterministic endpoint, so a single source should
# always land on the same backend.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

GATEWAY="http://localhost:8080"

echo "=== Test 03: IP-Hash Load Balancing ==="

wait_for "$GATEWAY/lb/hash/test" 30 || exit 1

first_instance=""
for i in $(seq 1 5); do
  body=$(http_body "$GATEWAY/lb/hash/test")
  inst=$(echo "$body" | grep -o '"instance": *"[^"]*"' | sed 's/.*"instance": *"//;s/"//')
  echo "  request $i -> instance=$inst"
  if [ -z "$first_instance" ]; then
    first_instance="$inst"
  fi
  if [ "$inst" = "$first_instance" ]; then
    echo -e "${GREEN}PASS${NC}: request $i same instance ($inst)"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}FAIL${NC}: request $i got '$inst', expected '$first_instance'"
    FAIL=$((FAIL + 1))
  fi
done

print_summary
