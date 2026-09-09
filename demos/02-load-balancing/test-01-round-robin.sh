#!/bin/bash
# Test 01: Round-robin load balancing.
#
# Sends 10 requests to /lb/rr/test and asserts that at least two
# different echo instances (echo-a, echo-b, echo-c) are observed in
# the "instance" field of the JSON response. Round-robin with equal
# weights should distribute across all three.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

GATEWAY="http://localhost:8080"

echo "=== Test 01: Round-Robin Load Balancing ==="

wait_for "$GATEWAY/lb/rr/test" 30 || exit 1

instances=""
for i in $(seq 1 10); do
  body=$(http_body "$GATEWAY/lb/rr/test")
  inst=$(echo "$body" | grep -o '"instance": *"[^"]*"' | sed 's/.*"instance": *"//;s/"//')
  echo "  request $i -> instance=$inst"
  instances="$instances $inst"
done

# Count distinct instances.
distinct=$(echo "$instances" | tr ' ' '\n' | grep -v '^$' | sort -u | wc -l | tr -d ' ')
echo "  distinct instances seen: $distinct"

if [ "$distinct" -ge 2 ]; then
  echo -e "${GREEN}PASS${NC}: round-robin distributed across $distinct instances"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: round-robin only hit $distinct instance(s) (expected >= 2)"
  FAIL=$((FAIL + 1))
fi

print_summary
