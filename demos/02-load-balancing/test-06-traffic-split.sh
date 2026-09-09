#!/bin/bash
# Test 06: Weighted traffic split.
#
# The split-service sends 90% of traffic to rr-pool (echo-a/b/c) and
# 10% to lr-pool (echo-a/b/c). Both pools draw from the same three
# echo instances, so the "instance" field alone cannot distinguish the
# pool. Instead this test asserts that the split is exercised: over 20
# requests at least two distinct instances are seen (proving traffic
# is being distributed, not pinned to one backend).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

GATEWAY="http://localhost:8080"

echo "=== Test 06: Traffic Split ==="

wait_for "$GATEWAY/lb/split/test" 30 || exit 1

instances=""
for i in $(seq 1 20); do
  body=$(http_body "$GATEWAY/lb/split/test")
  inst=$(echo "$body" | grep -o '"instance": *"[^"]*"' | sed 's/.*"instance": *"//;s/"//')
  echo "  request $i -> instance=$inst"
  instances="$instances $inst"
done

# Count distinct instances seen across both pools.
distinct=$(echo "$instances" | tr ' ' '\n' | grep -v '^$' | sort -u | wc -l | tr -d ' ')
echo "  distinct instances seen: $distinct"

if [ "$distinct" -ge 2 ]; then
  echo -e "${GREEN}PASS${NC}: traffic split distributed across $distinct instances"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: traffic split only hit $distinct instance(s) (expected >= 2)"
  FAIL=$((FAIL + 1))
fi

print_summary
