#!/bin/bash
# test-05-hedging.sh
#
# Request hedging: a request to the slow upstream (300ms delay) triggers
# a speculative hedge copy to the healthy echo endpoint after
# hedge_after_ms: 100. The echo response wins, so the total latency is
# well under 300ms.
set -u
. "$(dirname "$0")/../_shared/helpers.sh"

echo "=== test-05: hedging ==="

wait_for http://localhost:8080/healthy/ 30 || exit 1

echo "--- sending request to hedge-pool (slow 300ms); expect 200 in < 300ms ---"

# curl -w prints timing; capture status and time_total.
out=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' http://localhost:8080/hedge/slow/300)
status=$(echo "$out" | awk '{print $1}')
total_ms=$(echo "$out" | awk '{printf "%.0f", $2 * 1000}')
echo "  status=$status  total=${total_ms}ms"

assert_status 200 "$status" "hedge request returns 200"

if [ "$status" = "200" ] && [ "$total_ms" -lt 300 ]; then
  echo -e "${GREEN}PASS${NC}: hedge response arrived in ${total_ms}ms (< 300ms, echo hedge won)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: hedge response took ${total_ms}ms (expected < 300ms)"
  FAIL=$((FAIL + 1))
fi

print_summary
