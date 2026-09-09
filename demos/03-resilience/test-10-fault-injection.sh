#!/bin/bash
# test-10-fault-injection.sh
#
# Fault injection: the /fault/ route injects a 100ms delay on 100% of
# requests (delay.percentage: 100, fixed_ms: 100) before proxying to the
# healthy upstream. The response is still 200, but the total latency
# exceeds 100ms.
set -u
. "$(dirname "$0")/../_shared/helpers.sh"

echo "=== test-10: fault injection (delay) ==="

wait_for http://localhost:8080/healthy/ 30 || exit 1

echo "--- sending request to /fault/test; expect 200 with > 100ms latency ---"
out=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' http://localhost:8080/fault/test)
status=$(echo "$out" | awk '{print $1}')
total_ms=$(echo "$out" | awk '{printf "%.0f", $2 * 1000}')
echo "  status=$status  total=${total_ms}ms"

assert_status 200 "$status" "fault-injected request still returns 200"

if [ "$status" = "200" ] && [ "$total_ms" -ge 100 ]; then
  echo -e "${GREEN}PASS${NC}: delay injected (${total_ms}ms >= 100ms)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: no delay observed (${total_ms}ms < 100ms)"
  FAIL=$((FAIL + 1))
fi

print_summary
