#!/bin/bash
# test-03-circuit-breaker.sh
#
# Circuit breaker: flood the single flaky endpoint in breaker-pool. The
# breaker opens after the error threshold (consecutive_failures: 3,
# error_ratio: 0.5, error_volume: 5) and subsequent requests get 502/503
# instead of being forwarded to the failing upstream.
set -u
. "$(dirname "$0")/../_shared/helpers.sh"

echo "=== test-03: circuit breaker ==="

wait_for http://localhost:8080/healthy/ 30 || exit 1

echo "--- sending requests to breaker-pool (flaky at 80%) until breaker opens ---"
opened=0
for i in $(seq 1 20); do
  status=$(http_status http://localhost:8080/breaker/flaky/80)
  echo "  request $i: status=$status"
  # Breaker open returns 502 or 503 (no healthy endpoint to fall back on).
  if [ "$status" = "502" ] || [ "$status" = "503" ]; then
    opened=1
    break
  fi
  sleep 0.05
done

if [ "$opened" = "1" ]; then
  echo -e "${GREEN}PASS${NC}: circuit breaker opened (got 502/503)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: circuit breaker did not open (no 502/503 observed)"
  FAIL=$((FAIL + 1))
fi

print_summary
