#!/bin/bash
# test-02-active-health.sh
#
# Active health verification: both endpoints in the healthy pool are
# up and respond 200. This is a baseline sanity check that the pool is
# reachable before the resilience-specific tests run.
set -u
. "$(dirname "$0")/../_shared/helpers.sh"

echo "=== test-02: active health (healthy endpoints respond) ==="

wait_for http://localhost:8080/healthy/ 30 || exit 1

echo "--- verifying healthy-pool endpoints respond 200 ---"
ok=0
for i in $(seq 1 6); do
  status=$(http_status http://localhost:8080/healthy/)
  echo "  request $i: status=$status"
  if [ "$status" = "200" ]; then
    ok=$((ok + 1))
  fi
done

if [ "$ok" -ge 5 ]; then
  echo -e "${GREEN}PASS${NC}: healthy endpoints respond 200 ($ok/6 requests)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: healthy endpoints did not respond 200 ($ok/6 requests)"
  FAIL=$((FAIL + 1))
fi

print_summary
