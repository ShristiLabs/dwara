#!/bin/bash
# test-07-load-shedding.sh
#
# Load shedding: the gateway caps concurrent requests (max_concurrent_requests)
# and sheds (or queues, per admission_queue) the excess. Full shedding
# verification requires lowering max_concurrent_requests to a small value
# (e.g. 10) and flooding beyond it; this script keeps the demo config's
# high cap and instead verifies that basic requests still succeed under
# a burst of concurrent traffic (the admission queue absorbs the spike).
set -u
. "$(dirname "$0")/../_shared/helpers.sh"

echo "=== test-07: load shedding (basic requests under burst) ==="

wait_for http://localhost:8080/healthy/ 30 || exit 1

echo "--- flooding 50 concurrent requests to healthy-pool ---"
tmpdir=$(mktemp -d)
for i in $(seq 1 50); do
  curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/healthy/ > "$tmpdir/$i.out" &
done
wait

ok=0
fail=0
for i in $(seq 1 50); do
  code=$(cat "$tmpdir/$i.out")
  if [ "$code" = "200" ]; then
    ok=$((ok + 1))
  else
    fail=$((fail + 1))
  fi
done
rm -rf "$tmpdir"
echo "  results: $ok succeeded, $fail non-200"

if [ "$ok" -ge 40 ]; then
  echo -e "${GREEN}PASS${NC}: basic requests survived the burst ($ok/50 200)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: too many requests failed under burst ($ok/50 200)"
  FAIL=$((FAIL + 1))
fi

print_summary
