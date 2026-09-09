#!/bin/bash
# test-01-passive-health.sh
#
# Passive health / outlier detection: send 5 requests to the flaky
# upstream at 80% error rate, then send one more request. The flaky
# endpoint should be ejected (consecutive_failures: 3, failure_ratio:
# 0.5, failure_min_volume: 5) and the subsequent request should be
# served 200 by the healthy echo endpoint.
set -u
. "$(dirname "$0")/../_shared/helpers.sh"

echo "=== test-01: passive health (outlier detection) ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/healthy/ 30 || exit 1

# Warm the healthy pool so both endpoints are known.
curl -s -o /dev/null http://localhost:8080/healthy/

echo "--- sending 5 requests to flaky upstream (80% error rate) ---"
for i in $(seq 1 5); do
  status=$(http_status http://localhost:8080/flaky/flaky/80)
  echo "  request $i: status=$status"
  sleep 0.1
done

echo "--- sending a follow-up request; expect 200 from healthy echo ---"
status=$(http_status http://localhost:8080/flaky/test)
assert_status 200 "$status" "follow-up request served by healthy endpoint (flaky ejected)"

print_summary
