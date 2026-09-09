#!/bin/bash
# Test 04: Peak-EWMA (latency-aware) load balancing.
#
# The ewma-pool has two endpoints: echo-a (fast) and slow (adds ~200ms
# delay). The peak-EWMA balancer tracks an exponentially-weighted moving
# average of round-trip time and skews traffic toward the faster
# endpoint. This test asserts that all 5 requests return 200 (the
# balancer is healthy) and reports the instance distribution.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

GATEWAY="http://localhost:8080"

echo "=== Test 04: Peak-EWMA Load Balancing ==="

wait_for "$GATEWAY/lb/ewma/test" 30 || exit 1

for i in $(seq 1 5); do
  status=$(http_status "$GATEWAY/lb/ewma/test")
  body=$(http_body "$GATEWAY/lb/ewma/test")
  inst=$(echo "$body" | grep -o '"instance": *"[^"]*"' | sed 's/.*"instance": *"//;s/"//')
  echo "  request $i -> status=$status instance=$inst"
  assert_status 200 "$status" "peak-ewma request $i returns 200"
done

echo "  (peak-ewma should skew toward echo-a over slow)"
print_summary
