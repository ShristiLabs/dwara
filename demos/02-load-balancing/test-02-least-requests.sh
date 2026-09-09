#!/bin/bash
# Test 02: Least-requests load balancing.
#
# Sends 5 requests to /lb/lr/test and asserts that every response is
# 200 OK. The least-requests balancer picks the endpoint with the
# fewest in-flight requests, so all requests should succeed.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

GATEWAY="http://localhost:8080"

echo "=== Test 02: Least-Requests Load Balancing ==="

wait_for "$GATEWAY/lb/lr/test" 30 || exit 1

for i in $(seq 1 5); do
  status=$(http_status "$GATEWAY/lb/lr/test")
  body=$(http_body "$GATEWAY/lb/lr/test")
  inst=$(echo "$body" | grep -o '"instance": *"[^"]*"' | sed 's/.*"instance": *"//;s/"//')
  echo "  request $i -> status=$status instance=$inst"
  assert_status 200 "$status" "least-requests request $i returns 200"
done

print_summary
