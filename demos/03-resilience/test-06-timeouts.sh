#!/bin/bash
# test-06-timeouts.sh
#
# Read timeout: the slow upstream takes 2000ms but the timeout-pool
# read_ms is 500, so the gateway returns 504 Gateway Timeout.
set -u
. "$(dirname "$0")/../_shared/helpers.sh"

echo "=== test-06: timeouts ==="

wait_for http://localhost:8080/healthy/ 30 || exit 1

echo "--- sending request to timeout-pool (slow 2000ms); expect 504 (read_ms 500) ---"
status=$(http_status http://localhost:8080/timeout/slow/2000)
echo "  status=$status"
assert_status 504 "$status" "read timeout returns 504 (read_ms 500 < 2000ms delay)"

print_summary
