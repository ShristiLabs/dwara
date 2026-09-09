#!/bin/bash
# test-12-maintenance-mode.sh
#
# Maintenance mode: the /maint/ route is configured with a maintenance
# block, so the gateway short-circuits every request with 503 and a
# Retry-After header (retry_after_secs: 60) instead of proxying.
set -u
. "$(dirname "$0")/../_shared/helpers.sh"

echo "=== test-12: maintenance mode ==="

wait_for http://localhost:8080/healthy/ 30 || exit 1

echo "--- sending request to /maint/test; expect 503 + Retry-After: 60 ---"
headers=$(http_headers http://localhost:8080/maint/test)
status=$(echo "$headers" | head -1 | awk '{print $2}')
echo "  status=$status"
echo "  headers:"
echo "$headers" | grep -i 'retry-after'

assert_status 503 "$status" "maintenance route returns 503"
assert_header "$headers" "Retry-After" "60" "Retry-After header is 60"

print_summary
