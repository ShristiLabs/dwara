#!/bin/bash
# test-11-mirroring.sh
#
# Traffic mirroring: the /mirror-test/ route proxies to main-service
# (healthy-pool) and mirrors 100% of traffic to mirror-pool (the mirror
# echo instance). The client still gets the 200 response from the main
# service; the mirror copy is fire-and-forget.
set -u
. "$(dirname "$0")/../_shared/helpers.sh"

echo "=== test-11: mirroring ==="

wait_for http://localhost:8080/healthy/ 30 || exit 1

echo "--- sending request to /mirror-test/test; expect 200 from main-service ---"
status=$(http_status http://localhost:8080/mirror-test/test)
echo "  status=$status"
assert_status 200 "$status" "mirror-test returns 200 from main-service"

# Send a few more so the mirror copy is observable in the mirror logs.
for i in $(seq 1 3); do
  curl -s -o /dev/null http://localhost:8080/mirror-test/test
done

print_summary
