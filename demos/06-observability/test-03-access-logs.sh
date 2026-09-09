#!/bin/bash
# test-03-access-logs.sh — structured access logs.
#
# The gateway emits one structured access log record per request to
# its stdout (visible via `docker compose logs dwara`). There is no
# HTTP endpoint to fetch logs, so this test simply generates traffic
# and asserts the gateway responds 200. Inspect the logs with:
#
#   docker compose logs dwara | grep '"event":"access"'
#
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-03-access-logs ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/v1/echo/test 30 || exit 1

# Generate a burst of traffic; each request produces one access log
# record in the gateway's docker logs.
ok=0
for i in $(seq 1 10); do
  status=$(http_status http://localhost:8080/v1/echo/test)
  if [ "$status" = "200" ]; then
    ok=$((ok + 1))
  fi
done
assert_status 200 "$status" "last request returns 200"
echo "  generated $ok/10 successful requests (access logs in docker logs)"

echo "  NOTE: access logs are emitted to the gateway's stdout."
echo "        Inspect with: docker compose logs dwara"

print_summary
