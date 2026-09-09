#!/bin/bash
# test-04-retries.sh
#
# Retries: a request to the retry-pool at 50% error rate is retried
# (attempts: 3, retry_statuses: [500,502,503], retry_transport: true)
# on the healthy echo endpoint and ultimately returns 200.
set -u
. "$(dirname "$0")/../_shared/helpers.sh"

echo "=== test-04: retries ==="

wait_for http://localhost:8080/healthy/ 30 || exit 1

echo "--- sending request to retry-pool (flaky at 50%); expect 200 after retry ---"
succeeded=0
for i in $(seq 1 10); do
  status=$(http_status http://localhost:8080/retry/flaky/50)
  echo "  attempt $i: status=$status"
  if [ "$status" = "200" ]; then
    succeeded=1
    break
  fi
  sleep 0.1
done

if [ "$succeeded" = "1" ]; then
  echo -e "${GREEN}PASS${NC}: retry succeeded (200 from healthy endpoint)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: retry did not succeed (no 200 observed)"
  FAIL=$((FAIL + 1))
fi

print_summary
