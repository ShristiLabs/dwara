#!/bin/bash
# test-11-rate-limiting.sh — Per-route rate limiting (GCRA).
#
# The rate-limited-route has a demo-rate-limit policy: 5 requests per
# 10 seconds. Sending 6 rapid requests should result in the first 5
# succeeding (200) and the 6th being rejected with 429.
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-11-rate-limiting ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/public/ 30 || exit 1

# Send 6 rapid requests. The first 5 should be 200, the 6th 429.
success_count=0
limited_count=0

for i in $(seq 1 6); do
  status=$(http_status http://localhost:8080/v1/ratelimited/test)
  if [ "$status" = "200" ]; then
    success_count=$((success_count + 1))
  elif [ "$status" = "429" ]; then
    limited_count=$((limited_count + 1))
  fi
  echo "  request $i: status=$status"
done

# At least one request should be rate-limited (429).
if [ "$limited_count" -ge 1 ]; then
  echo -e "${GREEN}PASS${NC}: at least 1 request rate-limited (429)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: expected at least 1 request to be rate-limited (429)"
  FAIL=$((FAIL + 1))
fi

# At least 5 requests should have succeeded (the limit is 5/10s).
if [ "$success_count" -ge 5 ]; then
  echo -e "${GREEN}PASS${NC}: at least 5 requests succeeded (200)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: expected at least 5 requests to succeed, got $success_count"
  FAIL=$((FAIL + 1))
fi

print_summary
