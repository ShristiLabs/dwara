#!/bin/bash
# Test 07: Response caching (TTL + stale-while-revalidate).
#
# Requests a cacheable JSON file twice. A cache hit is indicated either by
# an Age header on the second response or by the second response being
# served faster than the first.
set -euo pipefail
source ../_shared/helpers.sh

BASE="http://localhost:8080"

echo "=== Test 07: Response Caching ==="

# Prime the cache with a first request.
curl -s -o /dev/null "$BASE/v1/cache/api/users.json"

# Second request: look for an Age header (cache hit indicator).
HEADERS=$(curl -s -I "$BASE/v1/cache/api/users.json")
if echo "$HEADERS" | grep -qi "^Age:"; then
  echo -e "${GREEN}PASS${NC}: Second response has Age header (cache hit)"
  PASS=$((PASS + 1))
else
  # Fallback: compare request timings. A cached response should be faster.
  T1=$(curl -s -o /dev/null -w '%{time_total}' "$BASE/v1/cache/api/users.json")
  T2=$(curl -s -o /dev/null -w '%{time_total}' "$BASE/v1/cache/api/users.json")
  if awk "BEGIN{exit !($T2 < $T1)}"; then
    echo -e "${GREEN}PASS${NC}: Second request faster ($T2 < $T1s) - likely cached"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}FAIL${NC}: No Age header and second request not faster ($T1 vs $T2s)"
    FAIL=$((FAIL + 1))
  fi
fi

print_summary
