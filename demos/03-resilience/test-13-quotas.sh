#!/bin/bash
# test-13-quotas.sh -- consumer request quotas (DW-033).
#
# The /quota/ route requires authentication; the quota-user consumer
# authenticates with X-API-Key: quota-demo-key and carries a
# daily_requests: 5 budget. Quotas are budgets, not rates: the counter
# never replenishes inside the UTC day, so after 5 accepted requests
# every further request answers 429 with Retry-After (seconds until UTC
# midnight) and the X-RateLimit-* family. Counters live in the SQLite
# state store (DWARA_STATE_DB) and are readable on the mTLS admin API
# via GET /quotas/usage.
#
# NOTE on re-runs: the budget is per UTC day and persists in ./data
# (the state-store bind mount). Re-running the test on the same day
# without resetting will see the budget already spent. Reset with:
#   docker compose down && rm -f data/state.db && docker compose up -d
set -u
. "$(dirname "$0")/../_shared/helpers.sh"

BASE="http://localhost:8080"
ADMIN="https://localhost:2019"
CERTS="$(cd "$(dirname "$0")/../_shared/certs" && pwd)"
KEY="quota-demo-key"
BUDGET=5

echo "=== test-13: consumer quotas ==="

wait_for "$BASE/healthy/" 30 || exit 1

# --- 0. Route requires authentication: anonymous -> 401 -------------------
status=$(http_status "$BASE/quota/test")
assert_status 401 "$status" "anonymous request to /quota/ is rejected 401"

# --- 1. Spend the budget: requests 1..BUDGET -> 200 -----------------------
# (No warm-up/probe request here: EVERY authenticated request reserves
# a budget unit, so an extra curl would shift the boundary by one.)
for i in $(seq 1 "$BUDGET"); do
  status=$(http_status "$BASE/quota/test" -H "X-API-Key: $KEY")
  echo "  request $i -> $status"
  if [ "$status" = "429" ] && [ "$i" = "1" ]; then
    echo -e "${YELLOW}NOTE${NC}: budget already consumed today (state DB persists"
    echo "across runs). Reset with: docker compose down && rm -f data/state.db && docker compose up -d"
  fi
  assert_status 200 "$status" "request $i within budget returns 200"
done

# --- 2. Over budget: request BUDGET+1 -> 429 + Retry-After ----------------
headers=$(http_headers "$BASE/quota/test" -H "X-API-Key: $KEY" -X GET)
status=$(echo "$headers" | head -1 | awk '{print $2}')
body=$(http_body "$BASE/quota/test" -H "X-API-Key: $KEY")
echo "  over-budget response headers:"
echo "$headers" | grep -iE 'retry-after|x-ratelimit' || true
assert_status 429 "$status" "request $((BUDGET + 1)) over budget returns 429"
# The 429 reuses the rate-limit client-facing contract: the same JSON
# envelope code (rate_limit_exceeded) plus Retry-After / X-RateLimit-*.
assert_contains "$body" "rate_limit_exceeded" "error code is rate_limit_exceeded"

retry_after=$(echo "$headers" | grep -i '^Retry-After:' | sed 's/^[^:]*: *//' | tr -d '\r')
if [ -n "$retry_after" ] && [ "$retry_after" -ge 1 ] 2>/dev/null; then
  echo -e "${GREEN}PASS${NC}: Retry-After present and >= 1 (got $retry_after)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: Retry-After missing or < 1 (got '$retry_after')"
  FAIL=$((FAIL + 1))
fi

assert_header "$headers" "X-RateLimit-Limit" "$BUDGET" "X-RateLimit-Limit is the daily budget"
assert_header "$headers" "X-RateLimit-Remaining" "0" "X-RateLimit-Remaining is 0"

# --- 3. Admin API usage report --------------------------------------------
# GET /quotas/usage (mTLS): the daily counter must show BUDGET used of
# BUDGET, remaining 0 (the denied request does not consume budget).
usage=$(curl -s --cacert "$CERTS/server.crt" \
  --cert "$CERTS/client.crt" --key "$CERTS/client.key" \
  "$ADMIN/quotas/usage?consumer=quota-user")
echo "  admin /quotas/usage: $usage"
assert_contains "$usage" '"consumer": *"quota-user"' "usage report names quota-user"
assert_contains "$usage" '"budget": *"daily"' "usage report carries the daily budget"
assert_contains "$usage" "\"limit\": *$BUDGET" "usage report shows limit $BUDGET"
assert_contains "$usage" "\"used\": *$BUDGET" "usage report shows $BUDGET requests used"

# --- 4. The quota denial is observable on /metrics ------------------------
# (Prometheus text exposition orders labels alphabetically: budget,
# consumer.) The counter plus the scrape-time usage gauges make the
# budget observable without the admin API.
metrics=$(http_body "$BASE/metrics")
assert_contains "$metrics" 'dwara_quota_denied_total{budget="daily",consumer="quota-user"}' \
  "dwara_quota_denied_total counter is exported for quota-user/daily"
assert_contains "$metrics" 'dwara_quota_used{budget="daily",consumer="quota-user"}' \
  "dwara_quota_used gauge is exported for quota-user/daily"

print_summary
