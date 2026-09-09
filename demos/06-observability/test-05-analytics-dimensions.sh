#!/bin/bash
# test-05-analytics-dimensions.sh — custom request-header dimensions.
#
# Sends a request tagged with the X-API-Version custom dimension,
# waits for the analytics flush, then queries the mTLS admin API
# (POST /analytics/dimensions) for the dimension rollup and asserts
# the dimension data is present.
set -euo pipefail
source ../_shared/helpers.sh

CERTS=../_shared/certs
ADMIN="https://localhost:2019"

echo "=== test-05-analytics-dimensions ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/v1/echo/test 30 || exit 1

# Send several requests carrying the X-API-Version dimension header.
for i in $(seq 1 5); do
  curl -s -o /dev/null -H 'X-API-Version: 2' http://localhost:8080/v1/echo/test
done

# Wait for the analytics flush (flush_ms=100) plus margin.
sleep 2

# Query the custom-dimension rollup over the last 5 minutes.
now_ms=$(($(date +%s) * 1000))
from_ms=$((now_ms - 300000))
body='{"from_ms":'"$from_ms"',"to_ms":'"$now_ms"',"gran":0,"dim":"api_version","value":"2"}'

status=$(http_status \
  "${ADMIN}/analytics/dimensions" \
  -X POST \
  -H 'Content-Type: application/json' \
  -d "$body" \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_status 200 "$status" "admin /analytics/dimensions returns 200"

resp=$(http_body \
  "${ADMIN}/analytics/dimensions" \
  -X POST \
  -H 'Content-Type: application/json' \
  -d "$body" \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_contains "$resp" "rows" "dimension query response contains rows"
assert_contains "$resp" "api_version" "dimension data references api_version"

print_summary
