#!/bin/bash
# test-04-analytics-query.sh — embedded analytics store query.
#
# Generates traffic, waits for the analytics flush (flush_ms=100), then
# queries the mTLS admin API for the per-window dashboard series.
#
# NOTE: the admin analytics series endpoint is GET /analytics/dashboard
# (the spec referenced /analytics/series; the actual route is
# /analytics/dashboard). It requires from_ms/to_ms epoch-millisecond
# bounds and an optional gran (0..=3) + group_by.
set -euo pipefail
source ../_shared/helpers.sh

CERTS=../_shared/certs
ADMIN="https://localhost:2019"

echo "=== test-04-analytics-query ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/v1/echo/test 30 || exit 1

# Generate traffic so the analytics store has records.
for i in $(seq 1 5); do
  curl -s -o /dev/null http://localhost:8080/v1/echo/test
done

# Wait for the analytics flush (flush_ms=100) plus margin.
sleep 2

# Query the dashboard series over the last 5 minutes.
now_ms=$(($(date +%s) * 1000))
from_ms=$((now_ms - 300000))

status=$(http_status \
  "${ADMIN}/analytics/dashboard?from_ms=${from_ms}&to_ms=${now_ms}&gran=0" \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_status 200 "$status" "admin /analytics/dashboard returns 200"

# The body should contain a points array (series data).
body=$(http_body \
  "${ADMIN}/analytics/dashboard?from_ms=${from_ms}&to_ms=${now_ms}&gran=0" \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_contains "$body" "points" "dashboard response contains points"

print_summary
