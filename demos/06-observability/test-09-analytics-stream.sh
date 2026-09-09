#!/bin/bash
# test-09-analytics-stream.sh — real-time analytics NDJSON firehose.
#
# Generates traffic, waits for the analytics-stream flush (flush_ms=
# 1000), then queries the webhook-receiver's /events endpoint and
# asserts that analytics-stream batches (POSTed to /analytics) were
# received.
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-09-analytics-stream ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/v1/echo/test 30 || exit 1

# Generate traffic so the analytics stream has records to flush.
for i in $(seq 1 10); do
  curl -s -o /dev/null http://localhost:8080/v1/echo/test
done

# Wait for the analytics-stream flush (flush_ms=1000) plus margin.
sleep 3

# The webhook-receiver stores every received POST in /tmp/events.jsonl
# and exposes them via GET /events. Analytics-stream batches are POSTed
# to /analytics; event webhooks are POSTed to /events. Both land in the
# same ledger, so /events returns the union.
resp=$(http_body http://localhost:8081/events 2>/dev/null || echo "")
status=$(http_status http://localhost:8081/events)
assert_status 200 "$status" "webhook-receiver /events is reachable"

# The receiver logs every POST with its path. An analytics-stream
# batch is POSTed to /analytics, so the ledger should contain a path
# entry for /analytics.
if [ -n "$resp" ]; then
  assert_contains "$resp" "/analytics" "webhook-receiver received analytics-stream batches"
else
  echo -e "${RED}FAIL${NC}: webhook-receiver returned an empty event ledger"
  FAIL=$((FAIL + 1))
fi

print_summary
