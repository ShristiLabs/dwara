#!/bin/bash
# test-07-federated-analytics.sh — Federated analytics (enterprise feature).
#
# Federated analytics (DW-095) is an enterprise feature: edge-to-
# controller gRPC streaming via the PublishAnalytics RPC. Each edge
# gateway streams its access records to a central controller for
# fleet-wide aggregation. See crates/dwara-core/src/ai/analytics.rs
# (FederatedAnalyticsSink implements AnalyticsSink, AnalyticsCollector
# trait for controller-side aggregation; Ent-only).
#
# The OSS edition ships the embedded analytics store (DW-043): every
# completed request's access record is written to a local SQLite file
# with 1m/5m/1h/1d additive rollups and per-granularity retention. The
# config includes an `analytics` block that enables this local store.
#
# This test verifies the local analytics store is active by checking
# the admin API's stats endpoint (which serves from the analytics store).
set -euo pipefail
source ../_shared/helpers.sh

CERTS_DIR="../_shared/certs"

echo "=== test-07-federated-analytics ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/healthz 30 || exit 1

# Generate some traffic so the analytics store has records.
for i in 1 2 3 4 5; do
  http_status http://localhost:8080/v1/echo/test > /dev/null
done

# Brief pause for the fire-and-forget writer to flush.
sleep 2

# Verify the admin API /stats endpoint returns 200 (the local
# analytics store is active and serving data).
stats_status=$(curl -s -o /dev/null -w '%{http_code}' \
  --cert "$CERTS_DIR/client.crt" \
  --key "$CERTS_DIR/client.key" \
  --cacert "$CERTS_DIR/server.crt" \
  https://localhost:2019/stats)
assert_status 200 "$stats_status" "admin API /stats returns 200 (local analytics active)"

# Verify the stats response contains analytics data.
stats_body=$(curl -s \
  --cert "$CERTS_DIR/client.crt" \
  --key "$CERTS_DIR/client.key" \
  --cacert "$CERTS_DIR/server.crt" \
  https://localhost:2019/stats)
assert_contains "$stats_body" "requests" "stats response contains request data"

print_summary
