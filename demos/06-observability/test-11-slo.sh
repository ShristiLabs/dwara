#!/bin/bash
# test-11-slo.sh — SLO burn-rate metrics.
#
# Sends a request through the SLO-instrumented route (slo-route),
# then fetches /metrics and asserts the per-route SLO metric families
# are present (dwara_slo_burn_rate, dwara_slo_target).
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-11-slo ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/v1/echo/test 30 || exit 1

# Drive traffic through the SLO-instrumented route so the SLO state
# is initialized and the gauges are exported.
for i in $(seq 1 5); do
  curl -s -o /dev/null http://localhost:8080/v1/slo/test
done

# Fetch the metrics endpoint and assert the SLO metric families.
body=$(http_body http://localhost:8080/metrics)
assert_contains "$body" "dwara_slo_burn_rate" "/metrics contains dwara_slo_burn_rate"
assert_contains "$body" "dwara_slo_target" "/metrics contains dwara_slo_target"

print_summary
