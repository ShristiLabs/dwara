#!/bin/bash
# test-01-metrics.sh — Prometheus /metrics endpoint.
#
# Verifies that the gateway exposes a Prometheus-format /metrics
# endpoint on the HTTP listener and that it contains the request
# counter family.
#
# NOTE: the gateway emits the counter as `requests_total` (no `dwara_`
# prefix) on the /metrics text endpoint; the `dwara_` prefix is only
# applied to OTLP-exported metric names. This test asserts the actual
# emitted name.
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-01-metrics ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/v1/echo/test 30 || exit 1

# Generate a request so the counter is non-zero.
curl -s -o /dev/null http://localhost:8080/v1/echo/test

# Fetch the metrics endpoint.
body=$(http_body http://localhost:8080/metrics)
assert_contains "$body" "requests_total" "/metrics contains requests_total"

print_summary
