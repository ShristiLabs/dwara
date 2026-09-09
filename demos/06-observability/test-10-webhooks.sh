#!/bin/bash
# test-10-webhooks.sh — alert/event webhook delivery.
#
# Alert/event webhooks fire on resilience transitions (breaker opened/
# closed, endpoint ejected/recovered) and config lifecycle events
# (config published/rejected). Triggering a breaker or ejection
# requires a failing upstream, which this demo does not run, so this
# test verifies the webhook-receiver is reachable and documents that
# events fire automatically when the configured conditions occur.
#
# To exercise event delivery end-to-end, point the echo upstream at a
# flaky/slow upstream (see demos/_shared/upstreams/flaky) to force
# breaker transitions, then inspect the receiver ledger:
#
#   curl http://localhost:8081/events | jq .
#
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-10-webhooks ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/v1/echo/test 30 || exit 1

# The webhook-receiver is exposed on 8081 (GET /events returns the
# ledger of every received POST).
status=$(http_status http://localhost:8081/events)
assert_status 200 "$status" "webhook-receiver is reachable on :8081"

echo "  NOTE: event webhooks (breaker_opened, breaker_closed,"
echo "        endpoint_ejected, endpoint_recovered, config_published,"
echo "        config_rejected) fire automatically on resilience/config"
echo "        transitions. Trigger a failing upstream to observe them:"
echo "          curl http://localhost:8081/events"

print_summary
