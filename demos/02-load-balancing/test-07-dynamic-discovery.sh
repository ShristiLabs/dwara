#!/bin/bash
# test-07-dynamic-discovery.sh — DNS-based dynamic upstream discovery.
#
# The dns-pool upstream has NO static endpoints: a background
# discovery task resolves `echo-dns` (a compose service name answered
# by docker's embedded DNS) and hot-swaps the resolved A records into
# the balancer's endpoint set, re-resolving every
# refresh_interval_s (5s here). Traffic through /lb/dns/ can therefore
# ONLY flow if discovery resolved and routed — a 200 naming echo-dns
# is the end-to-end assertion.
#
# The refresh loop is observable in /metrics (reserved path served on
# every HTTP listener):
#   dwara_dns_discovery_endpoints{upstream="dns-pool"}       gauge
#   dwara_dns_discovery_refresh_total{upstream="dns-pool"}   counter
# The counter incrementing across a refresh_interval_s window proves
# the TTL/refresh cadence is live (docker DNS answers with a TTL that
# the task honors; the cadence is min(refresh_interval_s, ttl)).
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-07-dynamic-discovery ==="

wait_for http://localhost:8080/healthz 30 || exit 1

# --- Discovery resolved and routed: the ONLY path to echo-dns is the
# DNS-resolved endpoint set (no static endpoints exist).
body=""
for i in $(seq 1 15); do
  body=$(http_body http://localhost:8080/lb/dns/test 2>/dev/null || true)
  if echo "$body" | grep -q '"instance": "echo-dns"'; then
    break
  fi
  sleep 1
done
assert_contains "$body" '"instance": "echo-dns"' "request routed to the DNS-discovered echo-dns endpoint"
status=$(http_status http://localhost:8080/lb/dns/test)
assert_status 200 "$status" "discovery-configured upstream serves traffic (200)"

# --- The discovery gauge reports the resolved endpoint set.
metrics=$(http_body http://localhost:8080/metrics)
ep=$(echo "$metrics" | grep '^dwara_dns_discovery_endpoints{.*dns-pool' | grep -o '[0-9]*$' || true)
if [ -n "$ep" ] && [ "$ep" -ge 1 ] 2>/dev/null; then
  echo -e "${GREEN}PASS${NC}: dwara_dns_discovery_endpoints{dns-pool} = $ep (>= 1 resolved)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: dwara_dns_discovery_endpoints{dns-pool} is '${ep:-absent}' (expected >= 1)"
  FAIL=$((FAIL + 1))
fi

# --- The refresh cadence is live: the refresh counter increments
# across one refresh_interval_s window (5s configured).
refreshes() {
  echo "$metrics" | grep '^dwara_dns_discovery_refresh_total{.*dns-pool' | grep -o '[0-9]*$' || true
}
before=$(refreshes)
sleep 6
metrics=$(http_body http://localhost:8080/metrics)
after=$(refreshes)
if [ -n "$before" ] && [ -n "$after" ] && [ "$after" -gt "$before" ] 2>/dev/null; then
  echo -e "${GREEN}PASS${NC}: refresh_total advanced ${before} -> ${after} over one interval (TTL refresh live)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: refresh_total did not advance (${before:-absent} -> ${after:-absent})"
  FAIL=$((FAIL + 1))
fi

# --- No discovery failures recorded (docker DNS answered cleanly).
# The failures counter series is absent until the first failure (a
# zero-touch counter exports no series), so "missing" is also a pass.
fails=$(echo "$metrics" | grep '^dwara_dns_discovery_refresh_failures_total{.*dns-pool' | grep -o '[0-9]*$' || true)
if [ -z "$fails" ] || [ "$fails" -eq 0 ] 2>/dev/null; then
  echo -e "${GREEN}PASS${NC}: no DNS discovery failures for dns-pool (counter ${fails:-absent = 0})"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: DNS discovery failures for dns-pool = $fails"
  FAIL=$((FAIL + 1))
fi

# --- The gateway logged the first resolution.
logs=$(docker compose logs dwara 2>&1)
assert_contains "$logs" "dns_discovery_refreshed" "dns_discovery_refreshed logged"

echo ""
echo "NOTE: docker DNS answers a single A record per service here, so"
echo "      the demo asserts resolve-and-route (not fan-out). Scale"
echo "      echo-dns replicas up to see the endpoint set grow: the"
echo "      gauge and the balancer update without a restart."

print_summary
