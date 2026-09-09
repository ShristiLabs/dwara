#!/bin/bash
# test-05-synthetic-monitoring.sh — synthetic route probes
# (documented limitation: library surface, not yet a config block).
#
# Synthetic monitoring (DW-071, docs-site/guide/synthetic-monitoring.md)
# runs built-in probes per route: a periodic request through the
# route's matched path that records latency/status and feeds results
# into analytics and edge-triggered webhook alerts
# (probe_alert / probe_recovered once per state transition, not per
# failure).
#
# LIMITATION: the probe ENGINE is complete and test-covered as a
# library surface (crates/dwara-core/src/synthetic/ — ProbeSpec,
# ProbeRunner with edge-triggered alerting and failure thresholds),
# but it is NOT yet wired into the gateway binary: the config schema
# has no top-level `synthetic:` block, so the documented probes
# config cannot be applied yet. The Gateway config struct rejects
# unknown fields (deny_unknown_fields), which this test proves
# negatively: a config carrying the guide's `synthetic:` block fails
# validation with "unknown field `synthetic`".
#
# What IS live today and asserted here:
#   - the /metrics endpoint (the surface probe results would feed)
#     serves the gateway's Prometheus metric families.
# What is NOT live (documented, not asserted):
#   - probe scheduling (interval_ms / timeout_ms), failure
#     thresholds, probe_alert webhooks, and synthetic-flagged
#     analytics records.
#
# To exercise the engine itself: cargo test -p dwara-core synthetic.
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-05-synthetic-monitoring ==="

echo "SKIP (documented limitation): synthetic monitoring's probe engine"
echo "      (crates/dwara-core/src/synthetic/) is a library surface not"
echo "      yet wired into the gateway binary — there is no top-level"
echo "      'synthetic:' config block, so the guide's probes config"
echo "      cannot be applied to a running gateway yet. The tests below"
echo "      pin the current state: /metrics works, and the synthetic"
echo "      block is rejected by validation."

# Wait for the gateway to be ready.
wait_for http://localhost:8080/healthz 30 || exit 1

# 1) The metrics surface synthetic probe results would feed is live:
#    GET /metrics serves the gateway's Prometheus families (e.g.
#    requests_total — the dwara_ prefix in the guide's metric table
#    is illustrative; the registry's family names are unprefixed).
#    Generate a little traffic first so the counters are non-zero.
curl -s -o /dev/null http://localhost:8080/v1/echo/synthetic
metrics=$(http_body http://localhost:8080/metrics)
assert_contains "$metrics" "requests_total" \
  "/metrics exposes the requests_total family (the surface probes would feed)"

# 2) Negative proof that the synthetic config block is not yet part
#    of the schema: the guide's probes config must FAIL validation
#    with an unknown-field error naming 'synthetic'.
REPO_ROOT="$(cd "$(dirname $0)/../.." && pwd)"
DWARA_CLI="$REPO_ROOT/target/debug/dwara-cli"
if [ -x "$DWARA_CLI" ]; then
  echo "--- validating a config carrying the documented synthetic block ---"
  probe_conf=$(mktemp /tmp/dwara-synthetic-XXXXXX.yaml)
  trap 'rm -f "$probe_conf"' EXIT
  cat >"$probe_conf" <<'EOF'
listeners:
  - name: edge-http
    address: 127.0.0.1
    port: 18080
    protocol: http
routes:
  - name: echo-route
    service: echo-service
    match:
      path:
        type: prefix
        value: /v1/echo/
    action:
      type: proxy
services:
  - name: echo-service
    upstream: echo-upstream
upstreams:
  - name: echo-upstream
    load_balancer: round_robin
    protocol: http1
    endpoints:
      - address: 127.0.0.1
        port: 1
synthetic:
  probes:
    - route_name: echo-route
      interval_ms: 5000
      timeout_ms: 2000
      failure_threshold: 3
EOF
  cli_out=$("$DWARA_CLI" validate "$probe_conf" 2>&1 || true)
  if echo "$cli_out" | grep -q "unknown field \`synthetic\`"; then
    echo -e "${GREEN}PASS${NC}: 'synthetic:' block is rejected by validation (confirms the not-yet-wired state)"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}FAIL${NC}: expected an unknown-field error for 'synthetic', got: $cli_out"
    FAIL=$((FAIL + 1))
  fi
else
  echo "SKIP: host dwara-cli not found at $DWARA_CLI"
  echo "      (build with: cargo build -p dwara-cli) — the negative"
  echo "      validation proof is skipped; the /metrics assertion above"
  echo "      still ran."
fi

echo ""
echo "NOTE: once a 'synthetic:' block lands in the config schema, this"
echo "test should apply probes (route_name: healthz, interval_ms: 1000),"
echo "wait past the interval, and assert /metrics exposes the synthetic"
echo "probe metrics plus a probe_alert webhook on the webhook-receiver."

print_summary
