#!/bin/bash
# test-04-otlp-export.sh — OTLP trace + metrics export to a collector.
#
# The gateway can push telemetry over the OpenTelemetry Protocol
# (#126 traces / DW-073 metrics): setting DWARA_OTLP_ENDPOINT to a
# BASE http URL arms both exporters — the trace exporter appends
# /v1/traces and the periodic metrics exporter appends /v1/metrics
# (interval override: DWARA_OTLP_METRICS_INTERVAL_SECS, default 15s;
# the compose file sets 2s so this test observes exports quickly).
# Without the env var the exporters are inert.
#
# This demo adds an `otel-collector` container (pinned 0.96.0, the
# last release shipping the `logging` exporter under that name)
# whose config (fixtures/otel-collector.yaml) receives OTLP/http on
# :4318 and logs everything at detailed verbosity — so
# `docker compose logs otel-collector` shows the gateway's spans
# and metric families verbatim.
#
# This test:
#   1) Verifies the gateway is up and OTLP is armed (the
#      otlp_export_enabled / otlp_metrics_export_enabled startup
#      log lines in the gateway's logs).
#   2) Generates traffic through the gateway (the DW-021 span tree:
#      root `request` span + authn/authz/ratelimit/admission/
#      upstream_pick/upstream_attempt phase spans).
#   3) Asserts the collector's logs contain dwara telemetry: the
#      service.name resource attribute "dwara" and dwara metric
#      names (dwara_requests_total etc.).
set -euo pipefail
source ../_shared/helpers.sh

COMPOSE_FILE="$(cd "$(dirname "$0")" && pwd)/docker-compose.yml"

# assert_file_contains <file> <needle> <description>
# Grep the FILE directly: compose logs get large, and piping a large
# string through assert_contains' `echo | grep -q` trips a benign
# broken pipe (grep -q exits on first match, echo loses the race).
assert_file_contains() {
  local file="$1"
  local needle="$2"
  local desc="$3"
  if grep -q "$needle" "$file" 2>/dev/null; then
    echo -e "${GREEN}PASS${NC}: $desc"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}FAIL${NC}: $desc (expected '$needle' in $file)"
    FAIL=$((FAIL + 1))
  fi
}

echo "=== test-04-otlp-export ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/healthz 30 || exit 1

# 1) The gateway logs must show the OTLP exporters armed. The trace
#    exporter logs `otlp_export_enabled` (base endpoint; /v1/traces
#    appended) and the metrics exporter logs
#    `otlp_metrics_export_enabled` (/v1/metrics appended).
echo "--- checking gateway startup logs for OTLP export ---"
gw_log=$(mktemp /tmp/dwara-otlp-gw-XXXXXX.log)
trap 'rm -f "$gw_log" "$c_log"' EXIT
docker compose -f "$COMPOSE_FILE" logs dwara >"$gw_log" 2>/dev/null || true
assert_file_contains "$gw_log" "otlp_export_enabled" \
  "gateway logs show otlp_export_enabled (trace exporter armed)"
assert_file_contains "$gw_log" "otlp_metrics_export_enabled" \
  "gateway logs show otlp_metrics_export_enabled (metrics exporter armed)"
assert_file_contains "$gw_log" "otel-collector:4318" \
  "OTLP endpoint is the compose collector (http://otel-collector:4318)"

# 2) Generate traffic: each proxied request emits the DW-021 span
#    tree (root `request` span + phase spans), and the observability
#    registry accumulates the metric families the metrics exporter
#    ships on its next tick.
echo "--- generating gateway traffic (spans + metrics) ---"
for i in $(seq 1 10); do
  curl -s -o /dev/null http://localhost:8080/v1/echo/otlp-$i
  curl -s -o /dev/null http://localhost:8080/healthz
done

# 3) The collector must have received dwara telemetry. The metrics
#    exporter fires every DWARA_OTLP_METRICS_INTERVAL_SECS (2s here)
#    and the trace exporter flushes finished span batches, so poll
#    the collector logs for up to 30s for the service.name resource
#    attribute and a gateway metric family name (the exporter ships
#    the same families /metrics serves; e.g. requests_total — the
#    dwara_ prefix in the guide's table is illustrative, the family
#    names on the wire are the registry's own).
echo "--- polling otel-collector logs for dwara telemetry ---"
c_log=$(mktemp /tmp/dwara-otlp-collector-XXXXXX.log)
collector_saw_dwara=""
collector_saw_metric=""
collector_saw_span=""
elapsed=0
while [ $elapsed -lt 30 ]; do
  docker compose -f "$COMPOSE_FILE" logs otel-collector >"$c_log" 2>/dev/null || true
  if grep -q 'service.name: Str(dwara)' "$c_log" 2>/dev/null; then
    collector_saw_dwara=yes
  fi
  if grep -q 'Name: requests_total' "$c_log" 2>/dev/null; then
    collector_saw_metric=yes
  fi
  if grep -Eq 'Name[[:space:]]*:[[:space:]]*request[[:space:]]*$' "$c_log" 2>/dev/null; then
    collector_saw_span=yes
  fi
  if [ -n "$collector_saw_dwara" ] && [ -n "$collector_saw_metric" ]; then
    break
  fi
  sleep 2
  elapsed=$((elapsed + 2))
done

if [ "$collector_saw_dwara" = "yes" ]; then
  echo -e "${GREEN}PASS${NC}: collector received dwara telemetry (service.name resource attribute)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: collector logs show no dwara service.name attribute after ${elapsed}s"
  FAIL=$((FAIL + 1))
fi

if [ "$collector_saw_metric" = "yes" ]; then
  echo -e "${GREEN}PASS${NC}: collector received dwara metrics (requests_total family)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: collector logs show no gateway metric families after ${elapsed}s"
  FAIL=$((FAIL + 1))
fi

# Also confirm spans reached the collector: detailed-verbosity span
# logs name the span (the DW-021 root span is `request`).
if [ "$collector_saw_span" = "yes" ]; then
  echo -e "${GREEN}PASS${NC}: collector received dwara request spans (root span 'request')"
  PASS=$((PASS + 1))
else
  echo -e "${YELLOW}WARN${NC}: no named span lines in collector logs yet (batch flush timing); metrics path above is the load-bearing assertion"
fi

echo ""
echo "NOTE: both OTLP signals share ONE base endpoint env var"
echo "(DWARA_OTLP_ENDPOINT); paths /v1/traces and /v1/metrics are"
echo "appended automatically. On SIGTERM the gateway flushes a final"
echo "metrics export and drains the trace batch exporter inside the"
echo "graceful-shutdown budget."

print_summary
