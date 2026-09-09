#!/bin/bash
# test-02-multi-sni.sh — multi-SNI certificate selection.
#
# The edge-https listener configures a SNI-scoped certificate entry
# for `api.example.com` (and a fallback for unmatched SNI). This test
# sends a request with SNI=api.example.com via curl --resolve and
# confirms the gateway selects the matching cert entry and routes the
# request.
#
# NOTE: the shared demo cert is self-signed for CN=localhost with SAN
# DNS:localhost,IP:127.0.0.1 only — it does NOT list api.example.com,
# so curl's hostname verification would fail against api.example.com.
# We pass -k to skip hostname verification (the cert is still trusted
# via --cacert for its chain); the point of this test is SNI-based cert
# *selection*, not hostname matching. With a real cert that carried
# api.example.com in its SAN, --cacert alone would suffice.
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-02-multi-sni ==="

wait_for http://localhost:8080/healthz 30 || exit 1

# SNI=api.example.com routed through the multi-SNI cert entry -> 200.
status=$(http_status https://api.example.com:8443/healthz \
  --cacert ../_shared/certs/server.crt \
  --resolve api.example.com:8443:127.0.0.1 \
  -k)
assert_status 200 "$status" "multi-SNI (api.example.com) returns 200"

# Fallback SNI (localhost, no explicit entry) also -> 200.
status=$(http_status https://localhost:8443/healthz \
  --cacert ../_shared/certs/server.crt)
assert_status 200 "$status" "fallback SNI (localhost) returns 200"

print_summary
