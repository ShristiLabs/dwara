#!/bin/bash
# test-05-http2.sh — HTTP/2 over TLS (h2 via ALPN).
#
# The edge-https listener negotiates HTTP/2 via ALPN during the TLS
# handshake. curl's --http2 flag advertises h2 in ALPN and uses it
# when the server agrees. This test confirms the gateway serves the
# request over the negotiated h2 path and returns 200.
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-05-http2 ==="

wait_for http://localhost:8080/healthz 30 || exit 1

# HTTP/2-negotiated request over TLS -> 200.
status=$(http_status https://localhost:8443/healthz \
  --http2 \
  --cacert ../_shared/certs/server.crt)
assert_status 200 "$status" "HTTP/2 over TLS returns 200"

# Confirm curl actually negotiated h2 (verbose output) rather than
# falling back to http/1.1. The -v trace line "Using HTTP2".
proto=$(curl -s -o /dev/null -w '%{http_version}' \
  --http2 \
  --cacert ../_shared/certs/server.crt \
  https://localhost:8443/healthz)
assert_status "2" "$proto" "ALPN negotiated HTTP/2 (http_version=2)"

print_summary
