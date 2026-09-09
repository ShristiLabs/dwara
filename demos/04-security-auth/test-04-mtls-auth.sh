#!/bin/bash
# test-04-mtls-auth.sh — mTLS client-certificate authentication.
#
# Verifies that a request with a valid client certificate (chained to
# the client CA) is accepted (200) on the HTTPS listener. The client
# certificate's subject CN (dwara-admin-client) maps to the partner-mtls
# consumer via mtls_consumer_mapping.
set -euo pipefail
source ../_shared/helpers.sh

CERTS=../_shared/certs

echo "=== test-04-mtls-auth ==="

# Wait for the gateway to be ready (use the HTTP listener for the
# readiness check; both listeners are on the same gateway).
wait_for http://localhost:8080/public/ 30 || exit 1

# Valid mTLS client cert -> 200 (partner-mtls consumer is allowed).
status=$(http_status https://localhost:8443/v1/mtls/test \
  --cacert "$CERTS/server.crt" \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key")
assert_status 200 "$status" "valid mTLS client cert returns 200"

print_summary
