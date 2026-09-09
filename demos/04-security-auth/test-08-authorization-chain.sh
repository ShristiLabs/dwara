#!/bin/bash
# test-08-authorization-chain.sh — Authorization chain (consumer allowlist).
#
# The mtls-route has authorization.allowed_consumers: [partner-mtls].
# A request authenticated as a different consumer (mobile-app via API
# key) should be denied with 403, while a request authenticated as
# partner-mtls (via mTLS client cert) should succeed (200).
#
# This demonstrates the route-level authorization link: even though
# both consumers are validly authenticated, only partner-mtls is
# authorized for this route.
set -euo pipefail
source ../_shared/helpers.sh

CERTS=../_shared/certs

echo "=== test-08-authorization-chain ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/public/ 30 || exit 1

# API-key consumer (mobile-app) on the mTLS-only route -> 403.
# The mobile-app consumer is authenticated but not in allowed_consumers.
status=$(http_status http://localhost:8080/v1/mtls/test -H 'X-API-Key: demo-api-key-123')
assert_status 403 "$status" "API-key consumer denied on mTLS-only route (403)"

# mTLS consumer (partner-mtls) on the mTLS-only route -> 200.
status=$(http_status https://localhost:8443/v1/mtls/test \
  --cacert "$CERTS/server.crt" \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key")
assert_status 200 "$status" "mTLS consumer allowed on mTLS-only route (200)"

print_summary
