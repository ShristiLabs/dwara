#!/bin/bash
# test-06-workspace-rb.sh — Workspace RBAC (enterprise feature).
#
# Workspace RBAC is an enterprise feature: multi-workspace isolation
# with role-based access control for API management. Workspaces
# partition consumers, routes, and policies into isolated namespaces,
# and RBAC bindings control who can manage each workspace.
#
# The OSS edition does not have workspace isolation. It does support:
#   - Consumer-level authentication (API key, JWT, mTLS, HMAC, OIDC)
#   - Route/service/listener/global authorization chains
#   - Admin API RBAC (SEC-01): mTLS client cert fingerprints mapped to
#     roles via admin.rbac, with fail-closed default (no implicit admin)
#
# This test verifies the admin API is reachable over mTLS (the OSS
# admin RBAC surface) and the gateway proxies traffic correctly.
set -euo pipefail
source ../_shared/helpers.sh

CERTS_DIR="../_shared/certs"

echo "=== test-06-workspace-rb ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/healthz 30 || exit 1

# Verify the admin API is reachable over mTLS (the OSS admin surface).
# The admin listener requires a client cert signed by client-ca.crt.
admin_status=$(curl -s -o /dev/null -w '%{http_code}' \
  --cert "$CERTS_DIR/client.crt" \
  --key "$CERTS_DIR/client.key" \
  --cacert "$CERTS_DIR/server.crt" \
  https://localhost:2019/health)
assert_status 200 "$admin_status" "admin API /health returns 200 over mTLS"

# Verify the admin API /stats endpoint is reachable.
stats_status=$(curl -s -o /dev/null -w '%{http_code}' \
  --cert "$CERTS_DIR/client.crt" \
  --key "$CERTS_DIR/client.key" \
  --cacert "$CERTS_DIR/server.crt" \
  https://localhost:2019/stats)
assert_status 200 "$stats_status" "admin API /stats returns 200 over mTLS"

# Verify the gateway proxies to the echo upstream.
status=$(http_status http://localhost:8080/v1/echo/test)
assert_status 200 "$status" "gateway proxies to echo"

print_summary
