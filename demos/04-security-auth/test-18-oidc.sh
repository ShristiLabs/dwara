#!/bin/bash
# test-18-oidc.sh — OIDC Bearer-token introspection (RFC 7662).
#
# The gateway's oidc_providers entry fetches the discovery document
# from {issuer}/.well-known/openid-configuration (served by idp-mock)
# and introspects Bearer tokens that did not verify as JWTs. An
# `active: true` result resolves the oidc-user consumer (the
# provider's explicit `consumer` binding); `active: false` (or an IdP
# failure — fail_closed is the default) is a 401.
#
# The mock's /issue endpoint can mint unstructured tokens
# (format=opaque) that are recorded server-side: they fail JWT
# verification by construction, so they can ONLY authenticate through
# introspection — which is exactly what this test asserts.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/../_shared/helpers.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GW=http://localhost:8080
IDP=${IDP_MOCK:-http://localhost:19011}

echo "=== test-18-oidc ==="

# Wait for the gateway and the mock IdP to be ready.
wait_for "$GW/public/" 30 || exit 1
wait_for "$IDP/healthz" 30 || exit 1

# The mock serves the OIDC discovery document with its endpoints.
disc=$(http_body "$IDP/.well-known/openid-configuration")
assert_contains "$disc" '"introspection_endpoint"' \
  "discovery document advertises the introspection endpoint"
assert_contains "$disc" '"token_endpoint"' \
  "discovery document advertises the token endpoint"

# Mint an OPAQUE token at the IdP: it cannot verify as a JWT, so the
# gateway must authenticate it through introspection.
TOKEN=$(http_body "$IDP/issue?sub=oidc-demo&scope=openid&format=opaque" | tr -d '\n\r')

status=$(http_status "$GW/v1/oidc/test" -H "Authorization: Bearer $TOKEN")
assert_status 200 "$status" "active introspected token returns 200"

# Unknown token -> the IdP answers active:false -> 401 (never cached).
status=$(http_status "$GW/v1/oidc/test" -H "Authorization: Bearer totally-unknown-token")
assert_status 401 "$status" "unknown token introspects inactive: 401"

# Missing token -> 401 (route is auth_required).
status=$(http_status "$GW/v1/oidc/test")
assert_status 401 "$status" "missing Bearer token returns 401"

# The gateway really introspected: the mock's counters moved.
stats=$(http_body "$IDP/stats")
if echo "$stats" | grep -Eq '"introspections": [1-9]'; then
  echo -e "${GREEN}PASS${NC}: idp-mock received introspection calls from the gateway"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: idp-mock received no introspection calls"
  echo "  stats: $stats"
  FAIL=$((FAIL + 1))
fi

# Identity mapping: the provider's consumer binding resolves oidc-user
# and the gateway forwards it as X-Consumer-Name (reflected by echo).
body=$(http_body "$GW/v1/oidc/test" -H "Authorization: Bearer $TOKEN")
assert_contains "$body" '"x-consumer-name": "oidc-user"' \
  "introspected token maps to the oidc-user consumer (provider binding)"

print_summary
