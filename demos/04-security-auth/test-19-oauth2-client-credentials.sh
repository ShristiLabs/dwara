#!/bin/bash
# test-19-oauth2-client-credentials.sh — OAuth2 upstream authn.
#
# The oauth2-echo-upstream carries an oauth2_client_credentials block:
# before forwarding, the gateway POSTs grant_type=client_credentials
# to idp-mock's token endpoint (HTTP Basic auth with the configured
# client_id/client_secret) and forwards the resulting token upstream
# as `Authorization: Bearer <token>`, REPLACING any client-supplied
# Authorization header. Tokens are cached per upstream and refreshed
# lazily after min(expires_in - 60s, token_cache_ttl_s).
#
# The echo upstream reflects the Authorization header it received, and
# idp-mock's /last-token reports the token it issued, so the test can
# prove the upstream saw exactly the gateway-obtained token.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/../_shared/helpers.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GW=http://localhost:8080
IDP=${IDP_MOCK:-http://localhost:19011}

echo "=== test-19-oauth2-client-credentials ==="

# Wait for the gateway and the mock IdP to be ready.
wait_for "$GW/public/" 30 || exit 1
wait_for "$IDP/healthz" 30 || exit 1

# A request through the OAuth2-fronted route: the gateway must obtain
# a token from the IdP and forward it upstream.
status=$(http_status "$GW/v1/oauth2/test")
assert_status 200 "$status" "request via oauth2 upstream returns 200"

body=$(http_body "$GW/v1/oauth2/test")
assert_contains "$body" '"authorization": "Bearer mock-token-' \
  "upstream received the gateway-obtained Bearer token"

# The forwarded token must be exactly the one the IdP issued for this
# client (compare with the mock's /last-token record).
last=$(http_body "$IDP/last-token")
issued=$(echo "$last" | sed -n 's/.*"access_token": "\([^"]*\)".*/\1/p')
assert_contains "$body" "Bearer $issued" \
  "forwarded token matches the idp-mock issuance (/last-token)"

# The gateway authenticated to the token endpoint as the configured
# OAuth2 client (HTTP Basic user = client_id).
assert_contains "$last" '"client_id": "demo-oauth-client"' \
  "token endpoint saw the configured client_id (RFC 6749 section 2.3.1)"

# A client-supplied Authorization header is REPLACED, not forwarded:
# the upstream must see the gateway's token, never the client's. The
# client authenticates with a VALID opaque token minted by the mock
# (presenting a credential engages consumer authn on the route; an
# unknown one would 401 before the upstream call, which is a
# different, already-covered behavior).
CLIENT_TOKEN=$(http_body "$IDP/issue?sub=oauth2-demo&scope=openid&format=opaque" | tr -d '\n\r')
body=$(http_body "$GW/v1/oauth2/test" -H "Authorization: Bearer $CLIENT_TOKEN")
assert_contains "$body" "Bearer $issued" \
  "gateway token still forwarded when the client sends its own"
assert_not_contains "$body" "$CLIENT_TOKEN" \
  "client-supplied Authorization is replaced upstream"

print_summary
