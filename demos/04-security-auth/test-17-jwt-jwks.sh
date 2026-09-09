#!/bin/bash
# test-17-jwt-jwks.sh — JWT authentication via JWKS.
#
# The idp-mock upstream generates an RSA keypair at container start,
# serves the public key as a JWKS (RS256), and mints signed JWTs on
# demand (GET /issue). The gateway's jwt_providers entry verifies
# `Authorization: Bearer` tokens against that JWKS and maps the token
# to a consumer by its `iss` claim matching the jwt-user consumer's
# `jwt` credential (issuer binding).
#
# RS256 is the only viable demo algorithm: the gateway's algorithm
# allowlist rejects `none` and every HS* (symmetric) algorithm
# outright — asymmetric verification only — so the mock must sign
# with RSA (HS256 with a shared secret is not a supported shape).
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/../_shared/helpers.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GW=http://localhost:8080
IDP=${IDP_MOCK:-http://localhost:19011}

echo "=== test-17-jwt-jwks ==="

# Wait for the gateway and the mock IdP to be ready.
wait_for "$GW/public/" 30 || exit 1
wait_for "$IDP/jwks.json" 30 || exit 1

# The mock IdP serves a JWKS with one RS256 RSA key.
jwks=$(http_body "$IDP/jwks.json")
assert_contains "$jwks" '"kty": "RSA"' "idp-mock JWKS advertises an RSA key"
assert_contains "$jwks" '"alg": "RS256"' "JWKS key is RS256 (HS* is never allowed)"

# Mint a valid token for subject jwt-demo (scope joined per the OAuth
# space-separated convention) and call the JWT route with it.
TOKEN=$(http_body "$IDP/issue?sub=jwt-demo&scope=demo:read,demo:write" | tr -d '\n\r')

status=$(http_status "$GW/v1/jwt/test" -H "Authorization: Bearer $TOKEN")
assert_status 200 "$status" "valid RS256 Bearer token returns 200"

# Missing token -> 401 (route is auth_required).
status=$(http_status "$GW/v1/jwt/test")
assert_status 401 "$status" "missing Bearer token returns 401"

# Garbage token -> 401 (signature/parse verification fails).
status=$(http_status "$GW/v1/jwt/test" -H "Authorization: Bearer not-a-jwt")
assert_status 401 "$status" "garbage Bearer token returns 401"

# A well-formed token signed by a DIFFERENT key is also rejected:
# take the minted token and tamper with its signature bytes.
TAMPERED="${TOKEN%?}X"
status=$(http_status "$GW/v1/jwt/test" -H "Authorization: Bearer $TAMPERED")
assert_status 401 "$status" "tampered signature returns 401"

# Identity mapping: the verified token resolves the jwt-user consumer
# (issuer binding), which the gateway forwards as X-Consumer-Name —
# the echo upstream reflects received headers in its JSON body.
body=$(http_body "$GW/v1/jwt/test" -H "Authorization: Bearer $TOKEN")
assert_contains "$body" '"x-consumer-name": "jwt-user"' \
  "verified token maps to the jwt-user consumer (X-Consumer-Name)"

print_summary
