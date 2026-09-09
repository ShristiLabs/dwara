#!/bin/bash
# test-05-hmac-signing.sh — HMAC request-signing authentication.
#
# The HMAC auth scheme requires the client to sign the request with a
# shared secret and send five X-Dwara-* headers:
#   X-Dwara-Key-Id      — the credential's key_id (public selector)
#   X-Dwara-Timestamp   — decimal Unix epoch seconds of signing
#   X-Dwara-Nonce       — opaque client string (16..=256 bytes)
#   X-Dwara-Body-Sha256 — lowercase hex SHA-256 of the request body
#   X-Dwara-Signature   — lowercase hex HMAC-SHA256(secret, canonical)
#
# Full HMAC signing requires computing the signature over the canonical
# string (method + path + query + timestamp + nonce + body digest) —
# this script does not compute a valid signature. Instead, it verifies
# that the hmac-route requires authentication: a request without any
# signature headers is rejected with 401, and a request with a bogus
# signature is also rejected with 401.
#
# To test a valid signature, compute (in a real client):
#   canonical = "dwara-hmac-v1\n<key_id>\n<METHOD>\n<path>\n<query>\n<timestamp>\n<nonce>\n<body_sha256>"
#   signature = hex(hmac_sha256(canonical, secret))
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-05-hmac-signing ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/public/ 30 || exit 1

# No signature headers -> 401 (auth required, no credential found).
status=$(http_status http://localhost:8080/v1/hmac/test)
assert_status 401 "$status" "missing HMAC signature returns 401"

# All five headers present but bogus signature -> 401.
# The timestamp is current (within clock skew), the nonce is random,
# the body digest is SHA-256 of the empty body, but the signature is
# wrong — the HMAC verification fails.
TIMESTAMP=$(date +%s)
BODY_SHA256=$(printf '' | shasum -a 256 | awk '{print $1}')
status=$(http_status http://localhost:8080/v1/hmac/test \
  -H "X-Dwara-Key-Id: mobile-hmac" \
  -H "X-Dwara-Timestamp: $TIMESTAMP" \
  -H "X-Dwara-Nonce: demo-nonce-0123456789abcdef" \
  -H "X-Dwara-Body-Sha256: $BODY_SHA256" \
  -H "X-Dwara-Signature: deadbeef0000000000000000000000000000000000000000000000000000dead")
assert_status 401 "$status" "invalid HMAC signature returns 401"

echo ""
echo "NOTE: Full HMAC signing requires computing the signature over the"
echo "canonical request string. See the script header for the signing"
echo "algorithm. This test only verifies the route is auth-gated (401)."

print_summary
