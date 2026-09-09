#!/bin/bash
# test-16-mtls-forward-headers.sh — mTLS identity-forwarding headers.
#
# With mtls_forward_headers enabled (prefix: X-Client-Cert), the
# gateway injects X-Client-Cert-{Fingerprint,Subject-CN,Issuer-CN,
# Not-After} into the forwarded request so the upstream can see the
# verified client certificate identity. The echo upstream reflects
# all received headers in its JSON response body, so we check the
# response body for the forwarded header.
set -euo pipefail
source ../_shared/helpers.sh

CERTS=../_shared/certs

echo "=== test-16-mtls-forward-headers ==="

# Wait for the gateway to be ready (use the HTTP listener for the
# readiness check; both listeners are on the same gateway).
wait_for http://localhost:8080/public/ 30 || exit 1

# Send a request with the mTLS client cert and capture the echo response.
body=$(http_body https://localhost:8443/v1/mtls/test \
  --cacert "$CERTS/server.crt" \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key")

# The echo upstream reflects headers in the "headers" field of the JSON
# response. The gateway should have forwarded X-Client-Cert-* headers
# (Python's http.server lowercases header names, so we check
# case-insensitively).
assert_contains "$body" "x-client-cert" "echo response contains X-Client-Cert-* header"

# Check for the Subject-CN header specifically (the client cert's CN).
if echo "$body" | grep -qi "x-client-cert-subject-cn"; then
  echo -e "${GREEN}PASS${NC}: X-Client-Cert-Subject-CN header forwarded to upstream"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: X-Client-Cert-Subject-CN not found in echo response"
  echo "  response headers section:"
  echo "$body" | grep -i "x-client-cert" || echo "  (none found)"
  FAIL=$((FAIL + 1))
fi

print_summary
