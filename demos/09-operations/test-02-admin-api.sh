#!/bin/bash
# test-02-admin-api.sh — mTLS admin API endpoints.
#
# The admin API binds 0.0.0.0:2019 and requires a client certificate
# chained to the client CA (mTLS is its only authentication). This test
# exercises the three GET endpoints:
#   - /health  (liveness)
#   - /config  (the active config snapshot, JSON)
#   - /stats   (runtime statistics)
#
# Every call uses the shared client cert + key, and trusts the server
# cert via --cacert (the admin listener serves the same server.crt).
set -euo pipefail
source ../_shared/helpers.sh

CERTS=../_shared/certs

echo "=== test-02-admin-api ==="

# Wait for the admin API to be ready (mTLS handshake against /health).
echo "--- waiting for admin API (mTLS /health) ---"
elapsed=0
while [ $elapsed -lt 30 ]; do
  code=$(curl -s -o /dev/null -w '%{http_code}' \
    --cert "$CERTS/client.crt" \
    --key "$CERTS/client.key" \
    --cacert "$CERTS/server.crt" \
    https://localhost:2019/health 2>/dev/null || true)
  if [ "$code" = "200" ]; then
    break
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done
if [ "$code" != "200" ]; then
  echo "ERROR: admin API /health not ready after 30s"
  exit 1
fi

# 1) GET /health -> 200.
status=$(http_status https://localhost:2019/health \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_status 200 "$status" "admin /health returns 200"

# 2) GET /config -> 200 with JSON body.
status=$(http_status https://localhost:2019/config \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_status 200 "$status" "admin /config returns 200"

config_body=$(http_body https://localhost:2019/config \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_contains "$config_body" "listeners" "admin /config body contains listeners"
assert_contains "$config_body" "routes" "admin /config body contains routes"
assert_contains "$config_body" "echo-service" "admin /config body contains echo-service"

# 3) GET /stats -> 200.
status=$(http_status https://localhost:2019/stats \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_status 200 "$status" "admin /stats returns 200"

stats_body=$(http_body https://localhost:2019/stats \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_contains "$stats_body" "{" "admin /stats body is JSON"

# 4) Negative: a call WITHOUT a client cert must fail the TLS handshake
#    (the admin API requires mTLS; curl exits non-zero / no HTTP code).
echo "--- verifying mTLS is enforced (no client cert) ---"
no_cert_code=$(curl -s -o /dev/null -w '%{http_code}' \
  --cacert "$CERTS/server.crt" \
  https://localhost:2019/health 2>/dev/null) || true
# A failed TLS handshake makes curl print "000" and exit non-zero.
# Any non-200 code here means mTLS blocked the request.
if [ "$no_cert_code" != "200" ]; then
  echo -e "${GREEN}PASS${NC}: admin API rejects request without client cert (mTLS enforced, got '$no_cert_code')"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: admin API accepted request without client cert (got $no_cert_code)"
  FAIL=$((FAIL + 1))
fi

print_summary
