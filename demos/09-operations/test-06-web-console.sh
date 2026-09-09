#!/bin/bash
# test-06-web-console.sh — the embedded web console on the admin listener.
#
# The web console (DW-117/DW-118) is a single-page app embedded in the
# gateway binary at compile time (include_str!/include_bytes! — no
# runtime file dependency) and served from the ADMIN listener at
# /console/ BEFORE the admin API dispatch. It inherits the admin
# listener's authentication, which in this demo is mTLS: the browser
# (or curl) must present a client certificate chained to the client
# CA. There is no separate login or token — the mTLS handshake IS the
# authentication.
#
# Served paths (crates/dwara-console): /console (and /console/ and
# /console/index.html) -> the SPA shell, /console/style.css,
# /console/app.js. Any other /console/* path answers 404
# console_not_found.
#
# This test:
#   1) GET /console/ with the client cert -> 200 HTML whose body
#      carries the console marker ("dwara console").
#   2) GET /console/style.css -> 200 with a text/css content type.
#   3) GET /console/nope -> 404 console_not_found.
#   4) Verifies the console inherits mTLS: a call without a client
#      cert fails the TLS handshake.
set -euo pipefail
source ../_shared/helpers.sh

CERTS=../_shared/certs

echo "=== test-06-web-console ==="

# Wait for the admin API to be ready (mTLS handshake against /health).
echo "--- waiting for admin API (mTLS /health) ---"
elapsed=0
code=""
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

# 1) The console SPA shell: 200 HTML with the marker.
status=$(http_status https://localhost:2019/console/ \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_status 200 "$status" "GET /console/ returns 200"

console_body=$(http_body https://localhost:2019/console/ \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_contains "$console_body" "dwara console" \
  "console HTML carries the 'dwara console' marker"

# Content type is text/html (the embedded StaticFile's content type).
# NOTE: headers are fetched with GET (-D -), not HEAD: the admin only
# serves console paths for GET, so a HEAD would fall through to the
# admin API's JSON 404 envelope.
console_headers=$(curl -s -D - -o /dev/null \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt" \
  https://localhost:2019/console/)
assert_header "$console_headers" "Content-Type" "text/html; charset=utf-8" \
  "console shell is served as text/html"

# 2) An embedded asset: the stylesheet.
css_status=$(http_status https://localhost:2019/console/style.css \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_status 200 "$css_status" "GET /console/style.css returns 200"
css_headers=$(curl -s -D - -o /dev/null \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt" \
  https://localhost:2019/console/style.css)
assert_header "$css_headers" "Content-Type" "text/css; charset=utf-8" \
  "console stylesheet is served as text/css"

# 3) Unknown console path -> 404 console_not_found (the admin's
#    documented envelope for unrecognized /console/* paths).
unknown_status=$(http_status https://localhost:2019/console/nope \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_status 404 "$unknown_status" "GET /console/nope returns 404"

# 4) The console has no auth of its own: without a client cert the
#    TLS handshake fails exactly as it does for the admin API.
echo "--- verifying the console inherits mTLS (no client cert) ---"
no_cert_code=$(curl -s -o /dev/null -w '%{http_code}' \
  --cacert "$CERTS/server.crt" \
  https://localhost:2019/console/ 2>/dev/null) || true
if [ "$no_cert_code" != "200" ]; then
  echo -e "${GREEN}PASS${NC}: console rejects request without client cert (mTLS inherited, got '$no_cert_code')"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: console served without a client cert (got $no_cert_code)"
  FAIL=$((FAIL + 1))
fi

echo ""
echo "NOTE: to use the console from a browser, install the shared"
echo "client certificate (../_shared/certs/client.crt + client.key)"
echo "in the browser's certificate store, then open"
echo "https://localhost:2019/console/ — the SPA fetches /health,"
echo "/stats, /config_dump, and /analytics endpoints same-origin."

print_summary
