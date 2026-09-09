#!/bin/bash
# test-01-tls-terminate.sh — TLS termination on the HTTPS listener.
#
# Verifies that the gateway terminates TLS on :8443 using the shared
# server certificate and serves a request over the decrypted path.
# The server cert is self-signed (CN=localhost, SAN DNS:localhost,
# IP:127.0.0.1), so curl trusts it via --cacert.
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-01-tls-terminate ==="

# Wait for the gateway to be up (probe the plaintext HTTP listener;
# the HTTPS listener is up at the same time).
wait_for http://localhost:8080/healthz 30 || exit 1

# TLS-terminated request -> 200.
status=$(http_status https://localhost:8443/healthz --cacert ../_shared/certs/server.crt)
assert_status 200 "$status" "TLS terminate returns 200 on :8443"

# The body of the healthz route is the literal "ok".
body=$(http_body https://localhost:8443/healthz --cacert ../_shared/certs/server.crt)
assert_contains "$body" "ok" "healthz body is 'ok'"

print_summary
