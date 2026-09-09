#!/bin/bash
# test-02-basic-auth.sh — Basic authentication.
#
# Verifies that a request with valid Basic credentials succeeds (200)
# and a request without credentials is rejected (401).
#
# Basic auth credentials are store-managed (not config-declared). This
# script first seeds the admin:secret123 credential into the state DB,
# then tests authentication.
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-02-basic-auth ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/public/ 30 || exit 1

# Seed the Basic auth credential (idempotent).
./seed-basic-auth.sh

# Valid Basic auth -> 200.
status=$(http_status http://localhost:8080/v1/basic/test -u 'admin:secret123')
assert_status 200 "$status" "valid Basic auth returns 200"

# Missing Basic auth -> 401.
status=$(http_status http://localhost:8080/v1/basic/test)
assert_status 401 "$status" "missing Basic auth returns 401"

# Invalid password -> 401.
status=$(http_status http://localhost:8080/v1/basic/test -u 'admin:wrongpass')
assert_status 401 "$status" "invalid Basic password returns 401"

print_summary
