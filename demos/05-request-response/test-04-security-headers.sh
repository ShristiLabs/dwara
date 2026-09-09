#!/bin/bash
# Test 04: Security-header injection (HSTS, nosniff, CSP, X-Frame-Options).
#
# Sends a HEAD request to the secure route and asserts the response carries
# the configured security headers.
#
# NOTE: Strict-Transport-Security (HSTS) is an HTTPS-only directive per RFC
# 6797. Some gateways only emit HSTS on TLS listeners. This demo runs a
# plaintext HTTP listener, so if the gateway suppresses HSTS on HTTP the
# HSTS assertion may fail while the other security headers still pass.
set -euo pipefail
source ../_shared/helpers.sh

BASE="http://localhost:8080"

echo "=== Test 04: Security Headers ==="

HEADERS=$(curl -s -D - -o /dev/null "$BASE/v1/secure/test")

# Note: header names are case-insensitive; the gateway emits lowercase.
assert_contains "$HEADERS" "[Ss]trict-[Tt]ransport-[Ss]ecurity" "HSTS header present"
assert_contains "$HEADERS" "[Xx]-[Cc]ontent-[Tt]ype-[Oo]ptions: nosniff" "nosniff header present"
assert_contains "$HEADERS" "[Xx]-[Ff]rame-[Oo]ptions: [Dd][Ee][Nn][Yy]" "X-Frame-Options: deny present"
assert_contains "$HEADERS" "[Cc]ontent-[Ss]ecurity-[Pp]olicy" "CSP header present"

print_summary
