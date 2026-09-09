#!/bin/bash
# test-03-sni-passthrough.sh — SNI passthrough (documented limitation).
#
# The edge-passthrough listener (:8444) is configured with
# tls.mode: passthrough and an sni_route mapping api.example.com to
# echo-upstream. In passthrough mode the gateway peeks the TLS
# ClientHello SNI and splices the raw TLS stream byte-for-byte to the
# matched upstream — it does NOT terminate TLS, so the upstream must
# speak TLS itself.
#
# LIMITATION: the dwara-demo/echo upstream is HTTP only (plaintext on
# :8080). Splicing a client TLS handshake into a plaintext HTTP server
# cannot complete the handshake, so a live `curl https://...:8444/...`
# fails with a TLS error. This is expected, not a bug.
#
# This script therefore DOCUMENTS the passthrough configuration and
# SKIPS the live connection test. To exercise SNI passthrough end to
# end, point an sni_route at an HTTPS upstream (for example an nginx
# container with `ssl on`), then curl the passthrough listener.
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-03-sni-passthrough ==="

echo "SKIP: SNI passthrough requires an HTTPS upstream; the echo"
echo "      upstream is HTTP only. The listener is configured in"
echo "      dwara.yaml (edge-passthrough, :8444) to demonstrate the"
echo "      sni_routes config shape; the live test is skipped."
echo "      See README.md for how to enable a real passthrough test."

# No assertions: this test is intentionally a no-op documentation step.
# Report a clean pass so the suite does not fail.
PASS=0
FAIL=0
print_summary
