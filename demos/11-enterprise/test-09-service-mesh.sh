#!/bin/bash
# test-09-service-mesh.sh — Service mesh (enterprise feature).
#
# Service mesh mode (DW-107) is an enterprise feature: dwara runs as
# a sidecar in each pod, intercepting traffic via iptables/TPROXY
# redirect, with mTLS identity provided by SPIFFE/SPIRE (X.509 SVIDs).
# Inbound terminates mTLS and forwards to the local app; outbound
# wraps in mTLS and dials the remote sidecar. See
# crates/dwara-core/src/config/mesh.rs and the `mesh` domain module.
#
# The config block (gateway.mesh) is accepted but inert in the OSS
# build: validation warns and no sidecar listeners or SPIFFE client
# are wired. The `mesh` cargo feature + a license claim are required.
#
# The OSS gateway functions as a regular reverse proxy (the baseline
# that the mesh sidecar mode extends). This test verifies the proxy
# path works correctly.
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-09-service-mesh ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/healthz 30 || exit 1

# Verify the gateway proxies to the echo upstream.
status=$(http_status http://localhost:8080/v1/echo/test)
assert_status 200 "$status" "gateway proxies to echo (reverse proxy baseline)"

# Verify the echo response contains the expected data.
body=$(http_body http://localhost:8080/v1/echo/test)
assert_contains "$body" "echo" "echo response contains echo data"

# Verify the static upstream is reachable.
status=$(http_status http://localhost:8080/)
assert_status 200 "$status" "gateway proxies to static"

# Verify the strip_prefix rewrite worked (the echo upstream should
# see /test, not /v1/echo/test).
body=$(http_body http://localhost:8080/v1/echo/test)
assert_contains "$body" "/test" "echo response shows stripped path /test"

print_summary
