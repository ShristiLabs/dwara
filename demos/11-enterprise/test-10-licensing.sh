#!/bin/bash
# test-10-licensing.sh — Licensing (enterprise feature).
#
# The enterprise edition uses a private `licensing-core` dependency
# (stubbed out in OSS builds). The config block (gateway.license,
# DW-032) is accepted in the OSS build but INERT: the gate is always
# LicenseGate::none(), so all features available are OSS-only and no
# license verification occurs. See
# crates/dwara-core/src/extensions/licensing.rs.
#
# In the enterprise edition (built from Dockerfile.ent with the `ent`
# cargo feature), the gateway verifies the license file at startup
# and gates enterprise features behind the license's feature claims
# (redis_rate_limiter, config_convergence, service_mesh,
# fleet_operations, etc.). The public key comes from the
# DWARA_LICENSE_PUBLIC_KEY env var (or the compiled-in development key
# when unset), never user-configurable.
#
# This test verifies the OSS stub works: the gateway starts
# successfully with a `license` block in the config (proving the block
# is accepted-but-inert), and serves traffic normally. The license
# file path in the config (/etc/dwara/license.json) does not exist in
# the container -- the OSS build does not read it.
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-10-licensing ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/healthz 30 || exit 1

# The gateway started successfully despite the license block in the
# config pointing to a nonexistent file. This proves the OSS licensing
# stub is inert (LicenseGate::none()): the block is accepted, no file
# is read, and no license verification occurs.
status=$(http_status http://localhost:8080/healthz)
assert_status 200 "$status" "gateway started with inert license block (OSS stub works)"

# Verify the gateway proxies to the echo upstream.
status=$(http_status http://localhost:8080/v1/echo/test)
assert_status 200 "$status" "gateway proxies to echo (no license gate in OSS)"

# Verify the gateway proxies to the static upstream.
status=$(http_status http://localhost:8080/)
assert_status 200 "$status" "gateway proxies to static (no license gate in OSS)"

# Verify the admin API is reachable (enterprise features are not
# gated in OSS -- the admin API is an OSS feature).
CERTS_DIR="../_shared/certs"
admin_status=$(curl -s -o /dev/null -w '%{http_code}' \
  --cert "$CERTS_DIR/client.crt" \
  --key "$CERTS_DIR/client.key" \
  --cacert "$CERTS_DIR/server.crt" \
  https://localhost:2019/health)
assert_status 200 "$admin_status" "admin API reachable (OSS feature, not license-gated)"

print_summary
