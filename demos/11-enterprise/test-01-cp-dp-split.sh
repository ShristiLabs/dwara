#!/bin/bash
# test-01-cp-dp-split.sh — CP/DP split architecture (enterprise feature).
#
# The enterprise edition's flagship topology is the control plane /
# data plane split: a dwara-controller compiles config, publishes
# generations, and broadcasts them over gRPC to dwara-edge data planes,
# each driving a gateway that hot-reloads. One config file reconfigures
# the whole fleet. See quickstart/enterprise/docker-compose.yml for
# the full topology (controller + edge-1 + edge-2 + gateway-1 +
# gateway-2 + upstream, built from Dockerfile.ent).
#
# The OSS image (dwara:demo) does NOT include the CP/DP split binaries
# (dwara-controller, dwara-edge) -- those require the `ent` cargo
# feature. This demo runs a single-node OSS gateway instead and
# verifies it serves traffic correctly as the baseline that the
# enterprise CP/DP split builds on top of.
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-01-cp-dp-split ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/healthz 30 || exit 1

# The OSS gateway is a single-node data plane with no controller.
# Verify it proxies traffic to the echo upstream (the same behavior
# each edge gateway in the CP/DP split provides).
status=$(http_status http://localhost:8080/v1/echo/test)
assert_status 200 "$status" "single-node gateway proxies to echo"

# Verify the static upstream is reachable.
status=$(http_status http://localhost:8080/)
assert_status 200 "$status" "single-node gateway proxies to static"

# Verify the healthz endpoint responds directly.
status=$(http_status http://localhost:8080/healthz)
body=$(http_body http://localhost:8080/healthz)
assert_status 200 "$status" "healthz returns 200"
assert_contains "$body" "ok" "healthz body is 'ok'"

print_summary
