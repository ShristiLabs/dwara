#!/bin/bash
set -e

# Test 04: Nano-services pattern (DW-106)
#
# Nano-services are small WASM modules that generate responses directly
# instead of proxying to an upstream. A route with `action: nano_service`
# loads a .wasm module, calls its `handle` export with the serialized
# request (method, path, headers, body), and returns the response the
# module produces (status, headers, body). No upstream is contacted.
#
# The nano-services pattern enables composing small, self-contained
# services at the gateway layer: each nano-service is a single .wasm
# module that handles one route, and the gateway routes between them.
# This is the "functions at the edge" pattern without a separate
# functions runtime.
#
# Feature gate: `nano_services` cargo feature (which pulls in `wasm`).
# Default OFF. Build with:
#   cargo build --release --features nano_services
#
# The default `dwara:demo` image is built WITHOUT `nano_services`. The
# config schema ACCEPTS the `nano_service` route action, but without
# the feature the action is inert (validation warns, the route returns
# 502).
#
# This test documents the nano-services pattern and verifies the
# gateway composes multiple upstream services (echo + static) as a
# stand-in for the nano-service composition pattern: the gateway
# routes /v1/echo/* to the echo service and / to the static service,
# demonstrating service composition at the gateway layer.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

BASE_URL="http://localhost:8080"

echo "=== Test 04: Nano-services Pattern (DW-106) ==="

echo ""
echo "--- Background: Nano-services ---"
echo "Nano-services are small WASM modules that generate responses"
echo "directly instead of proxying to an upstream. A route with"
echo "'action: nano_service' loads a .wasm module, calls its 'handle'"
echo "export with the serialized request, and returns the response."
echo "No upstream is contacted."
echo ""
echo "Feature gate: 'nano_services' cargo feature (pulls in 'wasm')"
echo "Build: cargo build --release --features nano_services"
echo ""
echo "The default dwara:demo image does not include nano_services."
echo "This test verifies the composition pattern using upstream"
echo "services (echo + static) as a stand-in."
echo ""

echo "--- Verifying gateway starts ---"
wait_for "$BASE_URL/healthz" 30

status=$(http_status "$BASE_URL/healthz")
assert_status "200" "$status" "GET /healthz returns 200"

echo ""
echo "--- Composed service 1: echo (prefix /v1/echo/) ---"
status=$(http_status "$BASE_URL/v1/echo/hello")
body=$(http_body "$BASE_URL/v1/echo/hello")
assert_status "200" "$status" "GET /v1/echo/hello returns 200"
assert_contains "$body" "echo" "GET /v1/echo/hello body contains echo JSON"

echo ""
echo "--- Composed service 2: static (exact /) ---"
status=$(http_status "$BASE_URL/")
assert_status "200" "$status" "GET / returns 200 (static service)"

echo ""
echo "--- Composition verified: gateway routes to multiple services ---"
echo "The gateway composes two services behind one listener:"
echo "  /v1/echo/* -> echo-service  (echo upstream, strip_prefix)"
echo "  /          -> static-service (static upstream, exact match)"
echo ""
echo "With nano_services enabled, each route could instead run a WASM"
echo "module directly (no upstream), composing nano-services at the"
echo "gateway layer."

print_summary
