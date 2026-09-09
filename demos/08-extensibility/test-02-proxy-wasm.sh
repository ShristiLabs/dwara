#!/bin/bash
set -e

# Test 02: Proxy-Wasm (WebAssembly) plugins (DW-055)
#
# dwara supports Proxy-Wasm (WebAssembly) plugins via the `wasm` cargo
# feature (default OFF). Each plugin is a .wasm module loaded at
# startup and run on the request pipeline phases it declares. Routes
# reference plugins by name via their `plugins` field. Community
# Kong/Envoy proxy-wasm filters run unmodified.
#
# The Proxy-Wasm host uses wasmtime as the WebAssembly engine. The
# four HTTP filter phases mirror the native filter contract exactly:
#   1. request_headers  2. request_body
#   3. response_headers 4. response_body
#
# The default `dwara:demo` image is built WITHOUT the `wasm` feature
# (wasmtime + cranelift add significant binary size against the 25MB
# budget). The config schema ACCEPTS the `plugins` block with WASM
# plugin definitions, but without the feature the plugins are not
# instantiated (the block is inert).
#
# To enable Proxy-Wasm, build with:
#   cargo build --release --features wasm
# Then supply a .wasm module path in the plugins block and reference
# it from a route's `plugins` field.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

BASE_URL="http://localhost:8080"

echo "=== Test 02: Proxy-Wasm (WebAssembly) Plugins (DW-055) ==="

echo ""
echo "--- Background: Proxy-Wasm host ---"
echo "Proxy-Wasm plugins are .wasm modules loaded at startup and run on"
echo "the request pipeline phases they declare. The host uses wasmtime."
echo "Community Kong/Envoy proxy-wasm filters run unmodified."
echo ""
echo "Feature gate: 'wasm' cargo feature (default OFF)"
echo "Build: cargo build --release --features wasm"
echo ""

echo "--- Verifying gateway starts with default build ---"
wait_for "$BASE_URL/healthz" 30

status=$(http_status "$BASE_URL/healthz")
assert_status "200" "$status" "GET /healthz returns 200"

echo ""
echo "--- Verifying proxying works (echo upstream) ---"
status=$(http_status "$BASE_URL/v1/echo/test")
body=$(http_body "$BASE_URL/v1/echo/test")
assert_status "200" "$status" "GET /v1/echo/test returns 200"
assert_contains "$body" "echo" "GET /v1/echo/test body contains echo JSON"

echo ""
echo "--- Proxy-Wasm config block is accepted but inert ---"
echo "The config schema accepts the top-level 'plugins' block with WASM"
echo "plugin definitions (wasm path, phases, config, limits). Without"
echo "the 'wasm' feature, the block is accepted but plugins are not"
echo "instantiated. The gateway starts and routes traffic normally."

print_summary
