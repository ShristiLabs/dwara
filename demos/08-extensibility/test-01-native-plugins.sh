#!/bin/bash
set -e

# Test 01: Native plugin filters (NativeFilter trait, DW-119)
#
# dwara supports compile-in Rust filters via the NativeFilter trait,
# feature-gated behind the `plugins` cargo feature (default OFF). A
# native filter is a Rust type implementing NativeFilter, registered
# with NativeRegistry at startup under a name. Routes reference native
# filters by name via their `plugins` field, exactly as they reference
# WASM plugins. The four HTTP filter phases are:
#   1. request_headers  (after route resolution, before authn)
#   2. request_body     (after authn/authz/rate-limit, before upstream)
#   3. response_headers (after upstream responds, before masking)
#   4. response_body    (after masking, before compression)
#
# The default `dwara:demo` image is built WITHOUT the `plugins` feature
# (it is default OFF to keep the binary within the 25MB budget). The
# config schema ACCEPTS the `plugins` top-level block and the
# `routes[].plugins` field, but without the feature compiled in the
# plugins are not instantiated (the block is inert).
#
# This test verifies that the gateway starts and proxies correctly
# with the default build, and documents how to enable native plugins
# via a custom build:
#   cargo build --release --features plugins
# (combine with `wasm` for both native and WASM plugins).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

BASE_URL="http://localhost:8080"

echo "=== Test 01: Native Plugin Filters (NativeFilter, DW-119) ==="

echo ""
echo "--- Background: NativeFilter trait ---"
echo "Native filters are compile-in Rust types implementing the"
echo "NativeFilter trait, registered with NativeRegistry at startup."
echo "They attach identically to WASM plugins from config's point of"
echo "view: both are entries in the top-level 'plugins' list, referenced"
echo "by name from routes."
echo ""
echo "Feature gate: 'plugins' cargo feature (default OFF)"
echo "Build: cargo build --release --features plugins"
echo ""

echo "--- Verifying gateway starts with default build ---"
wait_for "$BASE_URL/healthz" 30

status=$(http_status "$BASE_URL/healthz")
body=$(http_body "$BASE_URL/healthz")
assert_status "200" "$status" "GET /healthz returns 200"
assert_contains "$body" "ok" "GET /healthz body is 'ok'"

echo ""
echo "--- Verifying proxying works (echo upstream) ---"
status=$(http_status "$BASE_URL/v1/echo/test")
body=$(http_body "$BASE_URL/v1/echo/test")
assert_status "200" "$status" "GET /v1/echo/test returns 200"
assert_contains "$body" "echo" "GET /v1/echo/test body contains echo JSON"

echo ""
echo "--- Native plugin config block is accepted but inert ---"
echo "The config schema accepts the top-level 'plugins' block with"
echo "native filter definitions. Without the 'plugins' feature, the"
echo "block is accepted but the filters are not instantiated."
echo "The gateway starts and routes traffic normally."

print_summary
