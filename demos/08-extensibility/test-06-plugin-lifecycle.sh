#!/bin/bash
# test-06-plugin-lifecycle.sh — plugin lifecycle management (DW-056).
#
# The plugin lifecycle manager (crates/dwara-core/src/wasm/lifecycle.rs)
# owns how plugins are loaded, hot-swapped, and health-tracked:
#
#   Loading (per configured plugin):
#     1. read the .wasm file from the configured path
#     2. compute a SHA-256 checksum of the module
#     3. compile it with wasmtime (via the plugin runner)
#     4. validate the proxy-wasm ABI (proxy_on_vm_start export at
#        minimum, exported linear memory, no unknown host imports)
#     5. instantiate with the configured limits (fuel/memory/timeout)
#   A plugin whose file cannot be read or compiled FAILS the load --
#   the operator knows up front, not from silently missing behavior.
#
#   Hot swap on reload: plugins are re-evaluated by comparing
#   checksums. Unchanged (same checksum): the loaded instance and its
#   health state are kept, nothing is recompiled. Changed: the old
#   module is replaced and health resets to Healthy. Removed: the
#   entry is dropped. The swap is atomic: the new plugin table and
#   runner are built first, then swapped in.
#
#   Health tracking: Healthy / Crashed { error, crash_count } /
#   Disabled { reason }. A runtime failure calls mark_crashed (the
#   counter accumulates); a successful invocation or a checksum change
#   calls mark_healthy; the circuit breaker can disable a plugin.
#   Health state lives in the lifecycle manager -- there is no
#   /plugins admin endpoint yet (documented follow-up).
#
#   Failure isolation: the manager keeps a route-to-plugins map; routes
#   referencing a crashed plugin fail closed with 500, other routes are
#   unaffected. Phase ordering across multiple plugins is deterministic
#   (phase first, then the route's plugins list order).
#
# LIMITATION: this runtime is a compile-time capability (`wasm` for the
# proxy-wasm host, `plugins` for native filters; both default OFF) and
# is NOT included in the published OSS binaries -- the lifecycle
# manager, runner, and unified dispatch chain are complete and
# test-covered as library components, with request-path wiring landing
# iteratively. The default `dwara:demo` image therefore exposes no
# live plugin surface (no admin /plugins endpoint, no plugin gauges).
#
# This test verifies what IS wired in the default image:
#   1) Config shape: the plugins block + route-level plugin attachment
#      (the schema the lifecycle manager consumes) validates via
#      `dwara-cli validate`.
#   2) Live: the config hot-reload flow (DW-006, demonstrated by the
#      09-operations category) that triggers the lifecycle manager's
#      checksum re-evaluation in a feature-enabled build -- touch the
#      config file, then verify the gateway still re-validates and
#      serves traffic.
#
# See docs-site/guide/plugin-lifecycle.md for the full behavior.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

BASE_URL="http://localhost:8080"

echo "=== test-06-plugin-lifecycle ==="

# Locate the host operator CLI (`dwara-cli`).
CLI=""
for c in "$SCRIPT_DIR/../../target/debug/dwara-cli" \
         "$SCRIPT_DIR/../../target/release/dwara-cli" \
         "$(command -v dwara-cli 2>/dev/null || true)"; do
  if [ -n "$c" ] && [ -x "$c" ]; then CLI="$c"; break; fi
done
if [ -z "$CLI" ]; then
  echo -e "${RED}FAIL${NC}: dwara-cli not found (build it: cargo build -p dwara-cli)"
  FAIL=$((FAIL + 1))
  print_summary
  exit 1
fi
echo "using dwara-cli at: $CLI"

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

echo ""
echo "--- Background: plugin lifecycle (DW-056) ---"
echo "Load: read .wasm -> SHA-256 checksum -> wasmtime compile -> ABI"
echo "validate -> instantiate with limits. A bad module FAILS the load."
echo "Hot swap on reload: unchanged checksums keep the loaded instance;"
echo "changed checksums replace the module and reset health to Healthy."
echo "Health: Healthy / Crashed{error,crash_count} / Disabled{reason};"
echo "routes referencing a crashed plugin fail closed with 500."
echo ""

# 1) Config shape: the lifecycle manager consumes the top-level
#    `plugins` list plus each route's `plugins` attachment. Both
#    validate in the OSS schema (shape-only: file existence is checked
#    at feature-enabled load time, not by validate).
cat > "$SCRATCH/lifecycle-shape.yaml" <<'EOF'
listeners:
  - name: edge-http
    address: 127.0.0.1
    port: 9099
    protocol: http
routes:
  - name: echo-route
    service: echo-service
    match:
      path:
        type: prefix
        value: /v1/echo/
    action:
      type: proxy
      rewrite:
        type: strip_prefix
    auth_required: false
    plugins:
      - example-wasm-plugin
services:
  - name: echo-service
    upstream: echo-upstream
upstreams:
  - name: echo-upstream
    load_balancer: round_robin
    protocol: http1
    endpoints:
      - address: 127.0.0.1
        port: 9098
plugins:
  - name: example-wasm-plugin
    wasm: /etc/dwara/plugins/filter.wasm
    phases:
      - request_headers
      - request_body
      - response_headers
      - response_body
    config: '{"mode": "observe"}'
    limits:
      fuel: 1000000
      memory_mb: 32
      timeout_ms: 100
EOF
out=$("$CLI" validate "$SCRATCH/lifecycle-shape.yaml" 2>&1) && rc=0 || rc=1
assert_status 0 "$rc" "plugins block + route attachment validates (lifecycle schema)"
assert_contains "$out" "ok:" "validation prints ok for the lifecycle config shape"

echo ""
echo "--- Verifying the live config-reload flow (the hot-swap trigger) ---"
wait_for "$BASE_URL/healthz" 30

status=$(http_status "$BASE_URL/v1/echo/test")
assert_status 200 "$status" "echo route proxies before reload"

# 2) Touch the mounted config file (mtime change) to trigger the file
#    watcher: the gateway re-reads, validates, and atomically publishes
#    a new snapshot generation. In a feature-enabled build this same
#    hook is where the lifecycle manager re-evaluates plugin checksums
#    (unchanged -> reuse; changed -> replace + health reset).
echo "--- touching dwara.yaml to trigger the reload hook ---"
touch "$SCRIPT_DIR/dwara.yaml"
sleep 2

status=$(http_status "$BASE_URL/v1/echo/test")
assert_status 200 "$status" "echo route proxies after reload nudge (checksum re-evaluation hook)"

body=$(http_body "$BASE_URL/healthz")
assert_contains "$body" "ok" "healthz responds ok after reload nudge"

echo ""
echo "NOTE: the default dwara:demo image has no plugin runtime compiled"
echo "in (the 'wasm'/'plugins' cargo features are default OFF), so there"
echo "is no live plugin surface to probe -- plugin health lives in the"
echo "lifecycle manager and no /plugins admin endpoint exists yet. The"
echo "reload flow above is the hook a feature-enabled build uses for"
echo "checksum-based hot swap. See docs-site/guide/plugin-lifecycle.md."

print_summary
