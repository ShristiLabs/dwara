#!/bin/bash
# test-05-extism-pdk.sh — Extism PDK plugin runtime (STUBBED, DW-109).
#
# Extism is the third plugin implementation path alongside proxy-wasm
# (DW-055) and native filters (DW-119): plugins written against the
# Extism Plugin Development Kit, a higher-level host-function ABI with
# language SDKs for Rust, Go, Python, JavaScript, and others. An
# Extism plugin is designed to be an entry in the top-level `plugins`
# list, referenced by name from routes, hooking the same four phase
# slots (`request_headers`, `request_body`, `response_headers`,
# `response_body`) with the same short-circuit semantics.
#
# STATUS: STUBBED. The runtime scaffold lives at
# crates/dwara-core/src/plugins/extism.rs behind the `extism` cargo
# feature (default OFF). The actual `extism` crate (the Extism C SDK
# FFI wrapper) is NOT a dependency yet -- the host's runtime calls are
# documented no-ops that return FilterOutcome::Continue with the input
# unchanged. The config schema does not yet accept the `extism:`
# selector either: PluginConfig accepts `wasm`/`native` only, so an
# `extism:` block is REJECTED by validation as an unknown field. The
# schema, validation, and dispatch trait were designed so the real
# wiring lands without touching the rest of the gateway.
#
# This test verifies the current, honest state:
#   1) The plugins config SHAPE the Extism path will join (a `wasm:`
#      plugin block with phases/config/limits) validates via
#      `dwara-cli validate`.
#   2) The `extism:` selector is rejected by the OSS config schema
#      (unknown field) -- the documented limitation. A future build
#      with the real Extism runtime adds the selector; until then the
#      guide's `extism:` examples do not validate.
#   3) The demo gateway starts and proxies normally with the default
#      build (the stub does not affect the request path).
#
# See docs-site/guide/extism-pdk.md for the target design (bot
# detection, signed-URL verification, certificate pinning hooks).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

BASE_URL="http://localhost:8080"

echo "=== test-05-extism-pdk ==="

# Locate the host operator CLI (`dwara-cli`). The scratch demo image
# ships only the gateway server binary, so validation runs on the host.
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

# Scratch dir for the config-shape probes; cleaned up on exit.
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

# A minimal valid gateway config the probes are appended to.
base_config() {
  cat <<'EOF'
listeners:
  - name: edge-http
    address: 127.0.0.1
    port: 9099
    protocol: http
routes:
  - name: healthz
    service: echo-service
    match:
      path:
        type: exact
        value: /healthz
    action:
      type: respond
      status: 200
      body: ok
    auth_required: false
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
EOF
}

echo ""
echo "--- Background: Extism PDK (DW-109) ---"
echo "Extism plugins are .wasm modules written against the Extism PDK"
echo "(SDKs for Rust, Go, Python, JS, ...). They are designed to occupy"
echo "the same phase slots as proxy-wasm and native filters, selected"
echo "by config. The runtime scaffold is feature-gated behind the"
echo "'extism' cargo feature (default OFF) and the host calls are"
echo "STUBBED no-ops; the config schema does not accept the 'extism:'"
echo "selector yet (wasm/native only)."
echo ""

# 1) The plugins block shape (a wasm plugin with phases + config +
#    limits) validates: this is the schema the Extism selector joins.
base_config > "$SCRATCH/wasm-shape.yaml"
cat >> "$SCRATCH/wasm-shape.yaml" <<'EOF'
plugins:
  - name: bot-detect
    wasm: /etc/dwara/plugins/bot_detect.wasm
    phases:
      - request_headers
    config: '{"mode": "observe"}'
    limits:
      fuel: 1000000
      memory_mb: 32
      timeout_ms: 100
EOF
out=$("$CLI" validate "$SCRATCH/wasm-shape.yaml" 2>&1) && rc=0 || rc=1
assert_status 0 "$rc" "plugins block shape (wasm selector) validates via dwara-cli"
assert_contains "$out" "ok:" "validation prints ok for the plugins block shape"

# 2) Documented limitation: the `extism:` selector is rejected by the
#    current config schema (unknown field). It lands with the real
#    Extism runtime; until then the guide's extism: examples do not
#    validate. This is fail-closed, not silently ignored.
base_config > "$SCRATCH/extism-shape.yaml"
cat >> "$SCRATCH/extism-shape.yaml" <<'EOF'
plugins:
  - name: bot-detect
    extism: /etc/dwara/plugins/bot_detect.wasm
    phases:
      - request_headers
    config: '{"mode": "observe"}'
EOF
out=$("$CLI" validate "$SCRATCH/extism-shape.yaml" 2>&1) && rc=0 || rc=1
assert_status 1 "$rc" "extism: selector rejected by OSS schema (documented limitation)"
assert_contains "$out" "unknown field" "rejection names the unknown field (fail-closed, not silent)"

echo ""
echo "--- Verifying gateway starts with default build (stub is inert) ---"
wait_for "$BASE_URL/healthz" 30

status=$(http_status "$BASE_URL/healthz")
assert_status 200 "$status" "GET /healthz returns 200 (stubbed runtime is inert)"

status=$(http_status "$BASE_URL/v1/echo/test")
body=$(http_body "$BASE_URL/v1/echo/test")
assert_status 200 "$status" "GET /v1/echo/test returns 200"
assert_contains "$body" "echo" "GET /v1/echo/test body contains echo JSON"

echo ""
echo "NOTE: the Extism runtime is a documented stub (DW-109). With a"
echo "feature-enabled build (cargo build --features extism,plugins),"
echo "the host records plugin definitions but the Extism SDK calls are"
echo "no-ops returning Continue. The 'extism:' config selector lands"
echo "with the real runtime. See docs-site/guide/extism-pdk.md."

print_summary
