#!/bin/bash
# test.sh -- demo 04: zero-upstream endpoints (feature flags).
#
# Builds the hand-written no_std WASM module in module/ (the
# nano-service dedicated ABI: memory/alloc/handle exports, dwara.*
# imports, no WASI) and serves it as the /flags/ route's action. No
# upstream exists for the route -- the module IS the endpoint.
#
# Asserted:
#   1. GET /flags/new-ui      -> 200 {"flag":true}   (compiled ON)
#   2. GET /flags/beta-search -> 200 {"flag":true}   (compiled ON)
#   3. GET /flags/legacy-reports -> 200 {"flag":false} (everything else)
#   4. Content-Type: application/json on every verdict
#   5. a query string does not change the verdict
#
# The 413 (request body over 1 MiB), 504 (execution_timeout_ms), and
# 502 (handle returns non-zero / traps) failure modes are contract,
# not asserted here -- they need oversized bodies or deliberately
# broken modules; see the README's failure-semantics table.
#
# Ports (exclusive to this demo): gateway 18231 (no upstream).
set -euo pipefail

# helpers.sh redefines SCRIPT_DIR/DEMO_ROOT from ITS own path when
# sourced, so the demo's paths must be computed AFTER the source line.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/../_shared/helpers.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$DEMO_ROOT/../.." && pwd)"

PORT_GW=18231
BASE_URL="http://127.0.0.1:$PORT_GW"

GW_PID=""
SCRATCH="$(mktemp -d /tmp/dwara-demo13-04.XXXXXX)"
CLEANED=0

cleanup() {
  if [ "$CLEANED" -eq 1 ]; then
    return 0
  fi
  CLEANED=1
  [ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null || true
  rm -rf "$SCRATCH"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

port_in_use() {
  (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null
}

echo "=== demo 04: feature-flag nano-service ==="

echo "--- pre-flight: port $PORT_GW must be free"
if port_in_use "$PORT_GW"; then
  echo "FAIL: port $PORT_GW already in use (stale process from an earlier run?)"
  exit 1
fi

echo "--- toolchain: wasm32-unknown-unknown target (idempotent)"
rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || {
  echo "FAIL: rustup target add wasm32-unknown-unknown failed"
  exit 1
}

echo "--- building the nano-service module (no_std, plain WASM)"
WASM="$SCRIPT_DIR/module/target/wasm32-unknown-unknown/release/feature_flag_nano.wasm"
rm -f "$WASM"
(
  cd "$SCRIPT_DIR/module" &&
    cargo build -q --release --target wasm32-unknown-unknown 2>&1 | tail -5
) || {
  echo "FAIL: nano-service module build failed"
  exit 1
}
[ -f "$WASM" ] || {
  echo "FAIL: module artifact missing: $WASM"
  exit 1
}

echo "--- locating the gateway binary (cargo build -p dwara-bin)"
DWARA=""
for candidate in "$REPO_ROOT/target/debug/dwara" "$REPO_ROOT/target/release/dwara"; do
  if [ -x "$candidate" ]; then
    DWARA="$candidate"
    break
  fi
done
if [ -z "$DWARA" ]; then
  (cd "$REPO_ROOT" && cargo build -q -p dwara-bin 2>&1 | tail -5) || {
    echo "FAIL: gateway build failed"
    exit 1
  }
  DWARA="$REPO_ROOT/target/debug/dwara"
fi

echo "--- starting the gateway (no upstream to start)"
(
  cd "$REPO_ROOT" &&
    DWARA_CONFIG="$SCRIPT_DIR/dwara.yaml" exec "$DWARA"
) >"$SCRATCH/gateway.log" 2>&1 &
GW_PID=$!
wait_for "$BASE_URL/healthz" 30

echo ""
echo "--- canned verdicts, no upstream hop"
status=$(http_status "$BASE_URL/flags/new-ui")
assert_status "200" "$status" "GET /flags/new-ui answers 200 from the module"
body=$(http_body "$BASE_URL/flags/new-ui")
assert_contains "$body" '{"flag":true}' "a compiled-ON flag answers {\"flag\":true}"
body=$(http_body "$BASE_URL/flags/beta-search")
assert_contains "$body" '{"flag":true}' "the second compiled-ON flag answers true"
body=$(http_body "$BASE_URL/flags/legacy-reports")
assert_contains "$body" '{"flag":false}' "an unknown flag answers {\"flag\":false}"
body=$(http_body "$BASE_URL/flags/new-ui?client=mobile")
assert_contains "$body" '{"flag":true}' "a query string does not change the verdict"
headers=$(curl -s -D - -o /dev/null "$BASE_URL/flags/new-ui" | tr 'A-Z' 'a-z')
assert_contains "$headers" "content-type: application/json" \
  "the module's response_header import set Content-Type"

print_summary
