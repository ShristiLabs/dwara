#!/bin/bash
# test.sh -- demo 03: custom request authentication.
#
# Builds the shipped plugins/examples/static-auth plugin BY PATH and
# runs it against a mock protected upstream (an echo service, so the
# demo proves authenticated traffic reaches the backend).
#
# Asserted:
#   1. missing credential  -> 401 + WWW-Authenticate Bearer challenge
#      (the plugin's own response; the upstream is never dialed)
#   2. wrong token         -> 401
#   3. wrong scheme        -> 401 (Bearer is configured)
#   4. correct token       -> 200 + the upstream's echo body
#   5. the sibling /public/ route (no plugin) serves WITHOUT any
#      credential throughout
#
# Ports (exclusive to this demo): gateway 18221, upstream 18222.
set -euo pipefail

# helpers.sh redefines SCRIPT_DIR/DEMO_ROOT from ITS own path when
# sourced, so the demo's paths must be computed AFTER the source line.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/../_shared/helpers.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$DEMO_ROOT/../.." && pwd)"

PORT_GW=18221
PORT_UP=18222
BASE_URL="http://127.0.0.1:$PORT_GW"

GW_PID=""
UP_PID=""
SCRATCH="$(mktemp -d /tmp/dwara-demo13-03.XXXXXX)"
CLEANED=0

cleanup() {
  if [ "$CLEANED" -eq 1 ]; then
    return 0
  fi
  CLEANED=1
  for pid in "$GW_PID" "$UP_PID"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  rm -rf "$SCRATCH"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

port_in_use() {
  (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null
}

echo "=== demo 03: custom request authentication ==="

echo "--- pre-flight: ports $PORT_GW $PORT_UP must be free"
for port in "$PORT_GW" "$PORT_UP"; do
  if port_in_use "$port"; then
    echo "FAIL: port $port already in use (stale process from an earlier run?)"
    exit 1
  fi
done

echo "--- toolchain: wasm32-wasip1 target (idempotent)"
rustup target add wasm32-wasip1 >/dev/null 2>&1 || {
  echo "FAIL: rustup target add wasm32-wasip1 failed"
  exit 1
}

echo "--- building the shipped static-auth example BY PATH"
AUTH_EXAMPLE="$REPO_ROOT/plugins/examples/static-auth"
WASM="$AUTH_EXAMPLE/target/wasm32-wasip1/release/static_auth.wasm"
rm -f "$WASM"
(
  cd "$AUTH_EXAMPLE" &&
    cargo build -q --release --target wasm32-wasip1 2>&1 | tail -5
) || {
  echo "FAIL: static-auth build failed"
  exit 1
}
[ -f "$WASM" ] || {
  echo "FAIL: plugin artifact missing: $WASM"
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

echo "--- starting the protected upstream"
python3 "$SCRIPT_DIR/protected-upstream.py" "$PORT_UP" >"$SCRATCH/upstream.log" 2>&1 &
UP_PID=$!
wait_for "http://127.0.0.1:$PORT_UP/public/ping" 15

echo "--- starting the gateway"
(
  cd "$REPO_ROOT" &&
    DWARA_CONFIG="$SCRIPT_DIR/dwara.yaml" exec "$DWARA"
) >"$SCRATCH/gateway.log" 2>&1 &
GW_PID=$!
wait_for "$BASE_URL/healthz" 30

echo ""
echo "--- denied at the edge: 401 + WWW-Authenticate, no upstream dial"
status=$(http_status "$BASE_URL/protected/profile")
assert_status "401" "$status" "missing credential is challenged with 401"
# HTTP/1.1 header names arrive from the gateway lowercased (hyper's
# HeaderName); match case-insensitively, like the plugin gallery does.
challenge=$(curl -s -D - -o /dev/null "$BASE_URL/protected/profile" | tr 'A-Z' 'a-z')
assert_contains "$challenge" "www-authenticate: bearer realm=" \
  "the 401 carries a WWW-Authenticate Bearer challenge"
body=$(http_body "$BASE_URL/protected/profile")
assert_contains "$body" "missing credential" "the 401 body names the reason"
status=$(http_status "$BASE_URL/protected/profile" -H "authorization: Bearer not-the-token")
assert_status "401" "$status" "wrong token is denied"
status=$(http_status "$BASE_URL/protected/profile" -H "authorization: Basic c29tZXRoaW5n")
assert_status "401" "$status" "wrong scheme is denied (Bearer is configured)"

echo ""
echo "--- the correct token reaches the backend"
status=$(http_status "$BASE_URL/protected/profile" -H "authorization: Bearer dwara-demo-secret")
assert_status "200" "$status" "the correct bearer token is forwarded"
body=$(http_body "$BASE_URL/protected/profile" -H "authorization: Bearer dwara-demo-secret")
assert_contains "$body" '"path":"/protected/profile"' \
  "the authenticated request reached the upstream (echo body)"

echo ""
echo "--- the sibling unprotected route is unaffected"
status=$(http_status "$BASE_URL/public/ping")
assert_status "200" "$status" "/public serves with NO credential"
body=$(http_body "$BASE_URL/public/ping")
assert_contains "$body" '"path":"/public/ping"' "the control route reaches the upstream"

print_summary
