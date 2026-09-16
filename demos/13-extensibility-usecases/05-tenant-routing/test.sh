#!/bin/bash
# test.sh -- demo 05: tenant-aware routing and tagging.
#
# Builds the tenant-router SDK-style plugin and runs it on the single
# /portal/ route. The plugin's :path rewrite is applied to the
# forwarded request, so the mock upstream answers /tenant/<t>/* per
# tenant straight from the request path.
#
# Asserted (for x-org-domain: acme.com, globex.com, and no header):
#   1. per-tenant routing: the upstream serves the REWRITTEN path and
#      decodes the tenant from it ("tenant":"acme" etc.) -- the
#      request itself only ever carried /portal/...
#   2. the upstream SAW the stamped x-tenant request header
#      ("seen_tenant_header")
#   3. the client response carries the stamped x-tenant response
#      header (the response_headers phase)
#   4. a missing org header routes to the safe default tenant
#      "public"
#
# Ports (exclusive to this demo): gateway 18241, upstream 18242.
set -euo pipefail

# helpers.sh redefines SCRIPT_DIR/DEMO_ROOT from ITS own path when
# sourced, so the demo's paths must be computed AFTER the source line.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/../_shared/helpers.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$DEMO_ROOT/../.." && pwd)"

PORT_GW=18241
PORT_UP=18242
BASE_URL="http://127.0.0.1:$PORT_GW"

GW_PID=""
UP_PID=""
SCRATCH="$(mktemp -d /tmp/dwara-demo13-05.XXXXXX)"
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

echo "=== demo 05: tenant-aware routing ==="

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

echo "--- building the tenant-router plugin (cargo, wasm32-wasip1)"
WASM="$SCRIPT_DIR/plugin/target/wasm32-wasip1/release/tenant_router.wasm"
rm -f "$WASM"
(
  cd "$SCRIPT_DIR/plugin" &&
    cargo build -q --release --target wasm32-wasip1 2>&1 | tail -5
) || {
  echo "FAIL: plugin build failed"
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

echo "--- starting the tenants upstream"
python3 "$SCRIPT_DIR/tenants-upstream.py" "$PORT_UP" >"$SCRATCH/upstream.log" 2>&1 &
UP_PID=$!
wait_for "http://127.0.0.1:$PORT_UP/tenant/probe/x" 15

echo "--- starting the gateway"
(
  cd "$REPO_ROOT" &&
    DWARA_CONFIG="$SCRIPT_DIR/dwara.yaml" exec "$DWARA"
) >"$SCRATCH/gateway.log" 2>&1 &
GW_PID=$!
wait_for "$BASE_URL/healthz" 30

# expect_tenant <x-org-domain or ""> <expected-tenant> <description>
expect_tenant() {
  local org="$1" tenant="$2" desc="$3" body headers
  if [ -n "$org" ]; then
    body=$(http_body "$BASE_URL/portal/dashboard" -H "x-org-domain: $org")
    headers=$(curl -s -D - -o /dev/null -H "x-org-domain: $org" "$BASE_URL/portal/dashboard")
  else
    body=$(http_body "$BASE_URL/portal/dashboard")
    headers=$(curl -s -D - -o /dev/null "$BASE_URL/portal/dashboard")
  fi
  assert_contains "$body" "\"tenant\":\"$tenant\"" "$desc (tenant decoded from the rewritten path prefix)"
  assert_contains "$body" "\"seen_tenant_header\":\"$tenant\"" "$desc (upstream saw the stamped x-tenant header)"
  assert_contains "$body" "\"path\":\"/tenant/$tenant/dashboard\"" \
    "$desc (the upstream received the rewritten /tenant/ path)"
  assert_header "$headers" "x-tenant" "$tenant" "$desc (stamped response header)"
}

echo ""
echo "--- tenant verdicts from the x-org-domain header grammar"
expect_tenant "acme.com" acme "x-org-domain: acme.com routes to tenant acme"
expect_tenant "globex.com" globex "x-org-domain: globex.com routes to tenant globex"
expect_tenant "" public "a missing org header routes to the public default"

print_summary
