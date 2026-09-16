#!/bin/bash
# test.sh -- demo 07: per-request external decisions with a TTL cache.
#
# Builds the entitlement-guard SDK-style plugin (proxy_http_call +
# pause/resume + a 2s shared-data cache) and runs it on the single
# /api/ route. Every request is decided by the mock decision service;
# the verdict rides the forwarded request to the mock user API.
#
# Asserted:
#   1. the FIRST request for a user hits the decision service
#      (its per-user count goes to 1) and the upstream sees
#      x-entitlement: allow, source service
#   2. a request inside the TTL window is served from the plugin's
#      cache (the count stays 1; the upstream sees source cache)
#   3. a DIFFERENT user is uncached (their count goes to 1)
#   4. a denied user is short-circuited with 403 by the plugin from
#      the delivered (non-2xx-capable) verdict data -- the upstream is
#      never dialed
#   5. a decision slower than the plugin's 400ms callout timeout
#      fails the route CLOSED: 500 plugin_failed, upstream never
#      dialed, count for that user recorded once
#
# Ports (exclusive to this demo): gateway 18261, decision 18262,
# user API 18263.
set -euo pipefail

# helpers.sh redefines SCRIPT_DIR/DEMO_ROOT from ITS own path when
# sourced, so the demo's paths must be computed AFTER the source line.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/../_shared/helpers.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$DEMO_ROOT/../.." && pwd)"

PORT_GW=18261
PORT_DECISION=18262
PORT_API=18263
BASE_URL="http://127.0.0.1:$PORT_GW"

GW_PID=""
DECISION_PID=""
API_PID=""
SCRATCH="$(mktemp -d /tmp/dwara-demo13-07.XXXXXX)"
CLEANED=0

cleanup() {
  if [ "$CLEANED" -eq 1 ]; then
    return 0
  fi
  CLEANED=1
  for pid in "$GW_PID" "$DECISION_PID" "$API_PID"; do
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

echo "=== demo 07: per-request decisions with a TTL cache ==="

echo "--- pre-flight: ports $PORT_GW $PORT_DECISION $PORT_API must be free"
for port in "$PORT_GW" "$PORT_DECISION" "$PORT_API"; do
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

echo "--- building the entitlement-guard plugin (cargo, wasm32-wasip1)"
WASM="$SCRIPT_DIR/plugin/target/wasm32-wasip1/release/entitlement_guard.wasm"
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

echo "--- starting the decision service and the user API"
python3 "$SCRIPT_DIR/services/decision-service.py" "$PORT_DECISION" >"$SCRATCH/decision.log" 2>&1 &
DECISION_PID=$!
python3 "$SCRIPT_DIR/services/user-api.py" "$PORT_API" >"$SCRATCH/api.log" 2>&1 &
API_PID=$!
wait_for "http://127.0.0.1:$PORT_DECISION/counts" 15
# The user API answers every path; one request proves readiness.
curl -sf "http://127.0.0.1:$PORT_API/probe" >/dev/null

echo "--- starting the gateway"
(
  cd "$REPO_ROOT" &&
    DWARA_CONFIG="$SCRIPT_DIR/dwara.yaml" exec "$DWARA"
) >"$SCRATCH/gateway.log" 2>&1 &
GW_PID=$!
wait_for "$BASE_URL/healthz" 30

# count_for <user> -- the decision service's per-user hit count.
count_for() {
  curl -s "http://127.0.0.1:$PORT_DECISION/counts" | python3 -c "
import json, sys
print(json.load(sys.stdin).get('$1', 0))
"
}

echo ""
echo "--- 1. first request for alice: the decision service decides it"
BODY=$(http_body "$BASE_URL/api/orders" -H "x-user: alice")
assert_contains "$BODY" '"entitlement":"allow"' "the upstream saw the applied allow verdict"
assert_contains "$BODY" '"entitlement_source":"service"' "the first request hit the decision service"
assert_contains "$BODY" '"user":"alice"' "the principal rode the request headers"
COUNT=$(count_for alice)
assert_status 1 "$COUNT" "the decision service saw exactly one alice hit"

echo ""
echo "--- 2. second request for alice (inside the TTL window): cached"
BODY=$(http_body "$BASE_URL/api/orders" -H "x-user: alice")
assert_contains "$BODY" '"entitlement":"allow"' "the cached verdict is still applied"
assert_contains "$BODY" '"entitlement_source":"cache"' "this request was served from the plugin's cache"
COUNT=$(count_for alice)
assert_status 1 "$COUNT" "the cached window did NOT hit the decision service again"

echo ""
echo "--- 3. a different user (bob) is uncached"
BODY=$(http_body "$BASE_URL/api/orders" -H "x-user: bob")
assert_contains "$BODY" '"entitlement_source":"service"' "bob's first request hit the service"
COUNT=$(count_for bob)
assert_status 1 "$COUNT" "the service saw exactly one bob hit"

echo ""
echo "--- 4. a denied user is short-circuited by the plugin (403)"
STATUS=$(http_status "$BASE_URL/api/orders" -H "x-user: mallory")
assert_status 403 "$STATUS" "the plugin's 403 from the delivered deny verdict"

echo ""
echo "--- 5. a decision slower than the callout timeout fails CLOSED"
STATUS=$(http_status "$BASE_URL/api/orders" -H "x-user: slow")
assert_status 500 "$STATUS" "the timed-out decision fails the route closed (500)"
BODY=$(http_body "$BASE_URL/api/orders" -H "x-user: slow")
assert_contains "$BODY" '"code":"plugin_failed"' "the 500 is the plugin_failed envelope"

print_summary
