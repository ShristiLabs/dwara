#!/bin/bash
# test.sh -- demo 01: user-subset migration to a new API version.
#
# The flagship recipe (docs-site "Extension use cases and recipes",
# use case 1, Option A) run live: an SDK-style proxy-wasm plugin
# (plugin/) rewrites /v1/ -> /v2/ for the users on the entitlement
# allow-list, the entitlement microservice (services/entitlement.py)
# owns the list, and services/publish.sh materializes it into the
# plugin's config include and triggers a hot reload.
#
# Asserted:
#   1. user on the list      -> the /v2/ endpoint answers (migrated)
#   2. user off the list     -> the /v1/ endpoint answers
#   3. unknown / missing id  -> /v1/ (fail to the old version)
#   4. empty allow-list      -> EVERYONE gets /v1/ (safe default)
#   5. hot-reload flip       -> publisher adds/removes a user; the
#      NEXT request changes verdict with no restart (module checksum
#      unchanged, only the config generation moves)
#   6. the plugin-less /public/ control route is unaffected throughout
#
# Ports (exclusive to this demo): gateway 18201, user API 18202,
# entitlement service 18203.
set -euo pipefail

# helpers.sh redefines SCRIPT_DIR/DEMO_ROOT from ITS own path when
# sourced, so the demo's paths must be computed AFTER the source line.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/../_shared/helpers.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$DEMO_ROOT/../.." && pwd)"

PORT_GW=18201
PORT_API=18202
PORT_ENT=18203
BASE_URL="http://127.0.0.1:$PORT_GW"
ENT_URL="http://127.0.0.1:$PORT_ENT"

GW_PID=""
API_PID=""
ENT_PID=""
SCRATCH="$(mktemp -d /tmp/dwara-demo13-01.XXXXXX)"
CLEANED=0

cleanup() {
  # Idempotent: EXIT and the signal traps both land here.
  if [ "$CLEANED" -eq 1 ]; then
    return 0
  fi
  CLEANED=1
  for pid in "$GW_PID" "$API_PID" "$ENT_PID"; do
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

echo "=== demo 01: user-subset migration ==="

echo "--- pre-flight: ports $PORT_GW $PORT_API $PORT_ENT must be free"
for port in "$PORT_GW" "$PORT_API" "$PORT_ENT"; do
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

echo "--- building the v2-migrator plugin (cargo, wasm32-wasip1)"
WASM="$SCRIPT_DIR/plugin/target/wasm32-wasip1/release/v2_migrator.wasm"
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

echo "--- staging the scratch config (dwara.yaml copied verbatim)"
cp "$SCRIPT_DIR/dwara.yaml" "$SCRATCH/dwara.yaml"

echo "--- starting the mock upstreams"
python3 "$SCRIPT_DIR/services/user-api.py" "$PORT_API" >"$SCRATCH/user-api.log" 2>&1 &
API_PID=$!
python3 "$SCRIPT_DIR/services/entitlement.py" "$PORT_ENT" >"$SCRATCH/entitlement.log" 2>&1 &
ENT_PID=$!
wait_for "http://127.0.0.1:$PORT_API/v1/user" 15
wait_for "$ENT_URL/entitlements" 15

echo "--- initial publish: allow-list [user-42] (the service's boot state)"
bash "$SCRIPT_DIR/services/publish.sh" "$SCRATCH" "$ENT_URL" >"$SCRATCH/publish-0.log"

echo "--- starting the gateway"
(
  cd "$REPO_ROOT" &&
    DWARA_CONFIG="$SCRATCH/dwara.yaml" exec "$DWARA"
) >"$SCRATCH/gateway.log" 2>&1 &
GW_PID=$!
wait_for "$BASE_URL/healthz" 30

# Helpers -----------------------------------------------------------

# api_of <user-id or ""> -- prints '"api":"v1"' or '"api":"v2"' for
# GET /v1/user through the gateway.
api_of() {
  local user="$1"
  if [ -n "$user" ]; then
    http_body "$BASE_URL/v1/user" -H "x-user-id: $user"
  else
    http_body "$BASE_URL/v1/user"
  fi
}

# expect_api <user-id> <v1|v2> <description>
expect_api() {
  local user="$1" expected="$2" desc="$3" body
  body=$(api_of "$user")
  assert_contains "$body" "\"api\":\"$expected\"" "$desc"
}

# wait_for_api <user-id> <v1|v2> -- poll until the verdict flips
# (bounded; a reload takes effect within the 250 ms debounce plus the
# publish, so 15 s is a generous margin: 60 x 0.25 s).
wait_for_api() {
  local user="$1" expected="$2" ticks=0
  while [ "$ticks" -lt 60 ]; do
    if grep -q "\"api\":\"$expected\"" <<<"$(api_of "$user")"; then
      return 0
    fi
    sleep 0.25
    ticks=$((ticks + 1))
  done
  return 1
}

# publish_and_flip <user-id> <v1|v2> <description> [users...]: replace
# the entitlement list, publish, and poll for the verdict to reach the
# expected value.
publish_and_flip() {
  local user="$1" expected="$2" desc="$3"
  shift 3
  local list rc=0
  list=$(printf '%s\n' "$@" | python3 -c 'import json,sys; print(json.dumps({"allowed_users": [l.strip() for l in sys.stdin if l.strip()]}))')
  curl -sf -X POST -H "Content-Type: application/json" -d "$list" "$ENT_URL/entitlements" >/dev/null
  bash "$SCRIPT_DIR/services/publish.sh" "$SCRATCH" "$ENT_URL" "$GW_PID" >/dev/null
  wait_for_api "$user" "$expected" || rc=1
  assert_status 0 "$rc" "hot reload: $desc"
}

control_ok() {
  local body
  body=$(http_body "$BASE_URL/public/status")
  assert_contains "$body" '"path":"/public/status"' "$1"
}

# Assertions --------------------------------------------------------

echo ""
echo "--- verdicts with the initial allow-list [user-42]"
expect_api "user-42" v2 "user on the list is migrated to /v2/user"
expect_api "user-77" v1 "user off the list stays on /v1/user"
expect_api "someone-else" v1 "unknown user id stays on /v1/user"
expect_api "" v1 "missing x-user-id header stays on /v1/user"
control_ok "control route serves before any reload"

echo ""
echo "--- flip 1: empty allow-list (publisher outage -> safe default)"
publish_and_flip "user-42" v1 \
  "empty list moves user-42 back to /v1/user" ""
expect_api "user-77" v1 "user-77 still on /v1/user with an empty list"
expect_api "" v1 "missing header still on /v1/user with an empty list"
control_ok "control route serves after the empty-list publish"

echo ""
echo "--- flip 2: add user-77 (list [user-42 user-77])"
publish_and_flip "user-77" v2 \
  "adding user-77 migrates them on the next request" "user-42" "user-77"
expect_api "user-42" v2 "user-42 stays migrated after the add"
expect_api "user-108" v1 "user outside the new list stays on /v1/user"
control_ok "control route serves after the add publish"

echo ""
echo "--- flip 3: remove user-42 (list [user-77])"
publish_and_flip "user-42" v1 \
  "removing user-42 demotes them on the next request" "user-77"
expect_api "user-77" v2 "user-77 stays migrated after the removal"
control_ok "control route serves after the remove publish (and throughout)"

echo ""
echo "--- gateway log: reload generations and plugin config refresh"
reload_log=$(cat "$SCRATCH/gateway.log")
assert_contains "$reload_log" "config_reloaded" "the file-watch reloads published new generations"

print_summary
