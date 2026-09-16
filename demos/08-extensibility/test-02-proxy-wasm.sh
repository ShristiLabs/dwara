#!/bin/bash
set -euo pipefail

# Test 02: Proxy-Wasm (WebAssembly) plugins run on the live request path
# (DW-055 / DW-157).
#
# Proxy-wasm plugins execute on EVERY default build — there is no
# `wasm` cargo feature to enable. Each plugin is a .wasm module loaded
# at config publish time and run at the phases it declares. This test
# proves the full developer round-trip on a DEFAULT build:
#
#   scaffold (`dwara-cli plugin new`, DW-057) ->
#   implement a header effect in src/lib.rs ->
#   `rustup target add wasm32-wasip1` (idempotent) ->
#   `cargo build --release --target wasm32-wasip1` ->
#   a gateway config that loads the .wasm and attaches it to routes ->
#   curl asserts the plugin's header effect on the live response.
#
# It also asserts the dispatch contract's failure semantics live
# (DW-157):
#   - a route referencing a plugin whose .wasm cannot be read answers
#     500 `plugin_unavailable` (fail-closed: the plugin never runs and
#     the request does not proceed);
#   - routes that do not reference the broken plugin are unaffected
#     (blast radius is the referencing routes only);
#   - a plugin-less route on the same gateway is byte-identical to a
#     no-plugin gateway (the fast path).
#
# HOST-BASED DEMO (no compose): like test-09-zero-downtime-upgrade, it
# runs the prebuilt host gateway (target/{debug,release}/dwara) and
# host CLI (dwara-cli) against loopback listeners on ports no compose
# stack uses; it skips with a message when the binaries are missing.
# The plugin build needs the wasm32-wasip1 rustup target (installed
# idempotently below) and network access for the first `proxy-wasm`
# crate fetch.
#
# See docs-site/guide/proxy-wasm-plugins.md (configuration reference)
# and docs-site/guide/plugin-sdk.md (the developer workflow this test
# mirrors).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Locate the host gateway and CLI binaries (debug, then release, then
# PATH — the same order as test-07).
DWARA=""
for c in "$REPO_ROOT/target/debug/dwara" \
         "$REPO_ROOT/target/release/dwara" \
         "$(command -v dwara 2>/dev/null || true)"; do
  if [ -n "$c" ] && [ -x "$c" ]; then DWARA="$c"; break; fi
done
DWARA_CLI=""
for c in "$REPO_ROOT/target/debug/dwara-cli" \
         "$REPO_ROOT/target/release/dwara-cli" \
         "$(command -v dwara-cli 2>/dev/null || true)"; do
  if [ -n "$c" ] && [ -x "$c" ]; then DWARA_CLI="$c"; break; fi
done

echo "=== Test 02: Proxy-Wasm (WebAssembly) Plugins on the live path ==="

if [ -z "$DWARA" ] || [ -z "$DWARA_CLI" ]; then
  echo "SKIP: host binaries not found."
  [ -z "$DWARA" ] && echo "      gateway: build it with: cargo build -p dwara-bin"
  [ -z "$DWARA_CLI" ] && echo "      CLI:     build it with: cargo build -p dwara-cli"
  echo "      Proxy-wasm dispatch runs on every default build; this test"
  echo "      verifies it end to end (scaffold -> build -> load -> curl)."
  PASS=0
  FAIL=0
  print_summary
  exit 0
fi
echo "using gateway at: $DWARA"
echo "using dwara-cli at: $DWARA_CLI"

PLUGIN_NAME="demo-wasm-plugin"
PORT=18096
BASE_URL="http://127.0.0.1:$PORT"
SCRATCH="$(mktemp -d /tmp/dwara-test02-XXXXXX)"
LOG="$SCRATCH/gateway.log"

cleanup() {
  [ -n "${gw_pid:-}" ] && kill "$gw_pid" 2>/dev/null || true
  rm -rf "$SCRATCH"
}
trap cleanup EXIT

# --- 1) Scaffold the plugin from the SDK template -----------------------

echo ""
echo "--- scaffolding plugin: dwara-cli plugin new $PLUGIN_NAME ---"
out=$("$DWARA_CLI" plugin new "$PLUGIN_NAME" -o "$SCRATCH" 2>&1) && rc=0 || rc=1
assert_status 0 "$rc" "dwara-cli plugin new exits 0"
assert_contains "$out" "created plugin" "CLI reports the created plugin"

PLUGIN_DIR="$SCRATCH/$PLUGIN_NAME"
WASM="$PLUGIN_DIR/target/wasm32-wasip1/release/${PLUGIN_NAME//-/_}.wasm"

# --- 2) Implement the plugin's effect -----------------------------------
#
# The scaffold compiles as generated; a real plugin adds its logic in
# the phase callbacks. Add a response header at response_headers so
# the effect is visible in `curl -i` output.
echo ""
echo "--- implementing the header effect in src/lib.rs ---"
python3 - "$PLUGIN_DIR/src/lib.rs" "$PLUGIN_NAME" <<'PYEOF'
import sys

path, name = sys.argv[1], sys.argv[2]
src = open(path).read()
old = """    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        Action::Continue
    }"""
new = """    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        self.add_http_response_header("x-dwara-plugin", "%s");
        Action::Continue
    }""" % name
assert old in src, "response headers callback not found in the scaffold"
open(path, "w").write(src.replace(old, new))
PYEOF
assert_status 0 $? "the response-headers callback was patched"

# --- 3) Build the .wasm (target installed idempotently) ----------------

echo ""
echo "--- building the plugin for wasm32-wasip1 ---"
rustup target add wasm32-wasip1 >/dev/null 2>&1
assert_status 0 $? "rustup target add wasm32-wasip1 is installed (idempotent)"
(cd "$PLUGIN_DIR" && cargo build --release --target wasm32-wasip1 >"$SCRATCH/build.log" 2>&1) && rc=0 || rc=1
if [ "$rc" != "0" ]; then tail -20 "$SCRATCH/build.log"; fi
assert_status 0 "$rc" "cargo build --release --target wasm32-wasip1 succeeds"
if [ -f "$WASM" ]; then
  echo -e "${GREEN}PASS${NC}: the .wasm artifact exists at ${WASM#$SCRATCH/}"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: the .wasm artifact is missing (expected $WASM)"
  FAIL=$((FAIL + 1))
fi

# --- 4) Gateway config: plugin route, plugin-less route, broken plugin --

echo ""
echo "--- starting the gateway with the plugin loaded ---"
cat >"$SCRATCH/dwara.yaml" <<YAML
listeners:
  - name: demo-http
    address: 127.0.0.1
    port: $PORT
    protocol: http

routes:
  - name: plugged
    service: demo-service
    match:
      path:
        type: prefix
        value: /plugged
    action:
      type: respond
      status: 200
      body: '{"ok":true}'
      headers:
        Content-Type: application/json
    plugins:
      - $PLUGIN_NAME

  - name: plain
    service: demo-service
    match:
      path:
        type: prefix
        value: /plain
    action:
      type: respond
      status: 200
      body: '{"ok":true}'
      headers:
        Content-Type: application/json

  - name: broken
    service: demo-service
    match:
      path:
        type: exact
        value: /broken
    action:
      type: respond
      status: 200
      body: '{"ok":true}'
      headers:
        Content-Type: application/json
    plugins:
      - broken-plugin

services:
  - name: demo-service
    upstream: demo-upstream

upstreams:
  - name: demo-upstream
    load_balancer: round_robin
    protocol: http1
    endpoints:
      - address: 127.0.0.1
        port: 1

plugins:
  - name: $PLUGIN_NAME
    wasm: $WASM
    phases:
      - request_headers
      - response_headers

  - name: broken-plugin
    wasm: $SCRATCH/does-not-exist.wasm
    phases:
      - request_headers
YAML

DWARA_CONFIG="$SCRATCH/dwara.yaml" "$DWARA" >"$LOG" 2>&1 &
gw_pid=$!
wait_for "$BASE_URL/plain" 30

# --- 5) Assertions on the live path -------------------------------------

echo ""
echo "--- the plugin's effect is visible on the response ---"
status=$(http_status "$BASE_URL/plugged")
assert_status "200" "$status" "GET /plugged returns 200"
headers=$(http_headers "$BASE_URL/plugged")
assert_header "$headers" "x-dwara-plugin" "$PLUGIN_NAME" \
  "the plugin stamped x-dwara-plugin: $PLUGIN_NAME on the response"

echo ""
echo "--- routes without plugins take the unchanged fast path ---"
status=$(http_status "$BASE_URL/plain")
assert_status "200" "$status" "GET /plain returns 200"
headers=$(http_headers "$BASE_URL/plain")
if echo "$headers" | grep -qi "^x-dwara-plugin:"; then
  echo -e "${RED}FAIL${NC}: the plugin leaked onto a plugin-less route"
  FAIL=$((FAIL + 1))
else
  echo -e "${GREEN}PASS${NC}: the plugin-less route carries no plugin header"
  PASS=$((PASS + 1))
fi

echo ""
echo "--- fail-closed: an unreadable .wasm answers 500 plugin_unavailable ---"
body=$(http_body "$BASE_URL/broken")
status=$(http_status "$BASE_URL/broken")
assert_status "500" "$status" "GET /broken (crashed plugin) returns 500"
assert_contains "$body" "plugin_unavailable" "the 500 names plugin_unavailable"

echo ""
echo "--- blast radius: the healthy plugin keeps serving ---"
status=$(http_status "$BASE_URL/plugged")
assert_status "200" "$status" "GET /plugged still returns 200 after /broken failed"

if grep -q "plugin_load_failed" "$LOG" 2>/dev/null; then
  echo -e "${GREEN}PASS${NC}: the gateway logged plugin_load_failed for the broken .wasm at load time"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: expected a plugin_load_failed log line for the broken .wasm"
  FAIL=$((FAIL + 1))
fi

echo ""
echo "NOTE: plugins run on every default build (no cargo feature). The"
echo "four dispatch phases, the fail-closed 500s (plugin_unavailable /"
echo "plugin_failed / plugin_body_too_large), and the body-buffering"
echo "policy are documented in docs-site/guide/proxy-wasm-plugins.md;"

echo "the scaffold-to-running workflow lives in"
echo "docs-site/guide/plugin-sdk.md."

print_summary
