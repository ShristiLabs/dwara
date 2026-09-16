#!/bin/bash
# test-07-plugin-sdk.sh — Plugin SDK: host CLI scaffolding to a running
# plugin (DW-057 / DW-159).
#
# `dwara-cli plugin new <NAME>` scaffolds a ready-to-build proxy-wasm
# plugin project (see crates/dwara-cli/src/plugin_scaffold.rs): a Rust
# crate targeting wasm32-wasip1 with the proxy-wasm dependency wired
# up, a minimal filter implementing the phase callbacks, a dwara.yaml
# manifest for loading the plugin into the gateway, a README with
# build instructions, and a .gitignore.
#
# This is a HOST CLI demo: the scratch demo image (dwara:demo, FROM
# scratch) ships only the gateway server binary, so the plugin
# subcommand runs on the host operator CLI (`dwara-cli`), not in the
# container. The final section additionally uses the prebuilt HOST
# gateway (target/{debug,release}/dwara) to prove the whole
# scaffold-to-running path on a DEFAULT build (plugins run with no
# cargo feature; DW-157) and skips that section when the gateway
# binary is missing.
#
# This test:
#   1) Runs `dwara-cli plugin new` into a temp dir.
#   2) Asserts the scaffold files exist (Cargo.toml, src/lib.rs,
#      dwara.yaml, README.md, .gitignore).
#   3) Asserts the crate is a cdylib depending on proxy-wasm, and that
#      src/lib.rs implements the four phase callbacks.
#   4) Asserts the generated manifest references the plugin and its
#      phases.
#   5) Asserts the generated manifest is a VALID gateway config as
#      generated: `dwara-cli validate` passes on the untouched
#      dwara.yaml (a real `action: { type: proxy }` route on the /api
#      prefix with its service/upstream chain; validation does not
#      check that the .wasm exists yet).
#   6) The SDK round-trip (DW-159): builds the scaffolded crate with
#      `cargo build --release --target wasm32-wasip1`, loads the .wasm
#      into a real gateway, and asserts the plugin's header effect on
#      a live response.
#
# See docs-site/guide/plugin-sdk.md for the workflow: scaffold, build
# with `cargo build --release --target wasm32-wasip1`, load the .wasm
# via the plugins block.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=== test-07-plugin-sdk ==="

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

# Locate the host gateway for the round-trip section (skip-with-note
# when missing; sections 1-5 are CLI-only and still run).
DWARA=""
for c in "$REPO_ROOT/target/debug/dwara" \
         "$REPO_ROOT/target/release/dwara" \
         "$(command -v dwara 2>/dev/null || true)"; do
  if [ -n "$c" ] && [ -x "$c" ]; then DWARA="$c"; break; fi
done

# 1) Scaffold a plugin into a temp dir (cleaned up on exit).
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
PLUGIN_NAME="demo-extensibility-plugin"

echo ""
echo "--- scaffolding plugin: dwara-cli plugin new $PLUGIN_NAME ---"
out=$("$CLI" plugin new "$PLUGIN_NAME" -o "$SCRATCH" 2>&1) && rc=0 || rc=1
assert_status 0 "$rc" "dwara-cli plugin new exits 0"
assert_contains "$out" "created plugin" "CLI reports the created plugin"

PLUGIN_DIR="$SCRATCH/$PLUGIN_NAME"

# 2) Assert the scaffold files exist.
for f in Cargo.toml src/lib.rs dwara.yaml README.md .gitignore; do
  if [ -f "$PLUGIN_DIR/$f" ]; then
    echo -e "${GREEN}PASS${NC}: scaffold file exists: $f"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}FAIL${NC}: scaffold file missing: $f"
    FAIL=$((FAIL + 1))
  fi
done

# 3) Assert the crate is a cdylib with the proxy-wasm dependency, and
#    the scaffold stubs the phase callbacks (the generated lib.rs
#    implements the request/response headers callbacks; the body
#    callbacks are left for the plugin author to add).
cargo_toml=$(cat "$PLUGIN_DIR/Cargo.toml")
assert_contains "$cargo_toml" "crate-type" "Cargo.toml declares a crate-type (wasm output)"
assert_contains "$cargo_toml" "cdylib" "Cargo.toml builds a cdylib"
assert_contains "$cargo_toml" "proxy-wasm" "Cargo.toml depends on proxy-wasm"

lib_rs=$(cat "$PLUGIN_DIR/src/lib.rs")
assert_contains "$lib_rs" "on_http_request_headers" "lib.rs stubs on_http_request_headers"
assert_contains "$lib_rs" "on_http_response_headers" "lib.rs stubs on_http_response_headers"
assert_contains "$lib_rs" "hostcalls::log" "lib.rs logs via the proxy-wasm hostcalls module"

# 4) Assert the generated manifest declares the plugin + phases.
manifest=$(cat "$PLUGIN_DIR/dwara.yaml")
assert_contains "$manifest" "name: $PLUGIN_NAME" "manifest declares the plugin name"
assert_contains "$manifest" "request_headers" "manifest declares the request_headers phase"
assert_contains "$manifest" "response_headers" "manifest declares the response_headers phase"
assert_contains "$manifest" "wasm32-wasip1" "manifest points at the wasm32-wasip1 build output"

# 5) The generated manifest is a valid gateway config as generated:
#    the scaffold emits a real `action: { type: proxy }` route on the
#    /api prefix with its service/upstream chain, so `dwara-cli
#    validate` passes on the untouched dwara.yaml (validation does not
#    check that the .wasm exists yet).
out=$("$CLI" validate "$PLUGIN_DIR/dwara.yaml" 2>&1) && rc=0 || rc=1
assert_status 0 "$rc" "as-generated manifest passes validation"
assert_contains "$out" "ok:" "validation prints ok for the generated manifest"

# 6) The SDK round-trip (DW-159): build the scaffolded crate, load it
#    into a real gateway, assert the plugin's header effect live.
#    Plugins run on every DEFAULT build (no cargo feature).
if [ -z "$DWARA" ]; then
  echo ""
  echo "NOTE: host gateway binary not found (build it: cargo build -p"
  echo "dwara-bin) — skipping the build-and-run round-trip; sections"
  echo "1-5 above verified the scaffold itself."
  print_summary
  exit 0
fi
echo "using gateway at: $DWARA"

echo ""
echo "--- SDK round-trip: build the scaffolded plugin ---"
# Give the scaffold its effect: a response header at response_headers
# (the workflow every plugin author starts with).
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

rustup target add wasm32-wasip1 >/dev/null 2>&1
assert_status 0 $? "rustup target add wasm32-wasip1 is installed (idempotent)"
(cd "$PLUGIN_DIR" && cargo build --release --target wasm32-wasip1 >"$SCRATCH/build.log" 2>&1) && rc=0 || rc=1
if [ "$rc" != "0" ]; then tail -20 "$SCRATCH/build.log"; fi
assert_status 0 "$rc" "the scaffolded crate builds to wasm32-wasip1"

WASM="$PLUGIN_DIR/target/wasm32-wasip1/release/${PLUGIN_NAME//-/_}.wasm"
if [ -f "$WASM" ]; then
  echo -e "${GREEN}PASS${NC}: the .wasm artifact exists"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: the .wasm artifact is missing (expected $WASM)"
  FAIL=$((FAIL + 1))
fi

PORT=18095
BASE_URL="http://127.0.0.1:$PORT"
LOG="$SCRATCH/gateway.log"
gw_pid=""
cleanup() {
  [ -n "$gw_pid" ] && kill "$gw_pid" 2>/dev/null || true
  rm -rf "$SCRATCH"
}
trap cleanup EXIT

cat >"$SCRATCH/gw.yaml" <<YAML
listeners:
  - name: sdk-http
    address: 127.0.0.1
    port: $PORT
    protocol: http

routes:
  - name: hello
    service: sdk-service
    match:
      path:
        type: prefix
        value: /hello
    action:
      type: respond
      status: 200
      body: '{"hello":"world"}'
      headers:
        Content-Type: application/json
    plugins:
      - $PLUGIN_NAME

services:
  - name: sdk-service
    upstream: sdk-upstream

upstreams:
  - name: sdk-upstream
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
YAML

echo ""
echo "--- SDK round-trip: run the gateway, assert the effect ---"
DWARA_CONFIG="$SCRATCH/gw.yaml" "$DWARA" >"$LOG" 2>&1 &
gw_pid=$!
wait_for "$BASE_URL/hello" 30

status=$(http_status "$BASE_URL/hello")
assert_status "200" "$status" "GET /hello returns 200 with the plugin loaded"
headers=$(http_headers "$BASE_URL/hello")
assert_header "$headers" "x-dwara-plugin" "$PLUGIN_NAME" \
  "the scaffolded plugin stamped x-dwara-plugin: $PLUGIN_NAME"

echo ""
echo "NOTE: plugins run on every default build (no cargo feature). The"
echo "15-minute quickstart this test mirrors — scaffold, implement,"
echo "build, load, curl — is documented in docs-site/guide/plugin-sdk.md."

print_summary
