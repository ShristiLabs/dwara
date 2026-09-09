#!/bin/bash
# test-07-plugin-sdk.sh — Plugin SDK: host CLI scaffolding (DW-057).
#
# `dwara-cli plugin new <NAME>` scaffolds a ready-to-build proxy-wasm
# plugin project (see crates/dwara-cli/src/plugin_scaffold.rs): a Rust
# crate targeting wasm32-wasip1 with the proxy-wasm dependency wired
# up, a minimal filter implementing the four phase callbacks, a
# dwara.yaml manifest for loading the plugin into the gateway, a README
# with build instructions, and a .gitignore.
#
# This is a HOST CLI demo: the scratch demo image (dwara:demo, FROM
# scratch) ships only the gateway server binary, so the plugin
# subcommand runs on the host operator CLI (`dwara-cli`), not in the
# container.
#
# This test:
#   1) Runs `dwara-cli plugin new` into a temp dir.
#   2) Asserts the scaffold files exist (Cargo.toml, src/lib.rs,
#      dwara.yaml, README.md, .gitignore).
#   3) Asserts the crate is a cdylib depending on proxy-wasm, and that
#      src/lib.rs implements the four phase callbacks.
#   4) Asserts the generated manifest references the plugin and its
#      phases.
#   5) Documents known scaffold quirks (verified live): the generated
#      manifest does not pass gateway validation as-is. It emits
#      `action: proxy: {}` (the schema requires `type: proxy`) and a
#      prefix match on `/` (validation rejects a prefix that would
#      match every path). The test asserts the as-generated manifest
#      fails validation, then asserts the corrected manifest (action
#      type + a non-root prefix) validates.
#
# See docs-site/guide/plugin-sdk.md for the workflow: scaffold, build
# with `cargo build --release --target wasm32-wasip1`, load the .wasm
# via the plugins block.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

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

# 4) Assert the generated manifest declares the plugin + phases.
manifest=$(cat "$PLUGIN_DIR/dwara.yaml")
assert_contains "$manifest" "name: $PLUGIN_NAME" "manifest declares the plugin name"
assert_contains "$manifest" "request_headers" "manifest declares the request_headers phase"
assert_contains "$manifest" "response_headers" "manifest declares the response_headers phase"
assert_contains "$manifest" "wasm32-wasip1" "manifest points at the wasm32-wasip1 build output"

# 5) Known scaffold quirks, verified live: the generated manifest does
#    not pass gateway validation as-is -- it emits `action: proxy: {}`
#    (the schema requires `type: proxy`) and a prefix match on `/`
#    (validation rejects a prefix that would match every path). Assert
#    the rejection, then fix both shapes and assert the corrected
#    manifest validates.
out=$("$CLI" validate "$PLUGIN_DIR/dwara.yaml" 2>&1) && rc=0 || rc=1
assert_status 1 "$rc" "as-generated manifest fails validation (scaffold quirks)"
assert_contains "$out" "config error" "rejection is a config error naming the issue"

sed -i.bak -e 's/^      proxy: {}$/      type: proxy/' \
           -e 's|^        value: /$|        value: /api/|' "$PLUGIN_DIR/dwara.yaml"
rm -f "$PLUGIN_DIR/dwara.yaml.bak"
out=$("$CLI" validate "$PLUGIN_DIR/dwara.yaml" 2>&1) && rc=0 || rc=1
assert_status 0 "$rc" "corrected manifest (type: proxy + /api/ prefix) validates"
assert_contains "$out" "ok:" "validation prints ok for the corrected manifest"

echo ""
echo "NOTE: the plugin SDK is a host-side workflow (DW-057). Scaffold"
echo "with 'dwara-cli plugin new <name>', build with 'cargo build"
echo "--release --target wasm32-wasip1', then load the .wasm via the"
echo "gateway's top-level plugins block (requires a feature-enabled"
echo "build). See docs-site/guide/plugin-sdk.md."

print_summary
