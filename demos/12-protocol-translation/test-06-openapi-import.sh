#!/bin/bash
# test-06-openapi-import.sh — OpenAPI import flow (DW-047). Host-side.
#
# `dwara-cli import openapi <spec> --output <file>` reads an OpenAPI 3.x
# spec and scaffolds a Dwara config: one route per unique path (methods
# merged into match.methods), a placeholder `openapi-service` /
# `openapi-backend` (127.0.0.1:9000), and an `openapi` metadata block on
# each route carrying the source operationId/summary/tags/method/path.
#
# This test runs the import against openapi.yaml, asserts the expected
# routes appear in the emitted YAML, and validates the emitted config
# with `dwara-cli validate`. It does not need the docker stack (pure
# CLI transform) but is harmless while the stack runs.
#
# SKIP: if the dwara-cli binary is missing (the prebuilt dwara:demo
# image ships only the server binary), the test prints a clear message
# and passes without assertions.
set -u
. "$(dirname "$0")/../_shared/helpers.sh"

echo "=== test-06: OpenAPI import ==="

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLI="$SCRIPT_DIR/../../target/debug/dwara-cli"
SPEC="$SCRIPT_DIR/openapi.yaml"
OUT="$SCRIPT_DIR/data/imported-dwara.yaml"

if [ ! -x "$CLI" ]; then
  echo "SKIP: dwara-cli not found at $CLI."
  echo "      Build it with: cargo build -p dwara-cli"
  echo "      (the prebuilt dwara:demo image ships only the gateway server,"
  echo "      not the operator CLI). No assertions run."
  print_summary
  exit 0
fi

if [ ! -f "$SPEC" ]; then
  echo -e "${RED}FAIL${NC}: spec not found at $SPEC"
  FAIL=$((FAIL + 1))
  print_summary
  exit 1
fi

mkdir -p "$SCRIPT_DIR/data"

echo "--- dwara-cli import openapi openapi.yaml --output data/imported-dwara.yaml ---"
import_out=$(cd "$SCRIPT_DIR" && "$CLI" import openapi "$SPEC" --output "$OUT" 2>&1)
import_rc=$?
echo "$import_out" | sed 's/^/  /'

if [ $import_rc -ne 0 ] || [ ! -f "$OUT" ]; then
  echo -e "${RED}FAIL${NC}: import did not produce $OUT (rc=$import_rc)"
  FAIL=$((FAIL + 1))
  print_summary
  exit 1
fi
echo -e "${GREEN}PASS${NC}: import emitted a Dwara config"
PASS=$((PASS + 1))

yaml=$(cat "$OUT")

# One route per unique path, named after the first operation's
# operationId (sanitized to lowercase alphanumerics + hyphens).
assert_contains "$yaml" "listUsers" "route listUsers (operationId of GET /api/users.json)"
assert_contains "$yaml" "listProducts" "route listProducts (operationId of GET /api/products.json)"
assert_contains "$yaml" "healthCheck" "route healthCheck (operationId of GET /healthz)"

# The paths survive as exact matches.
assert_contains "$yaml" "/api/users.json" "imported path /api/users.json"
assert_contains "$yaml$import_out" "3 route" \
  "import reports 3 routes (one per unique path)"

# Placeholder wiring: the operator edits these to point at real upstreams.
assert_contains "$yaml" "openapi-backend" "placeholder upstream openapi-backend"

# Traceability metadata: the openapi block carries the operationId.
assert_contains "$yaml" "operation_id: listUsers" "openapi.operation_id metadata on the route"
assert_contains "$yaml" "path: /api/products.json" "openapi.path metadata on the route"

echo "--- dwara-cli validate data/imported-dwara.yaml ---"
validate_out=$(cd "$SCRIPT_DIR" && "$CLI" validate "$OUT" 2>&1)
validate_rc=$?
echo "$validate_out" | sed 's/^/  /'

if [ $validate_rc -eq 0 ] && echo "$validate_out" | grep -q "ok: 3 routes"; then
  echo -e "${GREEN}PASS${NC}: the imported config validates (ok: 3 routes)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: imported config did not validate (rc=$validate_rc)"
  FAIL=$((FAIL + 1))
fi

print_summary
