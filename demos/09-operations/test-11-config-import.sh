#!/bin/bash
# test-11-config-import.sh — NGINX config import (DW-065).
#
# `dwara-cli import nginx <config> --output <file>` scaffolds a Dwara
# config from an existing NGINX config — a switching-cost lever for
# teams migrating to Dwara. The importer parses:
#   - `server` blocks (listen port, server_name)
#   - `location` blocks with `proxy_pass` (match modifiers: `=`
#     exact, none prefix, `~`/`~*` regex)
#   - `upstream` blocks with `server` endpoints
# and maps them to Dwara entities:
#   - NGINX `upstream backend`  -> dwara `backend-upstream`
#     (round_robin) + `backend-service`
#   - a location with `proxy_pass http://backend` -> a route with a
#     prefix/exact match pointing at backend-service
#   - a location with a literal `proxy_pass http://host:port` -> a
#     route plus a synthesized `route-N-upstream`/`route-N-service`
# Unsupported constructs (rewrite, auth_basic, limit_req, if,
# try_files, lua_/perl_*, ...) are reported as YAML-comment warnings
# appended to the generated config — the output always validates.
#
# HOST BINARY: dwara-cli is not in the scratch image; this test uses
# the prebuilt host CLI and skips with a message if it is missing.
set -euo pipefail
source ../_shared/helpers.sh

REPO_ROOT="$(cd "$(dirname $0)/../.." && pwd)"
DWARA_CLI="$REPO_ROOT/target/debug/dwara-cli"
DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
NGINX_CONF="$DEMO_DIR/fixtures/nginx-demo.conf"
OUT="$DEMO_DIR/data/nginx-demo-imported.yaml"

echo "=== test-11-config-import ==="

if [ ! -x "$DWARA_CLI" ]; then
  echo "SKIP: host dwara-cli not found at $DWARA_CLI."
  echo "      Build it with: cargo build -p dwara-cli"
  echo "      The importers are documented in README.md and"
  echo "      docs-site/guide/config-import.md."
  PASS=0
  FAIL=0
  print_summary
  exit 0
fi

# 1) The input file exists and carries the expected blocks.
if [ -f "$NGINX_CONF" ]; then
  echo -e "${GREEN}PASS${NC}: NGINX sample config present ($NGINX_CONF)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: NGINX sample config missing ($NGINX_CONF)"
  FAIL=$((FAIL + 1))
fi
nginx_text=$(cat "$NGINX_CONF" 2>/dev/null || true)
assert_contains "$nginx_text" "upstream backend" "sample defines the 'backend' upstream block"
assert_contains "$nginx_text" "location /api/" "sample defines the /api/ location"

# 2) Run the importer.
echo "--- dwara-cli import nginx ---"
rm -f "$OUT"
import_out=$("$DWARA_CLI" import nginx "$NGINX_CONF" --output "$OUT" 2>&1)
echo "$import_out" | sed 's/^/    /'
assert_contains "$import_out" "imported 3 routes" \
  "importer reports 3 routes (one per location)"

# 3) The emitted Dwara YAML exists and contains the expected routes,
#    services, and upstreams.
if [ -f "$OUT" ]; then
  echo -e "${GREEN}PASS${NC}: generated Dwara config emitted ($OUT)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: generated Dwara config missing ($OUT)"
  FAIL=$((FAIL + 1))
fi
imported=$(cat "$OUT" 2>/dev/null || true)
assert_contains "$imported" "route-0" "imported config contains route-0 (/api/)"
assert_contains "$imported" "backend-service" "imported config maps /api/ to backend-service"
assert_contains "$imported" "backend-upstream" "imported config contains backend-upstream"
assert_contains "$imported" "port: 8081" "backend-upstream carries NGINX server 127.0.0.1:8081"
assert_contains "$imported" "port: 8082" "backend-upstream carries NGINX server 127.0.0.1:8082"
assert_contains "$imported" "value: /exact" "exact location '= /exact' becomes an exact match"
assert_contains "$imported" "route-1-service" "literal proxy_pass synthesized route-1-service"

# The unsupported 'rewrite' directive is reported as a warning
# comment in the generated YAML.
assert_contains "$imported" "Import warnings" "warnings block appended to the generated YAML"
assert_contains "$imported" "rewrite" "rewrite directive reported in the warnings"

# 4) The generated config is valid (the importer's contract: output
#    always passes dwara-cli validate).
validate_out=$("$DWARA_CLI" validate "$OUT" 2>&1) && validate_rc=0 || validate_rc=$?
assert_status 0 "$validate_rc" "generated config passes dwara-cli validate"
assert_contains "$validate_out" "ok: 3 routes" "validation reports ok: 3 routes"

echo ""
echo "NOTE: the same CLI imports Kong (import kong), Envoy (import"
echo "envoy), and OpenAPI 3.x (import openapi) configs; each reports"
echo "unsupported constructs as advisory warnings. The importer is a"
echo "scaffolding step — add Dwara-native authn/rate limiting after."

print_summary
