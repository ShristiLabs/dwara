#!/bin/bash
# test-20-opa-authz.sh — OPA external policy authorization.
#
# DOCUMENTED LIMITATION (guide/opa-authz.md "Status"): the OPA HTTP
# client (with decision caching and fail_closed mode) is complete and
# test-covered as a library component
# (crates/dwara-core/src/security/cedar/opa.rs), but the gateway
# CONFIG WIRING has not landed: the OSS config schema has no `authz:`
# key, so the gateway cannot yet be pointed at an OPA server in a
# loadable config. The target surface is documented in
# policies/target-opa-authz.yaml.
#
# This test therefore verifies every part that DOES exist:
#   1. The OPA server runs the demo policy (policies/demo.rego) and
#      answers allow/deny over the documented input format.
#   2. The built-in authorization on the same route shape enforces
#      allow 200 / deny 403 — the layer an external engine composes
#      AFTER (per the guide, Cedar/OPA run after the built-in authz).
#   3. `dwara-cli validate` rejects the target `authz: opa:` config
#      with an unknown-field error, pinning the limitation live.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/../_shared/helpers.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GW=http://localhost:8080
OPA=${OPA:-http://localhost:8181}
CLI=${DWARA_CLI:-/Users/harikiranbavineni/ShristiLabs/dwara/target/debug/dwara-cli}
IDP=${IDP_MOCK:-http://localhost:19011}

echo "=== test-20-opa-authz ==="

wait_for "$GW/public/" 30 || exit 1
wait_for "$OPA/health" 60 || exit 1

# --- 1. The OPA policy engine answers decisions -------------------------
#
# Query /v1/data/demo/allow with the documented input shape.

decision=$(http_body "$OPA/v1/data/demo/allow" -X POST \
  -H 'Content-Type: application/json' \
  -d '{"input": {"method": "GET", "path": "/v1/opa/test", "consumer": "someone"}}')
assert_contains "$decision" "\"result\":true" \
  "OPA allows a /v1 path (policy: startswith(input.path, \"/v1\")"

decision=$(http_body "$OPA/v1/data/demo/allow" -X POST \
  -H 'Content-Type: application/json' \
  -d '{"input": {"method": "GET", "path": "/internal/admin", "consumer": "someone"}}')
assert_contains "$decision" "\"result\":false" \
  "OPA denies a non-/v1 path (default deny)"

decision=$(http_body "$OPA/v1/data/demo/allow" -X POST \
  -H 'Content-Type: application/json' \
  -d '{"input": {"method": "GET", "path": "/internal/admin", "consumer": "opa-user"}}')
assert_contains "$decision" "\"result\":true" \
  "OPA allows the named opa-user consumer regardless of path"

# --- 2. The built-in authz layer on the same route shape ----------------
#
# opa-route allows only the mobile-app consumer. External engines
# compose AFTER this layer; an allow here is the 200/403 semantics
# the OPA decision would gate.

status=$(http_status "$GW/v1/opa/test" -H "X-API-Key: demo-api-key-123")
assert_status 200 "$status" "allowed consumer (mobile-app) on opa-route: 200"

# jwt-user authenticates fine (valid idp-mock token) but is NOT in
# the allowed set — a denied-but-authenticated request answers 403.
TOKEN=$(http_body "$IDP/issue?sub=opa-demo&scope=demo:read" | tr -d '\n\r')
status=$(http_status "$GW/v1/opa/test" -H "Authorization: Bearer $TOKEN")
assert_status 403 "$status" "authenticated but unlisted consumer: 403"

status=$(http_status "$GW/v1/opa/test")
assert_status 401 "$status" "anonymous request on identity rules: 401"

# --- 3. The limitation, pinned live --------------------------------------
#
# The target config (authz: opa:) must be REJECTED by the OSS schema
# until the wiring lands; if this ever flips to "ok", the limitation
# has lifted and this test (plus the README) must be updated.

if [ -x "$CLI" ]; then
  if out=$("$CLI" validate "$SCRIPT_DIR/policies/target-opa-authz.yaml" 2>&1); then
    echo -e "${RED}FAIL${NC}: target authz: opa: config validated (wiring has landed — update this demo!)"
    FAIL=$((FAIL + 1))
  else
    assert_contains "$out" "unknown field \`authz\`" \
      "dwara-cli rejects the target authz: opa: block (config wiring pending)"
  fi
else
  echo "NOTE: dwara-cli not found at $CLI; skipping the schema-rejection check."
fi

print_summary
