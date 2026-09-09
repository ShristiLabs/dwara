#!/bin/bash
# test-21-cedar-authz.sh — Cedar in-process policy authorization.
#
# DOCUMENTED LIMITATION (guide/cedar-authz.md "Status"): the
# in-process Cedar authorizer is complete and test-covered as a
# library component (crates/dwara-core/src/security/cedar/), but the
# gateway CONFIG WIRING has not landed: the OSS config schema has no
# `authz:` key, so a policy set cannot yet be attached to the gateway
# in a loadable config. The target surface (inline policies + schema,
# principal = consumer, action = method, resource = route) is
# documented in policies/target-cedar-authz.yaml and the authored policy
# set lives in policies/demo.cedar.
#
# This test therefore verifies every part that DOES exist:
#   1. The demo Cedar policy set is present and well-formed.
#   2. The built-in fine-grained rules that Cedar would sit after —
#      JWT scope requirements — enforce allow 200 / deny 403 on the
#      cedar-route (the same request attributes Cedar policies would
#      consume: consumer identity + claims).
#   3. `dwara-cli validate` rejects the target `authz: cedar:` config
#      with an unknown-field error, pinning the limitation live.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/../_shared/helpers.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GW=http://localhost:8080
CLI=${DWARA_CLI:-/Users/harikiranbavineni/ShristiLabs/dwara/target/debug/dwara-cli}
IDP=${IDP_MOCK:-http://localhost:19011}

echo "=== test-21-cedar-authz ==="

wait_for "$GW/public/" 30 || exit 1
wait_for "$IDP/healthz" 30 || exit 1

# --- 1. The authored policy set ------------------------------------------

policy=$(cat "$SCRIPT_DIR/policies/demo.cedar")
assert_contains "$policy" "permit(" "demo.cedar contains a permit policy"
assert_contains "$policy" "forbid(" "demo.cedar contains a forbid policy"
assert_contains "$policy" 'User::"jwt-user"' \
  "policy binds the principal to the jwt-user consumer"

# --- 2. The built-in fine-grained authz on the same route ----------------
#
# cedar-route requires the demo:read JWT scope: attribute-based
# allow/deny over the verified token's claims — the same request
# attributes a Cedar policy set consumes.

# Token WITH the required scope -> allow 200.
TOKEN=$(http_body "$IDP/issue?sub=cedar-demo&scope=demo:read,demo:write" | tr -d '\n\r')
status=$(http_status "$GW/v1/cedar/test" -H "Authorization: Bearer $TOKEN")
assert_status 200 "$status" "token carrying demo:read scope: 200"

# Authenticated token WITHOUT the required scope -> deny 403 (the
# identity resolved; the attribute did not match).
TOKEN_NOSCOPE=$(http_body "$IDP/issue?sub=cedar-demo&scope=other:scope" | tr -d '\n\r')
status=$(http_status "$GW/v1/cedar/test" -H "Authorization: Bearer $TOKEN_NOSCOPE")
assert_status 403 "$status" "authenticated token missing demo:read scope: 403"

# No token -> 401 (identity rules imply authentication).
status=$(http_status "$GW/v1/cedar/test")
assert_status 401 "$status" "anonymous request on scope rules: 401"

# --- 3. The limitation, pinned live --------------------------------------
#
# The target config (authz: cedar:) must be REJECTED by the OSS
# schema until the wiring lands; if this ever flips to "ok", the
# limitation has lifted and this test (plus the README) must be
# updated.

if [ -x "$CLI" ]; then
  if out=$("$CLI" validate "$SCRIPT_DIR/policies/target-cedar-authz.yaml" 2>&1); then
    echo -e "${RED}FAIL${NC}: target authz: cedar: config validated (wiring has landed — update this demo!)"
    FAIL=$((FAIL + 1))
  else
    assert_contains "$out" "unknown field \`authz\`" \
      "dwara-cli rejects the target authz: cedar: block (config wiring pending)"
  fi
else
  echo "NOTE: dwara-cli not found at $CLI; skipping the schema-rejection check."
fi

print_summary
