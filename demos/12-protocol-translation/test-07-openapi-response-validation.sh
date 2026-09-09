#!/bin/bash
# test-07-openapi-response-validation.sh — OpenAPI response validation
# (documented limitation).
#
# TARGET SURFACE (guide: openapi-response-validation): a route-level
#   openapi_validation:
#     spec: ./openapi.yaml
#     mode: enforce | dry_run
# block that compiles the spec's response schemas at config load and
# validates every upstream response (status code, content type, body
# schema), rejecting non-conforming responses with 502 in enforce mode.
#
# WHAT IS WIRED TODAY: the validation ENGINE is complete and
# test-covered as a library component, but the route-level config
# wiring has not landed — the `openapi_validation:` block is NOT in the
# configuration schema (dwara-cli validate rejects it as an unknown
# field). Neither the enforce nor the dry-run path can be exercised
# through a published config, so per the guide both are skipped here.
#
# What IS live-verified: the route and upstream the spec describes
# return responses that CONFORM to the spec (200, application/json,
# arrays with the required fields) — i.e. the exact traffic a wired
# validator would pass.
set -u
. "$(dirname "$0")/../_shared/helpers.sh"

echo "=== test-07: OpenAPI response validation ==="

wait_for http://localhost:8080/healthz 30 || exit 1

# ---------------------------------------------------------------------------
# Conforming responses through the gateway (what a wired validator
# would pass in enforce mode).
# ---------------------------------------------------------------------------
echo "--- GET /api/users.json: conforming response per openapi.yaml ---"
status=$(http_status "http://localhost:8080/api/users.json")
body=$(http_body "http://localhost:8080/api/users.json")
echo "  status=$status"

assert_status 200 "$status" "users endpoint answers 200 (status defined in the spec)"

conformance=$(python3 -c '
import json, sys
try:
    users = json.loads(sys.argv[1])
except Exception as e:
    print(f"PARSE_ERROR:{e}"); raise SystemExit(0)
ok = (
    isinstance(users, list)
    and len(users) > 0
    and all(
        isinstance(u.get("id"), int)
        and isinstance(u.get("name"), str)
        and isinstance(u.get("email"), str)
        and set(u) >= {"id", "name", "email"}
        for u in users
    )
)
print("CONFORMS" if ok else "NON_CONFORMING")
' "$body")
echo "  schema check: $conformance"

if [ "$conformance" = "CONFORMS" ]; then
  echo -e "${GREEN}PASS${NC}: users response body conforms to the spec schema (array of {id,name,email})"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: users response does not conform: $conformance"
  FAIL=$((FAIL + 1))
fi

echo "--- GET /api/products.json: conforming response per openapi.yaml ---"
status=$(http_status "http://localhost:8080/api/products.json")
body=$(http_body "http://localhost:8080/api/products.json")
echo "  status=$status"

assert_status 200 "$status" "products endpoint answers 200 (status defined in the spec)"

conformance=$(python3 -c '
import json, sys
try:
    products = json.loads(sys.argv[1])
except Exception as e:
    print(f"PARSE_ERROR:{e}"); raise SystemExit(0)
ok = (
    isinstance(products, list)
    and len(products) > 0
    and all(
        isinstance(p.get("id"), int)
        and isinstance(p.get("name"), str)
        and isinstance(p.get("price"), (int, float))
        and set(p) >= {"id", "name", "price"}
        for p in products
    )
)
print("CONFORMS" if ok else "NON_CONFORMING")
' "$body")
echo "  schema check: $conformance"

if [ "$conformance" = "CONFORMS" ]; then
  echo -e "${GREEN}PASS${NC}: products response body conforms to the spec schema (array of {id,name,price})"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: products response does not conform: $conformance"
  FAIL=$((FAIL + 1))
fi

# ---------------------------------------------------------------------------
# Enforcement / dry-run paths: SKIPPED (config wiring not landed).
# ---------------------------------------------------------------------------
echo ""
echo "SKIP: the enforce and dry_run rejection paths are not live-tested."
echo "      The openapi_validation: route block is not in the configuration"
echo "      schema yet (the validation engine is a library component), so"
echo "      there is no wired failure path to exercise. See README.md"
echo "      (Documented limitations)."

print_summary
