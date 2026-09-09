#!/bin/bash
# test-05-api-aggregation.sh — API aggregation (documented limitation).
#
# TARGET SURFACE (guide: api-aggregation): a top-level `aggregations:`
# block of fragments (service + path + target_field, optional jsonpath,
# fail_policy, max_fragment_bytes) referenced from a
# `action: { type: aggregate, aggregation: dashboard }` route; the
# gateway fans out in parallel and composes one JSON object per
# fragment.
#
# WHAT IS WIRED TODAY: the composition core (specs, JSONPath shaping,
# fail policies, size caps) is complete and test-covered as a library
# component (crates/dwara-core/src/aggregation/), but the CONFIG WIRING
# has not landed — the `aggregations:` block and the `aggregate` route
# action are not in the configuration schema, so a composed route
# cannot be expressed in dwara.yaml yet (`dwara-cli validate` rejects
# the block as an unknown field). This is the same pattern as demo 10's
# SNI-passthrough test: the config shape is documented, the live
# composed response is skipped.
#
# What CAN be live-verified today: both fragments of the would-be
# dashboard aggregation are reachable THROUGH the gateway (the /api/
# route fronts the static upstream), so the moment the wiring lands the
# same fragments compose.
set -u
. "$(dirname "$0")/../_shared/helpers.sh"

echo "=== test-05: API aggregation ==="

wait_for http://localhost:8080/healthz 30 || exit 1

# ---------------------------------------------------------------------------
# Fragments of the target aggregation, fetched through the gateway.
# ---------------------------------------------------------------------------
echo "--- GET /api/users.json (fragment: users) ---"
users_status=$(http_status "http://localhost:8080/api/users.json")
users_body=$(http_body "http://localhost:8080/api/users.json")
echo "  status=$users_status"

assert_status 200 "$users_status" "users fragment reachable through the gateway"
assert_contains "$users_body" "Alice" "users fragment contains the user array"

echo "--- GET /api/products.json (fragment: products) ---"
products_status=$(http_status "http://localhost:8080/api/products.json")
products_body=$(http_body "http://localhost:8080/api/products.json")
echo "  status=$products_status"

assert_status 200 "$products_status" "products fragment reachable through the gateway"
assert_contains "$products_body" "Widget" "products fragment contains the product array"

# ---------------------------------------------------------------------------
# The composed response: SKIPPED (config wiring not landed).
# ---------------------------------------------------------------------------
echo ""
echo "SKIP: the composed aggregation response is not live-tested. The"
echo "      aggregations: block / type: aggregate action are not in the"
echo "      configuration schema yet (library component only), so the"
echo "      merged { users: [...], products: [...] } object the guide"
echo "      shows cannot be expressed in dwara.yaml. The fragments above"
echo "      are the exact inputs that aggregation would compose. See"
echo "      README.md (Documented limitations)."

print_summary
