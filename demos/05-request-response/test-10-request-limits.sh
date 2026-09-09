#!/bin/bash
# Test 10: Request limits + JSON Schema body validation.
#
# The /v1/limits/ route declares a `limits` block (max_body_bytes: 1024,
# max_header_count: 10, max_header_bytes: 4096) and a `request_validation`
# block (a minimal JSON Schema: object with required `name`, optional
# bounded `age`, additionalProperties: false). Both are enforced after
# the route matches and BEFORE the route action runs:
#
#   - a body declaring more than max_body_bytes   -> 413 request_body_too_large
#   - more than max_header_count header fields    -> 431 request_headers_too_large
#   - a schema-violating JSON body                -> 400 validation_failed
#   - a conforming request                        -> 200 (echoed by the upstream)
set -euo pipefail
. "$(dirname "$0")/../_shared/helpers.sh"

BASE="http://localhost:8080"

echo "=== Test 10: Request Limits ==="

wait_for "$BASE/v1/transforms/test" 30 || exit 1

# --- 1. Conforming request: required `name`, optional in-range `age`. ---
status=$(http_status "$BASE/v1/limits/user" -X POST \
  -H 'Content-Type: application/json' \
  -d '{"name":"demo-user","age":42}')
assert_status 200 "$status" "conforming body returns 200"

body=$(http_body "$BASE/v1/limits/user" -X POST \
  -H 'Content-Type: application/json' \
  -d '{"name":"demo-user","age":42}')
assert_contains "$body" "demo-user" "conforming body reaches the echo upstream"

# --- 2. Schema violations -> 400 validation_failed -------------------------
# Missing required property `name`.
status=$(http_status "$BASE/v1/limits/user" -X POST \
  -H 'Content-Type: application/json' \
  -d '{"age":42}')
body=$(http_body "$BASE/v1/limits/user" -X POST \
  -H 'Content-Type: application/json' \
  -d '{"age":42}')
assert_status 400 "$status" "missing required property returns 400"
assert_contains "$body" "validation_failed" "error code is validation_failed"

# Out-of-range value (age > maximum: 150).
status=$(http_status "$BASE/v1/limits/user" -X POST \
  -H 'Content-Type: application/json' \
  -d '{"name":"demo-user","age":999}')
assert_status 400 "$status" "out-of-range value returns 400"

# Unknown property (additionalProperties: false).
status=$(http_status "$BASE/v1/limits/user" -X POST \
  -H 'Content-Type: application/json' \
  -d '{"name":"demo-user","role":"admin"}')
assert_status 400 "$status" "unknown property returns 400"

# --- 3. Oversize body -> 413 request_body_too_large ------------------------
# 2048 'a' characters inside a valid JSON string: far over the 1024-byte
# body cap. The declared Content-Length is rejected up front.
big=$(printf 'a%.0s' $(seq 1 2048))
status=$(http_status "$BASE/v1/limits/user" -X POST \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"$big\"}")
body=$(http_body "$BASE/v1/limits/user" -X POST \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"$big\"}")
assert_status 413 "$status" "oversize body returns 413"
assert_contains "$body" "request_body_too_large" "error code is request_body_too_large"

# --- 4. Header flood -> 431 request_headers_too_large ----------------------
# 15 extra header fields on top of curl's own (Host, User-Agent, Accept,
# Content-Type, Content-Length) -- well over max_header_count: 10.
flood_args=()
for i in $(seq 1 15); do
  flood_args+=(-H "X-Flood-$i: v")
done
status=$(http_status "$BASE/v1/limits/user" -X POST \
  -H 'Content-Type: application/json' \
  "${flood_args[@]}" \
  -d '{"name":"demo-user"}')
body=$(http_body "$BASE/v1/limits/user" -X POST \
  -H 'Content-Type: application/json' \
  "${flood_args[@]}" \
  -d '{"name":"demo-user"}')
assert_status 431 "$status" "header flood returns 431"
assert_contains "$body" "request_headers_too_large" "error code is request_headers_too_large"

print_summary
