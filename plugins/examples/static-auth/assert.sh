#!/bin/bash
# Assertions for the static-auth example plugin (DW-161).
#
# Runs against the harness gateway (plugins/examples/gateway.yaml,
# started by plugins/examples/run-all.sh):
#
#   ./assert.sh [base-url]
#
# Exits non-zero when any assertion fails.

BASE_URL="${1:-http://127.0.0.1:18101}"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# expect_status <expected> <description> <url> [curl args...]
expect_status() {
  local expected="$1" desc="$2" url="$3"
  shift 3
  local actual
  actual=$(curl -s -o /dev/null -w '%{http_code}' "$@" "$url")
  if [ "$actual" = "$expected" ]; then
    pass "$desc (status $actual)"
  else
    fail "$desc (expected $expected, got $actual)"
  fi
}

# expect_body_contains <needle> <description> <url> [curl args...]
expect_body_contains() {
  local needle="$1" desc="$2" url="$3"
  shift 3
  local body
  body=$(curl -s "$@" "$url")
  case "$body" in
    *"$needle"*) pass "$desc" ;;
    *) fail "$desc (body missing '$needle')" ;;
  esac
}

# expect_response_header_contains <needle> <description> <url> [curl args...]
#
# The match is case-insensitive: HTTP/1.1 header names arrive from the
# gateway lowercased (hyper's HeaderName), while the plugin and the
# RFC spell them in mixed case.
expect_response_header_contains() {
  local needle="$1" desc="$2" url="$3"
  shift 3
  local headers
  headers=$(curl -s -D - -o /dev/null "$@" "$url" | tr 'A-Z' 'a-z')
  case "$headers" in
    *"$needle"*) pass "$desc" ;;
    *) fail "$desc (response headers missing '$needle')" ;;
  esac
}

echo "static-auth: configured-token gate with a 401 challenge"

# No credential: 401 with a WWW-Authenticate challenge.
expect_status 401 "missing credential is challenged" "$BASE_URL/auth/things"
expect_response_header_contains 'www-authenticate: bearer realm="dwara"' \
  "401 carries a Bearer challenge" "$BASE_URL/auth/things"
expect_body_contains "missing credential" \
  "401 body names the reason" "$BASE_URL/auth/things"

# Wrong token: 401.
expect_status 401 "wrong token is denied" \
  "$BASE_URL/auth/things" -H "authorization: Bearer not-the-token"

# Wrong scheme: 401 (Bearer is configured; Basic does not satisfy it).
expect_status 401 "wrong scheme is denied" \
  "$BASE_URL/auth/things" -H "authorization: Basic c29tZXRoaW5n"

# Correct token: forwarded, and the echo upstream proves it.
expect_status 200 "correct bearer token is forwarded" \
  "$BASE_URL/auth/things" -H "authorization: Bearer dwara-example-token"
expect_body_contains '"path"' \
  "authenticated request reaches the upstream" \
  "$BASE_URL/auth/things" -H "authorization: Bearer dwara-example-token"

echo "static-auth: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
