#!/bin/bash
# Assertions for the header-guard example plugin (DW-161).
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

echo "header-guard: allow/deny by request header value"

# Missing header: denied by the plugin, upstream never dialed.
expect_status 403 "missing header is denied" "$BASE_URL/guard/data"
expect_body_contains "forbidden by header-guard" \
  "denial body names the plugin" "$BASE_URL/guard/data"

# Wrong value: denied.
expect_status 403 "wrong header value is denied" \
  "$BASE_URL/guard/data" -H "x-guard-key: wrong"

# Correct value: forwarded, and the echo upstream proves it.
expect_status 200 "correct header value is forwarded" \
  "$BASE_URL/guard/data" -H "x-guard-key: open-sesame"
expect_body_contains '"path"' \
  "allowed request reaches the upstream" \
  "$BASE_URL/guard/data" -H "x-guard-key: open-sesame"

echo "header-guard: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
