#!/bin/bash
# Assertions for the request-tagger example plugin (DW-161).
#
# Runs against the harness gateway (plugins/examples/gateway.yaml,
# started by plugins/examples/run-all.sh). The echo upstream returns
# the headers it received, so the request-side stamps are visible in
# the response body.
#
#   ./assert.sh [base-url]
#
# Exits non-zero when any assertion fails.

BASE_URL="${1:-http://127.0.0.1:18101}"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

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

expect_contains() {
  local needle="$1" desc="$2" body="$3"
  case "$body" in
    *"$needle"*) pass "$desc" ;;
    *) fail "$desc (missing '$needle')" ;;
  esac
}

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

echo "request-tagger: x-plugin-* correlation stamps on both directions"

# With an inbound request id: echoed on the response headers and
# stamped on the request the upstream received (the echo body shows
# the request-side headers, lowercased for a case-insensitive match).
expect_status 200 "tagged route answers" \
  "$BASE_URL/tag/hello" -H "x-request-id: req-tag-123"
expect_response_header_contains "x-plugin-name: request-tagger" \
  "response carries the plugin name" "$BASE_URL/tag/hello" -H "x-request-id: req-tag-123"
expect_response_header_contains "x-plugin-request-id: req-tag-123" \
  "response echoes the request id" "$BASE_URL/tag/hello" -H "x-request-id: req-tag-123"

BODY=$(curl -s "$BASE_URL/tag/hello" -H "x-request-id: req-tag-123" | tr 'A-Z' 'a-z')
expect_contains "x-plugin-request-id" "request side is stamped too" "$BODY"
expect_contains "req-tag-123" "the echoed id rides the request stamp" "$BODY"

# Without an inbound request id: the literal "unset".
expect_response_header_contains "x-plugin-request-id: unset" \
  "missing request id stamps unset" "$BASE_URL/tag/hello"

echo "request-tagger: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
