#!/bin/bash
# Assertions for the response-body-redact example plugin (DW-161).
#
# Runs against the harness gateway (plugins/examples/gateway.yaml,
# started by plugins/examples/run-all.sh). The echo upstream serves
# /statement with two Luhn-valid card numbers, one invalid-checksum
# control number, and a literal secret.
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

expect_not_contains() {
  local needle="$1" desc="$2" body="$3"
  case "$body" in
    *"$needle"*) fail "$desc (found '$needle')" ;;
    *) pass "$desc" ;;
  esac
}

echo "response-body-redact: scrub card numbers and secrets"

BODY=$(curl -s "$BASE_URL/statement")
expect_status 200 "statement route answers" "$BASE_URL/statement"

# Luhn-valid cards are masked, last four digits and separators kept.
expect_contains "****-****-****-1111" "dashed card is masked" "$BODY"
expect_not_contains "4111-1111-1111-1111" "dashed card digits are gone" "$BODY"
expect_contains "**** **** **** 4444" "spaced card is masked" "$BODY"
expect_not_contains "5555 5555 5555 4444" "spaced card digits are gone" "$BODY"

# The checksum gate: a 16-digit number that is not a card stays.
expect_contains "1234567812345678" "invalid-checksum number is untouched" "$BODY"

# Configured literal secrets are starred (same length: 13 stars).
expect_not_contains "sk-live-12345" "literal secret is gone" "$BODY"
expect_contains "pin is ************* for the demo" "literal secret is starred" "$BODY"

echo "response-body-redact: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
