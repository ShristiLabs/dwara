#!/bin/bash
# Shared helper functions for dwara demo test scripts.

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

PASS=0
FAIL=0

# assert_status <expected_status> <actual_status> <description>
assert_status() {
  local expected="$1"
  local actual="$2"
  local desc="$3"
  if [ "$actual" = "$expected" ]; then
    echo -e "${GREEN}PASS${NC}: $desc (expected $expected, got $actual)"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}FAIL${NC}: $desc (expected $expected, got $actual)"
    FAIL=$((FAIL + 1))
  fi
}

# assert_contains <haystack> <needle> <description>
#
# Uses a herestring instead of `echo | grep -q`: grep -q exits at the
# first match, so with a large haystack (gateway logs) the echo writer
# can take a SIGPIPE — with `set -o pipefail` that flips a successful
# match into a pipeline failure. A herestring has no pipe to break.
assert_contains() {
  local haystack="$1"
  local needle="$2"
  local desc="$3"
  if grep -q "$needle" <<< "$haystack"; then
    echo -e "${GREEN}PASS${NC}: $desc"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}FAIL${NC}: $desc (expected to contain '$needle')"
    FAIL=$((FAIL + 1))
  fi
}

# assert_not_contains <haystack> <needle> <description>
assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  local desc="$3"
  if grep -q "$needle" <<< "$haystack"; then
    echo -e "${RED}FAIL${NC}: $desc (expected NOT to contain '$needle')"
    FAIL=$((FAIL + 1))
  else
    echo -e "${GREEN}PASS${NC}: $desc"
    PASS=$((PASS + 1))
  fi
}

# assert_header <response_headers> <header_name> <expected_value> <description>
assert_header() {
  local headers="$1"
  local name="$2"
  local expected="$3"
  local desc="$4"
  local actual
  actual=$(echo "$headers" | grep -i "^$name:" | sed 's/^[^:]*: *//' | tr -d '\r')
  if [ "$actual" = "$expected" ]; then
    echo -e "${GREEN}PASS${NC}: $desc (expected $expected, got $actual)"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}FAIL${NC}: $desc (expected $expected, got '$actual')"
    FAIL=$((FAIL + 1))
  fi
}

# wait_for <url> [timeout_seconds]
wait_for() {
  local url="$1"
  local timeout="${2:-30}"
  local elapsed=0
  while [ $elapsed -lt $timeout ]; do
    if curl -sf -o /dev/null "$url" 2>/dev/null; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  echo "ERROR: $url not ready after ${timeout}s"
  return 1
}

# http_status <url> [curl args...]
http_status() {
  local url="$1"
  shift
  curl -s -o /dev/null -w '%{http_code}' "$@" "$url"
}

# http_body <url> [curl args...]
http_body() {
  local url="$1"
  shift
  curl -s "$@" "$url"
}

# http_headers <url> [curl args...]
http_headers() {
  local url="$1"
  shift
  curl -s -I "$@" "$url"
}

# summary
print_summary() {
  echo ""
  echo "========================================="
  echo "Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}"
  echo "========================================="
  if [ $FAIL -gt 0 ]; then
    exit 1
  fi
}

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
