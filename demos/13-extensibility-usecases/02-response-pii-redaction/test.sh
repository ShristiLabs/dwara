#!/bin/bash
# test.sh -- demo 02: response PII redaction at the edge.
#
# Builds the shipped plugins/examples/response-body-redact plugin BY
# PATH (no demo-local plugin code) and runs it against a mock LEAKY
# upstream that emits:
#   - a spaced Luhn-valid test card 4111 1111 1111 1111
#   - an innocent 16-digit non-Luhn number 1234567812345678
#   - a configured literal secret sk-live-12345
#
# Asserted:
#   1. buffered JSON route: the card is masked keep-last-4
#      ("**** **** **** 1111") and the digits are gone
#   2. the innocent number passes through untouched (the Luhn gate)
#   3. the configured literal is starred, same length
#   4. the SSE endpoint (/api/stream, text/event-stream, un-framed)
#      SKIPS the response_body phase: the card streams through
#      unmasked -- the documented streaming carve-out
#
# Ports (exclusive to this demo): gateway 18211, upstream 18212.
set -euo pipefail

# helpers.sh redefines SCRIPT_DIR/DEMO_ROOT from ITS own path when
# sourced, so the demo's paths must be computed AFTER the source line.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/../_shared/helpers.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$DEMO_ROOT/../.." && pwd)"

PORT_GW=18211
PORT_UP=18212
BASE_URL="http://127.0.0.1:$PORT_GW"

GW_PID=""
UP_PID=""
SCRATCH="$(mktemp -d /tmp/dwara-demo13-02.XXXXXX)"
CLEANED=0

cleanup() {
  if [ "$CLEANED" -eq 1 ]; then
    return 0
  fi
  CLEANED=1
  for pid in "$GW_PID" "$UP_PID"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  rm -rf "$SCRATCH"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

port_in_use() {
  (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null
}

echo "=== demo 02: response PII redaction ==="

echo "--- pre-flight: ports $PORT_GW $PORT_UP must be free"
for port in "$PORT_GW" "$PORT_UP"; do
  if port_in_use "$port"; then
    echo "FAIL: port $port already in use (stale process from an earlier run?)"
    exit 1
  fi
done

echo "--- toolchain: wasm32-wasip1 target (idempotent)"
rustup target add wasm32-wasip1 >/dev/null 2>&1 || {
  echo "FAIL: rustup target add wasm32-wasip1 failed"
  exit 1
}

echo "--- building the shipped response-body-redact example BY PATH"
REDEXAMPLE="$REPO_ROOT/plugins/examples/response-body-redact"
WASM="$REDEXAMPLE/target/wasm32-wasip1/release/response_body_redact.wasm"
rm -f "$WASM"
(
  cd "$REDEXAMPLE" &&
    cargo build -q --release --target wasm32-wasip1 2>&1 | tail -5
) || {
  echo "FAIL: response-body-redact build failed"
  exit 1
}
[ -f "$WASM" ] || {
  echo "FAIL: plugin artifact missing: $WASM"
  exit 1
}

echo "--- locating the gateway binary (cargo build -p dwara-bin)"
DWARA=""
for candidate in "$REPO_ROOT/target/debug/dwara" "$REPO_ROOT/target/release/dwara"; do
  if [ -x "$candidate" ]; then
    DWARA="$candidate"
    break
  fi
done
if [ -z "$DWARA" ]; then
  (cd "$REPO_ROOT" && cargo build -q -p dwara-bin 2>&1 | tail -5) || {
    echo "FAIL: gateway build failed"
    exit 1
  }
  DWARA="$REPO_ROOT/target/debug/dwara"
fi

echo "--- starting the leaky upstream"
python3 "$SCRIPT_DIR/leaky-upstream.py" "$PORT_UP" >"$SCRATCH/upstream.log" 2>&1 &
UP_PID=$!
wait_for "http://127.0.0.1:$PORT_UP/api/account" 15

echo "--- starting the gateway"
(
  cd "$REPO_ROOT" &&
    DWARA_CONFIG="$SCRIPT_DIR/dwara.yaml" exec "$DWARA"
) >"$SCRATCH/gateway.log" 2>&1 &
GW_PID=$!
wait_for "$BASE_URL/healthz" 30

echo ""
echo "--- buffered JSON: masked cards, untouched innocent numbers"
status=$(http_status "$BASE_URL/api/account")
assert_status "200" "$status" "GET /api/account answers 200 through the plugin"
body=$(http_body "$BASE_URL/api/account")
# The masked-value needles contain '*' runs, which grep would read as
# repetition operators; match those with shell globs (the plugin
# gallery's assert.sh approach) instead of the regex helpers.
expect_substring() {
  local needle="$1" desc="$2" haystack="$3"
  case "$haystack" in
    *"$needle"*)
      echo -e "${GREEN}PASS${NC}: $desc"
      PASS=$((PASS + 1))
      ;;
    *)
      echo -e "${RED}FAIL${NC}: $desc (expected to contain '$needle')"
      FAIL=$((FAIL + 1))
      ;;
  esac
}
expect_not_substring() {
  local needle="$1" desc="$2" haystack="$3"
  case "$haystack" in
    *"$needle"*)
      echo -e "${RED}FAIL${NC}: $desc (expected NOT to contain '$needle')"
      FAIL=$((FAIL + 1))
      ;;
    *)
      echo -e "${GREEN}PASS${NC}: $desc"
      PASS=$((PASS + 1))
      ;;
  esac
}
expect_substring '"**** **** **** 1111"' "the test card is masked keep-last-4" "$body"
expect_not_substring "4111 1111 1111 1111" "the test card digits are gone" "$body"
assert_contains "$body" '"1234567812345678"' "the non-Luhn 16-digit reference is untouched"
assert_not_contains "$body" "sk-live-12345" "the configured literal secret is gone"
expect_substring '"pin is *************"' "the literal secret is starred (same length)" "$body"

echo ""
echo "--- SSE: the response_body phase is skipped for streaming bodies"
sse_headers=$(curl -s -D - -o "$SCRATCH/sse.body" "$BASE_URL/api/stream")
assert_contains "$sse_headers" "text/event-stream" "the stream endpoint answers text/event-stream"
sse_body=$(cat "$SCRATCH/sse.body")
assert_contains "$sse_body" "4111 1111 1111 1111" "the card streams through UNMASKED (phase skipped)"
assert_contains "$sse_body" "data: \[DONE\]" "the full SSE event stream arrived"

print_summary
