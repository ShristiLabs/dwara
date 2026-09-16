#!/bin/bash
# test.sh -- demo 06: embedding dwara-core with a custom AnalyticsSink.
#
# Builds and runs the embedding crate in this directory: a binary that
# depends on dwara-core by path, constructs the dataplane the way the
# dwara-core integration tests do (parse -> compile_and_publish ->
# DataPlane -> a hyper serve loop over proxy::handle), registers its
# OWN AnalyticsSink (StdoutSink) at startup, and records one Event per
# completed request at the embedder-owned completion seam.
#
# Asserted (from the binary's own output):
#   1. the embedded gateway served the fired requests (3x 200, 1x 404)
#   2. the custom sink rendered a record for EVERY completed request,
#      including the unrouted 404
#   3. records carry method, path, and status
#   4. the binary exits 0 (its own sink-drain self-check passed)
#
# Ports (exclusive to this demo): 18251 (the embedded gateway).
#
# NOTE: the first build compiles the whole dwara-core dependency tree
# in this crate's own target/ (it is excluded from the workspace);
# subsequent runs are incremental.
set -euo pipefail

# helpers.sh redefines SCRIPT_DIR/DEMO_ROOT from ITS own path when
# sourced, so the demo's paths must be computed AFTER the source line.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/../_shared/helpers.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$DEMO_ROOT/../.." && pwd)"

PORT_EMBED=18251

echo "=== demo 06: embedding + custom AnalyticsSink ==="

echo "--- pre-flight: port $PORT_EMBED must be free"
if (exec 3<>/dev/tcp/127.0.0.1/"$PORT_EMBED") 2>/dev/null; then
  echo "FAIL: port $PORT_EMBED already in use (stale process from an earlier run?)"
  exit 1
fi

echo "--- building the embedding crate (dwara-core path dep)"
(
  cd "$SCRIPT_DIR" &&
    cargo build -q 2>&1 | tail -5
) || {
  echo "FAIL: embedding crate build failed"
  exit 1
}
BIN="$SCRIPT_DIR/target/debug/dwara-embed-analytics"
[ -x "$BIN" ] || {
  echo "FAIL: embedding binary missing: $BIN"
  exit 1
}

echo "--- running the embedding demo"
OUTPUT="$("$BIN" 2>&1)" || {
  echo "$OUTPUT"
  echo "FAIL: the embedding demo exited non-zero"
  exit 1
}
echo "$OUTPUT"

echo ""
echo "--- the custom sink saw the requests"
assert_contains "$OUTPUT" "custom AnalyticsSink registered" "the sink is registered at startup"
assert_contains "$OUTPUT" "client: GET /hello -> 200" "the embedded gateway served /hello"
assert_contains "$OUTPUT" "client: GET /no-such-route -> 404" "the unrouted request answered 404"
assert_contains "$OUTPUT" "sink: kind=request listener=embed-http method=GET path=/hello status=200" \
  "the sink rendered the /hello records"
assert_contains "$OUTPUT" "sink: kind=request listener=embed-http method=GET path=/no-such-route status=404" \
  "the sink rendered the 404 record too (every completed request)"
hello_records=$(grep -c "sink: .*path=/hello status=200" <<<"$OUTPUT" || true)
assert_status 3 "$hello_records" "three /hello records were rendered"

print_summary
