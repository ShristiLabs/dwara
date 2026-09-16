#!/bin/bash
# Example plugin gallery harness (DW-161).
#
# Builds every example plugin (host unit tests + wasm32-wasip1
# release artifacts), starts a real dwara gateway with
# plugins/examples/gateway.yaml plus a minimal echo upstream, runs
# each example's assertions, and tears everything down.
#
# From anywhere:
#   bash plugins/examples/run-all.sh
#
# Requirements: the repo's pinned Rust toolchain, curl, python3, and
# `cargo build -p dwara-bin` (run here automatically when needed).
# Ports are fixed to 18101 (gateway) and 18102 (upstream) via
# gateway.yaml; the harness fails fast if either is already in use
# (a stale listener would otherwise satisfy the readiness probe and
# fake a green run).

set -u
# The build steps pipe cargo output through `tail` to keep this log
# short; without pipefail the pipeline exits with tail's status and a
# failing `cargo test` upstream would never trip `die`.
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

EXAMPLES=(header-guard static-auth response-body-redact request-tagger)
GATEWAY_PORT=18101
UPSTREAM_PORT=18102
BASE_URL="http://127.0.0.1:$GATEWAY_PORT"

GATEWAY_PID=""
UPSTREAM_PID=""
LOG_DIR="$(mktemp -d /tmp/dwara-plugin-examples.XXXXXX)"
PRESERVE_LOGS=0
CLEANED=0

cleanup() {
  # Idempotent: the signal traps below run cleanup and then exit,
  # which fires the EXIT trap too; the gateway/upstream must be torn
  # down and the log-dir message printed exactly once.
  if [ "$CLEANED" -eq 1 ]; then
    return 0
  fi
  CLEANED=1
  if [ -n "$GATEWAY_PID" ]; then
    kill "$GATEWAY_PID" 2>/dev/null
    wait "$GATEWAY_PID" 2>/dev/null
  fi
  if [ -n "$UPSTREAM_PID" ]; then
    kill "$UPSTREAM_PID" 2>/dev/null
    wait "$UPSTREAM_PID" 2>/dev/null
  fi
  if [ "$PRESERVE_LOGS" -eq 1 ]; then
    echo "Logs preserved in $LOG_DIR (gateway.log, upstream.log)"
  else
    rm -rf "$LOG_DIR"
  fi
}
# EXIT covers the normal and die() paths; INT/TERM (Ctrl-C, kill)
# must tear the gateway and upstream down too, or an interrupted run
# leaves both listeners behind and the next run trips the port
# pre-flight.
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

step() { echo; echo "=== $1 ==="; }
die() {
  echo "ERROR: $1"
  exit 1
}

# wait_for <url> <name> [timeout_seconds]
wait_for() {
  local url="$1" name="$2" timeout="${3:-30}"
  local elapsed=0
  while [ "$elapsed" -lt "$timeout" ]; do
    if curl -sf -o /dev/null "$url" 2>/dev/null; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  echo "--- $name log tail ---"
  tail -20 "$LOG_DIR/$name.log" 2>/dev/null || true
  die "$name not ready at $url after ${timeout}s"
}

# port_in_use <port>: succeed when something already listens on
# 127.0.0.1:<port> (bash's /dev/tcp connect probe).
port_in_use() {
  (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null
}

step "Pre-flight: ports $GATEWAY_PORT and $UPSTREAM_PORT must be free"
for port in "$GATEWAY_PORT" "$UPSTREAM_PORT"; do
  if port_in_use "$port"; then
    die "port $port is already in use (stale gateway/upstream from an earlier run?); stop the listener and re-run"
  fi
done
echo "   both free"

step "Toolchain: wasm32-wasip1 target (idempotent)"
rustup target add wasm32-wasip1 >/dev/null 2>&1 || die "rustup target add wasm32-wasip1 failed"

step "Building the gateway binary (cargo build -p dwara-bin)"
(
  cd "$REPO_ROOT" &&
    cargo build -q -p dwara-bin 2>&1 | tail -5
) || die "gateway build failed"
[ -x "$REPO_ROOT/target/debug/dwara" ] || die "target/debug/dwara missing after build"

step "Building example plugins (host cargo test + wasm32-wasip1 release)"
for example in "${EXAMPLES[@]}"; do
  echo "-- $example"
  artifact="$SCRIPT_DIR/$example/target/wasm32-wasip1/release/"
  artifact="$artifact$(echo "$example" | tr - _).wasm"
  # Drop any artifact from an earlier run FIRST: the -f check below
  # must prove THIS run's build produced the file, not that one
  # exists at the path.
  rm -f "$artifact"
  (
    cd "$SCRIPT_DIR/$example" &&
      cargo test -q 2>&1 | tail -3 &&
      cargo build -q --release --target wasm32-wasip1 2>&1 | tail -3
  ) || die "$example failed to build/test"
  [ -f "$artifact" ] || die "$example artifact missing: $artifact"
  echo "   $(basename "$artifact") ok"
done

step "Starting the echo upstream on 127.0.0.1:$UPSTREAM_PORT"
python3 "$SCRIPT_DIR/echo-upstream.py" "$UPSTREAM_PORT" >"$LOG_DIR/upstream.log" 2>&1 &
UPSTREAM_PID=$!
wait_for "http://127.0.0.1:$UPSTREAM_PORT/echo" upstream 15

step "Starting the gateway on 127.0.0.1:$GATEWAY_PORT"
(
  cd "$REPO_ROOT" &&
    DWARA_CONFIG="$SCRIPT_DIR/gateway.yaml" \
    exec "$REPO_ROOT/target/debug/dwara"
  ) >"$LOG_DIR/gateway.log" 2>&1 &
GATEWAY_PID=$!
wait_for "$BASE_URL/healthz" gateway 30

step "Running example assertions"
FAILED_EXAMPLES=()
for example in "${EXAMPLES[@]}"; do
  echo
  echo "-- $example"
  if bash "$SCRIPT_DIR/$example/assert.sh" "$BASE_URL"; then
    echo "   $example: OK"
  else
    echo "   $example: FAILED"
    FAILED_EXAMPLES+=("$example")
  fi
done

step "Summary"
if [ "${#FAILED_EXAMPLES[@]}" -eq 0 ]; then
  echo "All ${#EXAMPLES[@]} example plugins passed their assertions."
  exit 0
fi
PRESERVE_LOGS=1
echo "Failed examples: ${FAILED_EXAMPLES[*]}"
exit 1
