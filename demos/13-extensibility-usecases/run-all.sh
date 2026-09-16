#!/bin/bash
# run-all.sh -- every extension use-case recipe, in order.
#
# Builds the shared prerequisites once (the gateway binary and the two
# wasm rustup targets), then runs each demo's test.sh sequentially and
# prints one summary line. Every test.sh is independently runnable and
# self-cleaning; this driver only sequences them.
#
# From anywhere:
#   bash demos/13-extensibility-usecases/run-all.sh
set -u
# Build steps pipe cargo output through `tail` to keep the log short;
# without pipefail a failing cargo would never trip the failure path.
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

DEMOS=(
  01-user-subset-migration
  02-response-pii-redaction
  03-custom-auth
  04-feature-flag-nano
  05-tenant-routing
  06-embedding-analytics-sink
  07-per-request-decision
)

step() { echo; echo "=== $1 ==="; }
die() {
  echo "ERROR: $1"
  exit 1
}

step "Pre-flight: wasm targets (idempotent)"
rustup target add wasm32-wasip1 wasm32-unknown-unknown >/dev/null 2>&1 ||
  die "rustup target add wasm32-wasip1 wasm32-unknown-unknown failed"

step "Building the gateway binary (cargo build -p dwara-bin)"
(
  cd "$REPO_ROOT" &&
    cargo build -q -p dwara-bin 2>&1 | tail -5
) || die "gateway build failed"
[ -x "$REPO_ROOT/target/debug/dwara" ] ||
  [ -x "$REPO_ROOT/target/release/dwara" ] ||
  die "no gateway binary after build"

FAILED=()
for demo in "${DEMOS[@]}"; do
  step "Demo $demo"
  if bash "$SCRIPT_DIR/$demo/test.sh"; then
    echo "--- $demo: OK"
  else
    echo "--- $demo: FAILED"
    FAILED+=("$demo")
  fi
done

step "Summary"
TOTAL=${#DEMOS[@]}
PASSED=$((TOTAL - ${#FAILED[@]}))
if [ "${#FAILED[@]}" -eq 0 ]; then
  echo "extension use-case demos: $PASSED/$TOTAL categories green"
  exit 0
fi
echo "extension use-case demos: $PASSED/$TOTAL categories green; failed: ${FAILED[*]}"
exit 1
